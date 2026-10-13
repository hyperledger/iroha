// Privacy-release evidence regression tests.
//
// Included by `privacy_release_evidence::tests` to preserve exact libtest names.
use super::*;
const RAYON_POOL_CHILD_MARKER_V1: &str = "IROHA_PRIVACY_RELEASE_RAYON_POOL_CHILD_V1";
fn compiled_profile_digest_mutations_v1() -> [fn(&mut CompiledPrivacyProfileV1); 5] {
    [
        |profile| profile.parameter_id.0[0] ^= 1,
        |profile| profile.parameter_digest.0[0] ^= 1,
        |profile| profile.verifier_digest.0[0] ^= 1,
        |profile| profile.statement_schema_digest.0[0] ^= 1,
        |profile| profile.engine_manifest_digest.0[0] ^= 1,
    ]
}
#[test]
fn zk_ace_is_unavailable_and_bootle_release_context_binds_every_profile_digest() {
    let zk_ace = PrivacyProtocolIdV1::ZkAcePqAuthorizationV1;
    assert_eq!(
        compiled_privacy_profile_v1(zk_ace),
        Err(
            crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
                protocol_id: zk_ace,
            }
        )
    );

    let protocol_id = PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1;
    let profile = compiled_privacy_profile_v1(protocol_id).expect("compiled profile");
    let baseline = norito::encode_canonical(&release_statement_context_from_compiled_profile_v1(
        &profile,
        release_network_id_from_genesis_hash([0xa7; 32]),
        3,
        PrivacyTransactionIntentDigestV1::new([0x51; 32]),
    ))
    .expect("release context");
    for mutate in compiled_profile_digest_mutations_v1() {
        let mut changed = profile;
        mutate(&mut changed);
        let changed =
            norito::encode_canonical(&release_statement_context_from_compiled_profile_v1(
                &changed,
                release_network_id_from_genesis_hash([0xa7; 32]),
                3,
                PrivacyTransactionIntentDigestV1::new([0x51; 32]),
            ))
            .expect("changed release context");
        assert_ne!(
            changed,
            baseline,
            "{} release context omitted one compiled-profile digest",
            protocol_id.canonical_label()
        );
    }
}
#[test]
fn verange_release_transcript_binds_every_compiled_profile_digest() {
    let profile = compiled_privacy_profile_v1(PrivacyProtocolIdV1::VeRangeTransparentRangeV1)
        .expect("compiled VeRange profile");
    let parameters =
        VeRangeParametersV1::for_profile(VeRangeBitLengthV1::Bits32).expect("VeRange parameters");
    let encode = |profile: &CompiledPrivacyProfileV1| {
        let binding = verange_binding_from_compiled_profile_v1(
            [0x61; 32],
            parameters.generator_digest(),
            profile,
        );
        let mut material = Vec::new();
        append_p256_binding_material_v1(&mut material, &binding);
        material
    };
    let baseline = encode(&profile);
    for mutate in compiled_profile_digest_mutations_v1() {
        let mut changed = profile;
        mutate(&mut changed);
        assert_ne!(
            encode(&changed),
            baseline,
            "VeRange release transcript omitted one compiled-profile digest"
        );
    }
}
#[test]
fn fcmp_release_statement_length_frames_every_compiled_profile_digest() {
    let profile = compiled_privacy_profile_v1(PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1)
        .expect("compiled FCMP++ profile");
    let encode = |profile: &CompiledPrivacyProfileV1| {
        let mut material = Vec::new();
        append_fcmp_compiled_profile_tuple_v1(&mut material, profile)
            .expect("FCMP++ profile tuple");
        material
    };
    let baseline = encode(&profile);
    let baseline_context =
        fcmp_release_context_hash_v1(&profile).expect("FCMP++ release context hash");
    let domain_length = usize::from(u16::from_be_bytes(
        baseline[..2].try_into().expect("domain length"),
    ));
    assert_eq!(
        &baseline[2..2 + domain_length],
        b"iroha.privacy.release.fcmp-plus-plus.compiled-profile-tuple.v1"
    );
    let count_offset = 2 + domain_length;
    assert_eq!(
        u16::from_be_bytes(
            baseline[count_offset..count_offset + 2]
                .try_into()
                .expect("field count")
        ),
        5
    );
    let mut offset = count_offset + 2;
    for expected in [
        profile.parameter_id.as_bytes().as_slice(),
        profile.parameter_digest.as_bytes().as_slice(),
        profile.verifier_digest.as_bytes().as_slice(),
        profile.statement_schema_digest.as_bytes().as_slice(),
        profile.engine_manifest_digest.as_bytes().as_slice(),
    ] {
        let length = usize::try_from(u64::from_be_bytes(
            baseline[offset..offset + 8]
                .try_into()
                .expect("field length"),
        ))
        .expect("field length fits usize");
        assert_eq!(length, 32);
        offset += 8;
        assert_eq!(&baseline[offset..offset + length], expected);
        offset += length;
    }
    assert_eq!(offset, baseline.len(), "profile tuple has trailing bytes");
    for mutate in compiled_profile_digest_mutations_v1() {
        let mut changed = profile;
        mutate(&mut changed);
        assert_ne!(
            encode(&changed),
            baseline,
            "FCMP++ release statement omitted one compiled-profile digest"
        );
        assert_ne!(
            fcmp_release_context_hash_v1(&changed).expect("changed FCMP++ release context hash"),
            baseline_context,
            "FCMP++ proof context omitted one compiled-profile digest"
        );
    }
}
#[test]
fn zk_ams_release_lineage_uses_distinct_single_action_transactions() {
    let admission =
        zk_ams_admission_transaction_context_v1().expect("admission transaction context");
    let provision =
        zk_ams_provision_transaction_context_v1().expect("provision transaction context");
    assert_eq!(ZK_AMS_RELEASE_ADMISSION_ACTION_INDEX_V1, 0);
    assert_eq!(ZK_AMS_RELEASE_PROVISION_ACTION_INDEX_V1, 0);
    assert_eq!(admission.network_id, provision.network_id);
    assert_eq!(admission.authority, provision.authority);
    assert_eq!(admission.time_to_live, provision.time_to_live);
    assert_eq!(admission.fee_payment, provision.fee_payment);
    assert_eq!(admission.metadata, provision.metadata);
    assert!(
        admission.creation_time < provision.creation_time,
        "admission must precede provisioning"
    );
    assert!(
        admission.nonce.expect("admission nonce") < provision.nonce.expect("provision nonce"),
        "sequential transactions require ordered nonces"
    );
}
#[test]
fn zk_ams_release_envelope_distinguishes_admission_from_native_rejection() {
    let ring = zk_ams_sorted_ring_v1(ZK_AMS_MIN_RING_SIZE_V1).expect("canonical minimum ring");
    let key_image = zk_ams_key_image_v1(&ring[5].1).expect("canonical key image");
    let statement = zk_ams_provision_statement_v1(
        &ring,
        key_image,
        PrivacyRootV1::new([0x41; 32]),
        2,
        PrivacyZkAmsRegistryRecordDigestV1::new([0x42; 32]),
    )
    .expect("canonical provisioning statement");
    let authoritative_network_id =
        release_network_id_from_genesis_hash(ZK_AMS_RELEASE_GENESIS_HASH_V1);
    let native_rejection = verify_zk_ams_release_production_envelope_v1(
        &statement,
        &[0x01],
        &authoritative_network_id,
        ZK_AMS_RELEASE_GENESIS_HASH_V1,
        ZK_AMS_RELEASE_PROVISION_ACTION_INDEX_V1,
    );
    assert_eq!(
        native_rejection,
        Err(PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected),
        "a canonical one-action envelope must reach the native ZK-AMS verifier"
    );
    assert_eq!(
        require_zk_ams_release_production_native_rejection_v1(
            native_rejection,
            PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
        ),
        Ok(()),
    );
    let mut impossible_second_action = statement.clone();
    impossible_second_action.context.action_index = 1;
    let pre_native_rejection = verify_zk_ams_release_production_envelope_v1(
        &impossible_second_action,
        &[0x01],
        &authoritative_network_id,
        ZK_AMS_RELEASE_GENESIS_HASH_V1,
        ZK_AMS_RELEASE_PROVISION_ACTION_INDEX_V1,
    );
    assert_eq!(
        pre_native_rejection,
        Err(PrivacyReleaseEvidenceErrorClassV1::ProductionEnvelopeRejected),
        "Taira's one-action transaction limit must reject before native verification"
    );
    assert_eq!(
        require_zk_ams_release_production_native_rejection_v1(
            pre_native_rejection,
            PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
        ),
        Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant),
        "a pre-native rejection cannot count as ZK-AMS corruption coverage"
    );
    assert_eq!(
        require_zk_ams_release_production_admission_rejection_v1(
            pre_native_rejection,
            PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
        ),
        Ok(()),
    );
    let oversized_len = usize::try_from(TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1)
        .expect("closed Taira proof-byte ceiling fits usize")
        + 1;
    let mut oversized = vec![0_u8; oversized_len];
    oversized[0] = 1;
    let oversized_rejection = verify_zk_ams_release_production_envelope_v1(
        &statement,
        &oversized,
        &authoritative_network_id,
        ZK_AMS_RELEASE_GENESIS_HASH_V1,
        ZK_AMS_RELEASE_PROVISION_ACTION_INDEX_V1,
    );
    assert_eq!(
        oversized_rejection,
        Err(PrivacyReleaseEvidenceErrorClassV1::ProductionEnvelopeRejected),
        "an oversized ZK-AMS proof must fail admission before native decoding"
    );
    assert_eq!(
        require_zk_ams_release_production_native_rejection_v1(
            oversized_rejection,
            PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
        ),
        Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant),
    );
    assert_eq!(
        require_zk_ams_release_production_admission_rejection_v1(
            oversized_rejection,
            PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
        ),
        Ok(()),
    );
}
#[test]
fn jindo_release_envelope_requires_the_production_native_dispatch() {
    let profile =
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1)
            .expect("compiled Jindo profile");
    let authoritative_network_id =
        release_network_id_from_genesis_hash(JINDO_RELEASE_GENESIS_HASH_V1);
    let polynomial_commitments = (1_i32..=4)
        .map(|coefficient| {
            let mut encoding =
                vec![0_u8; iroha_data_model::privacy::IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1];
            encoding[..4].copy_from_slice(&coefficient.to_le_bytes());
            iroha_data_model::privacy::PrivacyJindoLatticeCommitmentV1::new(encoding)
        })
        .collect();
    let statement = iroha_data_model::privacy::IrohaJindoPolynomialCommitmentStatementV1 {
        context: release_statement_context_from_compiled_profile_v1(
            &profile,
            authoritative_network_id,
            JINDO_RELEASE_ACTION_INDEX_V1,
            PrivacyTransactionIntentDigestV1::new([0x51; 32]),
        ),
        polynomial_commitments,
        evaluation_point: jindo_field_v1(13),
        claimed_evaluations: (17_u64..=20).map(jindo_field_v1).collect(),
    };
    let native_rejection = verify_jindo_release_production_envelope_v1(
        &statement,
        &[0x01],
        &authoritative_network_id,
        JINDO_RELEASE_GENESIS_HASH_V1,
        JINDO_RELEASE_ACTION_INDEX_V1,
    );
    assert_eq!(
        native_rejection,
        Err(PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected),
        "a canonical Jindo envelope with an invalid wire must reach the native verifier"
    );
    assert_eq!(
        require_jindo_release_production_native_rejection_v1(
            native_rejection,
            PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
        ),
        Ok(()),
    );
    let mut impossible_second_action = statement;
    impossible_second_action.context.action_index = 1;
    let pre_native_rejection = verify_jindo_release_production_envelope_v1(
        &impossible_second_action,
        &[0x01],
        &authoritative_network_id,
        JINDO_RELEASE_GENESIS_HASH_V1,
        JINDO_RELEASE_ACTION_INDEX_V1,
    );
    assert_eq!(
        pre_native_rejection,
        Err(PrivacyReleaseEvidenceErrorClassV1::ProductionEnvelopeRejected),
        "Taira's sole-action context must reject before native Jindo verification"
    );
    assert_eq!(
        require_jindo_release_production_native_rejection_v1(
            pre_native_rejection,
            PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
        ),
        Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant),
        "release evidence must not count a pre-native rejection as native corruption coverage"
    );
}
#[test]
fn vega_release_fixture_uses_the_canonical_single_taira_action() {
    let fixture = vega_release_fixture_v1().expect("canonical Vega release fixture");
    let transaction =
        vega_release_transaction_context_v1().expect("canonical Vega transaction context");
    let protocol_id = PrivacyProtocolIdV1::VegaExistingCredentialZkV1;
    assert_eq!(
        compiled_privacy_profile_v1(protocol_id),
        Err(
            crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
                protocol_id,
            }
        )
    );
    let limits = PrivacyConsensusLimitsV1::taira_default();
    fixture
        .public_input
        .issuer_record
        .validate()
        .expect("canonical active Vega issuer record");
    assert_eq!(VEGA_RELEASE_ACTION_INDEX_V1, 0);
    assert_eq!(limits.max_actions_per_transaction, 1);
    assert_eq!(
        VEGA_RELEASE_ACTION_INDEX_V1.checked_add(1),
        Some(limits.max_actions_per_transaction)
    );
    assert_eq!(
        transaction.network_id,
        release_network_id_from_genesis_hash([0xa7; 32])
    );
    assert_eq!(
        transaction.creation_time,
        Duration::from_millis(VEGA_RELEASE_CREATION_TIME_MS_V1)
    );
    assert_eq!(transaction.nonce, NonZeroU32::new(VEGA_RELEASE_NONCE_V1));
}
#[test]
fn vega_release_envelope_fails_closed_before_native_dispatch_while_profile_is_unavailable() {
    let fixture = vega_release_fixture_v1().expect("canonical Vega release fixture");
    let control_profile =
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::VeRangeTransparentRangeV1)
            .expect("available structural control profile");
    let authoritative_network_id = release_network_id_from_genesis_hash(fixture.genesis_hash);
    let input = fixture.public_input;
    let record = fixture.issuer_record;
    let mut statement = VegaExistingCredentialStatementV1 {
        context: release_statement_context_from_compiled_profile_v1(
            &control_profile,
            authoritative_network_id,
            VEGA_RELEASE_ACTION_INDEX_V1,
            PrivacyTransactionIntentDigestV1::new([0x27; 32]),
        ),
        issuer_id: record.issuer_id,
        issuer_record_epoch: record.record_epoch,
        issuer_record_digest: record.record_digest,
        document_type: record.document_type,
        namespace: record.namespace,
        digest_algorithm: record.digest_algorithm,
        issuer_authentication_algorithm: record.issuer_authentication_algorithm,
        device_authentication_algorithm: record.device_authentication_algorithm,
        issuer_public_key: record.issuer_public_key,
        device_authentication_digest:
            iroha_data_model::privacy::PrivacyVegaDeviceAuthenticationDigestV1::new([0; 32]),
        presentation_date: input.presentation_date,
        minimum_age_years: input.minimum_age_years,
        reader_challenge: input.reader_challenge,
        session_transcript_digest: input.session_transcript_digest,
    };
    refresh_vega_device_authentication_digest_v1(&mut statement, fixture.genesis_hash)
        .expect("canonical Vega device binding");
    let native_rejection = verify_vega_release_production_envelope_v1(
        &statement,
        Some(&record),
        &[0x01],
        &authoritative_network_id,
        fixture.genesis_hash,
        VEGA_RELEASE_ACTION_INDEX_V1,
        VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
    );
    assert_eq!(
        native_rejection,
        Err(PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable),
        "an unavailable Vega profile must reject before native verification"
    );
    assert_eq!(
        require_vega_release_production_native_rejection_v1(
            native_rejection,
            PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
        ),
        Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant),
        "profile unavailability must not count as native corruption coverage"
    );
    statement.context.action_index = 1;
    // Canonical H_dev derivation intentionally refuses this impossible sole-action index. Keep
    // the old digest so this call proves profile availability is checked before statement admission.
    let pre_native_rejection = verify_vega_release_production_envelope_v1(
        &statement,
        Some(&record),
        &[0x01],
        &authoritative_network_id,
        fixture.genesis_hash,
        VEGA_RELEASE_ACTION_INDEX_V1,
        VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
    );
    assert_eq!(
        pre_native_rejection,
        Err(PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable),
        "profile unavailability must precede statement/action-index admission"
    );
    assert_eq!(
        require_vega_release_production_native_rejection_v1(
            pre_native_rejection,
            PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
        ),
        Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant),
        "release evidence must not count a pre-native rejection as Vega corruption coverage"
    );
}
#[test]
fn vega_public_action_builder_fails_closed_with_an_otherwise_valid_fixture() {
    let fixture = vega_release_fixture_v1().expect("canonical Vega release fixture");
    let witness_material = VegaPrivacyActionWitnessMaterialV1::new(
        fixture.issuer_authentication_sig_structure.clone(),
        fixture.mobile_security_object_payload.clone(),
        fixture.birth_date_issuer_signed_item.clone(),
        &fixture.issuer_signature.to_bytes(),
    )
    .expect("canonical Vega action witness material");
    let result = prepare_vega_privacy_action_with_rng_v1(
        vega_release_transaction_context_v1().expect("canonical transaction context"),
        fixture.public_input,
        witness_material,
        &fixture.device_signing_key,
        fixture.genesis_hash,
        VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
        &mut EvidenceRng06::new([0x90; 32]),
    );
    assert!(matches!(
        result,
        Err(
            crate::privacy_engines::vega::VegaPrivacyActionBuildErrorV1::CompiledProfileUnavailable
        )
    ));
}
#[test]
fn vega_release_stages_and_network_builder_fail_closed_without_an_activatable_profile() {
    let protocol_id = PrivacyProtocolIdV1::VegaExistingCredentialZkV1;
    for case_kind in PrivacyReleaseCaseKindV1::ALL {
        assert_eq!(
            run_privacy_release_stage_v1(protocol_id, case_kind),
            Err(PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class: PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable,
            })
        );
    }

    let transaction =
        vega_release_transaction_context_v1().expect("canonical Vega transaction context");
    let transaction_key_pair = KeyPair::try_from_seed(vec![0x56; 32], Algorithm::Ed25519)
        .expect("fixed Vega transaction key");
    let network_result = build_privacy_release_vega_network_action_v1(
        PrivacyReleaseTransactionContextV1 {
            network_id: transaction.network_id,
            authority: transaction.authority,
            creation_time: transaction.creation_time,
            time_to_live: transaction.time_to_live,
            nonce: transaction.nonce,
            fee_payment: transaction.fee_payment,
            metadata: transaction.metadata,
            genesis_hash: [0xa7; 32],
        },
        [0x93; 32],
        transaction_key_pair.private_key(),
    );
    assert!(matches!(
        network_result,
        Err(PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable)
    ));

    let stage_source = include_str!("vega.rs");
    let stage = stage_source
        .split_once("pub(super) fn run_vega_stage_v1")
        .expect("Vega release stage")
        .1
        .split_once("pub(super) fn require_vega_release_production_native_rejection_v1")
        .expect("Vega release stage boundary")
        .0;
    assert!(stage.contains("compiled_privacy_profile_v1(protocol_id)"));
    assert!(stage.contains("prepare_vega_privacy_action_with_rng_v1("));

    let production_envelope = stage_source
        .split_once("pub(super) fn verify_vega_release_production_envelope_v1")
        .expect("Vega production envelope helper")
        .1
        .split_once("pub(super) fn refresh_vega_device_authentication_digest_v1")
        .expect("Vega production envelope helper boundary")
        .0;
    assert!(production_envelope.contains("compiled_privacy_profile_v1(protocol_id)"));
    assert!(production_envelope.contains("verify_privacy_envelope_v1("));

    let network_source = include_str!("network_actions.rs");
    let network_builder = network_source
        .split_once("pub fn build_privacy_release_vega_network_action_v1")
        .expect("Vega network action builder")
        .1
        .split_once("/// Build one canonical network-bound Orchard action")
        .expect("Vega network action builder boundary")
        .0;
    assert!(network_builder.contains("compiled_privacy_profile_v1(protocol_id)"));
    assert!(network_builder.contains("build_signed_vega_privacy_action_with_rng_v1("));
}
#[test]
fn canonical_process_profile_is_exact_and_has_one_authoritative_source() {
    let profiles = PrivacyProtocolIdV1::ALL
        .into_iter()
        .filter_map(privacy_release_process_profile_v1)
        .collect::<Vec<_>>();
    assert_eq!(
        profiles,
        vec![PrivacyReleaseProcessProfileV1 {
            protocol_id: PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            elapsed_ceiling_millis: 300_000,
            peak_rss_ceiling_bytes: 12_884_901_888,
            address_space_ceiling_bytes: 34_359_738_368,
        }]
    );
    assert_eq!(
        profiles[0].elapsed_ceiling_millis,
        ZK_X509_PROVER_TARGET_SECONDS_V1 * 1_000
    );
    assert_eq!(
        profiles[0].peak_rss_ceiling_bytes,
        ZK_X509_PROVER_PEAK_MEMORY_BYTES_V1
    );
    assert_eq!(
        profiles[0].address_space_ceiling_bytes,
        ZK_X509_PROVER_ADDRESS_SPACE_CEILING_BYTES_V1
    );
}
#[test]
fn privacy_release_rayon_pool_fresh_process_child_v1() {
    if std::env::var_os(RAYON_POOL_CHILD_MARKER_V1).is_none() {
        return;
    }
    assert_eq!(
        std::env::var("RUST_MIN_STACK").as_deref(),
        Ok("1048576"),
        "the child must exercise the release override under a hostile one-MiB default"
    );
    assert_eq!(PRIVACY_RELEASE_RAYON_THREAD_COUNT_V1, 4);
    assert_eq!(PRIVACY_RELEASE_STAGE_STACK_BYTES_V1, 8 * 1024 * 1024);
    initialize_privacy_release_rayon_pool_v1().expect("initialize exact release Rayon pool");
    let worker_stack_probes = rayon::broadcast(|_| {
        let stack_probe = [0xA5_u8; 2 * 1024 * 1024];
        assert_eq!(stack_probe[0], 0xA5);
        assert_eq!(stack_probe[stack_probe.len() - 1], 0xA5);
        std::hint::black_box(&stack_probe);
    });
    assert_eq!(
        worker_stack_probes.len(),
        usize::from(PRIVACY_RELEASE_RAYON_THREAD_COUNT_V1)
    );
    assert_eq!(
        rayon::current_num_threads(),
        usize::from(PRIVACY_RELEASE_RAYON_THREAD_COUNT_V1)
    );
    assert_eq!(
        initialize_privacy_release_rayon_pool_v1(),
        Err(PrivacyReleaseRayonPoolErrorV1::InitializationRejected),
        "a second global-pool initialization must fail closed"
    );
}
#[test]
fn privacy_release_rayon_pool_is_one_time_and_exact_at_api_boundary_v1() {
    let executable = std::env::current_exe().expect("resolve core unit-test executable");
    let output = std::process::Command::new(executable)
        .arg("privacy_release_rayon_pool_fresh_process_child_v1")
        .arg("--nocapture")
        .env(RAYON_POOL_CHILD_MARKER_V1, "1")
        .env("RUST_MIN_STACK", "1048576")
        .output()
        .expect("execute release Rayon API child");
    assert!(
        output.status.success(),
        "release Rayon API child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn frozen_stage_order_is_explicit_and_matches_the_enum_product() {
    assert!(validate_privacy_release_stage_coordinates_v1(
        &PRIVACY_RELEASE_STAGE_COORDINATES_V1
    ));
    let mut observed = Vec::new();
    for protocol_id in PrivacyProtocolIdV1::ALL {
        for case_kind in PrivacyReleaseCaseKindV1::ALL {
            observed.push(privacy_release_stage_ordinal_v1(protocol_id, case_kind));
        }
    }
    assert_eq!(observed.len(), PRIVACY_RELEASE_STAGE_COUNT_V1);
    assert_eq!(
        observed,
        (0..u16::try_from(PRIVACY_RELEASE_STAGE_COUNT_V1).unwrap()).collect::<Vec<_>>()
    );
    assert_eq!(
        PRIVACY_RELEASE_STAGE_COORDINATES_V1
            .map(|coordinate| coordinate.stage_ordinal)
            .to_vec(),
        observed
    );
}
#[test]
fn resource_facts_are_frozen_for_every_exact12_stage() {
    for protocol_id in PrivacyProtocolIdV1::ALL {
        for case_kind in PrivacyReleaseCaseKindV1::ALL {
            let facts = privacy_release_resource_facts_v1(protocol_id, case_kind)
                .expect("every exact-12 stage has frozen resource facts");
            assert!(facts.validate());
            if case_kind == PrivacyReleaseCaseKindV1::MaximumShapeResource {
                assert_eq!(facts.primary_units, facts.primary_ceiling);
                assert_eq!(facts.secondary_units, facts.secondary_ceiling);
                assert_eq!(facts.relation_depth, facts.relation_depth_ceiling);
            }
        }
    }
}
#[test]
fn exact_parsers_reject_aliases_and_case_folding() {
    for case_kind in PrivacyReleaseCaseKindV1::ALL {
        assert_eq!(
            PrivacyReleaseCaseKindV1::from_canonical_label(case_kind.canonical_label()),
            Some(case_kind)
        );
    }
    assert_eq!(
        PrivacyReleaseCaseKindV1::from_canonical_label("Positive-Canonical-End-To-End"),
        None
    );
    assert_eq!(
        PrivacyReleaseCaseKindV1::from_canonical_label("positive-canonical-end-to-end "),
        None
    );
    assert_eq!(
        PrivacyReleaseCaseKindV1::from_canonical_label("positive"),
        None
    );
}
#[test]
fn evidence_seeds_are_deterministic_and_purpose_separated() {
    let case_kind = PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation;
    let purposes: [&[u8]; 6] = [
        b"canonical-fixture-keygen",
        b"canonical-fixture-encryption",
        b"canonical-proof",
        b"invalid-path-fixture-keygen",
        b"invalid-path-fixture-encryption",
        b"invalid-path-proof",
    ];
    for protocol_id in [
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        PrivacyProtocolIdV1::PqMaspStarkV1,
    ] {
        let seeds = purposes
            .iter()
            .map(|purpose| {
                stage_purpose_seed_v1(protocol_id, case_kind, purpose)
                    .expect("fixed evidence purpose derives a seed")
            })
            .collect::<Vec<_>>();
        for (index, seed) in seeds.iter().enumerate() {
            assert_eq!(
                *seed,
                stage_purpose_seed_v1(protocol_id, case_kind, purposes[index])
                    .expect("same purpose derives the same seed")
            );
            for other in &seeds[index + 1..] {
                assert_ne!(seed, other);
            }
        }
    }
    assert_ne!(
        stage_purpose_seed_v1(
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            case_kind,
            b"canonical-proof",
        )
        .expect("IVM proof seed"),
        stage_purpose_seed_v1(
            PrivacyProtocolIdV1::PqMaspStarkV1,
            case_kind,
            b"canonical-proof",
        )
        .expect("PQ-MASP proof seed"),
    );
}
#[test]
fn zk_x509_profile_is_unavailable_until_qualification_and_resource_facts_are_total() {
    let protocol_id = PrivacyProtocolIdV1::IrohaZkX509StarkP256V1;
    assert!(matches!(
        compiled_privacy_profile_v1(protocol_id),
        Err(crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
            protocol_id: unavailable,
        }) if unavailable == protocol_id
    ));
    for case_kind in PrivacyReleaseCaseKindV1::ALL {
        let resources = privacy_release_resource_facts_v1(protocol_id, case_kind)
            .expect("every X.509 release coordinate has frozen resource facts");
        assert!(resources.validate());
    }
}
#[test]
fn maximum_fixture_dimensions_equal_governed_first_release_caps() {
    assert_eq!(BOOTLE_LANTERN_MAX_ALLOWED_VALUES_PER_ATTRIBUTE_V1, 32);
    assert_eq!(ZK_AMS_MAX_RING_SIZE_V1, 64);
    assert_eq!(ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1, 8);
    assert_eq!(ORCHARD_MAX_ACTIONS_V1, 2);
    assert_eq!(ORCHARD_TREE_DEPTH_V1, 32);
    let orchard = orchard_maximum_spend_fixture_v1()
        .expect("maximum Orchard fixture has two shared-anchor real spends");
    assert_eq!(orchard.spends.len(), ORCHARD_MAX_ACTIONS_V1);
    assert_eq!(orchard.total_value, 36);
    assert_ne!(orchard.anchor, orchard_empty_root_v1());
}
#[test]
fn ordered_proof_artifact_cardinality_is_closed_and_fail_closed() {
    let artifact = |protocol_id: PrivacyProtocolIdV1,
                    case_kind: PrivacyReleaseCaseKindV1,
                    artifact_ordinal: u8| {
        let canonical_proof_bytes =
            vec![artifact_ordinal.saturating_add(1); usize::from(artifact_ordinal) + 1];
        PrivacyReleaseProofArtifactEvidenceV1 {
            artifact_ordinal,
            proof_sha256: sha256_v1(&canonical_proof_bytes),
            canonical_proof_bytes,
            proof_bytes_ceiling: privacy_release_proof_artifact_ceiling_v1(
                protocol_id,
                case_kind,
                artifact_ordinal,
            )
            .expect("valid fixture artifact has a canonical ceiling"),
        }
    };
    let ordinary_protocol = PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1;
    let ordinary_case = PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd;
    let pgc_protocol = PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1;
    let zk_ams_protocol = PrivacyProtocolIdV1::IrohaZkAmsV1;
    let maximum_case = PrivacyReleaseCaseKindV1::MaximumShapeResource;
    let adversarial_case = PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation;
    assert_eq!(
        privacy_release_proof_artifact_count_v1(ordinary_protocol, ordinary_case),
        1
    );
    assert_eq!(
        privacy_release_proof_artifact_count_v1(pgc_protocol, maximum_case),
        2
    );
    assert_eq!(
        privacy_release_proof_artifact_count_v1(pgc_protocol, ordinary_case),
        2
    );
    assert_eq!(
        privacy_release_proof_artifact_count_v1(zk_ams_protocol, maximum_case),
        2
    );
    assert_eq!(
        privacy_release_proof_artifact_count_v1(zk_ams_protocol, ordinary_case),
        2
    );
    assert_eq!(
        privacy_release_proof_artifact_count_v1(zk_ams_protocol, adversarial_case),
        2
    );
    assert!(validate_privacy_release_proof_artifacts_v1(
        ordinary_protocol,
        ordinary_case,
        &[artifact(ordinary_protocol, ordinary_case, 0)],
    ));
    assert!(validate_privacy_release_proof_artifacts_v1(
        pgc_protocol,
        maximum_case,
        &[
            artifact(pgc_protocol, maximum_case, 0),
            artifact(pgc_protocol, maximum_case, 1),
        ],
    ));
    assert!(validate_privacy_release_proof_artifacts_v1(
        pgc_protocol,
        ordinary_case,
        &[
            artifact(pgc_protocol, ordinary_case, 0),
            artifact(pgc_protocol, ordinary_case, 1),
        ],
    ));
    assert!(validate_privacy_release_proof_artifacts_v1(
        zk_ams_protocol,
        ordinary_case,
        &[
            artifact(zk_ams_protocol, ordinary_case, 0),
            artifact(zk_ams_protocol, ordinary_case, 1),
        ],
    ));
    assert!(validate_privacy_release_proof_artifacts_v1(
        zk_ams_protocol,
        adversarial_case,
        &[
            artifact(zk_ams_protocol, adversarial_case, 0),
            artifact(zk_ams_protocol, adversarial_case, 1),
        ],
    ));
    assert_eq!(
        privacy_release_proof_artifact_ceiling_v1(pgc_protocol, ordinary_case, 0),
        u64::try_from(MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1).ok()
    );
    assert_eq!(
        privacy_release_proof_artifact_ceiling_v1(pgc_protocol, ordinary_case, 1),
        u64::try_from(MAX_PGC_PAYMENT_PROOF_BYTES_V1).ok()
    );
    assert_eq!(
        privacy_release_proof_artifact_ceiling_v1(zk_ams_protocol, ordinary_case, 0),
        u64::try_from(MAX_ZK_AMS_BATCH_ADMISSION_PROOF_BYTES_V1).ok()
    );
    assert_eq!(
        privacy_release_proof_artifact_ceiling_v1(zk_ams_protocol, ordinary_case, 1),
        u64::try_from(MAX_ZK_AMS_LSAG_PROOF_BYTES_V1).ok()
    );
    assert_eq!(
        privacy_release_proof_artifact_ceiling_v1(zk_ams_protocol, adversarial_case, 0),
        u64::try_from(MAX_ZK_AMS_BATCH_ADMISSION_PROOF_BYTES_V1).ok()
    );
    assert_eq!(
        privacy_release_proof_artifact_ceiling_v1(zk_ams_protocol, adversarial_case, 1),
        u64::try_from(MAX_ZK_AMS_LSAG_PROOF_BYTES_V1).ok()
    );
    let valid = artifact(ordinary_protocol, ordinary_case, 0);
    let mut hash_mismatch = valid.clone();
    hash_mismatch.proof_sha256[0] ^= 1;
    let mut empty = valid.clone();
    empty.canonical_proof_bytes.clear();
    empty.proof_sha256 = sha256_v1(&empty.canonical_proof_bytes);
    let mut over_ceiling = valid.clone();
    over_ceiling.canonical_proof_bytes = vec![
        7;
        usize::try_from(over_ceiling.proof_bytes_ceiling)
            .expect("FCMP++ ceiling fits usize")
            + 1
    ];
    over_ceiling.proof_sha256 = sha256_v1(&over_ceiling.canonical_proof_bytes);
    let mut zero_ceiling = valid.clone();
    zero_ceiling.proof_bytes_ceiling = 0;
    let mut substituted_ceiling = valid.clone();
    substituted_ceiling.proof_bytes_ceiling = substituted_ceiling
        .proof_bytes_ceiling
        .checked_sub(1)
        .expect("FCMP++ ceiling is nonzero");
    let mut unbounded_ceiling = valid.clone();
    unbounded_ceiling.proof_bytes_ceiling = PRIVACY_RELEASE_MAX_PROOF_ARTIFACT_BYTES_V1 + 1;
    let mut byte_mutation = valid.clone();
    byte_mutation.canonical_proof_bytes[0] ^= 1;
    let malformed = [
        Vec::new(),
        vec![valid.clone(), valid.clone()],
        vec![hash_mismatch],
        vec![empty],
        vec![over_ceiling],
        vec![zero_ceiling],
        vec![substituted_ceiling],
        vec![unbounded_ceiling],
        vec![byte_mutation],
    ];
    for artifacts in malformed {
        assert!(!validate_privacy_release_proof_artifacts_v1(
            ordinary_protocol,
            ordinary_case,
            &artifacts,
        ));
    }
    let pgc_artifact_zero = artifact(pgc_protocol, maximum_case, 0);
    let pgc_artifact_one = artifact(pgc_protocol, maximum_case, 1);
    for artifacts in [
        vec![pgc_artifact_zero.clone()],
        vec![pgc_artifact_one.clone(), pgc_artifact_zero.clone()],
        vec![pgc_artifact_zero.clone(), pgc_artifact_zero.clone()],
        vec![
            pgc_artifact_zero.clone(),
            PrivacyReleaseProofArtifactEvidenceV1 {
                artifact_ordinal: 2,
                ..pgc_artifact_one.clone()
            },
        ],
        vec![
            pgc_artifact_zero.clone(),
            pgc_artifact_one.clone(),
            pgc_artifact_one,
        ],
    ] {
        assert!(!validate_privacy_release_proof_artifacts_v1(
            pgc_protocol,
            maximum_case,
            &artifacts,
        ));
    }
}
#[test]
fn proof_artifact_consensus_cap_is_exact_and_cap_plus_one_rejects() {
    assert_eq!(
        PRIVACY_RELEASE_MAX_PROOF_ARTIFACT_BYTES_V1,
        u64::from(TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1)
    );
    assert_eq!(PRIVACY_RELEASE_MAX_PROOF_ARTIFACT_BYTES_V1, 9 * 1024 * 1024);
    let protocol_id = PrivacyProtocolIdV1::PqMaspStarkV1;
    let case_kind = PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd;
    let ceiling = privacy_release_proof_artifact_ceiling_v1(protocol_id, case_kind, 0)
        .expect("PQ-MASP stage has one canonical ceiling");
    assert_eq!(ceiling, PRIVACY_RELEASE_MAX_PROOF_ARTIFACT_BYTES_V1);
    let canonical_proof_bytes =
        vec![0x5a; usize::try_from(ceiling).expect("Taira proof cap fits usize")];
    let mut artifact = PrivacyReleaseProofArtifactEvidenceV1 {
        artifact_ordinal: 0,
        proof_sha256: sha256_v1(&canonical_proof_bytes),
        canonical_proof_bytes,
        proof_bytes_ceiling: ceiling,
    };
    assert!(validate_privacy_release_proof_artifacts_v1(
        protocol_id,
        case_kind,
        core::slice::from_ref(&artifact),
    ));
    artifact.canonical_proof_bytes.push(0);
    artifact.proof_sha256 = sha256_v1(&artifact.canonical_proof_bytes);
    assert!(!validate_privacy_release_proof_artifacts_v1(
        protocol_id,
        case_kind,
        core::slice::from_ref(&artifact),
    ));
}
#[test]
fn zk_x509_codec_bound_fits_cap_without_qualifying_the_engine() {
    let protocol_id = PrivacyProtocolIdV1::IrohaZkX509StarkP256V1;
    let case_kind = PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd;
    let exact_x5s1_ceiling = u64::from(ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1);
    assert_eq!(
        privacy_release_proof_artifact_ceiling_v1(protocol_id, case_kind, 0),
        Some(exact_x5s1_ceiling)
    );
    assert_eq!(exact_x5s1_ceiling, 9_204_362);
    assert_eq!(
        PRIVACY_RELEASE_MAX_PROOF_ARTIFACT_BYTES_V1 - exact_x5s1_ceiling,
        232_822
    );
    let descriptor = privacy_release_protocol_descriptor_v1(protocol_id);
    assert!(descriptor.contains("projected-X5S1-maximum=9204362 bytes"));
    assert!(descriptor.contains("outer-action-proof-cap=9437184 bytes"));
    assert!(descriptor.contains("activation=unavailable-qualification"));
    assert!(crate::privacy_profiles::compiled_privacy_profile_v1(protocol_id).is_err());
    let canonical_proof_bytes = vec![0x58; usize::try_from(exact_x5s1_ceiling).unwrap()];
    let mut artifact = PrivacyReleaseProofArtifactEvidenceV1 {
        artifact_ordinal: 0,
        proof_sha256: sha256_v1(&canonical_proof_bytes),
        canonical_proof_bytes,
        proof_bytes_ceiling: exact_x5s1_ceiling,
    };
    // This validates artifact framing and size only. Arbitrary bytes do not
    // establish cryptographic validity, a passing stage, or engine activation.
    assert!(validate_privacy_release_proof_artifacts_v1(
        protocol_id,
        case_kind,
        core::slice::from_ref(&artifact),
    ));
    for substituted_ceiling in [
        exact_x5s1_ceiling - 1,
        exact_x5s1_ceiling + 1,
        PRIVACY_RELEASE_MAX_PROOF_ARTIFACT_BYTES_V1,
    ] {
        artifact.proof_bytes_ceiling = substituted_ceiling;
        assert!(
            !validate_privacy_release_proof_artifacts_v1(
                protocol_id,
                case_kind,
                core::slice::from_ref(&artifact),
            ),
            "substituting a lower, higher, or outer action ceiling must reject"
        );
    }
    artifact.proof_bytes_ceiling = exact_x5s1_ceiling;
    artifact.canonical_proof_bytes.push(0);
    artifact.proof_sha256 = sha256_v1(&artifact.canonical_proof_bytes);
    assert!(!validate_privacy_release_proof_artifacts_v1(
        protocol_id,
        case_kind,
        core::slice::from_ref(&artifact),
    ));
}
#[test]
fn zk_x509_public_evidence_binds_the_exact_validated_input_shape() {
    let context =
        crate::privacy_engines::zk_x509::relation::release_fixture::reference_statement_context_v1(
        );
    let canonical = build_zk_x509_release_fixture_v1(context.clone(), false)
        .expect("canonical X.509 release fixture");
    let maximum =
        build_zk_x509_release_fixture_v1(context, true).expect("maximum X.509 release fixture");
    canonical
        .resource_shape
        .validate_v1()
        .expect("canonical resource shape");
    maximum
        .resource_shape
        .validate_v1()
        .expect("maximum resource shape");
    assert_eq!(maximum.resource_shape.certificate_chain_depth, 3);
    assert_eq!(maximum.resource_shape.maximum_serial_bytes, 20);
    assert_eq!(
        maximum.resource_shape.disclosed_value_lengths,
        [2, 256, 256, 256]
    );
    assert_eq!(maximum.resource_shape.maximum_disclosed_value_bytes, 256);
    assert_eq!(maximum.resource_shape.ca_membership_index, 1);
    assert!(
        maximum
            .resource_shape
            .ca_membership_path_has_nonzero_sibling
    );
    let statement_material = b"canonical-statement".to_vec();
    let canonical_material = zk_x509_release_public_statement_material_v1(
        statement_material.clone(),
        canonical.resource_shape,
    )
    .expect("canonical shape material");
    let maximum_material = zk_x509_release_public_statement_material_v1(
        statement_material.clone(),
        maximum.resource_shape,
    )
    .expect("maximum shape material");
    assert_ne!(canonical_material, maximum_material);
    assert_ne!(sha256_v1(&canonical_material), sha256_v1(&maximum_material));
    assert!(maximum_material.starts_with(ZK_X509_RELEASE_PUBLIC_MATERIAL_DOMAIN_V1));
    let statement_len_offset = ZK_X509_RELEASE_PUBLIC_MATERIAL_DOMAIN_V1.len();
    assert_eq!(
        &maximum_material[statement_len_offset..statement_len_offset + size_of::<u64>()],
        &u64::try_from(statement_material.len())
            .expect("statement length fits u64")
            .to_be_bytes()
    );
    assert_eq!(
        &maximum_material[statement_len_offset + size_of::<u64>()
            ..statement_len_offset + size_of::<u64>() + statement_material.len()],
        statement_material.as_slice()
    );
    let shape_wire_bytes = size_of::<u8>()
        + ZK_X509_MAX_CHAIN_DEPTH_V1 * size_of::<u32>()
        + size_of::<u32>()
        + size_of::<u8>()
        + 4 * size_of::<u16>()
        + size_of::<u16>()
        + size_of::<u16>()
        + size_of::<u8>();
    let shape_wire = &maximum_material[maximum_material.len() - shape_wire_bytes..];
    assert_eq!(shape_wire.len(), 31);
    assert_eq!(shape_wire[0], 3);
    assert_eq!(shape_wire[17], 20);
    assert_eq!(&shape_wire[18..26], &[0, 2, 1, 0, 1, 0, 1, 0]);
    assert_eq!(&shape_wire[26..28], &256_u16.to_be_bytes());
    assert_eq!(&shape_wire[28..30], &1_u16.to_be_bytes());
    assert_eq!(shape_wire[30], 1);
    let mut invalid_shape = maximum.resource_shape;
    invalid_shape.crl_der_length = 0;
    assert_eq!(
        zk_x509_release_public_statement_material_v1(statement_material, invalid_shape,),
        Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)
    );
}
#[test]
fn every_typed_artifact_has_one_exact_bound_and_oversized_bounds_reject() {
    let mut artifact_count = 0_usize;
    for protocol_id in PrivacyProtocolIdV1::ALL {
        for case_kind in PrivacyReleaseCaseKindV1::ALL {
            let stage_count = usize::from(privacy_release_proof_artifact_count_v1(
                protocol_id,
                case_kind,
            ));
            artifact_count = artifact_count
                .checked_add(stage_count)
                .expect("closed artifact count fits usize");
            for ordinal in 0..stage_count {
                let ceiling = privacy_release_proof_artifact_ceiling_v1(
                    protocol_id,
                    case_kind,
                    u8::try_from(ordinal).expect("at most two artifacts"),
                )
                .expect("every required artifact has one canonical ceiling");
                assert!(ceiling > 0);
                if protocol_id == PrivacyProtocolIdV1::IrohaZkX509StarkP256V1 {
                    assert_eq!(ceiling, u64::from(ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1));
                    assert!(ceiling > PRIVACY_RELEASE_MAX_PROOF_ARTIFACT_BYTES_V1);
                    let canonical_proof_bytes = vec![0x58, 0x35, 0x53, 0x31];
                    let artifact = PrivacyReleaseProofArtifactEvidenceV1 {
                        artifact_ordinal: u8::try_from(ordinal).expect("at most two artifacts"),
                        proof_sha256: sha256_v1(&canonical_proof_bytes),
                        canonical_proof_bytes,
                        proof_bytes_ceiling: ceiling,
                    };
                    assert!(!validate_privacy_release_proof_artifacts_v1(
                        protocol_id,
                        case_kind,
                        core::slice::from_ref(&artifact),
                    ));
                } else {
                    assert!(ceiling <= PRIVACY_RELEASE_MAX_PROOF_ARTIFACT_BYTES_V1);
                }
            }
            assert!(
                privacy_release_proof_artifact_ceiling_v1(
                    protocol_id,
                    case_kind,
                    u8::try_from(stage_count).expect("at most two artifacts"),
                )
                .is_none()
            );
        }
    }
    assert_eq!(artifact_count, PRIVACY_RELEASE_PROOF_ARTIFACT_COUNT_V1);
}
#[test]
fn canonical_proof_bytes_use_json_base64_and_round_trip_exactly() {
    let protocol_id = PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1;
    let case_kind = PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd;
    let canonical_proof_bytes = vec![0x00, 0x01, 0xfe, 0xff];
    let artifact = PrivacyReleaseProofArtifactEvidenceV1 {
        artifact_ordinal: 0,
        proof_sha256: sha256_v1(&canonical_proof_bytes),
        canonical_proof_bytes,
        proof_bytes_ceiling: privacy_release_proof_artifact_ceiling_v1(protocol_id, case_kind, 0)
            .expect("FCMP++ stage has one canonical ceiling"),
    };
    let json = norito::json::to_json(&artifact).expect("artifact JSON encodes");
    assert!(json.contains("\"canonical_proof_bytes\":\"AAH+/w==\""));
    let decoded: PrivacyReleaseProofArtifactEvidenceV1 =
        norito::json::from_str(&json).expect("artifact JSON decodes");
    assert_eq!(decoded, artifact);
    let unpadded = json.replace("AAH+/w==", "AAH+/w");
    assert!(
        norito::json::from_str::<PrivacyReleaseProofArtifactEvidenceV1>(&unpadded).is_err(),
        "non-canonical base64 spelling must reject"
    );
    let mut legacy_json = json;
    let closing_brace = legacy_json
        .pop()
        .expect("canonical artifact JSON has a closing brace");
    assert_eq!(closing_brace, '}');
    legacy_json.push_str(",\"proof_bytes\":4}");
    assert!(
        norito::json::from_str::<PrivacyReleaseProofArtifactEvidenceV1>(&legacy_json).is_err(),
        "removed reported-length field must not be accepted as a compatibility alias"
    );
}
#[test]
fn every_protocol_has_one_distinct_nonempty_canonical_descriptor() {
    let descriptors = PrivacyProtocolIdV1::ALL.map(privacy_release_protocol_descriptor_v1);
    assert!(descriptors.iter().all(|descriptor| !descriptor.is_empty()));
    for (index, descriptor) in descriptors.iter().enumerate() {
        assert!(!descriptors[index + 1..].contains(descriptor));
    }
}
#[test]
fn vega_release_descriptor_is_derived_from_the_canonical_mc_constants() {
    let descriptor =
        privacy_release_protocol_descriptor_v1(PrivacyProtocolIdV1::VegaExistingCredentialZkV1);
    let upstream_commit = super::vega::VEGA_RELEASE_MC_UPSTREAM_COMMIT_V1;
    let wire = super::vega::VEGA_RELEASE_MC_WIRE_DESCRIPTOR_V1;
    assert!(descriptor.contains(&format!(
        "canonical-profile=Microsoft-Vega_MC-Figure9@{upstream_commit}"
    )));
    assert!(descriptor.contains(&format!("wire={wire}")));
    assert!(descriptor.contains(&format!(
        "fixed-primary={VEGA_RELEASE_MC_TOTAL_APP_CONSTRAINTS_V1} total application constraints"
    )));
    assert!(descriptor.contains(&format!(
        "fixed-secondary={VEGA_RELEASE_MC_MAX_CIRCUIT_VARIABLES_V1} maximum circuit variables"
    )));
    assert!(descriptor.contains(&format!(
        "fixed-public-inputs={}",
        super::vega::VEGA_RELEASE_PUBLIC_INPUT_COUNT_V1
    )));
    assert!(descriptor.contains(&format!(
        "fixed-depth={VEGA_RELEASE_MC_RELAXED_SUMCHECK_ROUNDS_V1} relaxed sumcheck rounds"
    )));
    assert_eq!(
        super::vega::VEGA_RELEASE_PUBLIC_INPUT_COUNT_V1,
        VEGA_MDL_PUBLIC_INPUT_COUNT_V1
    );
    let manifest =
        core::str::from_utf8(iroha_zkp_halo2::vega::VEGA_MDL_COMPILED_PROFILE_MANIFEST_V1)
            .expect("Vega compiled profile manifest is ASCII");
    assert!(manifest.contains(&format!("upstream_commit={upstream_commit}")));
    assert!(manifest.contains(
        "vendor_manifest_sha256=539c54251c8853fa99673e71d777966a3e3e238e64028d47b3e683329023236f"
    ));
    assert!(manifest.contains("sha256_steps=birth:2,issuer:6,total:8"));
    assert!(manifest.contains("proof_wire=bincode-1.3.3-fixed-little-endian"));
    assert!(manifest.contains("envelope=IROVEGMC,version:1,context-keccak256:32"));
    assert!(manifest.contains("no-ambient-fallback"));
}
#[test]
fn jindo_release_descriptor_binds_monomial_repetitions_and_fail_closed_qrom_gate() {
    let descriptor = privacy_release_protocol_descriptor_v1(
        PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
    );
    assert!(descriptor.contains("challenge=32-independent-uniform-signed-monomials"));
    assert!(descriptor.contains("all-distinct-signed-monomial-differences-machine-checked-units"));
    assert!(descriptor.contains("qrom-production-certificate=unavailable"));
    assert!(descriptor.contains("split-challenge=uniform-nonzero-Fp-star"));
    assert!(descriptor.contains("wire=IJP3-no-IJP1-no-IJP2"));
    assert!(!descriptor.contains("S35"));
}

#[test]
fn zk_ace_release_descriptor_binds_final_geometry_and_unresolved_qrom_gate() {
    let protocol_id = PrivacyProtocolIdV1::ZkAcePqAuthorizationV1;
    let descriptor = privacy_release_protocol_descriptor_v1(protocol_id);
    assert!(descriptor.contains("poseidon-x7-goldilocks-digest384-six-independent-lanes"));
    assert!(descriptor.contains("fixed-secondary=136 unique verifier queries"));
    assert!(descriptor.contains("fixed-depth=11 binary Fp4 FRI rounds"));
    assert!(descriptor.contains("proof-cap=2131222 exact bytes"));
    assert!(descriptor.contains("classical-rom-security=128"));
    assert!(descriptor.contains("qrom-qualification=unavailable"));
    assert!(descriptor.contains("activation=unavailable"));
    for case_kind in PrivacyReleaseCaseKindV1::ALL {
        assert_eq!(
            run_privacy_release_stage_v1(protocol_id, case_kind),
            Err(PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class: PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable,
            })
        );
    }
}

#[test]
#[ignore = "operator-only native proof construction for the complete Bootle/Lantern release stage"]
fn bootle_lantern_release_stage_exercises_one_shot_issuance_and_wire_rejection() {
    let protocol_id = PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1;
    let case_kind = PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation;
    let evidence = run_privacy_release_stage_v1(protocol_id, case_kind)
        .expect("Bootle/Lantern corruption-and-truncation release stage");
    assert_eq!(evidence.protocol_id, protocol_id);
    assert_eq!(evidence.case_kind, case_kind);
    assert_eq!(
        evidence.failure_class,
        PrivacyReleaseFailureClassV1::CanonicalWireCorruptionAndTruncationRejected
    );
    assert_eq!(evidence.proof_artifacts.len(), 1);
    assert_eq!(
        evidence.proof_artifacts[0].canonical_proof_bytes.len(),
        BOOTLE_PROOF_BYTES_V1
    );
    assert_eq!(
        evidence.proof_artifacts[0].proof_bytes_ceiling,
        u64::try_from(BOOTLE_PROOF_BYTES_V1).expect("fixed ILN1 length fits u64")
    );
    assert!(validate_privacy_release_proof_artifacts_v1(
        protocol_id,
        case_kind,
        &evidence.proof_artifacts,
    ));
}
#[test]
#[ignore = "operator-only native proof construction for the complete ZK-AMS corruption stage"]
fn zk_ams_corruption_stage_rejects_maximum_and_submaximum_wire_mutations() {
    let protocol_id = PrivacyProtocolIdV1::IrohaZkAmsV1;
    let case_kind = PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation;
    let evidence =
        run_privacy_release_stage_v1(protocol_id, case_kind).expect("ZK-AMS corruption stage");
    assert_eq!(evidence.protocol_id, protocol_id);
    assert_eq!(evidence.case_kind, case_kind);
    assert_eq!(
        evidence.failure_class,
        PrivacyReleaseFailureClassV1::CanonicalWireCorruptionAndTruncationRejected
    );
    assert_eq!(
        evidence.proof_artifacts.len(),
        usize::from(privacy_release_proof_artifact_count_v1(
            protocol_id,
            case_kind
        ))
    );
    assert!(validate_privacy_release_proof_artifacts_v1(
        protocol_id,
        case_kind,
        &evidence.proof_artifacts,
    ));
}
