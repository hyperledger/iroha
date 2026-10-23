use super::{
    exact12_fixture::{
        account, assert_fixed_width_norito, asset_definition_id, bootle_lantern_policy, commitment,
        context, encrypted_output, envelope, fcmp_input, fcmp_output, jindo_commitment,
        jindo_field, network_id, nullifier, orchard_action, p256_ciphertext, p256_point, proof_for,
        proof_variant_name, raw, redigest_bootle_lantern_policy, redigest_zk_ace_policy,
        sample_statements, sorted_fcmp_outputs, statement_for, statement_variant_name,
        zk_ace_allowlist, zk_ace_identity_commitment, zk_ace_policy, zk_ams_anchor,
        zk_ams_provision_statement, zk_ams_seed_key, zk_x509_certificate_policy, zk_x509_crl,
        zk_x509_trust_anchor,
    },
    *,
};
use hex_literal::hex;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use std::str::FromStr as _;
fn pgc_accounts(count: u8) -> Vec<PrivacyPgcAccountV1> {
    (1..=count)
        .map(|seed| PrivacyPgcAccountV1 {
            public_key: p256_point(seed),
            encrypted_balance: p256_ciphertext(seed),
        })
        .collect()
}
fn pgc_bootstrap() -> PrivacyPgcAccountBootstrapV1 {
    let statement = statement_for(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1);
    PrivacyPgcAccountBootstrapV1 {
        namespace: PrivacyNamespaceV1::from_statement(&statement),
        initial_root: PrivacyRootV1::new(raw(201)),
        initial_epoch: 1,
        total_supply: 160,
        accounts: pgc_accounts(16),
    }
}
#[derive(Clone, Copy)]
enum RootCorruption {
    ZeroSuccessor,
    Unchanged,
    SkippedEpoch,
    EpochOverflow,
}
fn corrupt_root_transition(statement: &mut PrivacyStatementV1, corruption: RootCorruption) {
    macro_rules! corrupt {
        ($current:expr, $epoch:expr, $next:expr, $next_epoch:expr) => {
            match corruption {
                RootCorruption::ZeroSuccessor => $next = PrivacyRootV1::new([0; 32]),
                RootCorruption::Unchanged => $next = $current,
                RootCorruption::SkippedEpoch => {
                    $next_epoch = $epoch.checked_add(2).expect("fixture epoch has room")
                }
                RootCorruption::EpochOverflow => {
                    $epoch = u64::MAX;
                    $next_epoch = 0;
                }
            }
        };
    }
    match statement {
        PrivacyStatementV1::AnonymousPgcKOutOfNV1(statement) => corrupt!(
            statement.account_state_root,
            statement.account_state_root_epoch,
            statement.next_account_state_root,
            statement.next_account_state_root_epoch
        ),
        PrivacyStatementV1::IrohaZkAmsV1(statement) => {
            let PrivacyZkAmsActionV1::BatchAdmission(batch) = &mut statement.action else {
                panic!("ZK-AMS provisioning does not manage a root transition")
            };
            corrupt!(
                batch.account_registry_root,
                batch.account_registry_root_epoch,
                batch.next_account_registry_root,
                batch.next_account_registry_root_epoch
            )
        }
        PrivacyStatementV1::OrchardHalo2ActionsV1(_) => {
            panic!("Orchard successor roots are derived from the authoritative node frontier")
        }
        PrivacyStatementV1::MoneroFcmpPlusPlusV1(_)
        | PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(_)
        | PrivacyStatementV1::PqMaspStarkV1(_) => {
            panic!("FCMP++ and private-note successor roots are validator-derived")
        }
        _ => panic!("protocol does not manage a root transition"),
    }
}
fn protocol_limits(protocol: PrivacyProtocolIdV1) -> PrivacyProtocolActivationLimitsV1 {
    super::exact12_fixture::sample_protocol_limits(protocol)
}
fn assert_stable_schema_wire<T>(value: &T, schema_name: &str, expected_schema_hash: [u8; 16])
where
    T: norito::NoritoSerialize
        + for<'de> norito::NoritoDeserialize<'de>
        + PartialEq
        + core::fmt::Debug
        + 'static,
{
    let derived_schema_hash = norito::core::schema_hash_for_name(schema_name);
    assert_eq!(
        derived_schema_hash, expected_schema_hash,
        "permanent schema-name KAT changed for {schema_name}"
    );
    assert_eq!(
        norito::schema::identity::frame_hash::<T>(),
        expected_schema_hash
    );
    assert_eq!(
        norito::schema::identity::frame_hash::<T>(),
        expected_schema_hash
    );
    let legacy_type_name_hash = norito::core::type_name_schema_hash::<T>();
    assert_ne!(
        legacy_type_name_hash, expected_schema_hash,
        "permanent public schema must not fall back to the Rust type name"
    );
    let canonical = norito::encode_canonical(value).expect("encode permanent-schema frame");
    assert_eq!(
        &canonical[6..22],
        expected_schema_hash.as_slice(),
        "canonical frame header must carry the permanent schema identity"
    );
    assert_eq!(
        norito::decode_canonical::<T>(&canonical).expect("decode permanent-schema frame"),
        *value
    );
    let mut legacy_header = canonical.clone();
    legacy_header[6..22].copy_from_slice(&legacy_type_name_hash);
    assert!(
        matches!(
            norito::decode_canonical::<T>(&legacy_header),
            Err(norito::Error::SchemaMismatch)
        ),
        "the pre-release Rust type-name wire must fail closed"
    );
    let mut forged_header = canonical;
    forged_header[6] ^= 0x80;
    assert!(
        matches!(
            norito::decode_canonical::<T>(&forged_header),
            Err(norito::Error::SchemaMismatch)
        ),
        "an unknown schema identity must fail before payload decoding"
    );
}
#[test]
fn first_release_privacy_schema_names_and_old_headers_are_frozen() {
    let statement = statement_for(PrivacyProtocolIdV1::ZkAcePqAuthorizationV1);
    let PrivacyStatementV1::ZkAcePqAuthorizationV1(authorization_statement) = &statement else {
        unreachable!("ZK-ACE fixture must use the typed authorization statement")
    };
    let authorization_statement = authorization_statement.clone();
    let public_inputs =
        crate::zk::ZkAcePrivacyPublicInputsV1::new(authorization_statement.clone(), raw(0xD1));
    let proof = proof_for(PrivacyProtocolIdV1::ZkAcePqAuthorizationV1);
    let proof_envelope = envelope(statement.clone());
    let policy = zk_ace_policy(
        PRIVACY_ZK_ACE_POLICY_INITIAL_EPOCH_V1,
        11,
        PrivacyZkAcePolicyLifecycleV1::Active,
    );
    let policy_material = PrivacyZkAcePolicyDigestMaterialV1 {
        policy_id: policy.policy_id,
        identity_commitment: policy.identity_commitment,
        policy_digest: policy.policy_digest,
        authorization_epoch: policy.authorization_epoch,
        asset_definition_id: policy.asset_definition_id,
        source_allowlist: policy.source_allowlist,
        lifecycle: policy.lifecycle,
    };
    assert_stable_schema_wire(
        &authorization_statement,
        ZK_ACE_AUTHORIZATION_STATEMENT_SCHEMA_NAME_V1,
        hex!("4acf679326b17350dcb57f4ea7ac20a1"),
    );
    assert_stable_schema_wire(
        &statement,
        PRIVACY_STATEMENT_SCHEMA_NAME_V1,
        hex!("7966b2f6ebc8c1ff1a1eb8ac458657af"),
    );
    assert_stable_schema_wire(
        &public_inputs,
        crate::zk::ZK_ACE_PRIVACY_PUBLIC_INPUTS_SCHEMA_NAME_V1,
        hex!("0f16958a9641702815d6cddee3aeb8aa"),
    );
    assert_stable_schema_wire(
        &policy_material,
        ZK_ACE_POLICY_DIGEST_MATERIAL_SCHEMA_NAME_V1,
        hex!("5f08d7306e9c76b183a60175fa514966"),
    );
    assert_stable_schema_wire(
        &proof,
        PRIVACY_PROOF_SCHEMA_NAME_V1,
        hex!("8335f36ecd62f6cc59715441a3496a27"),
    );
    assert_stable_schema_wire(
        &proof_envelope,
        PRIVACY_PROOF_ENVELOPE_SCHEMA_NAME_V1,
        hex!("3956178024ddd2abae83d3a5b59827fb"),
    );
    assert_stable_schema_wire(
        &compiled_profile_catalog(),
        PRIVACY_COMPILED_PROFILE_CATALOG_SCHEMA_NAME_V1,
        hex!("f3addcc8d28f55b9119e6cc22e5e5b57"),
    );
    assert_stable_schema_wire(
        &exact12_capability_manifest(),
        PRIVACY_EXACT12_CAPABILITY_MANIFEST_SCHEMA_NAME_V1,
        hex!("5b9d88f68fd595c78e84f1693bbb0dcb"),
    );
}
fn activation(envelope: &PrivacyProofEnvelopeV1) -> PrivacyProtocolActivationRecordV1 {
    super::exact12_fixture::sample_activation(envelope)
}
fn compiled_profile_snapshot(
    activation: &PrivacyProtocolActivationRecordV1,
) -> PrivacyCompiledProfileSnapshotV1 {
    PrivacyCompiledProfileSnapshotV1 {
        protocol_id: activation.protocol_id,
        proof_system_id: activation.proof_system_id,
        engine_id: activation.engine_id,
        parameter_id: activation.parameter_id,
        parameter_digest: activation.parameter_digest,
        verifier_digest: activation.verifier_digest,
        statement_schema_digest: activation.statement_schema_digest,
        engine_manifest_digest: activation.engine_manifest_digest,
        protocol_limits: activation.protocol_limits,
    }
}
fn capability_snapshot() -> PrivacyCapabilitySnapshotV1 {
    let pgc_activation = activation(&envelope(statement_for(
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
    )));
    let pgc_profile = compiled_profile_snapshot(&pgc_activation);
    PrivacyCapabilitySnapshotV1 {
        version: PRIVACY_CAPABILITY_SNAPSHOT_VERSION_V1,
        committed_height: 2,
        consensus_policy: PrivacyConsensusPolicyV1::taira_default(),
        qualification: None,
        protocols: PrivacyProtocolIdV1::ALL
            .into_iter()
            .map(|protocol_id| {
                if protocol_id == PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1 {
                    PrivacyCapabilityRowV1 {
                        protocol_id,
                        compiled_profile: PrivacyCompiledProfileResultV1::Available(pgc_profile),
                        activation: Some(pgc_activation),
                    }
                } else {
                    PrivacyCapabilityRowV1 {
                        protocol_id,
                        compiled_profile: PrivacyCompiledProfileResultV1::Unavailable(
                            PrivacyCompiledProfileUnavailableReasonV1::EngineUnavailable,
                        ),
                        activation: None,
                    }
                }
            })
            .collect(),
    }
}
fn exact12_capability_manifest() -> PrivacyExact12CapabilityManifestV1 {
    capability_snapshot()
        .exact12_capability_manifest_v1()
        .expect("project valid committed snapshot")
}
fn redigest_exact12_capability_manifest(manifest: &mut PrivacyExact12CapabilityManifestV1) {
    manifest.manifest_digest = manifest
        .computed_manifest_digest()
        .expect("recompute canonical manifest digest");
}
fn compiled_profile_catalog() -> PrivacyCompiledProfileCatalogV1 {
    let pgc_activation = activation(&envelope(statement_for(
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
    )));
    let pgc_profile = compiled_profile_snapshot(&pgc_activation);
    PrivacyCompiledProfileCatalogV1 {
        version: PRIVACY_COMPILED_PROFILE_CATALOG_VERSION_V1,
        protocols: PrivacyProtocolIdV1::ALL
            .into_iter()
            .map(|protocol_id| PrivacyCompiledProfileCatalogRowV1 {
                protocol_id,
                compiled_profile: if protocol_id == PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1 {
                    PrivacyCompiledProfileResultV1::Available(pgc_profile)
                } else {
                    PrivacyCompiledProfileResultV1::Unavailable(
                        PrivacyCompiledProfileUnavailableReasonV1::EngineUnavailable,
                    )
                },
            })
            .collect(),
    }
}
#[test]
fn protocol_ids_keep_closed_norito_discriminants() {
    assert_eq!(PrivacyProtocolIdV1::ALL.len(), PrivacyProtocolIdV1::COUNT);
    for (expected, protocol) in PrivacyProtocolIdV1::ALL.into_iter().enumerate() {
        let encoded = protocol.encode();
        assert_eq!(encoded, u32::try_from(expected).unwrap().to_le_bytes());
        assert_eq!(
            PrivacyProtocolIdV1::decode(&mut encoded.as_slice()).expect("decode protocol"),
            protocol
        );
    }
    let protocol_count =
        u32::try_from(PrivacyProtocolIdV1::COUNT).expect("protocol count fits u32");
    for unknown in [protocol_count, 99, u32::MAX] {
        assert!(
            PrivacyProtocolIdV1::decode(&mut unknown.to_le_bytes().as_slice()).is_err(),
            "unknown protocol discriminant {unknown} must fail"
        );
    }
}
#[test]
fn protocol_ids_have_unique_exact_external_labels() {
    let expected = [
        (
            PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
            "zk-ace-pq-authorization-v1",
        ),
        (
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            "anonymous-pgc-k-out-of-n-v1",
        ),
        (
            PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
            "verange-transparent-range-v1",
        ),
        (PrivacyProtocolIdV1::IrohaZkAmsV1, "iroha-zk-ams-v1"),
        (
            PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
            "vega-existing-credential-zk-v1",
        ),
        (
            PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            "iroha-zk-x509-stark-p256-v1",
        ),
        (
            PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
            "iroha-jindo-polynomial-commitment-v1",
        ),
        (
            PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
            "iroha-bootle-lantern-anoncred-v1",
        ),
        (
            PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
            "orchard-halo2-actions-v1",
        ),
        (
            PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
            "monero-fcmp-plus-plus-v1",
        ),
        (
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            "iroha-ivm-private-note-stark-v1",
        ),
        (PrivacyProtocolIdV1::PqMaspStarkV1, "pq-masp-stark-v1"),
    ];
    assert_eq!(expected.len(), PrivacyProtocolIdV1::COUNT);
    for (index, (protocol, label)) in expected.into_iter().enumerate() {
        assert_eq!(PrivacyProtocolIdV1::ALL[index], protocol);
        assert_eq!(protocol.canonical_label(), label);
        assert_eq!(
            PrivacyProtocolIdV1::from_canonical_label(label),
            Some(protocol)
        );
        assert!(
            PrivacyProtocolIdV1::ALL[..index]
                .iter()
                .all(|prior| prior.canonical_label() != label),
            "duplicate privacy protocol label {label}"
        );
    }
}

#[test]
fn final_catalog_binds_ordinals_labels_and_weakest_security_models() {
    let expected_models = [
        PrivacySecurityModelV1::PostQuantumQrom,
        PrivacySecurityModelV1::ClassicalRom,
        PrivacySecurityModelV1::ClassicalRom,
        PrivacySecurityModelV1::ClassicalRom,
        PrivacySecurityModelV1::ClassicalRom,
        PrivacySecurityModelV1::ClassicalRom,
        PrivacySecurityModelV1::PostQuantumQrom,
        PrivacySecurityModelV1::PostQuantumQrom,
        PrivacySecurityModelV1::ClassicalRom,
        PrivacySecurityModelV1::ClassicalRom,
        PrivacySecurityModelV1::PostQuantumQrom,
        PrivacySecurityModelV1::PostQuantumQrom,
    ];
    for (protocol, expected) in PrivacyProtocolIdV1::ALL.into_iter().zip(expected_models) {
        assert_eq!(protocol.security_model(), expected);
    }
    assert_eq!(PRIVACY_EXACT12_CATALOG_PREIMAGE_V1.len(), 525);
    assert_eq!(
        *compute_privacy_exact12_catalog_commitment_v1().as_bytes(),
        PRIVACY_EXACT12_CATALOG_COMMITMENT_BYTES_V1
    );
    assert_eq!(
        *PrivacyExact12CatalogCommitmentV1::canonical().as_bytes(),
        PRIVACY_EXACT12_CATALOG_COMMITMENT_BYTES_V1
    );
}

#[test]
fn proof_envelope_wire_rejects_pre_release_layout_magic_and_catalog() {
    let envelope = envelope(statement_for(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1));
    let encoded = envelope.encode();
    let magic_bytes = PrivacyProofWireMagicV1::canonical().encode();
    let catalog_bytes = *PrivacyExact12CatalogCommitmentV1::canonical().as_bytes();
    assert_eq!(magic_bytes, PRIVACY_PROOF_WIRE_MAGIC_BYTES_V1);
    assert_eq!(usize::from(encoded[0]), magic_bytes.len());
    assert_eq!(&encoded[1..=magic_bytes.len()], &magic_bytes);
    let catalog_length_offset = 1 + magic_bytes.len();
    assert_eq!(
        usize::from(encoded[catalog_length_offset]),
        PrivacyExact12CatalogCommitmentV1::BYTES
    );
    let catalog_offset = catalog_length_offset + 1;
    assert_eq!(
        &encoded[catalog_offset..catalog_offset + PrivacyExact12CatalogCommitmentV1::BYTES],
        &catalog_bytes
    );

    let pre_release_layout = &encoded[catalog_offset + PrivacyExact12CatalogCommitmentV1::BYTES..];
    let mut pre_release_cursor = pre_release_layout;
    assert!(PrivacyProofEnvelopeV1::decode(&mut pre_release_cursor).is_err());

    let mut bad_magic = encoded.clone();
    bad_magic[1] ^= 1;
    assert!(PrivacyProofEnvelopeV1::decode(&mut bad_magic.as_slice()).is_err());

    let mut bad_catalog = encoded;
    bad_catalog[catalog_offset] ^= 1;
    assert!(PrivacyProofEnvelopeV1::decode(&mut bad_catalog.as_slice()).is_err());
}

#[test]
fn exact12_protocol_labels_form_one_closed_namespace() {
    let mut exact12 = std::collections::BTreeSet::new();
    for protocol in PrivacyProtocolIdV1::ALL {
        let label = protocol.canonical_label();
        assert!(
            privacy_protocol_label_is_exact12_v1(label),
            "Exact12 label {label} must be recognized"
        );
        assert!(exact12.insert(label), "duplicate Exact12 label {label}");
    }
    assert_eq!(exact12.len(), PrivacyProtocolIdV1::COUNT);
    for label in exact12 {
        for near_miss in [
            format!("generic-{label}"),
            format!("{label}-generic"),
            format!(" {label}"),
            format!("{label} "),
            label.to_ascii_uppercase(),
        ] {
            assert!(
                !privacy_protocol_label_is_exact12_v1(&near_miss),
                "near-miss label {near_miss:?} must not alias {label:?}"
            );
        }
    }
}
#[test]
fn protocol_id_parser_rejects_aliases_retired_ids_and_noncanonical_text() {
    for label in [
        "",
        " ",
        " iroha-zk-ams-v1",
        "iroha-zk-ams-v1 ",
        "IROHA-ZK-AMS-V1",
        "zk-ams-recursive-admission-v0",
        "zk-x509-onchain-identity-v0",
        "jindo-lattice-pcs-zk-v0",
        "sis-hints-anoncred-pq-v0",
        "sis-with-hints",
        "iroha-bootle-genisis-ac-stark-v0",
        "miden-stark-note-v1",
        "pq-masp-stark-fri-v1",
        "zkat-policy-private-auth-v1",
        "silent-threshold-anoncred-v0",
        "penumbra-masp-v1",
        "aztec-private-rollup-v1",
        "iroha-zk-ams-v1\0",
        "iroha-zk-\u{200b}ams-v1",
        "iroha\u{ff0f}zk-ams-v1",
        "iroh\u{0430}-zk-ams-v1",
    ] {
        assert!(
            PrivacyProtocolIdV1::from_canonical_label(label).is_none(),
            "non-canonical protocol label {label:?} must fail"
        );
    }
}
fn assert_protocol_json_labels_roundtrip() {
    for protocol in PrivacyProtocolIdV1::ALL {
        let expected = format!(
            "{{\"protocol\":\"{}\",\"value\":null}}",
            protocol.canonical_label()
        );
        assert_eq!(
            norito::json::to_json(&protocol).expect("serialize protocol id"),
            expected
        );
        assert_eq!(
            norito::json::from_json::<PrivacyProtocolIdV1>(&expected)
                .expect("deserialize protocol id"),
            protocol
        );
        let limits = protocol_limits(protocol);
        let limits_json = norito::json::to_json(&limits).expect("serialize protocol limits");
        assert!(
            limits_json.starts_with(&format!(
                "{{\"protocol\":\"{}\",\"limits\":",
                protocol.canonical_label()
            )),
            "unexpected activation-limit label: {limits_json}"
        );
        assert_eq!(
            norito::json::from_json::<PrivacyProtocolActivationLimitsV1>(&limits_json)
                .expect("deserialize protocol limits"),
            limits
        );
    }
}
fn assert_proof_system_json_labels_roundtrip() {
    let proof_systems = [
        (
            PrivacyProofSystemIdV1::StarkFriSha3_384Goldilocks,
            "stark-fri-sha3-384-goldilocks-v1",
        ),
        (
            PrivacyProofSystemIdV1::ZkAmsMaskedRelaxedSpartanT256Ristretto255Sha3_512,
            "zk-ams-masked-relaxed-spartan-t256-ristretto255-sha3-512",
        ),
        (
            PrivacyProofSystemIdV1::AnonymousPgcP256,
            "anonymous-pgc-p256",
        ),
        (
            PrivacyProofSystemIdV1::IrohaVeRangeP256,
            "iroha-verange-p256",
        ),
        (
            PrivacyProofSystemIdV1::VegaNeutronNovaSpartanHyraxT256,
            "vega-neutron-nova-spartan-hyrax-t256",
        ),
        (
            PrivacyProofSystemIdV1::JindoPolynomialCommitment,
            "jindo-polynomial-commitment",
        ),
        (PrivacyProofSystemIdV1::Halo2IpaPasta, "halo2-ipa-pasta"),
        (
            PrivacyProofSystemIdV1::FcmpPlusPlusCurveTreeBulletproofs,
            "fcmp-plus-plus-curve-tree-bulletproofs",
        ),
        (
            PrivacyProofSystemIdV1::LanternLnp22ModuleLinearNorm,
            "lantern-lnp22-module-linear-norm",
        ),
    ];
    for (value, label) in proof_systems {
        let expected = format!("{{\"proof_system\":\"{label}\",\"value\":null}}");
        assert_eq!(
            norito::json::to_json(&value).expect("serialize proof-system id"),
            expected
        );
        assert_eq!(
            norito::json::from_json::<PrivacyProofSystemIdV1>(&expected)
                .expect("deserialize proof-system id"),
            value
        );
    }
}
fn assert_engine_json_labels_roundtrip() {
    let engines = [
        (
            PrivacyEngineIdV1::NativeGoldilocksSha3_384StarkFri,
            "native-goldilocks-sha3-384-stark-fri-v1",
        ),
        (
            PrivacyEngineIdV1::NativeZkAmsMaskedRelaxedSpartanT256Ristretto255,
            "native-zk-ams-masked-relaxed-spartan-t256-ristretto255",
        ),
        (
            PrivacyEngineIdV1::NativeAnonymousPgcP256,
            "native-anonymous-pgc-p256",
        ),
        (PrivacyEngineIdV1::NativeVeRangeP256, "native-verange-p256"),
        (PrivacyEngineIdV1::NativeVega, "native-vega"),
        (PrivacyEngineIdV1::NativeJindo, "native-jindo"),
        (
            PrivacyEngineIdV1::NativeHalo2Orchard,
            "native-halo2-orchard",
        ),
        (
            PrivacyEngineIdV1::NativeFcmpPlusPlus,
            "native-fcmp-plus-plus",
        ),
        (
            PrivacyEngineIdV1::NativeLanternLnp22,
            "native-lantern-lnp22",
        ),
    ];
    for (value, label) in engines {
        let expected = format!("{{\"engine\":\"{label}\",\"value\":null}}");
        assert_eq!(
            norito::json::to_json(&value).expect("serialize engine id"),
            expected
        );
        assert_eq!(
            norito::json::from_json::<PrivacyEngineIdV1>(&expected).expect("deserialize engine id"),
            value
        );
    }
}
fn assert_unavailable_reason_json_labels_roundtrip() {
    let unavailable = [
        (
            PrivacyCompiledProfileUnavailableReasonV1::EngineUnavailable,
            "{\"reason\":\"engine-unavailable\",\"detail\":null}",
        ),
        (
            PrivacyCompiledProfileUnavailableReasonV1::ProfileInitializationFailed,
            "{\"reason\":\"profile-initialization-failed\",\"detail\":null}",
        ),
        (
            PrivacyCompiledProfileUnavailableReasonV1::StatementSchemaInvalid(
                PrivacyCompiledStatementSchemaErrorV1::ConflictingStableTypeId,
            ),
            "{\"reason\":\"statement-schema-invalid\",\"detail\":{\"schema_error\":\"conflicting-stable-type-id\",\"detail\":null}}",
        ),
        (
            PrivacyCompiledProfileUnavailableReasonV1::StatementSchemaInvalid(
                PrivacyCompiledStatementSchemaErrorV1::MissingTypeReference,
            ),
            "{\"reason\":\"statement-schema-invalid\",\"detail\":{\"schema_error\":\"missing-type-reference\",\"detail\":null}}",
        ),
    ];
    for (value, expected) in unavailable {
        assert_eq!(
            norito::json::to_json(&value).expect("serialize unavailable reason"),
            expected
        );
        assert_eq!(
            norito::json::from_json::<PrivacyCompiledProfileUnavailableReasonV1>(expected)
                .expect("deserialize unavailable reason"),
            value
        );
    }
}
#[test]
fn privacy_public_json_labels_are_exact_and_roundtrip() {
    assert_protocol_json_labels_roundtrip();
    assert_proof_system_json_labels_roundtrip();
    assert_engine_json_labels_roundtrip();
    assert_unavailable_reason_json_labels_roundtrip();
    assert_eq!(
        norito::json::to_json(&PrivacySecurityModelV1::PostQuantumQrom)
            .expect("serialize security model"),
        "{\"security_model\":\"pq-qrom\",\"value\":null}"
    );
    let lifecycle = PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
        proposed_at_height: 1,
        activated_at_height: 2,
        state_since_height: 2,
    });
    assert_eq!(
        norito::json::to_json(&lifecycle).expect("serialize lifecycle"),
        "{\"state\":\"active\",\"record\":{\"proposed_at_height\":1,\"activated_at_height\":2,\"state_since_height\":2}}"
    );
}
#[test]
fn privacy_public_json_rejects_aliases_case_whitespace_confusables_and_unknown_fields() {
    for hostile in [
        "AnonymousPgcKOutOfNV1",
        "anonymous-pgc-k-out-of-n",
        "anonymous-pgc-k-out-of-n-v0",
        "ANONYMOUS-PGC-K-OUT-OF-N-V1",
        " anonymous-pgc-k-out-of-n-v1",
        "anonymous-pgc-k-out-of-n-v1 ",
        "anonymous\u{2010}pgc-k-out-of-n-v1",
        "anonym\u{043e}us-pgc-k-out-of-n-v1",
        "sis-hints-anoncred-pq-v0",
        "sis-with-hints",
        "iroha-bootle-genisis-ac-stark-v0",
        "unknown",
    ] {
        let json = format!("{{\"protocol\":\"{hostile}\",\"value\":null}}");
        assert!(
            norito::json::from_json::<PrivacyProtocolIdV1>(&json).is_err(),
            "hostile protocol JSON {json} must fail"
        );
    }
    for hostile in [
        "{\"protocol\":\"anonymous-pgc-k-out-of-n-v1\",\"value\":null,\"extra\":1}",
        "{\"protocol\":\"anonymous-pgc-k-out-of-n-v1\",\"protocol\":\"anonymous-pgc-k-out-of-n-v1\",\"value\":null}",
        "{\"proof_system\":\"AnonymousPgcP256\",\"value\":null}",
        "{\"proof_system\":\"anonymous-pgc-p256 \",\"value\":null}",
        "{\"proof_system\":\"stark-fri-poseidon2-goldilocks\",\"value\":null}",
        "{\"engine\":\"NativeAnonymousPgcP256\",\"value\":null}",
        "{\"engine\":\"native-anonymous-pgc-p25\u{ff16}\",\"value\":null}",
        "{\"reason\":\"EngineUnavailable\",\"detail\":null}",
        "{\"reason\":\"engine-unavailable\",\"detail\":null,\"extra\":false}",
        "{\"reason\":\"statement-schema-invalid\",\"detail\":{\"schema_error\":\"MissingTypeReference\",\"detail\":null}}",
        "{\"assurance\":\"production\",\"value\":null}",
        "{\"assurance\":\"Experimental\",\"value\":null}",
    ] {
        let rejected = norito::json::from_json::<PrivacyProtocolIdV1>(hostile).is_err()
            && norito::json::from_json::<PrivacyProofSystemIdV1>(hostile).is_err()
            && norito::json::from_json::<PrivacyEngineIdV1>(hostile).is_err()
            && norito::json::from_json::<PrivacyCompiledProfileUnavailableReasonV1>(hostile)
                .is_err()
            && norito::json::from_json::<PrivacySecurityModelV1>(hostile).is_err();
        assert!(rejected, "hostile closed-enum JSON {hostile} must fail");
    }
}
fn available_pgc_profile(
    snapshot: &PrivacyCapabilitySnapshotV1,
) -> PrivacyCompiledProfileSnapshotV1 {
    match snapshot.protocols[1].compiled_profile {
        PrivacyCompiledProfileResultV1::Available(profile) => profile,
        PrivacyCompiledProfileResultV1::Unavailable(_) => unreachable!("PGC fixture available"),
    }
}
fn assert_capability_snapshot_codecs(snapshot: &PrivacyCapabilitySnapshotV1) -> String {
    snapshot.validate().expect("valid capability snapshot");
    let archive = norito::to_bytes(snapshot).expect("encode snapshot");
    let decoded: PrivacyCapabilitySnapshotV1 =
        norito::decode_from_bytes(&archive).expect("decode snapshot");
    assert_eq!(decoded, *snapshot);
    decoded.validate().expect("validate decoded snapshot");
    let canonical = norito::json::to_json(snapshot).expect("serialize snapshot JSON");
    let decoded_json: PrivacyCapabilitySnapshotV1 =
        norito::json::from_json(&canonical).expect("decode snapshot JSON");
    assert_eq!(decoded_json, *snapshot);
    decoded_json.validate().expect("validate JSON snapshot");
    canonical
}
fn assert_capability_snapshot_json_adversaries(
    snapshot: &PrivacyCapabilitySnapshotV1,
    canonical: &str,
) {
    let unknown = canonical.replacen('{', "{\"unknown\":true,", 1);
    assert!(
        norito::json::from_json::<PrivacyCapabilitySnapshotV1>(&unknown).is_err(),
        "unknown top-level field must fail"
    );
    let duplicate = canonical.replacen('{', "{\"version\":1,", 1);
    assert!(
        norito::json::from_json::<PrivacyCapabilitySnapshotV1>(&duplicate).is_err(),
        "duplicate top-level field must fail"
    );
    let security_model = norito::json::to_json(&PrivacySecurityModelV1::ClassicalRom)
        .expect("canonical security model");
    let security_model_alias =
        security_model.replacen("\"classical-rom\"", "\"classical-rom-v1\"", 1);
    assert_ne!(security_model_alias, security_model);
    assert!(
        norito::json::from_json::<PrivacySecurityModelV1>(&security_model_alias).is_err(),
        "security-model aliases must fail"
    );
    let pgc_profile = available_pgc_profile(snapshot);
    let parameter_json =
        norito::json::to_json(&pgc_profile.parameter_id).expect("serialize fixed bytes");
    let malformed_fixed_bytes = canonical.replacen(
        &format!("\"parameter_id\":{parameter_json}"),
        "\"parameter_id\":[1]",
        1,
    );
    assert!(
        norito::json::from_json::<PrivacyCapabilitySnapshotV1>(&malformed_fixed_bytes).is_err(),
        "wrong-length fixed bytes must fail"
    );
    let out_of_range_fixed_bytes = canonical.replacen(
        &format!("\"parameter_id\":{parameter_json}"),
        "\"parameter_id\":[256,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
        1,
    );
    assert!(
        norito::json::from_json::<PrivacyCapabilitySnapshotV1>(&out_of_range_fixed_bytes).is_err(),
        "out-of-range fixed byte must fail"
    );
}
fn assert_capability_snapshot_structural_adversaries(snapshot: PrivacyCapabilitySnapshotV1) {
    let mut missing = snapshot.clone();
    missing.protocols.pop();
    assert!(matches!(
        missing.validate(),
        Err(PrivacyCapabilitySnapshotValidationErrorV1::ProtocolCount { .. })
    ));
    let mut duplicate_row = snapshot.clone();
    duplicate_row.protocols[2] = duplicate_row.protocols[1];
    assert!(matches!(
        duplicate_row.validate(),
        Err(PrivacyCapabilitySnapshotValidationErrorV1::ProtocolOrder { .. })
    ));
    let mut reordered = snapshot.clone();
    reordered.protocols.swap(0, 1);
    assert!(matches!(
        reordered.validate(),
        Err(PrivacyCapabilitySnapshotValidationErrorV1::ProtocolOrder { .. })
    ));
    let mut embedded_id_mismatch = snapshot.clone();
    embedded_id_mismatch.protocols[2].compiled_profile =
        PrivacyCompiledProfileResultV1::Available(available_pgc_profile(&snapshot));
    assert!(matches!(
        embedded_id_mismatch.validate(),
        Err(PrivacyCapabilitySnapshotValidationErrorV1::ProtocolRow {
            source: PrivacyCapabilityRowValidationErrorV1::CompiledProfileProtocolMismatch { .. },
            ..
        })
    ));
    let mut activation_profile_mismatch = snapshot.clone();
    activation_profile_mismatch.protocols[1]
        .activation
        .as_mut()
        .expect("PGC activation")
        .parameter_digest = PrivacyParameterDigestV1::new(raw(250));
    assert!(matches!(
        activation_profile_mismatch.validate(),
        Err(PrivacyCapabilitySnapshotValidationErrorV1::ProtocolRow {
            source: PrivacyCapabilityRowValidationErrorV1::ActivationProfileMismatch {
                field: PrivacyCapabilityBindingFieldV1::ParameterDigest,
            },
            ..
        })
    ));
    let mut unavailable_activation = snapshot;
    unavailable_activation.protocols[2].activation = Some(activation(&envelope(statement_for(
        PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
    ))));
    assert!(matches!(
        unavailable_activation.validate(),
        Err(PrivacyCapabilitySnapshotValidationErrorV1::ProtocolRow {
            source: PrivacyCapabilityRowValidationErrorV1::UnavailableActivation { .. },
            ..
        })
    ));
}
#[test]
fn capability_snapshot_roundtrips_and_rejects_structural_adversaries() {
    let snapshot = capability_snapshot();
    let canonical = assert_capability_snapshot_codecs(&snapshot);
    assert_capability_snapshot_json_adversaries(&snapshot, &canonical);
    assert_capability_snapshot_structural_adversaries(snapshot);
}
#[test]
fn compiled_profile_catalog_roundtrips_and_has_no_governance_projection() {
    let catalog = compiled_profile_catalog();
    catalog.validate().expect("valid compiled-profile catalog");
    assert_eq!(catalog.protocols.len(), PrivacyProtocolIdV1::COUNT);
    assert!(
        catalog
            .protocols
            .iter()
            .map(|row| row.protocol_id)
            .eq(PrivacyProtocolIdV1::ALL)
    );
    let archive = norito::to_bytes(&catalog).expect("encode catalog");
    let decoded: PrivacyCompiledProfileCatalogV1 =
        norito::decode_from_bytes(&archive).expect("decode catalog");
    assert_eq!(decoded, catalog);
    let json = norito::json::to_json(&catalog).expect("encode catalog JSON");
    let decoded_json: PrivacyCompiledProfileCatalogV1 =
        norito::json::from_json(&json).expect("decode catalog JSON");
    assert_eq!(decoded_json, catalog);
    for governance_field in [
        "committed_height",
        "consensus_policy",
        "activation",
        "lifecycle",
        "readiness",
        "activation_state",
        "manifest_digest",
    ] {
        assert!(
            !json.contains(&format!("\"{governance_field}\":")),
            "local catalog must not project governance field {governance_field}"
        );
    }
    let unknown = json.replacen('{', "{\"committed_height\":0,", 1);
    assert!(
        norito::json::from_json::<PrivacyCompiledProfileCatalogV1>(&unknown).is_err(),
        "a governance-shaped field must fail closed"
    );
    let duplicate = json.replacen('{', "{\"version\":1,", 1);
    assert!(
        norito::json::from_json::<PrivacyCompiledProfileCatalogV1>(&duplicate).is_err(),
        "duplicate top-level field must fail closed"
    );
}
#[test]
fn compiled_profile_catalog_rejects_missing_duplicate_reordered_and_mutated_rows() {
    let catalog = compiled_profile_catalog();
    let mut missing = catalog.clone();
    missing.protocols.pop();
    assert!(matches!(
        missing.validate(),
        Err(PrivacyCompiledProfileCatalogValidationErrorV1::ProtocolCount { .. })
    ));
    let mut duplicate = catalog.clone();
    duplicate.protocols[2] = duplicate.protocols[1];
    assert!(matches!(
        duplicate.validate(),
        Err(PrivacyCompiledProfileCatalogValidationErrorV1::ProtocolOrder { .. })
    ));
    let mut reordered = catalog.clone();
    reordered.protocols.swap(0, 1);
    assert!(matches!(
        reordered.validate(),
        Err(PrivacyCompiledProfileCatalogValidationErrorV1::ProtocolOrder { .. })
    ));
    let mut profile_id_mismatch = catalog.clone();
    profile_id_mismatch.protocols[2].compiled_profile =
        profile_id_mismatch.protocols[1].compiled_profile;
    assert!(matches!(
            profile_id_mismatch.validate(),
            Err(PrivacyCompiledProfileCatalogValidationErrorV1::ProtocolRow {
                source:
                    PrivacyCompiledProfileCatalogRowValidationErrorV1::CompiledProfileProtocolMismatch {
                        ..
                    },
                ..
            })
        ));
    let mut binding_mutation = catalog;
    let PrivacyCompiledProfileResultV1::Available(profile) =
        &mut binding_mutation.protocols[1].compiled_profile
    else {
        panic!("PGC fixture must have a compiled profile");
    };
    profile.parameter_digest = PrivacyParameterDigestV1::new([0; 32]);
    assert!(matches!(
        binding_mutation.validate(),
        Err(
            PrivacyCompiledProfileCatalogValidationErrorV1::ProtocolRow {
                source: PrivacyCompiledProfileCatalogRowValidationErrorV1::CompiledProfile(
                    PrivacyCompiledProfileSnapshotValidationErrorV1::ZeroParameterDigest
                ),
                ..
            }
        )
    ));
}
#[test]
fn canonical_compiled_profile_catalog_validator_is_bounded_and_fail_closed() {
    use PrivacyCompiledProfileCatalogArchiveValidationStatusV1 as Status;
    assert_eq!(
        PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1,
        256 * 1024
    );
    assert_eq!(Status::Valid.code(), 0);
    assert_eq!(Status::NullPointer.code(), 1);
    assert_eq!(Status::Empty.code(), 2);
    assert_eq!(Status::ArchiveTooLarge.code(), 3);
    assert_eq!(Status::DecodeResourceLimit.code(), 4);
    assert_eq!(Status::SchemaMismatch.code(), 5);
    assert_eq!(Status::NonCanonical.code(), 6);
    assert_eq!(Status::MalformedArchive.code(), 7);
    assert_eq!(Status::InvalidCatalog.code(), 8);
    let catalog = compiled_profile_catalog();
    let archive = norito::encode_canonical(&catalog).expect("canonical catalog archive");
    assert_eq!(
        validate_privacy_compiled_profile_catalog_archive_v1(&archive),
        Status::Valid
    );
    assert_eq!(
        validate_privacy_compiled_profile_catalog_archive_v1(&[]),
        Status::Empty
    );
    assert_eq!(
        validate_privacy_compiled_profile_catalog_archive_v1(&vec![
            0;
            PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1
                + 1
        ]),
        Status::ArchiveTooLarge
    );
    for truncated in [
        &archive[..archive.len() - 1],
        &archive[1..],
        &archive[..archive.len() / 2],
    ] {
        assert_ne!(
            validate_privacy_compiled_profile_catalog_archive_v1(truncated),
            Status::Valid
        );
    }
    let mut trailing = archive.clone();
    trailing.push(0);
    assert_ne!(
        validate_privacy_compiled_profile_catalog_archive_v1(&trailing),
        Status::Valid
    );
    let mut wrong_schema = archive.clone();
    wrong_schema[6] ^= 0x80;
    assert_eq!(
        validate_privacy_compiled_profile_catalog_archive_v1(&wrong_schema),
        Status::SchemaMismatch
    );
    let mut reordered = catalog.clone();
    reordered.protocols.swap(0, 1);
    assert_eq!(
        validate_privacy_compiled_profile_catalog_archive_v1(
            &norito::encode_canonical(&reordered).expect("canonical reordered catalog")
        ),
        Status::InvalidCatalog
    );
    let mut duplicate = catalog.clone();
    duplicate.protocols[2] = duplicate.protocols[1];
    assert_eq!(
        validate_privacy_compiled_profile_catalog_archive_v1(
            &norito::encode_canonical(&duplicate).expect("canonical duplicate catalog")
        ),
        Status::InvalidCatalog
    );
    let mut mutation = catalog.clone();
    let PrivacyCompiledProfileResultV1::Available(profile) =
        &mut mutation.protocols[1].compiled_profile
    else {
        panic!("PGC fixture must have a compiled profile");
    };
    profile.verifier_digest = PrivacyVerifierDigestV1::new([0; 32]);
    assert_eq!(
        validate_privacy_compiled_profile_catalog_archive_v1(
            &norito::encode_canonical(&mutation).expect("canonical mutated catalog")
        ),
        Status::InvalidCatalog
    );
    let mut excessive_rows = catalog;
    excessive_rows.protocols.push(excessive_rows.protocols[0]);
    assert_eq!(
        validate_privacy_compiled_profile_catalog_archive_v1(
            &norito::encode_canonical(&excessive_rows).expect("canonical excessive catalog")
        ),
        Status::DecodeResourceLimit
    );
}
#[test]
fn canonical_capability_archive_validator_is_bounded_typed_and_fail_closed() {
    use PrivacyCapabilityArchiveValidationStatusV1 as Status;
    assert_eq!(PRIVACY_BRIDGE_ABI_VERSION_V1, 31);
    assert_eq!(PRIVACY_CAPABILITY_ARCHIVE_MAX_BYTES_V1, 256 * 1024);
    assert_eq!(Status::Valid.code(), 0);
    assert_eq!(Status::NullPointer.code(), 1);
    assert_eq!(Status::Empty.code(), 2);
    assert_eq!(Status::ArchiveTooLarge.code(), 3);
    assert_eq!(Status::DecodeResourceLimit.code(), 4);
    assert_eq!(Status::SchemaMismatch.code(), 5);
    assert_eq!(Status::NonCanonical.code(), 6);
    assert_eq!(Status::MalformedArchive.code(), 7);
    assert_eq!(Status::InvalidManifest.code(), 8);
    let manifest = exact12_capability_manifest();
    let archive = norito::encode_canonical(&manifest).expect("canonical capability archive");
    assert_eq!(
        validate_privacy_capability_archive_v1(&archive),
        Status::Valid
    );
    assert_eq!(validate_privacy_capability_archive_v1(&[]), Status::Empty);
    assert_eq!(
        validate_privacy_capability_archive_v1(&vec![
            0;
            PRIVACY_CAPABILITY_ARCHIVE_MAX_BYTES_V1 + 1
        ]),
        Status::ArchiveTooLarge
    );
    assert_eq!(
        validate_privacy_capability_archive_v1(&archive[..archive.len() - 1]),
        Status::MalformedArchive
    );
    let mut wrong_schema = archive.clone();
    wrong_schema[6] ^= 0x80;
    assert_eq!(
        validate_privacy_capability_archive_v1(&wrong_schema),
        Status::SchemaMismatch
    );
    // Preserve a valid CRC over a one-byte payload while substituting the
    // expected manifest schema. Header-only validation used to accept this
    // exact adversary; the typed decoder must reject it.
    let mut one_byte_fake = norito::encode_canonical(&0_u8).expect("canonical one-byte value");
    one_byte_fake[6..22].copy_from_slice(&archive[6..22]);
    assert_eq!(
        validate_privacy_capability_archive_v1(&one_byte_fake),
        Status::MalformedArchive
    );
    let legacy_snapshot =
        norito::encode_canonical(&capability_snapshot()).expect("canonical legacy snapshot");
    assert_eq!(
        validate_privacy_capability_archive_v1(&legacy_snapshot),
        Status::SchemaMismatch,
        "the manifest validator must reject the old snapshot schema outright"
    );
    let mut reordered = manifest.clone();
    reordered.protocols.swap(0, 1);
    let reordered =
        norito::encode_canonical(&reordered).expect("canonical reordered manifest bytes");
    assert_eq!(
        validate_privacy_capability_archive_v1(&reordered),
        Status::InvalidManifest
    );
    let mut profile_mutation = manifest.clone();
    let PrivacyCompiledProfileResultV1::Available(profile) =
        &mut profile_mutation.protocols[1].compiled_profile
    else {
        panic!("PGC fixture must have a compiled profile");
    };
    profile.parameter_digest = PrivacyParameterDigestV1::new([0; 32]);
    let profile_mutation =
        norito::encode_canonical(&profile_mutation).expect("canonical invalid-profile bytes");
    assert_eq!(
        validate_privacy_capability_archive_v1(&profile_mutation),
        Status::InvalidManifest
    );
    let mut activation_mutation = manifest.clone();
    activation_mutation.protocols[1]
        .activation
        .as_mut()
        .expect("PGC fixture activation")
        .parameter_digest = PrivacyParameterDigestV1::new(raw(250));
    let activation_mutation = norito::encode_canonical(&activation_mutation)
        .expect("canonical activation-mismatch bytes");
    assert_eq!(
        validate_privacy_capability_archive_v1(&activation_mutation),
        Status::InvalidManifest
    );
    let mut excessive_rows = manifest;
    excessive_rows.protocols.push(excessive_rows.protocols[0]);
    let excessive_rows =
        norito::encode_canonical(&excessive_rows).expect("canonical excessive-row bytes");
    assert_eq!(
        validate_privacy_capability_archive_v1(&excessive_rows),
        Status::InvalidManifest
    );
}
#[test]
fn all_protocol_mappings_and_typed_variants_are_exact() {
    let statements = sample_statements();
    assert_eq!(statements.len(), PrivacyProtocolIdV1::COUNT);
    for (protocol, statement) in PrivacyProtocolIdV1::ALL.into_iter().zip(statements) {
        assert_eq!(statement.protocol_id(), protocol);
        let proof = proof_for(protocol);
        assert_eq!(proof.protocol_id(), protocol);
        assert_eq!(
            statement_variant_name(&statement),
            protocol.canonical_typed_variant_label()
        );
        assert_eq!(
            proof_variant_name(&proof),
            protocol.canonical_typed_variant_label()
        );
        assert_eq!(
            protocol_limits(protocol).protocol_id(),
            protocol,
            "activation limits must carry the same closed protocol tag"
        );
    }
    assert_eq!(
        PrivacyProtocolIdV1::VeRangeTransparentRangeV1.expected_proof_system(),
        PrivacyProofSystemIdV1::IrohaVeRangeP256
    );
    assert_eq!(
        PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1.expected_proof_system(),
        PrivacyProofSystemIdV1::JindoPolynomialCommitment
    );
    assert_eq!(
        PrivacyProtocolIdV1::IrohaZkAmsV1.expected_proof_system(),
        PrivacyProofSystemIdV1::ZkAmsMaskedRelaxedSpartanT256Ristretto255Sha3_512
    );
    assert_eq!(
        PrivacyProtocolIdV1::IrohaZkAmsV1.expected_engine(),
        PrivacyEngineIdV1::NativeZkAmsMaskedRelaxedSpartanT256Ristretto255
    );
    for protocol in [
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        PrivacyProtocolIdV1::PqMaspStarkV1,
    ] {
        assert_eq!(
            protocol.expected_proof_system(),
            PrivacyProofSystemIdV1::StarkFriSha3_384Goldilocks,
            "{protocol:?} must identify the SHA3-384 transcript/Merkle STARK"
        );
    }
}
#[test]
fn exact12_typed_fixture_bundle_is_byte_complete_bounded_and_mutation_closed() {
    use crate::{
        isi::privacy::SubmitPrivacyProofV1,
        transaction::{SignedTransaction, TransactionBuilder},
    };
    use PrivacyExact12FixtureBundleValidationStatusV1 as Status;
    use iroha_version::codec::{DecodeVersioned as _, EncodeVersioned as _};
    let bundle = privacy_exact12_fixture_bundle_v1().expect("typed exact12 fixture bundle");
    let archive =
        privacy_exact12_fixture_bundle_bytes_v1().expect("canonical exact12 fixture archive");
    assert_eq!(bundle.version, 1);
    assert_eq!(bundle.rows.len(), PrivacyProtocolIdV1::COUNT);
    assert!(archive.len() <= PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1);
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&archive),
        Status::Valid
    );
    for (row, expected_protocol) in bundle.rows.iter().zip(PrivacyProtocolIdV1::ALL) {
        assert_eq!(row.protocol_id, expected_protocol);
        let statement: PrivacyStatementV1 =
            norito::decode_from_bytes(&row.statement_norito).expect("typed statement");
        assert_eq!(statement.protocol_id(), expected_protocol);
        assert_eq!(
            norito::encode_canonical(&statement).expect("canonical statement"),
            row.statement_norito
        );
        let envelope: PrivacyProofEnvelopeV1 =
            norito::decode_from_bytes(&row.envelope_norito).expect("typed envelope");
        assert_eq!(envelope.protocol_id, expected_protocol);
        assert_eq!(envelope.statement, statement);
        envelope
            .validate_with_limits(&PrivacyConsensusLimitsV1::default())
            .expect("intrinsically valid sample envelope");
        assert_eq!(
            norito::encode_canonical(&envelope).expect("canonical envelope"),
            row.envelope_norito
        );
        assert_eq!(
            row.submit_proof_wire_id,
            SubmitPrivacyProofV1::WIRE_ID,
            "fixture must bind the only first-release submission wire id"
        );
        let submission: SubmitPrivacyProofV1 =
            norito::decode_from_bytes(&row.submit_proof_instruction_norito)
                .expect("typed SubmitPrivacyProofV1 instruction");
        assert_eq!(submission.envelope, envelope);
        assert_eq!(
            norito::encode_canonical(&submission).expect("canonical submission instruction"),
            row.submit_proof_instruction_norito
        );
        let unsigned_builder =
            TransactionBuilder::decode_payload(&row.unsigned_transaction_payload_norito)
                .expect("canonical unsigned transaction payload");
        let unsigned_payload = unsigned_builder.payload().clone();
        assert_eq!(
            unsigned_payload.domain,
            crate::transaction::TransactionDomain::Network(statement.context().network_id),
            "the signed transaction and every proof must target the same network"
        );
        assert_eq!(
            unsigned_payload
                .privacy_transaction_intent_projection_bytes_v1()
                .expect("canonical normalized privacy projection"),
            row.transaction_intent_projection_norito
        );
        let intent = unsigned_payload
            .validate_privacy_transaction_intent_binding_v1()
            .expect("exactly one transaction-bound privacy submission");
        assert_eq!(intent.as_bytes(), &row.transaction_intent_digest);
        assert_ne!(
            row.transaction_intent_projection_norito, row.unsigned_transaction_payload_norito,
            "the signed payload must retain proof bytes while the intent projection removes them"
        );
        let signed =
            SignedTransaction::decode_all_versioned(&row.signed_transaction_versioned_norito)
                .expect("canonical versioned signed transaction");
        signed
            .verify_signature()
            .expect("deterministic fixture signature");
        assert_eq!(signed.payload(), &unsigned_payload);
        assert_eq!(
            signed.encode_versioned(),
            row.signed_transaction_versioned_norito
        );
        assert_eq!(signed.hash().as_ref(), &row.signed_transaction_hash);
    }
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&[]),
        Status::Empty
    );
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&vec![
            0;
            PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1
                + 1
        ]),
        Status::ArchiveTooLarge
    );
    let truncated = &archive[..archive.len() - 1];
    assert!(
        !validate_privacy_exact12_fixture_bundle_v1(truncated).is_valid(),
        "truncated outer archive must reject"
    );
    let mut trailing = archive.clone();
    trailing.push(0);
    assert!(
        !validate_privacy_exact12_fixture_bundle_v1(&trailing).is_valid(),
        "trailing outer bytes must reject"
    );
    let mut wrong_version = bundle.clone();
    wrong_version.version = 2;
    let wrong_version =
        norito::encode_canonical(&wrong_version).expect("canonical wrong-version mutation");
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&wrong_version),
        Status::InvalidBundle
    );
    let mut reordered = bundle.clone();
    reordered.rows.swap(0, 1);
    let reordered = norito::encode_canonical(&reordered).expect("canonical reordered mutation");
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&reordered),
        Status::InvalidBundle
    );
    let mut cross_protocol = bundle.clone();
    cross_protocol.rows[0].protocol_id = PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1;
    let cross_protocol =
        norito::encode_canonical(&cross_protocol).expect("canonical cross-protocol mutation");
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&cross_protocol),
        Status::InvalidBundle
    );
    let mut stale_statement = bundle.clone();
    stale_statement.rows[0].statement_norito[0] ^= 1;
    let stale_statement =
        norito::encode_canonical(&stale_statement).expect("canonical stale-statement mutation");
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&stale_statement),
        Status::InvalidBundle
    );
    let mut stale_envelope = bundle.clone();
    let final_byte = stale_envelope.rows[11].envelope_norito.len() - 1;
    stale_envelope.rows[11].envelope_norito[final_byte] ^= 1;
    let stale_envelope =
        norito::encode_canonical(&stale_envelope).expect("canonical stale-envelope mutation");
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&stale_envelope),
        Status::InvalidBundle
    );
    let mut wrong_wire_id = bundle.clone();
    wrong_wire_id.rows[0].submit_proof_wire_id.push('x');
    let wrong_wire_id =
        norito::encode_canonical(&wrong_wire_id).expect("canonical wrong-wire-id mutation");
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&wrong_wire_id),
        Status::InvalidBundle
    );
    let mut stale_instruction = bundle.clone();
    stale_instruction.rows[1].submit_proof_instruction_norito[0] ^= 1;
    let stale_instruction =
        norito::encode_canonical(&stale_instruction).expect("canonical stale-instruction mutation");
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&stale_instruction),
        Status::InvalidBundle
    );
    let mut stale_projection = bundle.clone();
    stale_projection.rows[2].transaction_intent_projection_norito[0] ^= 1;
    let stale_projection =
        norito::encode_canonical(&stale_projection).expect("canonical stale-projection mutation");
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&stale_projection),
        Status::InvalidBundle
    );
    let mut stale_intent = bundle.clone();
    stale_intent.rows[3].transaction_intent_digest[0] ^= 1;
    let stale_intent =
        norito::encode_canonical(&stale_intent).expect("canonical stale-intent mutation");
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&stale_intent),
        Status::InvalidBundle
    );
    let mut stale_unsigned = bundle.clone();
    stale_unsigned.rows[4].unsigned_transaction_payload_norito[0] ^= 1;
    let stale_unsigned = norito::encode_canonical(&stale_unsigned)
        .expect("canonical stale-unsigned-payload mutation");
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&stale_unsigned),
        Status::InvalidBundle
    );
    let mut stale_signed = bundle.clone();
    stale_signed.rows[5].signed_transaction_versioned_norito[0] ^= 1;
    let stale_signed = norito::encode_canonical(&stale_signed)
        .expect("canonical stale-signed-transaction mutation");
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&stale_signed),
        Status::InvalidBundle
    );
    let mut stale_transaction_hash = bundle;
    stale_transaction_hash.rows[6].signed_transaction_hash[0] ^= 1;
    let stale_transaction_hash = norito::encode_canonical(&stale_transaction_hash)
        .expect("canonical stale-transaction-hash mutation");
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&stale_transaction_hash),
        Status::InvalidBundle
    );
}
#[test]
#[ignore = "explicit regeneration helper for fixtures/privacy/exact12_v1.tsv"]
fn emit_exact12_typed_envelope_fixture_rows() {
    for row in privacy_exact12_typed_envelope_rows_v1().expect("compiled exact12 semantics") {
        println!(
            "typed-envelope\t{}\t{}\t{}\t{}\t{}",
            row.protocol_id.canonical_label(),
            row.statement_variant,
            row.proof_variant,
            hex::encode(row.statement_digest),
            hex::encode(row.envelope_sha256)
        );
    }
}
#[test]
#[ignore = "explicit complete regeneration helper for fixtures/privacy/exact12_v1.tsv"]
fn emit_exact12_matrix_fixture() {
    let bytes = privacy_exact12_matrix_bytes_v1().expect("compiled exact12 matrix");
    print!(
        "{}",
        std::str::from_utf8(&bytes).expect("exact12 generator emits UTF-8")
    );
}
#[test]
#[ignore = "explicit regeneration helper for fixtures/privacy/exact12_typed_fixture_bundle_v1.norito.b64"]
fn emit_exact12_fixture_bundle_base64() {
    use base64::Engine as _;
    let bytes = privacy_exact12_fixture_bundle_bytes_v1().expect("compiled exact12 fixture");
    println!(
        "{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    );
}
#[test]
fn exact12_checked_in_fixture_bundle_is_canonical_and_current() {
    use base64::Engine as _;
    let encoded =
        include_str!("../../../../../fixtures/privacy/exact12_typed_fixture_bundle_v1.norito.b64");
    assert_eq!(
        encoded.bytes().filter(|byte| *byte == b'\n').count(),
        1,
        "exact12 base64 fixture must contain exactly one terminal LF",
    );
    let payload = encoded
        .strip_suffix('\n')
        .expect("exact12 base64 fixture must end with exactly one LF");
    assert!(
        !payload.is_empty(),
        "exact12 base64 fixture must not be empty"
    );
    assert!(
        !payload.bytes().any(|byte| byte.is_ascii_whitespace()),
        "exact12 base64 fixture must be a single unwrapped line"
    );
    let archive = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .expect("exact12 fixture must use STANDARD base64");
    assert!(
        archive.len() <= PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1,
        "decoded exact12 fixture exceeds the native archive ceiling"
    );
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(&archive),
        payload,
        "exact12 fixture must use the canonical padded base64 spelling"
    );
    let expected = privacy_exact12_fixture_bundle_bytes_v1().expect("compiled exact12 fixture");
    assert_eq!(
        archive, expected,
        "checked-in exact12 archive must be regenerated from compiled Rust types"
    );
    assert_eq!(
        validate_privacy_exact12_fixture_bundle_v1(&archive),
        PrivacyExact12FixtureBundleValidationStatusV1::Valid
    );
}
#[test]
fn exact12_cross_sdk_matrix_binds_registry_routes_and_typed_envelopes() {
    let matrix = include_str!("../../../../../fixtures/privacy/exact12_v1.tsv");
    let generated = privacy_exact12_matrix_bytes_v1().expect("generate compiled exact12 matrix");
    assert_eq!(
        matrix.as_bytes(),
        generated,
        "checked-in exact12 matrix must be regenerated from compiled typed semantics"
    );
    assert!(matrix.ends_with('\n'), "matrix must end with one LF");
    assert!(!matrix.contains('\r'), "matrix must use canonical LF lines");
    assert!(
        matrix
            .strip_suffix('\n')
            .expect("terminal LF")
            .lines()
            .all(|line| !line.is_empty()),
        "matrix must not contain empty rows"
    );
    let mut matrix_version = None;
    let mut registry_sha256 = None;
    let mut protocols = Vec::new();
    let mut typed_envelopes = Vec::new();
    for (line_index, line) in matrix.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        match fields.as_slice() {
            ["matrix-version", version] => {
                assert!(
                    matrix_version.replace(*version).is_none(),
                    "duplicate version"
                );
            }
            ["registry-sha256", digest] => {
                assert!(
                    registry_sha256.replace(*digest).is_none(),
                    "duplicate registry digest"
                );
            }
            ["protocol", index, label, statement_variant, proof_variant] => {
                protocols.push((
                    index.parse::<usize>().expect("decimal protocol index"),
                    *label,
                    *statement_variant,
                    *proof_variant,
                ));
            }
            [
                "typed-envelope",
                label,
                statement_variant,
                proof_variant,
                statement_digest,
                envelope_sha256,
            ] => typed_envelopes.push((
                *label,
                *statement_variant,
                *proof_variant,
                *statement_digest,
                *envelope_sha256,
            )),
            _ => panic!("malformed exact12 matrix row {}", line_index + 1),
        }
    }
    assert_eq!(matrix_version, Some("1"));
    assert_eq!(protocols.len(), PrivacyProtocolIdV1::COUNT);
    assert_eq!(typed_envelopes.len(), PrivacyProtocolIdV1::COUNT);
    let semantic_rows =
        privacy_exact12_typed_envelope_rows_v1().expect("compiled exact12 semantics");
    assert_eq!(semantic_rows.len(), PrivacyProtocolIdV1::COUNT);
    let mut registry_preimage = String::new();
    let mut unique_labels = std::collections::BTreeSet::new();
    for (expected_index, (protocol, semantic)) in PrivacyProtocolIdV1::ALL
        .into_iter()
        .zip(&semantic_rows)
        .enumerate()
    {
        let (index, label, expected_statement_variant, expected_proof_variant) =
            protocols[expected_index];
        assert_eq!(index, expected_index);
        assert_eq!(label, protocol.canonical_label());
        assert_eq!(semantic.protocol_id, protocol);
        assert_eq!(
            PrivacyProtocolIdV1::from_canonical_label(label),
            Some(protocol)
        );
        assert!(unique_labels.insert(label), "duplicate protocol label");
        assert_eq!(semantic.statement_variant, expected_statement_variant);
        assert_eq!(semantic.proof_variant, expected_proof_variant);
        registry_preimage.push_str(label);
        registry_preimage.push('\n');
    }
    assert_eq!(
        hex::encode(Sha256::digest(registry_preimage.as_bytes())),
        registry_sha256.expect("registry digest")
    );
    for (semantic, row) in semantic_rows.iter().zip(typed_envelopes) {
        let (
            label,
            expected_statement_variant,
            expected_proof_variant,
            expected_statement_digest,
            expected_envelope_sha256,
        ) = row;
        assert_eq!(
            PrivacyProtocolIdV1::from_canonical_label(label),
            Some(semantic.protocol_id)
        );
        assert_eq!(semantic.statement_variant, expected_statement_variant);
        assert_eq!(semantic.proof_variant, expected_proof_variant);
        for expected_digest in [expected_statement_digest, expected_envelope_sha256] {
            assert_eq!(expected_digest.len(), 64);
            assert!(
                expected_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "typed envelope digest must be canonical lowercase hex"
            );
            assert!(
                expected_digest.bytes().any(|byte| byte != b'0'),
                "typed envelope digest must not be the zero placeholder"
            );
        }
        assert_eq!(
            hex::encode(semantic.statement_digest),
            expected_statement_digest
        );
        assert_eq!(
            hex::encode(semantic.envelope_sha256),
            expected_envelope_sha256
        );
    }
}
#[test]
fn exact12_compiled_semantics_are_closed_unique_and_context_bound() {
    let rows = privacy_exact12_typed_envelope_rows_v1().expect("compiled exact12 semantics");
    assert_eq!(rows.len(), PrivacyProtocolIdV1::COUNT);
    assert_eq!(
        rows.iter().map(|row| row.protocol_id).collect::<Vec<_>>(),
        PrivacyProtocolIdV1::ALL.to_vec()
    );
    assert!(rows.iter().all(|row| {
        row.statement_variant == row.protocol_id.canonical_typed_variant_label()
            && row.proof_variant == row.protocol_id.canonical_typed_variant_label()
            && row.statement_digest != [0; 32]
            && row.envelope_sha256 != [0; 32]
    }));
    assert_eq!(
        rows.iter()
            .map(|row| row.statement_digest)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        PrivacyProtocolIdV1::COUNT
    );
    assert_eq!(
        rows.iter()
            .map(|row| row.envelope_sha256)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        PrivacyProtocolIdV1::COUNT
    );
    let mut mutated = statement_for(PrivacyProtocolIdV1::ZkAcePqAuthorizationV1);
    let PrivacyStatementV1::ZkAcePqAuthorizationV1(statement) = &mut mutated else {
        unreachable!("closed first row is ZK-ACE")
    };
    statement.context.action_index = 1;
    let mutated_statement_digest = mutated.digest().expect("mutated statement digest");
    let mutated_envelope_sha256: [u8; 32] = Sha256::digest(
        norito::encode_canonical(&envelope(mutated)).expect("mutated canonical envelope"),
    )
    .into();
    assert_ne!(
        *mutated_statement_digest.as_bytes(),
        rows[0].statement_digest
    );
    assert_ne!(mutated_envelope_sha256, rows[0].envelope_sha256);
}
#[test]
fn fixed_digest_types_are_exact_and_nonzero_checked() {
    macro_rules! check_type {
        ($type:ident, $seed:expr) => {{
            let value = $type::new(raw($seed));
            assert_eq!(value.as_bytes(), &raw($seed));
            assert_eq!(value.into_bytes(), raw($seed));
            assert!(!value.is_zero());
            assert!($type::new([0; 32]).is_zero());
            assert_fixed_width_norito(&value, &raw($seed));
            let encoded = value.encode();
            // Bare Norito encodes a fixed byte-array field as one
            // canonical compact-width prefix followed by exactly 32
            // bytes. No variable-length payload is admitted.
            assert_eq!(encoded.len(), 33);
            assert_eq!(
                $type::decode(&mut encoded.as_slice()).expect("decode fixed value"),
                value
            );
        }};
    }
    check_type!(PrivacyParameterIdV1, 1);
    check_type!(PrivacyParameterDigestV1, 2);
    check_type!(PrivacyVerifierDigestV1, 3);
    check_type!(PrivacyStatementSchemaDigestV1, 4);
    check_type!(PrivacyEngineManifestDigestV1, 5);
    check_type!(PrivacyExact12CapabilityManifestDigestV1, 24);
    check_type!(PrivacySecurityReductionDigestV1, 25);
    check_type!(PrivacySecurityClaimDigestV1, 26);
    check_type!(PrivacyExact12ReleaseManifestDigestV1, 27);
    check_type!(PrivacyExact12DeploymentQualificationDigestV1, 28);
    check_type!(PrivacyAuditBundleDigestV1, 29);
    check_type!(PrivacyStatementDigestV1, 6);
    check_type!(PrivacyTransactionIntentDigestV1, 17);
    check_type!(PrivacyOrchardPoolBootstrapDigestV1, 20);
    check_type!(PrivacyProofManagedPoolBootstrapDigestV1, 21);
    check_type!(PrivacyFcmpOutputIdV1, 22);
    check_type!(PrivacyFcmpKeyImageV1, 23);
    check_type!(PrivacyBootleLanternIssuerPolicyDigestV1, 18);
    check_type!(PrivacyNullifierV1, 7);
    check_type!(PrivacyCommitmentV1, 8);
    check_type!(PrivacyPoolIdV1, 9);
    check_type!(PrivacyZkAmsRegistryIdV1, 10);
    check_type!(PrivacyPolicyIdV1, 10);
    check_type!(PrivacyRootV1, 11);
    check_type!(PrivacyChallengeV1, 12);
    check_type!(PrivacyZkAmsPhcHashV1, 13);
    check_type!(PrivacyZkAmsSubjectCommitmentV1, 14);
    check_type!(PrivacyZkAmsCredentialNonceV1, 15);
    check_type!(PrivacyZkAmsIssuerPolicyRecordDigestV1, 16);
    check_type!(PrivacyZkAmsRegistryRecordDigestV1, 19);
}
#[test]
fn all_statements_and_envelopes_roundtrip_and_validate() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    for statement in sample_statements() {
        statement.validate(&limits).expect("valid typed statement");
        let statement_bytes = norito::to_bytes(&statement).expect("frame statement");
        let decoded_statement: PrivacyStatementV1 =
            norito::decode_from_bytes(&statement_bytes).expect("decode statement");
        assert_eq!(decoded_statement, statement);
        assert_eq!(
            decoded_statement.digest().expect("decoded digest"),
            statement.digest().expect("original digest")
        );
        let envelope = envelope(statement);
        envelope
            .validate_with_limits(&limits)
            .expect("valid intrinsic envelope");
        let activation = activation(&envelope);
        activation.validate().expect("valid activation");
        envelope
            .validate_against_activation(&activation, &limits, 2)
            .expect("valid active envelope");
        let bytes = norito::to_bytes(&envelope).expect("frame envelope");
        let decoded: PrivacyProofEnvelopeV1 =
            norito::decode_from_bytes(&bytes).expect("decode envelope");
        assert_eq!(decoded, envelope);
    }
}
#[test]
fn canonical_privacy_byte_limits_ignore_ambient_layout_flags() {
    for statement in sample_statements() {
        let statement_bytes = u32::try_from(
            norito::encode_canonical(&statement)
                .expect("canonical statement")
                .len(),
        )
        .expect("fixture size fits u32");
        let envelope = envelope(statement);
        let envelope_bytes = u32::try_from(
            norito::encode_canonical(&envelope)
                .expect("canonical envelope")
                .len(),
        )
        .expect("fixture size fits u32");
        let limits = PrivacyConsensusLimitsV1 {
            max_proof_bytes_per_action: u32::try_from(envelope.proof.bytes().as_bytes().len())
                .expect("fixture proof size fits u32"),
            max_action_bytes: envelope_bytes,
            max_privacy_bytes_per_transaction: envelope_bytes,
            max_statement_and_encrypted_output_bytes_per_transaction: statement_bytes,
            ..PrivacyConsensusLimitsV1::taira_default()
        };
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        for flags in [norito::core::default_encode_flags(), alternate_flags] {
            let _layout = norito::core::DecodeFlagsGuard::enter(flags);
            // Prove that the ambient serializer really selects a different byte length.
            if flags == alternate_flags {
                assert_ne!(
                    norito::to_bytes(&envelope)
                        .expect("alternate envelope")
                        .len(),
                    usize::try_from(envelope_bytes).expect("fixture size fits usize")
                );
            }
            envelope
                .statement
                .validate(&limits)
                .expect("exact canonical statement limit");
            envelope
                .validate_with_limits(&limits)
                .expect("exact canonical envelope limit");
            let statement_too_small = PrivacyConsensusLimitsV1 {
                max_statement_and_encrypted_output_bytes_per_transaction: statement_bytes - 1,
                ..limits
            };
            assert_eq!(
                envelope.statement.validate(&statement_too_small),
                Err(
                    PrivacyStatementValidationError::StatementAndEncryptedOutputsTooLarge {
                        bytes: u64::from(statement_bytes),
                        max: statement_bytes - 1,
                    }
                )
            );
            let action_too_small = PrivacyConsensusLimitsV1 {
                max_action_bytes: envelope_bytes - 1,
                ..limits
            };
            assert_eq!(
                envelope.validate_with_limits(&action_too_small),
                Err(PrivacyProofEnvelopeValidationError::ActionTooLarge {
                    bytes: u64::from(envelope_bytes),
                    max: envelope_bytes - 1,
                })
            );
        }
    }
}
fn assert_privacy_digest_layout_invariant<T: core::fmt::Debug + PartialEq>(digest: impl Fn() -> T) {
    let expected = digest();
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let _layout = norito::core::DecodeFlagsGuard::enter(alternate_flags);
    assert_eq!(digest(), expected);
}
#[test]
fn bootle_lantern_digests_ignore_ambient_layout_flags() {
    let policy = bootle_lantern_policy();
    assert_privacy_digest_layout_invariant(|| {
        policy
            .computed_issuer_parameter_digest()
            .expect("canonical issuer matrix digest")
    });
    assert_privacy_digest_layout_invariant(|| {
        policy
            .computed_record_digest()
            .expect("canonical issuer policy digest")
    });
}
#[test]
fn normalization_accessors_cover_every_statement_and_nested_proof_variant() {
    for mut statement in sample_statements() {
        let replacement = PrivacyTransactionIntentDigestV1::new(raw(231));
        statement.context_mut().transaction_intent_digest = replacement;
        assert_eq!(statement.context().transaction_intent_digest, replacement);
    }
    let mut batch =
        PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(
            PrivacyProofBytesV1::new(vec![1, 2, 3]),
        ));
    batch.bytes_mut().bytes.clear();
    assert!(batch.bytes().as_bytes().is_empty());
    let mut provisioning =
        PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(
            PrivacyProofBytesV1::new(vec![4, 5, 6]),
        ));
    provisioning.bytes_mut().bytes.clear();
    assert!(provisioning.bytes().as_bytes().is_empty());
    for mut proof in sample_statements()
        .into_iter()
        .map(envelope)
        .map(|envelope| envelope.proof)
    {
        proof.bytes_mut().bytes.clear();
        assert!(proof.bytes().as_bytes().is_empty());
    }
}
#[test]
fn zk_ams_envelope_requires_the_proof_variant_for_its_exact_action() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let batch_statement = statement_for(PrivacyProtocolIdV1::IrohaZkAmsV1);
    let mut batch_envelope = envelope(batch_statement);
    batch_envelope
        .validate_with_limits(&limits)
        .expect("batch masked Relaxed Spartan proof variant");
    batch_envelope.proof = PrivacyProofV1::IrohaZkAmsV1(
        IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(PrivacyProofBytesV1::new(vec![1])),
    );
    assert!(matches!(
        batch_envelope.validate_with_limits(&limits),
        Err(PrivacyProofEnvelopeValidationError::ZkAmsActionProofMismatch)
    ));
    let provision_statement = zk_ams_provision_statement(16);
    let mut provision_envelope = envelope(provision_statement);
    provision_envelope
        .validate_with_limits(&limits)
        .expect("provisioning LSAG proof variant");
    provision_envelope.proof = PrivacyProofV1::IrohaZkAmsV1(
        IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(PrivacyProofBytesV1::new(vec![1])),
    );
    assert!(matches!(
        provision_envelope.validate_with_limits(&limits),
        Err(PrivacyProofEnvelopeValidationError::ZkAmsActionProofMismatch)
    ));
}
#[test]
fn p256_wire_types_are_exact_width_and_closed() {
    let point = p256_point(9);
    assert_eq!(point.as_bytes().len(), 33);
    assert_fixed_width_norito(&point, point.as_bytes());
    let encoded = point.encode();
    assert_eq!(encoded.len(), 34);
    assert_eq!(
        PrivacyP256PointV1::decode(&mut encoded.as_slice()).expect("decode exact point"),
        point
    );
    assert!(PrivacyP256PointV1::decode(&mut [0x02; 32].as_slice()).is_err());
    assert!(PrivacyP256PointV1::decode(&mut [0x02; 34].as_slice()).is_err());
    let ciphertext = p256_ciphertext(10);
    let bytes = norito::to_bytes(&ciphertext).expect("frame ciphertext");
    let decoded: PrivacyP256CiphertextV1 =
        norito::decode_from_bytes(&bytes).expect("decode ciphertext");
    assert_eq!(decoded, ciphertext);
    for unknown in [2_u32, 3, u32::MAX] {
        assert!(PrivacyVeRangeBitLengthV1::decode(&mut unknown.to_le_bytes().as_slice()).is_err());
    }
}
#[test]
fn zk_ams_ristretto_wire_types_and_action_tags_are_closed() {
    let seed_key = zk_ams_seed_key(9);
    assert_eq!(seed_key.as_bytes().len(), 32);
    assert_fixed_width_norito(&seed_key, seed_key.as_bytes());
    let key_image = PrivacyZkAmsKeyImageV1::new(raw(10));
    assert_eq!(key_image.as_bytes().len(), 32);
    assert_fixed_width_norito(&key_image, key_image.as_bytes());
    let encoded = seed_key.encode();
    assert_eq!(encoded.len(), 33);
    assert_eq!(
        PrivacyZkAmsSeedPublicKeyV1::decode(&mut encoded.as_slice())
            .expect("decode exact seed key"),
        seed_key
    );
    assert!(PrivacyZkAmsSeedPublicKeyV1::decode(&mut [9; 31].as_slice()).is_err());
    assert!(PrivacyZkAmsSeedPublicKeyV1::decode(&mut [9; 33].as_slice()).is_err());
    let key_image = PrivacyZkAmsKeyImageV1::new(raw(10));
    assert_eq!(key_image.encode().len(), 33);
    assert!(PrivacyZkAmsKeyImageV1::decode(&mut key_image.encode().as_slice()).is_ok());
    for unknown in [2_u32, 3, u32::MAX] {
        assert!(PrivacyZkAmsActionV1::decode(&mut unknown.to_le_bytes().as_slice()).is_err());
        assert!(IrohaZkAmsProofV1::decode(&mut unknown.to_le_bytes().as_slice()).is_err());
    }
}
#[test]
fn context_accepts_marked_network_ids_and_rejects_invalid_action_indexes() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let mut value = context();
    value.network_id = network_id(0);
    assert_eq!(value.validate(&limits), Ok(()));
    value = context();
    value.action_index = 1;
    assert!(matches!(
        value.validate(&limits),
        Err(PrivacyStatementValidationError::ActionIndexOutOfBounds {
            index: 1,
            max_actions: 1
        })
    ));
    value = context();
    value.transaction_intent_digest = PrivacyTransactionIntentDigestV1::new([0; 32]);
    assert_eq!(
        value.validate(&limits),
        Err(PrivacyStatementValidationError::ZeroTransactionIntentDigest)
    );
}
#[test]
fn native_consensus_binding_roundtrips_only_in_the_canonical_wire_shape() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let statement_context = context();
    let binding = PrivacyNativeConsensusBindingV1::new(
        &statement_context,
        *statement_context.network_id.as_bytes(),
        &limits,
    )
    .expect("construct canonical native consensus binding");
    binding.validate(&limits).expect("validate binding");
    binding
        .validate_against_context(&statement_context, &limits)
        .expect("binding matches its statement context");
    let canonical = norito::encode_canonical(&binding).expect("encode canonical binding");
    assert_eq!(
        norito::decode_canonical::<PrivacyNativeConsensusBindingV1>(&canonical)
            .expect("decode canonical binding"),
        binding
    );
    let mut truncated = canonical.clone();
    truncated.pop();
    assert!(
        norito::decode_canonical::<PrivacyNativeConsensusBindingV1>(&truncated).is_err(),
        "truncated binding must fail closed"
    );
    let mut trailing = canonical;
    trailing.push(0);
    assert!(
        norito::decode_canonical::<PrivacyNativeConsensusBindingV1>(&trailing).is_err(),
        "trailing binding bytes must fail closed"
    );
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let alternate = {
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::core::to_bytes(&binding).expect("encode alternate-layout binding")
    };
    assert_ne!(
        alternate,
        norito::encode_canonical(&binding).expect("canonical")
    );
    assert!(matches!(
        norito::decode_canonical::<PrivacyNativeConsensusBindingV1>(&alternate),
        Err(norito::Error::NonCanonicalEncoding)
    ));
    let json = norito::json::to_json(&binding).expect("encode binding JSON");
    assert_eq!(
        norito::json::from_json::<PrivacyNativeConsensusBindingV1>(&json)
            .expect("decode canonical binding JSON"),
        binding
    );
    let prefix = json.strip_suffix('}').expect("binding JSON is an object");
    assert!(
        norito::json::from_json::<PrivacyNativeConsensusBindingV1>(&format!(
            "{prefix},\"legacy_genesis\":true}}"
        ))
        .is_err(),
        "unknown legacy JSON fields must fail closed"
    );
}
#[test]
fn native_consensus_binding_digest_changes_on_every_consensus_axis() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let statement_context = context();
    let binding = PrivacyNativeConsensusBindingV1::new(
        &statement_context,
        *statement_context.network_id.as_bytes(),
        &limits,
    )
    .expect("construct canonical native consensus binding");
    let expected = binding.digest().expect("digest canonical binding");
    let mut mutations = Vec::new();
    let mut mutated = binding;
    mutated.network_id = network_id(201);
    mutations.push(("network_id", mutated));
    let mut mutated = binding;
    mutated.genesis_hash = raw(201);
    mutations.push(("genesis_hash", mutated));
    let mut mutated = binding;
    mutated.action_index = 1;
    mutations.push(("action_index", mutated));
    let mut mutated = binding;
    mutated.transaction_intent_digest = PrivacyTransactionIntentDigestV1::new(raw(202));
    mutations.push(("transaction_intent_digest", mutated));
    let mut mutated = binding;
    mutated.parameter_id = PrivacyParameterIdV1::new(raw(203));
    mutations.push(("parameter_id", mutated));
    let mut mutated = binding;
    mutated.parameter_digest = PrivacyParameterDigestV1::new(raw(204));
    mutations.push(("parameter_digest", mutated));
    let mut mutated = binding;
    mutated.verifier_digest = PrivacyVerifierDigestV1::new(raw(205));
    mutations.push(("verifier_digest", mutated));
    let mut mutated = binding;
    mutated.statement_schema_digest = PrivacyStatementSchemaDigestV1::new(raw(206));
    mutations.push(("statement_schema_digest", mutated));
    let mut mutated = binding;
    mutated.engine_manifest_digest = PrivacyEngineManifestDigestV1::new(raw(207));
    mutations.push(("engine_manifest_digest", mutated));
    for (axis, mutation) in mutations {
        assert_ne!(
            mutation.digest().expect("digest binding mutation"),
            expected,
            "changing {axis} must change the native consensus-binding digest"
        );
    }
}
#[test]
fn native_consensus_binding_rejects_zero_or_mismatched_network_identity() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    assert_eq!(
        PrivacyNativeConsensusBindingV1::new(&context(), [0; 32], &limits),
        Err(PrivacyNativeConsensusBindingValidationErrorV1::ZeroGenesisHash)
    );
    assert_eq!(
        PrivacyNativeConsensusBindingV1::new(&context(), raw(201), &limits),
        Err(PrivacyNativeConsensusBindingValidationErrorV1::NetworkGenesisMismatch)
    );
}
#[test]
fn native_consensus_binding_rejects_every_statement_context_substitution() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let base_context = context();
    let binding = PrivacyNativeConsensusBindingV1::new(
        &base_context,
        *base_context.network_id.as_bytes(),
        &limits,
    )
    .expect("construct canonical native consensus binding");
    let mut substitutions = Vec::new();
    let mut substituted = base_context;
    substituted.network_id = network_id(201);
    substitutions.push((
        "network_id",
        substituted,
        PrivacyNativeConsensusBindingValidationErrorV1::NetworkIdMismatch,
    ));
    let mut substituted = base_context;
    substituted.action_index = 1;
    substitutions.push((
        "action_index",
        substituted,
        PrivacyNativeConsensusBindingValidationErrorV1::ActionIndexMismatch,
    ));
    let mut substituted = base_context;
    substituted.transaction_intent_digest = PrivacyTransactionIntentDigestV1::new(raw(210));
    substitutions.push((
        "transaction_intent_digest",
        substituted,
        PrivacyNativeConsensusBindingValidationErrorV1::TransactionIntentDigestMismatch,
    ));
    let mut substituted = base_context;
    substituted.parameter_id = PrivacyParameterIdV1::new(raw(211));
    substitutions.push((
        "parameter_id",
        substituted,
        PrivacyNativeConsensusBindingValidationErrorV1::ParameterIdMismatch,
    ));
    let mut substituted = base_context;
    substituted.parameter_digest = PrivacyParameterDigestV1::new(raw(212));
    substitutions.push((
        "parameter_digest",
        substituted,
        PrivacyNativeConsensusBindingValidationErrorV1::ParameterDigestMismatch,
    ));
    let mut substituted = base_context;
    substituted.verifier_digest = PrivacyVerifierDigestV1::new(raw(213));
    substitutions.push((
        "verifier_digest",
        substituted,
        PrivacyNativeConsensusBindingValidationErrorV1::VerifierDigestMismatch,
    ));
    let mut substituted = base_context;
    substituted.statement_schema_digest = PrivacyStatementSchemaDigestV1::new(raw(214));
    substitutions.push((
        "statement_schema_digest",
        substituted,
        PrivacyNativeConsensusBindingValidationErrorV1::StatementSchemaDigestMismatch,
    ));
    let mut substituted = base_context;
    substituted.engine_manifest_digest = PrivacyEngineManifestDigestV1::new(raw(215));
    substitutions.push((
        "engine_manifest_digest",
        substituted,
        PrivacyNativeConsensusBindingValidationErrorV1::EngineManifestDigestMismatch,
    ));
    for (axis, substituted, expected) in substitutions {
        assert_eq!(
            binding.validate_against_context(&substituted, &limits),
            Err(expected),
            "substituted {axis} must fail closed"
        );
    }
    let mut zero_genesis = binding;
    zero_genesis.genesis_hash = [0; 32];
    assert_eq!(
        zero_genesis.validate_against_context(&context(), &limits),
        Err(PrivacyNativeConsensusBindingValidationErrorV1::ZeroGenesisHash)
    );
}
#[test]
fn privacy_context_statement_proof_and_envelope_json_are_closed() {
    let context = context();
    let context_json = norito::json::to_json(&context).expect("encode privacy context JSON");
    let context_prefix = context_json
        .strip_suffix('}')
        .expect("privacy context JSON is an object");
    assert!(
        norito::json::from_json::<PrivacyStatementContextV1>(&format!(
            "{context_prefix},\"legacy_context\":true}}"
        ))
        .is_err()
    );
    let envelope = envelope(statement_for(
        PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
    ));
    let envelope_json = norito::json::to_json(&envelope).expect("encode privacy envelope JSON");
    let decoded: PrivacyProofEnvelopeV1 =
        norito::json::from_json(&envelope_json).expect("decode canonical envelope JSON");
    assert_eq!(decoded, envelope);
    let envelope_prefix = envelope_json
        .strip_suffix('}')
        .expect("privacy envelope JSON is an object");
    assert!(
        norito::json::from_json::<PrivacyProofEnvelopeV1>(&format!(
            "{envelope_prefix},\"legacy_envelope\":true}}"
        ))
        .is_err()
    );
    let statement_json =
        norito::json::to_json(&envelope.statement).expect("encode typed statement JSON");
    let statement_prefix = statement_json
        .strip_suffix('}')
        .expect("typed statement JSON is an object");
    assert!(
        norito::json::from_json::<PrivacyStatementV1>(&format!(
            "{statement_prefix},\"legacy_statement\":true}}"
        ))
        .is_err()
    );
    let proof_json = norito::json::to_json(&envelope.proof).expect("encode typed proof JSON");
    let proof_prefix = proof_json
        .strip_suffix('}')
        .expect("typed proof JSON is an object");
    assert!(
        norito::json::from_json::<PrivacyProofV1>(&format!(
            "{proof_prefix},\"legacy_proof\":true}}"
        ))
        .is_err()
    );
}
#[test]
fn first_release_statements_reject_nested_unknown_json_fields() {
    for protocol_id in PrivacyProtocolIdV1::ALL {
        let statement = statement_for(protocol_id);
        let canonical =
            norito::json::to_json(&statement).expect("encode private-transfer statement JSON");
        let nested_prefix = canonical
            .strip_suffix("}}")
            .expect("tagged statement ends with nested and outer objects");
        let hostile = format!("{nested_prefix},\"legacy_transfer\":true}}}}");
        assert!(
            norito::json::from_json::<PrivacyStatementV1>(&hostile).is_err(),
            "nested unknown field must fail for {protocol_id:?}"
        );
    }
    for (protocol_id, removed_field) in [
        (PrivacyProtocolIdV1::ZkAcePqAuthorizationV1, "fee"),
        (PrivacyProtocolIdV1::OrchardHalo2ActionsV1, "fee"),
        (PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1, "fee"),
        (PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1, "fee"),
        (PrivacyProtocolIdV1::PqMaspStarkV1, "fee"),
        (
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            "next_state_root",
        ),
        (
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            "next_state_root_epoch",
        ),
        (PrivacyProtocolIdV1::PqMaspStarkV1, "next_anchor"),
        (PrivacyProtocolIdV1::PqMaspStarkV1, "next_anchor_epoch"),
    ] {
        let canonical = norito::json::to_json(&statement_for(protocol_id))
            .expect("encode validator-derived-successor statement");
        let nested_prefix = canonical
            .strip_suffix("}}")
            .expect("tagged statement ends with nested and outer objects");
        let hostile = format!("{nested_prefix},\"{removed_field}\":null}}}}");
        assert!(
            norito::json::from_json::<PrivacyStatementV1>(&hostile).is_err(),
            "removed caller-selected field `{removed_field}` must not decode"
        );
    }
    let authorization = norito::json::to_json(&PrivacyPqAuthorizationProfileV1::MlDsa65)
        .expect("encode PQ authorization profile");
    let authorization_prefix = authorization
        .strip_suffix('}')
        .expect("PQ authorization profile is an object");
    assert!(
        norito::json::from_json::<PrivacyPqAuthorizationProfileV1>(&format!(
            "{authorization_prefix},\"legacy\":null}}"
        ))
        .is_err()
    );
    let encryption =
        norito::json::to_json(&PrivacyPqNoteEncryptionProfileV1::MlKem768XChaCha20Poly1305)
            .expect("encode PQ note-encryption profile");
    let encryption_prefix = encryption
        .strip_suffix('}')
        .expect("PQ note-encryption profile is an object");
    assert!(
        norito::json::from_json::<PrivacyPqNoteEncryptionProfileV1>(&format!(
            "{encryption_prefix},\"legacy\":null}}"
        ))
        .is_err()
    );
    let encrypted_note =
        norito::json::to_json(&encrypted_output(31, 32)).expect("encode encrypted note");
    let encrypted_note_prefix = encrypted_note
        .strip_suffix('}')
        .expect("encrypted note is an object");
    assert!(
        norito::json::from_json::<PrivacyEncryptedOutputV1>(&format!(
            "{encrypted_note_prefix},\"legacy_ciphertext\":null}}"
        ))
        .is_err(),
        "nested private-note encrypted output must reject unknown fields"
    );
    let output = fcmp_output(33);
    let fcmp_encrypted_output = PrivacyFcmpEncryptedOutputV1 {
        recipient: PrivacyRecipientIdV1::new(raw(34)),
        ephemeral_public_key: PrivacyEncryptionKeyV1::new(raw(35)),
        output_id: output.output_id(),
        ciphertext: vec![0xA5],
    };
    let fcmp_encrypted_output_json =
        norito::json::to_json(&fcmp_encrypted_output).expect("encode FCMP++ encrypted output");
    let fcmp_encrypted_output_prefix = fcmp_encrypted_output_json
        .strip_suffix('}')
        .expect("FCMP++ encrypted output is an object");
    assert!(
        norito::json::from_json::<PrivacyFcmpEncryptedOutputV1>(&format!(
            "{fcmp_encrypted_output_prefix},\"legacy_output_id\":null}}"
        ))
        .is_err(),
        "nested FCMP++ encrypted output must reject unknown fields"
    );
}
#[test]
fn taira_consensus_limits_reject_zero_overflow_and_inconsistent_profiles() {
    type HardMaximumMutation = (PrivacyLimitFieldV1, u32, fn(&mut PrivacyConsensusLimitsV1));

    let defaults = PrivacyConsensusLimitsV1::taira_default();
    defaults.validate().expect("Taira defaults");
    assert_eq!(
        defaults.max_actions_per_transaction,
        TAIRA_PRIVACY_MAX_ACTIONS_PER_TRANSACTION_V1
    );
    assert_eq!(defaults.max_proof_bytes_per_action, 9 * 1024 * 1024);
    assert_eq!(defaults.max_action_bytes, 9_699_840);
    assert_eq!(defaults.max_privacy_bytes_per_transaction, 9_699_840);
    assert_eq!(defaults.max_privacy_bytes_per_block, 16_711_680);
    assert_eq!(
        defaults.max_commitments_per_action,
        TAIRA_PRIVACY_MAX_COMMITMENTS_PER_ACTION_V1
    );
    let invalid = [
        {
            let mut value = defaults;
            value.max_actions_per_transaction = 0;
            value
        },
        {
            let mut value = defaults;
            value.max_actions_per_block = 0;
            value
        },
        {
            let mut value = defaults;
            value.max_proof_bytes_per_action = 0;
            value
        },
        {
            let mut value = defaults;
            value.max_action_bytes = 0;
            value
        },
        {
            let mut value = defaults;
            value.max_privacy_bytes_per_transaction = 0;
            value
        },
        {
            let mut value = defaults;
            value.max_privacy_bytes_per_block = 0;
            value
        },
        {
            let mut value = defaults;
            value.max_statement_and_encrypted_output_bytes_per_transaction = 0;
            value
        },
        {
            let mut value = defaults;
            value.max_nullifiers_per_action = 0;
            value
        },
        {
            let mut value = defaults;
            value.max_commitments_per_action = 0;
            value
        },
        {
            let mut value = defaults;
            value.retained_root_count = 0;
            value
        },
        {
            let mut value = defaults;
            value.max_commitments_per_action = TAIRA_PRIVACY_MAX_COMMITMENTS_PER_ACTION_V1 + 1;
            value
        },
        {
            let mut value = defaults;
            value.max_action_bytes = defaults.max_proof_bytes_per_action - 1;
            value
        },
    ];
    for value in invalid {
        assert!(
            value.validate().is_err(),
            "mutated limits must fail: {value:?}"
        );
    }
    let hard_maximum_mutations: [HardMaximumMutation; 4] = [
        (
            PrivacyLimitFieldV1::ProofBytesPerAction,
            TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1,
            |value| value.max_proof_bytes_per_action += 1,
        ),
        (
            PrivacyLimitFieldV1::ActionBytes,
            TAIRA_PRIVACY_MAX_ACTION_BYTES_V1,
            |value| value.max_action_bytes += 1,
        ),
        (
            PrivacyLimitFieldV1::PrivacyBytesPerTransaction,
            TAIRA_PRIVACY_MAX_BYTES_PER_TRANSACTION_V1,
            |value| value.max_privacy_bytes_per_transaction += 1,
        ),
        (
            PrivacyLimitFieldV1::PrivacyBytesPerBlock,
            TAIRA_PRIVACY_MAX_BYTES_PER_BLOCK_V1,
            |value| value.max_privacy_bytes_per_block += 1,
        ),
    ];
    for (field, hard_max, mutate) in hard_maximum_mutations {
        let mut value = defaults;
        mutate(&mut value);
        assert_eq!(
            value.validate(),
            Err(PrivacyConsensusLimitsValidationError::ExceedsHardMaximum {
                field,
                value: hard_max + 1,
                hard_max,
            })
        );
    }
}
#[test]
fn privacy_proof_payload_admits_exact_nine_mib_and_rejects_cap_plus_one() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let maximum =
        usize::try_from(TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1).expect("cap fits usize");
    let mut proof = PrivacyProofBytesV1::new(vec![0xA5; maximum]);
    proof.validate(&limits).expect("exact 9 MiB proof payload");
    proof.bytes.push(0x5A);
    assert_eq!(
        proof.validate(&limits),
        Err(PrivacyProofValidationError::TooLarge {
            bytes: u64::from(TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1) + 1,
            max: TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1,
        })
    );
}
type ConsensusLimitMutationV1 = (PrivacyLimitFieldV1, fn(&mut PrivacyConsensusLimitsV1));
#[test]
fn consensus_limit_tightening_is_strict_and_rejects_every_component_increase() {
    let current = PrivacyConsensusLimitsV1 {
        max_actions_per_transaction: 1,
        max_actions_per_block: 1,
        max_proof_bytes_per_action: 1_024,
        max_action_bytes: 2_048,
        max_privacy_bytes_per_transaction: 4_096,
        max_privacy_bytes_per_block: 8_192,
        max_statement_and_encrypted_output_bytes_per_transaction: 1_024,
        max_nullifiers_per_action: 4,
        max_commitments_per_action: 4,
        retained_root_count: 100,
    };
    current.validate().expect("lower valid current profile");
    assert!(matches!(
        current.validate_tightening_to(&current),
        Err(PrivacyConsensusLimitsTighteningErrorV1::NoChange)
    ));
    let mut strict = current;
    strict.retained_root_count -= 1;
    current
        .validate_tightening_to(&strict)
        .expect("one component may be lowered");
    let mutations: [ConsensusLimitMutationV1; 10] = [
        (PrivacyLimitFieldV1::ActionsPerTransaction, |value| {
            value.max_actions_per_transaction += 1
        }),
        (PrivacyLimitFieldV1::ActionsPerBlock, |value| {
            value.max_actions_per_block += 1;
        }),
        (PrivacyLimitFieldV1::ProofBytesPerAction, |value| {
            value.max_proof_bytes_per_action += 1;
        }),
        (PrivacyLimitFieldV1::ActionBytes, |value| {
            value.max_action_bytes += 1;
        }),
        (PrivacyLimitFieldV1::PrivacyBytesPerTransaction, |value| {
            value.max_privacy_bytes_per_transaction += 1
        }),
        (PrivacyLimitFieldV1::PrivacyBytesPerBlock, |value| {
            value.max_privacy_bytes_per_block += 1;
        }),
        (
            PrivacyLimitFieldV1::StatementAndEncryptedOutputBytesPerTransaction,
            |value| value.max_statement_and_encrypted_output_bytes_per_transaction += 1,
        ),
        (PrivacyLimitFieldV1::NullifiersPerAction, |value| {
            value.max_nullifiers_per_action += 1;
        }),
        (PrivacyLimitFieldV1::CommitmentsPerAction, |value| {
            value.max_commitments_per_action += 1;
        }),
        (PrivacyLimitFieldV1::RetainedRootCount, |value| {
            value.retained_root_count += 1;
        }),
    ];
    for (field, mutate) in mutations {
        let mut candidate = current;
        mutate(&mut candidate);
        let error = current
            .validate_tightening_to(&candidate)
            .expect_err("an increased component must fail closed");
        if field == PrivacyLimitFieldV1::ActionsPerTransaction {
            assert!(matches!(
                error,
                PrivacyConsensusLimitsTighteningErrorV1::InvalidNext(
                    PrivacyConsensusLimitsValidationError::ExceedsHardMaximum {
                        field: PrivacyLimitFieldV1::ActionsPerTransaction,
                        ..
                    }
                )
            ));
        } else {
            assert!(matches!(
                error,
                PrivacyConsensusLimitsTighteningErrorV1::Increase {
                    field: actual,
                    ..
                } if actual == field
            ));
        }
    }
    let mut mixed = strict;
    mixed.max_actions_per_block += 1;
    assert!(matches!(
        current.validate_tightening_to(&mixed),
        Err(PrivacyConsensusLimitsTighteningErrorV1::Increase {
            field: PrivacyLimitFieldV1::ActionsPerBlock,
            ..
        })
    ));
}
#[test]
fn consensus_policy_schedule_enforces_future_height_and_snapshot_boundaries() {
    let current_limits = PrivacyConsensusLimitsV1::taira_default();
    let mut next_limits = current_limits;
    next_limits.max_actions_per_block -= 1;
    next_limits.retained_root_count -= 1;
    let valid = PrivacyConsensusPolicyTighteningV1 {
        scheduled_at_height: 100,
        effective_at_height: 101,
        next_limits,
    };
    valid
        .validate_against(&current_limits)
        .expect("next-block schedule");
    for invalid in [
        PrivacyConsensusPolicyTighteningV1 {
            scheduled_at_height: 0,
            ..valid
        },
        PrivacyConsensusPolicyTighteningV1 {
            effective_at_height: 99,
            ..valid
        },
        PrivacyConsensusPolicyTighteningV1 {
            effective_at_height: 100,
            ..valid
        },
        PrivacyConsensusPolicyTighteningV1 {
            scheduled_at_height: u64::MAX,
            effective_at_height: u64::MAX,
            ..valid
        },
    ] {
        assert!(
            invalid.validate_against(&current_limits).is_err(),
            "invalid schedule must reject: {invalid:?}"
        );
    }
    for (scheduled_at_height, effective_at_height) in [(100, 102), (u64::MAX - 1, u64::MAX)] {
        PrivacyConsensusPolicyTighteningV1 {
            scheduled_at_height,
            effective_at_height,
            ..valid
        }
        .validate_against(&current_limits)
        .expect("any representable future block is allowed");
    }
    assert!(matches!(
        PrivacyConsensusPolicyTighteningV1 {
            scheduled_at_height: u64::MAX,
            effective_at_height: u64::MAX,
            ..valid
        }
        .validate_against(&current_limits),
        Err(PrivacyPolicyValidationErrorV1::HeightOverflow)
    ));
    let policy = PrivacyConsensusPolicyV1 {
        current_limits,
        pending_tightening: Some(valid),
    };
    assert!(matches!(
        policy.validate_at_committed_height(99),
        Err(
            PrivacyPolicyValidationErrorV1::PendingScheduledAfterCommitted {
                scheduled_at_height: 100,
                committed_height: 99
            }
        )
    ));
    policy
        .validate_at_committed_height(100)
        .expect("schedule exists in its admitting committed block");
    policy
        .validate_at_committed_height(valid.effective_at_height - 1)
        .expect("effective E remains pending in committed E-1");
    assert!(matches!(
        policy.validate_at_committed_height(valid.effective_at_height),
        Err(PrivacyPolicyValidationErrorV1::PendingNotFuture {
            effective_at_height,
            committed_height
        }) if effective_at_height == valid.effective_at_height
            && committed_height == valid.effective_at_height
    ));
    assert_eq!(
        policy.admission_retained_root_count(),
        next_limits.retained_root_count
    );
}
#[test]
fn protocol_limit_schedule_rejects_bad_timing_mismatch_increase_and_noop() {
    let current =
        PrivacyProtocolActivationLimitsV1::VeRangeTransparentRangeV1(VeRangeActivationLimitsV1 {
            max_aggregation_count: 8,
        });
    let next =
        PrivacyProtocolActivationLimitsV1::VeRangeTransparentRangeV1(VeRangeActivationLimitsV1 {
            max_aggregation_count: 7,
        });
    let valid = PrivacyProtocolLimitsTighteningV1 {
        scheduled_at_height: 25,
        effective_at_height: 26,
        next_limits: next,
    };
    valid
        .validate_against(&current)
        .expect("next-block protocol tightening");
    assert!(matches!(
        PrivacyProtocolLimitsTighteningV1 {
            next_limits: current,
            ..valid
        }
        .validate_against(&current),
        Err(PrivacyProtocolLimitsTighteningValidationErrorV1::NoChange)
    ));
    assert!(matches!(
        PrivacyProtocolLimitsTighteningV1 {
            effective_at_height: valid.effective_at_height - 1,
            ..valid
        }
        .validate_against(&current),
        Err(PrivacyProtocolLimitsTighteningValidationErrorV1::Schedule(
            PrivacyPolicyValidationErrorV1::EffectiveNotLater { .. }
        ))
    ));
    assert!(matches!(
        PrivacyProtocolLimitsTighteningV1 {
            next_limits: PrivacyProtocolActivationLimitsV1::OrchardHalo2ActionsV1(
                OrchardActivationLimitsV1 {
                    max_action_count: 1,
                }
            ),
            ..valid
        }
        .validate_against(&current),
        Err(PrivacyProtocolLimitsTighteningValidationErrorV1::Limits(
            PrivacyProtocolActivationLimitsValidationError::ProtocolMismatch { .. }
        ))
    ));
    let lower_current = next;
    assert!(matches!(
        PrivacyProtocolLimitsTighteningV1 {
            next_limits: current,
            ..valid
        }
        .validate_against(&lower_current),
        Err(PrivacyProtocolLimitsTighteningValidationErrorV1::Limits(
            PrivacyProtocolActivationLimitsValidationError::ExceedsConfiguredCeiling {
                field: PrivacyActivationLimitFieldV1::VeRangeAggregationCount,
                value: 8,
                ceiling: 7
            }
        ))
    ));
}

#[test]
fn goldilocks_digest384_wire_is_six_canonical_little_endian_words() {
    let words = [
        0x0a08_4d27_65a9_990b,
        0xd59f_602c_37b6_9e1b,
        0xde9b_b335_7209_fa18,
        0x3faf_16ba_65a6_7ba3,
        0xe68c_cc7d_9933_b79d,
        0xcad6_6b94_7931_4d52,
    ];
    let digest = GoldilocksDigest384V1::new(words).expect("canonical digest words");
    let expected = hex!(
        "0b99a965274d080a1b9eb6372c609fd5"
        "18fa097235b39bdea37ba665ba16af3f"
        "9db733997dcc8ce6524d3179946bd6ca"
    );
    assert_eq!(digest.to_le_bytes(), expected);
    assert_eq!(digest.encode(), expected);
    assert_eq!(
        GoldilocksDigest384V1::decode(&mut expected.as_slice()).expect("decode canonical digest"),
        digest
    );

    let mut noncanonical = expected;
    noncanonical[16..24].copy_from_slice(&fastpq_isi::poseidon::FIELD_MODULUS.to_le_bytes());
    assert!(GoldilocksDigest384V1::decode(&mut noncanonical.as_slice()).is_err());
    assert!(GoldilocksDigest384V1::from_le_bytes(noncanonical).is_none());
}

#[test]
fn goldilocks_digest384_slice_decode_consumes_one_fixed_width_prefix() {
    let digest =
        GoldilocksDigest384V1::new([1, 2, 3, 4, 5, 6]).expect("fixture digest words are canonical");
    let mut bytes = digest.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

    let (decoded, consumed) =
        <GoldilocksDigest384V1 as norito::core::DecodeFromSlice>::decode_from_slice(&bytes)
            .expect("decode fixed-width digest prefix");
    assert_eq!(decoded, digest);
    assert_eq!(consumed, GoldilocksDigest384V1::BYTES);

    let short = &bytes[..GoldilocksDigest384V1::BYTES - 1];
    assert!(
        <GoldilocksDigest384V1 as norito::core::DecodeFromSlice>::decode_from_slice(short).is_err()
    );

    let mut noncanonical = digest.to_le_bytes().to_vec();
    noncanonical[..8].copy_from_slice(&fastpq_isi::poseidon::FIELD_MODULUS.to_le_bytes());
    noncanonical.push(0xAA);
    assert!(
        <GoldilocksDigest384V1 as norito::core::DecodeFromSlice>::decode_from_slice(&noncanonical)
            .is_err()
    );
}

#[test]
fn zk_ace_digest384_wrappers_reject_noncanonical_field_elements() {
    let identity = PrivacyZkAceIdentityCommitmentV1::new([1, 2, 3, 4, 5, 6])
        .expect("canonical identity words");
    let replay =
        PrivacyZkAceReplayNullifierV1::new([6, 5, 4, 3, 2, 1]).expect("canonical replay words");
    let identity_bytes = identity.encode();
    let replay_bytes = replay.encode();
    assert_eq!(identity_bytes.len(), GoldilocksDigest384V1::BYTES);
    assert_eq!(replay_bytes.len(), GoldilocksDigest384V1::BYTES);
    let identity_archive = norito::encode_canonical(&identity).expect("canonical identity archive");
    let replay_archive = norito::encode_canonical(&replay).expect("canonical replay archive");
    assert_eq!(
        norito::decode_canonical::<PrivacyZkAceIdentityCommitmentV1>(&identity_archive)
            .expect("decode identity archive"),
        identity
    );
    assert_eq!(
        norito::decode_canonical::<PrivacyZkAceReplayNullifierV1>(&replay_archive)
            .expect("decode replay archive"),
        replay
    );
    let mut framed = identity_bytes.clone();
    framed.push(0xAA);
    let (decoded, used) =
        <PrivacyZkAceIdentityCommitmentV1 as norito::core::DecodeFromSlice>::decode_from_slice(
            &framed,
        )
        .expect("decode bounded identity prefix");
    assert_eq!(decoded, identity);
    assert_eq!(used, GoldilocksDigest384V1::BYTES);
    assert!(
        <PrivacyZkAceReplayNullifierV1 as norito::core::DecodeFromSlice>::decode_from_slice(
            &replay_bytes[..GoldilocksDigest384V1::BYTES - 1],
        )
        .is_err()
    );
    assert_eq!(
        PrivacyZkAceIdentityCommitmentV1::decode(&mut identity_bytes.as_slice())
            .expect("decode canonical identity commitment"),
        identity
    );
    assert_eq!(
        PrivacyZkAceReplayNullifierV1::decode(&mut replay_bytes.as_slice())
            .expect("decode canonical replay nullifier"),
        replay
    );

    let mut noncanonical = [0_u8; GoldilocksDigest384V1::BYTES];
    noncanonical[..8].copy_from_slice(&fastpq_isi::poseidon::FIELD_MODULUS.to_le_bytes());
    assert!(PrivacyZkAceIdentityCommitmentV1::decode(&mut noncanonical.as_slice()).is_err());
    assert!(PrivacyZkAceReplayNullifierV1::decode(&mut noncanonical.as_slice()).is_err());
    assert!(PrivacyZkAceIdentityCommitmentV1::from_le_bytes(noncanonical).is_none());
    assert!(PrivacyZkAceReplayNullifierV1::from_le_bytes(noncanonical).is_none());
}

#[test]
fn goldilocks_digest384_json_rejects_noncanonical_words() {
    let digest = GoldilocksDigest384V1::new([1, 2, 3, 4, 5, 6]).expect("canonical words");
    let json = norito::json::to_json(&digest).expect("serialize digest");
    assert_eq!(
        norito::json::from_str::<GoldilocksDigest384V1>(&json).expect("decode digest"),
        digest
    );

    let mut bytes = [0_u8; GoldilocksDigest384V1::BYTES];
    bytes[..8].copy_from_slice(&fastpq_isi::poseidon::FIELD_MODULUS.to_le_bytes());
    let invalid_json = norito::json::to_json(&bytes.to_vec()).expect("serialize invalid bytes");
    assert!(norito::json::from_str::<GoldilocksDigest384V1>(&invalid_json).is_err());
}

#[test]
fn privacy_stark_ids_require_the_single_sha3_outer_suite() {
    for protocol in [
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        PrivacyProtocolIdV1::PqMaspStarkV1,
    ] {
        assert_eq!(
            protocol.expected_proof_system(),
            PrivacyProofSystemIdV1::StarkFriSha3_384Goldilocks
        );
        assert_eq!(
            protocol.expected_engine(),
            PrivacyEngineIdV1::NativeGoldilocksSha3_384StarkFri
        );
    }
    assert!(
        norito::json::from_json::<PrivacyProofSystemIdV1>(
            r#"{"proof_system":"stark-fri-poseidon-x7-goldilocks-6x64-v1","value":null}"#,
        )
        .is_err()
    );
    assert!(
        norito::json::from_json::<PrivacyEngineIdV1>(
            r#"{"engine":"native-goldilocks-poseidon-x7-stark-fri-6x64-v1","value":null}"#,
        )
        .is_err()
    );
}

#[test]
fn proposed_lifecycle_schema_and_codecs_have_no_activation_schedule() {
    use iroha_schema::{IntoSchema as _, Metadata};

    let schema = PrivacyProposedLifecycleV1::schema();
    let Metadata::Struct(fields) = schema
        .get::<PrivacyProposedLifecycleV1>()
        .expect("proposed lifecycle schema")
    else {
        panic!("proposed lifecycle must be a named struct");
    };
    assert_eq!(fields.declarations.len(), 1);
    assert_eq!(fields.declarations[0].name, "proposed_at_height");
    assert_eq!(fields.declarations[0].ty, std::any::TypeId::of::<u64>());
    let proposed = PrivacyProposedLifecycleV1 {
        proposed_at_height: 7,
    };
    let json = norito::json::to_json(&proposed).expect("serialize pending proposal");
    assert_eq!(json, r#"{"proposed_at_height":7}"#);
    assert_eq!(
        norito::json::from_json::<PrivacyProposedLifecycleV1>(&json)
            .expect("decode pending proposal"),
        proposed
    );
    let bytes = norito::to_bytes(&proposed).expect("encode pending proposal");
    assert_eq!(
        norito::decode_from_bytes::<PrivacyProposedLifecycleV1>(&bytes)
            .expect("decode pending proposal"),
        proposed
    );
    for removed_schedule in [
        r#"{"proposed_at_height":7,"activate_at_height":7}"#,
        r#"{"proposed_at_height":7,"activate_at_height":307}"#,
    ] {
        assert!(norito::json::from_json::<PrivacyProposedLifecycleV1>(removed_schedule).is_err());
    }
    assert!(
        norito::json::from_json::<PrivacyProtocolLifecycleV1>(
            r#"{"state":"proposed","record":{"proposed_at_height":7,"activate_at_height":307}}"#,
        )
        .is_err()
    );
    let active = PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
        proposed_at_height: 7,
        activated_at_height: 7,
        state_since_height: 7,
    });
    active.validate().expect("same-block active record");
    let active_bytes = norito::to_bytes(&active).expect("encode immediate active state");
    let decoded = norito::decode_from_bytes::<PrivacyProtocolLifecycleV1>(&active_bytes)
        .expect("decode immediate active state");
    assert_eq!(decoded, active);
    decoded.validate().expect("decoded immediate active state");
}

#[test]
fn proposed_lifecycle_norito_rejects_removed_schedule_payload() {
    // Test-only encoding of the removed shape under its unchanged nominal frame identity.
    #[derive(norito::codec::Encode, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::privacy::PrivacyProposedLifecycleV1")]
    struct RemovedScheduledProposal {
        proposed_at_height: u64,
        activate_at_height: u64,
    }
    assert_eq!(
        norito::schema::identity::frame_hash::<RemovedScheduledProposal>(),
        norito::schema::identity::frame_hash::<PrivacyProposedLifecycleV1>()
    );
    for activate_at_height in [7, 307] {
        let removed = RemovedScheduledProposal {
            proposed_at_height: 7,
            activate_at_height,
        };
        let frame = norito::encode_canonical(&removed).expect("encode removed payload fixture");
        assert!(norito::decode_from_bytes::<PrivacyProposedLifecycleV1>(&frame).is_err());
    }
}

#[test]
fn exact12_catalog_native32_fixed_vector_and_strict_codecs() {
    let expected = hex!("5bcf366fb18d2e4361486c015da5b41a3fb00edf05611042ccc452120d176eb0");
    let canonical = PrivacyExact12CatalogCommitmentV1::canonical();
    assert_eq!(canonical.as_bytes(), &expected);
    assert_eq!(
        compute_privacy_exact12_catalog_commitment_v1().as_bytes(),
        &expected
    );
    assert_eq!(canonical.encode(), expected);
    let json = norito::json::to_json(&canonical).unwrap();
    assert_eq!(
        norito::json::from_str::<PrivacyExact12CatalogCommitmentV1>(&json).unwrap(),
        canonical
    );
    for byte in 0..PrivacyExact12CatalogCommitmentV1::BYTES {
        for bit in 0..8 {
            let mut changed = expected;
            changed[byte] ^= 1 << bit;
            assert!(PrivacyExact12CatalogCommitmentV1::decode(&mut changed.as_slice()).is_err());
            let json = norito::json::to_json(&changed.to_vec()).unwrap();
            assert!(norito::json::from_str::<PrivacyExact12CatalogCommitmentV1>(&json).is_err());
        }
    }
    for length in [0, 31, 33, 48] {
        let mut bytes = expected.to_vec();
        bytes.resize(length, 0);
        let json = norito::json::to_json(&bytes).unwrap();
        assert!(norito::json::from_str::<PrivacyExact12CatalogCommitmentV1>(&json).is_err());
        let framed =
            norito::core::frame_bare_with_header_flags::<PrivacyExact12CatalogCommitmentV1>(
                &bytes,
                norito::core::default_encode_flags(),
            )
            .unwrap();
        assert!(norito::decode_canonical::<PrivacyExact12CatalogCommitmentV1>(&framed).is_err());
    }
}
