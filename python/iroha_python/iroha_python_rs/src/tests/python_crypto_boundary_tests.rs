// Python crypto/admission boundary regressions share the parent test module's fixtures.
use iroha_data_model::transaction::TransactionSubmissionReceipt;

#[test]
fn fee_sponsor_program_ids_require_exact_canonical_literals() {
    let sponsor_literal = canonical_i105_from_seed(0x74);
    let literal = format!("{sponsor_literal}/retail");
    let parsed = parse_fee_sponsor_program_id(&literal).expect("program id parses");
    assert_eq!(parsed.sponsor, sample_account(0x74));
    assert_eq!(parsed.name.as_ref(), "retail");
    assert!(parse_fee_sponsor_program_id(&format!(" {literal}")).is_err());
    assert!(parse_fee_sponsor_program_id(&sponsor_literal).is_err());
    assert!(parse_fee_sponsor_program_id(&format!("{}/retail", taira_i105_from_seed(0x74))).is_err());
}
#[test]
fn i105_discriminant_hint_decodes_valid_literals_only() {
    let custom_account = custom_i105_from_seed(0x70, 42);
    assert_eq!(
        AccountAddress::i105_discriminant(&custom_account).ok(),
        Some(42)
    );
    let noncanonical = custom_account.replacen("n42", "n00042", 1);
    assert_eq!(AccountAddress::i105_discriminant(&noncanonical).ok(), None);
    let mut chars = custom_account.chars().collect::<Vec<_>>();
    let last = chars.len().saturating_sub(1);
    chars[last] = if chars[last] == '1' { '2' } else { '1' };
    let tampered = chars.into_iter().collect::<String>();
    assert_eq!(AccountAddress::i105_discriminant(&tampered).ok(), None);
    assert_eq!(AccountAddress::i105_discriminant("n").ok(), None);
    assert_eq!(AccountAddress::i105_discriminant("nabc").ok(), None);
    assert_eq!(
        AccountAddress::i105_discriminant("n65536payload").ok(),
        None
    );
}
#[test]
fn parse_account_id_accepts_taira_i105_literals_without_global_discriminant() {
    let taira_account = taira_i105_from_seed(0x71);
    assert!(
        taira_account.starts_with("test"),
        "Taira I105 account must use the public test sentinel"
    );
    assert_eq!(
        parse_account_id(&taira_account).expect("Taira account parses"),
        sample_account(0x71)
    );
}
#[test]
fn parse_account_id_accepts_numeric_custom_i105_literals_without_global_discriminant() {
    let custom_account = custom_i105_from_seed(0x72, 42);
    assert!(
        custom_account.starts_with("n42"),
        "custom I105 account must use the numeric sentinel"
    );
    assert_eq!(
        parse_account_id(&custom_account).expect("custom account parses"),
        sample_account(0x72)
    );
}
#[test]
fn parse_account_id_rejects_noncanonical_and_tampered_numeric_custom_i105_literals() {
    let custom_account = custom_i105_from_seed(0x73, 42);
    let noncanonical = custom_account.replacen("n42", "n00042", 1);
    assert!(
        parse_account_id(&noncanonical).is_err(),
        "noncanonical numeric sentinel must be rejected"
    );
    let mut chars = custom_account.chars().collect::<Vec<_>>();
    let last = chars.len().saturating_sub(1);
    chars[last] = if chars[last] == '1' { '2' } else { '1' };
    let tampered = chars.into_iter().collect::<String>();
    assert!(
        parse_account_id(&tampered).is_err(),
        "payload/checksum tampering must be rejected"
    );
}
#[test]
fn seed_derivation_pyfunctions_use_checked_backend_derivation() {
    ensure_python();
    let seed = b"python checked seed derivation";
    let expected = KeyPair::try_from_seed(seed.to_vec(), Algorithm::Ed25519)
        .expect("derive expected checked Ed25519 key pair");
    let (_, expected_private) = expected.private_key().to_bytes();
    let (_, expected_public) = public_key_to_bytes(expected.public_key(), "expected public key")
        .expect("expected public key payload is well-formed");
    Python::attach(|py| {
        let (generic_private, generic_public) =
            derive_keypair_from_seed_py(py, seed, Algorithm::Ed25519.as_static_str())
                .expect("generic checked seed derivation succeeds");
        let (ed25519_private, ed25519_public) = derive_ed25519_keypair_from_seed_py(py, seed)
            .expect("Ed25519 checked seed derivation succeeds");
        assert_eq!(
            generic_private.bind(py).as_bytes(),
            expected_private.as_slice()
        );
        assert_eq!(generic_public.bind(py).as_bytes(), expected_public);
        assert_eq!(
            ed25519_private.bind(py).as_bytes(),
            expected_private.as_slice()
        );
        assert_eq!(ed25519_public.bind(py).as_bytes(), expected_public);
    });
}
#[test]
fn seed_derivation_pyfunction_rejects_empty_ml_dsa_seed() {
    ensure_python();
    Python::attach(|py| {
        match derive_keypair_from_seed_py(py, b"", Algorithm::MlDsa.as_static_str()) {
            Err(error) => assert!(error.to_string().contains("must not be empty")),
            Ok(_) => panic!("empty ML-DSA seed material must fail"),
        }
    });
}
#[test]
fn parse_algorithm_arg_accepts_exact_supported_aliases() {
    for (label, expected) in [
        ("ed-25519", Algorithm::Ed25519),
        ("ECDSA-SECP256K1-SHA256", Algorithm::Secp256k1),
        ("ml_dsa", Algorithm::MlDsa),
        ("ML-DSA-65", Algorithm::MlDsa),
        (
            "gost3410_2012_512_paramset_b",
            Algorithm::Gost3410_2012_512ParamSetB,
        ),
        ("bls-normal", Algorithm::BlsNormal),
        ("SM2", Algorithm::Sm2),
    ] {
        assert_eq!(parse_algorithm_arg(label).unwrap(), expected, "{label}");
    }
}
#[test]
fn parse_algorithm_arg_rejects_empty_padded_control_and_non_ascii_labels() {
    for (label, expected_message) in [
        ("", "algorithm must be a non-empty string"),
        (" ", "algorithm must not contain surrounding whitespace"),
        ("\t", "algorithm must not contain surrounding whitespace"),
        (
            "\u{00A0}",
            "algorithm must not contain surrounding whitespace",
        ),
        (
            " ed25519",
            "algorithm must not contain surrounding whitespace",
        ),
        (
            "ed25519 ",
            "algorithm must not contain surrounding whitespace",
        ),
        (
            "\ted25519",
            "algorithm must not contain surrounding whitespace",
        ),
        (
            "ed25519\n",
            "algorithm must not contain surrounding whitespace",
        ),
        ("ed\u{0000}25519", "unsupported crypto algorithm"),
        ("ed\u{001F}25519", "unsupported crypto algorithm"),
        ("ed\u{007F}25519", "unsupported crypto algorithm"),
        ("ed\u{200B}25519", "unsupported crypto algorithm"),
        ("\u{0435}d25519", "unsupported crypto algorithm"),
        ("ed\u{FF0D}25519", "unsupported crypto algorithm"),
        ("dilithium", "unsupported crypto algorithm"),
        ("dilithium3", "unsupported crypto algorithm"),
    ] {
        let err = parse_algorithm_arg(label).expect_err(label);
        let message = py_err_message(err);
        assert!(
            message.contains(expected_message),
            "{label:?}: expected {expected_message:?}, got {message:?}"
        );
    }
}
#[test]
fn privacy_compiled_profile_catalog_is_the_exact_closed_registry() {
    let catalog = privacy_compiled_profile_catalog().expect("compiled-profile catalog");
    catalog
        .validate()
        .expect("canonical compiled-profile catalog");
    assert_eq!(catalog.protocols.len(), PrivacyProtocolIdV1::COUNT);
    assert!(
        catalog
            .protocols
            .iter()
            .map(|row| row.protocol_id)
            .eq(PrivacyProtocolIdV1::ALL)
    );
}
fn bind_test_network_privacy_capability(
    builder: &mut TransactionBuilder,
    protocol_id: PrivacyProtocolIdV1,
) {
    builder.privacy_capability_manifest = Some(
        crate::privacy_capability_manifest::PyPrivacyExact12CapabilityManifestV1::test_fetched_binding_for_protocol(
            protocol_id, builder.network_id,
        ),
    );
}
#[test]
fn privacy_transaction_construction_requires_the_matching_network_manifest_tuple() {
    ensure_python();
    let authority = canonical_i105_from_seed(0x51);
    let new_builder = || {
        TransactionBuilder::new(
            &python_test_network_id(),
            &authority,
            authority_fee_payment_json(),
        )
        .expect("builder constructs")
    };
    let missing = new_builder()
        .require_empty_privacy_action_builder_v1(
            PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
            "Vega",
        )
        .expect_err("local catalog must not invent network availability");
    assert!(
        missing
            .to_string()
            .contains("requires a validated Torii Exact12")
    );
    let mut wrong_protocol = new_builder();
    bind_test_network_privacy_capability(
        &mut wrong_protocol,
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
    );
    let mismatch = wrong_protocol
        .require_empty_privacy_action_builder_v1(
            PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
            "Vega",
        )
        .expect_err("another active protocol row must not authorize Vega");
    assert!(
        mismatch
            .to_string()
            .contains("is not available in the committed")
    );
}
fn provider_metadata(provider_id: &str) -> PyProviderMetadata {
    PyProviderMetadata {
        provider_id: Some(provider_id.to_string()),
        profile_id: None,
        profile_aliases: None,
        availability: None,
        stake_amount: None,
        max_streams: Some(2),
        refresh_deadline: None,
        expires_at: None,
        ttl_secs: None,
        allow_unknown_capabilities: Some(true),
        capability_names: None,
        rendezvous_topics: None,
        notes: None,
        range_capability: Some(PyRangeCapability {
            max_chunk_span: u32::MAX,
            min_granularity: 1,
            supports_sparse_offsets: Some(true),
            requires_alignment: Some(false),
            supports_merkle_proof: Some(true),
        }),
        stream_budget: Some(PyStreamBudget {
            max_in_flight: 4,
            max_bytes_per_sec: 8 * 1024 * 1024,
            burst_bytes: Some(8 * 1024 * 1024),
        }),
        transport_hints: None,
    }
}
#[test]
fn generate_sm2_keypair_roundtrip() {
    ensure_python();
    Python::attach(|py| {
        let (private_py, public_py) =
            generate_sm2_keypair_py(py, None).expect("generate SM2 keypair");
        let private_bytes = private_py.bind(py).as_bytes();
        let public_bytes = public_py.bind(py).as_bytes();
        assert_eq!(private_bytes.len(), SM2_PRIVATE_KEY_LENGTH);
        assert_eq!(public_bytes.len(), SM2_PUBLIC_KEY_UNCOMPRESSED_LENGTH);
        let private = parse_sm2_private_key(None, private_bytes).expect("parse SM2 private key");
        let derived_public = private.public_key().to_sec1_bytes(false);
        assert_eq!(derived_public.as_slice(), public_bytes);
    });
}
#[test]
fn parse_public_key_multihash_returns_checked_payload() {
    ensure_python();
    let key_pair =
        KeyPair::try_from_seed(b"python-public-key-multihash".to_vec(), Algorithm::Ed25519)
            .expect("derive Python public-key multihash fixture key");
    let (algorithm, expected_payload) =
        public_key_to_bytes(key_pair.public_key(), "fixture public key")
            .expect("fixture public key is well-formed");
    let encoded = key_pair
        .public_key()
        .try_to_prefixed_string()
        .expect("fixture public key prefixed multihash formats");
    Python::attach(|py| {
        let (parsed_algorithm, parsed_payload) =
            parse_public_key_multihash_py(py, &encoded).expect("public key multihash parses");
        assert_eq!(parsed_algorithm, algorithm.as_static_str());
        assert_eq!(parsed_payload.bind(py).as_bytes(), expected_payload);
    });
}
#[test]
fn public_key_multihash_rejects_malformed_ed25519_public_key_material() {
    for (label, public_key, expected_error) in MALFORMED_ED25519_PUBLIC_KEYS {
        for prefixed in [false, true] {
            let err = py_err_message(
                public_key_multihash_py(Algorithm::Ed25519.as_static_str(), &public_key, prefixed)
                    .expect_err("malformed Ed25519 public key must not format"),
            );
            assert!(
                err.contains("failed to parse public key"),
                "unexpected public-key multihash {label} error: {err}"
            );
            assert!(
                err.contains(expected_error),
                "public-key multihash {label} error lost parser detail: {err}"
            );
        }
    }
}
#[test]
fn multihash_helpers_use_checked_formatters() {
    ensure_python();
    let key_pair = KeyPair::try_from_seed(b"python-multihash-helper".to_vec(), Algorithm::Ed25519)
        .expect("derive Python multihash helper fixture key");
    let (_, public_payload) = public_key_to_bytes(key_pair.public_key(), "fixture public key")
        .expect("fixture public key is well-formed");
    let public_payload = public_payload.to_vec();
    let (private_algorithm, private_payload) = key_pair.private_key().to_bytes();
    assert_eq!(private_algorithm, Algorithm::Ed25519);
    let exposed_private = ExposedPrivateKey(key_pair.private_key().clone());
    assert_eq!(
        public_key_multihash_py(Algorithm::Ed25519.as_static_str(), &public_payload, false)
            .expect("public key multihash formats"),
        public_key_multihash_string(key_pair.public_key(), false, "expected public key")
            .expect("expected public key multihash formats")
    );
    assert_eq!(
        public_key_multihash_py(Algorithm::Ed25519.as_static_str(), &public_payload, true)
            .expect("prefixed public key multihash formats"),
        public_key_multihash_string(key_pair.public_key(), true, "expected public key")
            .expect("expected prefixed public key multihash formats")
    );
    assert_eq!(
        private_key_multihash_py(
            Algorithm::Ed25519.as_static_str(),
            private_payload.as_slice(),
            false,
        )
        .expect("private key multihash formats"),
        private_key_multihash_string(&exposed_private, false, "expected private key")
            .expect("expected private key multihash formats")
    );
    assert_eq!(
        private_key_multihash_py(
            Algorithm::Ed25519.as_static_str(),
            private_payload.as_slice(),
            true,
        )
        .expect("prefixed private key multihash formats"),
        private_key_multihash_string(&exposed_private, true, "expected private key")
            .expect("expected prefixed private key multihash formats")
    );
}
#[test]
fn sm2_fixture_from_seed_uses_checked_public_key_formatters() {
    ensure_python();
    let distid = "1234567812345678";
    let seed = [0x42_u8; SM2_PRIVATE_KEY_LENGTH];
    let message = b"python sm2 fixture checked multihash";
    Python::attach(|py| {
        let fixture =
            sm2_fixture_from_seed_py(py, distid, &seed, message).expect("SM2 fixture generates");
        let fixture = fixture.bind(py);
        let public_key_sec1_hex = fixture
            .get_item("public_key_sec1_hex")
            .expect("SEC1 public key item lookup succeeds")
            .expect("SEC1 public key item exists")
            .extract::<String>()
            .expect("SEC1 public key is string");
        let public_key_multihash = fixture
            .get_item("public_key_multihash")
            .expect("multihash item lookup succeeds")
            .expect("multihash item exists")
            .extract::<String>()
            .expect("multihash is string");
        let public_key_prefixed = fixture
            .get_item("public_key_prefixed")
            .expect("prefixed item lookup succeeds")
            .expect("prefixed item exists")
            .extract::<String>()
            .expect("prefixed multihash is string");
        let public_key_sec1 =
            hex::decode(public_key_sec1_hex).expect("fixture SEC1 public key hex decodes");
        let payload = encode_sm2_public_key_payload(distid, &public_key_sec1)
            .expect("fixture SM2 public key payload encodes");
        let public_key = PublicKey::from_bytes(Algorithm::Sm2, &payload)
            .expect("fixture SM2 public key constructs");
        assert_eq!(
            sm2_public_key_multihash_py(&public_key_sec1, Some(distid))
                .expect("SM2 public key multihash formats"),
            public_key_multihash
        );
        assert_eq!(
            sm2_fixture_public_key_multihashes(&public_key)
                .expect("fixture public key multihashes format")
                .1,
            public_key_prefixed
        );
    });
}
#[test]
fn keypair_and_account_public_exports_use_checked_payloads() {
    ensure_python();
    let key_pair = KeyPair::try_from_seed(b"python-keypair-export".to_vec(), Algorithm::Ed25519)
        .expect("derive Python keypair export fixture key");
    let (_, expected_public) = public_key_to_bytes(key_pair.public_key(), "fixture public key")
        .expect("fixture public key is well-formed");
    let expected_public = expected_public.to_vec();
    let (_, expected_private) = key_pair.private_key().to_bytes();
    let authority = AccountId::new(key_pair.public_key().clone())
        .canonical_i105()
        .expect("canonical authority");
    Python::attach(|py| {
        let (private_py, public_py) = keypair_to_py(py, key_pair.clone()).expect("keypair exports");
        assert_eq!(public_py.bind(py).as_bytes(), expected_public.as_slice());
        assert_eq!(private_py.bind(py).as_bytes(), expected_private.as_slice());
    });
    let account = PyAccountId::new(&authority).expect("account id parses");
    assert_eq!(
        account.public_key_hex().expect("public key hex"),
        hex::encode(expected_public)
    );
}
#[test]
fn sorafs_alias_proof_fixture_generates_servable_checked_signer() {
    ensure_python();
    Python::attach(|py| {
        let fixture =
            sorafs_alias_proof_fixture_py(py, None).expect("alias proof fixture generates");
        let fixture = fixture.bind(py);
        let proof_b64 = fixture
            .get_item("proof_b64")
            .expect("proof item lookup succeeds")
            .expect("proof item exists")
            .extract::<String>()
            .expect("proof is string");
        let generated_at_unix = fixture
            .get_item("generated_at_unix")
            .expect("generated item lookup succeeds")
            .expect("generated item exists")
            .extract::<u64>()
            .expect("generated timestamp is integer");
        let evaluation =
            sorafs_evaluate_alias_proof_py(py, &proof_b64, None, Some(generated_at_unix))
                .expect("alias proof evaluates");
        let evaluation = evaluation.bind(py);
        let state = evaluation
            .get_item("state")
            .expect("state item lookup succeeds")
            .expect("state item exists")
            .extract::<String>()
            .expect("state is string");
        let servable = evaluation
            .get_item("servable")
            .expect("servable item lookup succeeds")
            .expect("servable item exists")
            .extract::<bool>()
            .expect("servable is boolean");
        assert_eq!(state, "fresh");
        assert!(servable);
    });
}

#[test]
fn sorafs_alias_proof_fixture_rejects_bad_cid_and_expiry_overflow() {
    ensure_python();
    Python::attach(|py| {
        let malformed = PyDict::new(py);
        malformed.set_item("manifest_cid_hex", "aabb").unwrap();
        assert!(sorafs_alias_proof_fixture_py(py, Some(&malformed)).is_err());
        let overflow = PyDict::new(py);
        overflow.set_item("generated_at_unix", u64::MAX).unwrap();
        let error = sorafs_alias_proof_fixture_py(py, Some(&overflow)).unwrap_err();
        assert!(error.to_string().contains("overflows the default alias expiry"));
    });
}
#[test]
fn decode_transaction_receipt_json_roundtrip() {
    let key_pair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
    let payload = iroha_data_model::transaction::TransactionSubmissionReceiptPayload {
        entrypoint_hash: HashOf::from_untyped_unchecked(Hash::prehashed([0xA5; 32])),
        signed_transaction_hash: Some(HashOf::from_untyped_unchecked(Hash::prehashed([0xB6; 32]))),
        submitted_at_ms: 42,
        submitted_at_height: 7,
        signer: key_pair.public_key().clone(),
    };
    let receipt = TransactionSubmissionReceipt::sign(payload, &key_pair);
    let bytes = to_bytes(&receipt).expect("encode receipt");
    let decoded = sorafs_orderbook_submission::decode_transaction_receipt_json_py(&bytes)
        .expect("decode receipt json");
    let expected = json::to_json(&receipt).expect("serialize receipt");
    assert_eq!(decoded, expected);
}
#[test]
fn transaction_submission_native_boundary_pins_wire_hash_and_receipt_signer() {
    ensure_python();
    let transaction_signing = SigningKey::from_bytes(&[0x31; 32]);
    let transaction_private =
        parse_private_key(transaction_signing.as_bytes()).expect("transaction private key");
    let authority = AccountId::new(PublicKey::from(transaction_private))
        .canonical_i105()
        .expect("canonical transaction authority");
    let mut builder = TransactionBuilder::new(
        &python_test_network_id(),
        &authority,
        authority_fee_payment_json(),
    )
    .expect("transaction builder");
    let envelope = builder
        .sign(transaction_signing.as_bytes())
        .expect("signed transaction envelope");

    let receipt_key_pair =
        KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Ed25519).expect("receipt signing key");
    let expected_receipt_signer = receipt_key_pair.public_key().to_string();
    Python::attach(|py| {
        let (hash, canonical_signer) =
            sorafs_orderbook_submission::inspect_transaction_submission_v1_py(
                py,
                &envelope.signed_transaction_versioned,
                &expected_receipt_signer,
            )
            .expect("native submission inspection");
        assert_eq!(hash.bind(py).as_bytes(), envelope.hash);
        assert_eq!(canonical_signer, expected_receipt_signer);
    });
    Python::attach(|py| {
        assert!(
            sorafs_orderbook_submission::inspect_transaction_submission_v1_py(
                py,
                &envelope.signed_transaction_versioned,
                &format!(" {expected_receipt_signer}"),
            )
            .is_err(),
            "non-canonical receipt signer text must fail before dispatch",
        );
    });

    let transaction_hash =
        HashOf::<iroha_data_model::transaction::SignedTransaction>::from_untyped_unchecked(
            Hash::prehashed(envelope.hash),
        );
    let receipt = TransactionSubmissionReceipt::sign(
        iroha_data_model::transaction::TransactionSubmissionReceiptPayload {
            entrypoint_hash: HashOf::from_untyped_unchecked(Hash::from(transaction_hash)),
            signed_transaction_hash: Some(transaction_hash),
            submitted_at_ms: 42,
            submitted_at_height: 7,
            signer: receipt_key_pair.public_key().clone(),
        },
        &receipt_key_pair,
    );
    let receipt_bytes = norito::encode_canonical(&receipt).expect("canonical receipt");
    let hash_literal = transaction_hash.to_string();
    let verified = sorafs_orderbook_submission::verify_transaction_submission_receipt_v1_py(
        &receipt_bytes,
        &hash_literal,
        &expected_receipt_signer,
    )
    .expect("pinned receipt verifies");
    assert_eq!(
        verified,
        norito::json::to_json(&receipt).expect("receipt JSON")
    );

    let wrong_signer = KeyPair::try_from_seed(vec![0x43; 32], Algorithm::Ed25519)
        .expect("alternate receipt key")
        .public_key()
        .to_string();
    assert!(
        sorafs_orderbook_submission::verify_transaction_submission_receipt_v1_py(
            &receipt_bytes,
            &hash_literal,
            &wrong_signer,
        )
        .is_err(),
        "a self-signed receipt from an unpinned signer must reject",
    );
}
#[test]
fn privacy_bridge_abi_version_python_function_matches_first_release() {
    assert_eq!(privacy_bridge_abi_version_py(), 31);
}
#[test]
fn privacy_compiled_profile_catalog_python_validator_calls_the_exact_local_boundary() {
    let catalog = privacy_compiled_profile_catalog().expect("compiled-profile catalog");
    let archive = norito::encode_canonical(&catalog).expect("canonical compiled catalog");
    assert_eq!(
        privacy_validate_compiled_profile_catalog_v1_py(&archive),
        iroha_data_model::privacy::PrivacyCompiledProfileCatalogArchiveValidationStatusV1::Valid
            .code()
    );
    let mut one_byte_fake = norito::encode_canonical(&0_u8).expect("one-byte fake");
    one_byte_fake[6..22].copy_from_slice(&archive[6..22]);
    assert_ne!(
        privacy_validate_compiled_profile_catalog_v1_py(&one_byte_fake),
        iroha_data_model::privacy::PrivacyCompiledProfileCatalogArchiveValidationStatusV1::Valid
            .code()
    );
    let mut substituted = catalog;
    let profile = substituted
        .protocols
        .iter_mut()
        .find_map(|row| match &mut row.compiled_profile {
            iroha_data_model::privacy::PrivacyCompiledProfileResultV1::Available(profile) => {
                Some(profile)
            }
            iroha_data_model::privacy::PrivacyCompiledProfileResultV1::Unavailable(_) => None,
        })
        .expect("at least one compiled profile");
    let mut digest = *profile.parameter_digest.as_bytes();
    digest[0] ^= 0x80;
    profile.parameter_digest = iroha_data_model::privacy::PrivacyParameterDigestV1::new(digest);
    profile
        .validate()
        .expect("substituted profile remains structurally valid");
    let substituted = norito::encode_canonical(&substituted).expect("encode substitution");
    assert_eq!(
        iroha_data_model::privacy::validate_privacy_compiled_profile_catalog_archive_v1(
            &substituted,
        ),
        iroha_data_model::privacy::PrivacyCompiledProfileCatalogArchiveValidationStatusV1::Valid,
        "the generic validator must accept the structurally valid substitution",
    );
    assert_eq!(
            privacy_validate_compiled_profile_catalog_v1_py(&substituted),
            iroha_data_model::privacy::PrivacyCompiledProfileCatalogArchiveValidationStatusV1::InvalidCatalog
                .code()
        );
}
#[test]
fn component_python_nonzero_digest_boundary_rejects_ambiguous_encodings() {
    assert!(python_nonzero_privacy_digest_v1(&[0x11; 32], "digest").is_ok());
    assert!(python_nonzero_privacy_digest_v1(&[0x11; 31], "digest").is_err());
    assert!(python_nonzero_privacy_digest_v1(&[0x11; 33], "digest").is_err());
    assert!(python_nonzero_privacy_digest_v1(&[0; 32], "digest").is_err());
}
#[test]
fn exported_vega_python_device_digest_fails_closed_with_unavailable_profile() {
    use iroha_core_privacy::privacy_engines::verange::{VeRangeBitLengthV1, VeRangeParametersV1};

    let protocol_id = PrivacyProtocolIdV1::VegaExistingCredentialZkV1;
    assert!(matches!(
        compiled_privacy_profile_v1(protocol_id),
        Err(
            iroha_core_privacy::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
                protocol_id: unavailable,
            }
        ) if unavailable == protocol_id
    ));
    let issuer_public_key = *VeRangeParametersV1::for_profile(VeRangeBitLengthV1::Bits32)
        .expect("P-256 parameters")
        .blinding_generator()
        .as_bytes();

    ensure_python();
    Python::attach(|py| {
        let error = privacy_vega_device_authentication_digest_v1_py(
            py,
            &python_test_network_id(),
            &[0xD2; 32],
            &[0xA1; 32],
            1,
            &[0xA2; 32],
            &issuer_public_key,
            2026,
            7,
            28,
            18,
            &[0xB4; 32],
            &[0xC3; 32],
        )
        .expect_err("the exported Vega digest boundary must reject an unavailable profile");
        assert!(error.is_instance_of::<PyRuntimeError>(py));
        let message = error.value(py).to_string();
        assert!(
            message.contains("compiled Vega privacy profile is unavailable"),
            "unexpected public error: {message}"
        );
        assert!(
            message.contains(
                "native privacy engine for VegaExistingCredentialZkV1 is not governance-available"
            ),
            "the EngineUnavailable cause must remain observable: {message}"
        );
    });
}
#[test]
fn vega_python_profile_is_unavailable_while_low_level_device_digest_binds_intent_and_session() {
    use iroha_core_privacy::privacy_engines::verange::{VeRangeBitLengthV1, VeRangeParametersV1};
    assert!(
        python_compiled_privacy_profile_v1(
            PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
            "Vega",
        )
        .is_err(),
        "Vega must remain unavailable until its full-shape artifacts and evidence are authenticated"
    );
    let issuer_public_key = *VeRangeParametersV1::for_profile(VeRangeBitLengthV1::Bits32)
        .expect("P-256 parameters")
        .blinding_generator()
        .as_bytes();
    // Explicit nonzero bindings exercise only the low-level hash boundary;
    // they are not a compiled profile or candidate admission authority.
    let context = |intent: [u8; 32]| PrivacyStatementContextV1 {
        network_id: python_test_network_id().inner,
        action_index: 0,
        transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(intent),
        parameter_id: iroha_data_model::privacy::PrivacyParameterIdV1::new([0x11; 32]),
        parameter_digest: iroha_data_model::privacy::PrivacyParameterDigestV1::new([0x22; 32]),
        verifier_digest: iroha_data_model::privacy::PrivacyVerifierDigestV1::new([0x33; 32]),
        statement_schema_digest: iroha_data_model::privacy::PrivacyStatementSchemaDigestV1::new(
            [0x44; 32],
        ),
        engine_manifest_digest: iroha_data_model::privacy::PrivacyEngineManifestDigestV1::new(
            [0x55; 32],
        ),
    };
    let statement = |intent, challenge| {
        python_vega_statement_v1(
            context(intent),
            [0xA5; 32],
            [0xA1; 32],
            1,
            [0xA2; 32],
            issuer_public_key,
            2026,
            7,
            28,
            18,
            challenge,
            [0xC3; 32],
        )
        .expect("valid Vega public statement")
    };
    let bound_intent = statement([0xD2; 32], [0xB4; 32]);
    let other_intent = statement([0xD3; 32], [0xB4; 32]);
    let other_session = statement([0xD2; 32], [0xB5; 32]);
    assert_ne!(
        bound_intent.device_authentication_digest, other_intent.device_authentication_digest,
        "H_dev must bind the canonical transaction intent"
    );
    assert_ne!(
        bound_intent.device_authentication_digest, other_session.device_authentication_digest,
        "H_dev must bind the reader challenge"
    );
    assert!(
        python_vega_statement_v1(
            context([0; 32]),
            [0xA5; 32],
            [0xA1; 32],
            1,
            [0xA2; 32],
            issuer_public_key,
            2026,
            7,
            28,
            18,
            [0xB4; 32],
            [0xC3; 32],
        )
        .is_err(),
        "the low-level helper must reject an unprepared all-zero intent"
    );
    assert!(
        python_vega_statement_v1(
            context([0xD2; 32]),
            [0xA5; 32],
            [0xA1; 32],
            1,
            [0xA2; 32],
            issuer_public_key,
            2026,
            13,
            28,
            18,
            [0xB4; 32],
            [0xC3; 32],
        )
        .is_err()
    );
    assert!(
        python_vega_statement_v1(
            context([0xD2; 32]),
            [0xA5; 32],
            [0xA1; 32],
            1,
            [0xA2; 32],
            [0; 33],
            2026,
            7,
            28,
            18,
            [0xB4; 32],
            [0xC3; 32],
        )
        .is_err()
    );
}
#[test]
fn component_python_inspectors_reject_empty_and_malformed_signed_wire() {
    ensure_python();
    Python::attach(|py| {
        for malformed in [&[][..], &[0xA5, 0x5A][..]] {
            assert!(inspect_signed_privacy_verange_action_v1_py(py, malformed).is_err());
            assert!(inspect_signed_privacy_vega_action_v1_py(py, malformed).is_err());
            assert!(
                inspect_signed_privacy_zk_x509_identity_presentation_action_v1_py(
                    py,
                    malformed,
                    &python_test_network_id(),
                )
                .is_err()
            );
            assert!(
                inspect_signed_privacy_zk_ams_batch_admission_action_v1_py(py, malformed).is_err()
            );
            assert!(
                inspect_signed_privacy_zk_ams_provision_account_action_v1_py(py, malformed)
                    .is_err()
            );
            assert!(
                inspect_signed_privacy_bootle_lantern_presentation_action_v1_py(py, malformed)
                    .is_err()
            );
        }
    });
}
#[test]
fn x509_statement_archive_boundary_is_nonempty_fixed_capacity_and_canonical() {
    assert!(python_zk_x509_statement_archive_v1(&[]).is_err());
    assert!(python_zk_x509_statement_archive_v1(&[0xA5]).is_err());
    assert!(
        python_zk_x509_statement_archive_v1(&vec![
            0xA5;
            crate::privacy_native_actions::PRIVACY_ZK_X509_MAX_STATEMENT_ARCHIVE_BYTES_V1
                + 1
        ])
        .is_err()
    );
}
#[test]
fn x509_python_result_keeps_exact_action_and_ledger_semantics() {
    assert_eq!(
        ZK_X509_ACTION_EXECUTION_CLASSIFICATION_V1,
        "presentation_action"
    );
    assert_eq!(ZK_X509_LEDGER_EFFECT_V1, "zk_x509_certificate_nullifier");
}
