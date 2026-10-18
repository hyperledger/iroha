//! BPNG signed selection only: genuine metadata signatures and genesis, no admitted graph.

use super::*;

struct BpngFixture(BaseFixture, Value);
impl BpngFixture {
    fn new() -> Self {
        Self::with_asset("839FV3NJC8NfgWQvghXU2hEFQm9a")
    }
    fn with_asset(asset: &str) -> Self {
        Self::with_asset_and_mode(asset, SumeragiConsensusMode::Permissioned)
    }
    fn with_asset_and_mode(asset: &str, mode: SumeragiConsensusMode) -> Self {
        let short_mode = match &mode {
            SumeragiConsensusMode::Permissioned => "permissioned",
            SumeragiConsensusMode::Npos => "npos",
        };
        let mut base = BaseFixture::with_asset_and_mode(asset, mode);
        // Complete public BPNG v7 DATA fixture from the maintained Android runtime
        // fixture. Replace its graph selections with this genuine signed genesis and
        // genuine scheme/certificate/policy originals; no proof graph is fabricated.
        let mut app: Value = norito::json::from_slice(include_bytes!("bpng_app_v7.json")).unwrap();
        mutate(
            object_mut(&mut app).get_mut("digitalKina").unwrap(),
            "assetDefinitionId",
            Value::String(asset.into()),
        );
        let digital_kina = object_mut(&mut app).get_mut("digitalKina").unwrap();
        mutate(digital_kina, "owningDomain", Value::Null);
        mutate(
            digital_kina,
            "owningDataspace",
            Value::String("8648377547929788715".into()),
        );
        mutate(
            digital_kina,
            "balanceScopePolicy",
            Value::String("Global".into()),
        );
        let native = native_installation_mut(&mut base.app);
        let mut ledger = native["ledger"].clone();
        mutate(
            &mut ledger,
            "toriiUrl",
            Value::String("https://taira.sora.org".into()),
        );
        mutate(&mut app, "ledger", ledger);
        let mut consensus = native["consensus"].clone();
        // Preserve the maintained BPNG v7 renderer grammar while replacing only
        // its public genesis/roster selections with genuine fixture originals. BPNG
        // signs no finality-verifier pin.
        object_mut(&mut consensus).remove("finalityVerifierSha256");
        mutate(&mut consensus, "mode", Value::String(short_mode.into()));
        for name in [
            "checkpointSha256",
            "checkpointHeight",
            "checkpointContextId",
        ] {
            mutate(&mut consensus, name, Value::Null);
        }
        let Value::Array(validators) = object_mut(&mut consensus).get_mut("validators").unwrap()
        else {
            panic!("validators")
        };
        for (index, row) in validators.iter_mut().enumerate() {
            mutate(
                row,
                "directToriiUrl",
                Value::String(bpng::VALIDATOR_BASES[index].into()),
            );
            mutate(
                row,
                "nodeFingerprint",
                Value::String(hex::encode([index as u8 + 1; 32])),
            );
        }
        mutate(&mut app, "consensus", consensus);
        base.app = app;
        mutate(
            &mut base.runtime,
            "schema",
            Value::String("bpng.current-wallet-core-runtime.v1".into()),
        );
        mutate(
            &mut base.runtime,
            "enrollment_session",
            bpng_session_selection(),
        );
        let (_, eligibility_key) = base.key.public_key().to_bytes();
        let template = iroha_data_model::kagemusha::KagemushaEligibilityPolicyTemplateV1 {
            version: 1,
            network_id: base.scheme.network_id,
            scheme_id: base.scheme.scheme_id(),
            revision: 1,
            authority: iroha_data_model::kagemusha::KagemushaEligibilityAuthorityV1::Bank {
                fi_digest: [7; 32],
            },
            public_key: eligibility_key.try_into().unwrap(),
            maximum_response_ms: 30_000,
        };
        mutate(
            &mut base.runtime,
            "eligibility_template_hex",
            Value::String(hex::encode(template.encode_canonical().unwrap())),
        );
        for (name, value) in [
            ("python_path", "/usr/bin/python3"),
            ("openssl_path", "/usr/bin/openssl"),
        ] {
            mutate(&mut base.runtime, name, Value::String(value.into()));
        }
        for name in ["python_sha256", "openssl_sha256"] {
            mutate(&mut base.runtime, name, Value::String("55".repeat(32)));
        }
        // Only Apple selects a root DER original; Android roots are SPKI pins in its policy.
        mutate(
            object_mut(&mut base.runtime).get_mut("apple").unwrap(),
            "attestation_root_der_base64",
            Value::String(STANDARD.encode(SESSION_ROOT)),
        );
        for name in ["android", "apple"] {
            mutate(
                object_mut(&mut base.runtime).get_mut(name).unwrap(),
                "verifier_configuration_path",
                Value::String(format!("srv/etc/kagemusha/wallet-e1-{name}.json")),
            );
        }
        Self(base, financial_record())
    }
    fn originals(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let runtime = norito::json::to_json_bounded(&self.0.runtime, WALLET_RUNTIME_MAX)
            .unwrap()
            .into_bytes();
        let mut app = self.0.app.clone();
        mutate(
            &mut app,
            "walletRuntime",
            norito::json!({"schema":("bpng.current-wallet-runtime-pin.v1"),"currentRuntimeSha256":(hex::encode(BlobV1::of(&runtime).sha256)),"financialOriginals":(self.1.clone())}),
        );
        let app = canonical(&app);
        let envelope = bpng_sign(&self.0.key, &app);
        (app, envelope, runtime)
    }
    fn load(&self) -> Result<Selection> {
        let (app, envelope, runtime) = self.originals();
        self.load_originals(&app, &envelope, &runtime)
    }
    fn load_originals(&self, app: &[u8], envelope: &[u8], runtime: &[u8]) -> Result<Selection> {
        self.load_offered(app, envelope, runtime, 7)
    }
    fn load_offered(
        &self,
        app: &[u8],
        envelope: &[u8],
        runtime: &[u8],
        offered: u8,
    ) -> Result<Selection> {
        Selection::load(
            &self.trust(),
            &RuntimeOriginals {
                app_manifest: app,
                envelope,
                wallet_runtime: runtime,
                verifier_pack: if offered & 1 != 0 { TEST_PACK } else { b"" },
                producer_inventory: if offered & 2 != 0 { TEST_CATALOG } else { b"" },
                signed_genesis: &self.0.genesis,
                originals_root: if offered & 4 != 0 { TEST_ROOT } else { b"" },
                registration_source: b"",
            },
        )
    }
    fn trust(&self) -> RuntimeTrust {
        RuntimeTrust {
            authority: RuntimeAuthority::BpngTairaV7,
            key: self.0.key.public_key().clone(),
        }
    }
}
fn bpng_session_selection() -> Value {
    let key = session_key(7);
    let (_, public) = key.public_key().to_bytes();
    norito::json!({"schema":("bpng.wallet-enrollment-session-selection.v1"),
        "jwt_issuer":("https://bpng-core.soramitsu.io/mibank"),
        "jwt_audience":("mibank.bpng"), "fi_id":("mibank.bpng"),
        "jwt_public_key_hex":(hex::encode(public))})
}
fn bpng_claims() -> Value {
    norito::json!({"sub":("owner@example.test"), "dataspace_id":("mibank.bpng"),
        "roles":["RETAIL_USER"], "iat":(1000), "nbf":(1000), "exp":(2000),
        "iss":("https://bpng-core.soramitsu.io/mibank"), "aud":("mibank.bpng")})
}
fn bpng_token(claims: &Value, key: &KeyPair) -> Vec<u8> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"EdDSA"}"#);
    let claims = URL_SAFE_NO_PAD.encode(norito::json::to_json(claims).unwrap().as_bytes());
    let message = format!("{header}.{claims}");
    let signature = Signature::try_new(key.private_key(), message.as_bytes()).unwrap();
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.payload())).into_bytes()
}

#[test]
fn bpng_consensus_mode_matches_genuine_genesis_with_exact_v7_labels() {
    for (mode, expected, other) in [
        (SumeragiConsensusMode::Permissioned, "permissioned", "npos"),
        (SumeragiConsensusMode::Npos, "npos", "permissioned"),
    ] {
        let mut fixture = BpngFixture::with_asset_and_mode("839FV3NJC8NfgWQvghXU2hEFQm9a", mode);
        assert_eq!(fixture.0.app["consensus"]["mode"].as_str(), Some(expected));
        fixture.load().unwrap();
        for wrong in [
            other,
            "iroha3-consensus::permissioned-sumeragi@v1",
            "iroha3-consensus::npos-sumeragi@v1",
            "unknown",
            "",
        ] {
            mutate(
                object_mut(&mut fixture.0.app).get_mut("consensus").unwrap(),
                "mode",
                Value::String(wrong.into()),
            );
            // Even a fresh genuine application signature cannot change genesis
            // policy or select a foreign format's mode grammar.
            assert!(fixture.load().is_err(), "BPNG {expected} accepted {wrong}");
        }
    }
}

#[test]
fn bpng_consensus_mode_remains_bound_to_original_signature() {
    let mut fixture = BpngFixture::new();
    let (_, envelope, runtime) = fixture.originals();
    mutate(
        object_mut(&mut fixture.0.app).get_mut("consensus").unwrap(),
        "mode",
        Value::String("npos".into()),
    );
    let (changed, changed_envelope, _) = fixture.originals();
    assert!(signed_app(&fixture.trust(), &changed, &changed_envelope).is_ok());
    assert!(signed_app(&fixture.trust(), &changed, &envelope).is_err());
    assert!(
        fixture
            .load_originals(&changed, &envelope, &runtime)
            .is_err()
    );
}

#[test]
fn cbsi_consensus_keeps_exact_protocol_tags_for_both_genuine_genesis_modes() {
    for (mode, expected, short, other) in [
        (
            SumeragiConsensusMode::Permissioned,
            "iroha3-consensus::permissioned-sumeragi@v1",
            "permissioned",
            "iroha3-consensus::npos-sumeragi@v1",
        ),
        (
            SumeragiConsensusMode::Npos,
            "iroha3-consensus::npos-sumeragi@v1",
            "npos",
            "iroha3-consensus::permissioned-sumeragi@v1",
        ),
    ] {
        let mut fixture = BaseFixture::with_asset_and_mode("7ZepsJTHCVLKsrFFNZGSRGZgvBhv", mode);
        assert_eq!(
            native_installation_mut(&mut fixture.app)["consensus"]["mode"].as_str(),
            Some(expected),
        );
        fixture.load().unwrap();
        for wrong in [short, other] {
            mutate(
                native_installation_mut(&mut fixture.app)
                    .get_mut("consensus")
                    .unwrap(),
                "mode",
                Value::String(wrong.into()),
            );
            assert!(fixture.load().is_err(), "CBSI {expected} accepted {wrong}");
        }
    }
}

fn bpng_root(android: bool) -> &'static [u8] {
    if android { b"" } else { SESSION_ROOT }
}
#[test]
fn bpng_session_authenticates_actual_retail_claims_and_exact_signed_release() {
    let fixture = BpngFixture::new();
    let selected = fixture.load().unwrap();
    let token = bpng_token(&bpng_claims(), &session_key(7));
    for android in [true, false] {
        let originals = [token.as_slice(), b"", bpng_root(android)];
        let session = selected.enrollment_session(android, originals).unwrap();
        assert!(session.matches(originals));
        // Android carries no root original: its KeyMint chain carries its own root.
        assert_eq!(
            session.config.attestation_root_der,
            (!android).then(|| SESSION_ROOT.to_vec())
        );
        assert_eq!(session.config.actor, b"owner@example.test");
        assert_eq!(session.config.fi, b"mibank.bpng");
        assert_eq!(
            session.config.service_origin,
            b"https://bpng-core.soramitsu.io/mibank"
        );
        assert_eq!(
            session.config.release,
            BlobV1::of(&fixture.originals().0).sha256
        );
        assert_eq!(session.config.session_valid_from_ms, 1_000_000);
        assert_eq!(session.config.session_expires_at_ms, 2_000_000);
    }
    // Re-signing a changed public selection produces a different release preimage.
    let mut other = BpngFixture::new();
    mutate(
        &mut other.0.app,
        "generatedAt",
        Value::String("2026-09-13T00:00:00Z".into()),
    );
    let other = other.load().unwrap();
    assert_ne!(
        selected
            .enrollment_session(true, [&token, b"", b""])
            .unwrap()
            .config
            .release,
        other
            .enrollment_session(true, [&token, b"", b""])
            .unwrap()
            .config
            .release,
    );
}

#[test]
fn bpng_session_rejects_wrong_signer_modified_token_root_and_foreign_proof() {
    let selected = BpngFixture::new().load().unwrap();
    let token = bpng_token(&bpng_claims(), &session_key(7));
    let mut tampered = token.clone();
    tampered[10] ^= 1;
    for android in [true, false] {
        for bad in [
            bpng_token(&bpng_claims(), &session_key(8)),
            tampered.clone(),
            vec![b'x'; 16_385],
        ] {
            assert!(
                selected
                    .enrollment_session(android, [&bad, b"", bpng_root(android)])
                    .is_err()
            );
        }
        assert!(
            selected
                .enrollment_session(android, [&token, b"offered DPoP", bpng_root(android)])
                .is_err()
        );
        // Product selection, not an empty frame supplied by managed code, selects BPNG.
        let cbsi = BaseFixture::new().load().unwrap();
        assert!(
            cbsi.enrollment_session(android, [&token, b"", bpng_root(android)])
                .is_err()
        );
    }
    // Apple requires exactly the signed runtime's root; Android refuses any offered root,
    // including the genuine Apple one.
    for root in [b"wrong root".as_slice(), b""] {
        assert!(
            selected
                .enrollment_session(false, [&token, b"", root])
                .is_err()
        );
    }
    for root in [b"wrong root".as_slice(), SESSION_ROOT] {
        assert!(
            selected
                .enrollment_session(true, [&token, b"", root])
                .is_err()
        );
    }
}

#[test]
fn bpng_session_rejects_resigned_foreign_incomplete_and_invalid_claims() {
    let selected = BpngFixture::new().load().unwrap();
    let claims = bpng_claims();
    let mut mutations = Vec::new();
    for (name, value) in [
        ("iss", Value::String("cbsi-fi-core-anz".into())),
        ("aud", Value::String("anz.cbsi".into())),
        ("dataspace_id", Value::String("bpng".into())),
        ("sub", Value::String(" owner@example.test".into())),
        ("roles", norito::json!(["FI_ADMIN"])),
        ("roles", norito::json!(["RETAIL_USER", "FI_ADMIN"])),
        ("nbf", norito::json!(1001)),
        ("exp", norito::json!(1000)),
        ("iat", norito::json!(0)),
        ("cnf", norito::json!({"jkt":("unselected")})),
    ] {
        let mut changed = claims.clone();
        mutate(&mut changed, name, value);
        mutations.push(changed);
    }
    for name in claims.as_object().unwrap().keys() {
        let mut changed = claims.clone();
        object_mut(&mut changed).remove(name);
        mutations.push(changed);
    }
    for changed in mutations {
        let token = bpng_token(&changed, &session_key(7));
        for android in [true, false] {
            assert!(
                selected
                    .enrollment_session(android, [&token, b"", bpng_root(android)])
                    .is_err()
            );
        }
    }
}

#[test]
fn bpng_public_session_selection_has_no_unsigned_or_unknown_field_fallback() {
    let selection = bpng_session_selection();
    for name in selection.as_object().unwrap().keys() {
        let mut fixture = BpngFixture::new();
        let offered = object_mut(&mut fixture.0.runtime)
            .get_mut("enrollment_session")
            .unwrap();
        object_mut(offered).remove(name);
        assert!(fixture.load().is_err());
    }
    for (name, value) in [
        ("jwt_public_key_hex", Value::String("00".repeat(32))),
        ("fi_id", Value::String("anz.cbsi".into())),
        (
            "jwt_issuer",
            Value::String("https://unselected.example".into()),
        ),
        ("jwt_audience", Value::String("bpng".into())),
        (
            "schema",
            Value::String("cbsi.fi-session-enrollment-selection.v1".into()),
        ),
        ("caller_authorized", Value::Bool(true)),
    ] {
        let mut fixture = BpngFixture::new();
        let offered = object_mut(&mut fixture.0.runtime)
            .get_mut("enrollment_session")
            .unwrap();
        mutate(offered, name, value);
        assert!(fixture.load().is_err());
    }
    let mut fixture = BpngFixture::new();
    object_mut(&mut fixture.0.runtime).remove("enrollment_session");
    assert!(fixture.load().is_err());
}

#[test]
fn bpng_public_apple_root_must_match_the_signed_policy_and_android_selects_none() {
    for replacement in [None, Some(""), Some("YQ=="), Some("YQ"), Some(" YQ==")] {
        let mut fixture = BpngFixture::new();
        let platform = object_mut(object_mut(&mut fixture.0.runtime).get_mut("apple").unwrap());
        if let Some(value) = replacement {
            platform.insert(
                "attestation_root_der_base64".into(),
                Value::String(value.into()),
            );
        } else {
            platform.remove("attestation_root_der_base64");
        }
        assert!(fixture.load().is_err());
    }
    // The retired Android root DER original is refused even when it is well formed.
    for value in [STANDARD.encode(SESSION_ROOT), "YQ==".into(), String::new()] {
        let mut fixture = BpngFixture::new();
        object_mut(
            object_mut(&mut fixture.0.runtime)
                .get_mut("android")
                .unwrap(),
        )
        .insert("attestation_root_der_base64".into(), Value::String(value));
        assert!(fixture.load().is_err());
    }
    let selected = BpngFixture::new().load().unwrap();
    let mut claims = bpng_claims();
    mutate(&mut claims, "sub", Value::String("a".repeat(257)));
    let token = bpng_token(&claims, &session_key(7));
    assert!(
        selected
            .enrollment_session(true, [&token, b"", b""])
            .is_err()
    );
}
#[test]
fn bpng_android_policy_with_unqualified_vendor_adapter_fails_configuration() {
    let mut roots = google_roots();
    roots.push(vendor_root("huawei"));
    let mut fixture = BpngFixture::new();
    fixture.0.set_android_platform(android_platform(roots));
    assert!(matches!(
        fixture.load(),
        Err(Failure {
            status: INVALID,
            ..
        })
    ));
}
fn bpng_sign(key: &KeyPair, app: &[u8]) -> Vec<u8> {
    let mut message = b"bpng:taira-app-runtime-manifest:v7\0".to_vec();
    message.extend_from_slice(app);
    let signature = Signature::try_new(key.private_key(), &message).unwrap();
    let (_, public) = key.public_key().to_bytes();
    canonical(
        &norito::json!({"schema":("bpng.taira-app-runtime-manifest-signature.v7"),"algorithm":("ed25519"),"domain":("bpng:taira-app-runtime-manifest:v7"),"keyId":(format!("sha256:{}",hex::encode(BlobV1::of(public).sha256))),"manifestSha256":(hex::encode(BlobV1::of(app).sha256)),"signatureBase64Url":(URL_SAFE_NO_PAD.encode(signature.payload()))}),
    )
}

#[test]
fn bpng_genuine_signed_originals_retain_the_exact_product_and_native_policy() {
    let fixture = BpngFixture::new();
    let selected = fixture.load().unwrap();
    let (app, envelope, runtime) = fixture.originals();
    assert!(
        matches!(selected.application, ApplicationBinding::BpngTairaV7 { _wallet_runtime_sha256 } if _wallet_runtime_sha256 == BlobV1::of(&runtime).sha256)
    );
    assert_eq!(selected._originals._app_manifest.as_ref(), app);
    assert_eq!(selected._originals._envelope.as_ref(), envelope);
    assert_eq!(selected._originals._wallet_runtime.as_ref(), runtime);
    assert_eq!(
        selected._originals._signed_genesis.as_ref(),
        fixture.0.genesis
    );
    assert_eq!(
        selected.asset.asset.to_string(),
        "839FV3NJC8NfgWQvghXU2hEFQm9a"
    );
    assert_eq!(selected.scheme.scheme_id(), fixture.0.scheme.scheme_id());
    let retained_runtime = json(
        &selected._originals._wallet_runtime,
        WALLET_RUNTIME_MAX,
        false,
    )
    .unwrap();
    for name in ["android", "apple"] {
        let retained = object(field(object(&retained_runtime).unwrap(), name).unwrap()).unwrap();
        let offered = object(field(object(&fixture.0.runtime).unwrap(), name).unwrap()).unwrap();
        let original = raw(retained, "enrollment_policy_original_base64", 1024).unwrap();
        assert_eq!(
            original,
            raw(offered, "enrollment_policy_original_base64", 1024).unwrap()
        );
        let policy = KagemushaWalletEnrollmentPolicyV1::decode_canonical(
            &original,
            &fixture.0.scheme.scheme_id(),
        )
        .unwrap();
        assert_eq!(
            policy.policy_digest().unwrap(),
            sha(text(retained, "enrollment_policy_hex").unwrap()).unwrap()
        );
    }
}
#[test]
fn bpng_signature_authority_has_no_cross_product_or_key_fallback() {
    let bpng = BpngFixture::new();
    let cbsi = BaseFixture::new();
    let (app, envelope, _) = bpng.originals();
    assert!(
        signed_app(
            &RuntimeTrust::test(bpng.0.key.public_key().clone()),
            &app,
            &envelope
        )
        .is_err()
    );
    let other = KeyPair::from_seed(vec![21; 32], Algorithm::Ed25519);
    assert!(
        signed_app(
            &RuntimeTrust {
                authority: RuntimeAuthority::BpngTairaV7,
                key: other.public_key().clone()
            },
            &app,
            &envelope
        )
        .is_err()
    );
    let (cbsi_app, cbsi_envelope, _) = cbsi.originals();
    assert!(signed_app(&bpng.trust(), &cbsi_app, &cbsi_envelope).is_err());
    assert!(signed_app(&bpng.trust(), &cbsi_app, &bpng_sign(&bpng.0.key, &cbsi_app)).is_err());
    assert!(
        signed_app(
            &RuntimeTrust::test(bpng.0.key.public_key().clone()),
            &app,
            &sign(&bpng.0.key, &app)
        )
        .is_err()
    );
    let mut changed = json(&envelope, ENVELOPE_MAX, true).unwrap();
    let padded = format!(
        "{}==",
        text(object(&changed).unwrap(), "signatureBase64Url").unwrap()
    );
    mutate(&mut changed, "signatureBase64Url", Value::String(padded));
    assert!(signed_app(&bpng.trust(), &app, &canonical(&changed)).is_err());
}
#[test]
fn bpng_whole_application_and_runtime_original_bytes_are_authenticated() {
    let fixture = BpngFixture::new();
    let (app, envelope, runtime) = fixture.originals();
    let mut changed = json(&app, APP_MANIFEST_MAX, true).unwrap();
    mutate(
        object_mut(&mut changed).get_mut("evidence").unwrap(),
        "nativeReleaseReceiptSha256",
        Value::String("ee".repeat(32)),
    );
    assert!(
        fixture
            .load_originals(&canonical(&changed), &envelope, &runtime)
            .is_err()
    );
    let mut changed_runtime = runtime.clone();
    changed_runtime.push(b'\n');
    assert!(
        fixture
            .load_originals(&app, &envelope, &changed_runtime)
            .is_err()
    );
    for (name, value) in [
        ("schema", "bpng.current-wallet-runtime-pin.v2"),
        ("currentRuntimeSha256", &"ff".repeat(32)),
    ] {
        let mut changed = json(&app, APP_MANIFEST_MAX, true).unwrap();
        mutate(
            object_mut(&mut changed).get_mut("walletRuntime").unwrap(),
            name,
            Value::String(value.into()),
        );
        let changed = canonical(&changed);
        assert!(
            fixture
                .load_originals(&changed, &bpng_sign(&fixture.0.key, &changed), &runtime)
                .is_err()
        );
    }
}
#[test]
fn bpng_current_signed_allocation_accepts_lane_eight() {
    let mut fixture = BpngFixture::new();
    for section in ["digitalKina", "routing"] {
        mutate(
            object_mut(&mut fixture.0.app).get_mut(section).unwrap(),
            "physicalLaneId",
            Value::from(8u64),
        );
    }
    fixture.load().unwrap();
}
#[test]
fn bpng_lane_selection_keeps_bounds_routing_and_original_signature_binding() {
    for lane in [0u64, 3, u64::from(u32::MAX) + 1] {
        let mut fixture = BpngFixture::new();
        for section in ["digitalKina", "routing"] {
            mutate(
                object_mut(&mut fixture.0.app).get_mut(section).unwrap(),
                "physicalLaneId",
                Value::from(lane),
            );
        }
        assert!(fixture.load().is_err(), "lane {lane}");
    }
    let mut fixture = BpngFixture::new();
    let (_, original_envelope, runtime) = fixture.originals();
    for section in ["digitalKina", "routing"] {
        mutate(
            object_mut(&mut fixture.0.app).get_mut(section).unwrap(),
            "physicalLaneId",
            Value::from(8u64),
        );
    }
    let (changed_app, _, _) = fixture.originals();
    assert!(
        fixture
            .load_originals(&changed_app, &original_envelope, &runtime)
            .is_err()
    );
    mutate(
        object_mut(&mut fixture.0.app).get_mut("routing").unwrap(),
        "physicalLaneId",
        Value::from(41u64),
    );
    assert!(fixture.load().is_err());
}
#[test]
fn bpng_signed_projection_refuses_foreign_network_asset_routes_and_service() {
    for (section, name, value) in [
        (
            "ledger",
            "toriiUrl",
            Value::String("https://bokolo.soramitsu.io".into()),
        ),
        ("ledger", "chainId", Value::String("foreign-chain".into())),
        ("ledger", "networkPrefix", Value::from(0u64)),
        (
            "digitalKina",
            "assetAlias",
            Value::String("sbd#cbsi".into()),
        ),
        (
            "digitalKina",
            "assetDefinitionId",
            Value::String("7ZepsJTHCVLKsrFFNZGSRGZgvBhv".into()),
        ),
        ("digitalKina", "scale", Value::from(3u64)),
        ("digitalKina", "physicalLaneId", Value::from(8u64)),
        ("routing", "physicalLaneId", Value::from(42u64)),
        (
            "routing",
            "mibankAliasScope",
            Value::String("mibank".into()),
        ),
        (
            "services",
            "coreApiUrl",
            Value::String("https://other.invalid".into()),
        ),
    ] {
        let mut fixture = BpngFixture::new();
        mutate(
            object_mut(&mut fixture.0.app).get_mut(section).unwrap(),
            name,
            value,
        );
        assert!(fixture.load().is_err(), "{section}.{name}");
    }
    let mut fixture = BpngFixture::new();
    let Value::Array(rows) =
        object_mut(object_mut(&mut fixture.0.app).get_mut("consensus").unwrap())
            .get_mut("validators")
            .unwrap()
    else {
        panic!("validators")
    };
    mutate(
        &mut rows[0],
        "directToriiUrl",
        Value::String("https://other.invalid".into()),
    );
    assert!(fixture.load().is_err());
    let mut fixture = BpngFixture::new();
    object_mut(&mut fixture.0.app).insert(
        "service_release_scope".into(),
        Value::String("11".repeat(32)),
    );
    assert!(fixture.load().is_err());
}
#[test]
fn bpng_current_runtime_requires_exact_policy_originals_and_core_data_paths() {
    for (name, value) in [
        (
            "schema",
            Value::String("cbsi.kagemusha.wallet-runtime.v1".into()),
        ),
        ("python_path", Value::String("/usr/../python".into())),
        ("openssl_sha256", Value::String("0".repeat(64))),
    ] {
        let mut fixture = BpngFixture::new();
        mutate(&mut fixture.0.runtime, name, value);
        assert!(fixture.load().is_err());
    }
    for name in ["android", "apple"] {
        for (key, value) in [
            (
                "verifier_configuration_path",
                Value::String("srv/etc/other.json".into()),
            ),
            ("enrollment_policy_hex", Value::String("ee".repeat(32))),
            ("app_policy_original_base64", Value::String("AA==".into())),
        ] {
            let mut fixture = BpngFixture::new();
            mutate(
                object_mut(&mut fixture.0.runtime).get_mut(name).unwrap(),
                key,
                value,
            );
            assert!(fixture.load().is_err());
        }
    }
}
#[test]
fn bpng_eligibility_template_is_required_canonical_and_bound_to_selected_scheme() {
    let mut missing = BpngFixture::new();
    object_mut(&mut missing.0.runtime).remove("eligibility_template_hex");
    assert!(missing.load().is_err());
    for encoded in ["".to_owned(), "AA".repeat(64), "01".repeat(2049)] {
        let mut fixture = BpngFixture::new();
        mutate(
            &mut fixture.0.runtime,
            "eligibility_template_hex",
            Value::String(encoded),
        );
        assert!(fixture.load().is_err());
    }
    for field in ["network", "scheme"] {
        let mut fixture = BpngFixture::new();
        let Value::String(encoded) = &fixture.0.runtime["eligibility_template_hex"] else {
            panic!("eligibility template")
        };
        let mut template =
            iroha_data_model::kagemusha::KagemushaEligibilityPolicyTemplateV1::decode_canonical(
                &hex::decode(encoded).unwrap(),
            )
            .unwrap();
        if field == "network" {
            template.network_id = [37; 32];
        } else {
            template.scheme_id = [39; 32];
        }
        mutate(
            &mut fixture.0.runtime,
            "eligibility_template_hex",
            Value::String(hex::encode(template.encode_canonical().unwrap())),
        );
        assert!(fixture.load().is_err());
    }
}

#[test]
fn bpng_checkpoint_all_null_or_exact_native_nonzero_context_is_required() {
    let mut fixture = BpngFixture::new();
    fixture.load().unwrap();
    let consensus = object_mut(&mut fixture.0.app).get_mut("consensus").unwrap();
    mutate(
        consensus,
        "checkpointSha256",
        Value::String("aa".repeat(32)),
    );
    mutate(consensus, "checkpointHeight", Value::from(2u64));
    mutate(
        consensus,
        "checkpointContextId",
        Value::String("ab".repeat(32)),
    );
    fixture.load().unwrap();
    for (name, value) in [
        ("checkpointSha256", Value::Null),
        ("checkpointHeight", Value::from(1u64)),
        ("checkpointContextId", Value::String("ac".repeat(32))),
        (
            "checkpointContextId",
            Value::String(format!("{}1", "0".repeat(63))),
        ),
    ] {
        let mut changed = fixture.0.app.clone();
        mutate(
            object_mut(&mut changed).get_mut("consensus").unwrap(),
            name,
            value,
        );
        assert!(
            bpng::checkpoint(
                object(field(object(&changed).unwrap(), "consensus").unwrap()).unwrap()
            )
            .is_err()
        );
    }
}

#[test]
fn bpng_metadata_uses_exact_utc_calendar_and_nonzero_source_commit() {
    for timestamp in [
        "2026-02-29T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-01-00T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:60:00Z",
        "2026-01-01T00:00:60Z",
    ] {
        let mut fixture = BpngFixture::new();
        mutate(
            &mut fixture.0.app,
            "generatedAt",
            Value::String(timestamp.into()),
        );
        assert!(fixture.load().is_err());
    }
    let mut fixture = BpngFixture::new();
    mutate(
        &mut fixture.0.app,
        "generatedAt",
        Value::String("2024-02-29T23:59:59Z".into()),
    );
    fixture.load().unwrap();
    mutate(
        object_mut(&mut fixture.0.app).get_mut("ledger").unwrap(),
        "irohaSourceCommit",
        Value::String("0".repeat(40)),
    );
    assert!(fixture.load().is_err());
}

// Financial DATA cannot satisfy a genuine verifier/prover loader; these tests
// establish signed selection and failure ordering, never financial readiness.
const TEST_TRANSPORT: &[u8] = b"PUBLIC_SOFTWARE_DATA_UNADMITTED_TRANSPORT";
fn financial_record() -> Value {
    let blob = |bytes: &[u8]| norito::json!({"bytes":(bytes.len()),"sha256":(hex::encode(BlobV1::of(bytes).sha256))});
    norito::json!({"schema":("iroha.kagemusha.wallet-financial-originals.v1"),
        "verifierPack":(blob(TEST_PACK)),"producerInventory":(blob(TEST_CATALOG)),
        "transport":(blob(TEST_TRANSPORT)),"producerCatalogDigest":(hex::encode([0x13; 32]))})
}
#[test]
fn bpng_null_financial_selection_authenticates_base_then_returns_unavailable_without_owner() {
    let mut fixture = BpngFixture::new();
    fixture.1 = Value::Null;
    let (app, envelope, runtime) = fixture.originals();
    let selected = Arc::new(fixture.load_offered(&app, &envelope, &runtime, 0).unwrap());
    assert!(selected.financial.is_none());
    assert_eq!(selected.scheme.scheme_id(), fixture.0.scheme.scheme_id());
    assert!(matches!(
        PreparedInstallation::from_selected(
            RuntimeOriginals {
                app_manifest: &app,
                envelope: &envelope,
                wallet_runtime: &runtime,
                verifier_pack: b"",
                producer_inventory: b"",
                signed_genesis: &fixture.0.genesis,
                originals_root: b"",
                registration_source: b"",
            },
            selected,
            OpeningMetricsV1::start()
        ),
        Err(Failure {
            status: ARTIFACTS_UNAVAILABLE,
            ..
        })
    ));
}
#[test]
fn bpng_financial_pin_and_original_tuple_refuse_downgrade_and_partial_offers() {
    for financial in [Value::Null, financial_record()] {
        let mut fixture = BpngFixture::new();
        fixture.1 = financial;
        let (app, envelope, runtime) = fixture.originals();
        for offered in 0..8 {
            assert_eq!(
                fixture
                    .load_offered(&app, &envelope, &runtime, offered)
                    .is_ok(),
                offered == if fixture.1 == Value::Null { 0 } else { 7 }
            );
        }
    }
    let fixture = BpngFixture::new();
    let (app, envelope, runtime) = fixture.originals();
    let selected = Arc::new(fixture.load().unwrap());
    assert!(matches!(
        PreparedInstallation::from_selected(
            RuntimeOriginals {
                app_manifest: &app,
                envelope: &envelope,
                wallet_runtime: &runtime,
                verifier_pack: b"",
                producer_inventory: b"",
                signed_genesis: &fixture.0.genesis,
                originals_root: b"",
                registration_source: b"",
            },
            selected,
            OpeningMetricsV1::start()
        ),
        Err(Failure {
            status: INVALID,
            ..
        })
    ));
}
#[test]
fn bpng_initial_absence_still_authenticates_each_base_original() {
    let mut fixture = BpngFixture::new();
    fixture.1 = Value::Null;
    let (app, envelope, runtime) = fixture.originals();
    for changed in 0..4 {
        let mut app = app.clone();
        let mut envelope = envelope.clone();
        let mut runtime = runtime.clone();
        let mut genesis = fixture.0.genesis.clone();
        match changed {
            0 => app[3] ^= 1,
            1 => envelope[3] ^= 1,
            2 => runtime[3] ^= 1,
            _ => genesis[0] ^= 1,
        }
        assert!(
            Selection::load(
                &fixture.trust(),
                &RuntimeOriginals {
                    app_manifest: &app,
                    envelope: &envelope,
                    wallet_runtime: &runtime,
                    verifier_pack: b"",
                    producer_inventory: b"",
                    signed_genesis: &genesis,
                    originals_root: b"",
                    registration_source: b"",
                }
            )
            .is_err()
        );
    }
    let mut missing = json(&app, APP_MANIFEST_MAX, true).unwrap();
    object_mut(object_mut(&mut missing).get_mut("walletRuntime").unwrap())
        .remove("financialOriginals");
    let missing = canonical(&missing);
    assert!(
        fixture
            .load_offered(&missing, &bpng_sign(&fixture.0.key, &missing), &runtime, 0)
            .is_err()
    );
}
#[test]
fn bpng_full_financial_record_is_closed_and_binds_actual_whole_originals() {
    let fixture = BpngFixture::new();
    let financial = fixture.load().unwrap().financial.unwrap();
    assert_eq!(financial.pack_identity, BlobV1::of(TEST_PACK));
    assert_eq!(financial.catalog_identity, BlobV1::of(TEST_CATALOG));
    assert_eq!(financial.transport_identity, BlobV1::of(TEST_TRANSPORT));
    assert_eq!(
        financial.original().unwrap(),
        canonical(&financial_record())
    );
    for key in [
        "schema",
        "verifierPack",
        "producerInventory",
        "transport",
        "producerCatalogDigest",
    ] {
        let mut fixture = BpngFixture::new();
        object_mut(&mut fixture.1).remove(key);
        assert!(fixture.load().is_err());
    }
    for key in ["verifierPack", "producerInventory", "transport"] {
        for (field, value) in [
            ("bytes", Value::from(0u64)),
            ("bytes", Value::from(u64::MAX)),
            ("sha256", Value::String("0".repeat(64))),
            ("sha256", Value::String("A".repeat(64))),
        ] {
            let mut fixture = BpngFixture::new();
            mutate(
                object_mut(&mut fixture.1).get_mut(key).unwrap(),
                field,
                value,
            );
            assert!(fixture.load().is_err());
        }
    }
    for key in ["verifierPack", "producerInventory"] {
        let mut fixture = BpngFixture::new();
        mutate(
            object_mut(&mut fixture.1).get_mut(key).unwrap(),
            "sha256",
            Value::String("ff".repeat(32)),
        );
        assert!(fixture.load().is_err());
    }
    let mut fixture = BpngFixture::new();
    mutate(&mut fixture.1, "authority", Value::Bool(true));
    assert!(fixture.load().is_err());
}
#[test]
fn bpng_v7_rejects_obsolete_retail_policy_even_with_authentic_signature() {
    for offered in [0, 7] {
        let mut baseline = BpngFixture::new();
        if offered == 0 {
            baseline.1 = Value::Null;
        }
        assert!(
            !object(&baseline.0.app)
                .unwrap()
                .contains_key("retailPolicy")
        );
        let (app, envelope, runtime) = baseline.originals();
        baseline
            .load_offered(&app, &envelope, &runtime, offered)
            .unwrap();
        for obsolete in [
            Value::Null,
            norito::json!({}),
            norito::json!({
                "dataspaceAlias": ("mibank.bpng"),
                "identityDailyLimitKina": ("1000"),
                "nativePolicySelection": (norito::json!({
                    "activationEntryHash": ("bb".repeat(32)),
                    "activationOwnerAccountId": ("obsolete-policy-owner"),
                    "policySha256": ("cc".repeat(32))
                }))
            }),
        ] {
            let mut document = json(&app, APP_MANIFEST_MAX, true).unwrap();
            object_mut(&mut document).insert("retailPolicy".into(), obsolete);
            let document = canonical(&document);
            // Re-sign every obsolete offer with the exact selected v7 authority.
            let signature = bpng_sign(&baseline.0.key, &document);
            assert!(matches!(
                baseline.load_offered(&document, &signature, &runtime, offered),
                Err(Failure {
                    status: INVALID,
                    ..
                })
            ));
        }
    }
}

#[test]
fn bpng_asset_is_bound_to_signed_current_native_original_not_a_retired_identifier() {
    let fixture = BpngFixture::with_asset("7ZepsJTHCVLKsrFFNZGSRGZgvBhv");
    assert_eq!(
        fixture.load().unwrap().asset.asset.to_string(),
        "7ZepsJTHCVLKsrFFNZGSRGZgvBhv"
    );
}

#[test]
fn bpng_direct_home_requires_domain_absence_and_exact_native_dataspace() {
    for policy in ["Global", "DataspaceRestricted"] {
        let mut fixture = BpngFixture::new();
        mutate(
            object_mut(&mut fixture.0.app)
                .get_mut("digitalKina")
                .unwrap(),
            "balanceScopePolicy",
            Value::String(policy.into()),
        );
        fixture.load().unwrap();
    }
    for (field, value) in [
        ("owningDomain", Value::String("bpng.bpng".into())),
        ("owningDataspace", Value::Null),
        (
            "owningDataspace",
            Value::String("08648377547929788715".into()),
        ),
        ("owningDataspace", Value::from(8648377547929788715u64)),
        ("owningDataspace", Value::String("1".into())),
        ("balanceScopePolicy", Value::String("global".into())),
        ("balanceScopePolicy", Value::Null),
    ] {
        let mut fixture = BpngFixture::new();
        mutate(
            object_mut(&mut fixture.0.app)
                .get_mut("digitalKina")
                .unwrap(),
            field,
            value,
        );
        assert!(fixture.load().is_err(), "{field}");
    }
    for field in ["owningDomain", "owningDataspace", "balanceScopePolicy"] {
        let mut fixture = BpngFixture::new();
        object_mut(
            object_mut(&mut fixture.0.app)
                .get_mut("digitalKina")
                .unwrap(),
        )
        .remove(field);
        assert!(fixture.load().is_err(), "missing {field}");
    }
}

#[test]
fn bpng_v7_rejects_retired_v6_application_and_signature_domains() {
    let fixture = BpngFixture::new();
    let (app, envelope, runtime) = fixture.originals();
    let mut previous = json(&app, APP_MANIFEST_MAX, true).unwrap();
    mutate(
        &mut previous,
        "schema",
        Value::String("bpng.taira-app-runtime-manifest.v6".into()),
    );
    let previous = canonical(&previous);
    assert!(
        fixture
            .load_originals(&previous, &bpng_sign(&fixture.0.key, &previous), &runtime)
            .is_err()
    );
    let mut previous = json(&envelope, ENVELOPE_MAX, true).unwrap();
    mutate(
        &mut previous,
        "schema",
        Value::String("bpng.taira-app-runtime-manifest-signature.v6".into()),
    );
    mutate(
        &mut previous,
        "domain",
        Value::String("bpng:taira-app-runtime-manifest:v6".into()),
    );
    let mut message = b"bpng:taira-app-runtime-manifest:v6\0".to_vec();
    message.extend_from_slice(&app);
    let signature = Signature::try_new(fixture.0.key.private_key(), &message).unwrap();
    mutate(
        &mut previous,
        "signatureBase64Url",
        Value::String(URL_SAFE_NO_PAD.encode(signature.payload())),
    );
    assert!(
        fixture
            .load_originals(&app, &canonical(&previous), &runtime)
            .is_err()
    );
}

#[test]
fn bpng_v7_refuses_retired_first_device_otp_anchor_and_finality_pin_members() {
    // A runtime without these members is the current contract (no firstDeviceAuthentication
    // selection, as every phone, iPhone included, needs).
    let fixture = BpngFixture::new();
    for name in [
        "firstDeviceAuthentication",
        "authentication",
        "retailStageAnchorAuthority",
    ] {
        assert!(!object(&fixture.0.app).unwrap().contains_key(name));
    }
    assert!(
        !object(&fixture.0.app["consensus"])
            .unwrap()
            .contains_key("finalityVerifierSha256")
    );
    fixture.load().unwrap();
    let (app, _, runtime) = fixture.originals();
    // Each retired member, genuinely re-signed by the exact v7 authority, is refused rather
    // than ignored: the exact member lists of Native, Core and both apps flip together.
    for (name, value) in [
        (
            "firstDeviceAuthentication",
            norito::json!({"schema":("bpng.first-device-auth-runtime-selection.v1"),"googleOAuthClientId":("fixture-client.apps.googleusercontent.com"),"googleOAuthIssuer":("https://accounts.google.com"),"integrityCloudProjectNumber":(123456789),"originalAuthPolicySha256":("11".repeat(32)),"verifierConfigurationSha256":("22".repeat(32)),"googlePolicySha256":("33".repeat(32))}),
        ),
        (
            "authentication",
            norito::json!({"schema":("bpng.taira-poc-auth-policy.v1"),"otpMode":("poc-fixed"),"otpFixedCode":("123456"),"totpMode":("poc-fixed")}),
        ),
        (
            "retailStageAnchorAuthority",
            norito::json!({"purpose":("bpng.retail-stage-sumeragi-anchor.v1"),"algorithm":("ed25519")}),
        ),
        ("firstDeviceAuthentication", Value::Null),
    ] {
        let mut document = json(&app, APP_MANIFEST_MAX, true).unwrap();
        object_mut(&mut document).insert(name.into(), value);
        let document = canonical(&document);
        let signature = bpng_sign(&fixture.0.key, &document);
        assert!(
            signed_app(&fixture.trust(), &document, &signature).is_err(),
            "{name}"
        );
        assert!(
            fixture
                .load_originals(&document, &signature, &runtime)
                .is_err(),
            "{name}"
        );
    }
    let mut document = json(&app, APP_MANIFEST_MAX, true).unwrap();
    mutate(
        object_mut(&mut document).get_mut("consensus").unwrap(),
        "finalityVerifierSha256",
        Value::String("ff".repeat(32)),
    );
    let document = canonical(&document);
    assert!(
        fixture
            .load_originals(&document, &bpng_sign(&fixture.0.key, &document), &runtime)
            .is_err()
    );
}
