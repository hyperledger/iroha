//! Generic release and exact native registration component tests. Synthetic successful rows do
//! not qualify real asset execution, a complete financial grant, hardware or a device runtime.
use super::*;
use iroha_core_zk::kagemusha_wallet_registration_v1::{
    RegistrationSelectionV1, publish_registration_source_v1,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    account::AccountId,
    asset::AssetBalanceScope,
    block::{BlockSignatures, builder::BlockBuilder},
    isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
    query::CommittedTransaction,
    transaction::{FeePaymentIntent, TransactionBuilder},
};
fn encode<T: norito::core::NoritoSerialize>(value: &T) -> Vec<u8> {
    norito::encode_canonical(value).unwrap()
}
fn selection(f: &BaseFixture) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let runtime = object(&f.runtime).unwrap();
    let mut generic = runtime.clone();
    for key in [
        "asset_original_base64",
        "regulatory_policy_original_base64",
        "challenge_lifetime_ms",
    ] {
        generic.remove(key);
    }
    generic.insert(
        "schema".into(),
        Value::String("iroha.kagemusha.wallet-runtime.v1".into()),
    );
    for platform in ["android", "apple"] {
        let row = object(field(runtime, platform).unwrap()).unwrap();
        let policy = KagemushaWalletEnrollmentPolicyV1::decode_canonical(
            &raw(row, "enrollment_policy_original_base64", 1024).unwrap(),
            &f.scheme.scheme_id(),
        )
        .unwrap();
        let mut selected = norito::json!({"app_policy_original_base64":(text(row,"app_policy_original_base64").unwrap()),"enrollment_template_original_base64":(STANDARD.encode(policy.template().encode_canonical().unwrap()))});
        // Only Apple selects a root DER original; Android pins roots by SPKI in its policy.
        if platform == "apple" {
            object_mut(&mut selected).insert(
                "attestation_root_der_base64".into(),
                Value::String(STANDARD.encode(SESSION_ROOT)),
            );
        }
        generic.insert(platform.into(), selected);
    }
    let (_, key) = f.key.public_key().to_bytes();
    generic.insert("sessions".into(), norito::json!([{"issuer":("community-provider"),"audience":("universal-provider"),"requestOrigin":("https://provider.example"),"verificationKeyEd25519Base64":(STANDARD.encode(key)),"releaseOriginalBase64":(STANDARD.encode(b"independent-provider-release")),"androidClientApp":("org.example.wallet"),"appleClientApp":("TEAM.org.example.wallet"),"enrollmentChallengePath":("/v1/kagemusha/enrollment"),"roles":[("WALLET_USER")],"requiredRole":("WALLET_USER")} ]));
    let runtime = canonical(&Value::Object(generic));
    let native = NativeFinalityFixture::start("fc56984b-2be7-431d-840e-21514d1883f0");
    let public = native
        .genesis()
        .external_transactions()
        .next()
        .unwrap()
        .authority()
        .try_signatory()
        .unwrap()
        .to_string();
    let identity = |raw: &[u8]| norito::json!({"bytes":(raw.len()),"sha256":(hex::encode(BlobV1::of(raw).sha256))});
    let app = canonical(
        &norito::json!({"schema":("iroha.kagemusha.wallet-application-release.v1"),"nativeBridgeAbiVersion":(crate::CONNECT_NORITO_BRIDGE_ABI_VERSION),"runtimeSha256":(hex::encode(BlobV1::of(&runtime).sha256)),"signedGenesisSha256":(hex::encode(BlobV1::of(&f.genesis).sha256)),"genesisBlockHash":(hex::encode(native.genesis().hash().as_ref())),"genesisPublicKey":(public),"chainId":(native.chain_id()),"networkId":(native.network_id().to_string()),"financialOriginals":{"verifierPack":(identity(TEST_PACK)),"producerInventory":(identity(TEST_CATALOG)),"producerCatalogDigest":("13".repeat(32)),"transport":(identity(b"unadmitted-transport-metadata"))}}),
    );
    let envelope = sign_generic(f, &app);
    (app, envelope, runtime)
}
fn sign_generic(f: &BaseFixture, app: &[u8]) -> Vec<u8> {
    let domain = "iroha.kagemusha.wallet-application-release.v1";
    let mut msg = domain.as_bytes().to_vec();
    msg.push(0);
    msg.extend_from_slice(app);
    let signature = Signature::try_new(f.key.private_key(), &msg).unwrap();
    let (_, key) = f.key.public_key().to_bytes();
    canonical(
        &norito::json!({"schema":("iroha.kagemusha.wallet-application-release-signature.v1"),"algorithm":("ed25519"),"domain":(domain),"keyId":(format!("sha256:{}",hex::encode(BlobV1::of(key).sha256))),"manifestSha256":(hex::encode(BlobV1::of(app).sha256)),"signatureBase64":(STANDARD.encode(signature.payload()))}),
    )
}
fn registration(
    f: &BaseFixture,
    parent: &iroha_fs::PrivateDirectory,
    name: &str,
    seed: u8,
    scale: u32,
) -> (Vec<u8>, KagemushaWalletAssetScopeV1) {
    let mut native = NativeFinalityFixture::start("fc56984b-2be7-431d-840e-21514d1883f0");
    let genesis = native.verifier();
    let asset = KagemushaWalletAssetScopeV1::new(
        AssetDefinitionId::from_uuid_bytes([
            seed, 1, 2, 3, 4, 5, 0x46, 7, 0x88, 9, 10, 11, 12, 13, 14, 15,
        ])
        .unwrap(),
        &AxtAssetIncarnationV1::try_from_bytes(*Hash::new([seed; 32]).as_ref()).unwrap(),
        scale,
    )
    .unwrap();
    let key = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let authority = AccountId::new(key.public_key().clone());
    let register = KagemushaWalletLedgerV1::new(
        f.scheme.scheme_id(),
        KagemushaWalletLedgerActionV1::Register {
            scheme: f.scheme.to_canonical_bytes().unwrap(),
            asset: encode(&asset),
            reserve: authority.clone(),
            balance_scope: AssetBalanceScope::Global,
        },
    );
    let header = native.next_header();
    let mut tx = TransactionBuilder::new(
        native.network_id(),
        authority,
        FeePaymentIntent::authority(vec![], None),
    );
    tx.set_creation_time(std::time::Duration::from_millis(
        header.creation_time_ms - 1,
    ));
    let mut builder = BlockBuilder::new(header);
    builder.push_transaction(tx.with_instructions([register]).sign(key.private_key()));
    let mut block = builder.build(BlockSignatures::default());
    NativeFinalityFixture::install_network_results(&mut block, vec![Ok(vec![])]);
    let proof = native.certify(block);
    let verified = native.verifier().verify_retained_decision(&proof).unwrap();
    let block = verified.block();
    let entrypoint = block.network_entrypoint_at(0).unwrap().clone();
    let (index, _) = block.network_output_at(0).unwrap();
    let output = block.execution_outputs()[index as usize].clone();
    let committed = CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block.network_input_proof(0).unwrap(),
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block.output_proof(index).unwrap(),
        output,
    };
    let proofs = [native.genesis_proof().clone(), proof];
    let (source, _) = publish_registration_source_v1(
        parent,
        name,
        RegistrationSelectionV1 {
            genesis: &genesis,
            scheme: &f.scheme,
            asset_digest: asset.asset_digest(),
            instruction_index: 0,
        },
        std::io::Cursor::new(encode(&committed)),
        proofs
            .iter()
            .map(|proof| Ok(std::io::Cursor::new(encode(proof)))),
        || false,
    )
    .unwrap();
    (source.encode_canonical().unwrap(), asset)
}
fn load(
    f: &BaseFixture,
    originals: &(Vec<u8>, Vec<u8>, Vec<u8>),
    source: &[u8],
) -> Result<Selection> {
    Selection::load(
        &RuntimeTrust {
            authority: RuntimeAuthority::ApplicationReleaseV1,
            key: f.key.public_key().clone(),
        },
        &RuntimeOriginals {
            app_manifest: &originals.0,
            envelope: &originals.1,
            wallet_runtime: &originals.2,
            verifier_pack: TEST_PACK,
            producer_inventory: TEST_CATALOG,
            signed_genesis: &f.genesis,
            originals_root: TEST_ROOT,
            registration_source: source,
        },
    )
}
#[test]
fn one_authenticated_release_derives_exact_policies_for_distinct_registered_tokens() {
    let f = BaseFixture::new();
    let original = selection(&f);
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let parent = iroha_fs::PrivateDirectory::open_exact(path).unwrap();
    for (name, seed, scale) in [("first", 2, 0), ("second", 4, 28)] {
        let (source, asset) = registration(&f, &parent, name, seed, scale);
        let selected = load(&f, &original, &source).unwrap();
        assert_eq!(selected.asset, asset);
        assert_eq!(selected.asset_original, encode(&asset));
        assert_eq!(
            selected.android_enrollment.1.asset_digest,
            asset.asset_digest()
        );
        assert_eq!(
            selected.apple_enrollment.1.asset_digest,
            asset.asset_digest()
        );
        assert_eq!(selected._originals._app_manifest.as_ref(), original.0);
        assert!(matches!(
            selected.application,
            ApplicationBinding::ApplicationReleaseV1 { .. }
        ));
    }
}
#[test]
fn generic_release_refuses_missing_registration_wrong_key_or_reintroduced_asset_allowlist() {
    let f = BaseFixture::new();
    let original = selection(&f);
    assert!(load(&f, &original, &[]).is_err());
    let wrong = RuntimeTrust {
        authority: RuntimeAuthority::ApplicationReleaseV1,
        key: KeyPair::from_seed(vec![91; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    };
    assert!(signed_app(&wrong, &original.0, &original.1).is_err());
    let mut document = json(&original.0, APP_MANIFEST_MAX, true).unwrap();
    object_mut(&mut document).insert(
        "asset".into(),
        Value::String("caller-selected-token".into()),
    );
    let bytes = canonical(&document);
    assert!(
        signed_app(
            &RuntimeTrust {
                authority: RuntimeAuthority::ApplicationReleaseV1,
                key: f.key.public_key().clone()
            },
            &bytes,
            &sign_generic(&f, &bytes)
        )
        .is_err()
    );
    let mut input = f.originals();
    input.2.push(0);
    assert!(load(&f, &input, &[]).is_err());
}

fn generic_session(f: &BaseFixture, android: bool, mutation: Option<&str>) -> [Vec<u8>; 3] {
    let proof_key = g1_key(31);
    let point = proof_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
    let jwk = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
    let encode = |value: Value| URL_SAFE_NO_PAD.encode(norito::json::to_json(&value).unwrap());
    let header = encode(norito::json!({"alg":("EdDSA"),"typ":("JWT")}));
    let mut claims = norito::json!({"sub":("alice@example.test"),"dataspace_id":("universal-provider"),"roles":[("WALLET_USER")],"iat":(1000),"nbf":(1000),"exp":(2000),"iss":("community-provider"),"aud":("universal-provider"),"device_id":("00000000-0000-4000-8000-000000000001"),"client_app":(if android {"org.example.wallet"}else{"TEAM.org.example.wallet"}),"cnf":{"jkt":(URL_SAFE_NO_PAD.encode(BlobV1::of(jwk.as_bytes()).sha256))}});
    if let Some(key @ ("iss" | "aud" | "dataspace_id" | "client_app")) = mutation {
        object_mut(&mut claims).insert(key.into(), Value::String("foreign".into()));
    }
    if mutation == Some("roles") {
        object_mut(&mut claims).insert("roles".into(), norito::json!([("RETAIL_USER")]));
    }
    let message = format!("{header}.{}", encode(claims));
    let signature = Signature::try_new(f.key.private_key(), message.as_bytes()).unwrap();
    let token = format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.payload())).into_bytes();
    let header = encode(
        norito::json!({"typ":("dpop+jwt"),"alg":("ES256"),"jwk":{"kty":("EC"),"crv":("P-256"),"x":(x),"y":(y)}}),
    );
    let mut claims = norito::json!({"htm":("POST"),"htu":("https://provider.example/v1/kagemusha/enrollment"),"iat":(1500),"jti":("00000000-0000-4000-8000-000000000002"),"ath":(URL_SAFE_NO_PAD.encode(BlobV1::of(&token).sha256))});
    if mutation == Some("htu") {
        object_mut(&mut claims).insert(
            "htu".into(),
            Value::String("https://foreign.example/v1/kagemusha/enrollment".into()),
        );
    }
    let message = format!("{header}.{}", encode(claims));
    let signature: G1Signature = proof_key.sign(message.as_bytes());
    let proof = format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())).into_bytes();
    let root = match (mutation == Some("root"), android) {
        (true, _) => b"foreign root".to_vec(),
        (false, true) => Vec::new(),
        (false, false) => SESSION_ROOT.to_vec(),
    };
    [token, proof, root]
}

#[test]
fn generic_provider_sessions_bind_selected_role_apps_origin_and_root() {
    let f = BaseFixture::new();
    let original = selection(&f);
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let parent = iroha_fs::PrivateDirectory::open_exact(path).unwrap();
    let (source, _) = registration(&f, &parent, "registered", 6, 2);
    let selected = load(&f, &original, &source).unwrap();
    for android in [true, false] {
        let originals = generic_session(&f, android, None);
        let session = selected
            .enrollment_session(android, originals.each_ref().map(Vec::as_slice))
            .unwrap();
        assert_eq!(session.config.fi, b"universal-provider");
        assert_eq!(session.config.actor, b"alice@example.test");
        assert_eq!(session.config.release, b"independent-provider-release");
        assert_eq!(
            session.config.policy.asset_digest,
            selected.asset.asset_digest()
        );
        assert!(
            selected
                .enrollment_session(!android, originals.each_ref().map(Vec::as_slice))
                .is_err()
        );
        for field in [
            "iss",
            "aud",
            "dataspace_id",
            "client_app",
            "roles",
            "htu",
            "root",
        ] {
            let changed = generic_session(&f, android, Some(field));
            assert!(
                selected
                    .enrollment_session(android, changed.each_ref().map(Vec::as_slice))
                    .is_err(),
                "{field}"
            );
        }
    }
}

#[test]
fn generic_release_selects_only_the_apple_root_original() {
    let f = BaseFixture::new();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let parent = iroha_fs::PrivateDirectory::open_exact(path).unwrap();
    let (source, _) = registration(&f, &parent, "roots", 6, 2);
    let original = selection(&f);
    load(&f, &original, &source).unwrap();
    // Re-sign the whole release around a changed runtime so only the platform rows differ.
    let resigned = |change: &dyn Fn(&mut Map)| {
        let mut runtime = json(&original.2, WALLET_RUNTIME_MAX, true).unwrap();
        change(object_mut(&mut runtime));
        let runtime = canonical(&runtime);
        let mut app = json(&original.0, APP_MANIFEST_MAX, true).unwrap();
        mutate(
            &mut app,
            "runtimeSha256",
            Value::String(hex::encode(BlobV1::of(&runtime).sha256)),
        );
        let app = canonical(&app);
        let envelope = sign_generic(&f, &app);
        (app, envelope, runtime)
    };
    // The retired Android root DER is refused even when well formed.
    let android_root = resigned(&|runtime| {
        object_mut(runtime.get_mut("android").unwrap()).insert(
            "attestation_root_der_base64".into(),
            Value::String(STANDARD.encode(SESSION_ROOT)),
        );
    });
    assert!(load(&f, &android_root, &source).is_err());
    let apple_missing = resigned(&|runtime| {
        object_mut(runtime.get_mut("apple").unwrap()).remove("attestation_root_der_base64");
    });
    assert!(load(&f, &apple_missing, &source).is_err());
    let apple_foreign = resigned(&|runtime| {
        object_mut(runtime.get_mut("apple").unwrap()).insert(
            "attestation_root_der_base64".into(),
            Value::String(STANDARD.encode(b"foreign root")),
        );
    });
    assert!(load(&f, &apple_foreign, &source).is_err());
}

#[test]
fn generic_provider_selection_rejects_ambiguous_or_foreign_signed_scope() {
    let f = BaseFixture::new();
    let (_, _, runtime) = selection(&f);
    let runtime = json(&runtime, WALLET_RUNTIME_MAX, true).unwrap();
    let sessions = field(object(&runtime).unwrap(), "sessions").unwrap();
    let selected = f.load().unwrap();
    let (android, _) = &selected.android_enrollment;
    let (apple, _) = &selected.apple_enrollment;
    session::universal_authorities(sessions, android, apple).unwrap();
    for (key, value) in [
        ("requestOrigin", "http://provider.example"),
        ("requestOrigin", "https://user@provider.example"),
        ("requestOrigin", "https://provider.example/path"),
        ("requestOrigin", "https://provider.example:0"),
        ("enrollmentChallengePath", "//foreign.example"),
        ("enrollmentChallengePath", "/v1/../enrollment"),
        ("androidClientApp", "foreign.app"),
        ("appleClientApp", "FOREIGN.app"),
        ("requiredRole", "unselected-role"),
    ] {
        let mut changed = sessions.clone();
        let Value::Array(rows) = &mut changed else {
            panic!("rows")
        };
        object_mut(&mut rows[0]).insert(key.into(), Value::String(value.into()));
        assert!(
            session::universal_authorities(&changed, android, apple).is_err(),
            "{key}: {value}"
        );
    }
    let mut duplicate = sessions.clone();
    let Value::Array(rows) = &mut duplicate else {
        panic!("rows")
    };
    rows.push(rows[0].clone());
    assert!(session::universal_authorities(&duplicate, android, apple).is_err());
}
