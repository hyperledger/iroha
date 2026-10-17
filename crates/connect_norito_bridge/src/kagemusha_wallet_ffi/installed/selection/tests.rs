//! Genuine metadata signature/genesis tests; fixture relation bytes grant no source graph.

use super::*;
use iroha_crypto::KeyPair;
use iroha_data_model::{
    nexus::AxtAssetIncarnationV1, parameter::system::SumeragiConsensusMode,
    sumeragi_finality::test_fixtures::NativeFinalityFixture,
};
use p256::ecdsa::{Signature as G1Signature, SigningKey, signature::Signer as _};

fn canonical(value: &Value) -> Vec<u8> {
    let mut bytes = norito::json::to_json_bounded(value, APP_MANIFEST_MAX - 1)
        .unwrap()
        .into_bytes();
    bytes.push(b'\n');
    bytes
}
fn object_mut(value: &mut Value) -> &mut Map {
    let Value::Object(map) = value else {
        panic!("fixture object")
    };
    map
}
fn native_installation_mut(value: &mut Value) -> &mut Map {
    let artifacts = object_mut(value).get_mut("artifacts").unwrap();
    let mobile = object_mut(artifacts).get_mut("kagemusha_mobile").unwrap();
    object_mut(object_mut(mobile).get_mut("native_installation").unwrap())
}
fn mobile_mut(value: &mut Value) -> &mut Map {
    let artifacts = object_mut(value).get_mut("artifacts").unwrap();
    object_mut(object_mut(artifacts).get_mut("kagemusha_mobile").unwrap())
}
fn mutate(value: &mut Value, key: &str, replacement: Value) {
    if value.as_object().is_some_and(|map| {
        map.get("schema").and_then(Value::as_str) == Some("cbsi.iroha-application-release.v1")
    }) && matches!(key, "ledger" | "consensus" | "asset")
    {
        native_installation_mut(value).insert(key.into(), replacement);
        return;
    }
    let Value::Object(map) = value else {
        panic!("fixture object")
    };
    map.insert(key.into(), replacement);
}
fn application() -> Value {
    // Signed public metadata DATA. These values never qualify a Native graph or device.
    let mut value = norito::json!({"schema":("cbsi.iroha-application-release.v1"),"source":{"commit":("77".repeat(20)),"tree":("78".repeat(20)),"cargo_lock_sha256":("79".repeat(32)),"cargo_lock_size_bytes":(1),"javascript_tree":("7a".repeat(20)),"iroha_js_tree":("7b".repeat(20)),"iroha_js_host_tree":("7c".repeat(20)),"android_source_fingerprint_sha256":("7d".repeat(32)),"apple_source_fingerprint_sha256":("7e".repeat(32))},"protocol":{"kagemusha_wallet_version":(1),"kagemusha_text_prefix":("kgm1:"),"kagemusha_wallet_types":{"scheme":("KagemushaWalletSchemeV1"),"signer_certificate":("KagemushaWalletSignerCertificateV1"),"artifact_manifest":("KagemushaWalletArtifactManifestV1"),"verifier_pack":("VerifierPackV1"),"producer_inventory":("ProducerInventoryV1")},"native_bridge_abi_version":(crate::CONNECT_NORITO_BRIDGE_ABI_VERSION),"native_prebuilt_provenance_schemas":{"android":("iroha.android-native-build-provenance.v1"),"apple":("cbsi.iroha-apple-xcframework-release.v1")}},"toolchain_closure":null,"artifacts":{"javascript_browser":null,"android_sdk":null,"apple_xcframework":null,"kagemusha_mobile":{"mode":("enabled"),"service_release_scope":("10".repeat(32)),"scheme_id":("11".repeat(32)),"artifact_manifest_digest":("12".repeat(32)),"producer_catalog_digest":("13".repeat(32)),"trust_assets":[],"native_installation":{"schema":("cbsi.kagemusha.native-installation.v1"),"ledger":null,"consensus":null,"asset":null}}}});
    native_installation_mut(&mut value).insert("fiSessionEnrollment".into(), session_selection());
    mobile_mut(&mut value).insert(
        "service_release_scope".into(),
        Value::String(hex::encode(session_release_digest())),
    );
    value
}
fn sign(key: &KeyPair, app: &[u8]) -> Vec<u8> {
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(app);
    let signature = Signature::try_new(key.private_key(), &message).unwrap();
    let (_, public) = key.public_key().to_bytes();
    canonical(
        &norito::json!({"schema":("cbsi.iroha-application-release-signature.v1"),"algorithm":("ed25519"),"domain":("cbsi.iroha-application-release.v1"),"keyId":(format!("sha256:{}",hex::encode(BlobV1::of(public).sha256))),"manifestSha256":(hex::encode(BlobV1::of(app).sha256)),"signatureBase64":(STANDARD.encode(signature.payload()))}),
    )
}
#[test]
fn only_the_independently_selected_trust_key_accepts_exact_signed_app_bytes() {
    let key = KeyPair::from_seed(vec![11; 32], Algorithm::Ed25519);
    let other = KeyPair::from_seed(vec![12; 32], Algorithm::Ed25519);
    let trust = RuntimeTrust::test(key.public_key().clone());
    let app = canonical(&application());
    let envelope = sign(&key, &app);
    signed_app(&trust, &app, &envelope).unwrap();
    assert!(
        signed_app(
            &RuntimeTrust::test(other.public_key().clone()),
            &app,
            &envelope
        )
        .is_err()
    );
    assert!(signed_app(&trust, &app, &sign(&other, &app)).is_err());
    let mut changed = app.clone();
    changed[3] ^= 1;
    assert!(signed_app(&trust, &changed, &envelope).is_err());
    let mut changed = envelope.clone();
    let last = changed.len() - 3;
    changed[last] ^= 1;
    assert!(signed_app(&trust, &app, &changed).is_err());
}
#[test]
fn even_genuinely_signed_unknown_fields_and_noncanonical_originals_refuse() {
    let key = KeyPair::from_seed(vec![13; 32], Algorithm::Ed25519);
    let trust = RuntimeTrust::test(key.public_key().clone());
    let mut app = application();
    mutate(
        &mut app,
        "offeredTrustKey",
        Value::String("untrusted".into()),
    );
    let bytes = canonical(&app);
    assert!(signed_app(&trust, &bytes, &sign(&key, &bytes)).is_err());
    let bytes = canonical(&application());
    let mut spaced = bytes.clone();
    spaced.insert(1, b' ');
    assert!(signed_app(&trust, &spaced, &sign(&key, &spaced)).is_err());
    let mut envelope = sign(&key, &bytes);
    envelope.insert(1, b' ');
    assert!(signed_app(&trust, &bytes, &envelope).is_err());
}
#[test]
fn cbsi_installation_uses_fi_session_enrollment_and_rejects_retired_pre_fi_selection() {
    let key = KeyPair::from_seed(vec![15; 32], Algorithm::Ed25519);
    let trust = RuntimeTrust::test(key.public_key().clone());
    let mut app = application();
    let bytes = canonical(&app);
    signed_app(&trust, &bytes, &sign(&key, &bytes)).unwrap();
    for retired in [
        Value::Null,
        Value::Bool(true),
        norito::json!({"schema":("cbsi.first-device-auth-runtime-selection.v1")}),
    ] {
        native_installation_mut(&mut app).insert("firstDeviceAuthentication".into(), retired);
        let bytes = canonical(&app);
        assert!(signed_app(&trust, &bytes, &sign(&key, &bytes)).is_err());
    }
}
#[test]
fn lexical_boundaries_reject_duplicates_fractions_unsafe_integers_and_depth_before_owned_decode() {
    for bytes in [
        b"{\"a\":1,\"a\":2}".as_slice(),
        b"{\"a\":0.5}",
        b"{\"a\":9007199254740992}",
        b"{\"\\u00e9\":1}",
    ] {
        assert!(json(bytes, 1024, false).is_err());
    }
    assert!(json(b"", 1024, false).is_err());
    assert!(json(&[b' '; 1025], 1024, false).is_err());
    let nested = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    assert!(json(nested.as_bytes(), 1024, false).is_err());
    assert!(json(b"{\"a\":9007199254740991}", 1024, false).is_ok());
}
#[test]
fn byte_originals_have_canonical_base64_and_nonzero_lowercase_digest_forms() {
    let map = exact(&norito::json!({"bytes":("AQI=")}), &["bytes"])
        .unwrap()
        .clone();
    assert_eq!(raw(&map, "bytes", 2).unwrap(), vec![1, 2]);
    assert!(raw(&map, "bytes", 1).is_err());
    let map = exact(&norito::json!({"bytes":("AQI")}), &["bytes"])
        .unwrap()
        .clone();
    assert!(raw(&map, "bytes", 2).is_err());
    for hash in [
        "0".repeat(64),
        "A".repeat(64),
        "g".repeat(64),
        "1".repeat(63),
    ] {
        assert!(sha(&hash).is_err());
    }
    assert_eq!(sha(&"1".repeat(64)).unwrap(), [0x11; 32]);
    assert!(exact(&norito::json!({"a":(1),"b":(2)}), &["a"]).is_err());
}
fn g1_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}
fn g1_public(key: &SigningKey) -> KagemushaDevicePublicKeyV1 {
    KagemushaDevicePublicKeyV1::from_sec1_bytes(
        key.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap()
}
fn g1_sign(key: &SigningKey, bytes: &[u8]) -> KagemushaWalletSignerOutputV1<'static> {
    let signature: G1Signature = key.sign(bytes);
    KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into())
}
// Explicit SOFTWARE DATA buffers exercise metadata selection only. They cannot decode
// as a Native verifier pack/catalog and cannot admit installation or a custody provider.
const TEST_PACK: &[u8] = b"PUBLIC_SOFTWARE_DATA_UNADMITTED_PACK";
const TEST_CATALOG: &[u8] = b"PUBLIC_SOFTWARE_DATA_UNADMITTED_CATALOG";
const TEST_ROOT: &[u8] = b"/unadmitted/metadata-only";
/// Public placeholder SPKI pins ordered as the policy requires; they name no genuine root.
fn google_roots() -> Vec<KagemushaWalletAndroidRootV1> {
    vec![
        KagemushaWalletAndroidRootV1 {
            family: KagemushaWalletAndroidRootFamilyV1::GoogleCa1,
            spki_sha256: [0x3e; 32],
            revocation_source: KagemushaWalletRevocationSourceV1::GoogleAttestationStatus,
        },
        KagemushaWalletAndroidRootV1 {
            family: KagemushaWalletAndroidRootFamilyV1::GoogleRsa,
            spki_sha256: [0xfe; 32],
            revocation_source: KagemushaWalletRevocationSourceV1::GoogleAttestationStatus,
        },
    ]
}
fn android_platform(
    root_set: Vec<KagemushaWalletAndroidRootV1>,
) -> KagemushaWalletEnrollmentPlatformV1 {
    KagemushaWalletEnrollmentPlatformV1::Android {
        root_set,
        patch_floor_yyyymm: 202610,
    }
}
fn vendor_root(adapter_id: &str) -> KagemushaWalletAndroidRootV1 {
    KagemushaWalletAndroidRootV1 {
        family: KagemushaWalletAndroidRootFamilyV1::Vendor {
            adapter_id: adapter_id.into(),
        },
        spki_sha256: [0xff; 32],
        revocation_source: KagemushaWalletRevocationSourceV1::OperatorDenylist,
    }
}
struct BaseFixture {
    key: KeyPair,
    app: Value,
    runtime: Value,
    genesis: Vec<u8>,
    scheme: KagemushaWalletSchemeV1,
}
impl BaseFixture {
    fn new() -> Self {
        Self::with_asset("7ZepsJTHCVLKsrFFNZGSRGZgvBhv")
    }
    fn with_asset(asset_id: &str) -> Self {
        Self::with_asset_and_mode(asset_id, SumeragiConsensusMode::Permissioned)
    }
    fn with_asset_and_mode(asset_id: &str, mode: SumeragiConsensusMode) -> Self {
        let native =
            NativeFinalityFixture::start_with_mode("fc56984b-2be7-431d-840e-21514d1883f0", mode);
        let genesis = native.genesis().encode_wire().unwrap();
        let epoch = authenticated_genesis(native.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap();
        let root = g1_key(7);
        let artifact = g1_key(8);
        let enrollment = g1_key(9);
        // These metadata-only protocol bytes deliberately have no proof keys. Real
        // InstalledRuntime still requires strict qualification of the complete graph.
        let mut body = KagemushaWalletArtifactManifestBodyV1 {
            version: 1,
            network_id: *native.network_id().as_bytes(),
            relation_id: [1; 32],
            eq_protocol_digest: [2; 32],
            ep_protocol_digest: [3; 32],
            native_profile_digest: [4; 32],
            verifying_key_set_digest: [5; 32],
            artifact_inventory_digest: [6; 32],
            provider_contract: kagemusha_wallet_provider_contract_v1(),
            signer_certificate: [1; 32],
        };
        body.relation_id = body.recomputed_relation_id();
        let scheme = KagemushaWalletSchemeV1 {
            version: 1,
            network_id: body.network_id,
            scheme_root_key: g1_public(&root),
            relation_id: body.relation_id,
            provider_contract: body.provider_contract,
        };
        let certificate = |role, signer: &SigningKey| {
            let body = KagemushaWalletSignerCertificateBodyV1 {
                version: 1,
                scheme_id: scheme.scheme_id(),
                role,
                key: g1_public(signer),
                serial: 1,
            };
            KagemushaWalletSignerCertificateV1::sign(
                body,
                &scheme,
                g1_sign(&root, &body.signing_message()),
            )
            .unwrap()
        };
        let artifact_certificate = certificate(KagemushaWalletSignerRoleV1::Artifact, &artifact);
        let enrollment_certificate =
            certificate(KagemushaWalletSignerRoleV1::Enrollment, &enrollment);
        body.signer_certificate = artifact_certificate.certificate_digest();
        let manifest = KagemushaWalletArtifactManifestV1::sign(
            body,
            &artifact_certificate,
            g1_sign(&artifact, &body.signing_message()),
        )
        .unwrap();
        let asset = KagemushaWalletAssetScopeV1::new(
            AssetDefinitionId::from_str(asset_id).unwrap(),
            &AxtAssetIncarnationV1::try_from_bytes(
                *iroha_crypto::Hash::new(b"native-installation-test-incarnation").as_ref(),
            )
            .unwrap(),
            2,
        )
        .unwrap();
        let platform = |apple| {
            let app = KagemushaWalletAppPolicyV1 {
                version: 1,
                scheme_id: scheme.scheme_id(),
                identity: if apple {
                    KagemushaWalletAppIdentityV1::Apple {
                        app_id: "TEAM.org.example.wallet".into(),
                    }
                } else {
                    KagemushaWalletAppIdentityV1::Android {
                        package_name: "org.example.wallet".into(),
                        minimum_package_version: 7,
                        signer_set: vec![[3; 32]],
                    }
                },
            };
            let enrollment = KagemushaWalletEnrollmentPolicyV1 {
                version: 1,
                scheme_id: scheme.scheme_id(),
                asset_digest: asset.asset_digest(),
                app_policy: app.policy_digest().unwrap(),
                platform: if apple {
                    KagemushaWalletEnrollmentPlatformV1::Apple {
                        attestation_root_sha256: BlobV1::of(SESSION_ROOT).sha256,
                    }
                } else {
                    android_platform(google_roots())
                },
                regulatory_policy: KagemushaWalletRegulatoryPolicyV1::default(),
                challenge_lifetime_ms: 120000,
                attestation_lease_lifetime_ms: 0,
            };
            norito::json!({"app_policy_hex":(hex::encode(app.policy_digest().unwrap())),"enrollment_policy_hex":(hex::encode(enrollment.policy_digest().unwrap())),"app_policy_original_base64":(STANDARD.encode(norito::encode_canonical(&app).unwrap())),"enrollment_policy_original_base64":(STANDARD.encode(norito::encode_canonical(&enrollment).unwrap()))})
        };
        let runtime = norito::json!({"schema":("cbsi.kagemusha.wallet-runtime.v1"),"version":(1),"scheme_id":(hex::encode(scheme.scheme_id())),"scheme_original_base64":(STANDARD.encode(scheme.to_canonical_bytes().unwrap())),"asset_original_base64":(STANDARD.encode(norito::encode_canonical(&asset).unwrap())),"enrollment_certificate_original_base64":(STANDARD.encode(enrollment_certificate.to_canonical_bytes().unwrap())),"artifact_signer_certificate_original_base64":(STANDARD.encode(artifact_certificate.to_canonical_bytes().unwrap())),"artifact_manifest_original_base64":(STANDARD.encode(manifest.to_canonical_bytes().unwrap())),"regulatory_policy_original_base64":(STANDARD.encode(norito::encode_canonical(&KagemushaWalletRegulatoryPolicyV1::default()).unwrap())),"challenge_lifetime_ms":(120000),"android":(platform(false)),"apple":(platform(true))});
        let mut app = application();
        mutate(
            &mut app,
            "ledger",
            norito::json!({"toriiUrl":("https://bokolo.soramitsu.io"),"networkId":(native.network_id().to_string()),"networkPrefix":(369),"chainId":(native.chain_id()),"irohaSourceCommit":("77".repeat(20)),"irohaBuildSha256":("88".repeat(32))}),
        );
        let validators:Vec<_>=epoch.committee.iter().map(|member|norito::json!({"peerId":(member.validator.public_key().to_string()),"directToriiUrl":("https://test.invalid"),"nodeFingerprint":("11".repeat(32)),"buildFingerprint":("22".repeat(32)),"configFingerprint":("33".repeat(32))})).collect();
        let genesis_key = native
            .genesis()
            .external_transactions()
            .next()
            .unwrap()
            .authority()
            .try_signatory()
            .unwrap()
            .to_string();
        mutate(
            &mut app,
            "consensus",
            norito::json!({"mode":(if epoch.mode.is_permissioned() { "iroha3-consensus::permissioned-sumeragi@v1" } else { "iroha3-consensus::npos-sumeragi@v1" }),"protocolVersion":(1),"networkId":(native.network_id().to_string()),"genesisBlockHash":(hex::encode(native.genesis().hash().as_ref())),"signedGenesisSha256":(hex::encode(BlobV1::of(&genesis).sha256)),"genesisPublicKey":(genesis_key),"finalityVerifierSha256":("99".repeat(32)),"validators":(validators),"checkpointSha256":("ab".repeat(32)),"checkpointHeight":(0),"checkpointContextId":("ac".repeat(32))}),
        );
        mutate(
            &mut app,
            "asset",
            norito::json!({"assetAlias":("sbd#cbsi"),"assetDefinitionId":(asset.asset.to_string()),"scale":(2)}),
        );
        mobile_mut(&mut app).insert(
            "scheme_id".into(),
            Value::String(hex::encode(scheme.scheme_id())),
        );
        mobile_mut(&mut app).insert(
            "artifact_manifest_digest".into(),
            Value::String(hex::encode(manifest.manifest_digest())),
        );
        Self {
            key: KeyPair::from_seed(vec![14; 32], Algorithm::Ed25519),
            app,
            runtime,
            genesis,
            scheme,
        }
    }
    fn originals(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let runtime = norito::json::to_json_bounded(&self.runtime, WALLET_RUNTIME_MAX)
            .unwrap()
            .into_bytes();
        let mut app = self.app.clone();
        let mut assets = vec![];
        for (name, bytes) in [
            (
                "kagemusha/genesis-manifest.json",
                b"unadmitted-genesis-metadata".as_slice(),
            ),
            (
                "kagemusha/network-configuration.toml",
                b"unadmitted-network-metadata".as_slice(),
            ),
            ("kagemusha/producer-inventory.norito", TEST_CATALOG),
            ("kagemusha/signed-genesis.norito", self.genesis.as_slice()),
            (
                "kagemusha/transport.json",
                b"unadmitted-transport-metadata".as_slice(),
            ),
            ("kagemusha/verifier-pack.norito", TEST_PACK),
            ("kagemusha/wallet-runtime.json", runtime.as_slice()),
        ] {
            assets.push(norito::json!({"file_name":(name),"sha256":(hex::encode(BlobV1::of(bytes).sha256)),"size_bytes":(bytes.len())}));
        }
        let original = b"unadmitted-proof-source";
        assets.push(norito::json!({"file_name":(format!("kagemusha/originals/{}",hex::encode(BlobV1::of(original).sha256))),"sha256":(hex::encode(BlobV1::of(original).sha256)),"size_bytes":(original.len())}));
        assets.sort_by(|left, right| {
            left.as_object().unwrap()["file_name"]
                .as_str()
                .unwrap()
                .cmp(right.as_object().unwrap()["file_name"].as_str().unwrap())
        });
        mobile_mut(&mut app).insert("trust_assets".into(), Value::Array(assets));
        let app = canonical(&app);
        let envelope = sign(&self.key, &app);
        (app, envelope, runtime)
    }
    /// Replace the signed runtime's Android enrollment policy platform, keeping its digest pin
    /// consistent, so a genuinely signed release can select it.
    fn set_android_platform(&mut self, platform: KagemushaWalletEnrollmentPlatformV1) {
        let scheme = self.scheme.scheme_id();
        let android = object_mut(object_mut(&mut self.runtime).get_mut("android").unwrap());
        let original = STANDARD
            .decode(
                android["enrollment_policy_original_base64"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        let mut policy =
            KagemushaWalletEnrollmentPolicyV1::decode_canonical(&original, &scheme).unwrap();
        policy.platform = platform;
        android.insert(
            "enrollment_policy_original_base64".into(),
            Value::String(STANDARD.encode(norito::encode_canonical(&policy).unwrap())),
        );
        android.insert(
            "enrollment_policy_hex".into(),
            Value::String(hex::encode(policy.policy_digest().unwrap())),
        );
    }
    fn load(&self) -> Result<Selection> {
        let (app, envelope, runtime) = self.originals();
        Selection::load(
            &RuntimeTrust::test(self.key.public_key().clone()),
            &RuntimeOriginals {
                app_manifest: &app,
                envelope: &envelope,
                wallet_runtime: &runtime,
                verifier_pack: TEST_PACK,
                producer_inventory: TEST_CATALOG,
                signed_genesis: &self.genesis,
                originals_root: TEST_ROOT,
                registration_source: b"",
            },
        )
    }
}
#[test]
fn genuine_signed_genesis_and_delegated_monetary_manifest_derive_installation_internally() {
    let fixture = BaseFixture::new();
    let selection = fixture.load().unwrap();
    assert_eq!(selection.installation.scheme_id, fixture.scheme.scheme_id());
    assert_eq!(
        *selection.genesis.initial_epoch().network_id.as_bytes(),
        fixture.scheme.network_id
    );
    assert_eq!(
        selection._originals._signed_genesis.as_ref(),
        fixture.genesis
    );
    let (app, envelope, runtime) = fixture.originals();
    assert_eq!(selection._originals._app_manifest.as_ref(), app);
    assert_eq!(selection._originals._envelope.as_ref(), envelope);
    assert_eq!(selection._originals._wallet_runtime.as_ref(), runtime);
}

#[test]
fn signed_runtime_retains_canonical_enrollment_policy_preimages() {
    let fixture = BaseFixture::new();
    let selection = fixture.load().unwrap();
    let retained = json(
        &selection._originals._wallet_runtime,
        WALLET_RUNTIME_MAX,
        false,
    )
    .unwrap();
    for name in ["android", "apple"] {
        let platform = object(field(object(&retained).unwrap(), name).unwrap()).unwrap();
        let original = raw(platform, "enrollment_policy_original_base64", 1024).unwrap();
        let digest = sha(text(platform, "enrollment_policy_hex").unwrap()).unwrap();
        let offered = object(field(object(&fixture.runtime).unwrap(), name).unwrap()).unwrap();
        assert_eq!(
            original,
            raw(offered, "enrollment_policy_original_base64", 1024).unwrap()
        );
        let policy = KagemushaWalletEnrollmentPolicyV1::decode_canonical(
            &original,
            &fixture.scheme.scheme_id(),
        )
        .unwrap();
        assert_eq!(policy.policy_digest().unwrap(), digest);
    }
}

#[test]
fn authenticated_base_refuses_fixed_adapter_duplicate_pin_substitution() {
    let fixture = BaseFixture::new();
    let selected = fixture.load().unwrap();
    assert!(Arc::ptr_eq(
        &selected.authenticated_base().unwrap(),
        &selected.base
    ));
    for change in 0..5 {
        let mut selected = fixture.load().unwrap();
        let ApplicationBinding::CbsiReleaseV1 {
            scheme_id,
            manifest_digest,
            producer_catalog_digest,
            transport,
            ..
        } = &mut selected.application
        else {
            panic!("CBSI fixture")
        };
        match change {
            0 => scheme_id[0] ^= 1,
            1 => manifest_digest[0] ^= 1,
            2 => producer_catalog_digest[0] ^= 1,
            3 => transport.sha256[0] ^= 1,
            _ => transport.bytes += 1,
        }
        assert!(
            matches!(
                selected.authenticated_base(),
                Err(Failure {
                    status: INVALID,
                    ..
                })
            ),
            "change {change}"
        );
    }
}

#[test]
fn genuine_signed_runtime_rejects_missing_or_rebound_policy_preimages() {
    for field_name in [
        "app_policy_original_base64",
        "enrollment_policy_original_base64",
    ] {
        let mut fixture = BaseFixture::new();
        let Value::Object(runtime) = &mut fixture.runtime else {
            panic!("runtime")
        };
        let Value::Object(platform) = runtime.get_mut("android").unwrap() else {
            panic!("platform")
        };
        platform.remove(field_name);
        assert!(fixture.load().is_err());

        let mut fixture = BaseFixture::new();
        let Value::Object(runtime) = &mut fixture.runtime else {
            panic!("runtime")
        };
        let replacement = object(runtime.get("apple").unwrap()).unwrap()[field_name].clone();
        mutate(runtime.get_mut("android").unwrap(), field_name, replacement);
        assert!(fixture.load().is_err());
    }
    let mut fixture = BaseFixture::new();
    mutate(
        &mut fixture.runtime,
        "challenge_lifetime_ms",
        Value::from(120001u64),
    );
    assert!(fixture.load().is_err());
}
#[test]
fn exact_whole_runtime_and_signed_genesis_preimages_cannot_be_retargeted() {
    let mut fixture = BaseFixture::new();
    fixture.genesis[0] ^= 1;
    assert!(fixture.load().is_err());
    let fixture = BaseFixture::new();
    let (app, envelope, mut runtime) = fixture.originals();
    runtime.push(b' ');
    assert!(
        Selection::load(
            &RuntimeTrust::test(fixture.key.public_key().clone()),
            &RuntimeOriginals {
                app_manifest: &app,
                envelope: &envelope,
                wallet_runtime: &runtime,
                verifier_pack: TEST_PACK,
                producer_inventory: TEST_CATALOG,
                signed_genesis: &fixture.genesis,
                originals_root: TEST_ROOT,
                registration_source: b"",
            }
        )
        .is_err()
    );
}
#[test]
fn genuinely_resigned_application_still_cannot_change_native_genesis_policy_or_asset() {
    let mut fixture = BaseFixture::new();
    let consensus = native_installation_mut(&mut fixture.app)
        .get_mut("consensus")
        .unwrap();
    mutate(
        consensus,
        "mode",
        Value::String("iroha3-consensus::npos-sumeragi@v1".into()),
    );
    assert!(fixture.load().is_err());
    let mut fixture = BaseFixture::new();
    mutate(
        native_installation_mut(&mut fixture.app)
            .get_mut("asset")
            .unwrap(),
        "scale",
        Value::from(3u64),
    );
    assert!(fixture.load().is_err());
}
#[test]
fn cbsi_consensus_keeps_its_signed_finality_verifier_field() {
    // Only the BPNG runtime dropped this pin; the CBSI release format is unchanged.
    let mut fixture = BaseFixture::new();
    object_mut(
        native_installation_mut(&mut fixture.app)
            .get_mut("consensus")
            .unwrap(),
    )
    .remove("finalityVerifierSha256");
    assert!(fixture.load().is_err());
    let mut fixture = BaseFixture::new();
    mutate(
        native_installation_mut(&mut fixture.app)
            .get_mut("consensus")
            .unwrap(),
        "finalityVerifierSha256",
        Value::String("0".repeat(64)),
    );
    assert!(fixture.load().is_err());
}
#[test]
fn closed_runtime_rejects_tool_fields_and_out_of_bounds_challenge_lifetime() {
    let mut fixture = BaseFixture::new();
    mutate(
        &mut fixture.runtime,
        "challenge_lifetime_ms",
        Value::from(0u64),
    );
    assert!(fixture.load().is_err());
    mutate(
        &mut fixture.runtime,
        "challenge_lifetime_ms",
        Value::from(600001u64),
    );
    assert!(fixture.load().is_err());
    mutate(
        &mut fixture.runtime,
        "challenge_lifetime_ms",
        Value::from(120000u64),
    );
    mutate(
        &mut fixture.runtime,
        "python_path",
        Value::String("relative/tool".into()),
    );
    assert!(fixture.load().is_err());
}

#[test]
fn genuine_signed_base_cannot_omit_financial_originals_or_register_an_owner() {
    let fixture = BaseFixture::new();
    let selected = Arc::new(fixture.load().unwrap());
    let (app, envelope, runtime) = fixture.originals();
    let result = PreparedInstallation::from_selected(
        RuntimeOriginals {
            app_manifest: &app,
            envelope: &envelope,
            wallet_runtime: &runtime,
            verifier_pack: b"",
            producer_inventory: b"",
            signed_genesis: &fixture.genesis,
            originals_root: b"",
            registration_source: b"",
        },
        selected,
        OpeningMetricsV1::start(),
    );
    assert!(matches!(
        result,
        Err(Failure {
            status: INVALID,
            ..
        })
    ));
}

#[test]
fn cbsi_financial_original_roles_remain_mandatory_and_bounded() {
    let fixture = BaseFixture::new();
    let (app, envelope, runtime) = fixture.originals();
    for offered in 0..8 {
        let input = RuntimeOriginals {
            app_manifest: &app,
            envelope: &envelope,
            wallet_runtime: &runtime,
            signed_genesis: &fixture.genesis,
            verifier_pack: if offered & 1 == 0 { b"" } else { TEST_PACK },
            producer_inventory: if offered & 2 == 0 { b"" } else { TEST_CATALOG },
            originals_root: if offered & 4 == 0 { b"" } else { TEST_ROOT },
            registration_source: b"",
        };
        if offered == 0 || offered == 7 {
            assert!(input.validate_bounds().is_ok());
        } else {
            assert_eq!(input.validate_bounds().unwrap_err().status, INVALID);
        }
        assert_eq!(
            Selection::load(
                &RuntimeTrust::test(fixture.key.public_key().clone()),
                &input
            )
            .is_ok(),
            offered == 7
        );
    }
    for missing in 0..7 {
        let mut input = RuntimeOriginals {
            app_manifest: &app,
            envelope: &envelope,
            wallet_runtime: &runtime,
            signed_genesis: &fixture.genesis,
            verifier_pack: TEST_PACK,
            producer_inventory: TEST_CATALOG,
            originals_root: TEST_ROOT,
            registration_source: b"",
        };
        match missing {
            0 => input.app_manifest = b"",
            1 => input.envelope = b"",
            2 => input.wallet_runtime = b"",
            3 => input.verifier_pack = b"",
            4 => input.producer_inventory = b"",
            5 => input.signed_genesis = b"",
            _ => input.originals_root = b"",
        }
        assert_eq!(input.validate_bounds().unwrap_err().status, INVALID);
    }
}

#[test]
fn cbsi_signed_release_requires_exact_mobile_selection_and_all_seven_inventory_roles() {
    let fixture = BaseFixture::new();
    let selected = fixture.load().unwrap();
    let ApplicationBinding::CbsiReleaseV1 {
        service_release_scope,
        producer_catalog_digest,
        ..
    } = selected.application
    else {
        panic!("CBSI authority")
    };
    assert_eq!(service_release_scope, session_release_digest());
    assert_eq!(producer_catalog_digest, [0x13; 32]);
    for field_name in [
        "service_release_scope",
        "scheme_id",
        "artifact_manifest_digest",
        "producer_catalog_digest",
        "native_installation",
    ] {
        let mut fixture = BaseFixture::new();
        mobile_mut(&mut fixture.app).remove(field_name);
        assert!(fixture.load().is_err());
    }
    for (name, changed) in [
        ("mode", Value::String("disabled".into())),
        ("scheme_id", Value::String("11".repeat(32))),
        ("artifact_manifest_digest", Value::String("12".repeat(32))),
    ] {
        let mut fixture = BaseFixture::new();
        mobile_mut(&mut fixture.app).insert(name.into(), changed);
        assert!(fixture.load().is_err());
    }
    let (app, _, runtime) = fixture.originals();
    let app = cbsi::signed_document(&app).unwrap();
    for role in cbsi::REQUIRED {
        let mut changed = app.clone();
        let Value::Array(rows) = mobile_mut(&mut changed).get_mut("trust_assets").unwrap() else {
            panic!("rows")
        };
        rows.retain(|row| row.as_object().unwrap()["file_name"].as_str().unwrap() != role);
        let original = canonical(&changed);
        assert!(
            Selection::load(
                &RuntimeTrust::test(fixture.key.public_key().clone()),
                &RuntimeOriginals {
                    app_manifest: &original,
                    envelope: &sign(&fixture.key, &original),
                    wallet_runtime: &runtime,
                    verifier_pack: TEST_PACK,
                    producer_inventory: TEST_CATALOG,
                    signed_genesis: &fixture.genesis,
                    originals_root: TEST_ROOT,
                    registration_source: b"",
                }
            )
            .is_err()
        );
    }
    for role in [
        "kagemusha/verifier-pack.norito",
        "kagemusha/producer-inventory.norito",
        "kagemusha/wallet-runtime.json",
        "kagemusha/signed-genesis.norito",
    ] {
        let mut changed = app.clone();
        let Value::Array(rows) = mobile_mut(&mut changed).get_mut("trust_assets").unwrap() else {
            panic!("rows")
        };
        let row = rows
            .iter_mut()
            .find(|row| row.as_object().unwrap()["file_name"].as_str().unwrap() == role)
            .unwrap();
        object_mut(row).insert("sha256".into(), Value::String("ff".repeat(32)));
        let original = canonical(&changed);
        assert!(
            Selection::load(
                &RuntimeTrust::test(fixture.key.public_key().clone()),
                &RuntimeOriginals {
                    app_manifest: &original,
                    envelope: &sign(&fixture.key, &original),
                    wallet_runtime: &runtime,
                    verifier_pack: TEST_PACK,
                    producer_inventory: TEST_CATALOG,
                    signed_genesis: &fixture.genesis,
                    originals_root: TEST_ROOT,
                    registration_source: b"",
                }
            )
            .is_err()
        );
    }
}

#[test]
fn cbsi_authority_rejects_bpng_signature_domain_and_runtime_grammar() {
    let fixture = BaseFixture::new();
    let (app, envelope, _) = fixture.originals();
    let mut envelope = json(&envelope, ENVELOPE_MAX, true).unwrap();
    mutate(
        &mut envelope,
        "schema",
        Value::String("bpng.taira-app-runtime-manifest-signature.v7".into()),
    );
    assert!(
        signed_app(
            &RuntimeTrust::test(fixture.key.public_key().clone()),
            &app,
            &canonical(&envelope)
        )
        .is_err()
    );
    let mut fixture = BaseFixture::new();
    mutate(
        &mut fixture.runtime,
        "schema",
        Value::String("bpng.current-wallet-core-runtime.v1".into()),
    );
    assert!(fixture.load().is_err());
    let mut fixture = BaseFixture::new();
    native_installation_mut(&mut fixture.app).insert(
        "firstDeviceAuthentication".into(),
        norito::json!({"schema":("bpng.first-device-auth-runtime-selection.v1")}),
    );
    assert!(fixture.load().is_err());
}

// These genuinely delegated credential signatures test signed scope only. Evidence facts
// are DATA fixtures, confer no platform qualification and never create a custody provider.
fn scoped_credential(
    selected: &Selection,
    kind: KagemushaWalletEvidenceKindV1,
    policy: [u8; 32],
    issuer_seed: u8,
) -> KagemushaWalletCredentialV1 {
    let root = g1_key(7);
    let issuer = g1_key(issuer_seed);
    let payment = g1_public(&g1_key(13));
    let issuer_body = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: selected.scheme.scheme_id(),
        role: KagemushaWalletSignerRoleV1::Enrollment,
        key: g1_public(&issuer),
        serial: 2,
    };
    let certificate = KagemushaWalletSignerCertificateV1::sign(
        issuer_body,
        &selected.scheme,
        g1_sign(&root, &issuer_body.signing_message()),
    )
    .unwrap();
    let challenge = KagemushaWalletEnrollmentChallengeV1 {
        version: 1,
        scheme_id: selected.scheme.scheme_id(),
        asset_digest: selected.asset.asset_digest(),
        account_digest: [11; 32],
        app_policy: policy,
        enrollment_policy: [12; 32],
        issuer_nonce: [4; 32],
    };
    let facts = if kind.is_android() {
        KAGEMUSHA_WALLET_ANDROID_REQUIRED_FACTS_V1
    } else {
        KAGEMUSHA_WALLET_APPLE_REQUIRED_FACTS_V1
    };
    let patch = if kind.is_android() { 202_609 } else { 0 };
    let evidence = KagemushaWalletEvidenceV1 {
        digest: [10; 32],
        time_ms: 1000,
        facts,
        os_patch_level: patch,
        vendor_patch_level: patch,
        boot_patch_level: patch,
    };
    let body = KagemushaWalletCredentialBodyV1 {
        version: 1,
        scheme_id: challenge.scheme_id,
        asset_digest: challenge.asset_digest,
        wallet_id: challenge.wallet_id(&payment),
        account_digest: challenge.account_digest,
        payment_key: payment,
        provider_contract: selected.scheme.provider_contract,
        evidence_kind: kind,
        enrollment_evidence: evidence,
        fresh_evidence: evidence,
        app_policy: policy,
        regulatory_policy: KagemushaWalletRegulatoryPolicyV1::default(),
        enrollment_id: challenge.enrollment_id(&payment),
        issued_at_ms: 2000,
        renewal_sequence: 0,
        lease_expires_at_ms: 0,
        issuer_certificate: certificate.certificate_digest(),
    };
    KagemushaWalletCredentialV1::sign(
        body,
        &certificate,
        g1_sign(&issuer, &body.signing_message()),
    )
    .unwrap()
}
#[test]
fn independently_signed_runtime_scope_cannot_be_retargeted_by_an_original_credential() {
    let fixture = BaseFixture::new();
    let selected = Arc::new(fixture.load().unwrap());
    let binding = BoundOriginals {
        selected: Arc::clone(&selected),
        android: true,
    };
    let credential = scoped_credential(
        &selected,
        KagemushaWalletEvidenceKindV1::AndroidKeyMintTee,
        selected.android_app_policy,
        9,
    )
    .to_canonical_bytes()
    .unwrap();
    binding
        .require([
            &credential,
            b"certificates",
            b"account",
            &selected.asset_original,
        ])
        .unwrap();
    let wrong = scoped_credential(
        &selected,
        KagemushaWalletEvidenceKindV1::AndroidKeyMintTee,
        selected.apple_app_policy,
        9,
    )
    .to_canonical_bytes()
    .unwrap();
    assert!(
        binding
            .require([
                &wrong,
                b"certificates",
                b"account",
                &selected.asset_original
            ])
            .is_err()
    );
    let apple = scoped_credential(
        &selected,
        KagemushaWalletEvidenceKindV1::AppleAppAttest,
        selected.android_app_policy,
        9,
    )
    .to_canonical_bytes()
    .unwrap();
    assert!(
        binding
            .require([
                &apple,
                b"certificates",
                b"account",
                &selected.asset_original
            ])
            .is_err()
    );
    let mut changed = selected.asset_original.clone();
    changed.push(0);
    assert!(
        binding
            .require([&credential, b"certificates", b"account", &changed])
            .is_err()
    );
}
#[test]
fn renewed_issuer_original_is_left_to_genuine_intake_and_never_replaced_by_current_runtime_certificate()
 {
    let fixture = BaseFixture::new();
    let selected = Arc::new(fixture.load().unwrap());
    let renewed = scoped_credential(
        &selected,
        KagemushaWalletEvidenceKindV1::AndroidKeyMintTee,
        selected.android_app_policy,
        11,
    );
    let retained = json(
        &selected._originals._wallet_runtime,
        WALLET_RUNTIME_MAX,
        false,
    )
    .unwrap();
    let certificate = KagemushaWalletSignerCertificateV1::decode_canonical(
        &raw(
            object(&retained).unwrap(),
            "enrollment_certificate_original_base64",
            KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
        )
        .unwrap(),
        &selected.scheme,
    )
    .unwrap();
    assert_ne!(
        renewed.body.issuer_certificate,
        certificate.certificate_digest()
    );
    let original = renewed.to_canonical_bytes().unwrap();
    let binding = BoundOriginals {
        selected: Arc::clone(&selected),
        android: true,
    };
    binding
        .require([
            &original,
            b"certificates",
            b"account",
            &selected.asset_original,
        ])
        .unwrap();
    // This is scope admission only. Native original intake still requires its exact
    // actual issuer certificate, retained credential and positive enrolled key.
}

mod bpng_tests;

// Public DATA signatures only; these fixture roots never qualify a physical device.
const SESSION_ROOT: &[u8] = b"public component root DER placeholder";
const SESSION_RELEASE: &[u8] = b"public component service release original";
fn session_release_digest() -> [u8; 32] {
    kagemusha_enrollment_permit_scope_digest_v1(
        KagemushaEnrollmentPermitScopeRoleV1::Release,
        SESSION_RELEASE,
    )
    .unwrap()
}
fn session_key(index: u8) -> KeyPair {
    KeyPair::from_seed(vec![150 + index; 32], Algorithm::Ed25519)
}
fn session_selection() -> Value {
    let sessions: Vec<Value> = ["anz", "bred", "bsp", "ezipei", "m-selen", "pob"].iter().enumerate().map(|(index,fi)| {
        let namespace = format!("{fi}.cbsi");
        let key = session_key(index as u8);
        let (_,public) = key.public_key().to_bytes();
        norito::json!({"schema":("iroha.fi-session-authentication-original.v1"), "algorithm":("EdDSA"),
            "verificationKeyEd25519Base64":(STANDARD.encode(public)), "issuer":(format!("cbsi-fi-core-{fi}")),
            "audience":(namespace.clone()), "fiOriginalBase64":(STANDARD.encode(namespace.as_bytes())), "dataspaceId":(namespace),
            "androidClientApp":("com.soramitsu.bokolocash"), "appleClientApp":("jp.co.soramitsu.bokolo"),
            "requestOrigin":(format!("https://bokolo-{fi}.soramitsu.io")), "externalPathPrefix":("/api"),
            "enrollmentChallengePath":("/v1/retail/kagemusha/enrollment/challenge"), "releaseOriginalBase64":(STANDARD.encode(SESSION_RELEASE))})
    }).collect();
    norito::json!({"schema":("cbsi.fi-session-enrollment-selection.v1"), "sessions":(sessions),
        "enrollmentCollection":{"appleAttestationRootDERBase64":(STANDARD.encode(SESSION_ROOT))}})
}
/// The session root original: the selected Apple App Attestation root, or none on Android.
fn session_root(android: bool) -> Vec<u8> {
    if android {
        Vec::new()
    } else {
        SESSION_ROOT.to_vec()
    }
}
fn session_originals(android: bool) -> [Vec<u8>; 3] {
    session_originals_for(android, 31, "00000000-0000-4000-8000-000000000001", 1500)
}
fn session_originals_for(
    android: bool,
    proof_seed: u8,
    device: &str,
    proof_iat: u64,
) -> [Vec<u8>; 3] {
    let proof_key = g1_key(proof_seed);
    let point = proof_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
    let jwk = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
    let encode =
        |value: Value| URL_SAFE_NO_PAD.encode(norito::json::to_json(&value).unwrap().as_bytes());
    let header = encode(norito::json!({"alg":("EdDSA"),"typ":("JWT")}));
    let claims = encode(
        norito::json!({"sub":("alice@example.test"), "dataspace_id":("anz.cbsi"), "roles":["RETAIL_USER"],
        "iat":(1000), "nbf":(1000), "exp":(2000), "iss":("cbsi-fi-core-anz"), "aud":("anz.cbsi"),
        "device_id":(device), "client_app":(if android { "com.soramitsu.bokolocash" } else { "jp.co.soramitsu.bokolo" }),
        "cnf":{"jkt":(URL_SAFE_NO_PAD.encode(BlobV1::of(jwk.as_bytes()).sha256))}}),
    );
    let message = format!("{header}.{claims}");
    let signature = Signature::try_new(session_key(0).private_key(), message.as_bytes()).unwrap();
    let token = format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.payload())).into_bytes();
    let header = encode(
        norito::json!({"typ":("dpop+jwt"), "alg":("ES256"), "jwk":{"kty":("EC"),"crv":("P-256"),"x":(x),"y":(y)}}),
    );
    let claims = encode(
        norito::json!({"htm":("POST"),"htu":("https://bokolo-anz.soramitsu.io/api/v1/retail/kagemusha/enrollment/challenge"),
        "iat":(proof_iat),"jti":("00000000-0000-4000-8000-000000000002"),"ath":(URL_SAFE_NO_PAD.encode(BlobV1::of(&token).sha256))}),
    );
    let message = format!("{header}.{claims}");
    let signature: G1Signature = proof_key.sign(message.as_bytes());
    let proof = format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())).into_bytes();
    [token, proof, session_root(android)]
}
#[test]
fn renewed_session_requires_the_same_signed_device_and_dpop_key() {
    let selection = BaseFixture::new().load().unwrap();
    for android in [true, false] {
        let originals = session_originals(android);
        let current = selection
            .enrollment_session(android, originals.each_ref().map(Vec::as_slice))
            .unwrap();
        let renewed =
            session_originals_for(android, 31, "00000000-0000-4000-8000-000000000001", 1600);
        let renewed = selection
            .enrollment_session(android, renewed.each_ref().map(Vec::as_slice))
            .unwrap();
        current.require_renewal_identity(&renewed).unwrap();
        assert_eq!(renewed.config.session_expires_at_ms, 1_661_000);
        for (seed, device) in [
            (32, "00000000-0000-4000-8000-000000000001"),
            (31, "00000000-0000-4000-8000-000000000003"),
        ] {
            let foreign = session_originals_for(android, seed, device, 1600);
            let foreign = selection
                .enrollment_session(android, foreign.each_ref().map(Vec::as_slice))
                .unwrap();
            // These are individually valid signed sessions, not malformed DATA.
            assert!(current.require_renewal_identity(&foreign).is_err());
        }
    }
}
#[test]
fn enrolled_session_requires_signed_fi_token_bound_proof_and_exact_root() {
    let selection = BaseFixture::new().load().unwrap();
    for android in [true, false] {
        let originals = session_originals(android);
        let session = selection
            .enrollment_session(android, originals.each_ref().map(Vec::as_slice))
            .unwrap();
        assert!(session.matches(originals.each_ref().map(Vec::as_slice)));
        assert_eq!(session.config.actor, b"alice@example.test");
        assert_eq!(session.config.fi, b"anz.cbsi");
        assert_eq!(session.config.release, SESSION_RELEASE);
        assert_eq!(session.config.session_valid_from_ms, 1_440_000);
        assert_eq!(session.config.session_expires_at_ms, 1_561_000);
        assert_eq!(
            session.config.attestation_root_der,
            (!android).then(|| SESSION_ROOT.to_vec())
        );
        assert!(
            selection
                .enrollment_session(!android, originals.each_ref().map(Vec::as_slice))
                .is_err()
        );
        for field in 0..3 {
            let mut changed = originals.clone();
            match changed[field].first_mut() {
                Some(byte) => *byte ^= 1,
                // Android selects no root original: any offered root bytes are refused.
                None => changed[field] = SESSION_ROOT.to_vec(),
            }
            assert!(
                selection
                    .enrollment_session(android, changed.each_ref().map(Vec::as_slice))
                    .is_err()
            );
        }
    }
    // Apple requires the exact selected root original; it is never optional.
    let mut apple = session_originals(false);
    apple[2].clear();
    assert!(
        selection
            .enrollment_session(false, apple.each_ref().map(Vec::as_slice))
            .is_err()
    );
}
#[test]
fn fi_selection_rejects_missing_duplicate_reordered_and_release_alias_rows() {
    for field in 0..4 {
        let mut fixture = BaseFixture::new();
        let selection = native_installation_mut(&mut fixture.app)
            .get_mut("fiSessionEnrollment")
            .unwrap();
        let Value::Array(rows) = object_mut(selection).get_mut("sessions").unwrap() else {
            panic!("rows")
        };
        match field {
            0 => {
                rows.pop();
            }
            1 => {
                rows[1] = rows[0].clone();
            }
            2 => rows.swap(0, 1),
            _ => {
                object_mut(&mut rows[0]).insert(
                    "releaseOriginalBase64".into(),
                    Value::String(STANDARD.encode(session_release_digest())),
                );
            }
        }
        assert!(fixture.load().is_err());
    }
}

fn fi_collection_mut(fixture: &mut BaseFixture) -> &mut Map {
    let selection = native_installation_mut(&mut fixture.app)
        .get_mut("fiSessionEnrollment")
        .unwrap();
    object_mut(
        object_mut(selection)
            .get_mut("enrollmentCollection")
            .unwrap(),
    )
}
#[test]
fn fi_collection_selects_only_the_policy_bound_apple_root() {
    BaseFixture::new().load().unwrap();
    for root in [
        Value::String(STANDARD.encode(b"foreign root")),
        Value::String(String::new()),
        Value::Null,
    ] {
        let mut fixture = BaseFixture::new();
        fi_collection_mut(&mut fixture).insert("appleAttestationRootDERBase64".into(), root);
        assert!(fixture.load().is_err());
    }
    let mut fixture = BaseFixture::new();
    fi_collection_mut(&mut fixture).remove("appleAttestationRootDERBase64");
    assert!(fixture.load().is_err());
    // The retired Android root DER and Play Integrity project are refused, not ignored, even
    // with otherwise genuine values: Android chains carry their own SPKI-pinned root.
    for (name, value) in [
        (
            "androidAttestationRootDERBase64",
            Value::String(STANDARD.encode(SESSION_ROOT)),
        ),
        (
            "androidPlayIntegrityCloudProjectNumber",
            Value::String("123456789".into()),
        ),
    ] {
        let mut fixture = BaseFixture::new();
        fi_collection_mut(&mut fixture).insert(name.into(), value);
        assert!(fixture.load().is_err(), "{name}");
    }
}

#[test]
fn android_policy_naming_an_unqualified_or_unknown_vendor_adapter_fails_configuration() {
    // The `huawei` profile ships unqualified until a genuine chain qualifies it; an unknown
    // adapter is never implemented. Either fails installation before any session or challenge.
    for adapter in ["huawei", "unknown-vendor"] {
        let mut roots = google_roots();
        roots.push(vendor_root(adapter));
        let mut fixture = BaseFixture::new();
        fixture.set_android_platform(android_platform(roots));
        assert!(matches!(
            fixture.load(),
            Err(Failure {
                status: INVALID,
                ..
            })
        ));
    }
    // The same policy edit with Google roots only is still admitted.
    let mut fixture = BaseFixture::new();
    fixture.set_android_platform(android_platform(vec![google_roots().remove(1)]));
    fixture.load().unwrap();
}

mod universal_tests;
