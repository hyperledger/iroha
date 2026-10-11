//! Current policy-to-private-worker DATA vectors and substitution regressions.
use super::*;

const ROOT: &[u8] = b"Unadmitted configuration vector root DATA";

pub(super) fn selected(apple: bool) -> RequestV1 {
    let mut request = fixture(apple).request;
    if let KagemushaWalletEnrollmentPlatformV1::Apple {
        attestation_root_sha256,
    } = &mut request.body.policy.platform
    {
        *attestation_root_sha256 = Sha256::digest(ROOT).into();
    }
    request.body.challenge.enrollment_policy = request.body.policy.policy_digest().unwrap();
    request.body.marker = KagemushaWalletMarkerV1::enrollment(
        &request.body.challenge,
        request.body.marker.payment_key,
    )
    .unwrap();
    let key = KeyPair::from_seed(vec![43; 32], Algorithm::Ed25519);
    request.account_signature = Signature::try_new(
        key.private_key(),
        &request.body.account_challenge().unwrap(),
    )
    .unwrap()
    .payload()
    .try_into()
    .unwrap();
    request
}

fn runtime() -> VerifierRuntimeSelectionV1<'static> {
    VerifierRuntimeSelectionV1 {
        openssl_path: "/opt/iroha/unadmitted-data/openssl",
        openssl_sha256: [21; 32],
        store_directory: "/var/lib/iroha/unadmitted-data/enrollment",
    }
}

fn apple_root(request: &RequestV1) -> Option<&'static [u8]> {
    matches!(
        request.body.app.identity,
        KagemushaWalletAppIdentityV1::Apple { .. }
    )
    .then_some(ROOT)
}

pub(super) fn configuration(request: &RequestV1) -> VerifierConfigurationV1 {
    VerifierConfigurationV1::from_selected(
        &request.body.app,
        &request.body.policy,
        apple_root(request),
        runtime(),
    )
    .unwrap()
}

fn vectors() -> Value {
    Value::Array([false, true].into_iter().map(|apple| {
        let request = selected(apple);
        let config = configuration(&request);
        let preparation = config.preparation(&dispatch(&request), request.body.challenge, 1_000).unwrap();
        let worker = config.request(request.clone(), &preparation, 601_000).unwrap();
        norito::json!({
            "platform": (if apple { "apple" } else { "android" }),
            "configuration_base64": (STANDARD.encode(config.original())),
            "configuration_sha256": (hex::encode(config.digest())),
            "app_frame_base64": (STANDARD.encode(request.body.app.encode_canonical().unwrap())),
            "enrollment_frame_base64": (STANDARD.encode(request.body.policy.encode_canonical().unwrap())),
            "app_transcript_base64": (STANDARD.encode(request.body.app.transcript().unwrap())),
            "enrollment_transcript_base64": (STANDARD.encode(request.body.policy.transcript().unwrap())),
            "request_base64": (STANDARD.encode(worker.original())),
            "authority": "unadmitted DATA only",
        })
    }).collect())
}

#[test]
fn selected_configuration_binds_exact_originals_policy_and_request() {
    for apple in [false, true] {
        let request = selected(apple);
        let config = configuration(&request);
        assert_eq!(
            config.digest(),
            <[u8; 32]>::from(Sha256::digest(config.original()))
        );
        let value: Value = json::from_slice(config.original()).unwrap();
        assert_eq!(
            value["app_policy_hex"].as_str().unwrap(),
            hex::encode(request.body.app.policy_digest().unwrap())
        );
        assert_eq!(
            value["enrollment_policy_hex"].as_str().unwrap(),
            hex::encode(request.body.policy.policy_digest().unwrap())
        );
        let preparation = config
            .preparation(&dispatch(&request), request.body.challenge, 1_000)
            .unwrap();
        let worker = config
            .request(request.clone(), &preparation, 601_000)
            .unwrap();
        assert_eq!(worker.configuration, config.digest());
        assert!(
            config
                .request(request.clone(), &preparation, 601_001)
                .is_err()
        );
        let foreign = selected(!apple);
        assert!(config.request(foreign, &preparation, 601_000).is_err());
        let mut changed = request.clone();
        changed.body.policy.challenge_lifetime_ms += 1;
        assert!(config.request(changed, &preparation, 601_000).is_err());
        assert_eq!(config.original(), configuration(&request).original());
    }
}

#[test]
fn configuration_refuses_substituted_roots_and_runtime() {
    let android = selected(false);
    let apple = selected(true);
    let make = |request: &RequestV1, root: Option<&[u8]>, runtime| {
        VerifierConfigurationV1::from_selected(
            &request.body.app,
            &request.body.policy,
            root,
            runtime,
        )
    };
    // Android selects no root original: its chain carries its root, matched by SPKI.
    assert!(make(&android, None, runtime()).is_ok());
    for root in [ROOT, b"".as_slice()] {
        assert_eq!(
            make(&android, Some(root), runtime()).err(),
            Some(Error("Android root original"))
        );
    }
    assert!(make(&apple, None, runtime()).is_err());
    for root in [b"".as_slice(), b"substituted root", &vec![1; 16 * 1024 + 1]] {
        assert!(make(&apple, Some(root), runtime()).is_err());
    }
    for path in [
        "",
        "openssl",
        "/",
        "/tmp/../openssl",
        "/tmp/./openssl",
        "/tmp//openssl",
        "/tmp/openssl/",
        "/tmp/openssl\0",
    ] {
        let mut bad = runtime();
        bad.openssl_path = path;
        assert!(make(&apple, Some(ROOT), bad).is_err());
        let mut bad = runtime();
        bad.store_directory = path;
        assert!(make(&apple, Some(ROOT), bad).is_err());
    }
    let mut bad = runtime();
    bad.openssl_sha256 = [0; 32];
    assert!(make(&apple, Some(ROOT), bad).is_err());
    let oversized = format!("/{}", "x".repeat(128 * 1024));
    let mut bad = runtime();
    bad.openssl_path = &oversized;
    assert!(make(&apple, Some(ROOT), bad).is_err());
    let mut bad = apple.clone();
    bad.body.policy.app_policy[0] ^= 1;
    assert!(make(&bad, Some(ROOT), runtime()).is_err());
}

#[test]
fn android_configuration_projects_signer_set_root_set_and_minimum_version_only() {
    let request = selected(false);
    let config = configuration(&request);
    let value: Value = json::from_slice(config.original()).unwrap();
    assert_eq!(value["platform"].as_str(), Some("android"));
    let policy = value["policy"].as_object().unwrap();
    let mut keys: Vec<_> = policy.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "app_signer_sha256",
            "asset_digest_hex",
            "attestation_lease_lifetime_ms",
            "challenge_lifetime_ms",
            "minimum_package_version",
            "package_name",
            "patch_floor_yyyymm",
            "regulatory_policy",
            "roots",
            "scheme_id_hex",
        ]
    );
    assert_eq!(policy["minimum_package_version"].as_u64(), Some(7));
    assert_eq!(
        policy["app_signer_sha256"],
        Value::Array(vec![Value::from(hex::encode([3; 32]))])
    );
    let roots = policy["roots"].as_array().unwrap();
    assert_eq!(roots.len(), 1);
    let root = roots[0].as_object().unwrap();
    assert_eq!(root.len(), 3, "Google roots carry no adapter identifier");
    assert_eq!(root["family"].as_str(), Some("google_ca1"));
    assert_eq!(
        root["spki_sha256"].as_str(),
        Some(hex::encode([4; 32]).as_str())
    );
    assert_eq!(
        root["revocation_source"].as_str(),
        Some("google_attestation_status")
    );
    let text = String::from_utf8(config.original().to_vec()).unwrap();
    for retired in [
        "google_policy",
        "integrity",
        "security_levels",
        "maximum_evidence_age_ms",
        "require_play_recognized",
        "require_licensed",
        "minimum_device_integrity",
        "root_base64",
        "app_certificate_sha256",
        "\"package_version\"",
    ] {
        assert!(!text.contains(retired), "{retired}");
    }
}

#[test]
fn vendor_adapters_must_be_implemented_and_qualified_before_configuration() {
    assert_eq!(ANDROID_VENDOR_ADAPTER_PROFILES_V1, &[("huawei", false)]);
    for (adapter, expected) in [
        ("huawei", Error("unqualified Android adapter profile")),
        ("honor", Error("unknown Android adapter profile")),
        ("google", Error("unknown Android adapter profile")),
    ] {
        let mut request = selected(false);
        let KagemushaWalletEnrollmentPlatformV1::Android { root_set, .. } =
            &mut request.body.policy.platform
        else {
            unreachable!()
        };
        root_set.push(KagemushaWalletAndroidRootV1 {
            family: KagemushaWalletAndroidRootFamilyV1::Vendor {
                adapter_id: adapter.into(),
            },
            spki_sha256: [9; 32],
            revocation_source: KagemushaWalletRevocationSourceV1::OperatorDenylist,
        });
        request
            .body
            .policy
            .validate_for_app(&request.body.app)
            .unwrap();
        assert_eq!(
            require_qualified_android_adapters_v1(&request.body.policy.platform),
            Err(expected)
        );
        assert_eq!(
            VerifierConfigurationV1::from_selected(
                &request.body.app,
                &request.body.policy,
                None,
                runtime()
            )
            .err(),
            Some(expected)
        );
    }
    for apple in [false, true] {
        require_qualified_android_adapters_v1(&selected(apple).body.policy.platform).unwrap();
    }
}

#[test]
fn private_configuration_shared_data_vectors_match_native_projection() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/kagemusha/wallet_enrollment_worker_configuration_v1.json");
    let retained: Value = json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(retained, vectors());
}

#[test]
#[ignore = "explicit maintenance capture of unadmitted private worker DATA"]
fn regenerate_private_configuration_shared_data_vectors() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/kagemusha/wallet_enrollment_worker_configuration_v1.json");
    std::fs::write(path, json::to_vec(&vectors()).unwrap()).unwrap();
}
