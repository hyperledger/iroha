//! Real signature and private output tests; component fixtures are not physical evidence.
use super::*;
use p256::{ecdsa::signature::Verifier as _, pkcs8::EncodePrivateKey as _};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

fn fixture() -> (Scope, Request, PrivateKey, SigningKey, Vec<u8>) {
    let ed = PrivateKey::from_bytes(Algorithm::Ed25519, &[41; 32]).unwrap();
    let public = PublicKey::from_private_key(&ed).unwrap();
    let (_, bytes) = public.to_bytes();
    let public: [u8; 32] = bytes.try_into().unwrap();
    let dpop = SigningKey::from_bytes((&[42; 32]).into()).unwrap();
    let scheme_id = [43; 32];
    let android = KagemushaWalletAppPolicyV1 {
        version: 1,
        scheme_id,
        identity: KagemushaWalletAppIdentityV1::Android {
            package_name: "example.test.wallet".into(),
            minimum_package_version: 1,
            signer_set: vec![[45; 32]],
        },
    };
    let apple = KagemushaWalletAppPolicyV1 {
        version: 1,
        scheme_id,
        identity: KagemushaWalletAppIdentityV1::Apple {
            app_id: "TESTONLY.example.wallet".into(),
        },
    };
    let root = b"test-only root DATA; not an attestation certificate";
    let templates = [
        (
            &android,
            KagemushaWalletEnrollmentPlatformV1::Android {
                root_set: vec![KagemushaWalletAndroidRootV1 {
                    family: KagemushaWalletAndroidRootFamilyV1::GoogleCa1,
                    spki_sha256: [46; 32],
                    revocation_source: KagemushaWalletRevocationSourceV1::GoogleAttestationStatus,
                }],
                patch_floor_yyyymm: 202610,
            },
        ),
        (
            &apple,
            KagemushaWalletEnrollmentPlatformV1::Apple {
                attestation_root_sha256: BlobV1::of(root).sha256,
            },
        ),
    ];
    let templates = templates.map(|(app, platform)| {
        KagemushaWalletEnrollmentPolicyTemplateV1 {
            version: 1,
            scheme_id,
            app_policy: app.policy_digest().unwrap(),
            platform,
            regulatory_policy: KagemushaWalletRegulatoryPolicyV1::default(),
            challenge_lifetime_ms: 60_000,
            attestation_lease_lifetime_ms: 0,
        }
        .encode_canonical()
        .unwrap()
    });
    let runtime=canonical(&norito::json!({"schema":"iroha.kagemusha.wallet-runtime.v1","version":1,"scheme_id":(hex::encode(scheme_id)),
        "scheme_original_base64":"dGVzdA==","enrollment_certificate_original_base64":"dGVzdA==","artifact_signer_certificate_original_base64":"dGVzdA==","artifact_manifest_original_base64":"dGVzdA==",
        "android":{"app_policy_original_base64":(STANDARD.encode(android.encode_canonical().unwrap())),"enrollment_template_original_base64":(STANDARD.encode(&templates[0]))},
        "apple":{"app_policy_original_base64":(STANDARD.encode(apple.encode_canonical().unwrap())),"enrollment_template_original_base64":(STANDARD.encode(&templates[1])),"attestation_root_der_base64":(STANDARD.encode(root))},
        "sessions":[{"issuer":"test-issuer","audience":"test.dataspace","requestOrigin":"https://localhost:9443","verificationKeyEd25519Base64":(STANDARD.encode(public)),
            "releaseOriginalBase64":(STANDARD.encode(b"test-only-release")),"androidClientApp":"example.test.wallet","appleClientApp":"TESTONLY.example.wallet","enrollmentChallengePath":"/v1/enrollment/challenge",
            "roles":["RETAIL_USER","ADMIN"],"requiredRole":"RETAIL_USER"}]}),1<<20).unwrap();
    let selected = scope(&runtime, "test-issuer", "test.dataspace", "android").unwrap();
    let request = Request {
        schema: "iroha.kagemusha.wallet-session-issuance.v1".into(),
        runtime: OriginalInput {
            path: "/test-only/runtime".into(),
            sha256: hex::encode(BlobV1::of(&runtime).sha256),
        },
        issuer: "test-issuer".into(),
        audience: "test.dataspace".into(),
        platform: "android".into(),
        subject: "test-user".into(),
        registered_device_id: "194640b8-2014-4dde-88bc-77321d042b5a".into(),
        roles: vec!["RETAIL_USER".into()],
        token_lifetime_seconds: 300,
        issuer_custody_directory: "/test-only/issuer".into(),
        device_custody_directory: "/test-only/device".into(),
        dpop_public_key_hex: hex::encode(dpop.verifying_key().to_encoded_point(false).as_bytes()),
        output_parent: "/test-only/output".into(),
        output_name: "session".into(),
    };
    (selected, request, ed, dpop, runtime)
}
fn parts(bytes: &[u8]) -> (Value, Value, Vec<u8>, String) {
    let text = std::str::from_utf8(bytes).unwrap();
    let parts: Vec<_> = text.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header = json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims = json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    (
        header,
        claims,
        URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        format!("{}.{}", parts[0], parts[1]),
    )
}
#[test]
fn real_jwt_and_dpop_signatures_bind_exact_token_device_origin_and_time() {
    let (selected, request, ed, dpop, _) = fixture();
    let jti = "85757bda-b8e6-46f7-9d3c-dcfd37719523";
    let (token, proof) = issue(&selected, &request, &ed, &dpop, 1_900_000_000, jti).unwrap();
    let (header, claims, sig, message) = parts(&token);
    exact(&header, &["alg", "typ"]).unwrap();
    assert_eq!(text(&header, "alg").unwrap(), "EdDSA");
    EdSignature::from_bytes(&sig)
        .verify(
            &PublicKey::from_private_key(&ed).unwrap(),
            message.as_bytes(),
        )
        .unwrap();
    let mut altered = claims.clone();
    altered.as_object_mut().unwrap().insert(
        "device_id".into(),
        Value::from("93beadfd-40b2-40a5-a3c2-bfab9c80da6e"),
    );
    let altered = compact_input(&header, &altered, 16_384).unwrap();
    assert!(
        EdSignature::from_bytes(&sig)
            .verify(
                &PublicKey::from_private_key(&ed).unwrap(),
                altered.as_bytes()
            )
            .is_err()
    );
    assert_eq!(text(&claims, "client_app").unwrap(), "example.test.wallet");
    assert_eq!(
        text(&claims, "device_id").unwrap(),
        request.registered_device_id
    );
    assert_eq!(claims.get("nbf").unwrap().as_u64(), Some(1_900_000_000));
    assert_eq!(claims.get("exp").unwrap().as_u64(), Some(1_900_000_300));
    let (header, payload, sig, message) = parts(&proof);
    exact(&header, &["typ", "alg", "jwk"]).unwrap();
    exact(&payload, &["htm", "htu", "iat", "jti", "ath"]).unwrap();
    assert_eq!(text(&header, "typ").unwrap(), "dpop+jwt");
    let sig = Signature::from_slice(&sig).unwrap();
    dpop.verifying_key()
        .verify(message.as_bytes(), &sig)
        .unwrap();
    assert!(
        dpop.verifying_key()
            .verify(b"different compact bytes", &sig)
            .is_err()
    );
    assert_eq!(
        text(&payload, "htu").unwrap(),
        "https://localhost:9443/v1/enrollment/challenge"
    );
    assert_eq!(
        text(&payload, "ath").unwrap(),
        URL_SAFE_NO_PAD.encode(BlobV1::of(&token).sha256)
    );
    for (name, changed) in [
        ("ath", URL_SAFE_NO_PAD.encode([0u8; 32])),
        ("htu", "https://wrong.test/v1/enrollment/challenge".into()),
    ] {
        let mut altered = payload.clone();
        altered
            .as_object_mut()
            .unwrap()
            .insert(name.into(), Value::from(changed));
        let altered = compact_input(&header, &altered, 4096).unwrap();
        assert!(
            dpop.verifying_key()
                .verify(altered.as_bytes(), &sig)
                .is_err()
        );
    }
    assert_eq!(text(&payload, "jti").unwrap(), jti);
    let jwk = header.get("jwk").unwrap();
    let thumbprint = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        text(jwk, "x").unwrap(),
        text(jwk, "y").unwrap()
    );
    assert_eq!(
        text(claims.get("cnf").unwrap(), "jkt").unwrap(),
        URL_SAFE_NO_PAD.encode(BlobV1::of(thumbprint.as_bytes()).sha256)
    );
    let (token2, proof2) = issue(
        &selected,
        &request,
        &ed,
        &dpop,
        1_900_000_001,
        "93beadfd-40b2-40a5-a3c2-bfab9c80da6e",
    )
    .unwrap();
    assert_ne!(*token, *token2);
    assert_ne!(*proof, *proof2);
    assert_eq!(parts(&token2).1.get("cnf"), claims.get("cnf"));
}
#[test]
fn issuance_rejects_changed_keys_roles_device_time_and_platform_root() {
    let (selected, mut request, ed, dpop, runtime) = fixture();
    let jti = "85757bda-b8e6-46f7-9d3c-dcfd37719523";
    let wrong = PrivateKey::from_bytes(Algorithm::Ed25519, &[48; 32]).unwrap();
    assert!(issue(&selected, &request, &wrong, &dpop, 1_900_000_000, jti).is_err());
    let wrong = SigningKey::from_bytes((&[49; 32]).into()).unwrap();
    assert!(issue(&selected, &request, &ed, &wrong, 1_900_000_000, jti).is_err());
    request.roles = vec!["ADMIN".into()];
    assert!(issue(&selected, &request, &ed, &dpop, 1_900_000_000, jti).is_err());
    request.roles = vec!["RETAIL_USER".into(), "UNRELEASED".into()];
    assert!(issue(&selected, &request, &ed, &dpop, 1_900_000_000, jti).is_err());
    request.roles = vec!["RETAIL_USER".into()];
    request.registered_device_id = request.registered_device_id.to_uppercase();
    assert!(issue(&selected, &request, &ed, &dpop, 1_900_000_000, jti).is_err());
    assert!(scope(&runtime, "wrong", "test.dataspace", "android").is_err());
    assert!(scope(&runtime, "test-issuer", "test.dataspace", "other").is_err());
    assert!(selected.root.is_empty());
    let apple = scope(&runtime, "test-issuer", "test.dataspace", "apple").unwrap();
    assert!(!apple.root.is_empty());
    let changed = String::from_utf8(runtime.clone())
        .unwrap()
        .replace("TESTONLY.example.wallet", "TESTONLY.wrong.wallet");
    assert!(scope(changed.as_bytes(), "test-issuer", "test.dataspace", "apple").is_err());
    assert!(!uuid("UPPERCASE-device-id"));
    assert!(uuid(&random_uuid().unwrap()));
    assert_ne!(random_uuid().unwrap(), random_uuid().unwrap());
}
fn request_json(request: &Request) -> Vec<u8> {
    canonical(&norito::json!({"schema":(request.schema),"runtime":{"path":(request.runtime.path),"sha256":(request.runtime.sha256)},
        "issuer":(request.issuer),"audience":(request.audience),"platform":(request.platform),"subject":(request.subject),"registered_device_id":(request.registered_device_id),
        "roles":(request.roles),"token_lifetime_seconds":(request.token_lifetime_seconds),"issuer_custody_directory":(request.issuer_custody_directory),"device_custody_directory":(request.device_custody_directory),"dpop_public_key_hex":(request.dpop_public_key_hex),
        "output_parent":(request.output_parent),"output_name":(request.output_name)}),REQUEST_MAX).unwrap()
}
#[test]
fn full_private_session_command_publishes_complete_nonreplaceable_bundle() {
    let (_, mut request, _, dpop, runtime) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let root =
        PrivateDirectory::open_or_create(temp.path().canonicalize().unwrap().join("custody"))
            .unwrap();
    let issuer = root.create_child("issuer").unwrap();
    let device = root.create_child("device").unwrap();
    publish(&issuer, "session-issuer.ed25519.seed", &[41; 32]).unwrap();
    let encoded = p256::SecretKey::from_bytes(&dpop.to_bytes())
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    publish(&device, "session-device-dpop.pkcs8.der", encoded.as_bytes()).unwrap();
    #[cfg(unix)]
    for (directory, name) in [
        (&issuer, "session-issuer.ed25519.seed"),
        (&device, "session-device-dpop.pkcs8.der"),
    ] {
        std::fs::set_permissions(
            directory.path().join(name),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    publish(&root, "runtime.json", &runtime).unwrap();
    request.runtime.path = root.path().join("runtime.json").to_str().unwrap().into();
    request.issuer_custody_directory = issuer.path().to_str().unwrap().into();
    request.device_custody_directory = device.path().to_str().unwrap().into();
    request.output_parent = root.path().to_str().unwrap().into();
    publish(&root, "request.json", &request_json(&request)).unwrap();
    run(root.path().join("request.json").to_str().unwrap()).unwrap();
    let session = root.path().join("session");
    #[cfg(unix)]
    for name in [
        "access-token.jwt",
        "dpop-proof.jwt",
        "attestation-root.der",
        "session-complete.json",
    ] {
        assert_eq!(
            std::fs::metadata(session.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
    }
    assert!(
        std::fs::read(session.join("attestation-root.der"))
            .unwrap()
            .is_empty()
    );
    let before = std::fs::read(session.join("access-token.jwt")).unwrap();
    assert!(run(root.path().join("request.json").to_str().unwrap()).is_err());
    assert_eq!(
        std::fs::read(session.join("access-token.jwt")).unwrap(),
        before
    );
    let complete: Value =
        json::from_slice(&std::fs::read(session.join("session-complete.json")).unwrap()).unwrap();
    let issued = complete.get("issuedAtSeconds").unwrap().as_u64().unwrap();
    assert_eq!(
        complete.get("proofExpiresBeforeSeconds").unwrap().as_u64(),
        Some(issued + 61)
    );
    let mut changed = request_json(&request);
    changed.insert(1, b' '); // Unknown/retired policy is refused by the typed request.
    let changed = String::from_utf8(changed)
        .unwrap()
        .replacen('{', "{\"skip_key_check\":true,", 1);
    publish(&root, "bad-request.json", changed.as_bytes()).unwrap();
    assert!(run(root.path().join("bad-request.json").to_str().unwrap()).is_err());
}
