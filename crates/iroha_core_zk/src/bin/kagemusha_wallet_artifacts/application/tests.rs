//! Offline preparation tests use synthetic component DATA and establish no release evidence.
use super::*;
use iroha_crypto::{PrivateKey, Signature as EdSignature};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn endpoint_roles_and_json_limits_match_the_native_contract() {
    for origin in [
        "https://localhost:9443",
        "https://[::1]:9443",
        "https://example.test",
    ] {
        assert!(origin_valid(origin));
    }
    for origin in [
        "http://localhost",
        "https://localhost/",
        "https://user@host",
        "https://localhost:0",
        "https://[invalid]",
        "https://host:65536",
    ] {
        assert!(!origin_valid(origin));
    }
    assert!(path_valid("/v1/retail/enrollment/challenge"));
    for path in ["//host/path", "/a/../b", "/a?b", "/a#b", "/a\\b"] {
        assert!(!path_valid(path));
    }
    assert!(roles_valid(&["RETAIL_USER".into()], "RETAIL_USER"));
    assert!(!roles_valid(
        &["RETAIL_USER".into(), "RETAIL_USER".into()],
        "RETAIL_USER"
    ));
    assert!(!roles_valid(&["RETAIL_USER".into()], "ADMIN"));
    let bytes = canonical(&norito::json!({"z":1,"a":2}), 128).unwrap();
    assert_eq!(bytes, b"{\"a\":2,\"z\":1}\n");
    assert!(parse(&bytes, 128, true).is_ok());
    assert!(parse(b"{\"z\":1,\"a\":2}\n", 128, true).is_err());
    assert!(parse(b"{\"a\":1,\"a\":2}", 128, false).is_err());
    assert!(parse(&bytes, 3, false).is_err());
}
#[test]
fn output_is_exclusive_and_selected_originals_are_retained() {
    let temp = tempfile::tempdir().unwrap();
    let parent =
        PrivateDirectory::open_or_create(temp.path().canonicalize().unwrap().join("parent"))
            .unwrap();
    let child = output(parent.path().to_str().unwrap(), "fresh").unwrap();
    assert!(output(parent.path().to_str().unwrap(), "fresh").is_err());
    assert!(output(parent.path().to_str().unwrap(), "../escape").is_err());
    publish(&child, "original", b"exact bytes").unwrap();
    #[cfg(unix)]
    {
        assert_eq!(
            std::fs::metadata(child.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(child.path().join("original"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
    }
    let mut held = Vec::new();
    let selector = OriginalInput {
        path: child.path().join("original").to_str().unwrap().into(),
        sha256: hex::encode(BlobV1::of(b"exact bytes").sha256),
    };
    assert_eq!(input(&selector, 64, &mut held).unwrap(), b"exact bytes");
    recheck(&held).unwrap();
    std::fs::rename(child.path().join("original"), child.path().join("prior")).unwrap();
    assert!(recheck(&held).is_err());
}
fn test_release(key: &PrivateKey) -> Vec<u8> {
    let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::new(b"component-test-only-genesis-identity"),
    ));
    canonical(&norito::json!({"schema":DOMAIN,"nativeBridgeAbiVersion":29,"runtimeSha256":("11".repeat(32)),
        "signedGenesisSha256":("22".repeat(32)),"genesisBlockHash":(hex::encode(network.as_bytes())),
        "genesisPublicKey":(PublicKey::from_private_key(key).unwrap().to_string()),"chainId":"component-test-only","networkId":(network.to_string()),
        "financialOriginals":{"verifierPack":(blob(b"test-only pack")),"producerInventory":(blob(b"test-only catalog")),
        "producerCatalogDigest":("33".repeat(32)),"transport":(blob(b"test-only transport"))}}),APP_MAX).unwrap()
}
#[test]
fn signature_assembly_checks_real_eddsa_exact_manifest_domain_and_key() {
    let key = PrivateKey::from_bytes(Algorithm::Ed25519, &[37; 32]).unwrap();
    let public = PublicKey::from_private_key(&key).unwrap();
    let (_, bytes) = public.to_bytes();
    let public: [u8; 32] = bytes.try_into().unwrap();
    let manifest = test_release(&key);
    let signature = EdSignature::new(&key, &signing_message(&manifest));
    let result = envelope(&manifest, signature.payload(), public).unwrap();
    let document = parse(&result, 4096, true).unwrap();
    assert_eq!(
        document.get("keyId").unwrap().as_str().unwrap(),
        format!("sha256:{}", hex::encode(BlobV1::of(&public).sha256))
    );
    assert_eq!(
        document.get("signatureBase64").unwrap().as_str().unwrap(),
        STANDARD.encode(signature.payload())
    );
    assert!(envelope(&manifest, &signature.payload()[..63], public).is_err());
    let wrong_domain = EdSignature::new(&key, &manifest);
    assert!(envelope(&manifest, wrong_domain.payload(), public).is_err());
    let mut changed = manifest.clone();
    let at = changed.iter().position(|b| *b == b'1').unwrap();
    changed[at] = b'2';
    assert!(envelope(&changed, signature.payload(), public).is_err());
    let other = PrivateKey::from_bytes(Algorithm::Ed25519, &[38; 32]).unwrap();
    let other = PublicKey::from_private_key(&other).unwrap();
    let (_, bytes) = other.to_bytes();
    assert!(envelope(&manifest, signature.payload(), bytes.try_into().unwrap()).is_err());
}
#[test]
fn typed_templates_bind_app_platform_scheme_and_control_lifetime() {
    let app = KagemushaWalletAppPolicyV1 {
        version: 1,
        scheme_id: [3; 32],
        identity: KagemushaWalletAppIdentityV1::Apple {
            app_id: "TESTONLY.example.wallet".into(),
        },
    };
    let controls = Controls {
        permitted_controls: 0,
        blacklist_max_age_ms: 0,
        time_anchor_max_response_ms: 0,
        challenge_lifetime_ms: 60_000,
        attestation_lease_lifetime_ms: 0,
    };
    let platform = KagemushaWalletEnrollmentPlatformV1::Apple {
        attestation_root_sha256: [5; 32],
    };
    let bytes = policy(&app, platform.clone(), &controls).unwrap();
    let decoded =
        KagemushaWalletEnrollmentPolicyTemplateV1::decode_canonical(&bytes, &app.scheme_id)
            .unwrap();
    decoded.validate_for_app(&app).unwrap();
    assert!(KagemushaWalletEnrollmentPolicyTemplateV1::decode_canonical(&bytes, &[4; 32]).is_err());
    let invalid = Controls {
        attestation_lease_lifetime_ms: 1,
        ..controls
    };
    assert!(policy(&app, platform, &invalid).is_err());
    assert!(
        policy(
            &app,
            KagemushaWalletEnrollmentPlatformV1::Android {
                root_set: vec![],
                patch_floor_yyyymm: 202610
            },
            &invalid
        )
        .is_err()
    );
}

#[test]
fn assembly_refuses_signed_but_malformed_release_data() {
    let key = PrivateKey::from_bytes(Algorithm::Ed25519, &[37; 32]).unwrap();
    let public = PublicKey::from_private_key(&key).unwrap();
    let (_, bytes) = public.to_bytes();
    let public = bytes.try_into().unwrap();
    let manifest = test_release(&key);
    let value = parse(&manifest, APP_MAX, true).unwrap();
    for name in [
        "nativeBridgeAbiVersion",
        "runtimeSha256",
        "financialOriginals",
    ] {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(name);
        let changed = canonical(&changed, APP_MAX).unwrap();
        let signature = EdSignature::new(&key, &signing_message(&changed));
        assert!(envelope(&changed, signature.payload(), public).is_err());
    }
    let mut changed = value.clone();
    changed
        .as_object_mut()
        .unwrap()
        .insert("attestationAccepted".into(), Value::Bool(true));
    assert!(release_document(&canonical(&changed, APP_MAX).unwrap()).is_err());
    let mut changed = value;
    changed
        .as_object_mut()
        .unwrap()
        .get_mut("financialOriginals")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("transport")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("bytes".into(), Value::from(0u64));
    assert!(release_document(&canonical(&changed, APP_MAX).unwrap()).is_err());
}
#[test]
fn transport_requires_exact_catalog_addresses_and_extents() {
    use iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::{
        EncodedOriginalV1, OriginalV1, ProducerInventoryV1,
    };
    let a = BlobV1::of(b"test-descriptor");
    let b = BlobV1::of(b"test-verifier");
    let c = BlobV1::of(b"test-prover");
    let inventory = ProducerInventoryV1 {
        version: 1,
        native_profile: [1; 32],
        originals: vec![OriginalV1 {
            descriptor: a,
            verifying_key: b,
            proving_key: c,
        }],
        sigma: [0; 16],
        operations: vec![],
        routes: vec![],
        terminals: vec![],
        omega: 0,
    };
    let mut rows = vec![a, b, c]
        .into_iter()
        .map(|original| EncodedOriginalV1 {
            original,
            stored: BlobV1::of(b"synthetic stored bytes"),
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|r| r.original.sha256);
    let transport = EncodedTransportV1::new(rows.clone()).unwrap();
    transport_closure(&inventory, &transport).unwrap();
    let mut missing = rows.clone();
    missing.pop();
    assert!(transport_closure(&inventory, &EncodedTransportV1::new(missing).unwrap()).is_err());
    let mut extent = rows;
    extent[0].original.bytes += 1;
    assert!(transport_closure(&inventory, &EncodedTransportV1::new(extent).unwrap()).is_err());
    let mut conflict = inventory.clone();
    let mut other = conflict.originals[0];
    other.descriptor.bytes += 1;
    conflict.originals.push(other);
    assert!(transport_closure(&conflict, &transport).is_err());
}
#[test]
fn external_signature_finish_command_publishes_exact_checked_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temp.path().canonicalize().unwrap().join("public"))
        .unwrap();
    let key = PrivateKey::from_bytes(Algorithm::Ed25519, &[37; 32]).unwrap();
    let public = PublicKey::from_private_key(&key).unwrap();
    let (_, public) = public.to_bytes();
    let manifest = test_release(&key);
    let signature = EdSignature::new(&key, &signing_message(&manifest));
    publish(&root, "release.json", &manifest).unwrap();
    publish(&root, "signature.raw", signature.payload()).unwrap();
    let request=canonical(&norito::json!({"schema":"iroha.kagemusha.wallet-application-signature-assembly.v1",
        "manifest":{"path":(root.path().join("release.json").to_str().unwrap()),"sha256":(hex::encode(BlobV1::of(&manifest).sha256))},
        "signature":{"path":(root.path().join("signature.raw").to_str().unwrap()),"sha256":(hex::encode(BlobV1::of(signature.payload()).sha256))},
        "independent_release_public_key_hex":(hex::encode(public)),"output_parent":(root.path().to_str().unwrap()),"output_name":"signature"}),REQUEST_MAX).unwrap();
    publish(&root, "request.json", &request).unwrap();
    let path = root.path().join("request.json");
    finish(path.to_str().unwrap()).unwrap();
    assert!(finish(path.to_str().unwrap()).is_err());
    let actual = std::fs::read(
        root.path()
            .join("signature/application-release-signature.json"),
    )
    .unwrap();
    assert_eq!(
        actual,
        envelope(&manifest, signature.payload(), public.try_into().unwrap()).unwrap()
    );
    assert!(actual.len() < ENVELOPE_MAX);
}
