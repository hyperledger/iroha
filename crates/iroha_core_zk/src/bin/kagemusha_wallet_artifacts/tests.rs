//! Bounded intake, protocol signing and immutable output tests; no production authority.

use super::*;
use p256::pkcs8::EncodePrivateKey;

fn test_key(value: u8) -> SigningKey {
    SigningKey::from_bytes((&[value; 32]).into()).unwrap()
}

fn public(key: &SigningKey) -> KagemushaDevicePublicKeyV1 {
    KagemushaDevicePublicKeyV1::from_sec1_bytes(
        key.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap()
}

fn request_bytes() -> Vec<u8> {
    format!(r#"{{"schema":"iroha.kagemusha.wallet-artifact-production.v1","chain_id":"test-only","network_id_hex":"{}","genesis_public_key":"{}","signed_genesis":{{"path":"/private/test/genesis","sha256":"{}"}},"custody_directory":"/private/test/custody","scheme_root_public_key_hex":"{}","enrollment_public_key_hex":"{}","artifact_public_key_hex":"{}","output_parent":"/private/test/output","output_name":"test-only-output","maximum_total_bytes":1048576}}"#,
        "01".repeat(32), iroha_crypto::KeyPair::random().public_key(), "02".repeat(32),
        hex::encode(public(&test_key(1)).as_sec1_bytes()), hex::encode(public(&test_key(2)).as_sec1_bytes()), hex::encode(public(&test_key(3)).as_sec1_bytes())).into_bytes()
}

#[test]
fn public_request_refuses_unknown_fields_aliased_roles_and_unbounded_resources() {
    let bytes = request_bytes();
    let request = parse_request(&bytes).unwrap();
    assert_eq!(request.output_name, "test-only-output");
    let text = String::from_utf8(bytes).unwrap();
    let retired = text.replacen('{', "{\"finality_inventory\":{},", 1);
    assert!(parse_request(retired.as_bytes()).is_err());
    let unknown = text.replacen('{', "{\"readiness\":true,", 1);
    assert!(parse_request(unknown.as_bytes()).is_err());
    let aliased = text.replace(
        &request.enrollment_public_key_hex,
        &request.scheme_root_public_key_hex,
    );
    assert!(parse_request(aliased.as_bytes()).is_err());
    for bad in ["0", "18446744073709551615"] {
        assert!(parse_request(text.replace("1048576", bad).as_bytes()).is_err());
    }
    assert!(parse_request(text.replace("test-only-output", "../other").as_bytes()).is_err());
    assert!(digest(&"00".repeat(32)).is_err());
    assert!(digest(&"AA".repeat(32)).is_err());
    assert!(point(&"04".repeat(65)).is_err());
    assert!(point(&hex::encode(public(&test_key(1)).as_sec1_bytes()).to_uppercase()).is_err());
}

#[test]
fn immutable_originals_reject_tampering_aliases_hashes_and_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("originals");
    let directory = PrivateDirectory::open_or_create(&root).unwrap();
    publish(&directory, "original", b"actual bounded public bytes").unwrap();
    let path = root.join("original");
    let original = Original::open(
        path.to_str().unwrap(),
        100,
        Some(BlobV1::of(b"actual bounded public bytes").sha256),
    )
    .unwrap();
    original.recheck().unwrap();
    assert!(Original::open(path.to_str().unwrap(), 3, None).is_err());
    assert!(Original::open(path.to_str().unwrap(), 100, Some([1; 32])).is_err());
    assert!(publish(&directory, "original", b"replacement").is_err());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"actual bounded public bytes"
    );
    std::fs::rename(&path, root.join("retained-original")).unwrap();
    std::fs::write(&path, b"substituted original").unwrap();
    assert!(original.recheck().is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.join("retained-original"), root.join("redirect")).unwrap();
        assert!(Original::open(root.join("redirect").to_str().unwrap(), 100, None).is_err());
    }
}

#[test]
fn actual_private_key_intake_and_protocol_signatures_are_role_and_scheme_bound() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        PrivateDirectory::open_or_create(temp.path().canonicalize().unwrap().join("custody"))
            .unwrap();
    let secret = test_key(1);
    let encoded = p256::SecretKey::from_bytes(&secret.to_bytes())
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    publish(&root, "scheme-root.pkcs8.der", encoded.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // The established recovery custody stores PKCS#8 files with exact 0600.
        std::fs::set_permissions(
            root.path().join("scheme-root.pkcs8.der"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let admitted = private_key(&root, "scheme-root.pkcs8.der", public(&secret)).unwrap();
    assert!(private_key(&root, "scheme-root.pkcs8.der", public(&test_key(2))).is_err());
    let scheme = KagemushaWalletSchemeV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        network_id: [1; 32],
        scheme_root_key: public(&admitted),
        relation_id: [2; 32],
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    };
    let source = scope(scheme.scheme_root_key).unwrap();
    assert_ne!(source.provider(), [0; 2]);
    let enrollment = certificate(
        &scheme,
        &admitted,
        public(&test_key(2)),
        KagemushaWalletSignerRoleV1::Enrollment,
    )
    .unwrap();
    enrollment
        .verify_role(&scheme, KagemushaWalletSignerRoleV1::Enrollment)
        .unwrap();
    assert!(
        enrollment
            .verify_role(&scheme, KagemushaWalletSignerRoleV1::Artifact)
            .is_err()
    );
    let original = enrollment.to_canonical_bytes().unwrap();
    assert_eq!(
        KagemushaWalletSignerCertificateV1::decode_canonical(&original, &scheme).unwrap(),
        enrollment
    );
    let mut changed = scheme;
    changed.network_id = [3; 32];
    assert!(enrollment.verify(&changed).is_err());
    assert!(
        certificate(
            &scheme,
            &test_key(3),
            public(&test_key(2)),
            KagemushaWalletSignerRoleV1::Enrollment
        )
        .is_err()
    );
}

#[test]
fn malformed_genesis_never_reaches_compiler_or_signer() {
    let request = parse_request(&request_bytes()).unwrap();
    assert!(
        native_finality(
            &request.chain_id,
            &request.network_id_hex,
            &request.genesis_public_key,
            b"not signed genesis"
        )
        .is_err()
    );
    let temp = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temp.path().canonicalize().unwrap().join("inputs"))
        .unwrap();
    publish(&root, "request.json", &request_bytes()).unwrap();
    assert!(run(root.path().join("request.json").to_str().unwrap()).is_err());
    assert_eq!(root.entries(10).unwrap().len(), 1);
}

#[test]
fn completed_carrier_excludes_provisional_cache_and_refuses_changed_identities() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        PrivateDirectory::open_or_create(temp.path().canonicalize().unwrap().join("carrier-test"))
            .unwrap();
    let cache = root.create_child("cache").unwrap();
    let target = root.create_child("closed").unwrap();
    let mut source = DirectoryOriginalsV1::open_existing(cache.path(), 1 << 20).unwrap();
    let selected_bytes = vec![42; 150_000];
    let selected = BlobV1::of(&selected_bytes);
    let provisional = BlobV1::of(b"unselected provisional compiler DATA");
    source.store_original(selected, &selected_bytes).unwrap();
    source
        .store_original(provisional, b"unselected provisional compiler DATA")
        .unwrap();
    copy_closed(&source, &target, &[selected]).unwrap();
    let completed = DirectoryOriginalsV1::open_existing(target.path(), 1 << 20).unwrap();
    completed.verify_original(selected).unwrap();
    assert_eq!(target.entries(10).unwrap().len(), 1);
    assert!(completed.open_original(provisional.sha256).is_err());
    // The preserved cache remains intact; a repeat cannot replace carrier originals.
    source.verify_original(provisional).unwrap();
    assert!(copy_closed(&source, &target, &[selected]).is_err());
    let duplicate_target = root.create_child("duplicate").unwrap();
    assert!(copy_closed(&source, &duplicate_target, &[selected, selected]).is_err());
    assert!(duplicate_target.entries(10).unwrap().is_empty());
    let changed_target = root.create_child("changed").unwrap();
    let changed = BlobV1 {
        bytes: selected.bytes - 1,
        ..selected
    };
    assert!(copy_closed(&source, &changed_target, &[changed]).is_err());
    assert!(changed_target.entries(10).unwrap().is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let path = cache.path().join(hex::encode(selected.sha256));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, vec![41; selected_bytes.len()]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let tampered_target = root.create_child("tampered").unwrap();
        assert!(copy_closed(&source, &tampered_target, &[selected]).is_err());
        assert!(tampered_target.entries(10).unwrap().is_empty());
    }
}

#[test]
fn complete_reader_selects_closed_wallet_roster_only() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        PrivateDirectory::open_or_create(temp.path().canonicalize().unwrap().join("source-test"))
            .unwrap();
    let wallet_dir = root.create_child("wallet").unwrap();
    let mut wallet = DirectoryOriginalsV1::open_existing(wallet_dir.path(), 1024).unwrap();
    let wallet_bytes = b"selected wallet PK DATA";
    let excluded_bytes = b"unselected provisional wallet DATA";
    let wallet_blob = BlobV1::of(wallet_bytes);
    let excluded = BlobV1::of(excluded_bytes);
    wallet.store_original(wallet_blob, wallet_bytes).unwrap();
    wallet.store_original(excluded, excluded_bytes).unwrap();
    let wallet_blobs = BTreeMap::from([(wallet_blob.sha256, wallet_blob)]);
    let mut source = CompleteSource {
        wallet: &wallet,
        wallet_blobs: &wallet_blobs,
    };
    for (blob, expected) in [(wallet_blob, wallet_bytes.as_slice())] {
        let mut bytes = Vec::new();
        source
            .open(blob.sha256)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, expected);
    }
    assert!(matches!(
        source.open(excluded.sha256),
        Err(iroha_core_zk::kagemusha_wallet_proofs_v1::Error::Inventory)
    ));
    assert!(matches!(
        source.open([0; 32]),
        Err(iroha_core_zk::kagemusha_wallet_proofs_v1::Error::Inventory)
    ));
}
