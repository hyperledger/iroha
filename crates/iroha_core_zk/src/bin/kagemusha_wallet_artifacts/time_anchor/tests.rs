//! Real model signatures and private command custody; no physical exchange qualification.

use super::*;
use p256::pkcs8::EncodePrivateKey as _;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}

fn public(key: &SigningKey) -> KagemushaDevicePublicKeyV1 {
    KagemushaDevicePublicKeyV1::from_sec1_bytes(
        key.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap()
}

fn authority() -> (KagemushaWalletSchemeV1, KagemushaWalletSignerCertificateV1) {
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: [1; 32],
        scheme_root_key: public(&key(7)),
        relation_id: [2; 32],
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    };
    let certificate = super::super::certificate(
        &scheme,
        &key(7),
        public(&key(8)),
        KagemushaWalletSignerRoleV1::TimeAnchor,
    )
    .unwrap();
    (scheme, certificate)
}

#[test]
fn actual_time_response_binds_scheme_role_wallet_nonce_time_and_signer() {
    let (scheme, certificate) = authority();
    let anchor = response(&scheme, &certificate, &key(8), [3; 32], [4; 32], 1234).unwrap();
    anchor.verify(&scheme, &certificate).unwrap();
    assert_eq!(anchor.body.wallet_id, [3; 32]);
    assert_eq!(anchor.body.nonce, [4; 32]);
    assert_eq!(anchor.body.issuer_time_ms, 1234);
    let bytes = anchor.to_canonical_bytes().unwrap();
    assert_eq!(
        KagemushaWalletTimeAnchorV1::decode_canonical(&bytes, &scheme.scheme_id()).unwrap(),
        anchor
    );
    assert!(bytes.len() <= KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1);
    for (wallet, nonce, time) in [
        ([0; 32], [4; 32], 1),
        ([3; 32], [0; 32], 1),
        ([3; 32], [4; 32], 0),
    ] {
        assert!(response(&scheme, &certificate, &key(8), wallet, nonce, time).is_err());
    }
    assert!(response(&scheme, &certificate, &key(9), [3; 32], [4; 32], 1).is_err());
    let wrong_role = super::super::certificate(
        &scheme,
        &key(7),
        public(&key(8)),
        KagemushaWalletSignerRoleV1::Enrollment,
    )
    .unwrap();
    assert!(response(&scheme, &wrong_role, &key(8), [3; 32], [4; 32], 1).is_err());
    let mut foreign = scheme;
    foreign.network_id = [9; 32];
    assert!(response(&foreign, &certificate, &key(8), [3; 32], [4; 32], 1).is_err());
    for selector in 0..4 {
        let mut changed = anchor;
        match selector {
            0 => changed.body.wallet_id[0] ^= 1,
            1 => changed.body.nonce[0] ^= 1,
            2 => changed.body.issuer_time_ms += 1,
            _ => changed.body.signer_certificate[0] ^= 1,
        }
        assert!(changed.verify(&scheme, &certificate).is_err());
    }
}

fn selected(directory: &PrivateDirectory, name: &str, data: &[u8]) -> json::Value {
    publish(directory, name, data).unwrap();
    norito::json!({
        "path":(directory.path().join(name).to_str().unwrap()),
        "sha256":(hex::encode(BlobV1::of(data).sha256))
    })
}

fn command(directory: &PrivateDirectory, custody: &PrivateDirectory) -> json::Value {
    let (scheme, certificate) = authority();
    let scheme_input = selected(
        directory,
        "scheme.norito",
        &scheme.to_canonical_bytes().unwrap(),
    );
    let certificate_input = selected(
        directory,
        "certificate.norito",
        &certificate.to_canonical_bytes().unwrap(),
    );
    let nonce = selected(directory, "nonce.bin", &[4; 32]);
    norito::json!({
        "schema":"iroha.kagemusha.wallet-time-anchor-issuance.v1",
        "scheme":scheme_input, "scheme_id_hex":(hex::encode(scheme.scheme_id())),
        "certificate":certificate_input,
        "issuer_public_key_hex":(hex::encode(certificate.body.key.as_sec1_bytes())),
        "wallet_id_hex":(hex::encode([3; 32])), "nonce":nonce,
        "custody_directory":(custody.path().to_str().unwrap()),
        "output_parent":(directory.path().to_str().unwrap()), "output_name":"issued"
    })
}

#[test]
fn request_rejects_duplicate_unknown_clock_secret_and_noncanonical_fields() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let directory = PrivateDirectory::open_or_create(root.join("input")).unwrap();
    let custody = PrivateDirectory::open_or_create(root.join("custody")).unwrap();
    let value = command(&directory, &custody);
    let bytes = json::to_vec(&value).unwrap();
    request(&bytes).unwrap();
    for field in ["issuer_time_ms", "private_key", "allow_stale"] {
        let mut bad = value.clone();
        bad.as_object_mut()
            .unwrap()
            .insert(field.into(), 1_u64.into());
        assert!(request(&json::to_vec(&bad).unwrap()).is_err());
    }
    let duplicate =
        String::from_utf8(bytes)
            .unwrap()
            .replacen('{', "{\"schema\":\"duplicate\",", 1);
    assert!(request(duplicate.as_bytes()).is_err());
    for (field, bad_value) in [
        ("schema", "retired".to_owned()),
        ("wallet_id_hex", "00".repeat(32)),
        ("scheme_id_hex", "AA".repeat(32)),
        ("issuer_public_key_hex", "02".repeat(33)),
    ] {
        let mut bad = value.clone();
        bad.as_object_mut()
            .unwrap()
            .insert(field.into(), bad_value.into());
        assert!(request(&json::to_vec(&bad).unwrap()).is_err());
    }
}

#[test]
fn command_rejects_changed_authority_and_invalid_original_nonce_before_issuance() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let directory = PrivateDirectory::open_or_create(root.join("input")).unwrap();
    let custody = PrivateDirectory::open_or_create(root.join("custody")).unwrap();
    // No private key exists: every case must refuse its public inputs before issuance.
    let value = command(&directory, &custody);
    let mut cases = Vec::new();
    for (field, replacement) in [
        ("scheme_id_hex", hex::encode([9; 32]).into()),
        (
            "issuer_public_key_hex",
            hex::encode(public(&key(9)).as_sec1_bytes()).into(),
        ),
    ] {
        let mut bad = value.clone();
        bad.as_object_mut()
            .unwrap()
            .insert(field.into(), replacement);
        cases.push(bad);
    }
    for (index, nonce) in [vec![4; 31], vec![4; 33], vec![0; 32]].iter().enumerate() {
        let mut bad = value.clone();
        let original = selected(&directory, &format!("bad-nonce-{index}"), nonce);
        bad.as_object_mut()
            .unwrap()
            .insert("nonce".into(), original);
        cases.push(bad);
    }
    let mut bad_pin = value.clone();
    bad_pin
        .as_object_mut()
        .unwrap()
        .get_mut("nonce")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("sha256".into(), hex::encode([8; 32]).into());
    cases.push(bad_pin);
    for (index, bad) in cases.iter().enumerate() {
        let bytes = json::to_vec(bad).unwrap();
        let original = selected(&directory, &format!("bad-request-{index}.json"), &bytes);
        assert!(run(original["path"].as_str().unwrap()).is_err());
        assert!(!directory.path().join("issued").exists());
    }
}

#[test]
fn command_publishes_current_signed_originals_once_without_private_material() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let directory = PrivateDirectory::open_or_create(root.join("input")).unwrap();
    let custody = PrivateDirectory::open_or_create(root.join("custody")).unwrap();
    let value = command(&directory, &custody);
    let secret = p256::SecretKey::from_bytes(&key(8).to_bytes())
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let key_path = custody.path().join("time-anchor.pkcs8.der");
    std::fs::write(&key_path, secret.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let bytes = json::to_vec(&value).unwrap();
    let request_pin = selected(&directory, "request.json", &bytes);
    let request_path = request_pin["path"].as_str().unwrap();
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    run(request_path).unwrap();
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let output = directory.path().join("issued");
    let issued = std::fs::read(output.join("time-anchor.norito")).unwrap();
    let (scheme, certificate) = authority();
    let anchor =
        KagemushaWalletTimeAnchorV1::decode_canonical(&issued, &scheme.scheme_id()).unwrap();
    anchor.verify(&scheme, &certificate).unwrap();
    assert!((before..=after).contains(&u128::from(anchor.body.issuer_time_ms)));
    let completion: json::Value =
        json::from_slice(&std::fs::read(output.join("time-anchor-complete.json")).unwrap())
            .unwrap();
    assert_eq!(
        completion["anchorSha256"].as_str(),
        Some(hex::encode(BlobV1::of(&issued).sha256).as_str())
    );
    assert_eq!(
        completion["requestSha256"].as_str(),
        Some(hex::encode(BlobV1::of(&bytes).sha256).as_str())
    );
    assert_eq!(
        completion["issuerTimeMs"].as_u64(),
        Some(anchor.body.issuer_time_ms)
    );
    assert_eq!(std::fs::read_dir(&output).unwrap().count(), 4);
    assert_eq!(
        std::fs::read(output.join("time-certificate.norito")).unwrap(),
        certificate.to_canonical_bytes().unwrap()
    );
    let set: KagemushaWalletCertificateSetV1 =
        norito::decode_canonical(&std::fs::read(output.join("time-certificates.norito")).unwrap())
            .unwrap();
    assert_eq!(
        set,
        KagemushaWalletCertificateSetV1::new(vec![certificate]).unwrap()
    );
    assert!(run(request_path).is_err());
    assert_eq!(
        std::fs::read(output.join("time-anchor.norito")).unwrap(),
        issued
    );
}
