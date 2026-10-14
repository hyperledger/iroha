//! Pure command, configuration-selection and private-file controls; no enrollment authority.
use super::*;

fn scheme() -> KagemushaWalletSchemeV1 {
    let key = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    KagemushaWalletSchemeV1 {
        version: 1,
        network_id: *Hash::new(b"issuer selection test").as_ref(),
        scheme_root_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(
            key.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap(),
        relation_id: [9; 32],
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    }
}

fn configuration(scheme: &KagemushaWalletSchemeV1, manifest: [u8; 32]) -> String {
    // Tiny placeholders exercise only structural parsing. Normal serving startup must
    // reject them as invalid protocol originals; this fixture starts no service.
    format!(
        r#"[torii.kagemusha_enrollment]
revision = 1
scope_hex = "{}"
journal_dir = "/private/fixture-journal"
[[torii.kagemusha_enrollment.providers]]
eligibility_template_hex = "01"
scheme_hex = "{}"
app_hex = "01"
enrollment_template_hex = "01"
certificate_hex = "01"
manifest_digest_hex = "{}"
release_digest_hex = "{}"
service_origin_digest_hex = "{}"
observation_endpoint = "https://fixture.invalid/eligibility"
observation_credential = "/private/fixture-credential"
signer_private_key = "/private/fixture-signer"
[torii.kagemusha_enrollment.providers.worker]
python_executable = "/fixture/python"
python_sha256_hex = "{}"
verifier_archive = "/private/fixture.pyz"
verifier_sha256_hex = "{}"
openssl_executable = "/fixture/openssl"
openssl_sha256_hex = "{}"
store_directory = "/private/fixture-worker"
exchange_timeout_ms = 1000
"#,
        hex::encode([3; 32]),
        hex::encode(scheme.to_canonical_bytes().unwrap()),
        hex::encode(manifest),
        hex::encode([4; 32]),
        hex::encode([5; 32]),
        hex::encode([6; 32]),
        hex::encode([8; 32]),
        hex::encode([10; 32])
    )
}

#[test]
fn issuer_command_is_closed_and_selects_one_of_four_existing_peers() -> Result<()> {
    let command = norito::json!({
        "schema": "iroha.kagemusha.real-network-command.v1", "phase": "issuer",
        "setup_sha256": (hash(b"setup")), "previous_sha256": (hash(b"registered")),
        "peer_index": 1, "configuration": {"path": "/private/issuer.toml", "sha256": (hash(b"config"))}
    });
    require_command(&command)?;
    for changed in [
        ("phase", norito::json!("funding")),
        ("setup_sha256", norito::json!("00")),
        ("peer_index", norito::json!(4)),
        ("peer_index", norito::json!(-1)),
        ("raw_private_key", norito::json!("never accepted or copied")),
        (
            "configuration",
            norito::json!({"path":"relative.toml", "sha256":(hash(b"config"))}),
        ),
        (
            "configuration",
            norito::json!({"path":"/private/issuer.toml", "sha256":"00"}),
        ),
        (
            "configuration",
            norito::json!({"path":"/private/issuer.toml", "sha256":(hash(b"config")), "body":"never copied"}),
        ),
    ] {
        let mut value = command.clone();
        value
            .as_object_mut()
            .unwrap()
            .insert(changed.0.into(), changed.1);
        ensure!(
            require_command(&value).is_err(),
            "changed issuer command accepted"
        );
    }
    Ok(())
}

#[test]
fn issuer_layer_cannot_change_topology_storage_or_registered_selection() -> Result<()> {
    let selected = scheme();
    let text = configuration(&selected, [11; 32]);
    let layer = parse_layer(text.as_bytes(), &selected, [11; 32])?;
    for changed in [
        text.replacen(
            "[torii.kagemusha_enrollment]",
            "chain = \"foreign\"\n[torii.kagemusha_enrollment]",
            1,
        ),
        format!("{text}\n[kura]\nstore_dir=\"/foreign\"\n"),
        format!("{text}\n[torii]\naddress=\"127.0.0.1:1\"\n"),
        text.replacen("revision = 1", "unknown_key = \"hidden\"\nrevision = 1", 1),
        configuration(&selected, [12; 32]),
        text.replacen(&hex::encode(selected.to_canonical_bytes()?), "00", 1),
    ] {
        ensure!(
            parse_layer(changed.as_bytes(), &selected, [11; 32]).is_err(),
            "foreign issuer config accepted"
        );
    }
    ensure!(
        parse_layer(&vec![b'x'; CONFIG_MAX + 1], &selected, [11; 32]).is_err(),
        "unbounded configuration accepted"
    );
    let failure = parse_layer(b"secret-value = [ broken syntax", &selected, [11; 32]).unwrap_err();
    ensure!(
        !format!("{failure:?}").contains("secret-value"),
        "parser echoed private source"
    );
    ensure!(layer.len() == 1, "one runtime subtree");
    Ok(())
}

#[test]
fn issuer_configuration_requires_exact_private_original_and_rechecks_its_pin() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
    let selected = scheme();
    let bytes = configuration(&selected, [11; 32]).into_bytes();
    publish(&root, "issuer.toml", &bytes)?;
    let path = root.join("issuer.toml");
    let layer = read_layer(&path, &hash(&bytes), &selected, [11; 32])?;
    ensure!(
        read_layer(&path, &hash(b"foreign"), &selected, [11; 32]).is_err(),
        "foreign pin"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let link = root.join("redirect");
        symlink(&path, &link)?;
        ensure!(
            read_layer(&link, &hash(&bytes), &selected, [11; 32]).is_err(),
            "link redirect"
        );
        let hard = root.join("second-name");
        fs::hard_link(&path, &hard)?;
        ensure!(
            read_layer(&path, &hash(&bytes), &selected, [11; 32]).is_err(),
            "multiple links"
        );
        fs::remove_file(hard)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        ensure!(
            read_layer(&path, &hash(&bytes), &selected, [11; 32]).is_err(),
            "public configuration"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    ensure!(
        read_layer(&path, &hash(&bytes), &selected, [11; 32])? == layer,
        "exact selection"
    );
    fs::write(&path, configuration(&selected, [12; 32]))?;
    ensure!(
        read_layer(&path, &hash(&bytes), &selected, [11; 32]).is_err(),
        "changed original"
    );
    Ok(())
}
