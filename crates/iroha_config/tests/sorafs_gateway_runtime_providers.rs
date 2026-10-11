//! Validate exact non-secret runtime-provider bindings for `SoraFS` gateways.

use iroha_config::parameters::{actual::Root as ActualConfig, user::Root as UserConfig};
use iroha_config_base::{env::MockEnv, read::ConfigReader, toml::TomlSource};
use std::path::PathBuf;
fn base_reader() -> ConfigReader {
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base.toml");
    ConfigReader::new()
        .with_env(MockEnv::new())
        .read_toml_with_extends(base_path)
        .expect("base config should load")
}
fn parse_overlay(source: &str) -> Result<ActualConfig, String> {
    let table = source
        .parse()
        .map_err(|error| format!("inline TOML must parse: {error}"))?;
    base_reader()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .map_err(|error| format!("{error:?}"))?
        .parse()
        .map_err(|error| format!("{error:?}"))
}
fn acme_overlay(handle: &str, revision: u64, policy_digest_hex: &str) -> String {
    format!(
        r#"
[sorafs.gateway.acme]
enabled = true
provider_handle = "{handle}"
provider_revision = {revision}
provider_policy_digest_hex = "{policy_digest_hex}"
"#
    )
}
#[test]
fn enabled_acme_reads_one_exact_provider_binding_from_toml() {
    let actual = parse_overlay(&acme_overlay(
        "runtime://sorafs/gateway-acme/primary",
        17,
        &"51".repeat(32),
    ))
    .expect("valid ACME provider binding");
    let provider = actual
        .torii
        .sorafs_gateway
        .acme
        .provider
        .expect("enabled ACME provider");
    assert_eq!(
        provider.provider_handle,
        "runtime://sorafs/gateway-acme/primary"
    );
    assert_eq!(provider.revision, 17);
    assert_eq!(provider.policy_digest, [0x51; 32]);
}
#[test]
fn gateway_provider_toml_rejects_partial_zero_test_marked_and_noncanonical_forms() {
    for (label, source, expected) in [
        (
            "partial ACME binding",
            r#"
[sorafs.gateway.acme]
enabled = true
provider_handle = "runtime://sorafs/gateway-acme/primary"
"#
            .to_owned(),
            "provider_revision is required when enabled",
        ),
        (
            "zero ACME revision",
            acme_overlay("runtime://sorafs/gateway-acme/primary", 0, &"51".repeat(32)),
            "provider_revision must be nonzero",
        ),
        (
            "test-marked ACME handle",
            acme_overlay(
                "runtime://sorafs/gateway-acme/test-provider-secret",
                17,
                &"51".repeat(32),
            ),
            "must be one canonical production provider handle",
        ),
        (
            "uppercase ACME digest",
            acme_overlay(
                "runtime://sorafs/gateway-acme/primary",
                17,
                &"AB".repeat(32),
            ),
            "must be exactly 64 lowercase hexadecimal characters",
        ),
        (
            "missing enabled compliance binding",
            r"
[sorafs.gateway.compliance]
enabled = true
"
            .to_owned(),
            "feed_transport_provider_handle is required when enabled",
        ),
        (
            "dormant compliance binding",
            format!(
                r#"
[sorafs.gateway.compliance]
enabled = false
feed_transport_provider_handle = "sorafs.gateway.compliance.feed-https.v1"
feed_transport_provider_revision = 1
feed_transport_provider_policy_digest_hex = "{}"
"#,
                "52".repeat(32)
            ),
            "feed_transport_provider binding fields must be absent when disabled",
        ),
    ] {
        let error = parse_overlay(&source).expect_err(label);
        assert!(
            error.contains(expected),
            "{label} produced unexpected diagnostic: {error}"
        );
        if label == "test-marked ACME handle" {
            assert!(
                !error.contains("test-provider-secret"),
                "runtime provider values must not be echoed"
            );
        }
    }
}

fn compliance_overlay() -> String {
    let public = |seed| {
        let pair =
            iroha_crypto::KeyPair::try_from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
                .unwrap();
        hex::encode(pair.public_key().to_bytes().1)
    };
    let checkpoint =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/compliance-checkpoint.nrt");
    // This tests only parser ownership: no checkpoint, provider, key or native authority is opened.
    format!(
        r#"
[sorafs.gateway.compliance]
enabled = true
feed_transport_provider_handle = "sorafs.gateway.compliance.feed-https.v1"
feed_transport_provider_revision = 1
feed_transport_provider_policy_digest_hex = "{}"
checkpoint_path = {:?}
policy_id_hex = "{}"
region_id = "local"
gateway_id = "local-gateway"
catalog_threshold = 2
gateway_ack_threshold = 1
feeds = []
[[sorafs.gateway.compliance.catalog_signers]]
signer_id = "catalog-a"
public_key_hex = "{}"
[[sorafs.gateway.compliance.catalog_signers]]
signer_id = "catalog-b"
public_key_hex = "{}"
[[sorafs.gateway.compliance.gateway_signers]]
signer_id = "local-gateway"
public_key_hex = "{}"
"#,
        "52".repeat(32),
        checkpoint.to_str().unwrap(),
        "53".repeat(32),
        public(31),
        public(32),
        public(33)
    )
}

#[test]
fn enabled_compliance_allows_explicit_empty_feeds_without_relaxing_authority_or_host_rules() {
    let original = compliance_overlay();
    let actual = parse_overlay(&original).expect("explicit empty feed selection");
    let compliance = actual.torii.sorafs_gateway.compliance.unwrap();
    assert!(compliance.feeds.is_empty());
    assert_eq!(compliance.catalog_threshold, 2);
    assert_eq!(compliance.gateway_ack_threshold, 1);
    assert_eq!(compliance.gateway_id, "local-gateway");
    for changed in [
        original.replace("catalog_threshold = 2", "catalog_threshold = 0"),
        original.replace("gateway_ack_threshold = 1", "gateway_ack_threshold = 0"),
        original.replace(
            "feed_transport_provider_revision = 1",
            "feed_transport_provider_revision = 0",
        ),
    ] {
        assert!(parse_overlay(&changed).is_err());
    }
    let malformed_feed = original.replace("feeds = []", "")
        + r#"
[[sorafs.gateway.compliance.feeds]]
feed_id = "configured"
url = "https://feed.example/catalog"
required = true
hosts = []
"#;
    let host_error = parse_overlay(&malformed_feed).unwrap_err();
    assert!(
        host_error.contains("requires at least one HTTPS host"),
        "configured feed must reach the host validator: {host_error}"
    );
    let configured_feed = malformed_feed.replace(
        "hosts = []",
        &format!(
            r#"[[sorafs.gateway.compliance.feeds.hosts]]
hostname = "feed.example"
accepted_spki_sha256_hex = ["{}"]"#,
            "54".repeat(32)
        ),
    );
    let actual = parse_overlay(&configured_feed).expect("nonempty pinned feed remains valid");
    assert_eq!(
        actual.torii.sorafs_gateway.compliance.unwrap().feeds.len(),
        1
    );
}
