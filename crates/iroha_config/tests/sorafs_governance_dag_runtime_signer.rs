//! Validate the exact non-secret Governance DAG runtime-signer binding.

use iroha_config::parameters::{actual::Root as ActualConfig, defaults, user::Root as UserConfig};
use iroha_config_base::{env::MockEnv, read::ConfigReader, toml::TomlSource};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::account::AccountId;
use std::{fmt::Write as _, path::PathBuf};
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
fn public_key_hex(seed: u8) -> String {
    let key_pair =
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("test Ed25519 keypair");
    hex::encode(key_pair.public_key().to_bytes().1)
}
fn native_signer_bindings() -> String {
    [
        ("proof_outcome", "proof-outcome", 0x60),
        ("repair", "repair", 0x61),
        ("reserve", "reserve", 0x62),
        ("orderbook", "orderbook", 0x63),
    ]
    .into_iter()
    .fold(String::new(), |mut bindings, (role, handle_role, seed)| {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("test Ed25519 keypair");
        let public_key_hex = hex::encode(key_pair.public_key().to_bytes().1);
        let authority = AccountId::new(key_pair.public_key().clone())
            .to_i105_for_discriminant(defaults::common::CHAIN_DISCRIMINANT)
            .expect("test authority must encode as I105");
        let policy_digest_hex = hex::encode([seed; 32]);
        write!(
            bindings,
            r#"
[sorafs.storage.native_transaction_signers.{role}]
handle = "software://sorafs/{handle_role}/governance-primary"
authority = "{authority}"
algorithm = "ed25519"
public_key_hex = "{public_key_hex}"
revision = 1
policy_digest_hex = "{policy_digest_hex}""#
        )
        .expect("writing to a String cannot fail");
        bindings.push('\n');
        bindings
    })
}
fn producer_checkpoint_store_binding() -> String {
    format!(
        r#"
[sorafs.storage.governance_dag_service]
enabled = false
checkpoint_store_handle = "sealed://governance-dag/producer-checkpoint-primary"
checkpoint_store_revision = 31
checkpoint_store_policy_digest_hex = "{}"
"#,
        "81".repeat(32)
    )
}
fn signer_overlay(
    peer_id: Option<&str>,
    handle: Option<&str>,
    revision: Option<u64>,
    policy_digest_hex: Option<&str>,
    public_key_hex: Option<&str>,
) -> String {
    let mut source = String::from(
        r#"
[sorafs.storage]
enabled = true
governance_dag_dir = "/tmp/sorafs-governance"
"#,
    );
    if let Some(peer_id) = peer_id {
        writeln!(source, "governance_dag_publisher_peer_id = \"{peer_id}\"")
            .expect("writing to a String cannot fail");
    }
    if let Some(handle) = handle {
        writeln!(source, "governance_dag_signer_handle = \"{handle}\"")
            .expect("writing to a String cannot fail");
    }
    if let Some(revision) = revision {
        writeln!(source, "governance_dag_signer_revision = {revision}")
            .expect("writing to a String cannot fail");
    }
    if let Some(policy_digest_hex) = policy_digest_hex {
        writeln!(
            source,
            "governance_dag_signer_policy_digest_hex = \"{policy_digest_hex}\""
        )
        .expect("writing to a String cannot fail");
    }
    if let Some(public_key_hex) = public_key_hex {
        writeln!(
            source,
            "governance_dag_publisher_public_key_hex = \"{public_key_hex}\""
        )
        .expect("writing to a String cannot fail");
    }
    source.push_str(&producer_checkpoint_store_binding());
    source.push_str(&native_signer_bindings());
    source
}
#[test]
fn governance_dag_runtime_signer_and_producer_store_project_exact_bindings() {
    let public_key = public_key_hex(0x61);
    let policy_digest = "71".repeat(32);
    let actual = parse_overlay(&signer_overlay(
        Some("12D3KooWGovernancePrimary"),
        Some("software://sorafs/governance-dag/primary"),
        Some(17),
        Some(&policy_digest),
        Some(&public_key),
    ))
    .expect("complete canonical signer binding");
    let storage = &actual.torii.sorafs_storage;
    assert_eq!(
        storage.governance_dag_publisher_peer_id.as_deref(),
        Some("12D3KooWGovernancePrimary")
    );
    assert_eq!(
        storage.governance_dag_signer_handle.as_deref(),
        Some("software://sorafs/governance-dag/primary")
    );
    assert_eq!(storage.governance_dag_signer_revision, Some(17));
    assert_eq!(
        storage.governance_dag_signer_policy_digest,
        Some([0x71; 32])
    );
    assert_eq!(
        storage.governance_dag_publisher_public_key_hex.as_deref(),
        Some(public_key.as_str())
    );
    assert!(!storage.governance_dag_service.enabled);
    assert_eq!(
        storage
            .governance_dag_service
            .checkpoint_store_handle
            .as_deref(),
        Some("sealed://governance-dag/producer-checkpoint-primary")
    );
    assert_eq!(
        storage.governance_dag_service.checkpoint_store_revision,
        Some(31)
    );
    assert_eq!(
        storage
            .governance_dag_service
            .checkpoint_store_policy_digest,
        Some([0x81; 32])
    );
}
#[test]
fn governance_dag_local_producer_rejects_missing_checkpoint_store_binding() {
    let public_key = public_key_hex(0x66);
    let policy_digest = "76".repeat(32);
    let source = signer_overlay(
        Some("12D3KooWGovernancePrimary"),
        Some("software://sorafs/governance-dag/primary"),
        Some(31),
        Some(&policy_digest),
        Some(&public_key),
    )
    .replace(&producer_checkpoint_store_binding(), "");
    let error = parse_overlay(&source).expect_err("producer checkpoint store is mandatory");
    assert!(
        error.contains(
            "governance_dag_service.checkpoint_store_handle is required for the public service or signed local producer"
        ),
        "unexpected missing-store diagnostic: {error}"
    );
}
#[test]
fn governance_dag_local_producer_rejects_partial_checkpoint_store_bindings() {
    let public_key = public_key_hex(0x67);
    let policy_digest = "77".repeat(32);
    let complete = signer_overlay(
        Some("12D3KooWGovernancePrimary"),
        Some("software://sorafs/governance-dag/primary"),
        Some(33),
        Some(&policy_digest),
        Some(&public_key),
    );
    for (label, removed) in [
        (
            "handle",
            "checkpoint_store_handle = \"sealed://governance-dag/producer-checkpoint-primary\"\n",
        ),
        ("revision", "checkpoint_store_revision = 31\n"),
        (
            "policy digest",
            "checkpoint_store_policy_digest_hex = \"8181818181818181818181818181818181818181818181818181818181818181\"\n",
        ),
    ] {
        let error = parse_overlay(&complete.replace(removed, ""))
            .expect_err("partial producer checkpoint-store binding must fail");
        assert!(
            error.contains(
                "governance_dag_service.checkpoint_store handle, revision, and policy digest must be configured together"
            ),
            "{label} produced unexpected partial-store diagnostic: {error}"
        );
    }
}
#[test]
fn disabled_governance_service_rejects_network_auth_but_accepts_producer_store() {
    let public_key = public_key_hex(0x68);
    let policy_digest = "78".repeat(32);
    let complete = signer_overlay(
        Some("12D3KooWGovernancePrimary"),
        Some("software://sorafs/governance-dag/primary"),
        Some(35),
        Some(&policy_digest),
        Some(&public_key),
    );
    parse_overlay(&complete).expect("disabled service accepts the producer checkpoint store");
    let with_dormant_ipfs_auth = complete.replacen(
        "[sorafs.storage.governance_dag_service]\nenabled = false\n",
        &format!(
            r#"[sorafs.storage.governance_dag_service]
enabled = false
ipfs_authenticator_handle = "vault://governance/ipfs-primary"
ipfs_authenticator_revision = 37
ipfs_authenticator_policy_digest_hex = "{}"
"#,
            "82".repeat(32)
        ),
        1,
    );
    let error = parse_overlay(&with_dormant_ipfs_auth)
        .expect_err("disabled service must reject dormant network authentication");
    assert!(
        error.contains(
            "governance_dag_service IPFS and head runtime provider bindings must be absent when disabled"
        ),
        "unexpected disabled-service diagnostic: {error}"
    );
}
#[test]
fn governance_dag_runtime_signer_rejects_every_partial_five_field_binding() {
    let public_key = public_key_hex(0x62);
    let policy_digest = "72".repeat(32);
    let complete = (
        Some("12D3KooWGovernancePrimary"),
        Some("software://sorafs/governance-dag/primary"),
        Some(19),
        Some(policy_digest.as_str()),
        Some(public_key.as_str()),
    );
    let cases = [
        (None, complete.1, complete.2, complete.3, complete.4),
        (complete.0, None, complete.2, complete.3, complete.4),
        (complete.0, complete.1, None, complete.3, complete.4),
        (complete.0, complete.1, complete.2, None, complete.4),
        (complete.0, complete.1, complete.2, complete.3, None),
    ];
    for (peer_id, handle, revision, digest, public_key) in cases {
        let error = parse_overlay(&signer_overlay(
            peer_id, handle, revision, digest, public_key,
        ))
        .expect_err("partial signer binding must fail");
        assert!(
            error.contains("requires publisher peer id, signer handle, signer revision, signer policy digest, and publisher public key together"),
            "unexpected partial-binding diagnostic: {error}"
        );
    }
}
#[test]
fn governance_dag_runtime_signer_rejects_zero_and_noncanonical_qualification() {
    let public_key = public_key_hex(0x63);
    for (label, revision, digest, expected) in [
        (
            "zero revision",
            0,
            "73".repeat(32),
            "governance_dag_signer_revision must be nonzero",
        ),
        (
            "zero digest",
            21,
            "00".repeat(32),
            "governance_dag_signer_policy_digest_hex must be nonzero",
        ),
        (
            "uppercase digest",
            21,
            "AB".repeat(32),
            "must be canonical lowercase non-zero 32-byte hex",
        ),
        (
            "short digest",
            21,
            "73".repeat(31),
            "must be canonical lowercase non-zero 32-byte hex",
        ),
        (
            "non-hex digest",
            21,
            format!("{}gg", "73".repeat(31)),
            "must be canonical lowercase non-zero 32-byte hex",
        ),
    ] {
        let error = parse_overlay(&signer_overlay(
            Some("12D3KooWGovernancePrimary"),
            Some("software://sorafs/governance-dag/primary"),
            Some(revision),
            Some(&digest),
            Some(&public_key),
        ))
        .expect_err(label);
        assert!(
            error.contains(expected),
            "{label} produced unexpected diagnostic: {error}"
        );
    }
}
#[test]
fn governance_dag_runtime_signer_rejects_test_marked_handle_without_echoing_it() {
    let public_key = public_key_hex(0x64);
    let policy_digest = "74".repeat(32);
    let secret_marker = "software://sorafs/governance-dag/test-secret-must-not-escape";
    let error = parse_overlay(&signer_overlay(
        Some("12D3KooWGovernancePrimary"),
        Some(secret_marker),
        Some(23),
        Some(&policy_digest),
        Some(&public_key),
    ))
    .expect_err("test-marked signer handle must fail");
    assert!(error.contains("must be a production runtime handle"));
    assert!(!error.contains(secret_marker));
}
#[test]
fn governance_dag_runtime_signer_rejects_dormant_and_disabled_bindings() {
    let public_key = public_key_hex(0x65);
    let policy_digest = "75".repeat(32);
    let complete = signer_overlay(
        Some("12D3KooWGovernancePrimary"),
        Some("software://sorafs/governance-dag/primary"),
        Some(29),
        Some(&policy_digest),
        Some(&public_key),
    );
    for (label, source, expected) in [
        (
            "publisher directory without binding",
            r#"
[sorafs.storage]
enabled = true
governance_dag_dir = "/tmp/sorafs-governance"
"#
            .to_owned(),
            "governance_dag_dir requires the complete signed Governance DAG publisher binding",
        ),
        (
            "dormant binding",
            complete.replace("governance_dag_dir = \"/tmp/sorafs-governance\"\n", ""),
            "binding is forbidden without governance_dag_dir",
        ),
        (
            "dormant partial binding",
            r#"
[sorafs.storage]
enabled = true
governance_dag_signer_handle = "software://sorafs/governance-dag/primary"
"#
            .to_owned(),
            "binding is forbidden without governance_dag_dir",
        ),
        (
            "disabled binding",
            complete.replace("enabled = true", "enabled = false"),
            "publication requires storage.enabled",
        ),
    ] {
        let error = parse_overlay(&source).expect_err(label);
        assert!(
            error.contains(expected),
            "{label} produced unexpected diagnostic: {error}"
        );
    }
}
