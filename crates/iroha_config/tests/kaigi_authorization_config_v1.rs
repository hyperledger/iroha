//! Final Kaigi verifier configuration has one authorization key and no aliases.

use iroha_config::parameters::user::Root;
use iroha_config_base::{read::ConfigReader, toml::TomlSource};
use std::path::PathBuf;

fn reader() -> ConfigReader {
    ConfigReader::new()
        .read_toml_with_extends(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base.toml"),
        )
        .unwrap()
}

#[test]
fn kaigi_key_references_are_chain_policy_not_node_configuration() {
    // The verifying keys that select the Kaigi authorization and usage
    // relations are fields of the committed `zk_validity_policy_v1` parameter
    // (`proofs.kaigi_authorization_vk`, `proofs.kaigi_usage_vk`). A node
    // configuration that names one fails to load.
    for name in ["kaigi_authorization_vk", "kaigi_usage_vk"] {
        let table = format!("[zk.{name}]\nbackend = \"halo2/ipa\"\nname = \"kaigi-final\"\n")
            .parse()
            .unwrap();
        let error = reader()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<Root>()
            .unwrap_err();
        let diagnostic = format!("{error:?}");
        assert!(
            diagnostic.contains("unknown parameter") && diagnostic.contains(name),
            "{diagnostic}"
        );
    }
    let config = reader()
        .read_and_complete::<Root>()
        .unwrap()
        .parse()
        .unwrap();
    assert!(config.zk.kaigi_authorization_vk.is_none());
    assert!(config.zk.kaigi_usage_vk.is_none());
    // The policy carries exactly one authorization key and one usage key.
    let policy = iroha_data_model::zk_validity_policy::ZkValidityPolicyV1::protocol_default();
    assert!(policy.proofs.kaigi_authorization_vk.is_none());
    assert!(policy.proofs.kaigi_usage_vk.is_none());
    let kaigi_fields = iroha_data_model::zk_validity_policy::ZkValidityPolicyV1::field_names()
        .into_iter()
        .filter(|field| field.contains("kaigi"))
        .collect::<Vec<_>>();
    assert_eq!(
        kaigi_fields,
        ["proofs.kaigi_authorization_vk", "proofs.kaigi_usage_vk"]
    );
}

#[test]
fn retired_per_action_key_configuration_is_unknown() {
    for name in ["kaigi_roster_join_vk", "kaigi_roster_leave_vk"] {
        let table = format!("[zk.{name}]\nbackend = \"halo2/ipa\"\nname = \"retired\"\n")
            .parse()
            .unwrap();
        let error = reader()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<Root>()
            .unwrap_err();
        let diagnostic = format!("{error:?}");
        assert!(
            diagnostic.contains("unknown parameter") && diagnostic.contains(name),
            "{diagnostic}"
        );
    }
}
