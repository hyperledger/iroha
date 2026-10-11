//! End-to-end validation for the checked-in Minamoto validator profile.

use std::{path::Path, str::FromStr};

use iroha_config::parameters::{
    actual::{self, ToriiMcpProfile},
    user::Root as UserConfig,
};
use iroha_config_base::{read::ConfigReader, toml::TomlSource};
use toml::Value;

fn load_minamoto_profile() -> actual::Root {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("configs/soranexus/nexus/config.toml");
    let source = std::fs::read_to_string(&path).expect("read Minamoto validator profile");
    let mut table = toml::Table::from_str(&source).expect("parse Minamoto validator profile");

    table
        .remove("private_key_file")
        .expect("Minamoto profile validator private-key file");
    table.insert(
        "private_key".into(),
        Value::String(
            "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F".into(),
        ),
    );
    table.insert(
        "soranet_transport_public_key".into(),
        Value::String(
            "ed0120D9F6AEF1813164294D1D9C0662FEB9C7F7861B4DFFE385680331093DA4ABD10B".into(),
        ),
    );
    table
        .remove("soranet_transport_private_key_file")
        .expect("Minamoto profile transport private-key file");
    table.insert(
        "soranet_transport_private_key".into(),
        Value::String(
            "802620134C4527B3852AE2218A8F079B301C651EAD8C7567B96BD7A9BE8DB366E46B89".into(),
        ),
    );

    let streaming = table
        .get_mut("streaming")
        .and_then(Value::as_table_mut)
        .expect("Minamoto profile streaming table");
    streaming.insert(
        "identity_public_key".into(),
        Value::String(
            "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB".into(),
        ),
    );
    streaming
        .remove("identity_private_key_file")
        .expect("Minamoto profile streaming private-key file");
    streaming.insert(
        "identity_private_key".into(),
        Value::String(
            "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F".into(),
        ),
    );

    let genesis = table
        .get_mut("genesis")
        .and_then(Value::as_table_mut)
        .expect("Minamoto profile genesis table");
    genesis
        .remove("expected_hash_file")
        .expect("Minamoto profile expected-hash file");
    genesis.insert(
        "expected_hash".into(),
        Value::String(
            "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E".into(),
        ),
    );

    ConfigReader::new()
        .without_env()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .expect("Minamoto validator profile must decode")
        .parse()
        .unwrap_or_else(|error| panic!("Minamoto validator profile must fully parse: {error:?}"))
}

#[test]
fn minamoto_validator_profile_fully_parses() {
    let config = load_minamoto_profile();
    assert_eq!(
        config.common.chain.as_str(),
        "00000000-0000-0000-0000-000000000753"
    );
    assert_eq!(*config.common.chain_discriminant.value(), 753);
    assert_eq!(config.nexus.lane_catalog.lane_count().get(), 3);
    assert_eq!(config.nexus.dataspace_catalog.entries().len(), 1);
    assert!(config.torii.mcp.enabled);
    assert_eq!(config.torii.mcp.profile, ToriiMcpProfile::Writer);
    assert!(!config.torii.mcp.expose_operator_routes);
    assert_eq!(
        config.torii.mcp.allow_tool_prefixes,
        vec![String::from("iroha.")]
    );
}
