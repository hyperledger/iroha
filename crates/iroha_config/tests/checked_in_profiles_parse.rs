//! The checked-in peer configuration samples parse with the node configuration schema.
//!
//! Every sample under `defaults/kagami/` and the public Taira validator template must stay
//! admissible: a retired table or key in a sample is an unknown parameter and fails here.
//! Runtime node keys and genesis identity are bound to test fixtures before parsing.

use std::path::{Path, PathBuf};

use iroha_config::parameters::{actual::Root as ActualConfig, user::Root as UserConfig};
use iroha_config_base::{read::ConfigReader, toml::TomlSource};
use toml::{Table, Value};

/// Node key pair of `tests/fixtures/base.toml`, reused for secret substitutions.
const NODE_PRIVATE_KEY: &str =
    "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F";
const TRANSPORT_PUBLIC_KEY: &str =
    "ed0120D9F6AEF1813164294D1D9C0662FEB9C7F7861B4DFFE385680331093DA4ABD10B";
const TRANSPORT_PRIVATE_KEY: &str =
    "802620134C4527B3852AE2218A8F079B301C651EAD8C7567B96BD7A9BE8DB366E46B89";
const STREAMING_PUBLIC_KEY: &str =
    "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB";
const STREAMING_PRIVATE_KEY: &str =
    "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F";
const EXPECTED_HASH: &str =
    "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E";
/// Deployment-owned Soracloud runtime signer handle bound in place of the template placeholder.
const SORACLOUD_SIGNER_HANDLE: &str = "signer://soracloud/runtime-mutation/primary";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn read_table(relative: &str) -> Table {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        .parse()
        .unwrap_or_else(|error| panic!("parse {} as TOML: {error}", path.display()))
}

fn sub_table<'a>(table: &'a mut Table, key: &str) -> &'a mut Table {
    table
        .get_mut(key)
        .and_then(Value::as_table_mut)
        .unwrap_or_else(|| panic!("sample must have a `{key}` table"))
}

/// Replace the runtime-only genesis hash file with an inline hash.
fn inline_expected_hash(table: &mut Table) {
    let genesis = sub_table(table, "genesis");
    genesis
        .remove("expected_hash_file")
        .expect("samples resolve the genesis hash from a runtime file");
    genesis.insert("expected_hash".into(), EXPECTED_HASH.into());
}

/// Replace the Soracloud runtime signer placeholders with one valid public binding.
///
/// The authority is derived from `STREAMING_PUBLIC_KEY` and rendered for the sample's
/// chain discriminant, as the deployment renderer does.
fn bind_soracloud_runtime_signer(table: &mut Table) {
    let discriminant = table
        .get("chain_discriminant")
        .and_then(Value::as_integer)
        .and_then(|value| u16::try_from(value).ok())
        .expect("sample declares its chain discriminant");
    let public_key = STREAMING_PUBLIC_KEY
        .parse::<iroha_crypto::PublicKey>()
        .expect("streaming public key");
    let (_, raw_public_key) = public_key.to_bytes();
    let authority = {
        let _chain =
            iroha_data_model::account::address::ChainDiscriminantGuard::enter(discriminant);
        iroha_data_model::account::AccountId::new(public_key.clone()).to_string()
    };
    let signer = sub_table(
        sub_table(sub_table(table, "soracloud_runtime"), "submission"),
        "signer",
    );
    for key in [
        "handle",
        "authority",
        "algorithm",
        "public_key_hex",
        "revision",
        "policy_digest_hex",
    ] {
        let placeholder = signer
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("signer.{key} is a template placeholder"));
        assert!(
            placeholder.starts_with("REPLACE_WITH_SORACLOUD_RUNTIME_SIGNER_"),
            "signer.{key} must stay an explicit deployment placeholder"
        );
    }
    signer.insert("handle".into(), SORACLOUD_SIGNER_HANDLE.into());
    signer.insert("authority".into(), authority.into());
    signer.insert("algorithm".into(), "ed25519".into());
    signer.insert("public_key_hex".into(), hex::encode(raw_public_key).into());
    signer.insert("revision".into(), Value::Integer(1));
    signer.insert("policy_digest_hex".into(), "a5".repeat(32).into());
}

/// Replace the `InRoU` trusted guest artifact placeholders with one well-formed pair.
///
/// The operator preseeds the real artifact; the digest and its content CID here only have the
/// canonical shapes (32 bytes of `0x31` and the matching CID).
fn bind_inrou_trusted_guest(table: &mut Table) {
    let inrou = sub_table(sub_table(table, "soracloud_runtime"), "inrou");
    for (key, value) in [
        ("trusted_guest_manifest_digest_hex", "31".repeat(32)),
        (
            "trusted_guest_content_cid",
            "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge".to_owned(),
        ),
    ] {
        let placeholder = inrou
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("inrou.{key} is a template placeholder"));
        assert!(
            placeholder.starts_with("REPLACE_WITH_INROU_TRUSTED_GUEST_"),
            "inrou.{key} must stay an explicit deployment placeholder"
        );
        inrou.insert(key.into(), value.into());
    }
}

fn parse(table: Table, sample: &str) -> ActualConfig {
    ConfigReader::new()
        .without_env()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .unwrap_or_else(|error| panic!("{sample} must match the configuration schema: {error:?}"))
        .parse()
        .unwrap_or_else(|error| panic!("{sample} must parse: {error:?}"))
}

#[test]
fn kagami_dev_profile_peer_configs_parse() {
    for index in 0..4 {
        let sample = format!("defaults/kagami/iroha3-dev/peer{index}.toml");
        let mut table = read_table(&sample);
        inline_expected_hash(&mut table);
        let config = parse(table, &sample);
        assert_eq!(
            config.sumeragi.role,
            iroha_config::parameters::actual::NodeRole::Validator,
            "{sample} is a validator"
        );
        assert!(
            config.sumeragi.local.is_empty(),
            "{sample} keeps §9.3 defaults"
        );
    }
}

#[test]
fn taira_validator_template_parses_once_runtime_secrets_are_bound() {
    const SAMPLE: &str = "configs/soranexus/taira/config.toml";
    let mut table = read_table(SAMPLE);
    // Bind the runtime-only secrets and placeholders the template leaves to deployment.
    table
        .remove("private_key_file")
        .expect("Taira reads the validator key from a runtime file");
    table.insert("private_key".into(), NODE_PRIVATE_KEY.into());
    table
        .remove("soranet_transport_private_key_file")
        .expect("Taira reads the transport key from a runtime file");
    table.insert(
        "soranet_transport_public_key".into(),
        TRANSPORT_PUBLIC_KEY.into(),
    );
    table.insert(
        "soranet_transport_private_key".into(),
        TRANSPORT_PRIVATE_KEY.into(),
    );
    let streaming = sub_table(&mut table, "streaming");
    streaming
        .remove("identity_private_key_file")
        .expect("Taira reads the streaming key from a runtime file");
    streaming.insert("identity_public_key".into(), STREAMING_PUBLIC_KEY.into());
    streaming.insert("identity_private_key".into(), STREAMING_PRIVATE_KEY.into());
    bind_soracloud_runtime_signer(&mut table);
    bind_inrou_trusted_guest(&mut table);
    inline_expected_hash(&mut table);
    // Every table of the full template, including the deployment-owned Torii custody tables,
    // must match the schema: a retired key anywhere is an unknown parameter here.
    ConfigReader::new()
        .with_toml_source(TomlSource::inline(table.clone()))
        .read_and_complete::<UserConfig>()
        .unwrap_or_else(|error| panic!("{SAMPLE} must match the configuration schema: {error:?}"));
    // The onboarding and faucet signers read owner-only key files that exist only on a
    // provisioned validator; parse the rest of the template without them.
    let torii = sub_table(&mut table, "torii");
    for custody in ["account_onboarding", "faucet"] {
        torii
            .remove(custody)
            .unwrap_or_else(|| panic!("Taira template declares `torii.{custody}`"));
    }
    let config = parse(table, SAMPLE);
    assert_eq!(
        config.sumeragi.role,
        iroha_config::parameters::actual::NodeRole::Validator
    );
    assert!(config.sumeragi.local.is_empty());
}
