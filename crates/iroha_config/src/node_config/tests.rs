//! Tests for node-file loading: profile layering, the per-node allowlist and `data_dir`.

use super::*;
use crate::parameters::actual::{self, NodeSecretFile};
use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair};
use iroha_data_model::account::AccountId;
use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

const VALIDATOR_PUBLIC: &str = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2";
const VALIDATOR_PRIVATE: &str =
    "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F";
const VALIDATOR_POP: &str = "8515da750f81182aaba5c22fc9f03a01e81ed85e4495a2ca6b29a71c0c8549537e31e79cddf6ff285b9e22d0d9dc17ce0f46e7d0cf78b2ef9feab50c849a1ea8e1e4f07e966f6113faa8a999317545d9f111b8e08a7273913710b43a20b19c08";
const TRANSPORT_PUBLIC: &str =
    "ed0120D9F6AEF1813164294D1D9C0662FEB9C7F7861B4DFFE385680331093DA4ABD10B";
const TRANSPORT_PRIVATE: &str =
    "802620134C4527B3852AE2218A8F079B301C651EAD8C7567B96BD7A9BE8DB366E46B89";
const STREAMING_PUBLIC: &str =
    "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB";
const STREAMING_PRIVATE: &str =
    "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F";
const GENESIS_PUBLIC: &str =
    "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB";
const EXPECTED_HASH: &str =
    "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E";

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

/// A node file and the predicate its load error must satisfy.
type ErrorCase = (String, fn(&NodeConfigError) -> bool);

/// An owner-only temporary node directory with the fixed secret files.
struct NodeDir {
    root: PathBuf,
}

impl NodeDir {
    fn new(label: &str) -> Self {
        let nonce = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "iroha_config_node_{label}_{}_{nonce}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("data/secrets/authority")).unwrap();
        let dir = Self { root };
        dir.secret(NodeSecretFile::Validator, VALIDATOR_PRIVATE);
        dir.secret(NodeSecretFile::Transport, TRANSPORT_PRIVATE);
        dir.secret(NodeSecretFile::Streaming, STREAMING_PRIVATE);
        dir
    }

    fn data_dir(&self) -> PathBuf {
        self.root.join("data")
    }

    fn secret(&self, file: NodeSecretFile, contents: &str) {
        let path = actual::DataDir::new(self.data_dir()).secret(file);
        fs::write(&path, format!("{contents}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for NodeDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn authority(seed: &[u8]) -> (KeyPair, String) {
    let key_pair = KeyPair::from_seed(seed.to_vec(), Algorithm::Ed25519);
    let account = AccountId::new(key_pair.public_key().clone())
        .to_i105_for_discriminant(369)
        .unwrap();
    (key_pair, account)
}

fn signer_table() -> String {
    let (key_pair, account) = authority(b"node-config-runtime-signer");
    let (_, public) = key_pair.public_key().to_bytes();
    let public_hex = hex::encode(public);
    format!(
        "[soracloud_runtime.submission.signer]\n\
         handle = \"software://taira/inrou/{public_hex}\"\n\
         authority = \"{account}\"\n\
         algorithm = \"ed25519\"\n\
         public_key_hex = \"{public_hex}\"\n\
         revision = 1\n\
         policy_digest_hex = \"{}\"\n",
        "11".repeat(32)
    )
}

/// A `sora-nexus-v1` node file: selectors, the data directory and the per-node keys.
fn profile_node(dir: &NodeDir, role: &str, extra: &str) -> String {
    let signer = if role == "validator" {
        signer_table()
    } else {
        String::new()
    };
    format!(
        "profile = \"sora-nexus-v1\"\n\
         role = \"{role}\"\n\
         validators = 4\n\
         chain = \"fc56984b-2be7-431d-840e-21514d1883f0\"\n\
         data_dir = \"{}\"\n\
         public_key = \"{VALIDATOR_PUBLIC}\"\n\
         trusted_peers_pop = [{{ public_key = \"{VALIDATOR_PUBLIC}\", pop_hex = \"{VALIDATOR_POP}\" }}]\n\
         {extra}\n\
         [network]\n\
         address = \"addr:127.0.0.1:1337#8F78\"\n\
         public_address = \"addr:127.0.0.1:1337#8F78\"\n\
         [torii]\n\
         address = \"addr:127.0.0.1:8080#8942\"\n\
         [genesis]\n\
         public_key = \"{GENESIS_PUBLIC}\"\n\
         expected_hash = \"{EXPECTED_HASH}\"\n\
         {signer}",
        dir.data_dir().display()
    )
}

fn open(path: &Path) -> Result<NodeConfigReader, Report<NodeConfigError>> {
    open_node_config(
        NodeFile::Path(path.to_path_buf()),
        NodeConfigOptions::default(),
    )
}

fn parse(path: &Path) -> (actual::Root, Option<ProfileBinding>) {
    let (user, binding) = open(path)
        .unwrap_or_else(|report| panic!("{report:?}"))
        .read()
        .unwrap_or_else(|report| panic!("{report:?}"));
    let actual = user.parse().unwrap_or_else(|report| panic!("{report:?}"));
    (actual, binding)
}

/// Drop a prepared reader that a test only inspected.
fn discard(reader: NodeConfigReader) {
    let (reader, _) = reader.into_parts();
    let _ = reader.into_result();
}

#[test]
fn profile_node_file_layers_the_profile_and_completes_data_dir() {
    for role in ["validator", "lane_validator", "observer"] {
        let dir = NodeDir::new("layers");
        let path = dir.write("config.toml", &profile_node(&dir, role, ""));
        let (config, binding) = parse(&path);
        let binding = binding.expect("profile binding");
        let profile = Profile::compiled(ProfileId::SoraNexusV1).unwrap();
        assert_eq!(binding.profile, ProfileId::SoraNexusV1);
        assert_eq!(binding.role.as_str(), role);
        assert_eq!(
            config.sumeragi.role,
            if role == "observer" {
                actual::NodeRole::Observer
            } else {
                actual::NodeRole::Validator
            }
        );
        assert_eq!(binding.roster_size, 4);
        assert_eq!(binding.geometry, profile.derive(4).unwrap());
        assert_eq!(
            binding.consensus_digest,
            profile.consensus_digest(4).unwrap()
        );
        assert_eq!(binding.policy_digest, profile.policy_digest().unwrap());

        // derive(4)
        assert_eq!(
            config
                .network
                .max_total_connections
                .map(std::num::NonZeroUsize::get),
            Some(19)
        );
        // static, policy and role overlay
        assert_eq!(config.nexus.lane_catalog.lane_count().get(), 4);
        assert_eq!(
            config.snapshot.create_every_ms.get(),
            std::time::Duration::from_millis(600_000)
        );
        assert_eq!(
            config.soracloud_runtime.production_mode,
            role == "validator"
        );
        assert_eq!(config.soracloud_runtime.inrou.max_cpu_millis.get(), 1_000);
        assert!(!config.soracloud_runtime.inrou.enabled);
        assert!(config.torii.faucet.is_none(), "unbound faucet template");
        assert!(!config.lifecycle.exit_on_stdin_close);
        // data_dir layout
        let data_dir = dir.data_dir();
        let state = data_dir.join("state");
        assert_eq!(
            config.data_dir.as_ref().map(actual::DataDir::root),
            Some(data_dir.as_path())
        );
        assert_eq!(
            config.kura.store_dir.resolve_relative_path(),
            state.join("kura")
        );
        assert_eq!(
            config.snapshot.store_dir.resolve_relative_path(),
            state.join("snapshot")
        );
        assert_eq!(config.torii.data_dir, state.join("torii"));
        assert_eq!(
            config.torii.da_ingest.manifest_store_dir,
            state.join("torii/da_manifests")
        );
        assert_eq!(
            config.soracloud_runtime.state_dir,
            state.join("soracloud_runtime")
        );
        assert_eq!(
            config.tiered_state.cold_store_root.as_deref(),
            Some(state.join("tiered_state").as_path())
        );
        assert_eq!(config.streaming.session_store_dir, state.join("streaming"));
        // secrets under <data_dir>/secrets, public halves derived
        assert_eq!(
            config.common.key_pair.public_key().to_string(),
            VALIDATOR_PUBLIC
        );
        assert_eq!(
            config
                .common
                .soranet_transport_key_pair
                .public_key()
                .to_string(),
            TRANSPORT_PUBLIC
        );
        assert_eq!(
            config
                .streaming
                .key_material
                .identity()
                .public_key()
                .to_string(),
            STREAMING_PUBLIC
        );
    }
}

#[test]
fn omitted_role_defaults_to_validator() {
    let dir = NodeDir::new("default_role");
    let explicit = profile_node(&dir, "validator", "");
    let path = dir.write(
        "config.toml",
        &explicit.replace("role = \"validator\"\n", ""),
    );
    let (config, binding) = parse(&path);
    assert_eq!(binding.unwrap().role, ProfileRole::Validator);
    assert_eq!(config.sumeragi.role, actual::NodeRole::Validator);
    assert!(config.soracloud_runtime.production_mode);
}

#[test]
fn every_profile_supplies_its_chain_discriminant() {
    for id in ProfileId::ALL {
        let dir = NodeDir::new("profile_discriminant");
        let contents = profile_node(&dir, "observer", "").replace("sora-nexus-v1", id.as_str());
        let path = dir.write("config.toml", &contents);
        let (config, binding) = parse(&path);
        let profile = Profile::compiled(id).unwrap();
        assert_eq!(binding.unwrap().profile, id);
        assert_eq!(
            *config.common.chain_discriminant.value(),
            profile.chain_discriminant(),
            "{id}"
        );
    }
}

#[test]
fn checked_in_node_example_parses_with_real_public_bindings() {
    let dir = NodeDir::new("example");
    let mut example = include_str!("../../../../configs/validator.example.toml").to_owned();
    let fixture: toml::Table = toml::from_str(&profile_node(&dir, "validator", "")).unwrap();
    let signer = &fixture["soracloud_runtime"]["submission"]["signer"];
    for (placeholder, value) in [
        ("CHAIN_ID", fixture["chain"].as_str().unwrap().to_owned()),
        ("VALIDATOR_PUBLIC_KEY", VALIDATOR_PUBLIC.to_owned()),
        ("SEED_PEER", format!("{VALIDATOR_PUBLIC}@127.0.0.1:1337")),
        ("SEED_PUBLIC_KEY", VALIDATOR_PUBLIC.to_owned()),
        ("SEED_POP", VALIDATOR_POP.to_owned()),
        ("PUBLIC_ADDRESS", "addr:127.0.0.1:1337#8F78".to_owned()),
        ("GENESIS_PUBLIC_KEY", GENESIS_PUBLIC.to_owned()),
        ("GENESIS_HASH", EXPECTED_HASH.to_owned()),
        (
            "SIGNER_HANDLE",
            signer["handle"].as_str().unwrap().to_owned(),
        ),
        (
            "SIGNER_AUTHORITY",
            signer["authority"].as_str().unwrap().to_owned(),
        ),
        (
            "SIGNER_PUBLIC_KEY_HEX",
            signer["public_key_hex"].as_str().unwrap().to_owned(),
        ),
        (
            "SIGNER_POLICY_DIGEST_HEX",
            signer["policy_digest_hex"].as_str().unwrap().to_owned(),
        ),
    ] {
        let placeholder = format!("REPLACE_WITH_{placeholder}");
        assert_eq!(example.matches(&placeholder).count(), 1, "{placeholder}");
        example = example.replace(&placeholder, &value);
    }
    assert!(!example.contains("REPLACE_WITH_"));
    let mut node: toml::Table = toml::from_str(&example).expect("example is valid TOML");
    assert_eq!(node["data_dir"].as_str(), Some("./node"));
    *node.get_mut("data_dir").unwrap() = fixture["data_dir"].clone();
    let path = dir.write("config.toml", &toml::to_string(&node).unwrap());
    let (config, binding) = parse(&path);
    assert_eq!(binding.unwrap().role, ProfileRole::Validator);
    assert_eq!(*config.common.chain_discriminant.value(), 369);
    assert!(config.soracloud_runtime.production_mode);
}

#[test]
fn selectors_reject_wrong_types_and_invalid_values_with_file_and_key() {
    let dir = NodeDir::new("invalid_selectors");
    let base: toml::Table = toml::from_str(&profile_node(&dir, "observer", "")).unwrap();
    for (key, values) in [
        (PROFILE_KEY, vec!["false", "7", "[]", "{}", "\"unknown\""]),
        (
            ROLE_KEY,
            vec!["false", "7", "[]", "{}", "\"voter\"", "\"Validator\""],
        ),
        (
            VALIDATORS_KEY,
            vec![
                "false", "\"4\"", "4.0", "[]", "{}", "-1", "0", "1", "5", "34",
            ],
        ),
    ] {
        for value in values {
            let mut node = base.clone();
            let replacement: toml::Table = toml::from_str(&format!("value = {value}")).unwrap();
            node.insert(key.to_owned(), replacement["value"].clone());
            let path = dir.write("config.toml", &toml::to_string(&node).unwrap());
            let error = open(&path).expect_err("invalid selectors must fail");
            match error.current_context() {
                NodeConfigError::ProfileKey {
                    path: origin,
                    key: invalid,
                    ..
                } => {
                    assert_eq!(origin, &path);
                    assert_eq!(*invalid, key, "{key} = {value}");
                }
                other => panic!("{key} = {value}: {other:?}"),
            }
            assert!(error.to_string().contains(&path.display().to_string()));
            assert!(error.to_string().contains(&format!("`{key}`")));
        }
    }
}

#[test]
fn retired_selectors_and_duplicate_role_or_network_identity_are_rejected() {
    let dir = NodeDir::new("retired_selectors");
    for (key, extra, advice) in [
        (
            "role_overlay",
            "role_overlay = \"observer\"",
            "top-level `role`",
        ),
        (
            "profile_roster_size",
            "profile_roster_size = 4",
            "set `validators`",
        ),
        (
            "chain_discriminant",
            "chain_discriminant = 369",
            "supplied by `profile`",
        ),
        (
            "sumeragi.role",
            "[sumeragi]\nrole = \"observer\"",
            "top-level `role`",
        ),
    ] {
        let path = dir.write("config.toml", &profile_node(&dir, "lane_validator", extra));
        let error = open(&path).expect_err("old and duplicate selectors must fail");
        match error.current_context() {
            NodeConfigError::ProfileKey {
                path: origin,
                key: invalid,
                message,
            } => {
                assert_eq!(origin, &path);
                assert_eq!(*invalid, key);
                assert!(message.contains(advice), "{message}");
            }
            other => panic!("{key}: {other:?}"),
        }
    }
    // Diagnose the retired key even when the required new count is absent.
    let old = profile_node(&dir, "observer", "")
        .replace("role =", "role_overlay =")
        .replace("validators =", "profile_roster_size =");
    let path = dir.write("old.toml", &old);
    assert!(matches!(
        open(&path).unwrap_err().current_context(),
        NodeConfigError::ProfileKey {
            key: "role_overlay",
            ..
        }
    ));
}

#[test]
fn node_file_overrides_tunables_but_not_network_policy() {
    let dir = NodeDir::new("override");
    let extra = "[torii.transport]\ntrusted_proxy_cidrs = [\"10.0.0.1/32\"]\n\
                 [logger]\nlevel = \"debug\"\n\
                 [lifecycle]\nexit_on_stdin_close = true\n";
    let path = dir.write("config.toml", &profile_node(&dir, "lane_validator", extra));
    let (config, _) = parse(&path);
    assert_eq!(config.torii.transport.trusted_proxy_cidrs, ["10.0.0.1/32"]);
    assert_eq!(config.sumeragi.role, actual::NodeRole::Validator);
    assert_eq!(config.logger.level.to_string().to_lowercase(), "debug");
    assert!(config.lifecycle.exit_on_stdin_close);

    for key in [
        "[sumeragi.keys]\nallowed_algorithms = [\"bls_normal\"]\n",
        "nexus = { lane_count = 1 }\n",
        "[kura]\nfsync_mode = \"strict\"\n",
    ] {
        let path = dir.write("static.toml", &profile_node(&dir, "observer", key));
        let error = open(&path).expect_err("static keys are not per-node");
        assert!(matches!(
            error.current_context(),
            NodeConfigError::KeysNotAllowed { .. }
        ));
    }
}

#[test]
fn disallowed_keys_are_reported_with_their_file() {
    let dir = NodeDir::new("allowlist");
    let extra = "private_key = \"x\"\n[kura]\nfsync_mode = \"strict\"\n\
                 [torii.faucet]\namount = \"1\"\n";
    let path = dir.write("config.toml", &profile_node(&dir, "observer", extra));
    let error = open(&path).expect_err("policy keys are not per-node");
    match error.current_context() {
        NodeConfigError::KeysNotAllowed {
            path: origin,
            profile,
            keys,
        } => {
            assert_eq!(origin, &path);
            assert_eq!(*profile, ProfileId::SoraNexusV1);
            let mut keys = keys.clone();
            keys.sort();
            assert_eq!(
                keys,
                ["kura.fsync_mode", "private_key", "torii.faucet.amount"]
            );
        }
        other => panic!("unexpected error {other:?}"),
    }
    let rendered = error.to_string();
    assert!(rendered.contains(&path.display().to_string()), "{rendered}");
    assert!(rendered.contains("`kura.fsync_mode`"), "{rendered}");
}

#[test]
fn selectors_and_profile_rules_are_enforced() {
    let dir = NodeDir::new("selectors");
    let base = profile_node(&dir, "observer", "");
    let cases: Vec<ErrorCase> = vec![
        (
            base.replace("\"sora-nexus-v1\"", "\"sora-nexus-v9\""),
            |error| matches!(error, NodeConfigError::ProfileKey { key: "profile", .. }),
        ),
        (
            base.replace("role = \"observer\"", "role = \"voter\""),
            |error| matches!(error, NodeConfigError::ProfileKey { key: "role", .. }),
        ),
        (base.replace("validators = 4\n", ""), |error| {
            matches!(
                error,
                NodeConfigError::ProfileKey {
                    key: "validators",
                    ..
                }
            )
        }),
        (base.replace("validators = 4", "validators = 5"), |error| {
            matches!(
                error,
                NodeConfigError::ProfileKey {
                    key: "validators",
                    ..
                }
            )
        }),
        (
            base.replace(
                &format!("data_dir = \"{}\"\n", dir.data_dir().display()),
                "",
            ),
            |error| matches!(error, NodeConfigError::MissingDataDir(_)),
        ),
        (format!("extends = \"base.toml\"\n{base}"), |error| {
            matches!(error, NodeConfigError::Extends(_))
        }),
    ];
    for (index, (contents, expected)) in cases.into_iter().enumerate() {
        let path = dir.write(&format!("case{index}.toml"), &contents);
        let error = open(&path).expect_err("invalid profile node file");
        assert!(expected(error.current_context()), "case {index}: {error:?}");
    }
    let path = dir.write("config.toml", &base);
    let (_, binding) = read_node_config(NodeFile::Path(path.clone()), NodeConfigOptions::default())
        .expect("the unmodified observer file reads");
    assert_eq!(
        binding.map(|binding| binding.role),
        Some(ProfileRole::Observer)
    );
    let error = open_node_config(
        NodeFile::Path(path.clone()),
        NodeConfigOptions { sora: true },
    )
    .expect_err("a profile node file must not run with --sora");
    assert_eq!(
        error.current_context(),
        &NodeConfigError::SoraWithProfile(path)
    );
}

#[test]
fn node_bound_sections_merge_with_the_profile_template() {
    let dir = NodeDir::new("merge");
    let (faucet_key, faucet) = authority(b"node-config-faucet");
    let (onboarding_key, onboarding) = authority(b"node-config-onboarding");
    dir.secret(
        NodeSecretFile::FaucetAuthority,
        &ExposedPrivateKey(faucet_key.private_key().clone()).to_string(),
    );
    dir.secret(
        NodeSecretFile::OnboardingAuthority,
        &ExposedPrivateKey(onboarding_key.private_key().clone()).to_string(),
    );
    let extra = format!(
        "[torii.faucet]\nauthority = \"{faucet}\"\n\
         [torii.account_onboarding]\nauthority = \"{onboarding}\"\n\
         credentials = [{{ id = \"inori-app\", scope = {{ dataspace = \"universal\" }}, token_hash = \"blake3:{}\" }}]\n\
         [soracloud_runtime.inrou]\nenabled = false\n",
        "ab".repeat(32)
    );
    let path = dir.write("config.toml", &profile_node(&dir, "validator", &extra));
    let (config, _) = parse(&path);
    let faucet_config = config.torii.faucet.as_ref().expect("bound faucet");
    assert_eq!(
        faucet_config
            .authority
            .to_i105_for_discriminant(369)
            .unwrap(),
        faucet
    );
    assert_eq!(faucet_config.pow_difficulty_bits.get(), 8, "template value");
    let onboarding_config = config
        .torii
        .account_onboarding
        .as_ref()
        .expect("bound onboarding");
    assert_eq!(
        onboarding_config
            .authority
            .to_i105_for_discriminant(369)
            .unwrap(),
        onboarding
    );
    assert_eq!(config.soracloud_runtime.inrou.max_cpu_millis.get(), 1_000);
    assert!(config.soracloud_runtime.submission.signer.is_some());
}

#[test]
fn flat_files_load_exactly_as_before() {
    let dir = NodeDir::new("flat");
    let flat = format!(
        "chain = \"0\"\n\
         public_key = \"{VALIDATOR_PUBLIC}\"\n\
         private_key = \"{VALIDATOR_PRIVATE}\"\n\
         soranet_transport_public_key = \"{TRANSPORT_PUBLIC}\"\n\
         soranet_transport_private_key = \"{TRANSPORT_PRIVATE}\"\n\
         trusted_peers_pop = [{{ public_key = \"{VALIDATOR_PUBLIC}\", pop_hex = \"{VALIDATOR_POP}\" }}]\n\
         [streaming]\nidentity_public_key = \"{STREAMING_PUBLIC}\"\nidentity_private_key = \"{STREAMING_PRIVATE}\"\n\
         [network]\naddress = \"addr:127.0.0.1:1337#8F78\"\npublic_address = \"addr:127.0.0.1:1337#8F78\"\n\
         [torii]\naddress = \"addr:127.0.0.1:8080#8942\"\n\
         [genesis]\npublic_key = \"{GENESIS_PUBLIC}\"\nexpected_hash = \"{EXPECTED_HASH}\"\n"
    );
    let path = dir.write("flat.toml", &flat);
    let reader = open(&path).unwrap();
    assert!(reader.profile().is_none());
    assert_eq!(reader.reader().toml_sources().len(), 1);
    discard(reader);
    let (config, binding) = parse(&path);
    assert!(binding.is_none());
    assert!(config.data_dir.is_none());
    assert_eq!(
        config.kura.store_dir.resolve_relative_path(),
        PathBuf::from("./storage")
    );
    // The same file through a plain reader parses to the same layout.
    let plain = ConfigReader::new()
        .without_env()
        .read_toml_with_extends(&path)
        .unwrap()
        .read_and_complete::<user::Root>()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        plain.kura.store_dir.resolve_relative_path(),
        PathBuf::from("./storage")
    );
    assert_eq!(plain.torii.data_dir, config.torii.data_dir);

    // A self-contained verified table behaves the same, and rejects `extends`.
    let table: toml::Table = toml::from_str(&flat).unwrap();
    let verified = open_node_config(
        NodeFile::Verified {
            path: path.clone(),
            table: table.clone(),
        },
        NodeConfigOptions::default(),
    )
    .unwrap();
    assert!(verified.profile().is_none());
    discard(verified);
    let mut extended = table;
    extended.insert("extends".into(), toml::Value::String("x.toml".into()));
    let error = open_node_config(
        NodeFile::Verified {
            path: path.clone(),
            table: extended,
        },
        NodeConfigOptions::default(),
    )
    .expect_err("verified tables are self-contained");
    assert_eq!(error.current_context(), &NodeConfigError::Extends(path));
}

#[test]
fn flat_data_dir_derives_paths_and_keeps_explicit_overrides() {
    let dir = NodeDir::new("flat_data_dir");
    let flat = format!(
        "chain = \"0\"\n\
         data_dir = \"data\"\n\
         public_key = \"{VALIDATOR_PUBLIC}\"\n\
         private_key = \"{VALIDATOR_PRIVATE}\"\n\
         trusted_peers_pop = [{{ public_key = \"{VALIDATOR_PUBLIC}\", pop_hex = \"{VALIDATOR_POP}\" }}]\n\
         [kura]\nstore_dir = \"/explicit/kura\"\n\
         [network]\naddress = \"addr:127.0.0.1:1337#8F78\"\npublic_address = \"addr:127.0.0.1:1337#8F78\"\n\
         [torii]\naddress = \"addr:127.0.0.1:8080#8942\"\n\
         [genesis]\npublic_key = \"{GENESIS_PUBLIC}\"\nexpected_hash = \"{EXPECTED_HASH}\"\n"
    );
    let path = dir.write("flat.toml", &flat);
    let reader = open(&path).unwrap();
    // Inline `private_key` suppresses the derived validator key file.
    assert!(
        !reader
            .reader()
            .contains_toml_parameter(["private_key_file"])
    );
    assert!(
        reader
            .reader()
            .contains_toml_parameter(["soranet_transport_private_key_file"])
    );
    discard(reader);
    let (config, _) = parse(&path);
    // A relative data_dir resolves against the file that sets it.
    let data_dir = dir.root.join("data");
    let state = data_dir.join("state");
    assert_eq!(
        config.data_dir.as_ref().map(actual::DataDir::root),
        Some(data_dir.as_path())
    );
    assert_eq!(
        config.kura.store_dir.resolve_relative_path(),
        PathBuf::from("/explicit/kura")
    );
    assert_eq!(config.torii.data_dir, state.join("torii"));
    assert_eq!(config.torii.sorafs_storage.data_dir, state.join("sorafs"));
    assert_eq!(config.torii.sorafs_por.state_dir, state.join("sorafs/por"));
    assert_eq!(
        config
            .network
            .soranet_handshake
            .pow
            .revocation_store_path
            .as_ref(),
        state
            .join("soranet/ticket_revocations.norito")
            .to_string_lossy()
    );
    assert_eq!(
        config
            .common
            .soranet_transport_key_pair
            .public_key()
            .to_string(),
        TRANSPORT_PUBLIC
    );
}

#[test]
fn data_dir_outside_the_loader_is_rejected() {
    let dir = NodeDir::new("bypass");
    let flat = format!(
        "chain = \"0\"\n\
         data_dir = \"data\"\n\
         public_key = \"{VALIDATOR_PUBLIC}\"\n\
         private_key = \"{VALIDATOR_PRIVATE}\"\n\
         soranet_transport_private_key = \"{TRANSPORT_PRIVATE}\"\n\
         [network]\naddress = \"addr:127.0.0.1:1337#8F78\"\npublic_address = \"addr:127.0.0.1:1337#8F78\"\n\
         [torii]\naddress = \"addr:127.0.0.1:8080#8942\"\n\
         [genesis]\npublic_key = \"{GENESIS_PUBLIC}\"\nexpected_hash = \"{EXPECTED_HASH}\"\n"
    );
    let path = dir.write("flat.toml", &flat);
    let error = ConfigReader::new()
        .without_env()
        .read_toml_with_extends(&path)
        .unwrap()
        .read_and_complete::<user::Root>()
        .unwrap()
        .parse()
        .expect_err("an uncompleted data_dir must not be ignored");
    assert!(format!("{error:?}").contains("iroha_config::node_config"));
    assert!(format!("{error:?}").contains("Invalid node data directory"));
    // An explicit store directory does not make an uncompleted data_dir acceptable: the other
    // state and secret paths would still keep their defaults.
    let path = dir.write(
        "explicit_store.toml",
        &format!("{flat}[kura]\nstore_dir = \"/explicit/kura\"\n"),
    );
    let error = ConfigReader::new()
        .without_env()
        .read_toml_with_extends(&path)
        .unwrap()
        .read_and_complete::<user::Root>()
        .unwrap()
        .parse()
        .expect_err("a raw reader never completes data_dir");
    assert!(format!("{error:?}").contains("Invalid node data directory"));
    let path = dir.write(
        "empty.toml",
        &flat.replace("data_dir = \"data\"", "data_dir = \"\""),
    );
    let error = open(&path).expect_err("an empty data_dir is invalid");
    assert_eq!(
        error.current_context(),
        &NodeConfigError::InvalidDataDir(path)
    );
}

#[test]
fn merge_value_tables_merges_into_the_last_contributor() {
    let layer = |text: &str| TomlSource::inline(toml::from_str(text).unwrap());
    let mut sources = vec![
        layer(
            "[soracloud_runtime.inrou]\nmax_cpu_millis = 1\nstart_grace_ms = 2\n[torii.faucet]\namount = \"1\"\n",
        ),
        layer("[soracloud_runtime.inrou]\nstart_grace_ms = 3\n"),
        layer("[soracloud_runtime.inrou]\nenabled = true\n"),
    ];
    merge_value_tables(&mut sources);
    assert!(table_at(sources[0].table(), &["soracloud_runtime", "inrou"]).is_none());
    assert!(table_at(sources[1].table(), &["soracloud_runtime", "inrou"]).is_none());
    let merged: toml::Table =
        toml::from_str("max_cpu_millis = 1\nstart_grace_ms = 3\nenabled = true\n").unwrap();
    assert_eq!(
        table_at(sources[2].table(), &["soracloud_runtime", "inrou"]),
        Some(&merged)
    );
    // The node file (last source) does not bind the faucet, so the template is dropped.
    assert!(
        sources
            .iter()
            .all(|source| table_at(source.table(), &["torii", "faucet"]).is_none())
    );
}

#[test]
fn table_path_helpers_navigate_create_and_remove() {
    let mut table = toml::Table::new();
    insert_at(&mut table, &["a", "b", "c"], toml::Value::Integer(1));
    insert_at(&mut table, &["a", "d"], toml::Value::Integer(2));
    assert_eq!(
        table_at(&table, &["a", "b"])
            .and_then(|b| b.get("c"))
            .and_then(toml::Value::as_integer),
        Some(1)
    );
    table_at_mut(&mut table, &["a"])
        .unwrap()
        .insert("e".into(), toml::Value::Integer(3));
    assert!(remove_at(&mut table, &["a", "d"]).is_none(), "not a table");
    let removed = remove_at(&mut table, &["a", "b"]).unwrap();
    assert_eq!(removed.get("c").and_then(toml::Value::as_integer), Some(1));
    assert!(table_at(&table, &["a", "b"]).is_none());
    assert!(table_at(&table, &["missing"]).is_none());
}

/// The value of `key` in the last source that sets it, as the loader completed it.
fn completed_value(reader: &NodeConfigReader, key: &[&str]) -> String {
    let id = ParameterId::from(key);
    reader
        .reader()
        .toml_sources()
        .iter()
        .rev()
        .find_map(|source| source.fetch(&id))
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| panic!("{key:?} was not completed"))
}

#[test]
fn profile_nodes_reject_removed_publisher_configuration() {
    for id in ProfileId::ALL {
        for (key, value) in [
            ("keyring_file", "\"authorizer.norito\""),
            ("submitter_key_file", "\"submitter.key\""),
            ("enabled", "false"),
            ("enabled", "true"),
            ("keyring", "\"inline-custody\""),
            ("submitter_key", "\"inline-custody\""),
            ("page_size", "1"),
            ("keyring_file.inline", "\"inline-custody\""),
        ] {
            let table = toml::from_str(&format!(
                "profile = \"{id}\"\nvalidators = 4\ndata_dir = \"data\"\n[kagemusha_load_authorizer]\n{key} = {value}\n"
            ))
            .unwrap();
            let error = open_node_config(
                NodeFile::Verified {
                    path: PathBuf::from("publisher-refusal.toml"),
                    table,
                },
                NodeConfigOptions::default(),
            )
            .unwrap_err();
            assert!(matches!(
                error.current_context(),
                NodeConfigError::KeysNotAllowed { keys, .. }
                    if keys == &vec![format!("kagemusha_load_authorizer.{key}")]
            ));
        }
    }
}

/// `iroha3d --config cfg/node.toml` with `data_dir = "data"`: the configuration path is relative
/// to the working directory and `data_dir` to the file. Every completed state and secret path,
/// and `data_dir` itself, must be the same absolute path however the file was named.
#[test]
fn relative_config_and_data_dir_paths_complete_absolute_paths() {
    let cwd = std::env::current_dir().unwrap();
    let flat = |data_dir: &str| -> toml::Table {
        toml::from_str(&format!(
            "chain = \"0\"\n\
             data_dir = \"{data_dir}\"\n\
             public_key = \"{VALIDATOR_PUBLIC}\"\n\
             private_key = \"{VALIDATOR_PRIVATE}\"\n\
             soranet_transport_private_key = \"{TRANSPORT_PRIVATE}\"\n\
             trusted_peers_pop = [{{ public_key = \"{VALIDATOR_PUBLIC}\", pop_hex = \"{VALIDATOR_POP}\" }}]\n\
             [streaming]\nidentity_private_key = \"{STREAMING_PRIVATE}\"\n\
             [network]\naddress = \"addr:127.0.0.1:1337#8F78\"\npublic_address = \"addr:127.0.0.1:1337#8F78\"\n\
             [torii]\naddress = \"addr:127.0.0.1:8080#8942\"\n\
             [genesis]\npublic_key = \"{GENESIS_PUBLIC}\"\nexpected_hash = \"{EXPECTED_HASH}\"\n"
        ))
        .unwrap()
    };
    for (config_path, data_dir, expected) in [
        ("cfg/node.toml", "data", cwd.join("cfg/data")),
        ("node2.toml", "./data", cwd.join("data")),
        ("cfg/sub/node.toml", "../data", cwd.join("cfg/data")),
        (
            "cfg/node.toml",
            "/tmp/abs-data",
            PathBuf::from("/tmp/abs-data"),
        ),
    ] {
        let reader = open_node_config(
            NodeFile::Verified {
                path: PathBuf::from(config_path),
                table: flat(data_dir),
            },
            NodeConfigOptions::default(),
        )
        .unwrap();
        assert_eq!(reader.data_dir(), Some(expected.as_path()), "{config_path}");
        let (user, _) = reader.read().unwrap_or_else(|report| panic!("{report:?}"));
        let config = user.parse().unwrap_or_else(|report| panic!("{report:?}"));
        let state = expected.join("state");
        assert_eq!(
            config.data_dir.as_ref().map(actual::DataDir::root),
            Some(expected.as_path()),
            "{config_path}"
        );
        assert_eq!(
            config.kura.store_dir.resolve_relative_path(),
            state.join("kura")
        );
        assert_eq!(
            config.snapshot.store_dir.resolve_relative_path(),
            state.join("snapshot")
        );
        assert_eq!(config.torii.data_dir, state.join("torii"));
        assert_eq!(config.torii.sorafs_storage.data_dir, state.join("sorafs"));
    }

    // A profile node file named by a relative path: the completions land in profile layers
    // (`[kura]` comes from the policy layer) and in the loader's own source, and all of them are
    // absolute, including the secret files the parser opens.
    let dir = NodeDir::new("relative_profile");
    let node = profile_node(&dir, "observer", "").replace(
        &format!("data_dir = \"{}\"", dir.data_dir().display()),
        "data_dir = \"data\"",
    );
    let reader = open_node_config(
        NodeFile::Verified {
            path: PathBuf::from("node.toml"),
            table: toml::from_str(&node).unwrap(),
        },
        NodeConfigOptions::default(),
    )
    .unwrap();
    let expected = cwd.join("data");
    assert_eq!(reader.data_dir(), Some(expected.as_path()));
    assert_eq!(
        completed_value(&reader, &["kura", "store_dir"]),
        expected.join("state/kura").to_string_lossy()
    );
    assert_eq!(
        completed_value(&reader, &["private_key_file"]),
        expected.join("secrets/validator.key").to_string_lossy()
    );
    assert_eq!(
        completed_value(&reader, &["data_dir"]),
        expected.to_string_lossy()
    );
    discard(reader);
}

#[test]
fn absolute_lexical_resolves_against_the_working_directory() {
    let cwd = std::env::current_dir().unwrap();
    assert_eq!(absolute_lexical(Path::new("a/./b")), Some(cwd.join("a/b")));
    assert_eq!(absolute_lexical(Path::new("a/../b")), Some(cwd.join("b")));
    assert_eq!(
        absolute_lexical(Path::new("/x/y/../../../z")),
        Some(PathBuf::from("/z"))
    );
    assert_eq!(absolute_lexical(Path::new("")), None);
}

#[test]
fn resolve_data_dir_uses_the_last_source_that_sets_it() {
    let reader = ConfigReader::new()
        .without_env()
        .with_toml_source(TomlSource::new(
            PathBuf::from("/etc/iroha/base.toml"),
            toml::from_str("data_dir = \"/var/lib/a\"").unwrap(),
        ))
        .with_toml_source(TomlSource::new(
            PathBuf::from("/etc/iroha/node.toml"),
            toml::from_str("data_dir = \"b\"").unwrap(),
        ));
    assert_eq!(
        resolve_data_dir(&reader).unwrap().unwrap(),
        PathBuf::from("/etc/iroha/b")
    );
    let _ = reader.into_result();
    let reader = ConfigReader::new()
        .without_env()
        .with_toml_source(TomlSource::new(
            PathBuf::from("cfg/node.toml"),
            toml::from_str("data_dir = \"data\"").unwrap(),
        ));
    assert_eq!(
        resolve_data_dir(&reader).unwrap().unwrap(),
        std::env::current_dir().unwrap().join("cfg/data")
    );
    let _ = reader.into_result();
    let reader = ConfigReader::new().without_env();
    assert!(resolve_data_dir(&reader).is_none());
    let _ = reader.into_result();
}

thread_local! {
    static SENSITIVE_NODE_SOURCE_SCRUBS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

fn scrub_sensitive_node_test_table(table: &mut toml::Table) {
    fn scrub_value(value: &mut toml::Value) {
        use zeroize::Zeroize as _;

        match value {
            toml::Value::String(value) => value.zeroize(),
            toml::Value::Array(values) => values.iter_mut().for_each(scrub_value),
            toml::Value::Table(table) => {
                for (_, value) in table.iter_mut() {
                    scrub_value(value);
                }
            }
            toml::Value::Integer(_)
            | toml::Value::Float(_)
            | toml::Value::Boolean(_)
            | toml::Value::Datetime(_) => {}
        }
    }

    SENSITIVE_NODE_SOURCE_SCRUBS.with(|count| count.set(count.get().saturating_add(1)));
    for (_, value) in table.iter_mut() {
        scrub_value(value);
    }
}

fn sensitive_node_scrubs() -> u32 {
    SENSITIVE_NODE_SOURCE_SCRUBS.with(std::cell::Cell::get)
}

fn sensitive_flat_node() -> toml::Table {
    toml::from_str(&format!(
        "chain = \"0\"\n\
         data_dir = \"data\"\n\
         public_key = \"{VALIDATOR_PUBLIC}\"\n\
         private_key = \"{VALIDATOR_PRIVATE}\"\n\
         soranet_transport_public_key = \"{TRANSPORT_PUBLIC}\"\n\
         soranet_transport_private_key = \"{TRANSPORT_PRIVATE}\"\n\
         trusted_peers_pop = [{{ public_key = \"{VALIDATOR_PUBLIC}\", pop_hex = \"{VALIDATOR_POP}\" }}]\n\
         [streaming]\nidentity_public_key = \"{STREAMING_PUBLIC}\"\nidentity_private_key = \"{STREAMING_PRIVATE}\"\n\
         [network]\naddress = \"addr:127.0.0.1:1337#8F78\"\npublic_address = \"addr:127.0.0.1:1337#8F78\"\n\
         [torii]\naddress = \"addr:127.0.0.1:8080#8942\"\n\
         [genesis]\npublic_key = \"{GENESIS_PUBLIC}\"\nexpected_hash = \"{EXPECTED_HASH}\"\n"
    ))
    .unwrap()
}

#[test]
fn retained_sensitive_flat_source_keeps_scrubber_and_absolute_layout() {
    SENSITIVE_NODE_SOURCE_SCRUBS.with(|count| count.set(0));
    let dir = NodeDir::new("sensitive_flat");
    let path = dir.root.join("node.toml");
    let source = TomlSource::new_sensitive(
        path.clone(),
        sensitive_flat_node(),
        scrub_sensitive_node_test_table,
    );
    assert!(!format!("{source:?}").contains(VALIDATOR_PRIVATE));
    let clone = source.clone();
    drop(clone);
    assert_eq!(sensitive_node_scrubs(), 1);
    let reader = open_node_config_source(source, NodeConfigOptions::default()).unwrap();
    assert!(reader.profile().is_none());
    assert_eq!(reader.data_dir(), Some(dir.data_dir().as_path()));
    assert!(!format!("{reader:?}").contains(VALIDATOR_PRIVATE));
    assert!(
        reader
            .reader()
            .toml_sources()
            .iter()
            .any(|source| source.path() == &path)
    );
    assert_eq!(sensitive_node_scrubs(), 1);
    let (user, binding) = reader.read().unwrap();
    assert_eq!(sensitive_node_scrubs(), 2);
    assert!(binding.is_none());
    let config = user.parse().unwrap();
    assert_eq!(
        config.common.key_pair.public_key().to_string(),
        VALIDATOR_PUBLIC
    );
    assert_eq!(config.data_dir.as_ref().unwrap().root(), dir.data_dir());
    assert_eq!(config.torii.data_dir, dir.data_dir().join("state/torii"));
    assert_eq!(
        iroha_data_model::NetworkId::from_genesis_hash(config.genesis.expected_hash),
        EXPECTED_HASH
            .parse::<iroha_data_model::NetworkId>()
            .unwrap()
    );
}

#[test]
fn retained_sensitive_profile_source_keeps_scrubber_and_original_layer() {
    SENSITIVE_NODE_SOURCE_SCRUBS.with(|count| count.set(0));
    let dir = NodeDir::new("sensitive_profile");
    let path = dir.root.join("profile.toml");
    let table = toml::from_str(&profile_node(&dir, "validator", "")).unwrap();
    let source = TomlSource::new_sensitive(path.clone(), table, scrub_sensitive_node_test_table);
    let reader = open_node_config_source(source, NodeConfigOptions::default()).unwrap();
    assert_eq!(reader.profile().unwrap().profile, ProfileId::SoraNexusV1);
    assert_eq!(reader.data_dir(), Some(dir.data_dir().as_path()));
    let retained = reader
        .reader()
        .toml_sources()
        .iter()
        .find(|source| source.path() == &path)
        .unwrap();
    assert!(retained.table().get(PROFILE_KEY).is_none());
    assert!(retained.table().get(ROLE_KEY).is_none());
    assert!(retained.table().get(VALIDATORS_KEY).is_none());
    assert!(
        retained
            .fetch(&ParameterId::from([
                "soracloud_runtime",
                "submission",
                "signer",
                "handle"
            ]))
            .is_some()
    );
    let clone = retained.clone();
    assert!(!format!("{clone:?}").contains("software://taira/inrou/"));
    drop(clone);
    assert_eq!(sensitive_node_scrubs(), 1);
    let (user, binding) = reader.read().unwrap();
    assert_eq!(sensitive_node_scrubs(), 2);
    assert_eq!(binding.unwrap().roster_size, 4);
    let config = user.parse().unwrap();
    assert_eq!(
        config.common.key_pair.public_key().to_string(),
        VALIDATOR_PUBLIC
    );
    assert_eq!(config.nexus.lane_catalog.lane_count().get(), 4);
    assert!(config.soracloud_runtime.submission.signer.is_some());
    assert_eq!(
        iroha_data_model::NetworkId::from_genesis_hash(config.genesis.expected_hash),
        EXPECTED_HASH
            .parse::<iroha_data_model::NetworkId>()
            .unwrap()
    );
}

#[test]
fn retained_sensitive_source_scrubs_on_layout_and_profile_refusals() {
    let cases = [
        ("extends = \"original.toml\"", NodeConfigOptions::default()),
        (
            "profile = \"sora-nexus-v1\"\nextends = \"original.toml\"",
            NodeConfigOptions::default(),
        ),
        ("data_dir = \"\"", NodeConfigOptions::default()),
        (
            "profile = \"sora-nexus-v1\"",
            NodeConfigOptions { sora: true },
        ),
        (
            "profile = \"sora-nexus-v1\"\nvalidators = 4\ndata_dir = \"data\"\n[private_forbidden]\nkey = \"do-not-log\"",
            NodeConfigOptions::default(),
        ),
    ];
    for (input, options) in cases {
        SENSITIVE_NODE_SOURCE_SCRUBS.with(|count| count.set(0));
        let source = TomlSource::new_sensitive(
            PathBuf::from("sensitive-refusal.toml"),
            toml::from_str(input).unwrap(),
            scrub_sensitive_node_test_table,
        );
        let error = open_node_config_source(source, options).unwrap_err();
        assert_eq!(sensitive_node_scrubs(), 1);
        assert!(matches!(
            error.current_context(),
            NodeConfigError::Extends(_)
                | NodeConfigError::InvalidDataDir(_)
                | NodeConfigError::SoraWithProfile(_)
                | NodeConfigError::KeysNotAllowed { .. }
        ));
        assert!(!format!("{error:?}").contains("do-not-log"));
    }
}

#[test]
fn retained_sensitive_source_scrubs_when_layered_read_is_refused() {
    SENSITIVE_NODE_SOURCE_SCRUBS.with(|count| count.set(0));
    let source = TomlSource::new_sensitive(
        PathBuf::from("missing-fields.toml"),
        toml::from_str("private_key = \"do-not-log\"").unwrap(),
        scrub_sensitive_node_test_table,
    );
    let reader = open_node_config_source(source, NodeConfigOptions::default()).unwrap();
    assert_eq!(sensitive_node_scrubs(), 0);
    let error = reader.read().unwrap_err();
    assert!(matches!(error.current_context(), NodeConfigError::Read));
    assert_eq!(sensitive_node_scrubs(), 1);
}

#[test]
fn merged_sensitive_node_table_moves_original_string_backing() {
    SENSITIVE_NODE_SOURCE_SCRUBS.with(|count| count.set(0));
    let mut sources = vec![
        TomlSource::inline(
            toml::from_str("[soracloud_runtime.submission]\nworker_threads = 1").unwrap(),
        ),
        TomlSource::new_sensitive(
            PathBuf::from("sensitive-node.toml"),
            toml::from_str(
                "[soracloud_runtime.submission.signer]\nhandle = \"software://owner/do-not-log\"",
            )
            .unwrap(),
            scrub_sensitive_node_test_table,
        ),
    ];
    let handle = ParameterId::from(["soracloud_runtime", "submission", "signer", "handle"]);
    let original = sources[1]
        .fetch(&handle)
        .unwrap()
        .as_str()
        .unwrap()
        .as_ptr();
    merge_value_tables(&mut sources);
    assert_eq!(
        sources[1]
            .fetch(&handle)
            .unwrap()
            .as_str()
            .unwrap()
            .as_ptr(),
        original
    );
    assert!(sources[0].fetch(&handle).is_none());
    assert_eq!(
        sources[1]
            .fetch(&ParameterId::from([
                "soracloud_runtime",
                "submission",
                "worker_threads"
            ]))
            .unwrap()
            .as_integer(),
        Some(1)
    );
    assert_eq!(sensitive_node_scrubs(), 0);
    assert!(!format!("{:?}", sources[1]).contains("software://owner/do-not-log"));
    drop(sources);
    assert_eq!(sensitive_node_scrubs(), 1);
}
