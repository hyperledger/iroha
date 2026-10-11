//! Profile node files, `data_dir` node secrets and `lifecycle.exit_on_stdin_close` through the
//! daemon's own configuration path.

use super::*;
use iroha_config::parameters::actual::{DataDir, NodeSecretFile, node_runtime_signer};
use iroha_crypto::{ExposedPrivateKey, KeyPair};
use std::os::unix::fs::PermissionsExt as _;

const VALIDATOR_PUBLIC: &str = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2";
const VALIDATOR_PRIVATE: &str =
    "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F";
const VALIDATOR_POP: &str = "8515da750f81182aaba5c22fc9f03a01e81ed85e4495a2ca6b29a71c0c8549537e31e79cddf6ff285b9e22d0d9dc17ce0f46e7d0cf78b2ef9feab50c849a1ea8e1e4f07e966f6113faa8a999317545d9f111b8e08a7273913710b43a20b19c08";
const TRANSPORT_PRIVATE: &str =
    "802620134C4527B3852AE2218A8F079B301C651EAD8C7567B96BD7A9BE8DB366E46B89";
const STREAMING_PRIVATE: &str =
    "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F";
const GENESIS_PUBLIC: &str =
    "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB";
const EXPECTED_HASH: &str =
    "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E";

/// A validator node directory below the checkout (trusted ancestors).
struct ProfileNode {
    root: tempfile::TempDir,
    data_dir: DataDir,
    signer: KeyPair,
    profile: &'static str,
    chain_discriminant: u16,
}

impl ProfileNode {
    /// An `iroha-dev-v1` node. Its I105 discriminant is the process default, so reading it
    /// through the daemon (which installs the discriminant process-wide) cannot disturb
    /// concurrently running tests.
    fn new() -> Self {
        Self::with_profile("iroha-dev-v1", 753)
    }

    fn with_profile(profile: &'static str, chain_discriminant: u16) -> Self {
        let root = tempfile::Builder::new()
            .prefix(".irohad-profile-node-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("node directory");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        let data_dir = DataDir::new(root.path().join("data"));
        for directory in [
            data_dir.root().to_path_buf(),
            data_dir.secrets_dir(),
            data_dir.secrets_dir().join("authority"),
        ] {
            fs::create_dir(&directory).expect("create directory");
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        let node = Self {
            root,
            data_dir,
            signer: KeyPair::from_seed(vec![0x5E; 32], Algorithm::Ed25519),
            profile,
            chain_discriminant,
        };
        node.secret(
            NodeSecretFile::Validator,
            format!("{VALIDATOR_PRIVATE}\n").as_bytes(),
        );
        node.secret(
            NodeSecretFile::Transport,
            format!("{TRANSPORT_PRIVATE}\n").as_bytes(),
        );
        node.secret(
            NodeSecretFile::Streaming,
            format!("{STREAMING_PRIVATE}\n").as_bytes(),
        );
        let literal = ExposedPrivateKey(node.signer.private_key().clone())
            .try_to_multihash_string()
            .expect("canonical signer key");
        node.secret(
            NodeSecretFile::RuntimeSigner,
            format!("{literal}\n").as_bytes(),
        );
        node
    }

    fn secret(&self, file: NodeSecretFile, bytes: &[u8]) {
        let path = self.data_dir.secret(file);
        fs::write(&path, bytes).expect("write secret");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("owner-only");
    }

    /// Write the node file and return its path and BLAKE3.
    fn node_file(&self) -> (PathBuf, String) {
        let (_, public) = self.signer.public_key().to_bytes();
        let public_hex = hex::encode(public);
        let authority = AccountId::new(self.signer.public_key().clone())
            .to_i105_for_discriminant(self.chain_discriminant)
            .expect("I105 authority");
        let contents = format!(
            "profile = \"{profile}\"\n\
             role = \"validator\"\n\
             validators = 4\n\
             chain = \"fc56984b-2be7-431d-840e-21514d1883f0\"\n\
             data_dir = \"{data_dir}\"\n\
             public_key = \"{VALIDATOR_PUBLIC}\"\n\
             trusted_peers_pop = [{{ public_key = \"{VALIDATOR_PUBLIC}\", pop_hex = \"{VALIDATOR_POP}\" }}]\n\
             [network]\n\
             address = \"addr:127.0.0.1:1337#8F78\"\n\
             public_address = \"addr:127.0.0.1:1337#8F78\"\n\
             [torii]\n\
             address = \"addr:127.0.0.1:8080#8942\"\n\
             [genesis]\n\
             public_key = \"{GENESIS_PUBLIC}\"\n\
             expected_hash = \"{EXPECTED_HASH}\"\n\
             [lifecycle]\n\
             exit_on_stdin_close = true\n\
             [soracloud_runtime.submission.signer]\n\
             handle = \"{handle}\"\n\
             authority = \"{authority}\"\n\
             algorithm = \"ed25519\"\n\
             public_key_hex = \"{public_hex}\"\n\
             revision = {revision}\n\
             policy_digest_hex = \"{policy}\"\n",
            profile = self.profile,
            data_dir = self.data_dir.root().display(),
            handle =
                node_runtime_signer::handle_v1(self.signer.public_key()).expect("Ed25519 handle"),
            revision = node_runtime_signer::REVISION_V1,
            policy = hex::encode(node_runtime_signer::policy_digest_v1()),
        );
        let path = self.root.path().join("config.toml");
        fs::write(&path, &contents).expect("write node file");
        (path, blake3::hash(contents.as_bytes()).to_hex().to_string())
    }
}

fn read_with_fixture_space(
    args: &Args,
) -> ReportResult<(Config, Option<GenesisBlock>), ConfigError> {
    // Explicit capacity-only fixture observation, not host disk qualification.
    read_config_and_genesis_with_filesystem_space(args, |_| {
        Some((32 * 1024 * 1024 * 1024, 64 * 1024 * 1024 * 1024))
    })
}

#[test]
fn profile_node_file_loads_through_the_profile_path() {
    let node = ProfileNode::new();
    let (path, digest) = node.node_file();
    let path = path.to_str().expect("UTF-8 path").to_owned();
    let (config, genesis) = read_with_fixture_space(&parse_args_from(
        test_build_metadata(),
        ["iroha3d", "--config", &path],
    ))
    .unwrap_or_else(|report| panic!("{report:?}"));
    assert!(genesis.is_none());
    assert_eq!(config.data_dir.as_ref(), Some(&node.data_dir));
    assert!(config.lifecycle.exit_on_stdin_close);
    assert_eq!(config.common.chain_discriminant.value(), &753);
    assert_eq!(
        config.kura.store_dir.resolve_relative_path(),
        node.data_dir.state_dir().join("kura")
    );
    // `--sora` is refused with a profile.
    assert!(
        read_with_fixture_space(&parse_args_from(
            test_build_metadata(),
            ["iroha3d", "--sora", "--config", &path]
        ))
        .is_err()
    );
    // `--config-blake3` binds the exact node-file bytes.
    let (bound, _) = read_with_fixture_space(&parse_args_from(
        test_build_metadata(),
        ["iroha3d", "--config", &path, "--config-blake3", &digest],
    ))
    .unwrap_or_else(|report| panic!("{report:?}"));
    assert_eq!(bound.data_dir, config.data_dir);
    assert!(
        read_with_fixture_space(&parse_args_from(
            test_build_metadata(),
            [
                "iroha3d",
                "--config",
                &path,
                "--config-blake3",
                &"0".repeat(64),
            ]
        ))
        .is_err()
    );
}

/// The key files the parser reads pass the runtime-secret custody checks first, for every
/// invocation that loads the node file (including `--check-config`).
#[test]
fn parser_read_key_files_fail_closed_on_custody() {
    let node = ProfileNode::new();
    let (path, _) = node.node_file();
    let path = path.to_str().expect("UTF-8 path").to_owned();
    let validator = node.data_dir.secret(NodeSecretFile::Validator);
    fs::set_permissions(&validator, fs::Permissions::from_mode(0o640)).expect("group-readable");
    for args in [
        vec!["iroha3d", "--config", path.as_str()],
        vec!["iroha3d", "--config", path.as_str(), "--check-config"],
    ] {
        let Err(error) = read_with_fixture_space(&parse_args_from(test_build_metadata(), args))
        else {
            panic!("a group-readable validator key is refused");
        };
        assert!(
            format!("{error:?}").contains("secrets/validator.key"),
            "{error:?}"
        );
    }
    fs::set_permissions(&validator, fs::Permissions::from_mode(0o600)).expect("owner-only");
    let aside = node.root.path().join("validator.key");
    fs::rename(&validator, &aside).expect("move the key aside");
    std::os::unix::fs::symlink(&aside, &validator).expect("symlinked key");
    assert!(
        read_with_fixture_space(&parse_args_from(
            test_build_metadata(),
            ["iroha3d", "--config", &path]
        ))
        .is_err(),
        "a symlinked validator key is refused"
    );
}

#[test]
fn compiled_nexus_profile_needs_no_sora_flag() {
    let node = ProfileNode::with_profile("sora-nexus-v1", 369);
    let (path, _) = node.node_file();
    // Parse on this thread only: the daemon installs the discriminant process-wide.
    let _discriminant = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
    let reader = iroha_config::node_config::open_node_config(
        NodeFile::Path(path),
        NodeConfigOptions::default(),
    )
    .unwrap_or_else(|report| panic!("{report:?}"));
    assert!(reader.profile().is_some());
    let (user, _) = reader.read().unwrap_or_else(|report| panic!("{report:?}"));
    let config = user.parse().unwrap_or_else(|report| panic!("{report:?}"));
    assert!(
        config.soracloud_runtime.production_mode,
        "validator role overlay applies"
    );
    assert!(
        !sora_features_requiring_flag(&config).is_empty(),
        "the compiled Nexus profile enables features a flat file needs `--sora` for"
    );
    let flat = Config::from_toml_source(iroha_config::base::toml::TomlSource::inline(
        config_tests::minimal_config_table(),
    ))
    .expect("minimal config parses");
    assert!(sora_features_requiring_flag(&flat).is_empty());
}

#[test]
fn profile_node_secrets_resolve_and_fail_closed_on_custody() {
    let node = ProfileNode::new();
    let (path, _) = node.node_file();
    let path = path.to_str().expect("UTF-8 path").to_owned();
    let (config, genesis) = read_with_fixture_space(&parse_args_from(
        test_build_metadata(),
        ["iroha3d", "--config", &path],
    ))
    .unwrap_or_else(|report| panic!("{report:?}"));
    // A real start authenticates any local genesis once, before resolving the secrets.
    let _authenticated_genesis = genesis
        .as_ref()
        .map(|genesis| {
            validate_available_genesis_for_check(&config, genesis, None)
                .map(|(authenticated, _)| authenticated)
        })
        .transpose()
        .unwrap_or_else(|report| panic!("{report:?}"));
    let dependencies =
        resolve_node_secrets_runtime_deps(&config).unwrap_or_else(|report| panic!("{report:?}"));
    assert_eq!(
        dependencies
            .soracloud_runtime_mutation_signer
            .as_ref()
            .expect("Soracloud signer")
            .public_key()
            .expect("qualified key"),
        *node.signer.public_key()
    );
    let signer = node.data_dir.secret(NodeSecretFile::RuntimeSigner);
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o644)).expect("unsafe mode");
    let Err(error) = resolve_node_secrets_runtime_deps(&config) else {
        panic!("a world-readable signer is refused");
    };
    assert!(
        format!("{error:?}").contains("secrets/runtime_signer.key"),
        "{error:?}"
    );
    // Offline validation and the compatibility probe never open the secret.
    validate_config_and_genesis_for_check(&config, genesis.as_ref(), None)
        .map_or_else(|report| panic!("{report:?}"), drop);
    let compatibility =
        compatibility_probe::config_compatibility_v1(&config, None, crate::test_build_metadata())
            .unwrap_or_else(|report| panic!("{report:?}"));
    assert_eq!(compatibility.status, "pending");
}

#[test]
fn check_flags_parse_and_conflict() {
    let args = parse_args_from(
        test_build_metadata(),
        ["iroha3d", "--check-config", "--json"],
    );
    assert!(args.startup.check_config && args.startup.json);
    let args = parse_args_from(test_build_metadata(), ["iroha3d", "--check-storage"]);
    assert!(args.startup.check_storage && !args.startup.check_config);
    assert!(Args::try_parse_from(["iroha3d", "--json"]).is_err());
    assert!(Args::try_parse_from(["iroha3d", "--check-storage", "--check-config"]).is_err());
}

#[test]
fn drain_until_eof_consumes_the_whole_input() {
    let mut input = std::io::Cursor::new(vec![0x5A; 1_000]);
    drain_until_eof(&mut input);
    assert_eq!(input.position(), 1_000);
}

#[test]
fn closing_the_input_sends_the_shutdown_signal() {
    let (reader, writer) = rustix::pipe::pipe().expect("pipe");
    let signal = ShutdownSignal::new();
    spawn_input_close_shutdown(fs::File::from(reader), signal.clone()).expect("watch input");
    let mut writer = fs::File::from(writer);
    std::io::Write::write_all(&mut writer, b"keepalive").expect("write to the pipe");
    std::thread::sleep(Duration::from_millis(50));
    assert!(!signal.is_sent(), "open input keeps the node running");
    drop(writer);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !signal.is_sent() {
        assert!(
            std::time::Instant::now() < deadline,
            "end-of-file must send the shutdown signal"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
