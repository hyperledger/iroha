//! Custody, binding and resolution tests for fixed-name node secrets.

use super::*;
use crate::config_tests::minimal_config_table;
use iroha_config::base::toml::TomlSource;
use iroha_core::beacon::ceremony::{
    GlobalBeaconCeremonyPlanV1, deal_global_beacon_at_logical_clock_v1,
    global_beacon_genesis_dkg_session_v1,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::block::BlockHeader;
use iroha_model_base::peer::PeerId;
use std::{
    fs,
    os::unix::fs::{PermissionsExt as _, symlink},
};

/// Owner-only `data_dir` below the checkout, so no world-writable temporary ancestor weakens the
/// production custody policy.
struct SecretsFixture {
    root: tempfile::TempDir,
    data_dir: DataDir,
}

impl SecretsFixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix(".node-secrets-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("private fixture directory");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private fixture mode");
        let data_dir = DataDir::new(root.path().join("data"));
        for directory in [
            data_dir.root().to_path_buf(),
            data_dir.secrets_dir(),
            data_dir.secrets_dir().join("authority"),
        ] {
            fs::create_dir(&directory).expect("create fixture directory");
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("private directory mode");
        }
        Self { root, data_dir }
    }

    fn write(&self, file: NodeSecretFile, bytes: &[u8]) -> PathBuf {
        let path = self.data_dir.secret(file);
        fs::write(&path, bytes).expect("write fixture secret");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("owner-only secret");
        path
    }
}

fn signer_key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}

fn signer_record(key_pair: &KeyPair) -> Vec<u8> {
    let literal = ExposedPrivateKey(key_pair.private_key().clone())
        .try_to_multihash_string()
        .expect("canonical private key");
    format!("{literal}\n").into_bytes()
}

fn signer_binding(key_pair: &KeyPair) -> SoracloudRuntimeMutationSignerBinding {
    SoracloudRuntimeMutationSignerBinding {
        handle: node_runtime_signer::handle_v1(key_pair.public_key()).expect("Ed25519 handle"),
        authority: AccountId::new(key_pair.public_key().clone()),
        algorithm: Algorithm::Ed25519,
        public_key: key_pair.public_key().clone(),
        revision: node_runtime_signer::REVISION_V1,
        policy_digest: node_runtime_signer::policy_digest_v1(),
    }
}

fn network(marker: &[u8]) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        marker,
    )))
}

#[test]
fn runtime_signer_policy_and_handle_are_fixed() {
    let key_pair = signer_key(0x41);
    let signer = FileRuntimeSignerV1::new(NODE_RUNTIME_SIGNER_POLICY_V1, key_pair.clone())
        .expect("Ed25519 signer");
    let handle = node_runtime_signer::handle_v1(key_pair.public_key()).expect("Ed25519 handle");
    assert_eq!(signer.handle(), handle);
    assert!(is_production_runtime_handle(&handle));
    assert_eq!(
        signer.qualification_v1(),
        SoracloudRuntimeSignerQualificationV1::new(
            node_runtime_signer::REVISION_V1,
            node_runtime_signer::policy_digest_v1(),
            true,
            false,
        )
    );
    let bls = KeyPair::from_seed(vec![0x41; 32], Algorithm::BlsNormal);
    assert!(FileRuntimeSignerV1::new(NODE_RUNTIME_SIGNER_POLICY_V1, bls).is_none());
    assert_eq!(
        signer_record(&key_pair).len(),
        node_runtime_signer::KEY_FILE_BYTES_V1
    );
}

#[test]
fn runtime_signer_loads_the_exact_bound_key() {
    let fixture = SecretsFixture::new();
    let key_pair = signer_key(0x42);
    fixture.write(NodeSecretFile::RuntimeSigner, &signer_record(&key_pair));
    let signer = load_runtime_signer(&fixture.data_dir, &signer_binding(&key_pair))
        .expect("load bound runtime signer");
    assert_eq!(signer.signer_public_key(), key_pair.public_key());
    assert_eq!(signer.handle(), signer_binding(&key_pair).handle);
    assert_eq!(
        signer.qualification().expect("qualification"),
        signer.qualification_v1()
    );
    signer
        .qualification_v1()
        .validate()
        .expect("active production qualification");
}

#[test]
fn runtime_signer_rejects_custody_failures() {
    let fixture = SecretsFixture::new();
    let key_pair = signer_key(0x43);
    let binding = signer_binding(&key_pair);
    assert_eq!(
        load_runtime_signer(&fixture.data_dir, &binding).err(),
        Some(NodeSecretsErrorV1::Missing(NodeSecretFile::RuntimeSigner))
    );
    let path = fixture.write(NodeSecretFile::RuntimeSigner, &signer_record(&key_pair));
    let custody = |error| {
        Some(NodeSecretsErrorV1::Custody {
            file: NodeSecretFile::RuntimeSigner,
            error,
        })
    };
    for mode in [0o644, 0o640, 0o604, 0o4600] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("unsafe mode");
        assert_eq!(
            load_runtime_signer(&fixture.data_dir, &binding).err(),
            custody(RuntimeCredentialErrorV1::InvalidSource),
            "mode {mode:o} must be rejected"
        );
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore mode");
    let alias = fixture.root.path().join("alias");
    fs::hard_link(&path, &alias).expect("second link");
    assert_eq!(
        load_runtime_signer(&fixture.data_dir, &binding).err(),
        custody(RuntimeCredentialErrorV1::InvalidSource),
        "nlink 2 must be rejected"
    );
    fs::remove_file(&alias).expect("remove second link");
    let real = fixture.root.path().join("real.key");
    fs::rename(&path, &real).expect("move the key aside");
    symlink(&real, &path).expect("symlinked secret");
    assert_eq!(
        load_runtime_signer(&fixture.data_dir, &binding).err(),
        custody(RuntimeCredentialErrorV1::InvalidSource),
        "a symlink must be rejected"
    );
    fs::remove_file(&path).expect("remove symlink");
    let mut long = signer_record(&key_pair);
    long.push(b'\n');
    fixture.write(NodeSecretFile::RuntimeSigner, &long);
    assert_eq!(
        load_runtime_signer(&fixture.data_dir, &binding).err(),
        custody(RuntimeCredentialErrorV1::InvalidLength),
        "a longer record must be rejected"
    );
    let short = &signer_record(&key_pair)[..node_runtime_signer::KEY_FILE_BYTES_V1 - 1];
    fixture.write(NodeSecretFile::RuntimeSigner, short);
    assert_eq!(
        load_runtime_signer(&fixture.data_dir, &binding).err(),
        custody(RuntimeCredentialErrorV1::InvalidLength),
        "a shorter record must be rejected"
    );
    fs::set_permissions(
        fixture.data_dir.secrets_dir(),
        fs::Permissions::from_mode(0o770),
    )
    .expect("group-writable secrets directory");
    fixture.write(NodeSecretFile::RuntimeSigner, &signer_record(&key_pair));
    assert_eq!(
        load_runtime_signer(&fixture.data_dir, &binding).err(),
        custody(RuntimeCredentialErrorV1::InvalidSource),
        "a writable ancestor must be rejected"
    );
}

#[test]
fn runtime_signer_rejects_malformed_records() {
    let key_pair = signer_key(0x44);
    let record = signer_record(&key_pair);
    parse_ed25519_signer_record_v1(&record).expect("canonical record");
    let mut no_newline = record.clone();
    no_newline.pop();
    no_newline.push(b' ');
    let mut lowercase = String::from_utf8(record.clone()).expect("ASCII record");
    lowercase.make_ascii_lowercase();
    let mut garbage = record.clone();
    garbage[10] = b'z';
    for malformed in [no_newline, lowercase.into_bytes(), garbage] {
        if malformed == record {
            continue;
        }
        assert!(parse_ed25519_signer_record_v1(&malformed).is_none());
    }
}

#[test]
fn runtime_signer_rejects_a_mismatched_public_binding() {
    let fixture = SecretsFixture::new();
    let key_pair = signer_key(0x45);
    fixture.write(NodeSecretFile::RuntimeSigner, &signer_record(&key_pair));
    let other = signer_key(0x46);
    let mut cases = Vec::new();
    let mut foreign_key = signer_binding(&key_pair);
    foreign_key.public_key = other.public_key().clone();
    cases.push(foreign_key);
    let mut foreign_authority = signer_binding(&key_pair);
    foreign_authority.authority = AccountId::new(other.public_key().clone());
    cases.push(foreign_authority);
    let mut foreign_handle = signer_binding(&key_pair);
    foreign_handle.handle = "software://taira/inrou/primary".to_owned();
    cases.push(foreign_handle);
    let mut foreign_revision = signer_binding(&key_pair);
    foreign_revision.revision += 1;
    cases.push(foreign_revision);
    let mut foreign_policy = signer_binding(&key_pair);
    foreign_policy.policy_digest = [0x11; 32];
    cases.push(foreign_policy);
    let mut foreign_algorithm = signer_binding(&key_pair);
    foreign_algorithm.algorithm = Algorithm::MlDsa;
    cases.push(foreign_algorithm);
    for binding in cases {
        assert!(
            matches!(
                load_runtime_signer(&fixture.data_dir, &binding),
                Err(NodeSecretsErrorV1::BindingMismatch {
                    file: NodeSecretFile::RuntimeSigner,
                    ..
                })
            ),
            "{binding:?} must be rejected"
        );
    }
}

struct DealtSeat {
    network_id: NetworkId,
    handle: String,
    revision: u64,
    policy_digest: [u8; 32],
    credential: iroha_core::beacon::credential::SecretConsensusThresholdCredentialV1,
}

fn dealt_seat(network_id: NetworkId) -> DealtSeat {
    let mut keys = (0_u8..4)
        .map(|index| {
            let mut seed = vec![0x5B; 32];
            seed[31] = index;
            KeyPair::from_seed(seed, Algorithm::BlsNormal)
        })
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    let roster = keys
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    let session =
        global_beacon_genesis_dkg_session_v1(network_id, &roster).expect("exact 3f + 1 session");
    let handles = (1..=4)
        .map(|index| format!("software://iroha/global-beacon/validator-{index}"))
        .collect();
    let plan = GlobalBeaconCeremonyPlanV1::new(session, roster, handles, 2).expect("valid plan");
    let mut dealt = deal_global_beacon_at_logical_clock_v1(
        &plan,
        &keys.iter().collect::<Vec<_>>(),
        &credential_test_budget(),
    )
    .expect("logical-clock deal");
    let seat = dealt.seats.swap_remove(0);
    DealtSeat {
        network_id,
        handle: seat.binding.handle,
        revision: seat.binding.revision,
        policy_digest: seat.binding.policy_digest,
        credential: seat.credential,
    }
}

/// Parse the ordinary node configuration used by the native custody tests.
fn minimal_parser_config() -> Config {
    Config::from_toml_source(TomlSource::inline(minimal_config_table()))
        .expect("ordinary node parser fixture")
}

fn validator_sumeragi() -> Sumeragi {
    let config = minimal_parser_config();
    assert_eq!(config.sumeragi.role, NodeRole::Validator);
    config.sumeragi
}

#[test]
fn beacon_credential_binding_is_derived_from_its_header() {
    let fixture = SecretsFixture::new();
    let seat = dealt_seat(network(b"node-secrets beacon network"));
    let mut sumeragi = validator_sumeragi();
    assert!(
        secret_result(load_beacon_signer(
            &fixture.data_dir,
            &seat.network_id,
            &sumeragi,
            &credential_test_budget()
        ))
        .expect("no credential")
        .is_none(),
        "an absent beacon.cred leaves the node without a beacon signer"
    );
    fixture.write(NodeSecretFile::BeaconCredential, &seat.credential);
    let loaded = secret_result(load_beacon_signer(
        &fixture.data_dir,
        &seat.network_id,
        &sumeragi,
        &credential_test_budget(),
    ))
    .expect("load unconfigured credential")
    .expect("credential present");
    assert_eq!(loaded.handle, seat.handle);
    assert_eq!(loaded.revision, seat.revision);
    assert_eq!(loaded.policy_digest, seat.policy_digest);

    sumeragi.global_beacon_partial_signer_provider_handle = Some(seat.handle.clone());
    sumeragi.global_beacon_partial_signer_provider_revision = Some(seat.revision);
    sumeragi.global_beacon_partial_signer_provider_policy_digest = Some(seat.policy_digest);
    secret_result(load_beacon_signer(
        &fixture.data_dir,
        &seat.network_id,
        &sumeragi,
        &credential_test_budget(),
    ))
    .expect("a configured binding equal to the header is accepted");
    sumeragi.global_beacon_partial_signer_provider_revision = Some(seat.revision + 1);
    assert!(matches!(
        secret_result(load_beacon_signer(
            &fixture.data_dir,
            &seat.network_id,
            &sumeragi,
            &credential_test_budget()
        )),
        Err(NodeSecretsErrorV1::BindingMismatch {
            file: NodeSecretFile::BeaconCredential,
            ..
        })
    ));
    sumeragi.global_beacon_partial_signer_provider_revision = Some(seat.revision);
    assert!(matches!(
        secret_result(load_beacon_signer(
            &fixture.data_dir,
            &network(b"another beacon network"),
            &sumeragi,
            &credential_test_budget(),
        )),
        Err(NodeSecretsErrorV1::BindingMismatch { .. })
    ));
    sumeragi.role = NodeRole::Observer;
    assert!(matches!(
        secret_result(load_beacon_signer(
            &fixture.data_dir,
            &seat.network_id,
            &sumeragi,
            &credential_test_budget()
        )),
        Err(NodeSecretsErrorV1::Unsupported(_))
    ));
    sumeragi.role = NodeRole::Validator;
    let mut trailing = seat.credential.to_vec();
    trailing.push(0);
    fixture.write(NodeSecretFile::BeaconCredential, &trailing);
    assert_eq!(
        secret_result(load_beacon_signer(
            &fixture.data_dir,
            &seat.network_id,
            &sumeragi,
            &credential_test_budget()
        ))
        .err(),
        Some(NodeSecretsErrorV1::Malformed(
            NodeSecretFile::BeaconCredential
        ))
    );
    fixture.write(NodeSecretFile::BeaconCredential, &seat.credential);
    fs::set_permissions(
        fixture.data_dir.secret(NodeSecretFile::BeaconCredential),
        fs::Permissions::from_mode(0o640),
    )
    .expect("group-readable credential");
    assert_eq!(
        secret_result(load_beacon_signer(
            &fixture.data_dir,
            &seat.network_id,
            &sumeragi,
            &credential_test_budget()
        ))
        .err(),
        Some(NodeSecretsErrorV1::Custody {
            file: NodeSecretFile::BeaconCredential,
            error: RuntimeCredentialErrorV1::InvalidSource,
        })
    );
}

#[test]
fn onboarding_authority_key_must_match_the_authority() {
    let key_pair = signer_key(0x47);
    let record = signer_record(&key_pair);
    assert_eq!(
        &parse_authority_key(&record, NodeSecretFile::OnboardingAuthority)
            .expect("newline-terminated key"),
        key_pair.public_key()
    );
    assert_eq!(
        &parse_authority_key(
            &record[..record.len() - 1],
            NodeSecretFile::OnboardingAuthority
        )
        .expect("bare key"),
        key_pair.public_key()
    );
    for malformed in [&b""[..], b"\n", b"not a key\n", b"80262000\n\n"] {
        assert_eq!(
            parse_authority_key(malformed, NodeSecretFile::OnboardingAuthority).err(),
            Some(NodeSecretsErrorV1::Malformed(
                NodeSecretFile::OnboardingAuthority
            ))
        );
    }
}

/// A parsed minimal configuration whose `data_dir` is the fixture.
fn data_dir_config(fixture: &SecretsFixture) -> Config {
    let mut config = minimal_parser_config();
    config.data_dir = Some(fixture.data_dir.clone());
    config
}

#[test]
fn open_without_data_dir_touches_no_secret() {
    let config = minimal_parser_config();
    // An ordinary node with no data directory opens no runtime custody source.
    assert!(config.data_dir.is_none());
    assert!(
        secret_result(NodeSecretsV1::open(&config, &credential_test_budget()))
            .expect("no data_dir")
            .is_none()
    );
}

#[test]
fn opened_secrets_resolve_the_configured_catalog() {
    let fixture = SecretsFixture::new();
    let key_pair = signer_key(0x48);
    fixture.write(NodeSecretFile::RuntimeSigner, &signer_record(&key_pair));
    let mut config = data_dir_config(&fixture);
    config.soracloud_runtime.submission.signer = Some(signer_binding(&key_pair));
    let seat = dealt_seat(NetworkId::from_genesis_hash(config.genesis.expected_hash));
    fixture.write(NodeSecretFile::BeaconCredential, &seat.credential);

    let secrets = secret_result(NodeSecretsV1::open(&config, &credential_test_budget()))
        .expect("open node secrets")
        .expect("data_dir node");
    let dependencies = secrets
        .resolve_runtime_deps(&config)
        .expect("resolve the signer binding and attach the derived beacon");
    let signer = dependencies
        .soracloud_runtime_mutation_signer
        .as_ref()
        .expect("Soracloud signer resolved");
    assert_eq!(
        signer.public_key().expect("qualified signer key"),
        *key_pair.public_key()
    );
    assert!(dependencies.sumeragi_global_beacon_partial_signer.is_some());

    // A configured beacon binding is resolved through the catalog instead.
    config.sumeragi.global_beacon_partial_signer_provider_handle = Some(seat.handle.clone());
    config
        .sumeragi
        .global_beacon_partial_signer_provider_revision = Some(seat.revision);
    config
        .sumeragi
        .global_beacon_partial_signer_provider_policy_digest = Some(seat.policy_digest);
    let dependencies = secret_result(NodeSecretsV1::open(&config, &credential_test_budget()))
        .expect("open with a configured beacon binding")
        .expect("data_dir node")
        .resolve_runtime_deps(&config)
        .expect("resolve the configured beacon binding");
    assert!(dependencies.sumeragi_global_beacon_partial_signer.is_some());

    // A binding for another key never resolves.
    config.soracloud_runtime.submission.signer = Some(signer_binding(&signer_key(0x49)));
    assert!(matches!(
        secret_result(NodeSecretsV1::open(&config, &credential_test_budget())),
        Err(NodeSecretsErrorV1::BindingMismatch {
            file: NodeSecretFile::RuntimeSigner,
            ..
        })
    ));
}

#[test]
fn production_mode_requires_the_runtime_signer_file() {
    let fixture = SecretsFixture::new();
    let key_pair = signer_key(0x4A);
    let mut config = data_dir_config(&fixture);
    config.soracloud_runtime.production_mode = true;
    config.soracloud_runtime.submission.signer = Some(signer_binding(&key_pair));
    assert_eq!(
        secret_result(NodeSecretsV1::open(&config, &credential_test_budget())).err(),
        Some(NodeSecretsErrorV1::Missing(NodeSecretFile::RuntimeSigner))
    );
    config.soracloud_runtime.submission.signer = None;
    assert!(matches!(
        secret_result(NodeSecretsV1::open(&config, &credential_test_budget())),
        Err(NodeSecretsErrorV1::Unsupported(_))
    ));
}

#[test]
fn registry_rejects_substituted_catalog_bindings() {
    let fixture = SecretsFixture::new();
    let key_pair = signer_key(0x4B);
    fixture.write(NodeSecretFile::RuntimeSigner, &signer_record(&key_pair));
    let mut config = data_dir_config(&fixture);
    config.soracloud_runtime.submission.signer = Some(signer_binding(&key_pair));
    let secrets = secret_result(NodeSecretsV1::open(&config, &credential_test_budget()))
        .expect("open node secrets")
        .expect("data_dir node");
    // The catalog asks for a beacon signer but `beacon.cred` is absent.
    config.sumeragi.global_beacon_partial_signer_provider_handle =
        Some("software://iroha/global-beacon/validator-1".to_owned());
    config
        .sumeragi
        .global_beacon_partial_signer_provider_revision = Some(2);
    config
        .sumeragi
        .global_beacon_partial_signer_provider_policy_digest = Some([0x13; 32]);
    assert_eq!(
        secrets.resolve_runtime_deps(&config).err(),
        Some(NodeSecretsErrorV1::Registry(
            IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution
        ))
    );
}

#[test]
fn errors_name_the_file_and_never_its_bytes() {
    let message = NodeSecretsErrorV1::Custody {
        file: NodeSecretFile::BeaconCredential,
        error: RuntimeCredentialErrorV1::InvalidLength,
    }
    .to_string();
    assert!(message.contains("secrets/beacon.cred"), "{message}");
    assert!(
        NodeSecretsErrorV1::Missing(NodeSecretFile::OnboardingAuthority)
            .to_string()
            .contains("secrets/authority/onboarding.key")
    );
}

#[test]
fn symlinked_secrets_or_data_dir_is_refused() {
    let fixture = SecretsFixture::new();
    let key_pair = signer_key(0x61);
    let binding = signer_binding(&key_pair);
    // `<data_dir>/secrets` is a user-owned symlink to a private directory holding a valid key.
    let real = fixture.root.path().join("real-secrets");
    fs::create_dir(&real).expect("real secrets directory");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("private mode");
    fs::write(
        real.join(NodeSecretFile::RuntimeSigner.relative_path()),
        signer_record(&key_pair),
    )
    .expect("write real key");
    fs::set_permissions(
        real.join(NodeSecretFile::RuntimeSigner.relative_path()),
        fs::Permissions::from_mode(0o600),
    )
    .expect("owner-only key");
    fs::remove_dir(fixture.data_dir.secrets_dir().join("authority")).expect("empty authority");
    fs::remove_dir(fixture.data_dir.secrets_dir()).expect("empty secrets");
    symlink(&real, fixture.data_dir.secrets_dir()).expect("symlinked secrets directory");
    let refused = Some(NodeSecretsErrorV1::Custody {
        file: NodeSecretFile::RuntimeSigner,
        error: RuntimeCredentialErrorV1::InvalidSource,
    });
    assert_eq!(
        load_runtime_signer(&fixture.data_dir, &binding).err(),
        refused,
        "a symlinked secrets directory must be refused"
    );
    // The same key through a symlinked `data_dir`.
    fs::remove_file(fixture.data_dir.secrets_dir()).expect("remove secrets link");
    fs::rename(&real, fixture.data_dir.secrets_dir()).expect("restore real secrets");
    let linked = DataDir::new(fixture.root.path().join("linked-data"));
    symlink(fixture.data_dir.root(), linked.root()).expect("symlinked data_dir");
    assert_eq!(
        load_runtime_signer(&linked, &binding).err(),
        refused,
        "a symlinked data_dir must be refused"
    );
    load_runtime_signer(&fixture.data_dir, &binding).expect("the real path still loads");
}

#[test]
fn native_secret_paths_reject_traversal_and_user_links() {
    let fixture = SecretsFixture::new();
    let file = NodeSecretFile::Validator;
    assert_eq!(existing_secret_path(&fixture.data_dir, file), Ok(None));
    fixture.write(file, &signer_record(&signer_key(0x61)));
    assert!(
        existing_secret_path(&fixture.data_dir, file)
            .unwrap()
            .is_some()
    );
    for path in [
        PathBuf::from("relative"),
        fixture.data_dir.root().join("../data"),
    ] {
        assert!(existing_secret_path(&DataDir::new(path), file).is_err());
    }
    let link = fixture.root.path().join("user-link");
    symlink(fixture.data_dir.root(), &link).expect("user-owned link");
    assert!(existing_secret_path(&DataDir::new(link), file).is_err());
}

#[test]
fn config_key_files_pass_custody_before_the_parser_reads_them() {
    let fixture = SecretsFixture::new();
    verify_config_key_custody(&fixture.data_dir).expect("absent key files are not required");
    let validator = KeyPair::from_seed(vec![0x62; 32], Algorithm::BlsNormal);
    let record = format!(
        "{}\n",
        ExposedPrivateKey(validator.private_key().clone())
            .try_to_multihash_string()
            .expect("canonical validator key")
    );
    for file in CONFIG_KEY_FILES_V1 {
        fixture.write(file, record.as_bytes());
    }
    verify_config_key_custody(&fixture.data_dir).expect("owner-only key files");
    for file in CONFIG_KEY_FILES_V1 {
        let path = fixture.data_dir.secret(file);
        let refused = Err(NodeSecretsErrorV1::Custody {
            file,
            error: RuntimeCredentialErrorV1::InvalidSource,
        });
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("readable key");
        assert_eq!(
            verify_config_key_custody(&fixture.data_dir),
            refused,
            "{file:?} readable by others"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore mode");
        let aside = fixture.root.path().join("aside.key");
        fs::rename(&path, &aside).expect("move key aside");
        symlink(&aside, &path).expect("symlinked key");
        assert_eq!(
            verify_config_key_custody(&fixture.data_dir),
            refused,
            "{file:?} symlinked"
        );
        fs::remove_file(&path).expect("remove symlink");
        fs::rename(&aside, &path).expect("restore key");
    }
    verify_config_key_custody(&fixture.data_dir).expect("restored key files");
}

fn credential_test_budget() -> AllocationBudget {
    AllocationBudget::new(64 * 1024 * 1024)
}

// Existing exact custody/binding assertions still inspect their complete original error.
// A local admission failure cannot satisfy any of these negative protocol fixtures.
fn secret_result<T>(result: Result<T, NodeSecretsLoadErrorV1>) -> Result<T, NodeSecretsErrorV1> {
    result.map_err(|error| match error {
        NodeSecretsLoadErrorV1::Secret(error) => error,
        NodeSecretsLoadErrorV1::BeaconSession(error) => {
            panic!("unexpected local admission: {error}")
        }
        NodeSecretsLoadErrorV1::BeaconDecode(error) => {
            panic!("unexpected local decoder refusal: {error}")
        }
    })
}

#[test]
fn beacon_file_admission_keeps_original_pool_source_and_retries_without_consuming_input() {
    let fixture = SecretsFixture::new();
    let seat = dealt_seat(network(b"original credential pool"));
    let sumeragi = validator_sumeragi();
    let path = fixture.write(NodeSecretFile::BeaconCredential, &seat.credential);
    let budget = credential_test_budget();
    let occupied = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
    let error = match load_beacon_signer(&fixture.data_dir, &seat.network_id, &sumeragi, &budget) {
        Err(NodeSecretsLoadErrorV1::BeaconSession(
            iroha_core::beacon::GlobalThresholdBeaconSessionError::Admission(error),
        )) => error,
        _ => panic!("occupied original pool must produce its typed admission refusal"),
    };
    let iroha_allocation::AllocationRefusal::Capacity {
        requested_bytes, ..
    } = &error
    else {
        panic!("valid graph is temporarily blocked by original outstanding owner");
    };
    assert_eq!(
        error,
        budget.try_reserve_bytes(*requested_bytes).unwrap_err()
    );
    assert_eq!(
        fs::read(&path).unwrap().as_slice(),
        seat.credential.as_slice()
    );
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    drop(occupied);
    let loaded = load_beacon_signer(&fixture.data_dir, &seat.network_id, &sumeragi, &budget)
        .unwrap()
        .unwrap();
    let retained = budget.reserved_bytes();
    assert!(retained > 0);
    let final_reader = loaded.signer.clone();
    drop(loaded);
    assert_eq!(budget.reserved_bytes(), retained);
    drop(final_reader);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(
        fs::read(path).unwrap().as_slice(),
        seat.credential.as_slice()
    );
}

#[test]
fn beacon_header_decode_refusal_preserves_original_file_and_scope_until_retry() {
    let fixture = SecretsFixture::new();
    let seat = dealt_seat(network(b"original header decoder scope"));
    let sumeragi = validator_sumeragi();
    let path = fixture.write(NodeSecretFile::BeaconCredential, &seat.credential);
    let budget = credential_test_budget();
    let failed = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || load_beacon_signer(&fixture.data_dir, &seat.network_id, &sumeragi, &budget),
    )
    .err()
    .expect("actual original header decode refusal");
    assert_eq!(
        failed.to_string(),
        "node beacon credential decoder is unavailable"
    );
    assert!(std::error::Error::source(&failed).is_some());
    let NodeSecretsLoadErrorV1::BeaconDecode(error) = failed else {
        panic!("local header pressure is not malformed custody");
    };
    assert_eq!(
        error.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert!(matches!(
        error.into_error(),
        norito::Error::ScopedDecodeResource(_)
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(
        fs::read(&path).unwrap().as_slice(),
        seat.credential.as_slice()
    );
    let signer = load_beacon_signer(&fixture.data_dir, &seat.network_id, &sumeragi, &budget)
        .unwrap()
        .unwrap();
    assert!(budget.reserved_bytes() > 0);
    drop(signer);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(
        fs::read(path).unwrap().as_slice(),
        seat.credential.as_slice()
    );
}
