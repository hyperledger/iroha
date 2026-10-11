//! Validate the V1 public configuration boundary for native `SoraFS` transaction signers.

use iroha_config::parameters::{actual::Root as ActualConfig, defaults, user::Root as UserConfig};
use iroha_config_base::{env::MockEnv, read::ConfigReader, toml::TomlSource};
use iroha_crypto::{Algorithm, KeyPair, PublicKey};
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
#[derive(Clone)]
struct BindingFixture {
    handle: String,
    authority: String,
    algorithm: String,
    public_key_hex: String,
    public_key: PublicKey,
    revision: u64,
    policy_digest_hex: String,
}
fn binding_fixture(
    seed: u8,
    algorithm: Algorithm,
    handle: &str,
    revision: u64,
    digest_byte: u8,
) -> BindingFixture {
    let key_pair = KeyPair::try_from_seed(vec![seed; 32], algorithm)
        .expect("test signer keypair should be supported");
    let public_key = key_pair.public_key().clone();
    let (decoded_algorithm, public_key_bytes) = public_key
        .try_to_bytes()
        .expect("test public key must expose raw bytes");
    assert_eq!(decoded_algorithm, algorithm);
    let authority = AccountId::new(public_key.clone())
        .to_i105_for_discriminant(defaults::common::CHAIN_DISCRIMINANT)
        .expect("single-key test authority must encode as I105");
    BindingFixture {
        handle: handle.to_owned(),
        authority,
        algorithm: match algorithm {
            Algorithm::Ed25519 => "ed25519",
            Algorithm::MlDsa => "ml_dsa",
            _ => panic!("test helper only supports production native signer algorithms"),
        }
        .to_owned(),
        public_key_hex: hex::encode(public_key_bytes),
        public_key,
        revision,
        policy_digest_hex: hex::encode([digest_byte; 32]),
    }
}
fn render_binding(role: &str, binding: &BindingFixture) -> String {
    render_binding_omitting(role, binding, None)
}
fn render_binding_omitting(role: &str, binding: &BindingFixture, omitted: Option<&str>) -> String {
    let mut source = format!("\n[sorafs.storage.native_transaction_signers.{role}]\n");
    for (field, value) in [
        ("handle", binding.handle.clone()),
        ("authority", binding.authority.clone()),
        ("algorithm", binding.algorithm.clone()),
        ("public_key_hex", binding.public_key_hex.clone()),
        ("revision", binding.revision.to_string()),
        ("policy_digest_hex", binding.policy_digest_hex.clone()),
    ] {
        if omitted == Some(field) {
            continue;
        }
        if field == "revision" {
            writeln!(source, "{field} = {value}").expect("writing to a String cannot fail");
        } else {
            writeln!(source, "{field} = \"{value}\"").expect("writing to a String cannot fail");
        }
    }
    source
}
fn all_roles_enabled() -> &'static str {
    r"
[sorafs.storage]
enabled = true

[sorafs.repair]
enabled = true

[sorafs.storage.reserve_worker]
enabled = true

[sorafs.storage.orderbook_worker]
enabled = true
"
}
fn complete_role_fixtures() -> [BindingFixture; 4] {
    [
        binding_fixture(
            0x31,
            Algorithm::Ed25519,
            "software://sorafs/proof-outcome/primary",
            11,
            0xa1,
        ),
        binding_fixture(
            0x32,
            Algorithm::MlDsa,
            "software://sorafs/repair/primary",
            12,
            0xa2,
        ),
        binding_fixture(
            0x33,
            Algorithm::Ed25519,
            "software://sorafs/reserve/primary",
            13,
            0xa3,
        ),
        binding_fixture(
            0x34,
            Algorithm::MlDsa,
            "software://sorafs/orderbook/primary",
            14,
            0xa4,
        ),
    ]
}
fn complete_source(fixtures: &[BindingFixture; 4]) -> String {
    let mut source = all_roles_enabled().to_owned();
    for (role, binding) in ["proof_outcome", "repair", "reserve", "orderbook"]
        .into_iter()
        .zip(fixtures)
    {
        source.push_str(&render_binding(role, binding));
    }
    source
}
#[test]
fn native_transaction_signer_bindings_default_to_absent() {
    let actual = parse_overlay("").expect("default-disabled native workers need no signer binding");
    let bindings = &actual.torii.sorafs_storage.native_transaction_signers;
    assert!(bindings.proof_outcome.is_none());
    assert!(bindings.repair.is_none());
    assert!(bindings.reserve.is_none());
    assert!(bindings.orderbook.is_none());
}
#[test]
fn complete_bindings_accept_exact_ed25519_and_ml_dsa_public_identities() {
    let fixtures = complete_role_fixtures();
    let actual = parse_overlay(&complete_source(&fixtures))
        .expect("four complete, distinct signer bindings must parse");
    let bindings = &actual.torii.sorafs_storage.native_transaction_signers;
    for (actual, expected, algorithm) in [
        (
            bindings
                .proof_outcome
                .as_ref()
                .expect("proof signer binding"),
            &fixtures[0],
            Algorithm::Ed25519,
        ),
        (
            bindings.repair.as_ref().expect("repair signer binding"),
            &fixtures[1],
            Algorithm::MlDsa,
        ),
        (
            bindings.reserve.as_ref().expect("reserve signer binding"),
            &fixtures[2],
            Algorithm::Ed25519,
        ),
        (
            bindings
                .orderbook
                .as_ref()
                .expect("orderbook signer binding"),
            &fixtures[3],
            Algorithm::MlDsa,
        ),
    ] {
        assert_eq!(actual.handle, expected.handle);
        assert_eq!(actual.authority.to_string(), expected.authority);
        assert_eq!(actual.algorithm, algorithm);
        assert_eq!(actual.public_key, expected.public_key);
        assert_eq!(actual.revision, expected.revision);
        assert_eq!(
            actual.policy_digest.as_slice(),
            hex::decode(&expected.policy_digest_hex)
                .expect("fixture digest hex")
                .as_slice()
        );
    }
}
#[test]
fn every_binding_field_is_required_and_unknown_aliases_or_credentials_are_rejected() {
    let fixtures = complete_role_fixtures();
    for (role, enablement, binding) in [
        (
            "proof_outcome",
            "[sorafs.storage]\nenabled = true\n",
            &fixtures[0],
        ),
        ("repair", "[sorafs.repair]\nenabled = true\n", &fixtures[1]),
        (
            "reserve",
            "[sorafs.storage.reserve_worker]\nenabled = true\n",
            &fixtures[2],
        ),
        (
            "orderbook",
            "[sorafs.storage.orderbook_worker]\nenabled = true\n",
            &fixtures[3],
        ),
    ] {
        for field in [
            "handle",
            "authority",
            "algorithm",
            "public_key_hex",
            "revision",
            "policy_digest_hex",
        ] {
            let source = format!(
                "{enablement}{}",
                render_binding_omitting(role, binding, Some(field))
            );
            let error = parse_overlay(&source).expect_err("partial binding must fail closed");
            assert!(
                error.contains(field),
                "missing {role}.{field} produced unexpected diagnostic: {error}"
            );
        }
    }
    let binding = &fixtures[0];
    for alias in [
        "provider_handle",
        "authority_id",
        "signature_algorithm",
        "public_key",
        "public_key_buffer",
        "policy_revision",
        "policy_digest",
        "private_key",
        "private_key_hex",
        "credentials",
        "bearer_token",
    ] {
        let source = format!(
            "[sorafs.storage]\nenabled = true\n{}\n{alias} = \"forbidden\"\n",
            render_binding("proof_outcome", binding)
        );
        let error = parse_overlay(&source).expect_err("unknown alias or secret must be rejected");
        assert!(
            error.contains(alias),
            "{alias} produced unexpected diagnostic: {error}"
        );
    }
    let role_alias = format!(
        "[sorafs.storage]\nenabled = true\n{}",
        render_binding("proof", binding)
    );
    let error = parse_overlay(&role_alias).expect_err("role aliases must be rejected");
    assert!(error.contains("proof"), "unexpected diagnostic: {error}");
}
#[test]
fn production_handles_reject_empty_whitespace_and_every_test_marker() {
    let valid = binding_fixture(
        0x42,
        Algorithm::Ed25519,
        "software://sorafs/proof-outcome/production",
        22,
        0xb2,
    );
    for handle in [
        String::new(),
        "software://sorafs/proof outcome/production".to_owned(),
        "software://sorafs/é/production".to_owned(),
        format!("software://sorafs/{}", "a".repeat(257)),
        "software://sorafs/test/production".to_owned(),
        "software://sorafs/mock/production".to_owned(),
        "software://sorafs/dev/production".to_owned(),
        "software://sorafs/fake/production".to_owned(),
        "software://sorafs/dummy/production".to_owned(),
        "software://sorafs/null/production".to_owned(),
        "software://sorafs/placeholder/production".to_owned(),
    ] {
        let mut binding = valid.clone();
        binding.handle.clone_from(&handle);
        let source = format!(
            "[sorafs.storage]\nenabled = true\n{}",
            render_binding("proof_outcome", &binding)
        );
        let error = parse_overlay(&source).expect_err("non-production handle must fail");
        assert!(
            error.contains("must be one canonical production provider handle"),
            "unexpected diagnostic for handle class: {error}"
        );
        assert!(
            handle.is_empty() || !error.contains(&handle),
            "diagnostic must not echo provider handles"
        );
    }
}
#[test]
fn algorithm_and_public_key_are_exact_and_canonical() {
    let valid = binding_fixture(
        0x43,
        Algorithm::Ed25519,
        "software://sorafs/proof-outcome/canonical",
        23,
        0xb3,
    );
    for algorithm in ["ml-dsa", "Ed25519", "ML_DSA", "secp256k1", ""] {
        let mut binding = valid.clone();
        binding.algorithm = algorithm.to_owned();
        let source = format!(
            "[sorafs.storage]\nenabled = true\n{}",
            render_binding("proof_outcome", &binding)
        );
        let error = parse_overlay(&source).expect_err("algorithm aliases must fail");
        assert!(
            error.contains("must be exactly `ed25519` or `ml_dsa`"),
            "unexpected algorithm diagnostic: {error}"
        );
    }
    let ml_dsa = binding_fixture(
        0x44,
        Algorithm::MlDsa,
        "software://sorafs/proof-outcome/ml-dsa",
        24,
        0xb4,
    );
    for public_key_hex in [
        valid.public_key_hex.to_ascii_uppercase(),
        "00".repeat(32),
        "ab".repeat(31),
        format!("{}gg", "ab".repeat(31)),
        ml_dsa.public_key_hex,
    ] {
        let mut binding = valid.clone();
        binding.public_key_hex = public_key_hex;
        let source = format!(
            "[sorafs.storage]\nenabled = true\n{}",
            render_binding("proof_outcome", &binding)
        );
        let error = parse_overlay(&source).expect_err("noncanonical or mismatched key must fail");
        assert!(
            error.contains("public_key_hex"),
            "unexpected public-key diagnostic: {error}"
        );
    }
}
#[test]
fn authority_must_be_canonical_i105_derived_from_the_public_key() {
    let valid = binding_fixture(
        0x45,
        Algorithm::Ed25519,
        "software://sorafs/proof-outcome/authority",
        25,
        0xb5,
    );
    for authority in [
        "alice@wonderland".to_owned(),
        format!(" {} ", valid.authority),
        binding_fixture(
            0x46,
            Algorithm::Ed25519,
            "software://sorafs/proof-outcome/unused",
            1,
            0x11,
        )
        .authority,
    ] {
        let mut binding = valid.clone();
        binding.authority = authority;
        let source = format!(
            "[sorafs.storage]\nenabled = true\n{}",
            render_binding("proof_outcome", &binding)
        );
        let error = parse_overlay(&source).expect_err("authority mismatch must fail");
        assert!(
            error.contains("authority"),
            "unexpected authority diagnostic: {error}"
        );
    }
}
#[test]
fn qualification_revision_and_digest_are_nonzero_and_canonical() {
    let valid = binding_fixture(
        0x47,
        Algorithm::Ed25519,
        "software://sorafs/proof-outcome/qualification",
        27,
        0xb7,
    );
    for (revision, policy_digest_hex, expected) in [
        (
            0,
            valid.policy_digest_hex.clone(),
            "revision must be nonzero",
        ),
        (1, "00".repeat(32), "policy_digest_hex must be nonzero"),
        (
            1,
            "AB".repeat(32),
            "must be exactly 64 lowercase hexadecimal characters",
        ),
        (
            1,
            "ab".repeat(31),
            "must be exactly 64 lowercase hexadecimal characters",
        ),
        (
            1,
            format!("{}gg", "ab".repeat(31)),
            "must be exactly 64 lowercase hexadecimal characters",
        ),
    ] {
        let mut binding = valid.clone();
        binding.revision = revision;
        binding.policy_digest_hex = policy_digest_hex;
        let source = format!(
            "[sorafs.storage]\nenabled = true\n{}",
            render_binding("proof_outcome", &binding)
        );
        let error = parse_overlay(&source).expect_err("zero/noncanonical qualification must fail");
        assert!(
            error.contains(expected),
            "unexpected qualification diagnostic: {error}"
        );
    }
}
#[test]
fn all_role_handles_authorities_and_public_keys_must_be_distinct() {
    let mut duplicate_handle = complete_role_fixtures();
    duplicate_handle[1].handle = duplicate_handle[0].handle.clone();
    let error =
        parse_overlay(&complete_source(&duplicate_handle)).expect_err("duplicate handle must fail");
    assert!(
        error.contains("roles must use distinct handles"),
        "unexpected duplicate-handle diagnostic: {error}"
    );
    let mut duplicate_identity = complete_role_fixtures();
    duplicate_identity[1].authority = duplicate_identity[0].authority.clone();
    duplicate_identity[1].algorithm = duplicate_identity[0].algorithm.clone();
    duplicate_identity[1].public_key_hex = duplicate_identity[0].public_key_hex.clone();
    duplicate_identity[1].public_key = duplicate_identity[0].public_key.clone();
    let error = parse_overlay(&complete_source(&duplicate_identity))
        .expect_err("duplicate authority and public key must fail");
    assert!(
        error.contains("roles must use distinct authorities"),
        "unexpected duplicate-authority diagnostic: {error}"
    );
    assert!(
        error.contains("roles must use distinct public keys"),
        "unexpected duplicate-key diagnostic: {error}"
    );
}
#[test]
fn every_role_binding_is_required_iff_drain_or_generation_is_active() {
    let fixtures = complete_role_fixtures();
    for (role, enablement, binding) in [
        (
            "proof_outcome",
            "[sorafs.storage]\nenabled = true\n",
            &fixtures[0],
        ),
        ("repair", "[sorafs.repair]\nenabled = true\n", &fixtures[1]),
        (
            "reserve",
            "[sorafs.storage.reserve_worker]\nenabled = true\n",
            &fixtures[2],
        ),
        (
            "orderbook",
            "[sorafs.storage.orderbook_worker]\nenabled = true\n",
            &fixtures[3],
        ),
    ] {
        let error =
            parse_overlay(enablement).expect_err("active signer role without binding must fail");
        assert!(
            error.contains(&format!(
                "native_transaction_signers.{role} is required for storage-enabled durable drain or role generation"
            )),
            "{role} missing-binding diagnostic was unexpected: {error}"
        );
        let error = parse_overlay(&render_binding(role, binding))
            .expect_err("inactive signer role with dormant binding must fail");
        assert!(
            error.contains(&format!(
                "native_transaction_signers.{role} is forbidden without storage-enabled durable drain or role generation"
            )),
            "{role} dormant-binding diagnostic was unexpected: {error}"
        );
    }
}
#[test]
fn storage_enabled_requires_all_four_signers_with_generation_workers_disabled() {
    let fixtures = complete_role_fixtures();
    let mut complete = "[sorafs.storage]\nenabled = true\n".to_owned();
    for (role, binding) in ["proof_outcome", "repair", "reserve", "orderbook"]
        .into_iter()
        .zip(&fixtures)
    {
        complete.push_str(&render_binding(role, binding));
    }
    parse_overlay(&complete)
        .expect("storage-enabled durable drain must accept all four explicit bindings");
    for (missing_index, missing_role) in ["proof_outcome", "repair", "reserve", "orderbook"]
        .into_iter()
        .enumerate()
    {
        let mut incomplete = "[sorafs.storage]\nenabled = true\n".to_owned();
        for (index, (role, binding)) in ["proof_outcome", "repair", "reserve", "orderbook"]
            .into_iter()
            .zip(&fixtures)
            .enumerate()
        {
            if index != missing_index {
                incomplete.push_str(&render_binding(role, binding));
            }
        }
        let error =
            parse_overlay(&incomplete).expect_err("one missing durable-drain signer must fail");
        assert!(
            error.contains(&format!(
                "native_transaction_signers.{missing_role} is required for storage-enabled durable drain or role generation"
            )),
            "{missing_role} durable-drain diagnostic was unexpected: {error}"
        );
    }
}
#[test]
fn bundle_level_unknown_roles_and_secret_material_are_rejected() {
    for field in [
        "proof",
        "proofOutcome",
        "repair_signer",
        "reserve_signer",
        "orderbook_signer",
        "private_key",
        "credentials",
        "pkcs11_pin",
    ] {
        let source =
            format!("[sorafs.storage.native_transaction_signers]\n{field} = \"forbidden\"\n");
        let error = parse_overlay(&source).expect_err("bundle unknown fields must fail closed");
        assert!(
            error.contains(field),
            "{field} produced unexpected diagnostic: {error}"
        );
    }
}

#[test]
fn explicit_native_credential_path_is_parsed_without_reading_a_secret() {
    let fixtures = complete_role_fixtures();
    #[cfg(windows)]
    let path = r"C:\iroha\nonexistent-orderbook-key";
    #[cfg(not(windows))]
    let path = "/run/iroha/nonexistent-orderbook-key";
    let source = complete_source(&fixtures) + &format!("\nsoftware_credential = {path:?}\n");
    let actual = parse_overlay(&source).expect("config only validates the path shape");
    assert_eq!(
        actual
            .torii
            .sorafs_storage
            .native_transaction_signers
            .orderbook
            .unwrap()
            .software_credential,
        Some(PathBuf::from(path))
    );
    for path in ["relative/key", "/run/../key"] {
        let invalid = complete_source(&fixtures) + &format!("\nsoftware_credential = {path:?}\n");
        assert!(parse_overlay(&invalid).is_err());
    }
    let mut external = fixtures;
    external[3].handle = "provider://sorafs/orderbook/primary".into();
    let invalid = complete_source(&external) + &format!("\nsoftware_credential = {path:?}\n");
    assert!(parse_overlay(&invalid).is_err());
}

#[cfg(windows)]
#[test]
fn native_credentials_accept_exact_windows_drive_and_canonical_verbatim_drive_spelling() {
    let fixtures = complete_role_fixtures();
    // Parsing is lexical and does not probe the drive, create files or assert private custody.
    for path in [r"C:\iroha\signers\key", r"\\?\C:\iroha\signers\key"] {
        let source = complete_source(&fixtures) + &format!("\nsoftware_credential = {path:?}\n");
        let actual = parse_overlay(&source).expect("supported native local-drive shape");
        assert_eq!(
            actual
                .torii
                .sorafs_storage
                .native_transaction_signers
                .orderbook
                .unwrap()
                .software_credential,
            Some(PathBuf::from(path))
        );
    }
}

#[cfg(windows)]
#[test]
fn native_credentials_refuse_windows_relative_unc_device_and_traversal_paths() {
    let fixtures = complete_role_fixtures();
    for path in [
        r"C:relative\key",
        r"\iroha\key",
        r"C:\iroha\..\key",
        r"\\?\C:\iroha\..\key",
        r"\\?\C:\iroha\.\key",
        r"\\server\share\key",
        r"\\?\UNC\server\share\key",
        r"\\.\C:\iroha\key",
        r"\\.\pipe\runtime-key",
        r"\\?\Volume{00000000-0000-0000-0000-000000000000}\key",
    ] {
        let source = complete_source(&fixtures) + &format!("\nsoftware_credential = {path:?}\n");
        let error = parse_overlay(&source).expect_err("unsupported native credential path");
        assert!(
            error.contains("software_credential must be an absolute path without traversal"),
            "{error}"
        );
    }
}
