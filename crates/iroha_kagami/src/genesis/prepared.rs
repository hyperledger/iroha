//! Independent, fail-closed admission for one prepared signed genesis bundle.

use crate::{Outcome, RunArgs, tui};
use clap::Parser;
use color_eyre::eyre::{WrapErr as _, ensure, eyre};
use iroha_config::parameters::actual;
use iroha_crypto::{Hash, HashOf, PublicKey, sha256};
use iroha_data_model::{
    Encode,
    account::{AccountId, address::ChainDiscriminantGuard},
    block::BlockHeader,
};
use iroha_genesis::{
    RawGenesisTransaction, read_genesis_manifest_bytes, read_signed_genesis_bytes,
    validate_prepared_genesis_bundle,
};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{BufWriter, Read as _, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const TAIRA_VALIDATOR_COUNT: usize = 4;
// Effective configs contain policy settings and paths, while large runtime artifacts remain
// external files. Eight MiB leaves ample first-release policy headroom while bounding parser input.
const MAX_VALIDATOR_CONFIG_BYTES_V1: usize = 8 * 1024 * 1024;
// The first-release Taira roster is exactly four public identity/PoP rows. This permits 16 KiB per
// validator while preventing an unauthenticated roster from consuming unbounded memory.
const MAX_VALIDATOR_ROSTER_BYTES_V1: usize = 64 * 1024;

/// Verify the exact semantic, signer, hash, and canonical-wire binding of a prepared genesis.
#[derive(Clone, Debug, Parser)]
pub struct Args {
    /// Exact reviewed NEVO genesis before validator rendering.
    #[arg(long, value_name = "PATH")]
    reviewed_manifest: PathBuf,
    /// Exact public validator roster used by the renderer.
    #[arg(long, value_name = "PATH")]
    validator_roster: PathBuf,
    /// Exact config-bound genesis manifest used by the external signer.
    #[arg(long, value_name = "PATH")]
    bound_manifest: PathBuf,
    /// Exact renderer output accepted by the external signer before config binding.
    #[arg(long, value_name = "PATH")]
    pre_sign_manifest: PathBuf,
    /// Exact signed genesis in canonical framed Norito form.
    #[arg(long, value_name = "PATH")]
    signed_genesis: PathBuf,
    /// Effective validator configs whose complete roster and policy must reproduce the signed
    /// context. Repeat exactly four times in `taira-validator-1` through `-4` order.
    #[arg(long = "peer-config", value_name = "PATH")]
    peer_configs: Vec<PathBuf>,
    /// Public key of the independently provisioned genesis signer.
    #[arg(long, value_name = "PUBLIC_KEY")]
    genesis_public_key: PublicKey,
    /// Exact signed genesis block-header hash.
    #[arg(long, value_name = "HASH")]
    expected_hash: HashOf<BlockHeader>,
    /// Publish the exact public Nexus AMX context preimage after all four configurations agree.
    #[arg(long, value_name = "PATH")]
    nexus_context_output: Option<PathBuf>,
}

#[derive(norito::JsonSerialize)]
struct Receipt {
    schema: &'static str,
    status: &'static str,
    reviewed_manifest_sha256: String,
    validator_roster_sha256: String,
    bound_manifest_sha256: String,
    pre_sign_manifest_sha256: String,
    signed_genesis_sha256: String,
    nexus_amx_context_sha256: String,
    peer_config_sha256: Vec<String>,
    peer_config_set_sha256: String,
    genesis_public_key: String,
    expected_hash: String,
    validator_count: u64,
    reviewed_transform_passed: bool,
    allowed_transform_passed: bool,
    staged_context_passed: bool,
    full_core_validation_passed: bool,
}

struct ValidatorBinding {
    slug: String,
    account_id: String,
    public_key: PublicKey,
    pop: Vec<u8>,
    pop_hex: String,
}

type LoadedValidatorConfigs = (
    Vec<Zeroizing<Vec<u8>>>,
    Vec<actual::Root>,
    Vec<ValidatorBinding>,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreparedFileCustody {
    Public,
    OwnerOnly,
}

fn read_prepared_file_bounded(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> color_eyre::Result<Vec<u8>> {
    read_prepared_file_bounded_with_custody(path, max_bytes, label, PreparedFileCustody::Public)
}

fn read_owner_only_prepared_file_bounded(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> color_eyre::Result<Vec<u8>> {
    read_prepared_file_bounded_with_custody(path, max_bytes, label, PreparedFileCustody::OwnerOnly)
}

fn read_prepared_file_bounded_with_custody(
    path: &Path,
    max_bytes: usize,
    label: &str,
    custody: PreparedFileCustody,
) -> color_eyre::Result<Vec<u8>> {
    #[cfg(not(unix))]
    ensure!(
        custody == PreparedFileCustody::Public,
        "{label} requires owner-only file custody, which Kagami cannot verify on this platform"
    );
    let max_bytes_u64 = u64::try_from(max_bytes)
        .map_err(|_| eyre!("{label} byte limit is not representable on this platform"))?;
    let lexical = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("inspect {label} {}", path.display()))?;
    ensure!(
        lexical.is_file() && !lexical.file_type().is_symlink(),
        "{label} must be a non-symlink regular file: {}",
        path.display()
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .wrap_err_with(|| format!("open {label} {}", path.display()))?;
    let before = file
        .metadata()
        .wrap_err_with(|| format!("inspect opened {label} {}", path.display()))?;
    ensure!(
        before.is_file() && crate::secure_fs::same_file_snapshot(&lexical, &before),
        "{label} changed while opening or is not a regular file: {}",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        ensure!(
            before.uid() == rustix::process::geteuid().as_raw() && before.nlink() == 1,
            "{label} must be owner-held and single-link: {}",
            path.display()
        );
        match custody {
            PreparedFileCustody::Public => ensure!(
                before.mode() & 0o022 == 0,
                "{label} must not be group/world writable: {}",
                path.display()
            ),
            PreparedFileCustody::OwnerOnly => ensure!(
                before.mode() & 0o777 == 0o600,
                "{label} must have exact owner-only mode 0600: {}",
                path.display()
            ),
        }
    }
    ensure!(
        before.len() <= max_bytes_u64,
        "{label} exceeds the first-release {max_bytes}-byte limit: {}",
        path.display()
    );
    let capacity = usize::try_from(before.len())
        .map_err(|_| eyre!("{label} length cannot be addressed on this platform"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity.saturating_add(1))
        .map_err(|error| eyre!("failed to reserve {label} input buffer: {error}"))?;
    std::io::Read::by_ref(&mut file)
        .take(max_bytes_u64.saturating_add(1))
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= max_bytes,
        "{label} exceeds the first-release {max_bytes}-byte limit: {}",
        path.display()
    );
    let after = file.metadata()?;
    ensure!(
        crate::secure_fs::same_file_snapshot(&before, &after)
            && u64::try_from(bytes.len()).ok() == Some(before.len()),
        "{label} changed while it was being read: {}",
        path.display()
    );
    Ok(bytes)
}

fn config_slug(path: &Path, index: usize) -> color_eyre::Result<String> {
    let slug = path
        .parent()
        .and_then(Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| color_eyre::eyre::eyre!("peer config lacks a UTF-8 validator directory"))?;
    let expected = format!("taira-validator-{}", index + 1);
    ensure!(
        slug == expected,
        "peer configs must be ordered in exact Taira validator directories; expected {expected}, saw {slug}"
    );
    Ok(slug.to_owned())
}

fn load_validator_configs(
    paths: &[PathBuf],
    manifest: &RawGenesisTransaction,
    genesis_public_key: &PublicKey,
    expected_hash: HashOf<BlockHeader>,
) -> color_eyre::Result<LoadedValidatorConfigs> {
    ensure!(
        paths.len() == TAIRA_VALIDATOR_COUNT,
        "prepared Taira genesis requires exactly {TAIRA_VALIDATOR_COUNT} peer configs"
    );
    let mut bytes = Vec::with_capacity(paths.len());
    let mut configs = Vec::with_capacity(paths.len());
    let mut bindings = Vec::with_capacity(paths.len());
    let mut roster = None;
    let mut local_keys = BTreeSet::new();
    for (index, path) in paths.iter().enumerate() {
        let slug = config_slug(path, index)?;
        let config_bytes = Zeroizing::new(
            read_owner_only_prepared_file_bounded(
                path,
                MAX_VALIDATOR_CONFIG_BYTES_V1,
                "validator config",
            )
            .wrap_err_with(|| format!("read effective validator config {}", path.display()))?,
        );
        let config = super::sign::load_peer_config_bytes(path, &config_bytes)?;
        iroha_deploy::genesis::staging::ensure_peer_config_matches_manifest(&config, manifest)?;
        ensure!(
            config.genesis.public_key == *genesis_public_key,
            "effective validator config {slug} genesis public key differs from the admitted signer"
        );
        ensure!(
            config.genesis.expected_hash == expected_hash,
            "effective validator config {slug} expected hash differs from the admitted signed genesis"
        );
        ensure!(
            matches!(config.sumeragi.role, actual::NodeRole::Validator),
            "effective validator config {slug} is not a validator"
        );
        let trusted = config.common.trusted_peers.value();
        if let Some(expected_roster) = roster.as_ref() {
            ensure!(
                expected_roster == &trusted.pops,
                "effective validator config {slug} has a different trusted PoP roster"
            );
        } else {
            roster = Some(trusted.pops.clone());
        }
        let public_key = config.common.key_pair.public_key().clone();
        ensure!(
            trusted.myself.id().public_key() == &public_key,
            "effective validator config {slug} local identity differs from trusted-roster self"
        );
        ensure!(
            local_keys.insert(public_key.clone()),
            "effective validator config {slug} duplicates a validator identity"
        );
        let pop = trusted.pops.get(&public_key).cloned().ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "effective validator config {slug} identity is absent from its PoP roster"
            )
        })?;
        iroha_crypto::bls_normal_pop_verify(&public_key, &pop)
            .wrap_err_with(|| format!("verify effective validator {slug} PoP"))?;
        bytes.push(config_bytes);
        configs.push(config);
        bindings.push(ValidatorBinding {
            slug,
            account_id: String::new(),
            public_key,
            pop_hex: hex::encode(&pop),
            pop,
        });
    }
    let roster = roster.expect("four peer configs yield a roster");
    ensure!(
        roster.len() == TAIRA_VALIDATOR_COUNT
            && roster.keys().cloned().collect::<BTreeSet<_>>() == local_keys,
        "effective validator identities do not exactly cover the four-key trusted PoP roster"
    );
    Ok((bytes, configs, bindings))
}

fn required_roster_string<'a>(
    table: &'a toml::Table,
    field: &str,
    index: usize,
) -> color_eyre::Result<&'a str> {
    let value = table
        .get(field)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "validator roster entry {} lacks string field `{field}`",
                index + 1
            )
        })?;
    ensure!(
        !value.is_empty() && value.trim() == value,
        "validator roster entry {} field `{field}` is not canonical",
        index + 1
    );
    Ok(value)
}

fn bind_validator_roster(
    roster_bytes: &[u8],
    config_bindings: &[ValidatorBinding],
    chain_discriminant: u16,
) -> color_eyre::Result<Vec<ValidatorBinding>> {
    let roster_text =
        std::str::from_utf8(roster_bytes).wrap_err("validator roster is not canonical UTF-8")?;
    let roster = roster_text
        .parse::<toml::Table>()
        .wrap_err("parse exact validator roster TOML")?;
    let validators = roster
        .get("validators")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| color_eyre::eyre::eyre!("validator roster lacks `validators` array"))?;
    ensure!(
        validators.len() == TAIRA_VALIDATOR_COUNT,
        "validator roster must contain exactly {TAIRA_VALIDATOR_COUNT} validators"
    );
    let _chain_discriminant = ChainDiscriminantGuard::enter(chain_discriminant);
    let mut account_ids = BTreeSet::new();
    validators
        .iter()
        .zip(config_bindings)
        .enumerate()
        .map(|(index, (value, configured))| {
            let table = value.as_table().ok_or_else(|| {
                color_eyre::eyre::eyre!("validator roster entry {} is not a table", index + 1)
            })?;
            let slug = required_roster_string(table, "slug", index)?;
            ensure!(
                slug == configured.slug,
                "validator roster entry {} slug differs from its ordered peer config",
                index + 1
            );
            let public_key_literal = required_roster_string(table, "public_key", index)?;
            let public_key = public_key_literal
                .parse::<PublicKey>()
                .wrap_err_with(|| format!("parse validator roster public key for {slug}"))?;
            ensure!(
                public_key == configured.public_key
                    && public_key_literal == configured.public_key.to_string(),
                "validator roster public key for {slug} differs from its exact peer config"
            );
            let pop_hex = required_roster_string(table, "pop_hex", index)?;
            let pop = hex::decode(pop_hex)
                .wrap_err_with(|| format!("decode validator roster PoP for {slug}"))?;
            ensure!(
                pop == configured.pop,
                "validator roster PoP for {slug} differs from its exact peer config"
            );
            let account_id_literal = required_roster_string(table, "account_id", index)?;
            let account_id = AccountId::parse_encoded(account_id_literal)
                .wrap_err_with(|| format!("parse validator roster account id for {slug}"))?;
            ensure!(
                account_id.to_string() == account_id_literal,
                "validator roster account id for {slug} is not canonical for the reviewed chain"
            );
            ensure!(
                account_ids.insert(account_id_literal.to_owned()),
                "validator roster account id for {slug} is duplicated"
            );
            Ok(ValidatorBinding {
                slug: slug.to_owned(),
                account_id: account_id_literal.to_owned(),
                public_key,
                pop,
                pop_hex: pop_hex.to_owned(),
            })
        })
        .collect()
}

fn json_object(
    entries: impl IntoIterator<Item = (&'static str, norito::json::Value)>,
) -> norito::json::Value {
    norito::json::Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn validator_topology_values(validators: &[ValidatorBinding]) -> Vec<norito::json::Value> {
    validators
        .iter()
        .map(|validator| {
            json_object([
                (
                    "peer",
                    norito::json::Value::from(validator.public_key.to_string()),
                ),
                (
                    "pop_hex",
                    norito::json::Value::from(validator.pop_hex.clone()),
                ),
            ])
        })
        .collect()
}

fn expected_pre_sign_value(
    reviewed_bytes: &[u8],
    validators: &[ValidatorBinding],
) -> color_eyre::Result<norito::json::Value> {
    let mut value: norito::json::Value = norito::json::from_slice(reviewed_bytes)
        .wrap_err("parse reviewed manifest as a semantic JSON value")?;
    let transactions = value
        .as_object_mut()
        .and_then(|root| root.get_mut("transactions"))
        .and_then(norito::json::Value::as_array_mut)
        .ok_or_else(|| {
            color_eyre::eyre::eyre!("reviewed manifest transactions must be an array")
        })?;
    ensure!(
        !transactions.is_empty(),
        "reviewed manifest transactions must not be empty"
    );
    let mut registered_accounts = BTreeSet::new();
    for (index, transaction) in transactions.iter_mut().enumerate() {
        let transaction = transaction.as_object_mut().ok_or_else(|| {
            color_eyre::eyre::eyre!("reviewed manifest transaction {index} is not an object")
        })?;
        transaction.insert(
            "topology".to_owned(),
            norito::json::Value::Array(Vec::new()),
        );
        let instructions = transaction
            .get("instructions")
            .and_then(norito::json::Value::as_array)
            .ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "reviewed manifest transaction {index} instructions must be an array"
                )
            })?;
        for instruction in instructions {
            let Some(register) = instruction
                .as_object()
                .and_then(|object| object.get("Register"))
                .and_then(norito::json::Value::as_object)
            else {
                continue;
            };
            let Some(account_id) = register
                .get("Account")
                .and_then(norito::json::Value::as_object)
                .and_then(|account| account.get("id"))
                .and_then(norito::json::Value::as_str)
            else {
                continue;
            };
            registered_accounts.insert(account_id.to_owned());
        }
    }

    let instructions = validators
        .iter()
        .filter(|validator| !registered_accounts.contains(&validator.account_id))
        .map(|validator| {
            json_object([(
                "Register",
                json_object([(
                    "Account",
                    json_object([
                        (
                            "id",
                            norito::json::Value::from(validator.account_id.clone()),
                        ),
                        (
                            "metadata",
                            json_object([
                                (
                                    "purpose",
                                    norito::json::Value::from("taira_validator_payout_recipient"),
                                ),
                                (
                                    "validator_slug",
                                    norito::json::Value::from(validator.slug.clone()),
                                ),
                            ]),
                        ),
                    ]),
                )]),
            )])
        })
        .collect::<Vec<_>>();
    let topology = validator_topology_values(validators);
    transactions.push(json_object([
        ("instructions", norito::json::Value::Array(instructions)),
        ("ivm_triggers", norito::json::Value::Array(Vec::new())),
        ("topology", norito::json::Value::Array(topology)),
    ]));
    Ok(value)
}

fn config_set_sha256(digests: &[String]) -> String {
    let mut encoded = digests.join("\n");
    encoded.push('\n');
    hex::encode(sha256(encoded.as_bytes()))
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        tui::status("Verifying prepared signed genesis bundle");
        let reviewed_bytes = read_genesis_manifest_bytes(&self.reviewed_manifest)
            .wrap_err("read reviewed genesis manifest under fixed resource bounds")?;
        let reviewed = RawGenesisTransaction::from_json_slice(&reviewed_bytes)
            .wrap_err("parse exact reviewed genesis manifest")?;
        let validator_roster_bytes = read_prepared_file_bounded(
            &self.validator_roster,
            MAX_VALIDATOR_ROSTER_BYTES_V1,
            "public validator roster",
        )
        .wrap_err("read exact public validator roster")?;
        let manifest_bytes = read_genesis_manifest_bytes(&self.bound_manifest)
            .wrap_err("read bound genesis manifest under fixed resource bounds")?;
        let manifest = RawGenesisTransaction::from_json_slice(&manifest_bytes)
            .wrap_err("parse exact bound genesis manifest")?;
        let pre_sign_bytes = read_genesis_manifest_bytes(&self.pre_sign_manifest)
            .wrap_err("read pre-sign genesis manifest under fixed resource bounds")?;
        let bundle_root = self
            .pre_sign_manifest
            .parent()
            .ok_or_else(|| color_eyre::eyre::eyre!("pre-sign manifest lacks a bundle parent"))?;
        ensure!(
            self.bound_manifest.parent() == Some(bundle_root),
            "pre-sign and bound manifests must share one exact bundle root"
        );
        let signer_input_path = bundle_root.join("rendered/genesis.json");
        let pre_sign =
            RawGenesisTransaction::from_json_slice_at_path(&pre_sign_bytes, &signer_input_path)
                .wrap_err("parse exact pre-sign genesis manifest with signer path semantics")?;
        let (peer_config_bytes, configs, config_bindings) = load_validator_configs(
            &self.peer_configs,
            &manifest,
            &self.genesis_public_key,
            self.expected_hash,
        )?;
        let validator_bindings = bind_validator_roster(
            &validator_roster_bytes,
            &config_bindings,
            reviewed.chain_discriminant(),
        )?;
        let expected_pre_sign = expected_pre_sign_value(&reviewed_bytes, &validator_bindings)?;
        let observed_pre_sign: norito::json::Value = norito::json::from_slice(&pre_sign_bytes)
            .wrap_err("parse pre-sign manifest as a semantic JSON value")?;
        ensure!(
            expected_pre_sign == observed_pre_sign,
            "pre-sign genesis differs from the reviewed manifest outside the exact four-validator renderer transform"
        );
        let pre_sign_consensus_mode = pre_sign.consensus_mode();
        let signer_prepared = super::sign::prepare_genesis_for_signing(
            pre_sign,
            Some(&configs[0]),
            pre_sign_consensus_mode,
            None,
            &[],
        )
        .wrap_err("reproduce the external signer's deterministic manifest preparation")?;
        let expected_bound = signer_prepared
            .with_sumeragi_context_parameters(manifest.sumeragi_context_parameters())
            .with_consensus_meta()?;
        ensure!(
            expected_bound.encode() == manifest.encode(),
            "bound genesis differs from the pre-sign manifest outside the exact staged-context transform"
        );
        let signed_bytes = read_signed_genesis_bytes(&self.signed_genesis)
            .wrap_err("read signed genesis under fixed resource bounds")?;
        let validated = validate_prepared_genesis_bundle(
            &signed_bytes,
            &manifest,
            &self.genesis_public_key,
            self.expected_hash,
        )
        .wrap_err("validate exact prepared genesis bundle")?;
        iroha_core::validate_genesis_block(
            validated.block(),
            &AccountId::new(self.genesis_public_key.clone()),
        )
        .map_err(|error| {
            color_eyre::eyre::eyre!("prepared genesis failed full core validation: {error}")
        })?;
        let signed_context = manifest.sumeragi_context_parameters();
        let mut nexus_context = None;
        for (config, binding) in configs.iter().zip(&validator_bindings) {
            let staged = iroha_deploy::genesis::staging::restage_signed_sumeragi_context_hashes(
                &manifest,
                Some(config),
                validated.block(),
            )
            .wrap_err_with(|| {
                format!(
                    "restage signed genesis under effective validator policy {}",
                    binding.slug
                )
            })?;
            ensure!(
                staged.nexus_amx_context_hash
                    == Hash::prehashed(signed_context.nexus_amx_context_hash),
                "effective validator {} Nexus/AMX context differs from signed genesis",
                binding.slug
            );
            ensure!(
                staged.execution_policy_hash
                    == Hash::prehashed(signed_context.execution_policy_hash),
                "effective validator {} execution policy differs from signed genesis",
                binding.slug
            );
            if let Some(original) = &nexus_context {
                ensure!(
                    original == &staged.nexus_amx_context_preimage,
                    "effective validator {} Nexus AMX preimage differs",
                    binding.slug
                );
            } else {
                nexus_context = Some(staged.nexus_amx_context_preimage);
            }
        }
        let nexus_context =
            nexus_context.ok_or_else(|| eyre!("missing staged Nexus AMX context"))?;
        ensure!(
            validated.validator_pops()
                == &validator_bindings
                    .iter()
                    .map(|binding| (binding.public_key.clone(), binding.pop.clone()))
                    .collect(),
            "signed genesis validator roster differs from the exact four peer configs"
        );
        let peer_config_sha256 = peer_config_bytes
            .iter()
            .map(|bytes| hex::encode(sha256(bytes)))
            .collect::<Vec<_>>();
        let receipt = Receipt {
            schema: "iroha.kagami.prepared-genesis-verification.v2",
            status: "verified",
            reviewed_manifest_sha256: hex::encode(sha256(&reviewed_bytes)),
            validator_roster_sha256: hex::encode(sha256(&validator_roster_bytes)),
            bound_manifest_sha256: hex::encode(sha256(&manifest_bytes)),
            pre_sign_manifest_sha256: hex::encode(sha256(&pre_sign_bytes)),
            signed_genesis_sha256: hex::encode(sha256(&signed_bytes)),
            nexus_amx_context_sha256: hex::encode(sha256(&nexus_context)),
            peer_config_set_sha256: config_set_sha256(&peer_config_sha256),
            peer_config_sha256,
            genesis_public_key: self.genesis_public_key.to_string(),
            expected_hash: self.expected_hash.to_string(),
            validator_count: u64::try_from(validated.validator_pops().len())
                .expect("validator count fits u64"),
            reviewed_transform_passed: true,
            allowed_transform_passed: true,
            staged_context_passed: true,
            full_core_validation_passed: true,
        };
        if let Some(path) = &self.nexus_context_output {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .wrap_err("create public Nexus AMX context without replacement")?;
            file.write_all(&nexus_context)?;
            file.sync_all()?;
        }
        writeln!(writer, "{}", norito::json::to_json(&receipt)?)?;
        tui::success("Prepared signed genesis bundle verified");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        isi::{ActivatePublicLaneValidator, MintBox, RegisterPublicLaneValidator},
        parameter::{
            Parameter,
            system::{SumeragiConsensusMode, SumeragiNposParameters},
        },
    };
    use iroha_genesis::GenesisBuilder;
    use iroha_model_base::peer::PeerId;

    #[test]
    fn bounded_prepared_reader_accepts_exact_limit() {
        let file = tempfile::NamedTempFile::new().expect("create exact-limit prepared input");
        std::fs::write(file.path(), [0xA5; 32]).expect("write exact-limit prepared input");
        assert_eq!(
            read_prepared_file_bounded(file.path(), 32, "test prepared input")
                .expect("accept exact-limit prepared input"),
            vec![0xA5; 32]
        );
    }

    #[test]
    fn bounded_prepared_reader_rejects_limit_plus_one() {
        let file = tempfile::NamedTempFile::new().expect("create oversized prepared input");
        std::fs::write(file.path(), [0xA5; 33]).expect("write oversized prepared input");
        let error = read_prepared_file_bounded(file.path(), 32, "test prepared input")
            .expect_err("reject prepared input one byte over the limit");
        assert!(error.to_string().contains("32-byte limit"));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_validator_configs_require_exact_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let file = tempfile::NamedTempFile::new().expect("create validator config input");
        std::fs::write(file.path(), b"private_key = \"secret\"\n")
            .expect("write validator config input");
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644))
            .expect("set public-readable mode");
        read_prepared_file_bounded(file.path(), 64, "public fixture")
            .expect("public input may be world-readable");
        let error = read_owner_only_prepared_file_bounded(file.path(), 64, "validator config")
            .expect_err("public-readable validator config must fail");
        assert!(error.to_string().contains("exact owner-only mode 0600"));

        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("set owner-only mode");
        read_owner_only_prepared_file_bounded(file.path(), 64, "validator config")
            .expect("owner-only validator config");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_prepared_reader_rejects_symlinks_and_special_files_without_blocking() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("create adversarial prepared-input directory");
        let target = directory.path().join("target.toml");
        let linked = directory.path().join("linked.toml");
        std::fs::write(&target, b"value = 1\n").expect("seed prepared input target");
        symlink(&target, &linked).expect("create prepared input symlink");
        let error = read_prepared_file_bounded(&linked, 32, "test prepared input")
            .expect_err("prepared input symlink must fail closed");
        assert!(error.to_string().contains("non-symlink regular file"));

        let fifo = directory.path().join("input.fifo");
        crate::secure_fs::create_fifo_for_test(&fifo, 0o600).expect("create prepared input FIFO");
        let error = read_prepared_file_bounded(&fifo, 32, "test prepared input")
            .expect_err("prepared input FIFO must fail closed");
        assert!(error.to_string().contains("non-symlink regular file"));
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        reviewed: PathBuf,
        roster: PathBuf,
        manifest: PathBuf,
        pre_sign: PathBuf,
        signed: PathBuf,
        configs: Vec<PathBuf>,
        signer: KeyPair,
        expected_hash: HashOf<BlockHeader>,
    }

    fn fixture() -> Fixture {
        iroha_genesis::init_instruction_registry();
        let directory = tempfile::tempdir().expect("create prepared Kagami fixture directory");
        let signer = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let defaults = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../defaults/kagami/iroha3-dev");
        let sources = [
            defaults.join("peer0.toml"),
            defaults.join("peer1.toml"),
            defaults.join("peer2.toml"),
            defaults.join("peer3.toml"),
        ];
        let mut config_tables = Vec::new();
        let mut config_paths = Vec::new();
        for (index, source) in sources.iter().enumerate() {
            let mut table = std::fs::read_to_string(source)
                .expect("read checked-in prepared-verifier config")
                .parse::<toml::Table>()
                .expect("parse checked-in prepared-verifier config");
            let genesis = table
                .get_mut("genesis")
                .and_then(toml::Value::as_table_mut)
                .expect("fixture config genesis table");
            genesis.insert(
                "public_key".to_owned(),
                toml::Value::String(signer.public_key().to_string()),
            );
            genesis.remove("expected_hash_file");
            // The signed genesis identity exists only after signing, and the config loader
            // rejects an unresolved placeholder. Bind a provisional canonical identity; the
            // final verifier configs below replace it with the exact signed genesis hash.
            genesis.insert(
                "expected_hash".to_owned(),
                toml::Value::String(
                    "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                        .to_owned(),
                ),
            );
            let config_dir = directory
                .path()
                .join(format!("taira-validator-{}", index + 1));
            std::fs::create_dir(&config_dir).expect("create fixture validator directory");
            let path = config_dir.join("config.toml");
            std::fs::write(
                &path,
                toml::to_string_pretty(&table).expect("render prepared-verifier config"),
            )
            .expect("write prepared-verifier config");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("protect prepared-verifier config");
            }
            config_tables.push(table);
            config_paths.push(path);
        }
        let configs = config_paths
            .iter()
            .map(|path| {
                let bytes = std::fs::read(path).expect("read prepared-verifier config");
                super::super::sign::load_peer_config_bytes(path, &bytes)
                    .expect("load prepared-verifier config")
            })
            .collect::<Vec<_>>();
        let _chain_discriminant =
            ChainDiscriminantGuard::enter(*configs[0].common.chain_discriminant.value());
        let validator_bindings = configs
            .iter()
            .enumerate()
            .map(|(index, config)| {
                let public_key = config.common.key_pair.public_key().clone();
                let pop = config
                    .common
                    .trusted_peers
                    .value()
                    .pops
                    .get(&public_key)
                    .cloned()
                    .expect("fixture validator has a PoP");
                ValidatorBinding {
                    slug: format!("taira-validator-{}", index + 1),
                    account_id: AccountId::new(
                        KeyPair::random_with_algorithm(Algorithm::Ed25519)
                            .public_key()
                            .clone(),
                    )
                    .to_string(),
                    public_key,
                    pop_hex: hex::encode(&pop),
                    pop,
                }
            })
            .collect::<Vec<_>>();
        let _author_context = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
            *configs[0].common.chain_discriminant.value(),
        );
        let reviewed = super::super::complete_test_genesis_builder(
            GenesisBuilder::new_without_executor(
                configs[0].common.chain.clone(),
                ".",
                iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                    iroha_crypto::Algorithm::Ed25519,
                    iroha_crypto::Algorithm::Secp256k1,
                    iroha_crypto::Algorithm::BlsNormal,
                ])
                .expect("explicit canonical genesis producer policy"),
            )
            .with_staking_policy(crate::genesis::test_staking_policy())
            .expect("explicit fixture staking policy")
            .append_parameter(Parameter::Custom(
                SumeragiNposParameters::default().into_custom_parameter(),
            ))
            .set_topology(
                validator_bindings
                    .iter()
                    .map(|binding| PeerId::new(binding.public_key.clone()))
                    .collect(),
            ),
        )
        .build_raw()
        .expect("complete prepared-bundle test genesis")
        .with_chain_discriminant(*configs[0].common.chain_discriminant.value())
        .with_consensus_mode(SumeragiConsensusMode::Npos)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
        let reviewed = super::super::sign::tests::with_explicit_test_xor_allocations(
            reviewed,
            &validator_bindings
                .iter()
                .map(|binding| PeerId::new(binding.public_key.clone()))
                .collect::<Vec<_>>(),
        );
        let reviewed_bytes =
            norito::json::to_vec_pretty(&reviewed).expect("encode reviewed fixture manifest");
        let pre_sign_value = expected_pre_sign_value(&reviewed_bytes, &validator_bindings)
            .expect("render fixture validator transform");
        let pre_sign_bytes =
            norito::json::to_vec_pretty(&pre_sign_value).expect("encode pre-sign fixture manifest");
        let rendered_dir = directory.path().join("rendered");
        std::fs::create_dir(&rendered_dir).expect("create signer input directory");
        let signer_input_path = rendered_dir.join("genesis.json");
        let pre_sign =
            RawGenesisTransaction::from_json_slice_at_path(&pre_sign_bytes, &signer_input_path)
                .expect("parse pre-sign fixture with signer path semantics");
        let signer_prepared = super::super::sign::prepare_genesis_for_signing(
            pre_sign,
            Some(&configs[0]),
            SumeragiConsensusMode::Npos,
            None,
            &[],
        )
        .expect("prepare deterministic NPoS signer transform");
        let npos_counts = signer_prepared.instructions().fold(
            (0_usize, 0_usize, 0_usize),
            |(mints, registrations, activations), instruction| {
                (
                    mints + usize::from(instruction.as_any().downcast_ref::<MintBox>().is_some()),
                    registrations
                        + usize::from(
                            instruction
                                .as_any()
                                .downcast_ref::<RegisterPublicLaneValidator>()
                                .is_some(),
                        ),
                    activations
                        + usize::from(
                            instruction
                                .as_any()
                                .downcast_ref::<ActivatePublicLaneValidator>()
                                .is_some(),
                        ),
                )
            },
        );
        assert_eq!(
            npos_counts,
            (
                TAIRA_VALIDATOR_COUNT,
                TAIRA_VALIDATOR_COUNT,
                TAIRA_VALIDATOR_COUNT
            ),
            "fixture must exercise the exact four-validator NPoS bootstrap tail"
        );
        let da_proof_policies = Some(iroha_core::da::proof_policy_bundle(
            &configs[0].nexus.lane_config,
        ));
        let confidential_policy_hash =
            iroha_core::state::default_genesis_confidential_policy_hash();
        let (manifest, sealed_genesis) = super::super::bind_and_sign_staged_sumeragi_context(
            signer_prepared,
            &signer,
            Some(&configs[0]),
            da_proof_policies,
            confidential_policy_hash,
            Some(1_700_000_000_000),
        )
        .expect("bind and sign prepared Kagami fixture");
        let manifest_value = norito::json::value::to_value(&manifest)
            .expect("encode normalized bound fixture manifest");
        let expected_ivm_dir = rendered_dir.join(".").to_string_lossy().into_owned();
        assert_eq!(
            manifest_value
                .as_object()
                .and_then(|object| object.get("ivm_dir"))
                .and_then(norito::json::Value::as_str),
            Some(expected_ivm_dir.as_str()),
            "fixture must exercise the signer's manifest-origin normalization"
        );
        let sealed_genesis = sealed_genesis.0;
        let expected_hash = sealed_genesis.hash();
        for (table, path) in config_tables.iter_mut().zip(&config_paths) {
            table
                .get_mut("genesis")
                .and_then(toml::Value::as_table_mut)
                .expect("fixture config genesis table")
                .insert(
                    "expected_hash".to_owned(),
                    toml::Value::String(norito::literal::format(
                        "hash",
                        &expected_hash.to_string().to_ascii_uppercase(),
                    )),
                );
            std::fs::write(
                path,
                toml::to_string_pretty(table).expect("render final verifier config"),
            )
            .expect("write final verifier config");
        }
        let reviewed_path = directory.path().join("genesis.reviewed.json");
        let roster_path = directory.path().join("validator-roster.toml");
        let manifest_path = directory.path().join("genesis.bound.json");
        let pre_sign_path = directory.path().join("genesis.pre-sign.json");
        let signed_path = directory.path().join("genesis.signed.nrt");
        std::fs::write(&reviewed_path, reviewed_bytes).expect("write reviewed fixture manifest");
        let roster_rows = validator_bindings
            .iter()
            .map(|binding| {
                toml::Value::Table(toml::Table::from_iter([
                    ("slug".to_owned(), toml::Value::String(binding.slug.clone())),
                    (
                        "account_id".to_owned(),
                        toml::Value::String(binding.account_id.clone()),
                    ),
                    (
                        "public_key".to_owned(),
                        toml::Value::String(binding.public_key.to_string()),
                    ),
                    (
                        "pop_hex".to_owned(),
                        toml::Value::String(binding.pop_hex.clone()),
                    ),
                ]))
            })
            .collect();
        let roster_table =
            toml::Table::from_iter([("validators".to_owned(), toml::Value::Array(roster_rows))]);
        std::fs::write(
            &roster_path,
            toml::to_string_pretty(&roster_table).expect("encode fixture validator roster"),
        )
        .expect("write fixture validator roster");
        std::fs::write(
            &manifest_path,
            norito::json::to_vec_pretty(&manifest).expect("encode bound fixture manifest"),
        )
        .expect("write bound fixture manifest");
        std::fs::write(&pre_sign_path, pre_sign_bytes).expect("write pre-sign fixture manifest");
        std::fs::write(
            &signed_path,
            sealed_genesis
                .encode_wire()
                .expect("encode signed fixture genesis"),
        )
        .expect("write signed fixture genesis");
        Fixture {
            _directory: directory,
            reviewed: reviewed_path,
            roster: roster_path,
            manifest: manifest_path,
            pre_sign: pre_sign_path,
            signed: signed_path,
            configs: config_paths,
            signer,
            expected_hash,
        }
    }

    fn run_fixture(fixture: &Fixture) -> Outcome {
        run_fixture_output(fixture, None)
    }

    fn run_fixture_output(fixture: &Fixture, output: Option<PathBuf>) -> Outcome {
        Args {
            reviewed_manifest: fixture.reviewed.clone(),
            validator_roster: fixture.roster.clone(),
            bound_manifest: fixture.manifest.clone(),
            pre_sign_manifest: fixture.pre_sign.clone(),
            signed_genesis: fixture.signed.clone(),
            peer_configs: fixture.configs.clone(),
            genesis_public_key: fixture.signer.public_key().clone(),
            expected_hash: fixture.expected_hash,
            nexus_context_output: output,
        }
        .run(&mut BufWriter::new(Vec::<u8>::new()))
    }

    #[test]
    fn prepared_verifier_exports_exact_context_without_replacement() {
        let fixture = fixture();
        let output = fixture.signed.with_file_name("nexus-amx-context.v1.bin");
        run_fixture_output(&fixture, Some(output.clone())).expect("export verified context");
        let preimage = std::fs::read(&output).expect("read exported context");
        let signed = iroha_data_model::block::decode_framed_signed_block(
            &std::fs::read(&fixture.signed).expect("read signed original"),
        )
        .expect("decode signed original");
        let metadata =
            iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(&signed)
                .expect("signed genesis metadata");
        assert_eq!(
            Hash::new(&preimage),
            Hash::prehashed(metadata.sumeragi_context.nexus_amx_context_hash)
        );
        iroha_data_model::nexus::decode_nexus_amx_context_v1(&preimage).expect("strict context");
        assert!(run_fixture_output(&fixture, Some(output.clone())).is_err());
        assert_eq!(std::fs::read(output).unwrap(), preimage);
    }

    #[test]
    fn prepared_verifier_accepts_exact_bundle_and_rejects_signed_divergence() {
        let fixture = fixture();
        run_fixture(&fixture).expect("accept exact prepared genesis bundle");

        let original_reviewed = std::fs::read(&fixture.reviewed).expect("read reviewed fixture");
        let mut generic_reviewed: norito::json::Value =
            norito::json::from_slice(&original_reviewed).expect("parse reviewed fixture");
        generic_reviewed
            .as_object_mut()
            .expect("reviewed fixture object")
            .insert(
                "chain".to_owned(),
                norito::json::Value::String("generic-substitution-chain".to_owned()),
            );
        std::fs::write(
            &fixture.reviewed,
            norito::json::to_vec_pretty(&generic_reviewed)
                .expect("encode generic reviewed fixture"),
        )
        .expect("write generic reviewed fixture");
        let transform_error =
            run_fixture(&fixture).expect_err("reject generic reviewed-genesis substitution");
        assert!(transform_error.to_string().contains("renderer transform"));
        std::fs::write(&fixture.reviewed, original_reviewed).expect("restore reviewed fixture");

        let original_roster =
            std::fs::read_to_string(&fixture.roster).expect("read roster fixture");
        let mut spliced_roster = original_roster
            .parse::<toml::Table>()
            .expect("parse roster fixture");
        let reviewed_manifest = RawGenesisTransaction::from_json_slice(
            &std::fs::read(&fixture.reviewed).expect("reread reviewed fixture"),
        )
        .expect("parse restored reviewed fixture");
        let _chain_discriminant =
            ChainDiscriminantGuard::enter(reviewed_manifest.chain_discriminant());
        let replacement_account = AccountId::new(
            KeyPair::random_with_algorithm(Algorithm::Ed25519)
                .public_key()
                .clone(),
        )
        .to_string();
        spliced_roster
            .get_mut("validators")
            .and_then(toml::Value::as_array_mut)
            .and_then(|validators| validators.get_mut(1))
            .and_then(toml::Value::as_table_mut)
            .expect("second validator roster table")
            .insert(
                "account_id".to_owned(),
                toml::Value::String(replacement_account),
            );
        std::fs::write(
            &fixture.roster,
            toml::to_string_pretty(&spliced_roster).expect("encode spliced roster fixture"),
        )
        .expect("write spliced roster fixture");
        let roster_error = run_fixture(&fixture)
            .expect_err("reject a payout-account splice in the public validator roster");
        assert!(roster_error.to_string().contains("renderer transform"));
        std::fs::write(&fixture.roster, original_roster).expect("restore roster fixture");

        let original_manifest = std::fs::read(&fixture.manifest).expect("read bound fixture");
        let mut spliced_manifest: norito::json::Value =
            norito::json::from_slice(&original_manifest).expect("parse bound fixture");
        let bootstrap_instructions = spliced_manifest
            .as_object_mut()
            .expect("bound fixture object")
            .get_mut("transactions")
            .and_then(norito::json::Value::as_array_mut)
            .and_then(|transactions| transactions.last_mut())
            .and_then(norito::json::Value::as_object_mut)
            .and_then(|transaction| transaction.get_mut("instructions"))
            .and_then(norito::json::Value::as_array_mut)
            .expect("bound fixture NPoS bootstrap instructions");
        let registration_index = bootstrap_instructions
            .iter()
            .position(|instruction| {
                instruction
                    .as_object()
                    .is_some_and(|object| object.contains_key("RegisterPublicLaneValidator"))
            })
            .expect("bound fixture validator registration");
        bootstrap_instructions.remove(registration_index);
        std::fs::write(
            &fixture.manifest,
            norito::json::to_vec_pretty(&spliced_manifest).expect("encode spliced bound fixture"),
        )
        .expect("write spliced bound fixture");
        let bound_error = run_fixture(&fixture)
            .expect_err("reject a missing deterministic NPoS bootstrap instruction");
        assert!(bound_error.to_string().contains("staged-context transform"));
        std::fs::write(&fixture.manifest, original_manifest).expect("restore bound fixture");

        let original_manifest = std::fs::read(&fixture.manifest).expect("reread bound fixture");
        let mut wrong_origin: norito::json::Value =
            norito::json::from_slice(&original_manifest).expect("parse restored bound fixture");
        wrong_origin
            .as_object_mut()
            .expect("bound fixture object")
            .insert(
                "ivm_dir".to_owned(),
                norito::json::Value::String(".".to_owned()),
            );
        std::fs::write(
            &fixture.manifest,
            norito::json::to_vec_pretty(&wrong_origin).expect("encode wrong-origin bound fixture"),
        )
        .expect("write wrong-origin bound fixture");
        let origin_error = run_fixture(&fixture)
            .expect_err("reject a bound manifest with signer path normalization removed");
        assert!(
            origin_error
                .to_string()
                .contains("staged-context transform")
        );
        std::fs::write(&fixture.manifest, original_manifest).expect("restore bound fixture");

        let original_context = RawGenesisTransaction::from_path(&fixture.manifest)
            .expect("read original bound policy")
            .sumeragi_context_parameters();
        for config_index in 1..TAIRA_VALIDATOR_COUNT {
            let config_path = &fixture.configs[config_index];
            let original_config = std::fs::read_to_string(config_path).expect("read peer config");
            let mut drifted_config = original_config
                .parse::<toml::Table>()
                .expect("parse peer config");
            // A node-local policy value the signed context binds. The pipeline
            // execution limits are committed chain policy and are not keys of
            // a peer configuration.
            let mut rotation = &mut drifted_config;
            for section in ["nexus", "da", "rotation"] {
                rotation = rotation
                    .entry(section)
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                    .as_table_mut()
                    .expect("peer config Nexus DA rotation table");
            }
            rotation.insert("window_slots".to_owned(), toml::Value::Integer(65));
            std::fs::write(
                config_path,
                toml::to_string_pretty(&drifted_config).expect("render drifted peer config"),
            )
            .expect("write drifted peer config");
            let context_error = run_fixture(&fixture)
                .expect_err("reject effective policy drift from signed context");
            let Some(iroha_core::block::BlockValidationError::GenesisPolicyMismatch {
                expected_execution,
                actual_execution,
                expected_nexus,
                actual_nexus,
            }) = context_error.downcast_ref::<iroha_core::block::BlockValidationError>()
            else {
                panic!("unexpected original policy drift refusal: {context_error:#}");
            };
            assert_eq!(
                *expected_nexus,
                Hash::prehashed(original_context.nexus_amx_context_hash)
            );
            assert_eq!(
                *expected_execution,
                Hash::prehashed(original_context.execution_policy_hash)
            );
            assert_ne!(actual_nexus, expected_nexus);
            assert_ne!(actual_execution, expected_execution);
            std::fs::write(config_path, original_config).expect("restore peer config");
        }

        let mut mutated = std::fs::read(&fixture.signed).expect("read signed fixture");
        mutated.push(0);
        std::fs::write(&fixture.signed, mutated).expect("mutate signed fixture");
        let _error =
            run_fixture(&fixture).expect_err("reject a non-canonical signed-genesis mutation");
    }
}
