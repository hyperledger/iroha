mod amx;
use super::require_native_wire_protocol;
use crate::{Outcome, RunArgs, genesis::reject_retired_public_chain_id, tui};
use clap::Parser;
use color_eyre::eyre::{WrapErr, eyre};
#[cfg(test)]
use iroha_config::parameters::defaults;
use iroha_config::{base::toml::TomlSource, parameters::actual};
#[cfg(test)]
use iroha_crypto::Hash;
use iroha_crypto::{ExposedPrivateKey, KeyPair, PublicKey};
#[cfg(test)]
use iroha_data_model::account::address::ChainDiscriminantGuard;
use iroha_data_model::{
    da::commitment::DaProofPolicyBundle, isi::RegisterPublicLaneValidator,
    nexus::PublicLaneMonetaryPlanV1, parameter::system::SumeragiConsensusMode, prelude::*,
    sumeragi::epoch::MAX_VALIDATORS,
};
use iroha_deploy::genesis::staging::{
    bind_and_sign_staged_sumeragi_context_with_preimage, configured_npos_bootstrap_stake_asset_id,
    ensure_peer_config_matches_manifest, staged_default_nexus, staged_genesis_chain_discriminant,
};
#[cfg(test)]
use iroha_deploy::genesis::staging::{
    build_signed_genesis, configured_initial_genesis_state, retired_synthetic_stake_asset_id,
    staged_default_account_literal, staged_default_pipeline, staged_lane_manifest_registry,
    staged_signed_native_genesis, staged_signed_native_genesis_with_projection,
    staged_signed_sumeragi_context_hashes,
};
#[cfg(test)]
use iroha_genesis::GenesisBlock;
use iroha_genesis::{
    GenesisBuilder, GenesisTopologyEntry, RawGenesisTransaction, SIGNED_GENESIS_MAX_BYTES_V1,
    validate_genesis_manifest_json,
};
#[cfg(test)]
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::LaneId;
#[cfg(test)]
use std::sync::Arc;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize as _, Zeroizing};
/// Sign the genesis block
#[derive(Parser)]
pub struct Args {
    /// Path to genesis json file
    genesis_file: PathBuf,
    /// Path to signed genesis output file in canonical Norito wire format (stdout by default).
    #[clap(short, long, value_name("PATH"))]
    out_file: Option<PathBuf>,
    /// Persist the exact config-bound genesis manifest used to build the signed block.
    /// May point to `GENESIS_FILE` to replace the input only after binding succeeds.
    #[clap(long, value_name = "PATH")]
    bound_manifest_out: Option<PathBuf>,
    /// Write the canonical checked NetworkId derived from the exact signed consensus-header hash
    /// as one line.
    ///
    /// Validators and clients must select this same file through `genesis.expected_hash_file` and
    /// `network_id_file`, respectively.
    #[clap(long, value_name = "PATH")]
    expected_hash_out: Option<PathBuf>,
    /// Publish the exact Nexus/AMX context preimage whose hash the signed genesis commits
    /// (`nexus-amx-context.v1.bin`). Validators and public reset inputs consume these bytes.
    #[clap(long, value_name = "PATH")]
    nexus_context_output: Option<PathBuf>,
    /// Reserve the final SCCP network identity in the same history used during
    /// genesis generation. Rejects an unreserved nonce or any previously signed reset identity.
    #[clap(long, value_name = "PATH")]
    sccp_reset_history: Option<PathBuf>,
    /// Reserve a fresh SCCP reset nonce before signing a revised genesis.
    /// Requires the durable history; use when reseating a previously signed network.
    #[clap(long, requires = "sccp_reset_history")]
    fresh_sccp_reset_nonce: bool,
    /// Replace the expected-hash file only if it still contains this exact prior NetworkId.
    /// Requires all four output paths. The identity is published last as the bundle's commit
    /// marker; interrupted publication must be retried with the same prior identity.
    #[clap(long, value_name = "NETWORK_ID", requires_all = ["expected_hash_out", "out_file", "bound_manifest_out", "nexus_context_output"])]
    replace_expected_hash: Option<NetworkId>,
    /// Use this topology instead of specified in genesis.json.
    /// JSON-serialized vector of `PeerId`. For use in `iroha_swarm`.
    ///
    /// The final unique topology must be an exact Sumeragi `3f + 1`
    /// committee in the range 4..=31.
    #[clap(short, long)]
    topology: Option<String>,
    /// Embed one or more PoPs into the same transaction as `--topology`.
    /// Repeatable flag: `--peer-pop <public_key=pop_hex>`
    #[clap(long = "peer-pop")]
    peer_pops: Vec<String>,
    /// Owner-held mode-0600 file containing one canonical private-key multihash.
    #[clap(long, value_name = "PATH")]
    private_key_file: PathBuf,
    /// Public key that the selected private key must derive.
    ///
    /// Use this when the verifier key is distributed separately from the
    /// owner-held signing key, such as through container secrets.
    #[clap(long, value_name = "PUBLIC_KEY")]
    expected_public_key: Option<PublicKey>,
    /// Deterministic genesis transaction creation-time base in Unix milliseconds.
    ///
    /// Omit this for a fresh wall-clock timestamp. Fixture generators should
    /// set it so repeated signing produces identical canonical wire bytes.
    #[clap(long, value_name = "MILLISECONDS")]
    creation_time_ms: Option<u64>,
    /// Explicit complete global source pair for native AMX participant bootstrap.
    #[clap(flatten)]
    amx: amx::Args,
    /// Optional peer config TOML used to derive the DA proof-policy bundle embedded into genesis.
    #[clap(long, value_name = "PATH")]
    config: Option<PathBuf>,
}
const DEFAULT_NPOS_BOOTSTRAP_STAKE_AMOUNT: u64 = 10_000;
const MAX_GENESIS_NETWORK_IDENTITY_BYTES: u64 = 4 * 1024;
struct ResolvedArtifactPaths {
    genesis_input: PathBuf,
    signed_output: Option<PathBuf>,
    bound_manifest_output: Option<PathBuf>,
    expected_hash_output: Option<PathBuf>,
    nexus_context_output: Option<PathBuf>,
}

impl ResolvedArtifactPaths {
    /// Every requested output, labelled for alias diagnostics.
    fn outputs(&self) -> [(&'static str, Option<&Path>); 4] {
        [
            ("signed genesis output", self.signed_output.as_deref()),
            (
                "bound manifest output",
                self.bound_manifest_output.as_deref(),
            ),
            (
                "genesis expected-hash output",
                self.expected_hash_output.as_deref(),
            ),
            (
                "Nexus AMX context output",
                self.nexus_context_output.as_deref(),
            ),
        ]
    }
}

fn artifact_paths_alias(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    matches!(
        (fs::metadata(left), fs::metadata(right)),
        (Ok(left), Ok(right)) if crate::secure_fs::same_file_identity(&left, &right)
    )
}

fn reject_artifact_alias(
    left_label: &str,
    left: Option<&Path>,
    right_label: &str,
    right: Option<&Path>,
) -> Result<(), color_eyre::eyre::Error> {
    if let (Some(left), Some(right)) = (left, right)
        && artifact_paths_alias(left, right)
    {
        return Err(eyre!(
            "{left_label} and {right_label} must use different paths"
        ));
    }
    Ok(())
}

fn resolve_artifact_paths(args: &Args) -> Result<ResolvedArtifactPaths, color_eyre::eyre::Error> {
    if args.fresh_sccp_reset_nonce && args.sccp_reset_history.is_none() {
        return Err(eyre!(
            "--fresh-sccp-reset-nonce requires --sccp-reset-history"
        ));
    }
    if args.replace_expected_hash.is_some()
        && (args.expected_hash_out.is_none()
            || args.out_file.is_none()
            || args.bound_manifest_out.is_none()
            || args.nexus_context_output.is_none())
    {
        return Err(eyre!(
            "--replace-expected-hash requires --expected-hash-out, --out-file, --bound-manifest-out, and --nexus-context-output"
        ));
    }
    let genesis_input = fs::canonicalize(&args.genesis_file).wrap_err_with(|| {
        format!(
            "resolve input genesis manifest {}",
            args.genesis_file.display()
        )
    })?;
    let resolve = |path: Option<&Path>, label: &str| {
        path.map(crate::atomic_output::resolve_output_file)
            .transpose()
            .wrap_err_with(|| format!("resolve {label}"))
    };
    let resolved = ResolvedArtifactPaths {
        genesis_input,
        signed_output: resolve(args.out_file.as_deref(), "signed genesis output")?,
        bound_manifest_output: resolve(
            args.bound_manifest_out.as_deref(),
            "config-bound genesis manifest output",
        )?,
        expected_hash_output: resolve(
            args.expected_hash_out.as_deref(),
            "genesis expected-hash output",
        )?,
        nexus_context_output: resolve(
            args.nexus_context_output.as_deref(),
            "Nexus AMX context output",
        )?,
    };

    let outputs = resolved.outputs();
    // The bound manifest may intentionally replace its input; every other output may not.
    for (label, output) in outputs {
        if label != "bound manifest output" {
            reject_artifact_alias(
                label,
                output,
                "input genesis manifest",
                Some(&resolved.genesis_input),
            )?;
        }
    }
    for (index, (left_label, left)) in outputs.iter().enumerate() {
        for (right_label, right) in &outputs[index + 1..] {
            reject_artifact_alias(left_label, *left, right_label, *right)?;
        }
    }

    for (label, input) in [
        ("genesis signing key", Some(args.private_key_file.as_path())),
        ("peer configuration", args.config.as_deref()),
    ] {
        let Some(input) = input else {
            continue;
        };
        let input = fs::canonicalize(input)
            .wrap_err_with(|| format!("resolve protected {label} input {}", input.display()))?;
        for (output_label, output) in outputs {
            reject_artifact_alias(output_label, output, label, Some(&input))?;
        }
    }

    Ok(resolved)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenesisNetworkIdentityTarget {
    Missing,
    Exact,
}
fn genesis_network_identity_body(network_id: NetworkId) -> String {
    format!("{network_id}\n")
}
fn read_existing_genesis_network_identity(
    path: &Path,
) -> Result<Option<Vec<u8>>, color_eyre::eyre::Error> {
    Ok(open_existing_genesis_network_identity(path)?.map(|held| held.bytes))
}

struct GenesisNetworkIdentityGuard {
    file: File,
    snapshot: fs::Metadata,
    bytes: Vec<u8>,
}

impl GenesisNetworkIdentityGuard {
    /// All publishers of signed/manifest outputs use the same existing-identity lock.
    fn acquire(path: &Path) -> Result<Option<Self>, color_eyre::eyre::Error> {
        let Some(mut held) = open_existing_genesis_network_identity(path)? else {
            return Ok(None);
        };
        #[cfg(unix)]
        rustix::fs::flock(
            &held.file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .wrap_err("another genesis publisher holds the expected-hash file")?;
        held.revalidate(path)?;
        Ok(Some(held))
    }

    fn require_identity(&self, expected: NetworkId) -> Outcome {
        if self.bytes != genesis_network_identity_body(expected).as_bytes() {
            return Err(eyre!(
                "genesis expected-hash file does not match the required prior NetworkId"
            ));
        }
        Ok(())
    }

    fn revalidate(&mut self, path: &Path) -> Outcome {
        use std::io::{Read as _, Seek as _};

        let current = open_existing_genesis_network_identity(path)?
            .ok_or_else(|| eyre!("held genesis expected-hash file disappeared"))?;
        if !crate::secure_fs::same_file_snapshot(&self.snapshot, &current.snapshot)
            || self.bytes != current.bytes
        {
            return Err(eyre!("held genesis expected-hash path or contents changed"));
        }
        self.file
            .rewind()
            .wrap_err("rewind held genesis expected-hash file")?;
        let mut bytes = Vec::with_capacity(self.bytes.len());
        std::io::Read::by_ref(&mut self.file)
            .take(MAX_GENESIS_NETWORK_IDENTITY_BYTES + 1)
            .read_to_end(&mut bytes)
            .wrap_err("reread held genesis expected-hash file")?;
        if bytes != self.bytes
            || !crate::secure_fs::same_file_snapshot(&self.snapshot, &self.file.metadata()?)
        {
            return Err(eyre!(
                "held genesis expected-hash inode or contents changed"
            ));
        }
        Ok(())
    }

    fn publish_replacement(&mut self, path: &Path, temporary: tempfile::NamedTempFile) -> Outcome {
        self.revalidate(path)?;
        // No signed/manifest writes may follow this rename: the lock remains attached to the
        // prior inode, while a subsequent publisher can now lock the new identity inode.
        publish_staged_genesis_output(temporary, path, "replacement genesis network identity")
    }
}

fn open_existing_genesis_network_identity(
    path: &Path,
) -> Result<Option<GenesisNetworkIdentityGuard>, color_eyre::eyre::Error> {
    let lexical = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).wrap_err_with(|| {
                format!("inspect genesis network identity output {}", path.display())
            });
        }
    };
    #[cfg(not(unix))]
    return Err(eyre!(
        "existing genesis network identity {} requires owner-held file custody, which Kagami cannot verify on this platform",
        path.display()
    ));
    #[cfg(unix)]
    {
        use std::io::Read as _;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let mut file = options.open(path).wrap_err_with(|| {
            format!("open existing genesis network identity {}", path.display())
        })?;
        let before = file.metadata().wrap_err_with(|| {
            format!("inspect opened genesis network identity {}", path.display())
        })?;
        if lexical.file_type().is_symlink()
            || !before.is_file()
            || !crate::secure_fs::same_file_snapshot(&lexical, &before)
        {
            return Err(eyre!(
                "genesis network identity output changed while opening or is not a regular file: {}",
                path.display()
            ));
        }
        if before.uid() != rustix::process::geteuid().as_raw()
            || before.nlink() != 1
            || before.mode() & 0o022 != 0
        {
            return Err(eyre!(
                "genesis network identity output must be owner-held, single-link, and not group/world writable: {}",
                path.display()
            ));
        }
        if before.len() > MAX_GENESIS_NETWORK_IDENTITY_BYTES {
            return Err(eyre!(
                "existing genesis network identity exceeds the {MAX_GENESIS_NETWORK_IDENTITY_BYTES}-byte limit: {}",
                path.display()
            ));
        }
        let mut existing = Vec::with_capacity(
            usize::try_from(before.len())
                .map_err(|_| eyre!("genesis network identity length is not addressable"))?,
        );
        std::io::Read::by_ref(&mut file)
            .take(MAX_GENESIS_NETWORK_IDENTITY_BYTES + 1)
            .read_to_end(&mut existing)
            .wrap_err_with(|| {
                format!("read existing genesis network identity {}", path.display())
            })?;
        let after = file
            .metadata()
            .wrap_err_with(|| format!("reinspect genesis network identity {}", path.display()))?;
        if !crate::secure_fs::same_file_snapshot(&before, &after)
            || u64::try_from(existing.len()).ok() != Some(before.len())
        {
            return Err(eyre!(
                "genesis network identity output changed while being read: {}",
                path.display()
            ));
        }
        Ok(Some(GenesisNetworkIdentityGuard {
            file,
            snapshot: after,
            bytes: existing,
        }))
    }
}
fn preflight_genesis_network_identity(
    path: &Path,
    network_id: NetworkId,
) -> Result<GenesisNetworkIdentityTarget, color_eyre::eyre::Error> {
    let body = genesis_network_identity_body(network_id);
    if body.len() as u64 > MAX_GENESIS_NETWORK_IDENTITY_BYTES {
        return Err(eyre!(
            "generated genesis network identity exceeds the {MAX_GENESIS_NETWORK_IDENTITY_BYTES}-byte limit"
        ));
    }
    let Some(existing) = read_existing_genesis_network_identity(path)? else {
        return Ok(GenesisNetworkIdentityTarget::Missing);
    };
    if existing != body.as_bytes() {
        return Err(eyre!(
            "refusing to replace a different genesis network identity: {}",
            path.display()
        ));
    }
    Ok(GenesisNetworkIdentityTarget::Exact)
}
fn publish_genesis_network_identity(path: &Path, network_id: NetworkId) -> Outcome {
    let body = genesis_network_identity_body(network_id);
    if preflight_genesis_network_identity(path, network_id)? == GenesisNetworkIdentityTarget::Exact
    {
        return Ok(());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".genesis-identity-")
        .tempfile_in(parent)
        .wrap_err_with(|| {
            format!(
                "create temporary genesis network identity beside {}",
                path.display()
            )
        })?;
    temporary
        .write_all(body.as_bytes())
        .wrap_err("write temporary genesis network identity")?;
    temporary
        .flush()
        .wrap_err("flush temporary genesis network identity")?;
    temporary
        .as_file()
        .sync_all()
        .wrap_err("sync temporary genesis network identity")?;
    match temporary.persist_noclobber(path) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            let Some(existing) = read_existing_genesis_network_identity(path)? else {
                return Err(eyre!(
                    "raced genesis network identity disappeared: {}",
                    path.display()
                ));
            };
            if existing != body.as_bytes() {
                return Err(eyre!(
                    "refusing raced genesis network identity with different contents: {}",
                    path.display()
                ));
            }
        }
        Err(error) => {
            return Err(error.error).wrap_err_with(|| {
                format!(
                    "publish genesis network identity atomically to {}",
                    path.display()
                )
            });
        }
    }
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .wrap_err_with(|| {
            format!(
                "sync genesis network identity directory {}",
                parent.display()
            )
        })?;
    Ok(())
}
fn stage_genesis_output(
    path: &Path,
    bytes: &[u8],
    label: &str,
) -> Result<tempfile::NamedTempFile, color_eyre::eyre::Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".genesis-output-")
        .tempfile_in(parent)
        .wrap_err_with(|| format!("stage {label} beside {}", path.display()))?;
    temporary
        .write_all(bytes)
        .wrap_err_with(|| format!("write staged {label} for {}", path.display()))?;
    temporary
        .flush()
        .wrap_err_with(|| format!("flush staged {label} for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .wrap_err_with(|| format!("sync staged {label} for {}", path.display()))?;
    Ok(temporary)
}

fn publish_guarded_genesis_bundle(
    guard: &mut GenesisNetworkIdentityGuard,
    identity_path: &Path,
    outputs: [(&Path, tempfile::NamedTempFile, &str); 3],
    identity: tempfile::NamedTempFile,
) -> Outcome {
    for (path, temporary, label) in outputs {
        guard.revalidate(identity_path)?;
        publish_staged_genesis_output(temporary, path, label)?;
    }
    // This is a commit marker, not a multi-file transaction. An interrupted earlier
    // output write leaves the prior identity in place; consumers reject disagreement.
    guard.publish_replacement(identity_path, identity)
}
fn publish_staged_genesis_output(
    temporary: tempfile::NamedTempFile,
    path: &Path,
    label: &str,
) -> Outcome {
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .wrap_err_with(|| format!("publish staged {label} to {}", path.display()))?;
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .wrap_err_with(|| format!("sync {label} directory {}", parent.display()))?;
    }
    Ok(())
}
struct BootstrapRegistrations {
    accounts: BTreeSet<AccountId>,
    asset_defs: BTreeSet<AssetDefinitionId>,
}
impl BootstrapRegistrations {
    fn from_manifest(manifest: &RawGenesisTransaction) -> Self {
        let mut accounts = BTreeSet::new();
        let mut asset_defs = BTreeSet::new();
        for instruction in manifest.instructions() {
            if let Some(register) = instruction.as_any().downcast_ref::<Register<Account>>() {
                accounts.insert(register.object.id.clone());
                continue;
            }
            if let Some(register) = instruction
                .as_any()
                .downcast_ref::<Register<AssetDefinition>>()
            {
                asset_defs.insert(register.object.id.clone());
                continue;
            }
            if let Some(register) = instruction
                .as_any()
                .downcast_ref::<iroha_data_model::isi::register::RegisterBox>()
            {
                match register {
                    iroha_data_model::isi::register::RegisterBox::Account(register) => {
                        accounts.insert(register.object.id.clone());
                    }
                    iroha_data_model::isi::register::RegisterBox::AssetDefinition(register) => {
                        asset_defs.insert(register.object.id.clone());
                    }
                    _ => {}
                }
            }
        }
        Self {
            accounts,
            asset_defs,
        }
    }
}
fn manifest_has_npos_bootstrap(manifest: &RawGenesisTransaction) -> bool {
    manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<RegisterPublicLaneValidator>()
            .is_some()
            || instruction
                .as_any()
                .downcast_ref::<ActivatePublicLaneValidator>()
                .is_some()
    })
}
fn collect_topology_peers(manifest: &RawGenesisTransaction) -> Vec<PeerId> {
    let mut peers = Vec::new();
    for tx in manifest.transactions() {
        for entry in tx.topology() {
            peers.push(entry.peer.clone());
        }
    }
    peers
}
fn configured_npos_bootstrap_escrow_account_id(
    manifest: &RawGenesisTransaction,
    config: Option<&actual::Root>,
) -> Result<AccountId, color_eyre::eyre::Error> {
    let literal = if let Some(config) = config {
        config.nexus.staking.stake_escrow_account_id.clone()
    } else {
        staged_default_nexus(manifest)?
            .staking
            .stake_escrow_account_id
    };
    AccountId::parse_encoded(&literal)
        .map_err(|error| {
            eyre!(
                "NPoS auto-bootstrap requires `nexus.staking.stake_escrow_account_id` to be a canonical account literal, found `{literal}`: {error}"
            )
        })
}
fn append_npos_bootstrap(
    builder: GenesisBuilder,
    registrations: &mut BootstrapRegistrations,
    topology: &[PeerId],
    escrow_account_id: &AccountId,
    stake_asset_id: &AssetDefinitionId,
) -> Result<GenesisBuilder, color_eyre::eyre::Error> {
    if topology.is_empty() {
        return Ok(builder);
    }
    if !registrations.asset_defs.contains(stake_asset_id) {
        return Err(eyre!(
            "NPoS bootstrap requires the genesis XOR definition `{stake_asset_id}` and explicit validator allocations before signing"
        ));
    }
    let mut builder = builder.next_transaction();
    if !registrations.accounts.contains(escrow_account_id) {
        builder =
            builder.append_instruction(Register::account(Account::new(escrow_account_id.clone())));
        registrations.accounts.insert(escrow_account_id.clone());
    }
    for peer in topology {
        let validator_id = AccountId::new(peer.public_key().clone());
        if !registrations.accounts.contains(&validator_id) {
            return Err(eyre!(
                "NPoS validator `{validator_id}` must be registered and explicitly funded with XOR in genesis before signing"
            ));
        }
        builder = builder.append_instruction(RegisterPublicLaneValidator {
            lane_id: LaneId::SINGLE,
            validator: validator_id.clone(),
            peer_id: peer.clone(),
            stake_account: validator_id.clone(),
            initial_stake: iroha_primitives::numeric::Quantity::from(
                DEFAULT_NPOS_BOOTSTRAP_STAKE_AMOUNT,
            ),
            metadata: Metadata::default(),
            monetary_plan: PublicLaneMonetaryPlanV1::genesis_registration(
                AssetId::new(stake_asset_id.clone(), validator_id.clone()),
                AssetId::new(stake_asset_id.clone(), escrow_account_id.clone()),
                DEFAULT_NPOS_BOOTSTRAP_STAKE_AMOUNT.into(),
            ),
        });
        builder = builder.append_instruction(ActivatePublicLaneValidator {
            lane_id: LaneId::SINGLE,
            validator: validator_id,
        });
    }
    Ok(builder)
}
#[cfg(test)]
pub(super) fn load_peer_config(
    config_path: &Path,
) -> Result<actual::Root, color_eyre::eyre::Error> {
    let config_bytes = Zeroizing::new(
        crate::secure_fs::read_private_file(config_path)
            .wrap_err_with(|| format!("read owner-only peer config {}", config_path.display()))?,
    );
    load_peer_config_bytes(config_path, &config_bytes)
}

/// Parse a peer config from the exact bytes already hashed by an admission caller.
pub(super) fn load_peer_config_bytes(
    config_path: &Path,
    config_bytes: &[u8],
) -> Result<actual::Root, color_eyre::eyre::Error> {
    let source_text = std::str::from_utf8(config_bytes).map_err(|error| {
        eyre!(
            "peer config at {} is not UTF-8: {error}",
            config_path.display()
        )
    })?;
    let description = format!("peer config {}", config_path.display());
    let table = crate::secret_toml::parse_table(source_text, &description)?;
    load_peer_config_user(config_path, table)?
        .parse()
        .map_err(|_| eyre!("peer config {} is invalid", config_path.display()))
}

/// Use the node's loader for the exact retained source, including profile and data-dir layout.
fn load_peer_config_user(
    config_path: &Path,
    table: toml::Table,
) -> Result<iroha_config::parameters::user::Root, color_eyre::eyre::Error> {
    use iroha_config::node_config::{NodeConfigOptions, open_node_config_source};
    let source = TomlSource::new_sensitive(
        config_path.to_path_buf(),
        table,
        crate::secret_toml::zeroize_table,
    );
    let node = open_node_config_source(source, NodeConfigOptions::default()).map_err(|_| {
        eyre!(
            "peer config {} has an invalid node layout",
            config_path.display()
        )
    })?;
    let (user, _) = node
        .read()
        .map_err(|_| eyre!("peer config {} is invalid", config_path.display()))?;
    Ok(user)
}
/// Load one complete signing input. Absence of both runtime identity fields selects the
/// distinct unpublished context; a supplied identity is always parsed by the strict runtime
/// parser. A failed runtime parse never falls back to an unpublished context.
fn load_peer_config_for_signing(
    config_path: &Path,
    genesis: &RawGenesisTransaction,
    key: &KeyPair,
    creation_time_ms: Option<u64>,
) -> Result<actual::Root, color_eyre::eyre::Error> {
    let config_bytes = Zeroizing::new(
        crate::secure_fs::read_private_file(config_path)
            .wrap_err("read owner-only complete genesis signing config")?,
    );
    let text = std::str::from_utf8(&config_bytes)
        .map_err(|_| eyre!("genesis signing config is not UTF-8"))?;
    let table = crate::secret_toml::parse_table(text, "genesis signing config")?;
    let user = load_peer_config_user(config_path, table)?;
    if user.has_genesis_identity() {
        let config = user
            .parse()
            .map_err(|_| eyre!("runtime genesis signing config is invalid"))?;
        return Ok(config);
    }
    let context = user
        .parse_for_genesis_signing()
        .map_err(|_| eyre!("unpublished genesis signing policy is invalid"))?;
    let provisional = iroha_deploy::genesis::staging::build_signed_genesis(
        genesis.clone(),
        key,
        Some(iroha_core::da::proof_policy_bundle(
            &context.nexus().lane_config,
        )),
        iroha_core::state::default_genesis_confidential_policy_hash(),
        creation_time_ms,
    )
    .wrap_err("construct original provisional signed genesis for policy binding")?;
    context
        .bind_signed_genesis(&provisional.0)
        .map_err(|message| eyre!(message))
}
/// Execute an independently prepared genesis with its exact original node configuration and
/// known fixture custody. No provisional block, alternate epoch, or synthetic result enters
/// the production native worker.
#[cfg(test)]
pub fn prepared_native_test_chain(
    genesis: iroha_genesis::ValidatedGenesisBundle,
    manifest: &RawGenesisTransaction,
    config: &actual::Root,
    validator_keys: Vec<KeyPair>,
    clock: KeyPair,
    lane_blocks: Arc<dyn iroha_core::sumeragi::lanes::merge::LaneBlockSource>,
) -> Result<iroha_core::sumeragi::test_chain::CertifiedTestChain, color_eyre::eyre::Error> {
    ensure_peer_config_matches_manifest(config, manifest)?;
    if genesis.public_key() != &config.genesis.public_key
        || genesis.expected_hash() != config.genesis.expected_hash
    {
        return Err(eyre!(
            "native fixture config changes its exact prepared genesis"
        ));
    }
    let _discriminant = staged_genesis_chain_discriminant(manifest);
    let (state, kura, _) = configured_initial_genesis_state(
        manifest,
        Some(config),
        &GenesisBlock(genesis.block().clone()),
    )?;
    iroha_core::sumeragi::test_chain::CertifiedTestChain::from_prepared(
        iroha_core::sumeragi::test_chain::PreparedTestChainConfig {
            genesis,
            manifest: manifest.clone(),
            state: Arc::new(state),
            kura,
            validator_keys,
            clock,
            lane_blocks,
        },
    )
    .map_err(|failure| {
        eyre!(
            "execute original prepared native fixture: {}",
            failure.error
        )
    })
}

fn should_auto_bootstrap_npos_validators(config: Option<&actual::Root>) -> bool {
    let Some(config) = config else {
        return true;
    };
    matches!(
        config
            .nexus
            .staking
            .validator_mode(LaneId::SINGLE, &config.nexus.lane_catalog),
        actual::LaneValidatorMode::StakeElected
    )
}

/// Apply the exact deterministic manifest preparation performed before staged-context binding.
///
/// The external signer and prepared-bundle admission both use this function so topology handling,
/// NPoS validator bootstrap, consensus metadata, and configured stake semantics cannot drift.
pub(super) fn prepare_genesis_for_signing(
    mut genesis: RawGenesisTransaction,
    config: Option<&actual::Root>,
    consensus_mode: SumeragiConsensusMode,
    topology_override: Option<&[PeerId]>,
    peer_pops: &[String],
) -> Result<RawGenesisTransaction, color_eyre::eyre::Error> {
    let _chain_discriminant = staged_genesis_chain_discriminant(&genesis);
    if let Some(config) = config {
        ensure_peer_config_matches_manifest(config, &genesis)?;
    }
    require_native_wire_protocol(&genesis)?;
    if topology_override.is_some() {
        genesis = genesis.clear_topology();
    }
    super::ensure_genesis_schedule_matches_consensus(&genesis)?;
    let mut final_topology =
        topology_override.map_or_else(|| collect_topology_peers(&genesis), <[PeerId]>::to_vec);
    ensure_valid_genesis_committee(&final_topology)?;
    final_topology.sort();
    if topology_override.is_none() && !peer_pops.is_empty() {
        return Err(eyre!(
            "--peer-pop requires --topology to align PoPs with peers"
        ));
    }
    let topology_entries = topology_override
        .map(|topology| build_topology_entries(topology, peer_pops))
        .transpose()?;

    let uses_npos = matches!(consensus_mode, SumeragiConsensusMode::Npos);
    let topology_peers = if uses_npos {
        final_topology
    } else {
        Vec::new()
    };
    let needs_npos_bootstrap = uses_npos
        && should_auto_bootstrap_npos_validators(config)
        && !manifest_has_npos_bootstrap(&genesis)
        && !topology_peers.is_empty();
    let mut bootstrap_registrations = if needs_npos_bootstrap {
        BootstrapRegistrations::from_manifest(&genesis)
    } else {
        BootstrapRegistrations {
            accounts: BTreeSet::new(),
            asset_defs: BTreeSet::new(),
        }
    };
    let bootstrap_stake_asset_id = if needs_npos_bootstrap {
        Some(configured_npos_bootstrap_stake_asset_id(&genesis, config)?)
    } else {
        None
    };
    let bootstrap_escrow_account_id = if needs_npos_bootstrap {
        Some(configured_npos_bootstrap_escrow_account_id(
            &genesis, config,
        )?)
    } else {
        None
    };

    let direct_sign_safe = topology_override.is_none() && !needs_npos_bootstrap;
    let mut prepared = if direct_sign_safe {
        genesis.with_consensus_mode(consensus_mode)
    } else {
        let chain_discriminant = genesis.chain_discriminant();
        let mut builder = genesis.into_builder();
        if let Some(entries) = topology_entries {
            // Put topology into a dedicated transaction so it remains separate
            // from other genesis instructions.
            builder = builder.next_transaction().set_topology(entries);
        }
        if needs_npos_bootstrap {
            builder = append_npos_bootstrap(
                builder,
                &mut bootstrap_registrations,
                &topology_peers,
                bootstrap_escrow_account_id
                    .as_ref()
                    .expect("NPoS bootstrap escrow resolved above"),
                bootstrap_stake_asset_id
                    .as_ref()
                    .expect("NPoS XOR identity resolved above"),
            )?;
        }
        builder
            .build_raw()?
            .with_chain_discriminant(chain_discriminant)
            .with_consensus_mode(consensus_mode)
            .with_consensus_meta()?
    };
    if needs_npos_bootstrap {
        // The explicit SCCP initializer captures the original staking bindings.
        // Keep its own complete batch after the bootstrap appended above.
        let initializers = prepared
            .transactions()
            .iter()
            .enumerate()
            .filter_map(|(index, tx)| {
                tx.instructions()
                    .iter()
                    .any(|instruction| {
                        instruction
                            .as_any()
                            .is::<iroha_data_model::isi::sccp::InitializeSccpV1>()
                    })
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        if let [index] = initializers.as_slice() {
            color_eyre::eyre::ensure!(
                prepared.transactions()[*index].instructions().len() == 1,
                "SCCP initialization must be its own genesis transaction before automatic NPoS bootstrap"
            );
            prepared.move_instruction_only_transaction_to_end(*index)?;
        } else if !initializers.is_empty() {
            return Err(eyre!("SCCP genesis must initialize exactly once"));
        }
    }
    prepared
        .validate_genesis_topology()
        .wrap_err("refusing to sign a genesis whose final topology is not an exact committee")?;
    Ok(prepared)
}

impl<T: Write> RunArgs<T> for Args {
    #[allow(clippy::too_many_lines)]
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        tui::status("Signing genesis manifest");
        let artifact_paths = resolve_artifact_paths(&self)?;
        for input in self.amx.source_paths() {
            let canonical = fs::canonicalize(input).wrap_err("resolve AMX global source")?;
            reject_artifact_alias(
                "AMX global source",
                Some(&canonical),
                "input genesis manifest",
                Some(&artifact_paths.genesis_input),
            )?;
            for (label, output) in artifact_paths.outputs() {
                reject_artifact_alias("AMX global source", Some(&canonical), label, output)?;
            }
        }
        let mut identity_guard = artifact_paths
            .expected_hash_output
            .as_deref()
            .map(GenesisNetworkIdentityGuard::acquire)
            .transpose()?
            .flatten();
        if let Some(prior) = self.replace_expected_hash {
            identity_guard
                .as_ref()
                .ok_or_else(|| {
                    eyre!("--replace-expected-hash requires an existing expected-hash file")
                })?
                .require_identity(prior)?;
        }
        let genesis = RawGenesisTransaction::from_path(&artifact_paths.genesis_input)?;
        reject_retired_public_chain_id(genesis.chain_id().as_str())?;
        let genesis = self.amx.append_to(genesis)?;
        // Keep every same-thread rebuild, config parse, and bound-manifest
        // serialization on the manifest's network. Staged execution re-enters
        // this discriminant on its worker thread.
        let _chain_discriminant = staged_genesis_chain_discriminant(&genesis);
        // Parse the peer configuration exactly once. Every policy projection
        // below borrows this immutable snapshot, so replacing the source file
        // concurrently cannot create a mixed genesis generation.
        let genesis_key_pair = load_genesis_key_file(&self.private_key_file)?;
        ensure_expected_public_key(&genesis_key_pair, self.expected_public_key.as_ref())?;
        let peer_config = self
            .config
            .as_deref()
            .map(|path| {
                load_peer_config_for_signing(
                    path,
                    &genesis,
                    &genesis_key_pair,
                    self.creation_time_ms,
                )
            })
            .transpose()?;
        let manifest_consensus_mode = genesis.consensus_mode();
        let consensus_mode = manifest_consensus_mode;
        let topology_override = if let Some(raw) = self.topology.as_deref() {
            Some(norito::json::from_str::<Vec<PeerId>>(raw).wrap_err("parse --topology JSON")?)
        } else {
            None
        };
        let mut prepared_genesis = prepare_genesis_for_signing(
            genesis,
            peer_config.as_ref(),
            consensus_mode,
            topology_override.as_deref(),
            &self.peer_pops,
        )?;
        if self.fresh_sccp_reset_nonce {
            let history = self
                .sccp_reset_history
                .as_deref()
                .ok_or_else(|| eyre!("fresh SCCP nonce requires reset history"))?;
            iroha_deploy::genesis::sccp::renew_reset_nonce(&mut prepared_genesis, history)?;
        }
        let da_proof_policies = resolve_da_proof_policies(peer_config.as_ref());
        let confidential_policy_hash = resolve_confidential_policy_hash();
        if let Some(config) = peer_config.as_ref()
            && config.genesis.public_key != *genesis_key_pair.public_key()
        {
            return Err(eyre!(
                "genesis signing key does not match the public key pinned by --config"
            ));
        }
        let (bound_manifest, genesis_block, nexus_context) =
            bind_and_sign_staged_sumeragi_context_with_preimage(
                prepared_genesis,
                &genesis_key_pair,
                peer_config.as_ref(),
                da_proof_policies,
                confidential_policy_hash,
                self.creation_time_ms,
            )?;
        let bound_manifest_json = self
            .bound_manifest_out
            .as_ref()
            .map(|_| {
                let json = norito::json::to_vec_pretty(&bound_manifest)
                    .wrap_err("encode config-bound genesis manifest")?;
                validate_genesis_manifest_json(&json)
                    .wrap_err("config-bound genesis manifest exceeds fixed resource bounds")?;
                Ok::<_, color_eyre::eyre::Report>(json)
            })
            .transpose()?;
        let sccp_reset_nonce = if self.sccp_reset_history.is_some() {
            let mut initializations = bound_manifest.instructions().filter_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::sccp::InitializeSccpV1>()
            });
            let nonce = initializations
                .next()
                .map(|init| init.reset_nonce)
                .ok_or_else(|| {
                    eyre!("--sccp-reset-history requires SCCP initialization in this genesis")
                })?;
            if initializations.next().is_some() {
                return Err(eyre!("SCCP genesis must initialize exactly once"));
            }
            Some(nonce)
        } else {
            None
        };
        drop(bound_manifest);
        let genesis_expected_hash = genesis_block.0.hash();
        let network_id = NetworkId::from_genesis_hash(genesis_expected_hash);
        let framed = genesis_block
            .0
            .encode_wire()
            .wrap_err("frame genesis block with Norito header")?;
        drop(genesis_block);
        if framed.len() > SIGNED_GENESIS_MAX_BYTES_V1 {
            return Err(eyre!(
                "signed genesis body is {} bytes, exceeding the {}-byte first-release limit",
                framed.len(),
                SIGNED_GENESIS_MAX_BYTES_V1
            ));
        }
        if let (Some(history), Some(nonce)) = (self.sccp_reset_history.as_deref(), sccp_reset_nonce)
        {
            iroha_deploy::genesis::sccp::record_network_identity(
                history,
                nonce,
                genesis_expected_hash.as_ref(),
            )?;
        }
        if self.replace_expected_hash.is_none()
            && let Some(path) = artifact_paths.expected_hash_output.as_deref()
        {
            preflight_genesis_network_identity(path, network_id)?;
        }
        let staged_signed_output = artifact_paths
            .signed_output
            .as_deref()
            .map(|path| stage_genesis_output(path, &framed, "signed genesis output"))
            .transpose()?;
        let staged_bound_manifest = match (
            artifact_paths.bound_manifest_output.as_deref(),
            bound_manifest_json.as_deref(),
        ) {
            (Some(path), Some(json)) => Some(stage_genesis_output(
                path,
                json,
                "config-bound genesis manifest",
            )?),
            (None, None) => None,
            _ => unreachable!("bound manifest bytes exist exactly when an output path was set"),
        };
        let staged_nexus_context = artifact_paths
            .nexus_context_output
            .as_deref()
            .map(|path| stage_genesis_output(path, &nexus_context, "Nexus AMX context output"))
            .transpose()?;
        let staged_identity = if self.replace_expected_hash.is_some() {
            Some(stage_genesis_output(
                artifact_paths
                    .expected_hash_output
                    .as_deref()
                    .expect("replacement output checked"),
                genesis_network_identity_body(network_id).as_bytes(),
                "replacement genesis network identity",
            )?)
        } else {
            None
        };
        if let Some(path) = artifact_paths.expected_hash_output.as_deref() {
            if self.replace_expected_hash.is_none() {
                // Fresh publication remains no-clobber. Lock and recheck the winning identity
                // before persisting any outputs, including when another publisher won this race.
                publish_genesis_network_identity(path, network_id)?;
                if identity_guard.is_none() {
                    identity_guard = GenesisNetworkIdentityGuard::acquire(path)?;
                }
                identity_guard
                    .as_ref()
                    .ok_or_else(|| eyre!("published genesis expected-hash file disappeared"))?
                    .require_identity(network_id)?;
            }
            identity_guard
                .as_mut()
                .expect("identity publication holds a guard")
                .revalidate(path)?;
        }
        eprintln!("Genesis public key: {}", genesis_key_pair.public_key());
        eprintln!("Genesis network identity: {network_id}");
        if let Some(identity) = staged_identity {
            publish_guarded_genesis_bundle(
                identity_guard
                    .as_mut()
                    .expect("replacement holds the prior identity"),
                artifact_paths
                    .expected_hash_output
                    .as_deref()
                    .expect("replacement output checked"),
                [
                    (
                        artifact_paths
                            .signed_output
                            .as_deref()
                            .expect("replacement output checked"),
                        staged_signed_output.expect("replacement signed output staged"),
                        "signed genesis output",
                    ),
                    (
                        artifact_paths
                            .bound_manifest_output
                            .as_deref()
                            .expect("replacement output checked"),
                        staged_bound_manifest.expect("replacement manifest staged"),
                        "config-bound genesis manifest",
                    ),
                    (
                        artifact_paths
                            .nexus_context_output
                            .as_deref()
                            .expect("replacement output checked"),
                        staged_nexus_context.expect("replacement Nexus AMX context staged"),
                        "Nexus AMX context output",
                    ),
                ],
                identity,
            )?;
            tui::success("Genesis block signed");
            return Ok(());
        }
        match (
            artifact_paths.signed_output.as_deref(),
            staged_signed_output,
        ) {
            (Some(path), Some(temporary)) => {
                publish_staged_genesis_output(temporary, path, "signed genesis output")?;
            }
            (None, None) => {
                writer.write_all(&framed)?;
                writer.flush()?;
            }
            _ => unreachable!("signed output staging follows the requested output path"),
        }
        match (
            artifact_paths.bound_manifest_output.as_deref(),
            staged_bound_manifest,
        ) {
            (Some(path), Some(temporary)) => {
                publish_staged_genesis_output(temporary, path, "config-bound genesis manifest")?
            }
            (None, None) => {}
            _ => unreachable!("bound manifest staging follows the requested output path"),
        }
        match (
            artifact_paths.nexus_context_output.as_deref(),
            staged_nexus_context,
        ) {
            (Some(path), Some(temporary)) => {
                publish_staged_genesis_output(temporary, path, "Nexus AMX context output")?
            }
            (None, None) => {}
            _ => unreachable!("Nexus AMX context staging follows the requested output path"),
        }
        tui::success("Genesis block signed");
        Ok(())
    }
}
fn ensure_expected_public_key(
    key_pair: &KeyPair,
    expected_public_key: Option<&PublicKey>,
) -> Result<(), color_eyre::eyre::Error> {
    if let Some(expected_public_key) = expected_public_key
        && key_pair.public_key() != expected_public_key
    {
        return Err(eyre!(
            "genesis signing key does not match --expected-public-key"
        ));
    }
    Ok(())
}
fn load_genesis_key_file(path: &Path) -> Result<KeyPair, color_eyre::eyre::Error> {
    let mut raw = zeroize::Zeroizing::new(crate::secure_fs::read_private_file(path)?);
    let text =
        std::str::from_utf8(raw.as_slice()).wrap_err("genesis private-key file is not UTF-8")?;
    let canonical = text.strip_suffix('\n').ok_or_else(|| {
        eyre!("genesis private-key file must contain one canonical key and a final newline")
    })?;
    if canonical.is_empty() || canonical.chars().any(char::is_whitespace) {
        return Err(eyre!(
            "genesis private-key file is not one canonical key record"
        ));
    }
    let exposed = canonical
        .parse::<ExposedPrivateKey>()
        .wrap_err("decode canonical genesis private-key file")?;
    let canonical_encoding = zeroize::Zeroizing::new(exposed.to_string());
    if canonical_encoding.as_str() != canonical {
        return Err(eyre!("genesis private-key file encoding is not canonical"));
    }
    raw.zeroize();
    KeyPair::from_private_key(exposed.0).wrap_err("derive genesis key pair from private-key file")
}
fn build_topology_entries(
    topology: &[PeerId],
    peer_pops: &[String],
) -> Result<Vec<GenesisTopologyEntry>, color_eyre::eyre::Error> {
    use iroha_crypto::PublicKey;
    ensure_valid_genesis_committee(topology)?;
    if peer_pops.is_empty() {
        return Err(eyre!(
            "topology provided without PoPs; supply --peer-pop for every peer"
        ));
    }
    let topo_set: BTreeSet<PublicKey> = topology
        .iter()
        .map(|pid| pid.public_key().clone())
        .collect();
    let mut map: BTreeMap<PublicKey, Vec<u8>> = BTreeMap::new();
    for kv in peer_pops {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| eyre!("invalid --peer-pop entry: {kv}"))?;
        let pk: PublicKey = k.parse()?;
        if !topo_set.contains(&pk) {
            return Err(eyre!(
                "peer-pop provided for {pk} but that peer is not present in --topology"
            ));
        }
        if map.insert(pk.clone(), decode_hex(v)?).is_some() {
            return Err(eyre!("duplicate --peer-pop entry for {pk}"));
        }
    }
    let missing: Vec<_> = topo_set
        .iter()
        .filter(|pk| !map.contains_key(*pk))
        .cloned()
        .collect();
    if !missing.is_empty() {
        let joined = missing
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(eyre!(
            "missing --peer-pop entries for topology peers: {joined}"
        ));
    }
    Ok(topology
        .iter()
        .map(|peer| {
            let pk = peer.public_key();
            GenesisTopologyEntry::new(
                peer.clone(),
                map.get(pk)
                    .cloned()
                    .expect("topology keys validated against pop map"),
            )
        })
        .collect())
}
fn ensure_valid_genesis_committee(topology: &[PeerId]) -> Result<(), color_eyre::eyre::Error> {
    let unique = topology.iter().collect::<BTreeSet<_>>();
    if unique.len() != topology.len() {
        return Err(eyre!(
            "genesis topology contains duplicate voting peer identities"
        ));
    }
    if !(4..=MAX_VALIDATORS).contains(&unique.len()) || (unique.len() - 1) % 3 != 0 {
        return Err(eyre!(
            "genesis topology must contain an exact Sumeragi `3f + 1` validator committee \
             in the supported range 4..={MAX_VALIDATORS} (saw {})",
            unique.len()
        ));
    }
    Ok(())
}
fn resolve_da_proof_policies(config: Option<&actual::Root>) -> Option<DaProofPolicyBundle> {
    config.map(|config| iroha_core::da::proof_policy_bundle(&config.nexus.lane_config))
}
/// The confidential policy hash a genesis header binds.
///
/// The genesis block runs under the protocol-default ZK validity policy on
/// every validator, whatever a node configuration holds; a chain sets other
/// values with the `zk_validity_policy_v1` parameter of its genesis manifest,
/// which governs the blocks after genesis.
fn resolve_confidential_policy_hash() -> [u8; 32] {
    iroha_core::state::default_genesis_confidential_policy_hash()
}
fn decode_hex(s: &str) -> Result<Vec<u8>, color_eyre::eyre::Error> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).wrap_err("decode PoP hex")
}
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::genesis::CompleteTestGenesisBuilder as _;
    use iroha_crypto::{Algorithm, HashOf, KeyPair as CryptoKeyPair, bls_normal_pop_prove};
    use iroha_data_model::{
        NetworkId,
        asset::AssetDefinitionAlias,
        block::{BlockHeader, SignedBlock, decode_framed_signed_block},
        isi::{
            SetParameter, asset_alias::SetAssetDefinitionAlias, mint_burn::MintBox,
            register::RegisterBox, staking::RegisterPublicLaneValidator,
        },
        nexus::{LaneCatalog, LaneConfig},
        parameter::{
            Parameter,
            system::{
                SumeragiConsensusMode, SumeragiNposParameters, SumeragiParameter,
                consensus_metadata,
            },
        },
        transaction::Executable,
    };
    use iroha_deploy::genesis::staging::bind_and_sign_staged_sumeragi_context;
    use iroha_genesis::{GenesisBuilder, GenesisTopologyEntry};
    use iroha_model_base::chain::ChainId;
    use std::{
        fs,
        io::{BufWriter, Write},
        path::PathBuf,
        str::FromStr,
        time::Duration,
    };

    pub struct NativeGenesisFixture {
        pub(crate) config: actual::Root,
        pub(crate) manifest: RawGenesisTransaction,
        pub(crate) signed: GenesisBlock,
        pub(crate) _manifests: tempfile::TempDir,
    }
    fn native_genesis_fixture(lane_count: u32) -> NativeGenesisFixture {
        native_genesis_fixture_with_instructions(lane_count, Vec::new())
    }
    pub fn native_genesis_fixture_with_instructions(
        lane_count: u32,
        instructions: Vec<iroha_data_model::isi::InstructionBox>,
    ) -> NativeGenesisFixture {
        use iroha_data_model::sumeragi_lanes::{
            SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy,
        };
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut config = checked_in_config(&root.join("defaults/kagami/iroha3-dev/peer0.toml"));
        let key = KeyPair::try_from_seed(vec![0x7D; 32], Algorithm::Ed25519).unwrap();
        config.genesis.public_key = key.public_key().clone();
        let topology = valid_test_topology_entries(4);
        let builder = GenesisBuilder::new_without_executor(config.common.chain.clone(), ".")
            .set_topology_for_test(topology.clone());
        let raw = instructions
            .into_iter()
            .fold(builder, GenesisBuilder::append_instruction)
            .build_raw()
            .expect("complete signed native genesis fixture")
            .with_consensus_mode(SumeragiConsensusMode::Permissioned);
        // The clock authority performs ordinary charged work after genesis. Its
        // currency, fee recipient and allocation must therefore be signed inputs,
        // with the original configured fee policy retained during execution.
        let fee_asset = config.nexus.fees.fee_asset_id.clone();
        let fee_sink = config.nexus.fees.fee_sink_account_id.clone();
        let mut registrations = BootstrapRegistrations::from_manifest(&raw);
        let mut builder = raw.into_builder().next_transaction();
        if registrations.asset_defs.insert(fee_asset.clone()) {
            builder = builder.append_instruction(Register::asset_definition(AssetDefinition::new(
                fee_asset.clone(),
                "XOR",
                NumericSpec::fractional(9),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )));
        }
        if fee_sink != AccountId::new(key.public_key().clone())
            && registrations.accounts.insert(fee_sink.clone())
        {
            builder = builder.append_instruction(Register::account(Account::new(fee_sink)));
        }
        let raw = builder
            .append_instruction(Mint::asset_quantity(
                10_000_u64,
                AssetId::new(fee_asset, AccountId::new(key.public_key().clone())),
            ))
            .build_raw()
            .expect("explicit original clock fee allocation");
        let mut committee = topology
            .iter()
            .map(|entry| SumeragiLaneMember {
                peer: entry.peer.clone(),
                pop: hex::decode(entry.pop_hex.as_ref().unwrap()).unwrap(),
            })
            .collect::<Vec<_>>();
        committee.sort_by(|a, b| a.peer.cmp(&b.peer));
        let policy = SumeragiLanePolicy {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            anchor_freshness: 16,
            max_merge_blocks: 32,
            stall_window: 256,
            lane_params: raw.effective_parameters().unwrap().sumeragi().clone(),
            fixed: (1..lane_count)
                .map(|lane| SumeragiFixedLane {
                    lane: LaneId::new(lane),
                    dataspace: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    committee: committee.clone(),
                })
                .collect(),
            routes: Vec::new(),
            autoscale: None,
        };
        let raw = raw
            .into_builder()
            .append_parameter(Parameter::Custom(policy.into_custom_parameter()))
            .build_raw()
            .unwrap();
        let manifests = tempfile::tempdir().unwrap();
        config.nexus = staged_default_nexus(&raw).expect("single universal native World");
        let policies = Some(iroha_core::da::proof_policy_bundle(
            &config.nexus.lane_config,
        ));
        let confidential = iroha_core::state::default_genesis_confidential_policy_hash();
        let (manifest, signed) = bind_and_sign_staged_sumeragi_context(
            raw,
            &key,
            Some(&config),
            policies,
            confidential,
            Some(1_700_000_000_000),
        )
        .expect("execute, bind, materialize and sign the generic final genesis");
        config.genesis.expected_hash = signed.0.hash();
        NativeGenesisFixture {
            config,
            manifest,
            signed,
            _manifests: manifests,
        }
    }

    #[test]
    fn prepared_native_chain_reuses_original_one_and_four_lane_configuration() {
        use iroha_core::state::WorldReadOnly;
        for lane_count in [1, 4] {
            let fixture = native_genesis_fixture(lane_count);
            let original = fixture.signed.0.encode_wire().unwrap();
            let validated = iroha_genesis::validate_prepared_genesis_bundle(
                &original,
                &fixture.manifest,
                &fixture.config.genesis.public_key,
                fixture.config.genesis.expected_hash,
            )
            .unwrap();
            let mut keys = (0x40..=0x43)
                .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
                .collect::<Vec<_>>();
            keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
            let mut chain = prepared_native_test_chain(
                validated,
                &fixture.manifest,
                &fixture.config,
                keys,
                KeyPair::from_seed(vec![0x7D; 32], Algorithm::Ed25519),
                Arc::new(iroha_core::sumeragi::lanes::merge::NoLanes),
            )
            .unwrap();
            assert_eq!(chain.genesis().encode_wire().unwrap(), original);
            assert_eq!(
                chain.state().view().world().sumeragi_lanes().lanes.len(),
                lane_count as usize - 1
            );
            let key = KeyPair::from_seed(vec![0x7D; 32], Algorithm::Ed25519);
            let fee_asset = fixture.config.nexus.fees.fee_asset_id.clone();
            let payer_asset =
                AssetId::new(fee_asset.clone(), AccountId::new(key.public_key().clone()));
            let before = chain
                .state()
                .view()
                .world()
                .asset(&payer_asset)
                .unwrap()
                .value()
                .clone()
                .into_inner();
            let mut transaction = iroha_data_model::transaction::TransactionBuilder::new(
                chain.network_id(),
                AccountId::new(key.public_key().clone()),
                iroha_data_model::transaction::FeePaymentIntent::authority(
                    vec![iroha_data_model::transaction::FeeChargeLimit::new(
                        iroha_data_model::transaction::FeeChargeKind::Nexus,
                        fee_asset,
                        1_u64.into(),
                    )],
                    None,
                ),
            );
            transaction.set_creation_time(
                chain.genesis().header().creation_time()
                    + Duration::from_millis(
                        fixture
                            .manifest
                            .effective_parameters()
                            .unwrap()
                            .sumeragi()
                            .block_cadence_ms
                            .get()
                            - 1,
                    ),
            );
            let transaction = transaction
                .with_instructions([Log::new(
                    Level::DEBUG,
                    "original prepared configuration charged work".into(),
                )])
                .sign(key.private_key());
            assert_eq!(chain.commit(vec![transaction]), [true]);
            let committed = chain.committed(2);
            let outcome = &committed.block().network_output_at(0).unwrap().1.result;
            assert!(outcome.is_ok(), "original clock transaction: {outcome:?}");
            assert!(
                chain
                    .state()
                    .view()
                    .world()
                    .asset(&payer_asset)
                    .unwrap()
                    .value()
                    .clone()
                    .into_inner()
                    < before,
                "the original configured fee policy must actually debit signed funds"
            );
            let mut prefix = iroha_core::sumeragi::certified_chain::CertifiedPrefix::new(
                fixture.manifest.chain_id(),
                chain.network_id(),
                chain.committed(1).block().clone(),
            )
            .unwrap();
            let (_, genesis) = prefix.push(committed.block().clone()).unwrap().into_parts();
            assert!(genesis.is_some());
        }
    }

    #[test]
    fn final_signed_native_policy_matches_actual_stage_for_one_and_four_lanes() {
        use iroha_core::state::WorldReadOnly;
        for lane_count in [1, 4] {
            let fixture = native_genesis_fixture(lane_count);
            let wire = fixture.signed.0.encode_wire().unwrap();
            let (authority, observed) = staged_signed_native_genesis_with_projection(
                &fixture.manifest,
                &wire,
                &fixture.config,
                |genesis, staged| {
                    assert_eq!(genesis.0.hash(), fixture.signed.0.hash());
                    Ok((
                        staged.world().sumeragi_lanes().clone(),
                        iroha_core::sumeragi::lanes::lane_policy(staged.world())
                            .wrap_err("read committed staged native policy")?,
                    ))
                },
            )
            .unwrap();
            assert_eq!(
                authority.epoch().network_id,
                NetworkId::from_genesis_hash(fixture.signed.0.hash())
            );
            assert_eq!(authority.epoch().authorization.first_height, 1);
            assert_eq!(authority.epoch().committee.len(), 4);
            assert_eq!(authority.lanes().lanes.len(), lane_count as usize - 1);
            assert_eq!(authority.lanes(), &observed.0);
            assert_eq!(authority.lane_policy(), observed.1.as_ref());
            for lane in &authority.lanes().lanes {
                let fixed = authority
                    .lane_policy()
                    .unwrap()
                    .fixed
                    .iter()
                    .find(|fixed| fixed.lane == lane.lane)
                    .unwrap();
                assert_eq!(lane.created_at, 1);
                assert_eq!(lane.active_from, 3);
                assert_eq!(lane.dataspace, fixed.dataspace);
                assert_eq!(lane.committee, fixed.committee);
                assert_eq!(lane.params, authority.lane_policy().unwrap().lane_params);
                for member in &lane.committee {
                    iroha_crypto::bls_normal_pop_verify(member.peer.public_key(), &member.pop)
                        .unwrap();
                }
            }
            for member in &authority.epoch().committee {
                iroha_crypto::bls_normal_pop_verify(
                    member.validator.public_key(),
                    &member.proof_of_possession,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn final_signed_native_genesis_rejects_wire_signer_hash_manifest_and_policy_rebinding() {
        let fixture = native_genesis_fixture(4);
        let wire = fixture.signed.0.encode_wire().unwrap();
        let mut wrong_chain = fixture.config.clone();
        wrong_chain.common.chain = ChainId::from("other-generic-chain");
        let error = staged_signed_native_genesis(&fixture.manifest, &wire, &wrong_chain)
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("does not match genesis manifest chain"));
        let mut wrong_discriminant = fixture.config.clone();
        *wrong_discriminant.common.chain_discriminant.value_mut() = fixture
            .manifest
            .chain_discriminant()
            .checked_add(1)
            .unwrap();
        let error = staged_signed_native_genesis(&fixture.manifest, &wire, &wrong_discriminant)
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("chain discriminant"));
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(
            staged_signed_native_genesis(&fixture.manifest, &trailing, &fixture.config).is_err()
        );
        let mut wrong_signer = fixture.config.clone();
        wrong_signer.genesis.public_key =
            KeyPair::try_from_seed(vec![0x7E; 32], Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone();
        let error = staged_signed_native_genesis(&fixture.manifest, &wire, &wrong_signer)
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("differs from verifier key"));
        let mut wrong_hash = fixture.config.clone();
        wrong_hash.genesis.expected_hash =
            HashOf::from_untyped_unchecked(Hash::new(b"different-final-genesis"));
        let error = staged_signed_native_genesis(&fixture.manifest, &wire, &wrong_hash)
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("signed genesis body hashes to"));
        let wrong_manifest = fixture
            .manifest
            .clone()
            .with_consensus_mode(SumeragiConsensusMode::Npos);
        let error = staged_signed_native_genesis(&wrong_manifest, &wire, &fixture.config)
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("genesis manifest consensus mode"));
        // A node-local policy value the signed context binds. The pipeline
        // execution limits are committed chain policy: staging ignores the
        // values a settings value holds for them.
        let mut wrong_policy = fixture.config.clone();
        wrong_policy.nexus.da.rotation.window_slots = wrong_policy
            .nexus
            .da
            .rotation
            .window_slots
            .checked_add(1)
            .expect("test rotation window increment must not overflow");
        let error = staged_signed_native_genesis(&fixture.manifest, &wire, &wrong_policy)
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("policy"), "{error:#}");
    }

    fn checked_in_config(path: &std::path::Path) -> actual::Root {
        let source_bytes = fs::read(path).expect("read checked-in config");
        if let Ok(config) = load_peer_config_bytes(path, &source_bytes) {
            return config;
        }
        actual::Root::from_toml_source(TomlSource::inline(checked_in_consensus_config_table(path)))
            .unwrap_or_else(|error| {
                panic!(
                    "failed to validate consensus projection from {}: {error}",
                    path.display()
                )
            })
    }
    fn checked_in_consensus_config_table(path: &std::path::Path) -> toml::Table {
        let source_bytes = fs::read(path).expect("read checked-in config");
        // Some deployment templates deliberately contain unresolved
        // runtime-secret bindings outside this projection. Reparse only the
        // Nexus and Pipeline tables consumed by the Nexus/AMX commitment,
        // while retaining the source chain/discriminant, through the
        // production config parser. No Nexus or Pipeline value is synthesized
        // or decoded by this test helper.
        let source = String::from_utf8(source_bytes).expect("checked-in config is UTF-8");
        let header = || {
            source
                .lines()
                .take_while(|line| !line.trim_start().starts_with('['))
        };
        let chain = header()
            .find(|line| line.trim_start().starts_with("chain ="))
            .expect("checked-in config has chain");
        let chain_discriminant = header()
            .find(|line| line.trim_start().starts_with("chain_discriminant ="))
            .unwrap_or("");
        let mut projected = format!(
            r#"{chain}
{chain_discriminant}
public_key = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2"
private_key = "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F"
soranet_transport_public_key = "ed0120D9F6AEF1813164294D1D9C0662FEB9C7F7861B4DFFE385680331093DA4ABD10B"
soranet_transport_private_key = "802620134C4527B3852AE2218A8F079B301C651EAD8C7567B96BD7A9BE8DB366E46B89"
trusted_peers_pop = [
  {{ public_key = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2", pop_hex = "8515da750f81182aaba5c22fc9f03a01e81ed85e4495a2ca6b29a71c0c8549537e31e79cddf6ff285b9e22d0d9dc17ce0f46e7d0cf78b2ef9feab50c849a1ea8e1e4f07e966f6113faa8a999317545d9f111b8e08a7273913710b43a20b19c08" }}
]

[network]
address = "addr:127.0.0.1:1337#8F78"
public_address = "addr:127.0.0.1:1337#8F78"

[torii]
address = "addr:127.0.0.1:8080#8942"

[genesis]
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
expected_hash = "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"

[streaming]
identity_public_key = "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB"
identity_private_key = "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F"
"#
        );
        let mut include = false;
        for line in source.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('[') {
                let section = trimmed.trim_start_matches('[');
                include = section.starts_with("nexus") || section.starts_with("pipeline");
            }
            if include {
                projected.push_str(line);
                projected.push('\n');
            }
        }

        toml::Table::from_str(&projected).unwrap_or_else(|error| {
            panic!(
                "failed to parse consensus projection from {}: {error}",
                path.display()
            )
        })
    }
    fn bind_fixture_private_key(
        table: &mut toml::Table,
        public_field: &str,
        private_field: &str,
        key_pair: &KeyPair,
        directory: &Path,
    ) {
        let file_field = format!("{private_field}_file");
        let path = directory.join(&file_field);
        let canonical = zeroize::Zeroizing::new(
            format!("{}\n", ExposedPrivateKey(key_pair.private_key().clone())).into_bytes(),
        );
        crate::secure_fs::write_private_file_atomic(&path, canonical.as_slice())
            .expect("write owner-only fixture key");
        table.remove(private_field);
        table.insert(
            public_field.to_owned(),
            key_pair.public_key().to_string().into(),
        );
        table.insert(file_field, path.to_string_lossy().into_owned().into());
    }

    fn runtime_test_peer_config(
        mut table: toml::Table,
        manifest: &RawGenesisTransaction,
        genesis_key_pair: &KeyPair,
    ) -> PathBuf {
        use std::cell::RefCell;

        thread_local! {
            static CONFIG_DIRECTORIES: RefCell<Vec<tempfile::TempDir>> = const { RefCell::new(Vec::new()) };
        }
        let directory = tempfile::tempdir().expect("create complete private config fixture");
        let canonical = crate::secure_fs::prepare_empty_private_directory(directory.path())
            .expect("prepare owner-only config fixture root");
        table.insert("chain".to_owned(), manifest.chain_id().to_string().into());
        table.insert(
            "chain_discriminant".to_owned(),
            i64::from(manifest.chain_discriminant()).into(),
        );
        let validator = KeyPair::try_from_seed(vec![0x40; 32], Algorithm::BlsNormal)
            .expect("derive fixture validator");
        bind_fixture_private_key(
            &mut table,
            "public_key",
            "private_key",
            &validator,
            &canonical,
        );
        let transport = KeyPair::try_from_seed(vec![0x65; 32], Algorithm::Ed25519)
            .expect("derive fixture transport identity");
        bind_fixture_private_key(
            &mut table,
            "soranet_transport_public_key",
            "soranet_transport_private_key",
            &transport,
            &canonical,
        );
        let topology = valid_test_topology_material(4);
        table.insert(
            "trusted_peers".to_owned(),
            toml::Value::Array(
                topology
                    .iter()
                    .enumerate()
                    .map(|(index, (peer, _))| {
                        format!("{}@127.0.0.1:{}", peer.public_key(), 1337 + index).into()
                    })
                    .collect(),
            ),
        );
        table.insert(
            "trusted_peers_pop".to_owned(),
            toml::Value::Array(
                topology
                    .iter()
                    .map(|(peer, pop)| {
                        toml::Value::Table(toml::Table::from_iter([
                            (
                                "public_key".to_owned(),
                                peer.public_key().to_string().into(),
                            ),
                            ("pop_hex".to_owned(), hex::encode(pop).into()),
                        ]))
                    })
                    .collect(),
            ),
        );
        let streaming = table
            .entry("streaming")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("streaming fixture table");
        let streaming_key = KeyPair::try_from_seed(vec![0x66; 32], Algorithm::Ed25519)
            .expect("derive fixture streaming identity");
        bind_fixture_private_key(
            streaming,
            "identity_public_key",
            "identity_private_key",
            &streaming_key,
            &canonical,
        );

        // Materialize a separate complete four-validator identity fixture.
        // Some tested manifests intentionally leave topology for the later CLI
        // override; their original bytes remain the signing input unchanged.
        let identity_manifest = manifest
            .clone()
            .clear_topology()
            .into_builder()
            .set_topology_for_test(valid_test_topology_entries(4))
            .build_raw()
            .expect("complete private config identity fixture")
            .with_consensus_mode(manifest.consensus_mode())
            .with_chain_discriminant(manifest.chain_discriminant())
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        let provisional = identity_manifest
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
                genesis_key_pair,
                None,
                None,
                1_700_000_000_000,
            )
            .expect("sign fixture identity before config admission");
        let identity = NetworkId::from_genesis_hash(provisional.0.hash());
        let identity_path = canonical.join("genesis.expected_hash");
        fs::write(&identity_path, format!("{identity}\n")).expect("write actual fixture identity");
        let genesis = table
            .entry("genesis")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("genesis fixture table");
        genesis.remove("expected_hash");
        genesis.insert(
            "expected_hash_file".to_owned(),
            identity_path.to_string_lossy().into_owned().into(),
        );
        genesis.insert(
            "public_key".to_owned(),
            genesis_key_pair.public_key().to_string().into(),
        );

        let nexus = table
            .entry("nexus")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("Nexus fixture table");
        let defaults = staged_default_nexus(manifest).expect("resolve fixture default identities");
        let staking = nexus
            .entry("staking")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("staking fixture table");
        staking
            .entry("stake_escrow_account_id")
            .or_insert_with(|| defaults.staking.stake_escrow_account_id.into());
        staking
            .entry("slash_sink_account_id")
            .or_insert_with(|| defaults.staking.slash_sink_account_id.into());
        // Fee terms remain in the signed manifest; node configuration has no fee policy.
        // Materialize the disabled VPN profile's default account in the same
        // network as this complete fixture, as localnet rendering does.
        let network = table
            .entry("network")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("network fixture table");
        let vpn = network
            .entry("soranet_vpn")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("VPN fixture table");
        vpn.entry("operator_account_id").or_insert_with(|| {
            staged_default_account_literal(
                &defaults::soranet::vpn::operator_account_id(),
                manifest.chain_discriminant(),
                "fixture VPN operator",
            )
            .expect("bind fixture operator discriminant")
            .into()
        });
        // Like localnet rendering, bind every omitted governance account default
        // to this fixture's network while preserving explicit policy inputs.
        let governance = table
            .entry("gov")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("governance fixture table");
        for (name, literal) in [
            (
                "bond_escrow_account",
                defaults::governance::bond_escrow_account(),
            ),
            (
                "citizenship_escrow_account",
                defaults::governance::citizenship_escrow_account(),
            ),
            (
                "slash_receiver_account",
                defaults::governance::slash_receiver_account(),
            ),
            (
                "viral_incentive_pool_account",
                defaults::governance::viral_incentive_pool_account(),
            ),
            (
                "viral_escrow_account",
                defaults::governance::viral_escrow_account(),
            ),
            (
                "sorafs_pin_fee_treasury_account",
                defaults::governance::sorafs_pin_fee::treasury_account(),
            ),
        ] {
            governance.entry(name).or_insert_with(|| {
                staged_default_account_literal(&literal, manifest.chain_discriminant(), name)
                    .expect("bind fixture governance account discriminant")
                    .into()
            });
        }
        let path = canonical.join("peer0.toml");
        let rendered = zeroize::Zeroizing::new(
            toml::to_string_pretty(&table).expect("render complete fixture config"),
        );
        crate::secure_fs::write_private_file_atomic(&path, rendered.as_bytes())
            .expect("write canonical owner-only fixture config");
        CONFIG_DIRECTORIES.with(|directories| directories.borrow_mut().push(directory));
        path
    }

    type ConsensusHandshakeMetaTest =
        iroha_data_model::parameter::system::ConsensusHandshakeMetadata;
    fn consensus_handshake_meta(block: &SignedBlock) -> ConsensusHandshakeMetaTest {
        for transaction in block.external_transactions() {
            if let Executable::Instructions(batch) = transaction.instructions() {
                for instruction in batch {
                    if let Some(set_parameter) = instruction.as_any().downcast_ref::<SetParameter>()
                        && let Parameter::Custom(custom) = set_parameter.inner()
                        && custom.id() == &consensus_metadata::handshake_meta_id()
                    {
                        return custom
                            .payload()
                            .try_into_any()
                            .expect("decode signed consensus handshake metadata");
                    }
                }
            }
        }
        panic!("signed genesis omitted consensus handshake metadata");
    }
    fn assert_genesis_signatures_verify(block: &SignedBlock, genesis_key_pair: &KeyPair) {
        let transactions = block.external_transactions().collect::<Vec<_>>();
        assert!(
            !transactions.is_empty(),
            "signed genesis must contain external transactions"
        );
        for transaction in transactions {
            transaction
                .verify_signature()
                .expect("genesis transaction signature must verify");
        }
        let signatures = block.signatures().collect::<Vec<_>>();
        assert!(
            !signatures.is_empty(),
            "signed genesis must have a block signature"
        );
        for signature in signatures {
            signature
                .signature()
                .verify_hash(genesis_key_pair.public_key(), block.hash())
                .expect("genesis block signature must verify");
        }
    }
    #[test]
    fn checked_in_genesis_source_templates_are_explicitly_incomplete() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        for path in [
            "defaults/genesis.template.json",
            "defaults/kagami/iroha3-dev/genesis.template.json",
            "defaults/kagami/iroha3-nexus/genesis.template.json",
            "defaults/nexus/genesis.template.json",
            "configs/soranexus/nexus/genesis.template.json",
            "configs/soranexus/taira/genesis.template.json",
        ] {
            let full_path = root.join(path);
            let bytes = fs::read(&full_path)
                .unwrap_or_else(|error| panic!("read {}: {error}", full_path.display()));
            let value: norito::json::Value = norito::json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("parse {}: {error}", full_path.display()));
            let object = value
                .as_object()
                .expect("source template must be an object");
            assert_eq!(
                object.get("consensus_fingerprint"),
                Some(&norito::json::Value::Null),
                "{path} must not advertise a fingerprint before materialization"
            );
            let manifest = RawGenesisTransaction::from_path(&full_path)
                .expect("bounded source JSON must remain parseable before materialization");
            assert_eq!(
                manifest.consensus_fingerprint(),
                None,
                "{path} must remain unbound"
            );
            let mode = manifest.consensus_mode();
            assert!(
                prepare_genesis_for_signing(manifest, None, mode, None, &[]).is_err(),
                "{path} must not enter signing without its required NPoS XOR selection"
            );
        }
    }
    #[test]
    fn checked_in_taira_source_template_requires_runtime_signer_rendering() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let path = root.join("configs/soranexus/taira/config.toml");
        let source = fs::read_to_string(&path).expect("read Taira deployment template");
        assert!(source.contains("production_mode = true"));
        for placeholder in [
            "REPLACE_WITH_SORACLOUD_RUNTIME_SIGNER_HANDLE",
            "REPLACE_WITH_SORACLOUD_RUNTIME_SIGNER_AUTHORITY",
            "REPLACE_WITH_SORACLOUD_RUNTIME_SIGNER_ALGORITHM",
            "REPLACE_WITH_SORACLOUD_RUNTIME_SIGNER_PUBLIC_KEY_HEX",
            "REPLACE_WITH_SORACLOUD_RUNTIME_SIGNER_REVISION",
            "REPLACE_WITH_SORACLOUD_RUNTIME_SIGNER_POLICY_DIGEST_HEX",
        ] {
            assert!(
                source.contains(placeholder),
                "Taira source template must retain explicit `{placeholder}`"
            );
        }
        assert!(
            load_peer_config_bytes(&path, source.as_bytes()).is_err(),
            "unrendered Taira production template must not be runnable"
        );
    }
    #[test]
    fn unpublished_signing_context_binds_original_signature() {
        let manifest = RawGenesisTransaction::from_path(minimal_genesis_file()).unwrap();
        let key = test_genesis_key_pair();
        let table = checked_in_consensus_config_table(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../defaults/kagami/iroha3-dev/peer0.toml"),
        );
        let path = runtime_test_peer_config(table, &manifest, &key);
        let mut table: toml::Table = fs::read_to_string(&path).unwrap().parse().unwrap();
        assert!(
            table["nexus"].as_table().unwrap().get("fees").is_none(),
            "runtime fixture must retain fee policy only in signed genesis"
        );
        let genesis = table.get_mut("genesis").unwrap().as_table_mut().unwrap();
        genesis.remove("expected_hash");
        genesis.remove("expected_hash_file");
        let source = || TomlSource::new(path.clone(), table.clone());
        assert!(actual::Root::from_toml_source(source()).is_err());
        let context = actual::GenesisSigningContext::from_toml_source(source()).unwrap();
        let signed = build_signed_genesis(
            manifest.clone(),
            &key,
            None,
            iroha_core::state::default_genesis_confidential_policy_hash(),
            Some(1_700_000_000_000),
        )
        .unwrap();
        let bound = context.bind_signed_genesis(&signed.0).unwrap();
        assert_eq!(bound.genesis.expected_hash, signed.0.hash());
        assert_eq!(bound.genesis.public_key, *key.public_key());
        fs::write(&path, toml::to_string(&table).unwrap()).unwrap();
        let loaded =
            load_peer_config_for_signing(&path, &manifest, &key, Some(1_700_000_000_000)).unwrap();
        let expected = iroha_deploy::genesis::staging::build_signed_genesis(
            manifest.clone(),
            &key,
            Some(iroha_core::da::proof_policy_bundle(
                &bound.nexus.lane_config,
            )),
            iroha_core::state::default_genesis_confidential_policy_hash(),
            Some(1_700_000_000_000),
        )
        .unwrap();
        assert_eq!(loaded.genesis.expected_hash, expected.0.hash());
        let wrong_key = checked_genesis_sign_keypair_with_algorithm(Algorithm::Ed25519);
        let wrong = build_signed_genesis(
            manifest,
            &wrong_key,
            None,
            iroha_core::state::default_genesis_confidential_policy_hash(),
            Some(1_700_000_000_000),
        )
        .unwrap();
        assert!(
            actual::GenesisSigningContext::from_toml_source(source())
                .unwrap()
                .bind_signed_genesis(&wrong.0)
                .is_err()
        );
        let mut runtime_claim = table.clone();
        runtime_claim
            .get_mut("genesis")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .insert(
                "expected_hash".into(),
                NetworkId::from_genesis_hash(signed.0.hash())
                    .to_string()
                    .into(),
            );
        assert!(
            actual::GenesisSigningContext::from_toml_source(TomlSource::new(
                path.clone(),
                runtime_claim
            ),)
            .is_err()
        );
        let mut referenced_claim = table.clone();
        referenced_claim
            .get_mut("genesis")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .insert(
                "expected_hash_file".into(),
                "unavailable-identity-DATA-only".into(),
            );
        // Structural presence refuses unpublished selection before any identity file read.
        assert!(
            actual::GenesisSigningContext::from_toml_source(TomlSource::new(
                path.clone(),
                referenced_claim,
            ))
            .is_err()
        );
    }
    #[test]
    fn signing_profile_hash_placeholder_is_never_a_runtime_trust_root() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let template = root.join("defaults/kagami/iroha3-dev/peer0.toml");
        let table = fs::read_to_string(template)
            .expect("read signing profile")
            .parse::<toml::Table>()
            .expect("parse signing profile");
        let manifest = RawGenesisTransaction::from_path(minimal_genesis_file())
            .expect("load complete fixture manifest");
        let path = runtime_test_peer_config(table, &manifest, &test_genesis_key_pair());
        load_peer_config(&path).expect("the actual materialized identity must load");
        let mut table = fs::read_to_string(&path)
            .expect("read complete signing config")
            .parse::<toml::Table>()
            .expect("parse complete signing config");
        let genesis = table
            .get_mut("genesis")
            .and_then(toml::Value::as_table_mut)
            .expect("fixture genesis table");
        genesis.remove("expected_hash_file");
        genesis.insert(
            "expected_hash".to_owned(),
            "REPLACE_WITH_GENESIS_EXPECTED_HASH".into(),
        );
        let path = path.with_file_name("unresolved-peer.toml");
        crate::secure_fs::write_private_file_atomic(
            &path,
            toml::to_string_pretty(&table)
                .expect("render unresolved identity fixture")
                .as_bytes(),
        )
        .expect("write unresolved identity fixture");
        let runtime_source = TomlSource::from_file(&path).expect("read signing profile");
        assert!(
            actual::Root::from_toml_source(runtime_source).is_err(),
            "the unresolved signing profile must not normalize as a runnable node config"
        );
        let source = fs::read(&path).expect("read signing profile bytes");
        assert!(
            load_peer_config_bytes(&path, &source).is_err(),
            "the signer must also reject an unresolved identity instead of inventing a hash"
        );
    }
    #[cfg(unix)]
    #[test]
    fn signing_peer_config_requires_exact_owner_only_custody() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let source = fs::read(root.join("defaults/kagami/iroha3-dev/peer0.toml"))
            .expect("read signing profile fixture");
        let directory = tempfile::tempdir().expect("create signing config custody fixture");
        let canonical_directory = fs::canonicalize(directory.path())
            .expect("canonicalize signing config custody directory");
        let network_id =
            NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"signing config custody fixture",
            )));
        fs::write(
            canonical_directory.join("genesis.expected_hash"),
            format!("{network_id}\n"),
        )
        .expect("write signing config network identity");
        let path = canonical_directory.join("peer0.toml");
        fs::write(&path, source).expect("write signing config custody fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("make signing config permissive");
        let error = load_peer_config(&path).expect_err("permissive signing config must fail");
        assert!(format!("{error:#}").contains("mode 0600"));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("make signing config owner-only");
        load_peer_config(&path).expect("owner-only signing config must load");
    }
    #[test]
    fn staged_genesis_ignores_validity_values_of_the_supplied_configuration() {
        // `configure_staged_genesis_state` (iroha_deploy) installs the supplied
        // configuration the way a node does: local resources only. The hashes a
        // staged genesis derives are therefore not a function of a ZK or pipeline
        // validity value of that configuration, while a value that is still
        // node-local changes them.
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut config = checked_in_config(&root.join("defaults/kagami/iroha3-dev/peer0.toml"));
        let genesis_key_pair = KeyPair::try_from_seed(vec![0x6D; 32], Algorithm::Ed25519)
            .expect("derive deterministic genesis key");
        config.genesis.public_key = genesis_key_pair.public_key().clone();
        let mut raw = GenesisBuilder::new_without_executor(config.common.chain.clone(), ".")
            .set_topology_for_test(valid_test_topology_entries(4))
            .build_raw()
            .expect("complete staging fixture")
            .with_consensus_mode(SumeragiConsensusMode::Permissioned);
        let mut unbound_parameters = raw.sumeragi_context_parameters();
        unbound_parameters.nexus_amx_context_hash = Hash::new(b"unbound-nexus-amx").into();
        unbound_parameters.execution_policy_hash = Hash::new(b"unbound-execution-policy").into();
        raw = raw
            .with_sumeragi_context_parameters(unbound_parameters)
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        let provisional = build_signed_genesis(
            raw.clone(),
            &genesis_key_pair,
            Some(iroha_core::da::proof_policy_bundle(
                &config.nexus.lane_config,
            )),
            iroha_core::state::default_genesis_confidential_policy_hash(),
            Some(1_700_000_000_000),
        )
        .expect("sign the exact unbound provisional genesis");
        // The hashes staging derives, read from the mismatch against the
        // unbound draft.
        let staged = |config: &iroha_config::parameters::actual::Root| {
            let error = staged_signed_sumeragi_context_hashes(&raw, &provisional.0, config)
                .expect_err("the unbound draft reports the hashes staging derived");
            match error.downcast_ref::<iroha_core::block::BlockValidationError>() {
                Some(iroha_core::block::BlockValidationError::GenesisPolicyMismatch {
                    actual_execution,
                    actual_nexus,
                    ..
                }) => (*actual_execution, *actual_nexus),
                _ => panic!("unexpected staging error: {error:#}"),
            }
        };
        let baseline = staged(&config);

        let mut divergent = config.clone();
        divergent.zk.max_proof_size_bytes = 1;
        divergent.zk.max_verify_calls_per_block = 1;
        divergent.zk.gas.proof_base = 1;
        divergent.zk.max_verify_batch = 5;
        divergent.pipeline.overlay_max_instructions = 1;
        divergent.pipeline.query_max_fetch_size = 1;
        divergent.pipeline.ivm_max_cycles_upper_bound =
            core::num::NonZeroU64::new(7).expect("nonzero cycle bound");
        divergent.pipeline.dynamic_prepass = !divergent.pipeline.dynamic_prepass;
        assert_eq!(
            staged(&divergent),
            baseline,
            "a staged genesis must ignore ZK and pipeline validity values of the configuration"
        );

        // The comparison is sensitive: a value that is still node-local moves
        // the execution-policy hash.
        let mut still_local = config.clone();
        still_local.gov.conviction_step_blocks += 1;
        assert_ne!(staged(&still_local).0, baseline.0);
    }
    #[test]
    fn signer_and_final_network_id_restaging_have_exact_context_parity() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut config = checked_in_config(&root.join("defaults/kagami/iroha3-dev/peer0.toml"));
        let genesis_key_pair = KeyPair::try_from_seed(vec![0x6D; 32], Algorithm::Ed25519)
            .expect("derive deterministic genesis key");
        config.genesis.public_key = genesis_key_pair.public_key().clone();
        let mut raw = GenesisBuilder::new_without_executor(config.common.chain.clone(), ".")
            .set_topology_for_test(valid_test_topology_entries(4))
            .build_raw()
            .expect("complete restaging parity fixture")
            .with_consensus_mode(SumeragiConsensusMode::Permissioned);
        let mut unbound_parameters = raw.sumeragi_context_parameters();
        unbound_parameters.nexus_amx_context_hash = Hash::new(b"unbound-nexus-amx").into();
        unbound_parameters.execution_policy_hash = Hash::new(b"unbound-execution-policy").into();
        raw = raw
            .with_sumeragi_context_parameters(unbound_parameters)
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        let da_proof_policies = Some(iroha_core::da::proof_policy_bundle(
            &config.nexus.lane_config,
        ));
        let confidential_policy_hash =
            iroha_core::state::default_genesis_confidential_policy_hash();
        let creation_time_ms = Some(1_700_000_000_000);
        let provisional = build_signed_genesis(
            raw.clone(),
            &genesis_key_pair,
            da_proof_policies.clone(),
            confidential_policy_hash,
            creation_time_ms,
        )
        .expect("sign the exact unbound provisional genesis");
        let provisional_error =
            staged_signed_sumeragi_context_hashes(&raw, &provisional.0, &config)
                .expect_err("the original unbound draft must report its exact policy mismatch");
        assert!(
            matches!(
                provisional_error.downcast_ref::<iroha_core::block::BlockValidationError>(),
                Some(iroha_core::block::BlockValidationError::GenesisPolicyMismatch {
                    expected_execution,
                    actual_execution,
                    expected_nexus,
                    actual_nexus,
                }) if *expected_execution == Hash::prehashed(unbound_parameters.execution_policy_hash)
                    && *expected_nexus == Hash::prehashed(unbound_parameters.nexus_amx_context_hash)
                    && actual_execution != expected_execution
                    && actual_nexus != expected_nexus
            ),
            "the report must retain the validator's concrete draft mismatch: {provisional_error:#}"
        );
        let (bound_manifest, signed) = bind_and_sign_staged_sumeragi_context(
            raw,
            &genesis_key_pair,
            Some(&config),
            da_proof_policies,
            confidential_policy_hash,
            creation_time_ms,
        )
        .expect("bind and sign staged genesis context");
        assert!(
            signed.0.has_results(),
            "the published signed genesis must carry validated execution results"
        );
        signed
            .0
            .validate_output_merkle_cache()
            .expect("published genesis has complete typed source/output ownership");
        for input_index in 0..signed.0.network_entrypoint_count() {
            let (_, output) = signed
                .0
                .network_output_at(u32::try_from(input_index).expect("genesis input fits u32"))
                .expect("every executed genesis entrypoint must have one Network result");
            assert!(
                output.result.as_ref().is_ok(),
                "genesis Network result failed"
            );
        }
        assert!(
            signed
                .0
                .output_results()
                .all(|result| result.as_ref().is_ok()),
            "every published genesis result must be successful"
        );
        let minimum_committed_fragments = u64::try_from(signed.0.output_results().count())
            .expect("genesis result count fits u64");
        let actual_committed_fragments = signed
            .0
            .committed_fragment_count()
            .expect("published genesis must advertise its committed fragment count");
        assert!(
            actual_committed_fragments >= minimum_committed_fragments,
            "the published fragment count must cover every successful result row and may include deterministic internal fragments"
        );
        let final_signature = signed
            .0
            .signatures()
            .next()
            .expect("published genesis signature");
        final_signature
            .signature()
            .verify_hash(genesis_key_pair.public_key(), signed.0.hash())
            .expect("published genesis must be signed after result materialization");
        assert_ne!(
            provisional.0.hash(),
            signed.0.hash(),
            "binding the staged context must exercise distinct provisional and final NetworkIds"
        );
        config.genesis.expected_hash = signed.0.hash();
        let (restaged_nexus_amx, restaged_execution_policy) =
            staged_signed_sumeragi_context_hashes(&bound_manifest, &signed.0, &config)
                .expect("restage signed genesis under its final NetworkId");
        let signed_parameters = bound_manifest.sumeragi_context_parameters();
        assert_eq!(
            restaged_nexus_amx,
            Hash::prehashed(signed_parameters.nexus_amx_context_hash),
            "final runtime Nexus/AMX staging must match signing without a hash fixed point"
        );
        assert_eq!(
            restaged_execution_policy,
            Hash::prehashed(signed_parameters.execution_policy_hash),
            "final runtime execution-policy staging must match signing"
        );

        // A node-local Nexus value the signed context binds; the AMX budgets
        // of the pipeline are committed chain policy and staging ignores them.
        let mut tampered_nexus_config = config.clone();
        tampered_nexus_config.nexus.da.rotation.window_slots = tampered_nexus_config
            .nexus
            .da
            .rotation
            .window_slots
            .checked_add(1)
            .expect("test rotation window increment must not overflow");
        let nexus_error = staged_signed_sumeragi_context_hashes(
            &bound_manifest,
            &signed.0,
            &tampered_nexus_config,
        )
        .expect_err("a final-identity Nexus/AMX policy mismatch must fail closed");
        let Some(iroha_core::block::BlockValidationError::GenesisPolicyMismatch {
            expected_execution,
            actual_execution,
            expected_nexus,
            actual_nexus,
        }) = nexus_error.downcast_ref::<iroha_core::block::BlockValidationError>()
        else {
            panic!("unexpected Nexus/AMX tamper error: {nexus_error:#}");
        };
        assert_eq!(
            *expected_nexus,
            Hash::prehashed(signed_parameters.nexus_amx_context_hash)
        );
        assert_eq!(
            *expected_execution,
            Hash::prehashed(signed_parameters.execution_policy_hash)
        );
        assert_ne!(actual_nexus, expected_nexus);
        assert_ne!(actual_execution, expected_execution);

        // A node-local value the execution-policy hash binds and the Nexus/AMX
        // context does not; the pipeline limits are committed chain policy and
        // staging ignores them.
        let mut tampered_execution_config = config.clone();
        tampered_execution_config.gov.conviction_step_blocks = tampered_execution_config
            .gov
            .conviction_step_blocks
            .checked_add(1)
            .expect("test conviction step increment must not overflow");
        let execution_error = staged_signed_sumeragi_context_hashes(
            &bound_manifest,
            &signed.0,
            &tampered_execution_config,
        )
        .expect_err("a final-identity execution-policy mismatch must fail closed");
        let Some(iroha_core::block::BlockValidationError::GenesisPolicyMismatch {
            expected_execution,
            actual_execution,
            expected_nexus,
            actual_nexus,
        }) = execution_error.downcast_ref::<iroha_core::block::BlockValidationError>()
        else {
            panic!("unexpected execution-policy tamper error: {execution_error:#}");
        };
        assert_eq!(
            *expected_execution,
            Hash::prehashed(signed_parameters.execution_policy_hash)
        );
        assert_eq!(
            *expected_nexus,
            Hash::prehashed(signed_parameters.nexus_amx_context_hash)
        );
        assert_ne!(actual_execution, expected_execution);
        assert_eq!(actual_nexus, expected_nexus);
    }

    fn checked_genesis_sign_keypair() -> CryptoKeyPair {
        CryptoKeyPair::try_random().expect("genesis sign fixture key generation should succeed")
    }
    fn checked_genesis_sign_keypair_with_algorithm(algorithm: Algorithm) -> CryptoKeyPair {
        CryptoKeyPair::try_random_with_algorithm(algorithm)
            .expect("genesis sign fixture key generation should succeed")
    }
    fn valid_test_topology_material(count: usize) -> Vec<(PeerId, Vec<u8>)> {
        let mut topology = (0..count)
            .map(|index| {
                let seed_byte = 0x40_u8
                    .checked_add(
                        u8::try_from(index)
                            .expect("genesis-sign fixture validator index fits in u8"),
                    )
                    .expect("genesis-sign fixture validator seed domain is not exhausted");
                let key_pair =
                    CryptoKeyPair::try_from_seed(vec![seed_byte; 32], Algorithm::BlsNormal)
                        .expect("derive deterministic genesis-sign fixture validator");
                let pop = bls_normal_pop_prove(key_pair.private_key())
                    .expect("generate checked topology proof of possession");
                (PeerId::new(key_pair.public_key().clone()), pop)
            })
            .collect::<Vec<_>>();
        topology.sort_by(|(left, _), (right, _)| left.cmp(right));
        topology
    }
    fn valid_test_topology(count: usize) -> (Vec<PeerId>, Vec<String>) {
        valid_test_topology_material(count)
            .into_iter()
            .map(|(peer, pop)| {
                let encoded_pop = format!("{}={}", peer.public_key(), hex::encode(pop));
                (peer, encoded_pop)
            })
            .unzip()
    }
    fn valid_test_topology_entries(count: usize) -> Vec<GenesisTopologyEntry> {
        valid_test_topology_material(count)
            .into_iter()
            .map(|(peer, pop)| GenesisTopologyEntry::new(peer, pop))
            .collect()
    }
    pub fn with_explicit_test_xor_allocations(
        manifest: RawGenesisTransaction,
        topology: &[PeerId],
    ) -> RawGenesisTransaction {
        if manifest.consensus_mode() != SumeragiConsensusMode::Npos {
            return manifest;
        }
        let parameters = manifest.effective_parameters().expect("fixture parameters");
        let asset = parameters
            .custom()
            .get(&SumeragiNposParameters::parameter_id())
            .map(SumeragiNposParameters::from_custom_parameter)
            .transpose()
            .expect("valid fixture NPoS parameters")
            .flatten()
            .expect("fixture NPoS asset pin")
            .xor_asset_definition_id;
        let mut registrations = BootstrapRegistrations::from_manifest(&manifest);
        let funded = manifest
            .instructions()
            .filter_map(
                |instruction| match instruction.as_any().downcast_ref::<MintBox>() {
                    Some(MintBox::Asset(mint)) if mint.destination.definition() == &asset => {
                        Some(mint.destination.account().clone())
                    }
                    _ => None,
                },
            )
            .collect::<BTreeSet<_>>();
        let domain =
            DomainId::parse_fully_qualified(crate::genesis::profile::PUBLIC_XOR_DOMAIN).unwrap();
        let domain_registered = manifest.instructions().any(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<Register<Domain>>()
                .is_some_and(|register| register.object.id == domain)
                || matches!(
                    instruction
                        .as_any()
                        .downcast_ref::<iroha_data_model::isi::register::RegisterBox>(),
                    Some(iroha_data_model::isi::register::RegisterBox::Domain(register))
                        if register.object.id == domain
                )
        });
        let chain_discriminant = manifest.chain_discriminant();
        let consensus_mode = manifest.consensus_mode();
        let mut builder = manifest.into_builder().next_transaction();
        if !domain_registered {
            builder = builder.append_instruction(Register::domain(Domain::new(domain)));
        }
        if registrations.asset_defs.insert(asset.clone()) {
            builder = builder.append_instruction(Register::asset_definition(AssetDefinition::new(
                asset.clone(),
                "XOR".to_owned(),
                NumericSpec::fractional(9),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )));
        }
        for peer in topology {
            let account = AccountId::new(peer.public_key().clone());
            if registrations.accounts.insert(account.clone()) {
                builder =
                    builder.append_instruction(Register::account(Account::new(account.clone())));
            }
            if !funded.contains(&account) {
                builder = builder.append_instruction(Mint::asset_quantity(
                    DEFAULT_NPOS_BOOTSTRAP_STAKE_AMOUNT,
                    AssetId::new(asset.clone(), account),
                ));
            }
        }
        builder
            .build_raw()
            .expect("explicit isolated fixture allocations")
            .with_chain_discriminant(chain_discriminant)
            .with_consensus_mode(consensus_mode)
            .with_consensus_meta()
            .expect("valid fixture consensus parameters")
    }
    fn with_test_authority_for_topology(path: PathBuf, topology: &[PeerId]) -> PathBuf {
        let manifest =
            RawGenesisTransaction::from_path(&path).expect("parse test genesis manifest");
        let _chain_discriminant = staged_genesis_chain_discriminant(&manifest);
        let consensus_mode = manifest.consensus_mode();
        let chain_discriminant = manifest.chain_discriminant();
        let manifest = manifest
            .into_builder()
            .complete_for_test()
            .build_raw()
            .expect("complete topology-bound signing fixture")
            .with_consensus_mode(consensus_mode)
            .with_chain_discriminant(chain_discriminant)
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        let manifest = with_explicit_test_xor_allocations(manifest, topology);
        fs::write(
            &path,
            norito::json::to_vec_pretty(&manifest).expect("encode topology-bound fixture"),
        )
        .expect("write topology-bound fixture");
        path
    }
    fn replace_manifest_wire_protocol_version(
        path: &std::path::Path,
        version: norito::json::Value,
    ) {
        let bytes = fs::read(path).expect("read genesis fixture");
        let mut value: norito::json::Value =
            norito::json::from_slice(&bytes).expect("parse genesis fixture JSON");
        value
            .as_object_mut()
            .expect("genesis fixture is an object")
            .insert("wire_protocol_version".to_owned(), version);
        fs::write(
            path,
            norito::json::to_json_pretty(&value).expect("serialize genesis fixture JSON"),
        )
        .expect("rewrite genesis fixture");
    }
    #[test]
    fn signing_rejects_retired_protocol_version_arrays() {
        for versions in [Vec::new(), vec![1], vec![1, 2], vec![2, 1], vec![2, 2]] {
            let genesis_file = minimal_genesis_file();
            replace_manifest_wire_protocol_version(
                &genesis_file,
                norito::json::value::to_value(&versions).expect("serialize protocol list"),
            );
            let args = Args {
                genesis_file,
                out_file: None,
                bound_manifest_out: None,
                expected_hash_out: None,
                nexus_context_output: None,
                sccp_reset_history: None,
                fresh_sccp_reset_nonce: false,
                replace_expected_hash: None,
                topology: None,
                peer_pops: Vec::new(),
                private_key_file: test_private_key_file(),
                expected_public_key: None,
                creation_time_ms: None,
                amx: amx::Args::default(),
                config: None,
            };
            let error = args
                .run(&mut BufWriter::new(Vec::new()))
                .expect_err("non-canonical protocol list must be rejected before signing");
            assert!(
                error
                    .to_string()
                    .contains("failed to deserialize raw genesis transaction"),
                "unexpected error for {versions:?}: {error}"
            );
        }
    }
    #[test]
    fn signing_rejects_every_non_v1_protocol_tag() {
        let current_args = Args {
            genesis_file: minimal_genesis_file(),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        current_args
            .run(&mut BufWriter::new(Vec::new()))
            .expect("first-release scalar protocol version 1 must be accepted before signing");
        for version in [0_u32, 2, 3, 4, 8, u32::MAX] {
            let genesis_file = minimal_genesis_file();
            replace_manifest_wire_protocol_version(
                &genesis_file,
                norito::json::Value::Number(norito::json::Number::U64(u64::from(version))),
            );
            let args = Args {
                genesis_file,
                out_file: None,
                bound_manifest_out: None,
                expected_hash_out: None,
                nexus_context_output: None,
                sccp_reset_history: None,
                fresh_sccp_reset_nonce: false,
                replace_expected_hash: None,
                topology: None,
                peer_pops: Vec::new(),
                private_key_file: test_private_key_file(),
                expected_public_key: None,
                creation_time_ms: None,
                amx: amx::Args::default(),
                config: None,
            };
            let error = args.run(&mut BufWriter::new(Vec::new())).expect_err(
                "retired or unknown future scalar protocol version must be rejected before signing",
            );
            assert!(
                error
                    .to_string()
                    .contains("fresh genesis must advertise wire_protocol_version = 1"),
                "unexpected error for protocol version {version}: {error}"
            );
        }
    }
    #[test]
    fn explicit_creation_time_repeats_signed_wire_bytes() {
        let genesis_file = minimal_genesis_file();
        let private_key_file = test_private_key_file();
        let sign = || {
            let args = Args {
                genesis_file: genesis_file.clone(),
                out_file: None,
                bound_manifest_out: None,
                expected_hash_out: None,
                nexus_context_output: None,
                sccp_reset_history: None,
                fresh_sccp_reset_nonce: false,
                replace_expected_hash: None,
                topology: None,
                peer_pops: Vec::new(),
                private_key_file: private_key_file.clone(),
                expected_public_key: None,
                creation_time_ms: Some(1_700_000_000_000),
                amx: amx::Args::default(),
                config: None,
            };
            let mut writer = BufWriter::new(Vec::new());
            args.run(&mut writer).expect("sign at fixed creation time");
            writer.into_inner().expect("extract signed genesis bytes")
        };
        assert_eq!(sign(), sign());
    }
    #[test]
    fn genesis_sign_fixture_key_generation_preserves_algorithms() {
        assert_eq!(
            checked_genesis_sign_keypair().public_key().algorithm(),
            Algorithm::default()
        );
        for algorithm in [Algorithm::Ed25519, Algorithm::BlsNormal] {
            assert_eq!(
                checked_genesis_sign_keypair_with_algorithm(algorithm)
                    .public_key()
                    .algorithm(),
                algorithm
            );
        }
    }
    #[test]
    fn peer_pops_without_topology_is_rejected() {
        let args = Args {
            genesis_file: npos_genesis_file(),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: vec!["pk=00".to_string()],
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut sink = BufWriter::new(Vec::new());
        let err = args
            .run(&mut sink)
            .expect_err("peer-pop without topology should fail");
        assert!(
            err.to_string().contains("requires --topology"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn duplicate_peer_pops_are_rejected() {
        let (topology, mut peer_pops) = valid_test_topology(4);
        let topology_json = norito::json::to_json(&topology).unwrap();
        let dup = peer_pops[0].clone();
        peer_pops.push(dup.clone());
        let args = Args {
            genesis_file: npos_genesis_file(),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some(topology_json),
            peer_pops,
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut sink = BufWriter::new(Vec::new());
        let err = args.run(&mut sink).expect_err("duplicate pop should fail");
        assert!(
            err.to_string().contains("duplicate --peer-pop"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn topology_entries_order_matches_topology() {
        let (topology, peer_pops) = valid_test_topology(4);
        let entries = build_topology_entries(&topology, &peer_pops).expect("valid pops");
        assert_eq!(
            entries[0].peer, topology[0],
            "entries should respect topology order"
        );
        assert_eq!(
            entries[1].peer, topology[1],
            "entries should respect topology order"
        );
    }
    #[test]
    fn signing_boundary_enforces_bounded_committee_geometry() {
        let (topology, _) = valid_test_topology(32);
        for count in [1_usize, 2, 3, 5, 32] {
            let error = ensure_valid_genesis_committee(&topology[..count])
                .expect_err("non-committee topology must fail");
            assert!(
                error.to_string().contains("exact Sumeragi `3f + 1`"),
                "unexpected error for {count} peers: {error}"
            );
        }
        for count in [4_usize, 7] {
            ensure_valid_genesis_committee(&topology[..count])
                .unwrap_or_else(|error| panic!("{count}-peer topology failed: {error}"));
        }
    }
    #[test]
    fn bound_manifest_output_matches_the_manifest_used_for_signing() {
        let temp = tempfile::tempdir().expect("bound manifest temp dir");
        let bound_manifest_path = temp.path().join("genesis.bound.json");
        let (topology, peer_pops) = valid_test_topology(4);
        let genesis_file = with_test_authority_for_topology(minimal_genesis_file(), &topology);
        let genesis_key_pair = KeyPair::try_from_seed(vec![0x41; 32], Algorithm::Ed25519)
            .expect("derive genesis signing key");
        let unbound_manifest = RawGenesisTransaction::from_path(&genesis_file)
            .expect("parse unbound genesis manifest");
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let config_source =
            fs::read_to_string(workspace_root.join("defaults/kagami/iroha3-dev/peer0.toml"))
                .expect("read current peer config fixture");
        let mut config_table = config_source
            .parse::<toml::Table>()
            .expect("parse current peer config fixture");
        config_table
            .get_mut("genesis")
            .and_then(toml::Value::as_table_mut)
            .expect("peer config genesis table")
            .insert(
                "public_key".to_owned(),
                toml::Value::String(genesis_key_pair.public_key().to_string()),
            );
        // A node-local policy value the staged context binds. The pipeline
        // execution limits are committed chain policy and are not keys of a
        // peer configuration.
        let mut rotation = &mut config_table;
        for section in ["nexus", "da", "rotation"] {
            rotation = rotation
                .entry(section)
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .expect("peer config Nexus DA rotation table");
        }
        rotation.insert("window_slots".to_owned(), toml::Value::Integer(65));
        let config_path =
            runtime_test_peer_config(config_table, &unbound_manifest, &genesis_key_pair);
        load_peer_config(&config_path).expect("load peer config");
        let args = Args {
            genesis_file,
            out_file: None,
            bound_manifest_out: Some(bound_manifest_path.clone()),
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some(norito::json::to_json(&topology).expect("serialize topology override")),
            peer_pops,
            private_key_file: test_private_key_file_for(&genesis_key_pair),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: Some(config_path),
        };
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer).expect("sign genesis");
        writer.flush().expect("flush signed genesis");
        let signed =
            decode_framed_signed_block(&writer.into_inner().expect("extract signed genesis bytes"))
                .expect("decode signed genesis");
        let bound_manifest = RawGenesisTransaction::from_path(&bound_manifest_path)
            .expect("parse config-bound manifest output");
        let signed_meta = consensus_handshake_meta(&signed);
        assert_eq!(
            bound_manifest.sumeragi_context_parameters(),
            signed_meta.sumeragi_context,
            "persisted manifest must carry the exact staged Nexus/AMX context signed into the block"
        );
        assert_eq!(
            bound_manifest.consensus_fingerprint(),
            Some(signed_meta.consensus_fingerprint),
            "persisted manifest fingerprint must match the signed handshake metadata"
        );
        assert_ne!(
            bound_manifest
                .sumeragi_context_parameters()
                .nexus_amx_context_hash,
            unbound_manifest
                .sumeragi_context_parameters()
                .nexus_amx_context_hash,
            "the peer configuration's Nexus policy must replace the generator's unbound context commitment"
        );
        assert_ne!(
            bound_manifest.consensus_fingerprint(),
            unbound_manifest.consensus_fingerprint(),
            "rebinding the Nexus/AMX context must refresh the persisted fingerprint"
        );
        assert_genesis_signatures_verify(&signed, &genesis_key_pair);
        let rebuilt = bound_manifest
            .build_and_sign_with_confidential_policy_hash(
                &genesis_key_pair,
                Some(iroha_core::state::default_genesis_confidential_policy_hash()),
            )
            .expect("rebuild persisted bound manifest");
        let signed_instructions = signed
            .external_transactions()
            .map(|transaction| transaction.instructions().clone())
            .collect::<Vec<_>>();
        let rebuilt_instructions = rebuilt
            .0
            .external_transactions()
            .map(|transaction| transaction.instructions().clone())
            .collect::<Vec<_>>();
        assert_eq!(
            signed_instructions, rebuilt_instructions,
            "bound manifest output must reproduce the signed transaction semantics"
        );
    }
    #[test]
    fn failed_signing_does_not_clobber_bound_manifest_output() {
        let temp = tempfile::tempdir().expect("bound manifest temp dir");
        let bound_manifest_path = temp.path().join("genesis.bound.json");
        let sentinel = b"existing-bound-manifest";
        fs::write(&bound_manifest_path, sentinel).expect("write sentinel manifest");
        let args = Args {
            genesis_file: npos_genesis_file(),
            out_file: None,
            bound_manifest_out: Some(bound_manifest_path.clone()),
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some("not valid json".to_owned()),
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let _ = args
            .run(&mut BufWriter::new(Vec::new()))
            .expect_err("invalid topology must fail before publishing outputs");
        assert_eq!(
            fs::read(&bound_manifest_path).expect("read sentinel manifest"),
            sentinel,
            "failed signing must leave an existing bound manifest untouched"
        );
    }
    #[test]
    fn signed_output_failure_does_not_publish_bound_manifest() {
        let temp = tempfile::tempdir().expect("output publication temp dir");
        let bound_manifest_path = temp.path().join("genesis.bound.json");
        let sentinel = b"existing-bound-manifest";
        fs::write(&bound_manifest_path, sentinel).expect("write sentinel manifest");
        let args = Args {
            genesis_file: minimal_genesis_file(),
            out_file: Some(temp.path().join("missing-parent/genesis.signed.nrt")),
            bound_manifest_out: Some(bound_manifest_path.clone()),
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let _ = args
            .run(&mut BufWriter::new(Vec::new()))
            .expect_err("uncreatable signed output must fail publication");
        assert_eq!(
            fs::read(&bound_manifest_path).expect("read sentinel manifest"),
            sentinel,
            "bound manifest must publish only after the signed block output succeeds"
        );
    }
    #[test]
    fn signed_and_bound_manifest_outputs_must_not_alias() {
        let temp = tempfile::tempdir().expect("output alias temp dir");
        let output_path = temp.path().join("genesis-output.nrt");
        let sentinel = b"existing-output";
        fs::write(&output_path, sentinel).expect("write output sentinel");
        let args = Args {
            genesis_file: minimal_genesis_file(),
            out_file: Some(output_path.clone()),
            bound_manifest_out: Some(output_path.clone()),
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let error = args
            .run(&mut BufWriter::new(Vec::new()))
            .expect_err("signed and manifest outputs must not alias");
        assert!(
            error.to_string().contains("must use different paths"),
            "unexpected output alias error: {error:#}"
        );
        assert_eq!(
            fs::read(&output_path).expect("read output sentinel"),
            sentinel,
            "output alias rejection must happen before either output is opened"
        );
    }
    #[test]
    fn signed_output_must_not_replace_the_input_manifest() {
        let genesis_file = minimal_genesis_file();
        let before = fs::read(&genesis_file).expect("read input manifest fixture");
        let args = Args {
            genesis_file: genesis_file.clone(),
            out_file: Some(genesis_file.clone()),
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let error = args
            .run(&mut BufWriter::new(Vec::new()))
            .expect_err("signed output must not replace its input manifest");
        assert!(format!("{error:#}").contains("input genesis manifest"));
        assert_eq!(
            fs::read(genesis_file).expect("reread input manifest"),
            before
        );
    }
    #[cfg(unix)]
    #[test]
    fn output_alias_checks_resolve_parent_symlinks_and_hard_links() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("resolved alias temp dir");
        let canonical_parent = temp.path().join("canonical");
        fs::create_dir(&canonical_parent).expect("create canonical output parent");
        let parent_alias = temp.path().join("alias");
        symlink(&canonical_parent, &parent_alias).expect("create output parent alias");
        let args = Args {
            genesis_file: minimal_genesis_file(),
            out_file: Some(canonical_parent.join("same-output")),
            bound_manifest_out: Some(parent_alias.join("same-output")),
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let error = args
            .run(&mut BufWriter::new(Vec::new()))
            .expect_err("parent aliases must resolve before output publication");
        assert!(error.to_string().contains("must use different paths"));
        assert!(!canonical_parent.join("same-output").exists());

        let signed = canonical_parent.join("signed");
        let manifest = canonical_parent.join("manifest");
        fs::write(&signed, b"sentinel").expect("write hard-link source");
        fs::hard_link(&signed, &manifest).expect("create hard-link output alias");
        let args = Args {
            genesis_file: minimal_genesis_file(),
            out_file: Some(signed.clone()),
            bound_manifest_out: Some(manifest.clone()),
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let error = args
            .run(&mut BufWriter::new(Vec::new()))
            .expect_err("hard-linked outputs must not alias");
        assert!(error.to_string().contains("must use different paths"));
        assert_eq!(fs::read(signed).expect("read signed sentinel"), b"sentinel");
        assert_eq!(
            fs::read(manifest).expect("read manifest sentinel"),
            b"sentinel"
        );
    }
    #[test]
    fn identity_drift_leaves_every_requested_output_unchanged() {
        let temp = tempfile::tempdir().expect("identity drift output temp dir");
        let signed_path = temp.path().join("genesis.signed.nrt");
        let bound_manifest_path = temp.path().join("genesis.bound.json");
        let identity_path = temp.path().join("genesis.expected_hash");
        let signed_sentinel = b"existing-signed-genesis";
        let manifest_sentinel = b"existing-bound-manifest";
        let foreign_network_id =
            NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                b"foreign pre-existing genesis identity",
            )));
        let identity_sentinel = format!("{foreign_network_id}\n");
        fs::write(&signed_path, signed_sentinel).expect("write signed output sentinel");
        fs::write(&bound_manifest_path, manifest_sentinel).expect("write manifest output sentinel");
        fs::write(&identity_path, &identity_sentinel).expect("write identity sentinel");
        let args = Args {
            genesis_file: minimal_genesis_file(),
            out_file: Some(signed_path.clone()),
            bound_manifest_out: Some(bound_manifest_path.clone()),
            expected_hash_out: Some(identity_path.clone()),
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let error = args
            .run(&mut BufWriter::new(Vec::new()))
            .expect_err("a different existing identity must stop publication");
        assert!(
            error
                .to_string()
                .contains("refusing to replace a different genesis network identity"),
            "unexpected identity drift error: {error:#}"
        );
        assert_eq!(
            fs::read(&signed_path).expect("read signed output sentinel"),
            signed_sentinel,
        );
        assert_eq!(
            fs::read(&bound_manifest_path).expect("read manifest output sentinel"),
            manifest_sentinel,
        );
        assert_eq!(
            fs::read_to_string(&identity_path).expect("read identity sentinel"),
            identity_sentinel,
        );
        assert!(
            fs::read_dir(temp.path())
                .expect("list identity drift output directory")
                .all(|entry| {
                    !entry
                        .expect("identity drift directory entry")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".genesis-output-")
                }),
            "identity preflight must reject before output staging"
        );
    }
    fn replacement_args(directory: &Path, prior: NetworkId) -> Args {
        Args {
            genesis_file: minimal_genesis_file(),
            out_file: Some(directory.join("genesis.signed.nrt")),
            bound_manifest_out: Some(directory.join("genesis.bound.json")),
            expected_hash_out: Some(directory.join("genesis.expected_hash")),
            nexus_context_output: Some(directory.join("nexus-amx-context.v1.bin")),
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: Some(prior),
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: Some(1_700_000_000_000),
            amx: amx::Args::default(),
            config: None,
        }
    }
    fn identity_fixture(label: &[u8]) -> NetworkId {
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
            label,
        )))
    }
    #[cfg(unix)]
    #[test]
    fn guarded_replacement_publishes_consistent_genesis_bundle() {
        let temp = tempfile::tempdir().unwrap();
        let prior = identity_fixture(b"prior genesis");
        let args = replacement_args(temp.path(), prior);
        let identity = args.expected_hash_out.clone().unwrap();
        let signed = args.out_file.clone().unwrap();
        let manifest = args.bound_manifest_out.clone().unwrap();
        let context = args.nexus_context_output.clone().unwrap();
        publish_genesis_network_identity(&identity, prior).unwrap();
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer).unwrap();
        assert!(writer.into_inner().unwrap().is_empty());
        let block = decode_framed_signed_block(&fs::read(&signed).unwrap()).unwrap();
        let current = NetworkId::from_genesis_hash(block.hash());
        assert_ne!(current, prior);
        let published_context = fs::read(&context).unwrap();
        assert_eq!(
            Hash::new(&published_context),
            Hash::prehashed(
                consensus_handshake_meta(&block)
                    .sumeragi_context
                    .nexus_amx_context_hash
            ),
            "replacement must publish the exact AMX preimage committed by the signed genesis"
        );
        assert_eq!(
            fs::read(&identity).unwrap(),
            genesis_network_identity_body(current).as_bytes()
        );
        RawGenesisTransaction::from_path(&manifest).unwrap();
        // Re-signing the exact published manifest with the same deterministic time must
        // reproduce the same consensus identity, through the ordinary Exact publisher.
        let mut repeat = replacement_args(temp.path(), current);
        repeat.genesis_file = manifest;
        repeat.replace_expected_hash = None;
        repeat.run(&mut BufWriter::new(Vec::new())).unwrap();
        let repeated = decode_framed_signed_block(&fs::read(signed).unwrap()).unwrap();
        assert_eq!(repeated.hash(), block.hash());
        assert_eq!(
            fs::read(&identity).unwrap(),
            genesis_network_identity_body(current).as_bytes()
        );
        // A completed operation must not silently replay using the old prior.
        let stale = replacement_args(temp.path(), prior);
        assert!(stale.run(&mut BufWriter::new(Vec::new())).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn guarded_replacement_rejects_stale_missing_and_unsafe_prior_without_writes() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let prior = identity_fixture(b"required prior");
        for defect in ["stale", "missing", "symlink", "hardlink", "writable"] {
            let temp = tempfile::tempdir().unwrap();
            let mut replacement = replacement_args(temp.path(), prior);
            let signed = replacement.out_file.clone().unwrap();
            let manifest = replacement.bound_manifest_out.clone().unwrap();
            let context = replacement.nexus_context_output.clone().unwrap();
            let identity = replacement.expected_hash_out.clone().unwrap();
            fs::write(&signed, b"prior signed").unwrap();
            fs::write(&manifest, b"prior manifest").unwrap();
            fs::write(&context, b"prior context").unwrap();
            if defect != "missing" {
                publish_genesis_network_identity(
                    &identity,
                    if defect == "stale" {
                        identity_fixture(b"foreign prior")
                    } else {
                        prior
                    },
                )
                .unwrap();
            }
            match defect {
                "symlink" => {
                    fs::rename(&identity, temp.path().join("target")).unwrap();
                    symlink(temp.path().join("target"), &identity).unwrap();
                }
                "hardlink" => fs::hard_link(&identity, temp.path().join("alias")).unwrap(),
                "writable" => {
                    fs::set_permissions(&identity, fs::Permissions::from_mode(0o620)).unwrap()
                }
                _ => {}
            }
            let before = fs::read(&identity).ok();
            // Existing but malformed key proves rejection happens before key loading.
            let key = temp.path().join("bad.key");
            fs::write(&key, b"not a key").unwrap();
            replacement.private_key_file = key;
            let error = format!(
                "{:#}",
                replacement
                    .run(&mut BufWriter::new(Vec::new()))
                    .unwrap_err()
            );
            assert!(!error.contains("private-key"), "{defect}: {error}");
            assert_eq!(fs::read(&signed).unwrap(), b"prior signed", "{defect}");
            assert_eq!(fs::read(&manifest).unwrap(), b"prior manifest", "{defect}");
            assert_eq!(fs::read(&context).unwrap(), b"prior context", "{defect}");
            assert_eq!(fs::read(&identity).ok(), before, "{defect}");
            assert!(fs::read_dir(temp.path()).unwrap().all(|e| {
                !e.unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".genesis-output-")
            }));
        }
    }
    #[cfg(unix)]
    #[test]
    fn identity_guard_serializes_publishers_and_rejects_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let prior = identity_fixture(b"locked prior");
        let identity = temp.path().join("genesis.expected_hash");
        publish_genesis_network_identity(&identity, prior).unwrap();
        let mut guard = GenesisNetworkIdentityGuard::acquire(&identity)
            .unwrap()
            .unwrap();
        for replace_identity in [false, true] {
            let mut replacement = replacement_args(temp.path(), prior);
            if !replace_identity {
                replacement.replace_expected_hash = None;
            }
            fs::write(replacement.out_file.as_ref().unwrap(), b"signed sentinel").unwrap();
            fs::write(
                replacement.bound_manifest_out.as_ref().unwrap(),
                b"manifest sentinel",
            )
            .unwrap();
            let error = format!(
                "{:#}",
                replacement
                    .run(&mut BufWriter::new(Vec::new()))
                    .unwrap_err()
            );
            assert!(error.contains("another genesis publisher"), "{error}");
            assert_eq!(
                fs::read(temp.path().join("genesis.signed.nrt")).unwrap(),
                b"signed sentinel"
            );
            assert_eq!(
                fs::read(temp.path().join("genesis.bound.json")).unwrap(),
                b"manifest sentinel"
            );
        }
        // An identical-byte inode replacement is still a changed custody boundary.
        let changed = stage_genesis_output(
            &identity,
            genesis_network_identity_body(prior).as_bytes(),
            "substitution",
        )
        .unwrap();
        changed.persist(&identity).unwrap();
        assert!(guard.revalidate(&identity).is_err());
        drop(guard);
        let mut guard = GenesisNetworkIdentityGuard::acquire(&identity)
            .unwrap()
            .unwrap();
        fs::write(
            &identity,
            genesis_network_identity_body(identity_fixture(b"mutated prior")),
        )
        .unwrap();
        assert!(guard.revalidate(&identity).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn interrupted_replacement_preserves_prior_identity_until_complete_retry() {
        let temp = tempfile::tempdir().unwrap();
        let prior = identity_fixture(b"interrupted prior");
        let next = identity_fixture(b"complete next");
        let identity = temp.path().join("genesis.expected_hash");
        let signed = temp.path().join("signed");
        let manifest = temp.path().join("manifest");
        let context = temp.path().join("context");
        publish_genesis_network_identity(&identity, prior).unwrap();
        let mut guard = GenesisNetworkIdentityGuard::acquire(&identity)
            .unwrap()
            .unwrap();
        let stage = || {
            [
                (
                    signed.as_path(),
                    stage_genesis_output(&signed, b"new signed", "signed").unwrap(),
                    "signed",
                ),
                (
                    manifest.as_path(),
                    stage_genesis_output(&manifest, b"new manifest", "manifest").unwrap(),
                    "manifest",
                ),
                (
                    context.as_path(),
                    stage_genesis_output(&context, b"new context", "context").unwrap(),
                    "context",
                ),
            ]
        };
        let outputs = stage();
        let next_identity = stage_genesis_output(
            &identity,
            genesis_network_identity_body(next).as_bytes(),
            "identity",
        )
        .unwrap();
        // Simulate an output destination becoming unavailable after staging.
        fs::create_dir(&manifest).unwrap();
        assert!(
            publish_guarded_genesis_bundle(&mut guard, &identity, outputs, next_identity).is_err()
        );
        assert_eq!(fs::read(&signed).unwrap(), b"new signed");
        assert_eq!(
            fs::read(&identity).unwrap(),
            genesis_network_identity_body(prior).as_bytes()
        );
        assert!(preflight_genesis_network_identity(&identity, next).is_err());
        fs::remove_dir(&manifest).unwrap();
        drop(guard);
        let mut retry = GenesisNetworkIdentityGuard::acquire(&identity)
            .unwrap()
            .unwrap();
        retry.require_identity(prior).unwrap();
        let next_identity = stage_genesis_output(
            &identity,
            genesis_network_identity_body(next).as_bytes(),
            "identity",
        )
        .unwrap();
        publish_guarded_genesis_bundle(&mut retry, &identity, stage(), next_identity).unwrap();
        assert_eq!(fs::read(&manifest).unwrap(), b"new manifest");
        assert_eq!(fs::read(&context).unwrap(), b"new context");
        assert_eq!(
            fs::read(&identity).unwrap(),
            genesis_network_identity_body(next).as_bytes()
        );
        drop(retry);
        let current = GenesisNetworkIdentityGuard::acquire(&identity)
            .unwrap()
            .unwrap();
        assert!(current.require_identity(prior).is_err());
    }
    #[test]
    fn replacement_requires_complete_explicit_output_bundle() {
        let prior = identity_fixture(b"parse prior");
        let prior_text = prior.to_string();
        let base = [
            "sign",
            "genesis.json",
            "--private-key-file",
            "key",
            "--replace-expected-hash",
            prior_text.as_str(),
        ];
        assert!(Args::try_parse_from(base).is_err());
        let flags = [
            ("--expected-hash-out", "identity"),
            ("--out-file", "signed"),
            ("--bound-manifest-out", "manifest"),
            ("--nexus-context-output", "context"),
        ];
        for omitted in 0..flags.len() {
            let mut argv = base.to_vec();
            for (index, (flag, value)) in flags.iter().enumerate() {
                if index != omitted {
                    argv.extend([*flag, *value]);
                }
            }
            assert!(Args::try_parse_from(argv).is_err());
            let temp = tempfile::tempdir().unwrap();
            let mut replacement = replacement_args(temp.path(), prior);
            match omitted {
                0 => replacement.expected_hash_out = None,
                1 => replacement.out_file = None,
                2 => replacement.bound_manifest_out = None,
                _ => replacement.nexus_context_output = None,
            }
            assert!(resolve_artifact_paths(&replacement).is_err());
        }
        let mut argv = base.to_vec();
        for (flag, value) in flags {
            argv.extend([flag, value]);
        }
        assert_eq!(
            Args::try_parse_from(argv).unwrap().replace_expected_hash,
            Some(prior)
        );
    }
    #[test]
    fn expected_hash_output_matches_the_signed_consensus_header() {
        let temp = tempfile::tempdir().expect("expected hash output temp dir");
        let expected_hash_path = temp.path().join("genesis.expected_hash");
        let args = Args {
            genesis_file: minimal_genesis_file(),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: Some(expected_hash_path.clone()),
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer)
            .expect("minimal genesis signing must succeed");
        let block = decode_framed_signed_block(
            &writer
                .into_inner()
                .expect("flush signed genesis output buffer"),
        )
        .expect("decode signed genesis output");
        let network_id = NetworkId::from_genesis_hash(block.hash());
        assert_eq!(
            fs::read_to_string(expected_hash_path).expect("read expected hash output"),
            format!("{network_id}\n"),
        );
    }
    #[test]
    fn nexus_context_output_is_the_exact_committed_amx_preimage() {
        let temp = tempfile::tempdir().expect("nexus context output temp dir");
        let context_path = temp.path().join("nexus-amx-context.v1.bin");
        let signed_path = temp.path().join("genesis.signed.nrt");
        let mut args = replacement_args(temp.path(), identity_fixture(b"unused prior"));
        args.replace_expected_hash = None;
        args.expected_hash_out = None;
        args.bound_manifest_out = None;
        args.out_file = Some(signed_path.clone());
        args.nexus_context_output = Some(context_path.clone());
        args.run(&mut BufWriter::new(Vec::new()))
            .expect("sign genesis with context export");
        let signed = decode_framed_signed_block(&fs::read(&signed_path).expect("read signed"))
            .expect("decode signed genesis");
        let preimage = fs::read(&context_path).expect("read exported context");
        let committed =
            iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(&signed)
                .expect("signed genesis metadata")
                .sumeragi_context
                .nexus_amx_context_hash;
        assert_eq!(Hash::new(&preimage), Hash::prehashed(committed));
        iroha_data_model::nexus::decode_nexus_amx_context_v1(&preimage)
            .expect("exported context decodes strictly");

        // The context output may not alias any other output, the input, or protected inputs.
        for target in ["signed", "input", "key"] {
            let mut aliased = replacement_args(temp.path(), identity_fixture(b"unused prior"));
            aliased.replace_expected_hash = None;
            aliased.nexus_context_output = Some(match target {
                "signed" => aliased.out_file.clone().unwrap(),
                "input" => aliased.genesis_file.clone(),
                _ => aliased.private_key_file.clone(),
            });
            let error = format!(
                "{:#}",
                resolve_artifact_paths(&aliased)
                    .err()
                    .expect("aliased context output must be rejected")
            );
            assert!(
                error.contains("must use different paths"),
                "{target}: {error}"
            );
        }
    }
    #[test]
    fn network_identity_publication_is_idempotent_and_refuses_drift() {
        let temp = tempfile::tempdir().expect("network identity temp dir");
        let identity_path = temp.path().join("genesis.expected_hash");
        let network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"genesis network identity")),
        );
        let different_network_id =
            NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                b"different genesis network identity",
            )));
        publish_genesis_network_identity(&identity_path, network_id)
            .expect("publish network identity");
        let published = fs::read(&identity_path).expect("read network identity");
        publish_genesis_network_identity(&identity_path, network_id)
            .expect("same network identity must be idempotent");
        let _error = publish_genesis_network_identity(&identity_path, different_network_id)
            .expect_err("different network identity must not replace the trust root");
        assert_eq!(
            fs::read(&identity_path).expect("reread network identity"),
            published,
        );
        assert!(
            fs::read_dir(temp.path())
                .expect("list network identity directory")
                .all(|entry| {
                    !entry
                        .expect("network identity directory entry")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".genesis-identity-")
                }),
            "atomic publication must not retain temporary files"
        );
    }
    #[cfg(unix)]
    #[test]
    fn existing_network_identity_requires_safe_single_link_custody() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().expect("network identity custody temp dir");
        let identity_path = temp.path().join("genesis.expected_hash");
        let network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"custody identity")),
        );
        publish_genesis_network_identity(&identity_path, network_id)
            .expect("publish network identity");

        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o620))
            .expect("make identity group-writable");
        let writable_error = publish_genesis_network_identity(&identity_path, network_id)
            .expect_err("group-writable trust roots must be rejected");
        assert!(
            writable_error
                .to_string()
                .contains("not group/world writable"),
            "unexpected custody diagnostic: {writable_error:#}"
        );

        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
            .expect("restore safe identity mode");
        let alias = temp.path().join("identity-alias");
        fs::hard_link(&identity_path, &alias).expect("create identity hard link");
        let linked_error = publish_genesis_network_identity(&identity_path, network_id)
            .expect_err("multiply-linked trust roots must be rejected");
        assert!(
            linked_error.to_string().contains("single-link"),
            "unexpected hard-link diagnostic: {linked_error:#}"
        );
    }
    #[test]
    fn pop_hex_decoder_accepts_one_optional_prefix_and_rejects_malformed_input() {
        assert_eq!(decode_hex("a50f").expect("bare hex"), [0xA5, 0x0F]);
        assert_eq!(decode_hex("0xa50f").expect("prefixed hex"), [0xA5, 0x0F]);
        assert!(decode_hex("0x0xa50f").is_err());
        assert!(decode_hex("abc").is_err());
    }
    #[test]
    fn expected_public_key_must_match_selected_private_key() {
        let selected = KeyPair::try_from_seed(vec![7_u8; 32], Algorithm::Ed25519)
            .expect("selected fixture key");
        let different = KeyPair::try_from_seed(vec![8_u8; 32], Algorithm::Ed25519)
            .expect("different fixture key");
        ensure_expected_public_key(&selected, Some(selected.public_key()))
            .expect("matching public key must be accepted");
        let error = ensure_expected_public_key(&selected, Some(different.public_key()))
            .expect_err("mismatched public key must be rejected");
        assert!(
            error.to_string().contains("--expected-public-key"),
            "mismatch error should identify the failed invariant: {error:#}"
        );
    }
    #[test]
    fn run_returns_err_on_invalid_topology_json() {
        let args = Args {
            genesis_file: npos_genesis_file(),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some("not valid json".to_owned()),
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        let result = args.run(&mut writer);
        assert!(result.is_err());
    }
    #[test]
    fn sign_requires_consensus_mode_in_manifest() {
        let args = Args {
            genesis_file: invalid_genesis_file_missing_consensus_mode(),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        let err = args
            .run(&mut writer)
            .expect_err("missing consensus_mode should be rejected");
        assert!(
            err.to_string().contains("consensus_mode"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn missing_pops_fail_when_topology_provided() {
        let genesis_file = npos_genesis_file();
        let (topology, peer_pops) = valid_test_topology(4);
        let topology_json = norito::json::to_json(&topology).unwrap();
        // Provide PoP only for the first peer to trigger the missing-pop validation.
        let args = Args {
            genesis_file,
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some(topology_json),
            peer_pops: vec![peer_pops[0].clone()],
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        let result = args.run(&mut writer);
        assert!(
            result.is_err(),
            "signing should fail when topology peers lack PoPs"
        );
    }
    #[test]
    fn topology_override_replaces_existing_entries() {
        use iroha_data_model::isi::register::RegisterBox;
        let existing_kp = checked_genesis_sign_keypair_with_algorithm(Algorithm::BlsNormal);
        let existing_peer = PeerId::new(existing_kp.public_key().clone());
        let existing_pop = iroha_crypto::bls_normal_pop_prove(existing_kp.private_key())
            .expect("generate BLS PoP");
        let (new_peers, peer_pops) = valid_test_topology(4);
        let genesis_file = tempfile::NamedTempFile::new().expect("create temp genesis file");
        let manifest = GenesisBuilder::new_without_executor(
            ChainId::from("topology-override"),
            PathBuf::from("."),
        )
        .append_parameter(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        ))
        .set_topology(vec![GenesisTopologyEntry::new(existing_peer, existing_pop)])
        .complete_for_test()
        .build_raw()
        .expect("complete topology-override fixture")
        .with_consensus_mode(SumeragiConsensusMode::Npos)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
        let manifest = with_explicit_test_xor_allocations(manifest, &new_peers);
        let json = norito::json::to_json_pretty(&manifest).expect("serialize genesis manifest");
        fs::write(genesis_file.path(), json).expect("write genesis json");
        let topology_json = norito::json::to_json(&new_peers).unwrap();
        let args = Args {
            genesis_file: genesis_file.path().to_path_buf(),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some(topology_json),
            peer_pops,
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer).expect("sign should succeed");
        writer.flush().expect("flush output");
        let bytes = writer.into_inner().expect("extract buffer");
        let block = decode_framed_signed_block(&bytes).expect("decode signed block");
        let mut registered_peers = Vec::new();
        for tx in block.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instr in instructions {
                    if let Some(RegisterBox::Peer(register)) =
                        instr.as_any().downcast_ref::<RegisterBox>()
                    {
                        registered_peers.push(register.peer.clone());
                    }
                }
            }
        }
        assert_eq!(
            registered_peers, new_peers,
            "expected topology override to replace existing entries"
        );
    }
    #[test]
    fn sign_binds_context_and_preserves_direct_manifest_instruction_batches() {
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_data_model::parameter::BlockParameter;
        use std::num::NonZeroU64;
        let manifest = GenesisBuilder::new_without_executor(
            ChainId::from("sign-direct-manifest-regression"),
            ".",
        )
        .append_parameter(Parameter::Sumeragi(SumeragiParameter::MaxClockDriftMs(100)))
        .append_parameter(Parameter::Block(BlockParameter::MaxTransactions(
            NonZeroU64::new(512).expect("non-zero"),
        )))
        .next_transaction()
        .append_parameter(Parameter::Sumeragi(SumeragiParameter::MaxClockDriftMs(333)))
        .set_topology_for_test(valid_test_topology_entries(4))
        .build_raw()
        .expect("complete direct-sign fixture")
        .with_consensus_mode(SumeragiConsensusMode::Permissioned)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
        let key_pair = KeyPair::try_from_seed(vec![0x43; 32], Algorithm::Ed25519)
            .expect("derive checked genesis fixture key");
        let (manifest, _) = bind_and_sign_staged_sumeragi_context(
            manifest,
            &key_pair,
            None,
            None,
            iroha_core::state::default_genesis_confidential_policy_hash(),
            Some(1_700_000_000_000),
        )
        .expect("complete the fixture's actual staged consensus commitments");
        let genesis_file = tempfile::NamedTempFile::new().expect("create temp genesis file");
        let json = norito::json::to_json_pretty(&manifest).expect("serialize genesis manifest");
        fs::write(genesis_file.path(), json).expect("write genesis json");
        let args = Args {
            genesis_file: genesis_file.path().to_path_buf(),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: vec![],
            private_key_file: test_private_key_file_for(&key_pair),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer).expect("sign should succeed");
        writer.flush().expect("flush output");
        let bytes = writer.into_inner().expect("extract buffer");
        let actual = decode_framed_signed_block(&bytes).expect("decode signed block");
        // Signing derives exactly these two execution commitments. Preserve every other
        // context field, recompute its fingerprint, and compare every complete instruction batch.
        let signed_meta = consensus_handshake_meta(&actual);
        signed_meta
            .validate()
            .expect("signed consensus metadata is complete");
        let mut bound_parameters = manifest.sumeragi_context_parameters();
        bound_parameters.nexus_amx_context_hash =
            signed_meta.sumeragi_context.nexus_amx_context_hash;
        bound_parameters.execution_policy_hash = signed_meta.sumeragi_context.execution_policy_hash;
        let expected = manifest
            .with_sumeragi_context_parameters(bound_parameters)
            .with_consensus_meta()
            .expect("valid fixture consensus parameters")
            .build_and_sign_with_confidential_policy_hash(
                &key_pair,
                Some(iroha_core::state::default_genesis_confidential_policy_hash()),
            )
            .expect("direct signing of the exactly context-bound manifest should succeed");
        assert_genesis_signatures_verify(&actual, &key_pair);
        let actual_instructions: Vec<_> = actual
            .external_transactions()
            .map(|tx| tx.instructions().clone())
            .collect();
        let expected_instructions: Vec<_> = expected
            .0
            .external_transactions()
            .map(|tx| tx.instructions().clone())
            .collect();
        assert_eq!(
            actual_instructions, expected_instructions,
            "binding computed context must preserve all remaining instructions and transaction boundaries"
        );
        assert_eq!(
            actual.da_proof_policies(),
            expected.0.da_proof_policies(),
            "signing an unchanged manifest should preserve DA proof policies"
        );
        assert_eq!(
            actual.header().confidential_features(),
            expected.0.header().confidential_features(),
            "signing an unchanged manifest should commit the default genesis confidential policy"
        );
    }
    #[test]
    fn generated_nexus_localnet_can_be_resigned_with_its_peer_config() {
        let temp = tempfile::tempdir().expect("create localnet output dir");
        let output_dir = fs::canonicalize(temp.path())
            .expect("canonical localnet output parent")
            .join("network");
        let seed = "localnet-resign-confidential-policy".to_owned();
        let options = iroha_deploy::localnet::LocalnetOptions {
            service_profile: iroha_deploy::localnet::LocalnetServiceProfile::Standard,
            sora_profile: Some(iroha_deploy::localnet::SoraProfile::Nexus),
            perf_profile: None,
            peers: std::num::NonZeroU16::new(4).expect("non-zero peer count"),
            seed: Some(seed.clone()),
            bind_host: iroha_deploy::localnet::DEFAULT_BIND_HOST.to_owned(),
            public_host: iroha_deploy::localnet::DEFAULT_PUBLIC_HOST.to_owned(),
            base_api_port: 31_080,
            base_p2p_port: 31_337,
            out_dir: output_dir.clone(),
            extra_accounts: 0,
            assets: Vec::new(),
            block_cadence_ms: None,
            consensus_mode: SumeragiConsensusMode::Npos,
        };
        iroha_deploy::localnet::generate_localnet(&options, &mut BufWriter::new(Vec::new()))
            .expect("generate Nexus localnet");
        let generated_bytes =
            fs::read(output_dir.join("genesis.signed.nrt")).expect("read generated signed genesis");
        let config_path = output_dir.join("peer0.toml");
        let config = load_peer_config(&config_path).expect("load generated peer config");
        let expected_policy = iroha_core::state::default_genesis_confidential_policy_hash();
        let (genesis_public_key, genesis_private_key) =
            iroha_deploy::localnet::generate_genesis_key_pair(
                Some(seed.as_bytes()),
                iroha_deploy::localnet::GENESIS_SEED,
            )
            .expect("derive generated localnet genesis key");
        let genesis_key_pair = KeyPair::new(genesis_public_key, genesis_private_key.0.clone())
            .expect("reconstruct generated localnet genesis key pair");
        let mut invalid_compliance_config = config.clone();
        invalid_compliance_config.nexus.compliance.enabled = true;
        invalid_compliance_config.nexus.compliance.policy_dir = None;
        let invalid_compliance_error = bind_and_sign_staged_sumeragi_context(
            RawGenesisTransaction::from_path(output_dir.join("genesis.json"))
                .expect("reload generated genesis manifest"),
            &genesis_key_pair,
            Some(&invalid_compliance_config),
            Some(iroha_core::da::proof_policy_bundle(
                &invalid_compliance_config.nexus.lane_config,
            )),
            iroha_core::state::default_genesis_confidential_policy_hash(),
            None,
        )
        .expect_err("compliance-enabled staging must require a policy directory");
        assert!(
            invalid_compliance_error
                .to_string()
                .contains("lane compliance is enabled but no policy_dir is configured"),
            "unexpected compliance staging error: {invalid_compliance_error:#}"
        );
        let args = Args {
            genesis_file: output_dir.join("genesis.json"),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: vec![],
            private_key_file: test_private_key_file_for(&genesis_key_pair),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: Some(config_path),
        };
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer)
            .expect("re-sign generated localnet genesis with its peer config");
        writer.flush().expect("flush signed genesis");
        let bytes = writer.into_inner().expect("extract signed genesis");
        let generated_block =
            decode_framed_signed_block(&generated_bytes).expect("decode generated signed genesis");
        let block = decode_framed_signed_block(&bytes).expect("decode re-signed genesis");
        // Each signing invocation intentionally stamps a fresh creation-time base, so wire bytes,
        // transaction signatures, and the block signature are expected to differ. Compare the
        // complete consensus-bearing semantics and verify both independently signed artifacts.
        let generated_instructions = generated_block
            .external_transactions()
            .map(|transaction| transaction.instructions().clone())
            .collect::<Vec<_>>();
        let resigned_instructions = block
            .external_transactions()
            .map(|transaction| transaction.instructions().clone())
            .collect::<Vec<_>>();
        assert_eq!(generated_instructions.len(), resigned_instructions.len());
        for (batch_index, (generated, resigned)) in generated_instructions
            .iter()
            .zip(&resigned_instructions)
            .enumerate()
        {
            if generated != resigned {
                let generated_json = norito::json::to_json(generated)
                    .expect("encode generated instruction batch diagnostics");
                let resigned_json = norito::json::to_json(resigned)
                    .expect("encode re-signed instruction batch diagnostics");
                panic!(
                    "localnet generation and matching-key re-sign differ at instruction batch {batch_index}:\ngenerated: {generated_json}\nre-signed: {resigned_json}"
                );
            }
        }
        assert_eq!(
            generated_block.external_transactions().count(),
            block.external_transactions().count(),
            "localnet generation and matching-key re-sign must preserve transaction count"
        );
        let generated_topology_entries = generated_block
            .external_transactions()
            .filter_map(|transaction| match transaction.instructions() {
                Executable::Instructions(batch) => Some(batch),
                _ => None,
            })
            .flatten()
            .filter(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .is_some_and(|register| matches!(register, RegisterBox::Peer(_)))
            })
            .count();
        let resigned_topology_entries = block
            .external_transactions()
            .filter_map(|transaction| match transaction.instructions() {
                Executable::Instructions(batch) => Some(batch),
                _ => None,
            })
            .flatten()
            .filter(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .is_some_and(|register| matches!(register, RegisterBox::Peer(_)))
            })
            .count();
        assert_eq!(generated_topology_entries, options.peers.get() as usize);
        assert_eq!(generated_topology_entries, resigned_topology_entries);
        assert_eq!(
            generated_block.da_proof_policies(),
            block.da_proof_policies()
        );
        assert_eq!(
            generated_block.header().confidential_features(),
            block.header().confidential_features()
        );
        let generated_consensus_meta = consensus_handshake_meta(&generated_block);
        let resigned_consensus_meta = consensus_handshake_meta(&block);
        assert_eq!(generated_consensus_meta, resigned_consensus_meta);
        assert_ne!(
            generated_consensus_meta
                .sumeragi_context
                .nexus_amx_context_hash,
            [0; 32],
            "staged Nexus/AMX context commitment must not be empty"
        );
        assert_genesis_signatures_verify(&generated_block, &genesis_key_pair);
        assert_genesis_signatures_verify(&block, &genesis_key_pair);
        assert_eq!(
            block
                .header()
                .confidential_features()
                .expect("re-signed genesis has confidential digest")
                .zk_policy_hash,
            Some(expected_policy),
        );
    }
    #[test]
    fn npos_bootstrap_requires_explicit_asset_and_never_mints_allocations() {
        let (peers, _) = valid_test_topology(4);
        let asset = SumeragiNposParameters::default().xor_asset_definition_id;
        let escrow = iroha_test_samples::ALICE_ID.clone();
        let make_builder = || {
            GenesisBuilder::new_without_executor(
                ChainId::from("explicit-xor-allocation-test"),
                PathBuf::from("."),
            )
            .complete_for_test()
        };
        let mut registrations = BootstrapRegistrations {
            accounts: peers
                .iter()
                .map(|peer| AccountId::new(peer.public_key().clone()))
                .collect(),
            asset_defs: BTreeSet::new(),
        };
        assert!(
            append_npos_bootstrap(make_builder(), &mut registrations, &peers, &escrow, &asset)
                .is_err()
        );
        registrations.asset_defs.insert(asset.clone());
        let manifest =
            append_npos_bootstrap(make_builder(), &mut registrations, &peers, &escrow, &asset)
                .expect("explicit allocations owned by caller")
                .build_raw()
                .expect("raw bootstrap");
        assert_eq!(
            manifest
                .instructions()
                .filter(|instruction| instruction
                    .as_any()
                    .downcast_ref::<RegisterPublicLaneValidator>()
                    .is_some())
                .count(),
            4
        );
        assert!(
            manifest
                .instructions()
                .all(|instruction| instruction.as_any().downcast_ref::<MintBox>().is_none())
        );
    }
    #[test]
    fn sccp_sign_preparation_places_initialization_after_original_staking() {
        use iroha_data_model::isi::sccp::InitializeSccpV1;

        let (peers, _) = valid_test_topology(4);
        let manifest = GenesisBuilder::new_without_executor(
            ChainId::from("sccp-sign-order"),
            PathBuf::from("."),
        )
        .append_parameter(Parameter::Custom(
            SumeragiNposParameters {
                max_validators: 4,
                ..SumeragiNposParameters::default()
            }
            .into_custom_parameter(),
        ))
        .set_topology_for_test(valid_test_topology_entries(4))
        .build_raw()
        .expect("complete signing fixture")
        .with_consensus_mode(SumeragiConsensusMode::Npos)
        .with_consensus_meta()
        .expect("consensus metadata");
        let manifest = with_explicit_test_xor_allocations(manifest, &peers);
        let manifest = iroha_deploy::genesis::sccp::append_profile(manifest, [9; 32])
            .expect("explicit SCCP profile");
        assert!(!manifest_has_npos_bootstrap(&manifest));
        let prepared = prepare_genesis_for_signing(
            manifest.clone(),
            None,
            SumeragiConsensusMode::Npos,
            None,
            &[],
        )
        .expect("prepare SCCP genesis with original staking");
        let mut registered = BTreeSet::new();
        let mut initialized = false;
        for instruction in prepared.instructions() {
            if let Some(registration) = instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
            {
                assert!(
                    !initialized,
                    "original staking must precede SCCP initialization"
                );
                registered.insert(registration.validator.clone());
            }
            if instruction.as_any().is::<InitializeSccpV1>() {
                assert!(!initialized, "SCCP initializes once");
                assert_eq!(registered.len(), 4);
                initialized = true;
            }
        }
        assert!(initialized);
        let last = prepared.transactions().last().expect("initializer batch");
        assert_eq!(last.instructions().len(), 1);
        assert!(last.instructions()[0].as_any().is::<InitializeSccpV1>());

        // Repreparation preserves the already bootstrapped ordering exactly.
        let again = prepare_genesis_for_signing(
            prepared.clone(),
            None,
            SumeragiConsensusMode::Npos,
            None,
            &[],
        )
        .expect("idempotent preparation");
        assert_eq!(
            norito::codec::Encode::encode(&again),
            norito::codec::Encode::encode(&prepared)
        );

        // Execute the actual staged genesis, including SCCP's original staking
        // checks and the pinned liability policy, before signing its final body.
        let key_pair = test_genesis_key_pair();
        let (_, signed) = bind_and_sign_staged_sumeragi_context(
            prepared,
            &key_pair,
            None,
            None,
            resolve_confidential_policy_hash(),
            Some(1_000),
        )
        .expect("SCCP profile must execute and bind a genuine signed genesis");
        assert_genesis_signatures_verify(&signed.0, &key_pair);

        // An initializer mixed with other effects cannot be moved implicitly.
        let mixed = manifest
            .into_builder()
            .append_instruction(iroha_data_model::isi::Log::new(
                iroha_data_model::level::Level::INFO,
                "after SCCP".to_owned(),
            ))
            .build_raw()
            .expect("mixed initializer batch");
        assert!(
            prepare_genesis_for_signing(mixed, None, SumeragiConsensusMode::Npos, None, &[],)
                .is_err()
        );
    }
    #[test]
    fn sign_auto_bootstraps_npos_validators_for_topology() {
        let (peers, peer_pops) = valid_test_topology(4);
        let genesis_file = with_test_authority_for_topology(npos_genesis_file(), &peers);
        let manifest =
            RawGenesisTransaction::from_path(&genesis_file).expect("parse NPoS genesis fixture");
        let _chain_discriminant = staged_genesis_chain_discriminant(&manifest);
        let expected_escrow = configured_npos_bootstrap_escrow_account_id(&manifest, None)
            .expect("resolve default staking escrow");
        let expected_stake_asset = configured_npos_bootstrap_stake_asset_id(&manifest, None)
            .expect("resolve genesis-pinned staking asset");
        let genesis_key_pair = test_genesis_key_pair();
        let private_key_file = test_private_key_file_for(&genesis_key_pair);
        let public_key_derived_orphan = AccountId::new(
            KeyPair::try_from_seed(
                genesis_key_pair
                    .public_key()
                    .to_string()
                    .bytes()
                    .chain(b"npos-escrow-account".iter().copied())
                    .collect(),
                Algorithm::default(),
            )
            .expect("derive prohibited public-key-based orphan identity")
            .public_key()
            .clone(),
        );
        let topology_json = norito::json::to_json(&peers).unwrap();
        let args = Args {
            genesis_file,
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some(topology_json),
            peer_pops,
            private_key_file,
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer).expect("sign should succeed");
        writer.flush().expect("flush output");
        let bytes = writer.into_inner().expect("extract buffer");
        let block = decode_framed_signed_block(&bytes).expect("decode signed block");
        let mut validators = std::collections::BTreeSet::new();
        let mut minted_asset_ids = std::collections::BTreeSet::new();
        let mut registered_accounts = std::collections::BTreeSet::new();
        for tx in block.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instr in instructions {
                    if let Some(RegisterBox::Account(register)) =
                        instr.as_any().downcast_ref::<RegisterBox>()
                    {
                        registered_accounts.insert(register.object.id.clone());
                    }
                    if let Some(register) =
                        instr.as_any().downcast_ref::<RegisterPublicLaneValidator>()
                    {
                        assert_eq!(
                            register.monetary_plan,
                            PublicLaneMonetaryPlanV1::genesis_registration(
                                AssetId::new(
                                    expected_stake_asset.clone(),
                                    register.validator.clone(),
                                ),
                                AssetId::new(expected_stake_asset.clone(), expected_escrow.clone(),),
                                register.initial_stake.clone(),
                            ),
                            "signed bootstrap must bind its configured stake custody",
                        );
                        validators.insert(register.validator.clone());
                        assert_eq!(
                            register.monetary_plan,
                            PublicLaneMonetaryPlanV1::genesis_registration(
                                AssetId::new(
                                    expected_stake_asset.clone(),
                                    register.stake_account.clone(),
                                ),
                                AssetId::new(expected_stake_asset.clone(), expected_escrow.clone(),),
                                register.initial_stake.clone(),
                            ),
                            "bootstrap consent must bind the configured custody transfer",
                        );
                    }
                    if let Some(mint) = instr.as_any().downcast_ref::<MintBox>()
                        && let MintBox::Asset(mint_asset) = mint
                    {
                        minted_asset_ids.insert(mint_asset.destination.definition().clone());
                    }
                }
            }
        }
        let expected = peers
            .iter()
            .map(|peer| AccountId::new(peer.public_key().clone()))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            validators, expected,
            "expected NPoS bootstrap to register topology validators"
        );
        assert!(
            minted_asset_ids.contains(
                &iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                    .parse()
                    .unwrap()
            ),
            "isolated NPoS fixture allocations must use the canonical XOR definition"
        );
        assert!(
            registered_accounts.contains(&expected_escrow),
            "auto-bootstrap must register the escrow account selected by nexus.staking"
        );
        assert!(
            !registered_accounts.contains(&public_key_derived_orphan),
            "auto-bootstrap must not emit an orphan account derived from public genesis data"
        );
    }
    fn bind_fixture_network_and_governance_accounts(table: &mut toml::Table, discriminant: u16) {
        // The real Taira profile explicitly projects these disabled-service and
        // governance identities too. User config deliberately rejects foreign
        // literals, including unprojected default-network account strings.
        let operator = staged_default_account_literal(
            &defaults::soranet::vpn::operator_account_id(),
            discriminant,
            "fixture VPN operator",
        )
        .expect("manifest-specific VPN operator");
        let network = table
            .get_mut("network")
            .and_then(toml::Value::as_table_mut)
            .expect("fixture network config");
        assert!(
            !network.contains_key("soranet_vpn"),
            "fixture must not overwrite an explicit VPN identity"
        );
        network.insert(
            "soranet_vpn".to_owned(),
            toml::Value::Table(toml::Table::from_iter([(
                "operator_account_id".to_owned(),
                toml::Value::String(operator),
            )])),
        );
        let mut governance = toml::Table::new();
        for (field, literal) in [
            (
                "citizenship_escrow_account",
                defaults::governance::citizenship_escrow_account(),
            ),
            (
                "bond_escrow_account",
                defaults::governance::bond_escrow_account(),
            ),
            (
                "slash_receiver_account",
                defaults::governance::slash_receiver_account(),
            ),
            (
                "viral_incentive_pool_account",
                defaults::governance::viral_incentive_pool_account(),
            ),
            (
                "viral_escrow_account",
                defaults::governance::viral_escrow_account(),
            ),
            (
                "sorafs_pin_fee_treasury_account",
                defaults::governance::sorafs_pin_fee::treasury_account(),
            ),
        ] {
            governance.insert(
                field.to_owned(),
                toml::Value::String(
                    staged_default_account_literal(&literal, discriminant, field)
                        .expect("manifest-specific governance identity"),
                ),
            );
        }
        assert!(
            !table.contains_key("gov"),
            "fixture must not overwrite explicit governance identities"
        );
        table.insert("gov".to_owned(), toml::Value::Table(governance));
    }
    fn nexus_profile_with_staking_overrides(
        genesis_file: &Path,
        overrides: &str,
    ) -> (tempfile::TempDir, PathBuf) {
        let manifest = RawGenesisTransaction::from_path(genesis_file)
            .expect("load manifest selected by the staking-policy fixture");
        let mut table = checked_in_consensus_config_table(&nexus_profile_config_path());
        table.insert(
            "chain".to_owned(),
            toml::Value::String(manifest.chain_id().to_string()),
        );
        table.insert(
            "chain_discriminant".to_owned(),
            toml::Value::Integer(i64::from(manifest.chain_discriminant())),
        );
        table["genesis"]
            .as_table_mut()
            .expect("genesis config")
            .insert(
                "public_key".to_owned(),
                toml::Value::String(test_genesis_key_pair().public_key().to_string()),
            );
        bind_fixture_network_and_governance_accounts(&mut table, manifest.chain_discriminant());
        // Preserve the profile's consensus settings while supplying the fixture's
        // real chain/account identities, rather than unresolved deployment secrets.
        let default_nexus =
            staged_default_nexus(&manifest).expect("manifest-specific default accounts");
        let mut staking = overrides
            .parse::<toml::Table>()
            .expect("typed staking overrides");
        staking.insert(
            "stake_escrow_account_id".to_owned(),
            toml::Value::String(default_nexus.staking.stake_escrow_account_id),
        );
        staking.insert(
            "slash_sink_account_id".to_owned(),
            toml::Value::String(default_nexus.staking.slash_sink_account_id),
        );
        let nexus = table["nexus"].as_table_mut().expect("Nexus config");
        nexus.insert("staking".to_owned(), toml::Value::Table(staking));
        let pipeline = table
            .entry("pipeline")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("pipeline config");
        let gas = pipeline
            .entry("gas")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("gas config");
        gas.insert(
            "tech_account_id".to_owned(),
            toml::Value::String(
                staged_default_pipeline(&manifest)
                    .expect("manifest-specific gas account")
                    .gas
                    .tech_account_id,
            ),
        );
        let directory = tempfile::Builder::new()
            .prefix("kagami-nexus-profile-")
            .tempdir()
            .expect("private peer config directory");
        let canonical_directory =
            crate::secure_fs::prepare_empty_private_directory(directory.path())
                .expect("canonical owner-only peer config directory");
        let path = canonical_directory.join("peer.toml");
        crate::secure_fs::write_private_file_atomic(
            &path,
            toml::to_string(&table)
                .expect("encode staking-policy fixture")
                .as_bytes(),
        )
        .expect("write owner-only peer config fixture");
        let config =
            load_peer_config(&path).expect("fixture must pass production config admission");
        ensure_peer_config_matches_manifest(&config, &manifest)
            .expect("fixture config must bind its exact manifest");
        (directory, path)
    }
    fn nexus_profile_with_validator_modes(
        genesis_file: &Path,
        public_mode: &str,
        restricted_mode: &str,
    ) -> (tempfile::TempDir, PathBuf) {
        nexus_profile_with_staking_overrides(
            genesis_file,
            &format!(
                "public_validator_mode = \"{public_mode}\"\nrestricted_validator_mode = \"{restricted_mode}\""
            ),
        )
    }
    fn nexus_profile_with_stake_asset_id(
        genesis_file: &Path,
        stake_asset_id: &str,
    ) -> (tempfile::TempDir, PathBuf) {
        nexus_profile_with_staking_overrides(
            genesis_file,
            &format!(
                "public_validator_mode = \"stake_elected\"\nrestricted_validator_mode = \"admin_managed\"\nstake_asset_id = \"{stake_asset_id}\""
            ),
        )
    }
    #[test]
    fn sign_auto_bootstraps_using_configured_alias_backed_stake_asset() {
        let (peers, peer_pops) = valid_test_topology(4);
        let topology_json = norito::json::to_json(&peers).unwrap();
        let configured_asset_id: AssetDefinitionId = "6TEAJqbb8oEPmLncoNiMRbLEK6tw"
            .parse()
            .expect("valid canonical asset id");
        let genesis_file =
            with_test_authority_for_topology(alias_backed_npos_genesis_file(), &peers);
        let (_config_directory, config_path) =
            nexus_profile_with_stake_asset_id(&genesis_file, "xor#universal");
        let manifest = RawGenesisTransaction::from_path(&genesis_file)
            .expect("parse alias-backed NPoS genesis fixture");
        let _chain_discriminant = staged_genesis_chain_discriminant(&manifest);
        let config = load_peer_config(&config_path).expect("load staking configuration");
        let expected_escrow = configured_npos_bootstrap_escrow_account_id(&manifest, Some(&config))
            .expect("resolve configured staking escrow");
        let args = Args {
            genesis_file,
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some(topology_json),
            peer_pops,
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: Some(config_path),
        };
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer).expect("sign should succeed");
        writer.flush().expect("flush output");
        let bytes = writer.into_inner().expect("extract buffer");
        let block = decode_framed_signed_block(&bytes).expect("decode signed block");
        let mut minted_asset_ids = std::collections::BTreeSet::new();
        let mut registered_asset_ids = std::collections::BTreeSet::new();
        for tx in block.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instr in instructions {
                    if let Some(mint) = instr.as_any().downcast_ref::<MintBox>()
                        && let MintBox::Asset(mint_asset) = mint
                    {
                        minted_asset_ids.insert(mint_asset.destination.definition().clone());
                    }
                    if let Some(RegisterBox::AssetDefinition(register)) =
                        instr.as_any().downcast_ref::<RegisterBox>()
                    {
                        registered_asset_ids.insert(register.object.id.clone());
                    }
                    if let Some(register) =
                        instr.as_any().downcast_ref::<RegisterPublicLaneValidator>()
                    {
                        assert_eq!(
                            register.monetary_plan,
                            PublicLaneMonetaryPlanV1::genesis_registration(
                                AssetId::new(
                                    configured_asset_id.clone(),
                                    register.stake_account.clone()
                                ),
                                AssetId::new(configured_asset_id.clone(), expected_escrow.clone()),
                                register.initial_stake.clone(),
                            ),
                        );
                    }
                }
            }
        }
        assert!(
            minted_asset_ids.contains(&configured_asset_id),
            "expected bootstrap mint to target configured stake asset"
        );
        assert!(
            !registered_asset_ids.contains(&retired_synthetic_stake_asset_id()),
            "alias-backed stake asset should not force the synthetic localnet bootstrap asset"
        );
    }
    #[test]
    fn staged_default_public_assets_follow_manifest_binding_without_changing_generic_defaults() {
        let public =
            RawGenesisTransaction::from_path(public_taira_alias_backed_npos_genesis_file())
                .expect("load public Taira manifest");
        let public_nexus = staged_default_nexus(&public).expect("resolve public default assets");
        let public_xor = configured_npos_bootstrap_stake_asset_id(&public, None)
            .expect("resolve the asset used by bootstrap")
            .to_string();
        assert_eq!(public_xor, crate::genesis::TAIRA_XOR_ASSET_DEFINITION_ID);
        assert_eq!(public_nexus.staking.stake_asset_id, public_xor);
        assert_eq!(
            public_nexus.fees.fee_asset_id.canonical_address(),
            public_xor
        );

        let generic = RawGenesisTransaction::from_path(npos_genesis_file())
            .expect("load generic NPoS manifest");
        let generic_nexus = staged_default_nexus(&generic).expect("resolve generic default assets");
        assert_eq!(
            generic_nexus.staking.stake_asset_id,
            defaults::nexus::staking::stake_asset_id()
        );
        assert_eq!(
            generic_nexus.fees.fee_asset_id.canonical_address(),
            defaults::nexus::fees::fee_asset_id()
        );
        assert_eq!(
            generic_nexus.staking.stake_asset_id,
            configured_npos_bootstrap_stake_asset_id(&generic, None)
                .expect("generic bootstrap asset")
                .to_string(),
        );
    }

    #[test]
    fn public_taira_auto_bootstrap_uses_alias_bound_xor_without_config() {
        let (peers, peer_pops) = valid_test_topology(4);
        let topology_json = norito::json::to_json(&peers).unwrap();
        let configured_asset_id: AssetDefinitionId = crate::genesis::TAIRA_XOR_ASSET_DEFINITION_ID
            .parse()
            .expect("valid canonical asset id");
        let bound_manifest = tempfile::NamedTempFile::new().expect("create bound manifest file");
        let args = Args {
            genesis_file: with_test_authority_for_topology(
                public_taira_alias_backed_npos_genesis_file(),
                &peers,
            ),
            out_file: None,
            bound_manifest_out: Some(bound_manifest.path().to_path_buf()),
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some(topology_json),
            peer_pops,
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer).expect("sign should succeed");
        writer.flush().expect("flush output");
        let bytes = writer.into_inner().expect("extract buffer");
        let block = decode_framed_signed_block(&bytes).expect("decode signed block");
        let rebound = RawGenesisTransaction::from_path(bound_manifest.path())
            .expect("parse config-bound Taira manifest");
        assert_eq!(
            rebound.chain_id(),
            &crate::genesis::profile_defaults(crate::genesis::GenesisProfile::Iroha3Taira).chain_id
        );
        assert_eq!(
            rebound.chain_discriminant(),
            crate::genesis::profile::TAIRA_CHAIN_DISCRIMINANT,
            "NPoS bootstrap rebuild must preserve Taira's I105 network prefix"
        );
        assert_eq!(
            staged_default_nexus(&rebound)
                .expect("resolve the same no-config staking policy used by staging")
                .staking
                .stake_asset_id,
            configured_asset_id.to_string(),
            "offline execution must use the same canonical XOR asset as public bootstrap"
        );
        let mut minted_asset_ids = std::collections::BTreeSet::new();
        let mut registered_asset_ids = std::collections::BTreeSet::new();
        for tx in block.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instr in instructions {
                    if let Some(mint) = instr.as_any().downcast_ref::<MintBox>()
                        && let MintBox::Asset(mint_asset) = mint
                    {
                        minted_asset_ids.insert(mint_asset.destination.definition().clone());
                    }
                    if let Some(RegisterBox::AssetDefinition(register)) =
                        instr.as_any().downcast_ref::<RegisterBox>()
                    {
                        registered_asset_ids.insert(register.object.id.clone());
                    }
                }
            }
        }
        assert!(
            minted_asset_ids.contains(&configured_asset_id),
            "public Taira bootstrap should mint to canonical XOR"
        );
        assert!(
            !registered_asset_ids.contains(&retired_synthetic_stake_asset_id()),
            "public Taira bootstrap must not register the synthetic NPoS stake asset"
        );
    }
    #[test]
    fn public_nexus_auto_bootstrap_requires_xor_alias_binding() {
        let (peers, peer_pops) = valid_test_topology(4);
        let topology_json = norito::json::to_json(&peers).unwrap();
        let args = Args {
            genesis_file: with_test_authority_for_topology(
                public_nexus_npos_genesis_file_without_xor_alias(),
                &peers,
            ),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some(topology_json),
            peer_pops,
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        let err = args
            .run(&mut writer)
            .expect_err("public Nexus without XOR binding should fail");
        assert!(
            err.to_string().contains(crate::genesis::PUBLIC_XOR_ALIAS),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn public_taira_auto_bootstrap_rejects_configured_stake_asset_that_bypasses_xor_binding() {
        let (peers, peer_pops) = valid_test_topology(4);
        let topology_json = norito::json::to_json(&peers).unwrap();
        let genesis_file =
            with_test_authority_for_topology(public_taira_alias_backed_npos_genesis_file(), &peers);
        let (_config_directory, config_path) =
            nexus_profile_with_stake_asset_id(&genesis_file, "61CtjvNd9T3THAR65GsMVHr82Bjc");
        let args = Args {
            genesis_file,
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some(topology_json),
            peer_pops,
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: Some(config_path),
        };
        let mut writer = BufWriter::new(Vec::new());
        let err = args
            .run(&mut writer)
            .expect_err("public stake config must match XOR alias binding");
        assert!(
            err.to_string()
                .contains("NPoS stake asset must equal the committed canonical XOR definition"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn public_taira_auto_bootstrap_rejects_conflicting_xor_alias_bindings() {
        let (peers, peer_pops) = valid_test_topology(4);
        let topology_json = norito::json::to_json(&peers).unwrap();
        let args = Args {
            genesis_file: with_test_authority_for_topology(
                public_taira_conflicting_xor_alias_npos_genesis_file(),
                &peers,
            ),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some(topology_json),
            peer_pops,
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        let err = args
            .run(&mut writer)
            .expect_err("conflicting public XOR bindings should fail");
        assert!(
            err.to_string().contains("multiple asset definitions"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn sign_skips_npos_validator_bootstrap_for_admin_managed_lane() {
        let (peers, peer_pops) = valid_test_topology(4);
        let topology_json = norito::json::to_json(&peers).unwrap();
        let genesis_file = with_test_authority_for_topology(npos_genesis_file(), &peers);
        let (_config_directory, config_path) =
            nexus_profile_with_validator_modes(&genesis_file, "admin_managed", "admin_managed");
        let args = Args {
            genesis_file,
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some(topology_json),
            peer_pops,
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: Some(config_path),
        };
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer).expect("sign should succeed");
        writer.flush().expect("flush output");
        let bytes = writer.into_inner().expect("extract buffer");
        let block = decode_framed_signed_block(&bytes).expect("decode signed block");
        let mut validators = std::collections::BTreeSet::new();
        for tx in block.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instr in instructions {
                    if let Some(register) =
                        instr.as_any().downcast_ref::<RegisterPublicLaneValidator>()
                    {
                        validators.insert(register.validator.clone());
                    }
                }
            }
        }
        assert!(
            validators.is_empty(),
            "admin-managed lane configs must not auto-inject NPoS validator bootstrap"
        );
    }
    #[test]
    fn sign_links_genesis_account_into_ivm_without_reregistering_it() {
        let (peers, peer_pops) = valid_test_topology(4);
        let topology_json = norito::json::to_json(&peers).unwrap();
        let args = Args {
            genesis_file: with_test_authority_for_topology(npos_genesis_file(), &peers),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: Some(topology_json),
            peer_pops,
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer).expect("sign should succeed");
        writer.flush().expect("flush output");
        let bytes = writer.into_inner().expect("extract buffer");
        let block = decode_framed_signed_block(&bytes).expect("decode signed block");
        let genesis_account = block
            .external_transactions()
            .next()
            .expect("signed genesis transaction")
            .authority()
            .clone();
        let mut ivm_genesis_registrations = 0usize;
        for tx in block.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instr in instructions {
                    if let Some(RegisterBox::Account(register)) =
                        instr.as_any().downcast_ref::<RegisterBox>()
                        && register.object.id == genesis_account
                    {
                        ivm_genesis_registrations += 1;
                    }
                }
            }
        }
        assert_eq!(
            ivm_genesis_registrations, 0,
            "expected NPoS bootstrap to avoid re-registering the genesis controller under ivm"
        );
    }
    #[test]
    fn npos_consensus_mode_requires_npos_parameters() {
        let genesis_file = minimal_genesis_file();
        let manifest = RawGenesisTransaction::from_path(&genesis_file)
            .expect("read permissioned fixture without NPoS parameters")
            .with_consensus_mode(SumeragiConsensusMode::Npos);
        assert!(
            manifest
                .clone()
                .with_consensus_meta()
                .unwrap_err()
                .to_string()
                .contains("NPoS genesis requires `sumeragi_npos_parameters`")
        );
        fs::write(
            &genesis_file,
            norito::json::to_vec_pretty(&manifest)
                .expect("encode NPoS fixture missing required parameters"),
        )
        .expect("write explicit NPoS negative fixture");
        let args = Args {
            genesis_file,
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        let err = args
            .run(&mut writer)
            .expect_err("NPoS consensus should require NPoS parameters");
        assert!(
            err.to_string().contains("sumeragi_npos_parameters"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn npos_sign_accepts_manifest_with_npos_parameters() {
        let args = Args {
            genesis_file: npos_genesis_file(),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer)
            .expect("NPoS genesis with parameters should sign");
    }
    fn nexus_profile_config_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
            .join("defaults/nexus/config.toml")
    }
    #[test]
    fn peer_config_chain_must_match_manifest() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut config = checked_in_config(&root.join("defaults/nexus/config.toml"));
        let manifest = GenesisBuilder::new_without_executor(config.common.chain.clone(), ".")
            .set_topology_for_test(valid_test_topology_entries(4))
            .build_raw()
            .expect("build complete config-aligned genesis")
            .with_chain_discriminant(*config.common.chain_discriminant.value());
        ensure_peer_config_matches_manifest(&config, &manifest)
            .expect("baseline config and manifest match");
        config.common.chain = ChainId::from("concurrently-replaced-chain");
        let error = ensure_peer_config_matches_manifest(&config, &manifest)
            .expect_err("chain mismatch must fail before signing");
        assert!(
            error
                .to_string()
                .contains("does not match genesis manifest chain")
        );
    }
    #[test]
    fn peer_config_discriminant_must_match_manifest() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut config = checked_in_config(&root.join("defaults/nexus/config.toml"));
        let manifest = GenesisBuilder::new_without_executor(config.common.chain.clone(), ".")
            .set_topology_for_test(valid_test_topology_entries(4))
            .build_raw()
            .expect("build complete config-aligned genesis")
            .with_chain_discriminant(*config.common.chain_discriminant.value());
        *config.common.chain_discriminant.value_mut() = manifest
            .chain_discriminant()
            .checked_add(1)
            .expect("fixture discriminant can increase");
        let error = ensure_peer_config_matches_manifest(&config, &manifest)
            .expect_err("discriminant mismatch must fail before signing");
        assert!(error.to_string().contains("chain discriminant"));
    }
    #[test]
    fn sign_embeds_da_proof_policies_from_peer_config() {
        // Deployment templates contain operator-owned secret paths. Materialize the exact
        // checked-in consensus policy with disposable fixture credentials and private custody.
        let key_pair = checked_genesis_sign_keypair();
        let mut table = checked_in_consensus_config_table(&nexus_profile_config_path());
        table["genesis"]
            .as_table_mut()
            .expect("fixture genesis config")
            .insert(
                "public_key".to_owned(),
                toml::Value::String(key_pair.public_key().to_string()),
            );
        let mut config_file = tempfile::NamedTempFile::new().expect("private peer config fixture");
        write!(
            config_file,
            "{}",
            toml::to_string(&table).expect("encode policy fixture")
        )
        .expect("write private peer config fixture");
        let config_path =
            fs::canonicalize(config_file.path()).expect("canonical private config path");
        let config = load_peer_config(&config_path).expect("load private policy fixture");
        let manifest = GenesisBuilder::new_without_executor(config.common.chain.clone(), ".")
            .set_topology_for_test(valid_test_topology_entries(4))
            .build_raw()
            .expect("complete policy fixture genesis")
            .with_chain_discriminant(*config.common.chain_discriminant.value())
            .with_consensus_mode(SumeragiConsensusMode::Permissioned)
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        let genesis_file = tempfile::NamedTempFile::new().expect("policy fixture genesis");
        fs::write(
            genesis_file.path(),
            norito::json::to_json_pretty(&manifest).unwrap(),
        )
        .expect("write policy fixture genesis");
        let args = Args {
            genesis_file: genesis_file.path().to_path_buf(),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file_for(&key_pair),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: Some(config_path),
        };
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer).expect("sign should succeed");
        writer.flush().expect("flush output");
        let bytes = writer.into_inner().expect("extract buffer");
        let block = decode_framed_signed_block(&bytes).expect("decode signed block");
        let bundle = block
            .da_proof_policies()
            .expect("expected genesis to embed configured DA proof policies");
        let aliases: Vec<_> = bundle
            .policies()
            .iter()
            .map(|policy| policy.alias.as_str())
            .collect();
        assert_eq!(aliases, vec!["core", "governance", "zk"]);
    }
    #[test]
    fn sign_accepts_permissioned_consensus() {
        let args = Args {
            genesis_file: minimal_genesis_file(),
            out_file: None,
            bound_manifest_out: None,
            expected_hash_out: None,
            nexus_context_output: None,
            sccp_reset_history: None,
            fresh_sccp_reset_nonce: false,
            replace_expected_hash: None,
            topology: None,
            peer_pops: Vec::new(),
            private_key_file: test_private_key_file(),
            expected_public_key: None,
            creation_time_ms: None,
            amx: amx::Args::default(),
            config: None,
        };
        let mut writer = BufWriter::new(Vec::new());
        args.run(&mut writer)
            .expect("permissioned genesis should be allowed");
    }
    #[test]
    fn staged_manifest_registry_reenters_genesis_discriminant() {
        let discriminant = crate::genesis::profile::TAIRA_CHAIN_DISCRIMINANT;
        let genesis = RawGenesisTransaction::from_path(minimal_genesis_file())
            .expect("parse minimal genesis")
            .with_chain_discriminant(discriminant);
        let directory = tempfile::tempdir().expect("manifest directory");
        fs::write(
            directory.path().join("governance.manifest.json"),
            r#"{
                "lane": "governance",
                "governance": "parliament",
                "version": 1,
                "validators": [{
                    "validator": "testﾜヰ8ｽuimdh9FﾂｦUｸﾈbﾕﾆヱMUYｴGｷﾙｹﾐRヱbﾐｷwﾄ6ﾃdDLPQﾋW496uﾙﾜFpﾈtHd4Hﾙﾎ45M1L5",
                    "peer_id": "ea0130999C999F728B0829387F4E93732EE0479F911DE0CE1E9409C8CEA66CF99376F57DB2E709892648F222D9F4E90DB29B84"
                }],
                "quorum": 1
            }"#,
        )
        .expect("write Taira manifest");
        let lane_catalog = LaneCatalog::new(
            std::num::NonZeroU32::new(1).expect("non-zero lane count"),
            vec![LaneConfig {
                id: LaneId::SINGLE,
                alias: "governance".to_owned(),
                governance: Some("parliament".to_owned()),
                ..LaneConfig::default()
            }],
        )
        .expect("governance lane catalog");
        let mut governance = actual::GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_owned(), actual::GovernanceModule::default());
        let nexus = actual::Nexus {
            lane_catalog: lane_catalog.clone(),
            configured_lane_catalog: lane_catalog,
            governance,
            registry: actual::LaneRegistry {
                manifest_directory: Some(directory.path().to_path_buf()),
                cache_directory: Some(directory.path().to_path_buf()),
                ..actual::LaneRegistry::default()
            },
            ..actual::Nexus::default()
        };
        let _wrong_discriminant = ChainDiscriminantGuard::enter(discriminant.wrapping_add(1));
        let registry = staged_lane_manifest_registry(&genesis, &nexus)
            .expect("staged registry must re-enter the genesis discriminant");
        registry
            .validate_active_coverage()
            .expect("Taira governance manifest must remain active");
    }
    fn minimal_genesis_file() -> PathBuf {
        let genesis_file = tempfile::Builder::new()
            .prefix("kagami-genesis-test-")
            .tempfile()
            .expect("create temp genesis file");
        let manifest =
            GenesisBuilder::new_without_executor(ChainId::from("test-chain"), PathBuf::from("."))
                .set_topology_for_test(valid_test_topology_entries(4))
                .build_raw()
                .expect("complete minimal signing fixture")
                .with_consensus_mode(SumeragiConsensusMode::Permissioned)
                .with_consensus_meta()
                .expect("valid fixture consensus parameters");
        let genesis_json = norito::json::to_json_pretty(&manifest).expect("serialize genesis");
        fs::write(genesis_file.path(), genesis_json).expect("write genesis json");
        let (_file, path) = genesis_file.keep().expect("persist temp genesis");
        path
    }
    fn invalid_genesis_file_missing_consensus_mode() -> PathBuf {
        let mut genesis_file = tempfile::Builder::new()
            .prefix("kagami-genesis-invalid-")
            .tempfile()
            .expect("create temp genesis file");
        let genesis_json = r#"{
            "chain": "test-chain",
            "chain_discriminant": 1,
            "executor": null,
            "ivm_dir": ".",
            "transactions": [
                {}
            ]
        }"#;
        write!(genesis_file, "{genesis_json}").expect("write genesis json");
        let (_file, path) = genesis_file.keep().expect("persist temp genesis");
        path
    }
    fn npos_genesis_file() -> PathBuf {
        let genesis_file = tempfile::Builder::new()
            .prefix("kagami-npos-genesis-")
            .tempfile()
            .expect("create temp genesis file");
        let manifest =
            GenesisBuilder::new_without_executor(ChainId::from("npos-sign"), PathBuf::from("."))
                .append_parameter(Parameter::Custom(
                    SumeragiNposParameters::default().into_custom_parameter(),
                ))
                .set_topology_for_test(valid_test_topology_entries(4))
                .build_raw()
                .expect("complete NPoS signing fixture")
                .with_consensus_mode(SumeragiConsensusMode::Npos)
                .with_consensus_meta()
                .expect("valid fixture consensus parameters");
        let manifest = with_explicit_test_xor_allocations(manifest, &valid_test_topology(4).0);
        let json = norito::json::to_json_pretty(&manifest).expect("serialize genesis manifest");
        fs::write(genesis_file.path(), json).expect("write genesis json");
        let (_file, path) = genesis_file.keep().expect("persist temp genesis");
        path
    }
    fn alias_backed_npos_genesis_file() -> PathBuf {
        let genesis_file = tempfile::Builder::new()
            .prefix("kagami-npos-alias-genesis-")
            .tempfile()
            .expect("create temp genesis file");
        let asset_definition_id: AssetDefinitionId = "6TEAJqbb8oEPmLncoNiMRbLEK6tw"
            .parse()
            .expect("valid canonical asset id");
        let alias: AssetDefinitionAlias = "xor#universal".parse().expect("valid alias");
        let manifest = GenesisBuilder::new_without_executor(
            ChainId::from("npos-sign-alias"),
            PathBuf::from("."),
        )
        .append_instruction(Register::asset_definition(
            AssetDefinition::new(
                asset_definition_id.clone(),
                "xor".to_owned(),
                NumericSpec::fractional(9),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .with_metadata(Metadata::default()),
        ))
        .append_instruction(SetAssetDefinitionAlias::bind(
            asset_definition_id,
            alias,
            None,
        ))
        .append_parameter(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        ))
        .complete_for_test()
        .build_raw()
        .expect("complete alias-backed NPoS fixture")
        .with_consensus_mode(SumeragiConsensusMode::Npos)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
        let json = norito::json::to_json_pretty(&manifest).expect("serialize genesis manifest");
        fs::write(genesis_file.path(), json).expect("write genesis json");
        let (_file, path) = genesis_file.keep().expect("persist temp genesis");
        path
    }
    fn public_taira_alias_backed_npos_genesis_file() -> PathBuf {
        let genesis_file = tempfile::Builder::new()
            .prefix("kagami-public-taira-npos-alias-genesis-")
            .tempfile()
            .expect("create temp genesis file");
        let asset_definition_id: AssetDefinitionId = crate::genesis::TAIRA_XOR_ASSET_DEFINITION_ID
            .parse()
            .expect("valid canonical asset id");
        let alias: AssetDefinitionAlias = crate::genesis::PUBLIC_XOR_ALIAS
            .parse()
            .expect("valid alias");
        let manifest = GenesisBuilder::new_without_executor(
            crate::genesis::profile_defaults(crate::genesis::GenesisProfile::Iroha3Taira).chain_id,
            PathBuf::from("."),
        )
        .append_instruction(Register::asset_definition(
            AssetDefinition::new(
                asset_definition_id.clone(),
                "xor".to_owned(),
                NumericSpec::fractional(9),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .with_metadata(Metadata::default()),
        ))
        .append_instruction(SetAssetDefinitionAlias::bind(
            asset_definition_id,
            alias,
            None,
        ))
        .append_parameter(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        ))
        .complete_for_test()
        .build_raw()
        .expect("complete public Taira NPoS fixture")
        .with_consensus_mode(SumeragiConsensusMode::Npos)
        .with_chain_discriminant(crate::genesis::profile::TAIRA_CHAIN_DISCRIMINANT)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
        let json = norito::json::to_json_pretty(&manifest).expect("serialize genesis manifest");
        fs::write(genesis_file.path(), json).expect("write genesis json");
        let (_file, path) = genesis_file.keep().expect("persist temp genesis");
        path
    }
    fn public_nexus_npos_genesis_file_without_xor_alias() -> PathBuf {
        let genesis_file = tempfile::Builder::new()
            .prefix("kagami-public-nexus-npos-genesis-")
            .tempfile()
            .expect("create temp genesis file");
        let manifest = GenesisBuilder::new_without_executor(
            crate::genesis::profile_defaults(crate::genesis::GenesisProfile::Iroha3Nexus).chain_id,
            PathBuf::from("."),
        )
        .append_parameter(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        ))
        .complete_for_test()
        .build_raw()
        .expect("complete public Nexus NPoS fixture")
        .with_consensus_mode(SumeragiConsensusMode::Npos)
        .with_chain_discriminant(crate::genesis::profile::NEXUS_CHAIN_DISCRIMINANT)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
        let json = norito::json::to_json_pretty(&manifest).expect("serialize genesis manifest");
        fs::write(genesis_file.path(), json).expect("write genesis json");
        let (_file, path) = genesis_file.keep().expect("persist temp genesis");
        path
    }
    fn public_taira_conflicting_xor_alias_npos_genesis_file() -> PathBuf {
        let genesis_file = tempfile::Builder::new()
            .prefix("kagami-public-taira-conflicting-xor-genesis-")
            .tempfile()
            .expect("create temp genesis file");
        let canonical_xor: AssetDefinitionId = crate::genesis::TAIRA_XOR_ASSET_DEFINITION_ID
            .parse()
            .expect("valid canonical asset id");
        let wrong_xor: AssetDefinitionId = "61CtjvNd9T3THAR65GsMVHr82Bjc"
            .parse()
            .expect("valid canonical asset id");
        let alias: AssetDefinitionAlias = crate::genesis::PUBLIC_XOR_ALIAS
            .parse()
            .expect("valid alias");
        let manifest = GenesisBuilder::new_without_executor(
            crate::genesis::profile_defaults(crate::genesis::GenesisProfile::Iroha3Taira).chain_id,
            PathBuf::from("."),
        )
        .append_instruction(Register::asset_definition(
            AssetDefinition::new(
                canonical_xor.clone(),
                "xor".to_owned(),
                NumericSpec::fractional(9),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .with_metadata(Metadata::default()),
        ))
        .append_instruction(Register::asset_definition(
            AssetDefinition::new(
                wrong_xor.clone(),
                "xor-shadow".to_owned(),
                NumericSpec::fractional(9),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .with_metadata(Metadata::default()),
        ))
        .append_instruction(SetAssetDefinitionAlias::bind(
            canonical_xor,
            alias.clone(),
            None,
        ))
        .append_instruction(SetAssetDefinitionAlias::bind(wrong_xor, alias, None))
        .append_parameter(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        ))
        .complete_for_test()
        .build_raw()
        .expect("complete conflicting Taira XOR fixture")
        .with_consensus_mode(SumeragiConsensusMode::Npos)
        .with_chain_discriminant(crate::genesis::profile::TAIRA_CHAIN_DISCRIMINANT)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
        let json = norito::json::to_json_pretty(&manifest).expect("serialize genesis manifest");
        fs::write(genesis_file.path(), json).expect("write genesis json");
        let (_file, path) = genesis_file.keep().expect("persist temp genesis");
        path
    }
    #[cfg(unix)]
    #[test]
    fn private_key_file_round_trips_owner_only_canonical_material() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = private_key_fixture_directory(".genesis-key-roundtrip-");
        assert_eq!(temp.path().canonicalize().unwrap(), temp.path());
        assert_eq!(
            temp.path().metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        let key_pair = checked_genesis_sign_keypair_with_algorithm(Algorithm::Ed25519);
        let canonical = ExposedPrivateKey(key_pair.private_key().clone()).to_string();
        let path = temp.path().join("genesis.private_key");
        let raw = zeroize::Zeroizing::new(format!("{canonical}\n").into_bytes());
        crate::secure_fs::write_private_file_atomic(&path, raw.as_slice())
            .expect("write canonical private key");
        assert_eq!(
            fs::metadata(&path)
                .expect("private key metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let loaded = load_genesis_key_file(&path).expect("load canonical private key");
        assert_eq!(loaded.public_key(), key_pair.public_key());
    }
    #[cfg(unix)]
    #[test]
    fn private_key_file_rejects_unsafe_mode_links_whitespace_and_oversize() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let temp = private_key_fixture_directory(".genesis-key-rejections-");
        let key_pair = checked_genesis_sign_keypair_with_algorithm(Algorithm::Ed25519);
        let canonical = ExposedPrivateKey(key_pair.private_key().clone()).to_string();
        let unsafe_mode = temp.path().join("unsafe-mode.key");
        fs::write(&unsafe_mode, format!("{canonical}\n")).expect("write unsafe key");
        fs::set_permissions(&unsafe_mode, fs::Permissions::from_mode(0o644))
            .expect("set unsafe mode");
        assert!(load_genesis_key_file(&unsafe_mode).is_err());
        fs::set_permissions(&unsafe_mode, fs::Permissions::from_mode(0o600))
            .expect("set safe mode");
        let symlink_path = temp.path().join("symlink.key");
        symlink(&unsafe_mode, &symlink_path).expect("create symlink");
        assert!(load_genesis_key_file(&symlink_path).is_err());
        let hardlink_path = temp.path().join("hardlink.key");
        fs::hard_link(&unsafe_mode, &hardlink_path).expect("create hardlink");
        assert!(load_genesis_key_file(&unsafe_mode).is_err());
        fs::remove_file(&hardlink_path).expect("remove hardlink");
        let whitespace = temp.path().join("whitespace.key");
        crate::secure_fs::write_private_file_atomic(
            &whitespace,
            format!(" {canonical}\n").as_bytes(),
        )
        .expect("write whitespace key");
        assert!(load_genesis_key_file(&whitespace).is_err());
        let oversized = temp.path().join("oversized.key");
        fs::write(&oversized, vec![b'A'; 1024 * 1024 + 1]).expect("write oversized key");
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600))
            .expect("set oversized key mode");
        assert!(load_genesis_key_file(&oversized).is_err());
    }
    fn test_genesis_key_pair() -> KeyPair {
        const PRIVATE_KEY: &str =
            "80262082B3BDE54AEBECA4146257DA0DE8D59D8E46D5FE34887DCD8072866792FCB3AD";
        let exposed = PRIVATE_KEY
            .parse::<ExposedPrivateKey>()
            .expect("parse canonical fixture private key");
        KeyPair::from_private_key(exposed.0).expect("derive fixture genesis key pair")
    }
    fn test_private_key_file() -> PathBuf {
        test_private_key_file_for(&test_genesis_key_pair())
    }
    fn private_key_fixture_directory(prefix: &str) -> tempfile::TempDir {
        // Signed release captures are read-only. Canonicalize the OS temporary
        // parent so private-file admission also works through macOS's /var alias.
        let parent =
            fs::canonicalize(std::env::temp_dir()).expect("resolve writable native fixture parent");
        let directory = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(parent)
            .expect("create private-key fixture directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .expect("harden private-key fixture directory");
        }
        directory
    }
    fn test_private_key_file_for(key_pair: &KeyPair) -> PathBuf {
        use std::cell::RefCell;

        thread_local! {
            static PRIVATE_KEY_FILES: RefCell<Vec<(tempfile::NamedTempFile, tempfile::TempDir)>> = const { RefCell::new(Vec::new()) };
        }

        let directory = private_key_fixture_directory(".genesis-sign-private-");
        let mut file = tempfile::Builder::new()
            .prefix(".genesis-sign-test-key-")
            .tempfile_in(directory.path())
            .expect("create owner-only private-key fixture");
        let canonical = zeroize::Zeroizing::new(
            format!("{}\n", ExposedPrivateKey(key_pair.private_key().clone())).into_bytes(),
        );
        file.write_all(canonical.as_slice())
            .expect("write private-key fixture");
        file.as_file_mut()
            .sync_all()
            .expect("sync private-key fixture");
        let path = file.path().to_path_buf();
        PRIVATE_KEY_FILES.with(|files| files.borrow_mut().push((file, directory)));
        path
    }
}
