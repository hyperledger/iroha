//! Read-only compatibility probes run with a new binary before it replaces an old one.
//!
//! - `iroha3d --check-config --json` prints [`ConfigCompatibilityV1`]: the values peers and the
//!   signed genesis bind, computed from the real rendered configuration.
//! - `iroha3d --check-storage` prints [`StorageCheckReportV1`]: the stopped node's Kura tip, the
//!   Kura hash at the newest snapshot's height and a snapshot-restore dry run, all read with this
//!   build's decoders.
//!
//! Neither probe opens runtime-only secrets (runtime signer and beacon
//! credential), binds a socket or mutates node storage. Both parse the configuration, which reads
//! the key files it names after their custody checks (`node_secrets::verify_config_key_custody`).

use crate::authenticated_genesis::AuthenticatedGenesis;
use crate::{
    Config, GenesisBlock, MainError, build_consensus_config_caps, consensus_caps_from_genesis,
    freeze_lane_compliance_for_startup_replay, freeze_lane_manifests_for_startup_replay,
    snapshot_mode_allows_restore,
};
use error_stack::{Report, ResultExt as _};
use iroha_config::kura::InitMode;
use iroha_core::{
    kura::{BlockCount, BlockIndex, BlockStore, Kura},
    query::store::LiveQueryStore,
    snapshot::{TryReadError, try_read_snapshot_with_limits},
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::sumeragi::PROTOCOL_VERSION;
use iroha_data_model::{
    NetworkId,
    block::{BlockHeader, consensus::MAX_EXECUTED_BLOCK_WIRE_BYTES, decode_framed_signed_block},
};
use iroha_futures::supervisor::ShutdownSignal;
use norito::derive::{JsonDeserialize, JsonSerialize};
use std::{io::ErrorKind, num::NonZeroUsize, path::Path, sync::Arc};

type ReportResult<T, C> = core::result::Result<T, Report<C>>;
/// Height and tip hash of a restored snapshot, or `None` when there is nothing to restore.
type RestoredSnapshotV1 = Option<(u64, Option<HashOf<BlockHeader>>)>;

/// `snapshot_restore_dry_run` value of a restore that succeeded or had nothing to restore.
pub const DRY_RUN_OK: &str = "ok";
/// `snapshot_restore_dry_run` value of a restore this build cannot perform.
pub const DRY_RUN_ERROR: &str = "error";

/// Native node and effective local configuration derived from an executed signed genesis.
///
/// This is an offline input projection, not evidence that a validator is running.
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct NodeConfigIdentityV1 {
    /// Consensus peer identity selected by the actual daemon configuration.
    pub node_id: iroha_model_base::peer::PeerId,
    /// Native hash of the Norito-encoded peer identity.
    pub node_fingerprint: String,
    /// Native fingerprint of the effective local/driver settings and retired keys.
    pub node_config_fingerprint: String,
    /// Ready committee size obtained from the executed genesis schedule.
    pub initial_committee_size: u64,
    /// Network identity authenticated by original signed genesis execution.
    pub network_id: NetworkId,
    /// Hash of the original signed genesis block.
    pub genesis_hash: String,
}

/// Identity compiled into the executable performing this offline diagnostic.
///
/// A separately built diagnostic must not be presented as the running validator's build.
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct DiagnosticBuildIdentityV1 {
    /// Diagnostic executable package version.
    pub version: String,
    /// Diagnostic executable source revision or explicit local development label.
    pub source_revision: String,
    /// Native fingerprint of the diagnostic executable's immutable build identity.
    pub build_fingerprint: String,
}

/// Compatibility values printed by `iroha3d --check-config --json`.
///
/// Hashes are lowercase hex. The genesis-bound values are `null` when the signed genesis is not
/// available locally (`status = "pending"`).
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ConfigCompatibilityV1 {
    /// `ready` when the configuration and the signed genesis validated, `pending` without genesis.
    pub status: String,
    /// Offline native node/configuration projection; absent without executed signed genesis.
    pub node_identity: Option<NodeConfigIdentityV1>,
    /// Immutable identity of this diagnostic executable, separate from a running node.
    pub diagnostic_build: DiagnosticBuildIdentityV1,
    /// Sumeragi configuration fingerprint (`/status` `config_fingerprint`, handshake-bound).
    pub config_fingerprint: Option<String>,
    /// Consensus wire protocol version.
    pub protocol_version: u16,
    /// Hash of the compiled consensus and block wire schema plus the IVM ABI.
    pub wire_schema_hash: String,
    /// Digest of the configured Nexus consensus policy, including lane manifest and compliance
    /// policy digests (handshake-bound).
    pub nexus_policy_digest: String,
    /// Digest of this build's IVM gas schedule (handshake-bound).
    pub gas_schedule_hash: String,
    /// Boot execution-policy identity the signed genesis commits to.
    pub execution_policy_hash: Option<String>,
    /// Nexus/AMX context commitment the signed genesis commits to.
    pub nexus_amx_context_hash: Option<String>,
}

/// Result printed by `iroha3d --check-storage`.
///
/// Hashes are lowercase hex. An empty store reports height 0 and no hashes.
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct StorageCheckReportV1 {
    /// Durable committed Kura height.
    pub tip_height: u64,
    /// Hash of the durable tip block.
    pub tip_hash: Option<String>,
    /// Height of the newest snapshot this build restored, when one exists.
    pub snapshot_height: Option<u64>,
    /// Kura's block hash at `snapshot_height`, which commits to the whole prefix.
    pub prefix_hash_at_snapshot_height: Option<String>,
    /// [`DRY_RUN_OK`] or [`DRY_RUN_ERROR`].
    pub snapshot_restore_dry_run: String,
    /// Why the dry run failed, when it did.
    pub snapshot_restore_error: Option<String>,
}

impl StorageCheckReportV1 {
    /// Whether the store opened and the snapshot restore dry run succeeded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.snapshot_restore_dry_run == DRY_RUN_OK
    }
}

fn hex_hash(hash: impl Into<Hash>) -> String {
    let hash: Hash = hash.into();
    let bytes: &[u8; Hash::LENGTH] = hash.as_ref();
    hex::encode(bytes)
}

/// Compute the compatibility values of this build and configuration.
///
/// `genesis` is the local signed genesis with its authenticated bootstrap when available.
///
/// # Errors
///
/// [`MainError::Config`] when the lane manifest or compliance policy cannot be frozen or the
/// signed genesis carries no valid handshake context, or compiled diagnostic identity is invalid.
pub fn config_compatibility_v1(
    config: &Config,
    genesis: Option<(&GenesisBlock, &AuthenticatedGenesis)>,
    build: iroha_core::release_identity::CompiledBuildMetadata,
) -> ReportResult<ConfigCompatibilityV1, MainError> {
    use norito::codec::Encode as _;
    let diagnostic = build
        .identity()
        .map_err(|error| Report::new(MainError::Config).attach(error.to_string()))?;
    let diagnostic_build = DiagnosticBuildIdentityV1 {
        version: diagnostic.version().to_owned(),
        source_revision: diagnostic.source_commit().to_owned(),
        build_fingerprint: hex_hash(diagnostic.build_fingerprint()),
    };
    let lane_manifests = freeze_lane_manifests_for_startup_replay(&config.nexus)
        .map_err(|error| Report::new(error).change_context(MainError::Config))
        .attach("lane manifest registry is not ready")?;
    let compliance = freeze_lane_compliance_for_startup_replay(&config.nexus)
        .change_context(MainError::Config)?;
    let caps = build_consensus_config_caps(
        &config.nexus,
        compliance
            .as_ref()
            .map(|engine| engine.consensus_policy_digest()),
        Some(lane_manifests.baseline_consensus_policy_digest()),
    )
    .change_context(MainError::Config)?;
    let (status, config_fingerprint, execution_policy_hash, nexus_amx_context_hash, node_identity) =
        match genesis {
            Some((block, bootstrap)) => {
                let (_, _, handshake, _, _) = consensus_caps_from_genesis(block, &caps)
                .ok_or_else(|| {
                    Report::new(MainError::Config).attach(
                        "local genesis does not contain one valid canonical Sumeragi handshake context",
                    )
                })?;
                let context = bootstrap;
                let node_id = iroha_model_base::peer::PeerId::new(
                    config.common.key_pair.public_key().clone(),
                );
                let node_identity = NodeConfigIdentityV1 {
                    node_fingerprint: hex_hash(Hash::new(node_id.encode())),
                    node_id,
                    node_config_fingerprint: hex_hash(
                        iroha_core::sumeragi::node::configuration_fingerprint(
                            context.initial_committee_size,
                            &config.sumeragi.local,
                            &iroha_core::sumeragi::driver::DriverConfig::default(),
                            &config.sumeragi.retired_keys,
                        ),
                    ),
                    initial_committee_size: u64::try_from(context.initial_committee_size).map_err(
                        |error| Report::new(MainError::Config).attach(error.to_string()),
                    )?,
                    network_id: context.network_id,
                    genesis_hash: hex_hash(block.0.hash()),
                };
                (
                    "ready",
                    Some(hex::encode(handshake.config.native_config_fingerprint)),
                    Some(hex_hash(context.execution_policy_hash)),
                    Some(hex_hash(context.nexus_amx_context_hash)),
                    Some(node_identity),
                )
            }
            None => ("pending", None, None, None, None),
        };
    Ok(ConfigCompatibilityV1 {
        status: status.to_owned(),
        node_identity,
        diagnostic_build,
        config_fingerprint,
        protocol_version: PROTOCOL_VERSION,
        wire_schema_hash: hex::encode(iroha_core::release_identity::wire_schema_hash()),
        nexus_policy_digest: hex::encode(caps.nexus_policy_digest),
        gas_schedule_hash: hex::encode(caps.ivm_gas_schedule_hash),
        execution_policy_hash,
        nexus_amx_context_hash,
    })
}

/// Durable Kura boundary read by [`check_storage`].
struct KuraTipV1 {
    height: u64,
    hash: Option<HashOf<BlockHeader>>,
}

/// Inspect the stopped node's store read-only and rehearse its snapshot restore.
///
/// Kura is opened in emergency-Fast mode, which takes the exclusive store-root lock (refusing a
/// store a running node owns), validates the durable commit marker and maps the hash journal
/// read-only without repairing, creating or publishing anything. Every retained block body up to
/// the tip is then decoded with this build's decoder and checked against the hash journal and its
/// parent. The newest snapshot is checked using a scratch Kura in a temporary directory; the real
/// store is only read. A positive-height snapshot reports that native execution replay is required.
///
/// # Errors
///
/// A description when the Kura store cannot be opened or a stored block cannot be decoded. A
/// failed snapshot restore is reported in the result instead.
pub fn check_storage(config: &Config) -> Result<StorageCheckReportV1, String> {
    let store_root = config.kura.store_dir.resolve_relative_path();
    let (kura, tip) = match std::fs::symlink_metadata(&store_root) {
        Err(error) if error.kind() == ErrorKind::NotFound => (
            None,
            KuraTipV1 {
                height: 0,
                hash: None,
            },
        ),
        Err(error) => {
            return Err(format!(
                "cannot inspect Kura store {}: {error}",
                store_root.display()
            ));
        }
        Ok(_) => {
            let kura = open_kura_read_only(config)?;
            let tip = durable_tip(&kura)?;
            verify_retained_bodies(&store_root, &kura, tip.height)?;
            (Some(kura), tip)
        }
    };
    let mut report = StorageCheckReportV1 {
        tip_height: tip.height,
        tip_hash: tip.hash.map(hex_hash),
        snapshot_height: None,
        prefix_hash_at_snapshot_height: None,
        snapshot_restore_dry_run: DRY_RUN_OK.to_owned(),
        snapshot_restore_error: None,
    };
    let outcome =
        snapshot_restore_dry_run(config, tip.height, kura.as_deref()).and_then(|restored| {
            let Some((height, snapshot_tip)) = restored else {
                return Ok(None);
            };
            let kura_hash =
                NonZeroUsize::new(usize::try_from(height).map_err(|error| error.to_string())?)
                    .and_then(|height| kura.as_ref()?.get_durable_block_hash(height));
            if height > 0 && kura_hash.is_none() {
                return Err(format!(
                    "Kura has no durable block at snapshot height {height}"
                ));
            }
            if kura_hash != snapshot_tip {
                return Err(format!(
                    "the snapshot's block hash at height {height} differs from Kura's"
                ));
            }
            Ok(Some((height, kura_hash)))
        });
    match outcome {
        Ok(Some((height, hash))) => {
            report.snapshot_height = Some(height);
            report.prefix_hash_at_snapshot_height = hash.map(hex_hash);
        }
        Ok(None) => {}
        Err(error) => {
            DRY_RUN_ERROR.clone_into(&mut report.snapshot_restore_dry_run);
            report.snapshot_restore_error = Some(error);
        }
    }
    drop(kura);
    Ok(report)
}

/// Open the existing store in emergency-Fast mode: lock, marker check, read-only journals.
fn open_kura_read_only(config: &Config) -> Result<Arc<Kura>, String> {
    let mut kura_config = config.kura.clone();
    kura_config.init_mode = InitMode::Fast;
    // Native startup requires the original signed genesis and certified block history.
    Kura::new_with_configured_lane_catalog(
        &kura_config,
        &config.nexus.lane_config,
        &config.nexus.configured_lane_catalog,
    )
    .map(|(kura, _)| kura)
    .map_err(|error| {
        format!(
            "cannot open Kura store {} read-only: {error}",
            config.kura.store_dir.resolve_relative_path().display()
        )
    })
}

fn durable_tip(kura: &Kura) -> Result<KuraTipV1, String> {
    let count = kura
        .exact_durable_blocks_count()
        .map_err(|error| format!("cannot read the durable Kura height: {error}"))?;
    let height = u64::try_from(count).map_err(|error| error.to_string())?;
    let hash = match NonZeroUsize::new(count) {
        None => None,
        Some(tip) => Some(
            kura.get_durable_block_hash(tip)
                .ok_or_else(|| format!("Kura has no durable hash at its tip {count}"))?,
        ),
    };
    Ok(KuraTipV1 { height, hash })
}

/// Decode every retained block body with this build and check its hash and parent link.
fn verify_retained_bodies(store_root: &Path, kura: &Kura, tip_height: u64) -> Result<(), String> {
    const BATCH: usize = 256;
    if tip_height == 0 {
        return Ok(());
    }
    let canonical = std::fs::canonicalize(store_root)
        .map_err(|error| format!("cannot resolve {}: {error}", store_root.display()))?;
    let mut store = BlockStore::open_read_only(Kura::canonical_storage_path(&canonical))
        .map_err(|error| format!("cannot open the Kura block journals read-only: {error}"))?;
    let mut indices = vec![
        BlockIndex {
            start: 0,
            length: 0
        };
        BATCH
    ];
    let mut body = Vec::new();
    let mut previous: Option<HashOf<BlockHeader>> = None;
    let mut next = 0_u64;
    while next < tip_height {
        let batch_len = usize::try_from((tip_height - next).min(BATCH as u64))
            .map_err(|error| error.to_string())?;
        store
            .read_block_indices(next, &mut indices[..batch_len])
            .map_err(|error| format!("cannot read Kura block indices at {}: {error}", next + 1))?;
        for (offset, index) in indices[..batch_len].iter().enumerate() {
            let height = next + offset as u64 + 1;
            let journal_hash =
                NonZeroUsize::new(usize::try_from(height).map_err(|e| e.to_string())?)
                    .and_then(|height| kura.get_durable_block_hash(height))
                    .ok_or_else(|| format!("Kura has no durable hash at height {height}"))?;
            // Evicted and hash-only heights keep no body; the next body starts a new link.
            if index.start == u64::MAX {
                previous = Some(journal_hash);
                continue;
            }
            if index.length == 0 || index.length > MAX_EXECUTED_BLOCK_WIRE_BYTES {
                return Err(format!(
                    "block {height} has invalid wire length {}",
                    index.length
                ));
            }
            body.resize(
                usize::try_from(index.length).map_err(|error| error.to_string())?,
                0,
            );
            store
                .read_block_data(index.start, &mut body)
                .map_err(|error| format!("cannot read block {height}: {error}"))?;
            let block = decode_framed_signed_block(&body)
                .map_err(|error| format!("this build cannot decode block {height}: {error}"))?;
            let header = block.header();
            if header.height().get() != height || block.hash() != journal_hash {
                return Err(format!("block {height} does not match Kura's hash journal"));
            }
            if header.prev_block_hash() != previous {
                return Err(format!("block {height} does not link to its parent"));
            }
            previous = Some(journal_hash);
        }
        next += batch_len as u64;
    }
    Ok(())
}

/// Restore the newest snapshot into a scratch Kura, exactly as startup would decode it, and
/// reconcile its retained block hashes with the real Kura as a Strict startup does
/// ([`reconcile_restored_hashes`]).
///
/// Returns the snapshot's height and tip hash, or `None` when restore is disabled or no snapshot
/// exists (the node would replay Kura from genesis).
///
/// Positive-height snapshots fail with `NativeExecutionReplayRequired`: a signed World export
/// does not authenticate its full state against the native witnessed-write commitment.
fn snapshot_restore_dry_run(
    config: &Config,
    tip_height: u64,
    kura: Option<&Kura>,
) -> Result<RestoredSnapshotV1, String> {
    if !snapshot_mode_allows_restore(config.snapshot.mode) {
        return Ok(None);
    }
    let mut scratch_config = config.kura.clone();
    scratch_config.init_mode = InitMode::Strict;
    // The scratch store holds no blocks and lives in a temporary directory; the node's disk
    // budget governs the real store only.
    scratch_config.max_disk_usage_bytes = iroha_config::base::util::Bytes(0);
    let scratch = Kura::new_temporary_with_configured_lane_catalog(
        &scratch_config,
        &config.nexus.lane_config,
        &config.nexus.configured_lane_catalog,
    )
    .map_err(|error| format!("cannot create the scratch Kura: {error}"))?;
    let lane_manifests = freeze_lane_manifests_for_startup_replay(&config.nexus)
        .map_err(|error| format!("lane manifest registry is not ready: {error}"))?;
    let live_query_store =
        LiveQueryStore::from_config(config.live_query_store, ShutdownSignal::new())
            .into_inert_handle();
    let verification_key = config
        .snapshot
        .verification_public_key
        .as_ref()
        .unwrap_or_else(|| config.common.key_pair.public_key());
    // Mirror startup: restored State owners retain this configured execution pool.
    let execution_budget =
        iroha_allocation::AllocationBudget::new(config.pipeline.ivm_execution_max_bytes);
    let read_buffer_budget =
        iroha_allocation::AllocationBudget::new(config.snapshot.max_read_buffer_bytes.get());
    // Supply the real durable height for bounds checking. This never grants a positive-height
    // snapshot authority to replace native certified execution replay.
    let block_count = BlockCount(usize::try_from(tip_height).map_err(|error| error.to_string())?);
    let restored = try_read_snapshot_with_limits(
        &execution_budget,
        config.snapshot.store_dir.resolve_relative_path(),
        &scratch,
        &lane_manifests,
        &config.nexus,
        || live_query_store.clone(),
        block_count,
        config.snapshot.merkle_chunk_size_bytes,
        config.snapshot.max_payload_bytes,
        config.snapshot.resources,
        verification_key,
        &config.common.chain,
        &NetworkId::from_genesis_hash(config.genesis.expected_hash),
        &config.zk,
        #[cfg(feature = "telemetry")]
        iroha_core::telemetry::StateTelemetry::default(),
        &read_buffer_budget,
    );
    match restored {
        Ok(state) => {
            let height =
                u64::try_from(state.committed_height()).map_err(|error| error.to_string())?;
            {
                let view = state
                    .try_view()
                    .map_err(|error| format!("the restored snapshot state is invalid: {error}"))?;
                reconcile_restored_hashes(
                    view.block_hashes().iter().copied(),
                    tip_height,
                    |height| kura.and_then(|kura| kura.get_durable_block_hash(height)),
                )?;
            }
            Ok(Some((height, state.latest_block_hash_fast())))
        }
        Err(TryReadError::NotFound) => Ok(None),
        Err(error) => Err(format!("snapshot restore failed: {error}")),
    }
}

/// Compare every block hash a restored snapshot retains with Kura's durable hash at the same
/// height. A mismatch, a missing retained hash, or a snapshot above Kura's durable tip fails.
fn reconcile_restored_hashes(
    snapshot_hashes: impl Iterator<Item = HashOf<BlockHeader>>,
    kura_height: u64,
    kura_hash: impl Fn(NonZeroUsize) -> Option<HashOf<BlockHeader>>,
) -> Result<(), String> {
    for (height, snapshot_hash) in (1_usize..).zip(snapshot_hashes) {
        if u64::try_from(height).map_or(true, |height| height > kura_height) {
            return Err(format!(
                "snapshot height {height} exceeds Kura's durable height {kura_height}"
            ));
        }
        let height_nz = NonZeroUsize::new(height).expect("heights start at 1");
        match kura_hash(height_nz) {
            Some(kura_hash) if kura_hash == snapshot_hash => {}
            Some(_) => {
                return Err(format!(
                    "the snapshot's block hash at height {height} differs from Kura's"
                ));
            }
            None => {
                return Err(format!(
                    "Kura has no durable block at height {height}, which the snapshot retains"
                ));
            }
        }
    }
    Ok(())
}

/// Run `--check-storage`: print the report as Norito JSON and fail when the dry run failed.
///
/// # Errors
///
/// [`MainError::CheckStorage`] when the store cannot be read or the restore dry run failed (the
/// report is printed first in the latter case).
pub fn run_check_storage(config: &Config) -> ReportResult<(), MainError> {
    let report = check_storage(config)
        .map_err(|error| Report::new(MainError::CheckStorage).attach(error))?;
    let json = norito::json::to_json(&report)
        .map_err(|error| Report::new(MainError::CheckStorage).attach(error.to_string()))?;
    println!("{json}");
    if report.is_ok() {
        Ok(())
    } else {
        Err(Report::new(MainError::CheckStorage).attach(
            report
                .snapshot_restore_error
                .unwrap_or_else(|| "snapshot restore dry run failed".to_owned()),
        ))
    }
}

#[cfg(test)]
mod tests;
