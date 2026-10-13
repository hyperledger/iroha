//! Persistence helpers for DA replay cursors, receipts, and spool artifacts.

#![allow(clippy::redundant_pub_crate)]
use crate::secure_file_metadata;
use eyre::{WrapErr, eyre};
use iroha_core::da::{LaneEpoch, ReplayFingerprint};
use iroha_crypto::{Algorithm, Hash, KeyPair, PublicKey, Signature};
use iroha_data_model::{
    NetworkId,
    da::{ingest::StoredDaReceipt, prelude::*},
};
use iroha_logger::{debug, warn};
use iroha_model_base::topology::LaneId;
use norito::{
    decode_from_bytes,
    json::{self, JsonDeserialize, JsonSerialize},
    to_bytes,
};
use parking_lot::{Mutex as NonPoisoningMutex, MutexGuard as NonPoisoningMutexGuard};
use sorafs_manifest::pdp::{PDP_COMMITMENT_MAX_CANONICAL_BYTES_V1, PdpCommitmentV1};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::{self, File},
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
const CURSOR_FILE_NAME: &str = "replay_cursors.norito.json";
const CURSOR_JOURNAL_FILE_NAME: &str = "replay_cursors.journal";
const CURSOR_SNAPSHOT_VERSION: u32 = 1;
const CURSOR_JOURNAL_VERSION: u32 = 1;
const CURSOR_JOURNAL_MAX_PAYLOAD_BYTES: usize = 256;
const CURSOR_JOURNAL_CHECKSUM_BYTES: usize = blake3::OUT_LEN;
const CURSOR_JOURNAL_FRAME_PREFIX_BYTES: usize = std::mem::size_of::<u32>();
const CURSOR_JOURNAL_DOMAIN: &[u8] = b"iroha.da.replay.cursor.journal.v1";
const CURSOR_SNAPSHOT_MAX_ENTRY_BYTES: usize = 256;
const CURSOR_SNAPSHOT_FIXED_OVERHEAD_BYTES: usize = 128;
const RECEIPT_FILE_PREFIX: &str = "da-receipt";
const RETIRED_RECEIPT_DIR_NAME: &str = "retired-da-receipts-v1";
/// First-release ceiling for one durable DA receipt, including its PDP commitment and signature.
const DA_RECEIPT_ARTIFACT_MAX_BYTES_V1: usize = 64 * 1024;
/// First-release ceiling covering Ed25519, secp256k1, and ML-DSA-65 receipt signatures.
const DA_RECEIPT_SIGNATURE_MAX_BYTES_V1: usize = 4 * 1024;
/// First-release ceiling for one canonical DA manifest spool body.
const DA_MANIFEST_ARTIFACT_MAX_BYTES_V1: usize = 2 * 1024 * 1024;
/// First-release ceiling for one authorised DA pin-intent spool body.
const DA_PIN_INTENT_ARTIFACT_MAX_BYTES_V1: usize = 2 * 1024 * 1024;
/// First-release ceiling for one unsigned producer pin-scope challenge.
const DA_PIN_SCOPE_ARTIFACT_MAX_BYTES_V1: usize = 64 * 1024;
const TICKET_ARTIFACTS_DIR: &str = "artifacts";
const MANIFEST_ARTIFACT_FILE_NAME: &str = "manifest.norito";
const PDP_COMMITMENT_ARTIFACT_FILE_NAME: &str = "pdp-commitment.norito";
/// Placeholder signature bytes used before signing DA receipts.
pub(crate) const RECEIPT_SIGNATURE_PLACEHOLDER: [u8; 64] = [0xA5; 64];
const RECEIPT_SIGNING_PAYLOAD_VERSION: u16 = 1;
const DA_COMMITMENT_SCHEDULE_ENTRY_VERSION: u16 = 1;
const DA_INGEST_SERVER_ASSIGNMENT_VERSION: u16 = 1;
const DA_INGEST_SIGNED_RECEIPT_ASSIGNMENT_VERSION: u16 = 1;
const DA_INGEST_SERVER_ASSIGNMENT_DIR: &str = "request-intents-v1";
const DA_INGEST_SERVER_ASSIGNMENT_MAX_BYTES_V1: usize = 4 * 1024 * 1024;
const DA_INGEST_SIGNED_RECEIPT_ASSIGNMENT_MAX_BYTES_V1: usize = 128 * 1024;
static ARTIFACT_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static DA_INGEST_SERVER_ASSIGNMENT_LOCK: OnceLock<NonPoisoningMutex<()>> = OnceLock::new();

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::da::persistence::DaIngestServerAssignmentV1")]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
/// Durable server-owned choices for one signed DA ingest request.
pub(super) struct DaIngestServerAssignmentV1 {
    /// Assignment layout version.
    pub(super) version: u16,
    /// Stable digest authorised by every request signer.
    pub(super) request_digest: [u8; 32],
    /// Network component of the replay-slot identity.
    pub(super) network_id: NetworkId,
    /// Bound Nexus lane.
    pub(super) lane_id: LaneId,
    /// Bound lane epoch.
    pub(super) epoch: u64,
    /// Bound replay sequence.
    pub(super) sequence: u64,
    /// Bound caller content identifier.
    pub(super) client_blob_id: BlobDigest,
    /// Bound canonical payload digest.
    pub(super) payload_hash: BlobDigest,
    /// Bound canonical payload length.
    pub(super) total_size: u64,
    /// Server-assigned queue time reused by the manifest, PDP, and receipt.
    pub(super) queued_at_secs: u64,
    /// Fully transformed metadata, including server-generated encryption nonces.
    pub(super) transformed_metadata: ExtraMetadata,
    /// Proof scheme selected from the admitted lane policy.
    pub(super) proof_scheme: DaProofScheme,
    /// Retention policy selected from the admitted replication policy.
    pub(super) enforced_retention: RetentionPolicy,
    /// Whether the selected retention policy differs from the submitted one.
    pub(super) retention_mismatch: bool,
    /// Canonical manifest bytes derived from all server-owned choices.
    pub(super) manifest_bytes: Vec<u8>,
    /// Operator key authenticating the frozen assignment independently of metadata-key rotation.
    pub(super) operator_public_key: PublicKey,
    /// Signature over the complete assignment with this field replaced by a fixed placeholder.
    pub(super) assignment_signature: Signature,
}

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::da::persistence::DaIngestSignedReceiptAssignmentV1")]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]

struct DaIngestSignedReceiptAssignmentV1 {
    version: u16,
    request_digest: [u8; 32],
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    operator_public_key: PublicKey,
    receipt: DaIngestReceipt,
}

impl DaIngestServerAssignmentV1 {
    /// Freeze and operator-attest every server-owned choice for one validated request.
    pub(super) fn try_new(
        request: &DaIngestRequest,
        queued_at_secs: u64,
        transformed_metadata: ExtraMetadata,
        proof_scheme: DaProofScheme,
        (enforced_retention, retention_mismatch): (RetentionPolicy, bool),
        manifest_bytes: Vec<u8>,
        signer: &KeyPair,
    ) -> std::io::Result<Self> {
        let mut assignment = Self {
            version: DA_INGEST_SERVER_ASSIGNMENT_VERSION,
            request_digest: request.signing_digest(),
            network_id: request.network_id,
            lane_id: request.lane_id,
            epoch: request.epoch,
            sequence: request.sequence,
            client_blob_id: request.client_blob_id,
            payload_hash: request.payload_hash,
            total_size: request.total_size,
            queued_at_secs,
            transformed_metadata,
            proof_scheme,
            enforced_retention,
            retention_mismatch,
            manifest_bytes,
            operator_public_key: signer.public_key().clone(),
            assignment_signature: receipt_signature_placeholder(),
        };
        let signing_bytes = assignment.signing_bytes()?;
        assignment.assignment_signature = Signature::try_new(signer.private_key(), &signing_bytes)
            .map_err(|err| std::io::Error::new(ErrorKind::Other, err))?;
        Ok(assignment)
    }

    fn signing_bytes(&self) -> std::io::Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.assignment_signature = receipt_signature_placeholder();
        to_bytes(&unsigned).map_err(|err| std::io::Error::new(ErrorKind::Other, err))
    }
}

fn validate_da_ingest_server_assignment(
    assignment: &DaIngestServerAssignmentV1,
    request: &DaIngestRequest,
    trusted_operator_key: &PublicKey,
) -> std::io::Result<()> {
    if assignment.version != DA_INGEST_SERVER_ASSIGNMENT_VERSION {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "unsupported DA ingest server assignment version {} (expected {})",
                assignment.version, DA_INGEST_SERVER_ASSIGNMENT_VERSION
            ),
        ));
    }
    if assignment.assignment_signature.payload().len() > DA_RECEIPT_SIGNATURE_MAX_BYTES_V1 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "DA ingest server assignment signature exceeds its first-release bound",
        ));
    }
    let signing_bytes = assignment.signing_bytes().map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("failed to encode DA ingest assignment signing payload: {err}"),
        )
    })?;
    assignment
        .assignment_signature
        .verify(&assignment.operator_public_key, &signing_bytes)
        .map_err(|err| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!("DA ingest server assignment signature is invalid: {err}"),
            )
        })?;
    if assignment.operator_public_key != *trusted_operator_key {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "DA ingest server assignment is not attested by the configured receipt signer",
        ));
    }
    let request_identity_matches = assignment.request_digest == request.signing_digest()
        && assignment.network_id == request.network_id
        && assignment.lane_id == request.lane_id
        && assignment.epoch == request.epoch
        && assignment.sequence == request.sequence
        && assignment.client_blob_id == request.client_blob_id
        && assignment.payload_hash == request.payload_hash
        && assignment.total_size == request.total_size;
    if !request_identity_matches {
        return Err(std::io::Error::new(
            ErrorKind::AlreadyExists,
            "DA ingest server assignment does not match the signed request identity",
        ));
    }
    if assignment.manifest_bytes.len() > DA_MANIFEST_ARTIFACT_MAX_BYTES_V1 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "DA ingest server assignment manifest is {} bytes, exceeding the first-release {}-byte limit",
                assignment.manifest_bytes.len(),
                DA_MANIFEST_ARTIFACT_MAX_BYTES_V1
            ),
        ));
    }
    let (manifest, _) = decode_manifest_spool_body(&assignment.manifest_bytes)?;
    let canonical_manifest = to_bytes(&manifest).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("failed to canonically re-encode assigned DA manifest: {err}"),
        )
    })?;
    if canonical_manifest != assignment.manifest_bytes {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "DA ingest server assignment contains a non-canonical manifest encoding",
        ));
    }
    let payload_hash_matches = manifest.blob_hash == assignment.payload_hash;
    let retention_matches = manifest.retention_policy == assignment.enforced_retention;
    if manifest.client_blob_id != assignment.client_blob_id
        || manifest.lane_id != assignment.lane_id
        || manifest.epoch != assignment.epoch
        || !payload_hash_matches
        || manifest.total_size != assignment.total_size
        || !retention_matches
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "assigned DA manifest does not match its durable request identity and policy",
        ));
    }
    Ok(())
}

fn decode_da_ingest_server_assignment(
    path: &Path,
    request: &DaIngestRequest,
    trusted_operator_key: &PublicKey,
) -> std::io::Result<DaIngestServerAssignmentV1> {
    decode_da_ingest_server_assignment_with_link_policy(path, request, trusted_operator_key, false)
}

fn decode_da_ingest_server_assignment_with_link_policy(
    path: &Path,
    request: &DaIngestRequest,
    trusted_operator_key: &PublicKey,
    allow_publish_hard_link: bool,
) -> std::io::Result<DaIngestServerAssignmentV1> {
    let bytes = read_regular_spool_artifact_with_link_policy(
        path,
        "DA ingest server assignment",
        DA_INGEST_SERVER_ASSIGNMENT_MAX_BYTES_V1,
        allow_publish_hard_link,
    )?;
    let assignment = decode_from_bytes::<DaIngestServerAssignmentV1>(&bytes).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "failed to decode DA ingest server assignment {}: {err}",
                path.display()
            ),
        )
    })?;
    let canonical = to_bytes(&assignment).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "failed to canonically re-encode DA ingest server assignment {}: {err}",
                path.display()
            ),
        )
    })?;
    if canonical != bytes {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "DA ingest server assignment {} is not canonically encoded",
                path.display()
            ),
        ));
    }
    validate_da_ingest_server_assignment(&assignment, request, trusted_operator_key)?;
    Ok(assignment)
}

fn assignment_target_has_recoverable_temp_link(
    target_path: &Path,
    temp_path: &Path,
) -> std::io::Result<bool> {
    if !spool_artifact_exists(temp_path)? {
        return Ok(false);
    }
    let target_metadata = secure_file_metadata::from_path(target_path)?;
    let temp_metadata = secure_file_metadata::from_path(temp_path)?;
    if !secure_file_metadata::same_file(&target_metadata, &temp_metadata) {
        return Ok(false);
    }
    if !secure_file_metadata::is_direct_file(&target_metadata)
        || !secure_file_metadata::is_direct_file(&temp_metadata)
        || secure_file_metadata::number_of_links(&target_metadata) != Some(2)
        || secure_file_metadata::number_of_links(&temp_metadata) != Some(2)
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "DA ingest assignment publish hard link is not an exact two-link regular file",
        ));
    }
    Ok(true)
}

fn da_ingest_server_assignment_paths(
    spool_dir: &Path,
    network_id: &NetworkId,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
) -> std::io::Result<(PathBuf, PathBuf)> {
    if spool_dir.as_os_str().is_empty() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "DA ingest spool directory is required for durable server assignments",
        ));
    }
    let assignments_dir = spool_dir.join(DA_INGEST_SERVER_ASSIGNMENT_DIR);
    let network_hash = blake3::hash(network_id.as_bytes());
    let network_dir = assignments_dir.join(hex::encode(network_hash.as_bytes()));
    let lane_dir = network_dir.join(format!("{:08x}", lane_id.as_u32()));
    let epoch_dir = lane_dir.join(format!("{epoch:016x}"));
    Ok((
        epoch_dir.join(format!("{sequence:016x}.norito")),
        epoch_dir.join(format!(".{sequence:016x}.tmp")),
    ))
}

fn create_da_ingest_server_assignment_dirs(target_path: &Path) -> std::io::Result<()> {
    let epoch_dir = target_path.parent().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "assignment path has no epoch directory",
        )
    })?;
    let lane_dir = epoch_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "assignment path has no lane directory",
        )
    })?;
    let network_dir = lane_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "assignment path has no network directory",
        )
    })?;
    let assignments_dir = network_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "assignment path has no intent directory",
        )
    })?;
    let spool_dir = assignments_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "assignment path has no spool directory",
        )
    })?;
    for directory in [spool_dir, assignments_dir, network_dir, lane_dir, epoch_dir] {
        create_spool_dir_no_follow(directory)?;
    }
    Ok(())
}

fn validate_existing_da_ingest_server_assignment_dirs(target_path: &Path) -> std::io::Result<bool> {
    let epoch_dir = target_path.parent().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "assignment path has no epoch directory",
        )
    })?;
    let lane_dir = epoch_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "assignment path has no lane directory",
        )
    })?;
    let network_dir = lane_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "assignment path has no network directory",
        )
    })?;
    let assignments_dir = network_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "assignment path has no intent directory",
        )
    })?;
    let spool_dir = assignments_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "assignment path has no spool directory",
        )
    })?;
    for directory in [spool_dir, assignments_dir, network_dir, lane_dir, epoch_dir] {
        let metadata = match secure_file_metadata::from_path(directory) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(err),
        };
        validate_spool_dir_metadata(directory, &metadata)?;
    }
    Ok(true)
}

fn da_ingest_signed_receipt_assignment_paths(
    spool_dir: &Path,
    network_id: &NetworkId,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
) -> std::io::Result<(PathBuf, PathBuf)> {
    let (assignment_path, _) =
        da_ingest_server_assignment_paths(spool_dir, network_id, lane_id, epoch, sequence)?;
    let shard_dir = assignment_path.parent().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "assignment path has no parent")
    })?;
    Ok((
        shard_dir.join(format!("{sequence:016x}.receipt.norito")),
        shard_dir.join(format!(".{sequence:016x}.receipt.tmp")),
    ))
}

fn install_da_ingest_server_assignment(
    temp_path: &Path,
    target_path: &Path,
) -> std::io::Result<()> {
    match fs::hard_link(temp_path, target_path) {
        Ok(()) => {
            sync_parent_dir(target_path)?;
            remove_temp_artifact(temp_path)?;
            sync_parent_dir(target_path)
        }
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            remove_temp_artifact(temp_path)?;
            sync_parent_dir(target_path)
        }
        Err(err) => Err(err),
    }
}

fn spool_artifact_exists(path: &Path) -> std::io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// Load a previously published server assignment, recovering its one bounded temp if necessary.
pub(super) fn load_da_ingest_server_assignment(
    spool_dir: &Path,
    request: &DaIngestRequest,
    trusted_operator_key: &PublicKey,
) -> std::io::Result<Option<DaIngestServerAssignmentV1>> {
    let _guard = DA_INGEST_SERVER_ASSIGNMENT_LOCK
        .get_or_init(|| NonPoisoningMutex::new(()))
        .lock();
    let (target_path, temp_path) = da_ingest_server_assignment_paths(
        spool_dir,
        &request.network_id,
        request.lane_id,
        request.epoch,
        request.sequence,
    )?;
    if !validate_existing_da_ingest_server_assignment_dirs(&target_path)? {
        return Ok(None);
    }
    if spool_artifact_exists(&target_path)? {
        let allow_publish_hard_link =
            assignment_target_has_recoverable_temp_link(&target_path, &temp_path)?;
        return decode_da_ingest_server_assignment_with_link_policy(
            &target_path,
            request,
            trusted_operator_key,
            allow_publish_hard_link,
        )
        .map(Some);
    }
    if !spool_artifact_exists(&temp_path)? {
        return Ok(None);
    }
    let metadata = fs::symlink_metadata(&temp_path)?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "DA ingest server assignment temp {} is not a regular file",
                temp_path.display()
            ),
        ));
    }
    match decode_da_ingest_server_assignment(&temp_path, request, trusted_operator_key) {
        Ok(assignment) => Ok(Some(assignment)),
        Err(err) if err.kind() == ErrorKind::InvalidData => Ok(None),
        Err(err) => Err(err),
    }
}

/// Atomically publish or recover the canonical server-owned choices for a signed ingest request.
pub(super) fn load_or_create_da_ingest_server_assignment(
    spool_dir: &Path,
    request: &DaIngestRequest,
    trusted_operator_key: &PublicKey,
    candidate: &DaIngestServerAssignmentV1,
) -> std::io::Result<DaIngestServerAssignmentV1> {
    validate_da_ingest_server_assignment(candidate, request, trusted_operator_key).map_err(
        |err| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("invalid DA ingest server assignment candidate: {err}"),
            )
        },
    )?;
    let encoded =
        to_bytes(candidate).map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))?;
    if encoded.len() > DA_INGEST_SERVER_ASSIGNMENT_MAX_BYTES_V1 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "DA ingest server assignment is {} bytes, exceeding the first-release {}-byte limit",
                encoded.len(),
                DA_INGEST_SERVER_ASSIGNMENT_MAX_BYTES_V1
            ),
        ));
    }

    let _guard = DA_INGEST_SERVER_ASSIGNMENT_LOCK
        .get_or_init(|| NonPoisoningMutex::new(()))
        .lock();
    let (target_path, temp_path) = da_ingest_server_assignment_paths(
        spool_dir,
        &candidate.network_id,
        candidate.lane_id,
        candidate.epoch,
        candidate.sequence,
    )?;
    create_da_ingest_server_assignment_dirs(&target_path)?;

    if spool_artifact_exists(&target_path)? {
        if spool_artifact_exists(&temp_path)? {
            remove_temp_artifact(&temp_path)?;
            sync_parent_dir(&target_path)?;
        }
        return decode_da_ingest_server_assignment(&target_path, request, trusted_operator_key);
    }

    match spool_artifact_exists(&temp_path) {
        Ok(true) => {
            let metadata = fs::symlink_metadata(&temp_path)?;
            if !metadata.file_type().is_file() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "DA ingest server assignment temp {} is not a regular file",
                        temp_path.display()
                    ),
                ));
            }
            match decode_da_ingest_server_assignment(&temp_path, request, trusted_operator_key) {
                Ok(assignment) => {
                    install_da_ingest_server_assignment(&temp_path, &target_path)?;
                    let installed = decode_da_ingest_server_assignment(
                        &target_path,
                        request,
                        trusted_operator_key,
                    )?;
                    if installed != assignment {
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "installed DA ingest server assignment changed during recovery",
                        ));
                    }
                    return Ok(installed);
                }
                Err(err) if err.kind() == ErrorKind::InvalidData => {
                    remove_temp_artifact(&temp_path)?;
                    sync_parent_dir(&target_path)?;
                }
                Err(err) => return Err(err),
            }
        }
        Ok(false) => {}
        Err(err) => return Err(err),
    }

    write_temp_artifact(&temp_path, &encoded)
        .map_err(|err| temp_artifact_write_error(&temp_path, err))?;
    install_da_ingest_server_assignment(&temp_path, &target_path)?;
    decode_da_ingest_server_assignment(&target_path, request, trusted_operator_key)
}

fn validate_da_ingest_signed_receipt_assignment(
    assignment: &DaIngestSignedReceiptAssignmentV1,
    expected: &DaIngestSignedReceiptAssignmentV1,
) -> std::io::Result<()> {
    if assignment.version != DA_INGEST_SIGNED_RECEIPT_ASSIGNMENT_VERSION
        || assignment.request_digest != expected.request_digest
        || assignment.lane_id != expected.lane_id
        || assignment.epoch != expected.epoch
        || assignment.sequence != expected.sequence
        || assignment.operator_public_key != expected.operator_public_key
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "signed DA receipt assignment does not match its request or operator identity",
        ));
    }
    validate_receipt_resource_bounds(&assignment.receipt).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("signed DA receipt assignment exceeds resource bounds: {err}"),
        )
    })?;
    if assignment.receipt.lane_id != assignment.lane_id
        || assignment.receipt.epoch != assignment.epoch
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "signed DA receipt assignment lane/epoch does not match its receipt",
        ));
    }
    let assigned_unsigned = unsigned_receipt_bytes(&assignment.receipt, assignment.sequence)
        .map_err(|err| std::io::Error::new(ErrorKind::InvalidData, err.to_string()))?;
    let expected_unsigned = unsigned_receipt_bytes(&expected.receipt, expected.sequence)
        .map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err.to_string()))?;
    if assigned_unsigned != expected_unsigned {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "signed DA receipt assignment conflicts with the deterministic receipt fields",
        ));
    }
    verify_receipt_signature(
        &assignment.receipt,
        assignment.sequence,
        &assignment.operator_public_key,
    )
    .map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("signed DA receipt assignment has an invalid operator signature: {err}"),
        )
    })?;
    Ok(())
}

fn decode_da_ingest_signed_receipt_assignment(
    path: &Path,
    expected: &DaIngestSignedReceiptAssignmentV1,
) -> std::io::Result<DaIngestSignedReceiptAssignmentV1> {
    let bytes = read_regular_spool_artifact(
        path,
        "signed DA receipt assignment",
        DA_INGEST_SIGNED_RECEIPT_ASSIGNMENT_MAX_BYTES_V1,
    )?;
    let assignment =
        decode_from_bytes::<DaIngestSignedReceiptAssignmentV1>(&bytes).map_err(|err| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "failed to decode signed DA receipt assignment {}: {err}",
                    path.display()
                ),
            )
        })?;
    let canonical = to_bytes(&assignment).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "failed to re-encode signed DA receipt assignment {}: {err}",
                path.display()
            ),
        )
    })?;
    if canonical != bytes {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "signed DA receipt assignment {} is not canonically encoded",
                path.display()
            ),
        ));
    }
    validate_da_ingest_signed_receipt_assignment(&assignment, expected)?;
    Ok(assignment)
}

fn validate_signed_receipt_against_server_assignment(
    request: &DaIngestRequest,
    assignment: &DaIngestServerAssignmentV1,
    receipt: &DaIngestReceipt,
) -> std::io::Result<()> {
    let manifest =
        decode_from_bytes::<DaManifestV1>(&assignment.manifest_bytes).map_err(|err| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!("failed to decode manifest from DA ingest server assignment: {err}"),
            )
        })?;
    let manifest_hash = BlobDigest::from_hash(blake3::hash(&assignment.manifest_bytes));
    if receipt.client_blob_id != request.client_blob_id
        || receipt.lane_id != request.lane_id
        || receipt.epoch != request.epoch
        || receipt.blob_hash != manifest.blob_hash
        || receipt.chunk_root != manifest.chunk_root
        || receipt.manifest_hash != manifest_hash
        || receipt.storage_ticket != manifest.storage_ticket
        || receipt.stripe_layout.total_stripes != manifest.total_stripes
        || receipt.stripe_layout.shards_per_stripe != manifest.shards_per_stripe
        || receipt.stripe_layout.row_parity_stripes != manifest.erasure_profile.row_parity_stripes
        || receipt.queued_at_unix != assignment.queued_at_secs
        || receipt.rent_quote != manifest.rent_quote
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "signed DA receipt assignment does not match its durable manifest assignment",
        ));
    }
    let pdp_bytes = receipt.pdp_commitment.as_deref().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            "signed DA receipt assignment is missing its PDP commitment",
        )
    })?;
    let pdp = decode_pdp_commitment_spool_body(pdp_bytes)?;
    if pdp.manifest_digest != *manifest_hash.as_bytes()
        || pdp.payload_len != manifest.total_size
        || pdp.sealed_at != assignment.queued_at_secs
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "signed DA receipt assignment PDP commitment does not match its manifest and queue time",
        ));
    }
    Ok(())
}

/// Freeze the complete signed receipt before independently persisted DA artifacts are published.
pub(super) fn load_or_create_da_ingest_signed_receipt(
    spool_dir: &Path,
    request: &DaIngestRequest,
    operator_public_key: &PublicKey,
    candidate: &DaIngestReceipt,
) -> std::io::Result<DaIngestReceipt> {
    let server_assignment =
        load_da_ingest_server_assignment(spool_dir, request, operator_public_key)?.ok_or_else(
            || {
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "signed DA receipt cannot be frozen before its server assignment is durable",
                )
            },
        )?;
    validate_signed_receipt_against_server_assignment(request, &server_assignment, candidate)?;
    let expected = DaIngestSignedReceiptAssignmentV1 {
        version: DA_INGEST_SIGNED_RECEIPT_ASSIGNMENT_VERSION,
        request_digest: request.signing_digest(),
        lane_id: request.lane_id,
        epoch: request.epoch,
        sequence: request.sequence,
        operator_public_key: operator_public_key.clone(),
        receipt: candidate.clone(),
    };
    validate_da_ingest_signed_receipt_assignment(&expected, &expected).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid signed DA receipt assignment candidate: {err}"),
        )
    })?;
    let encoded =
        to_bytes(&expected).map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))?;
    if encoded.len() > DA_INGEST_SIGNED_RECEIPT_ASSIGNMENT_MAX_BYTES_V1 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "signed DA receipt assignment is {} bytes, exceeding the first-release {}-byte limit",
                encoded.len(),
                DA_INGEST_SIGNED_RECEIPT_ASSIGNMENT_MAX_BYTES_V1
            ),
        ));
    }
    let _guard = DA_INGEST_SERVER_ASSIGNMENT_LOCK
        .get_or_init(|| NonPoisoningMutex::new(()))
        .lock();
    let (target_path, temp_path) = da_ingest_signed_receipt_assignment_paths(
        spool_dir,
        &request.network_id,
        expected.lane_id,
        expected.epoch,
        expected.sequence,
    )?;
    create_da_ingest_server_assignment_dirs(&target_path)?;
    match fs::symlink_metadata(&target_path) {
        Ok(_) => {
            if spool_artifact_exists(&temp_path)? {
                remove_temp_artifact(&temp_path)?;
                sync_parent_dir(&target_path)?;
            }
            return decode_da_ingest_signed_receipt_assignment(&target_path, &expected)
                .map(|assignment| assignment.receipt);
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    match fs::symlink_metadata(&temp_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "signed DA receipt assignment temp {} is not a regular file",
                        temp_path.display()
                    ),
                ));
            }
            match decode_da_ingest_signed_receipt_assignment(&temp_path, &expected) {
                Ok(_) => {
                    install_da_ingest_server_assignment(&temp_path, &target_path)?;
                    return decode_da_ingest_signed_receipt_assignment(&target_path, &expected)
                        .map(|assignment| assignment.receipt);
                }
                Err(err) if err.kind() == ErrorKind::InvalidData => {
                    remove_temp_artifact(&temp_path)?;
                    sync_parent_dir(&target_path)?;
                }
                Err(err) => return Err(err),
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    write_temp_artifact(&temp_path, &encoded)
        .map_err(|err| temp_artifact_write_error(&temp_path, err))?;
    install_da_ingest_server_assignment(&temp_path, &target_path)?;
    decode_da_ingest_signed_receipt_assignment(&target_path, &expected)
        .map(|assignment| assignment.receipt)
}

pub(crate) fn receipt_signature_placeholder() -> Signature {
    Signature::try_from_bytes(&RECEIPT_SIGNATURE_PLACEHOLDER)
        .expect("DA receipt placeholder signature is non-empty and nonzero")
}
/// Persistent store tracking the highest sequence observed per `(lane, epoch)`.
pub struct ReplayCursorStore {
    dir: PathBuf,
    max_lane_epochs: NonZeroUsize,
    // Cursor mutation runs inside the same caught spool actions as receipt persistence. Keep the
    // mutex non-poisoning so a caught panic cannot permanently disable every later ingest.
    inner: NonPoisoningMutex<ReplayCursorState>,
}
struct ReplayCursorState {
    highest: BTreeMap<LaneEpoch, u64>,
    journal: Option<File>,
    journal_records: usize,
    checkpoint_pending: bool,
    journal_healthy: bool,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
struct CursorSnapshot {
    version: u32,
    entries: Vec<CursorEntry>,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
struct CursorEntry {
    lane_id: u32,
    epoch: u64,
    highest_sequence: u64,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
struct CursorJournalRecord {
    version: u32,
    lane_id: u32,
    epoch: u64,
    highest_sequence: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CursorSnapshotRelation {
    Equal,
    CandidateAhead,
    CandidateBehind,
    Conflicting,
}
impl ReplayCursorStore {
    /// Load the replay cursor store from disk, returning an empty store when no snapshot exists.
    #[cfg(test)]
    pub fn open(path: PathBuf) -> eyre::Result<Self> {
        Self::open_with_max_lane_epochs(
            path,
            NonZeroUsize::new(iroha_core::da::ReplayCacheConfig::DEFAULT_LANE_EPOCH_CAPACITY)
                .expect("default DA replay lane/epoch capacity is non-zero"),
        )
    }
    /// Load a replay cursor store with an explicit global `(lane, epoch)` bound.
    pub fn open_with_max_lane_epochs(
        path: PathBuf,
        max_lane_epochs: NonZeroUsize,
    ) -> eyre::Result<Self> {
        create_replay_cursor_dir_no_follow(&path).wrap_err_with(|| {
            format!("failed to create DA replay directory at {}", path.display())
        })?;
        let file_path = path.join(CURSOR_FILE_NAME);
        let tmp_path = replay_cursor_temp_path(&file_path);
        let mut state = match read_cursor_snapshot(&file_path, max_lane_epochs) {
            Ok(Some(snapshot)) => match read_cursor_snapshot(&tmp_path, max_lane_epochs) {
                Ok(Some(tmp_snapshot)) => {
                    match compare_cursor_snapshots(&snapshot, &tmp_snapshot) {
                        CursorSnapshotRelation::CandidateAhead => {
                            warn!(
                                path = %tmp_path.display(),
                                "recovering newer DA replay cursor temp snapshot"
                            );
                            promote_replay_cursor_temp(&tmp_path, &file_path)?;
                            ReplayCursorState::from_snapshot(tmp_snapshot)
                        }
                        CursorSnapshotRelation::Equal | CursorSnapshotRelation::CandidateBehind => {
                            remove_replay_cursor_temp(&tmp_path)?;
                            ReplayCursorState::from_snapshot(snapshot)
                        }
                        CursorSnapshotRelation::Conflicting => {
                            warn!(
                                path = %tmp_path.display(),
                                "discarding conflicting DA replay cursor temp snapshot"
                            );
                            remove_replay_cursor_temp(&tmp_path)?;
                            ReplayCursorState::from_snapshot(snapshot)
                        }
                    }
                }
                Ok(None) => ReplayCursorState::from_snapshot(snapshot),
                Err(err) => {
                    warn!(
                        ?err,
                        path = %tmp_path.display(),
                        "discarding unreadable DA replay cursor temp snapshot"
                    );
                    remove_replay_cursor_temp(&tmp_path)?;
                    ReplayCursorState::from_snapshot(snapshot)
                }
            },
            Ok(None) => match read_cursor_snapshot(&tmp_path, max_lane_epochs) {
                Ok(Some(snapshot)) => {
                    promote_replay_cursor_temp(&tmp_path, &file_path)?;
                    ReplayCursorState::from_snapshot(snapshot)
                }
                Ok(None) => ReplayCursorState::empty(),
                Err(err) => return Err(err),
            },
            Err(err) => match read_cursor_snapshot(&tmp_path, max_lane_epochs) {
                Ok(Some(snapshot)) => {
                    warn!(
                        ?err,
                        path = %file_path.display(),
                        "DA replay cursor snapshot invalid; recovering from temp snapshot"
                    );
                    promote_replay_cursor_temp(&tmp_path, &file_path)?;
                    ReplayCursorState::from_snapshot(snapshot)
                }
                Ok(None) => return Err(err),
                Err(tmp_err) => {
                    warn!(
                        ?tmp_err,
                        path = %tmp_path.display(),
                        "failed to read DA replay cursor temp snapshot"
                    );
                    return Err(err);
                }
            },
        };
        let journal_path = replay_cursor_journal_path(&path);
        let recovery = read_cursor_journal(&journal_path, max_lane_epochs)?;
        for record in recovery.records {
            state.apply_journal_record(record, max_lane_epochs)?;
        }
        state.journal_records = recovery.record_count;
        state.checkpoint_pending = state.journal_records >= max_lane_epochs.get();
        state.journal = Some(open_cursor_journal(
            &journal_path,
            recovery.valid_bytes,
            recovery.had_torn_tail,
        )?);
        let store = Self::with_state(path, max_lane_epochs, state);
        let checkpoint_pending = store.lock_state().checkpoint_pending;
        if checkpoint_pending {
            store.checkpoint()?;
        }
        Ok(store)
    }
    /// Create an empty store backed by the provided directory (creating it if missing).
    #[cfg(test)]
    pub fn empty(path: PathBuf) -> eyre::Result<Self> {
        Self::empty_with_max_lane_epochs(
            path,
            NonZeroUsize::new(iroha_core::da::ReplayCacheConfig::DEFAULT_LANE_EPOCH_CAPACITY)
                .expect("default DA replay lane/epoch capacity is non-zero"),
        )
    }
    /// Create an empty persistent store with an explicit global `(lane, epoch)` bound.
    #[cfg(test)]
    pub fn empty_with_max_lane_epochs(
        path: PathBuf,
        max_lane_epochs: NonZeroUsize,
    ) -> eyre::Result<Self> {
        create_replay_cursor_dir_no_follow(&path).wrap_err_with(|| {
            format!("failed to create DA replay directory at {}", path.display())
        })?;
        for artifact in [
            path.join(CURSOR_FILE_NAME),
            replay_cursor_temp_path(&path.join(CURSOR_FILE_NAME)),
            replay_cursor_journal_path(&path),
        ] {
            if fs::symlink_metadata(&artifact).is_ok() {
                return Err(eyre!(
                    "refusing to reset existing DA replay cursor artifact at {}",
                    artifact.display()
                ));
            }
        }
        let journal_path = replay_cursor_journal_path(&path);
        let journal = create_cursor_journal(&journal_path)?;
        let mut state = ReplayCursorState::empty();
        state.journal = Some(journal);
        Ok(Self::with_state(path, max_lane_epochs, state))
    }
    /// Create an in-memory store (persistence disabled).
    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self::in_memory_with_max_lane_epochs(
            NonZeroUsize::new(iroha_core::da::ReplayCacheConfig::DEFAULT_LANE_EPOCH_CAPACITY)
                .expect("default DA replay lane/epoch capacity is non-zero"),
        )
    }
    /// Create an in-memory store with an explicit global `(lane, epoch)` bound.
    pub fn in_memory_with_max_lane_epochs(max_lane_epochs: NonZeroUsize) -> Self {
        Self {
            dir: PathBuf::new(),
            max_lane_epochs,
            inner: NonPoisoningMutex::new(ReplayCursorState::empty()),
        }
    }
    fn with_state(path: PathBuf, max_lane_epochs: NonZeroUsize, state: ReplayCursorState) -> Self {
        Self {
            dir: path,
            max_lane_epochs,
            inner: NonPoisoningMutex::new(state),
        }
    }
    /// Access the known highest sequences for seeding the replay cache.
    pub fn highest_sequences(&self) -> Vec<(LaneEpoch, u64)> {
        let guard = self.lock_state();
        guard
            .highest
            .iter()
            .map(|(lane_epoch, highest)| (*lane_epoch, *highest))
            .collect()
    }
    /// Retire every cursor outside an authoritative lane/epoch allow-set.
    ///
    /// The filtered snapshot is published and the applied journal is truncated
    /// before this method returns, so a later receipt scan cannot resurrect a
    /// retired window when it applies the same allow-set.
    pub(crate) fn retain_lane_epochs(
        &self,
        mut retain: impl FnMut(LaneEpoch) -> bool,
    ) -> eyre::Result<usize> {
        let mut guard = self.lock_state();
        let before = guard.highest.len();
        guard.highest.retain(|lane_epoch, _| retain(*lane_epoch));
        let removed = before.saturating_sub(guard.highest.len());
        if removed == 0 {
            return Ok(0);
        }
        self.checkpoint_locked(&mut guard)?;
        Ok(removed)
    }
    fn highest_sequence(&self, lane_epoch: LaneEpoch) -> Option<u64> {
        self.lock_state().highest.get(&lane_epoch).copied()
    }
    const fn max_lane_epochs(&self) -> NonZeroUsize {
        self.max_lane_epochs
    }
    /// Record a newly observed sequence for the provided `(lane, epoch)` window.
    pub fn record(&self, lane_epoch: LaneEpoch, sequence: u64) -> eyre::Result<()> {
        let mut guard = self.lock_state();
        if guard
            .highest
            .get(&lane_epoch)
            .is_some_and(|highest| *highest >= sequence)
        {
            return Ok(());
        }
        if !guard.highest.contains_key(&lane_epoch)
            && guard.highest.len() >= self.max_lane_epochs.get()
        {
            return Err(eyre!(
                "DA replay lane/epoch capacity {} is exhausted",
                self.max_lane_epochs
            ));
        }
        if guard.checkpoint_pending {
            self.checkpoint_locked(&mut guard)?;
        }
        if !self.dir.as_os_str().is_empty() {
            if !guard.journal_healthy {
                return Err(eyre!(
                    "DA replay cursor journal is unhealthy; restart is required before recording more cursors"
                ));
            }
            let record = CursorJournalRecord {
                version: CURSOR_JOURNAL_VERSION,
                lane_id: lane_epoch.lane_id.as_u32(),
                epoch: lane_epoch.epoch,
                highest_sequence: sequence,
            };
            if let Err(err) =
                append_cursor_journal_record(&self.dir, self.max_lane_epochs, &mut guard, &record)
            {
                guard.journal_healthy = false;
                return Err(err);
            }
        }
        guard.highest.insert(lane_epoch, sequence);
        if guard.journal.is_some() {
            guard.journal_records = guard.journal_records.saturating_add(1);
            if guard.journal_records >= self.max_lane_epochs.get() {
                guard.checkpoint_pending = true;
                if let Err(err) = self.checkpoint_locked(&mut guard) {
                    warn!(
                        ?err,
                        "DA replay cursor checkpoint deferred; durable journal remains authoritative"
                    );
                }
            }
        }
        Ok(())
    }
    fn recover_failed_journal(&self) -> eyre::Result<()> {
        let mut guard = self.lock_state();
        if guard.journal_healthy || self.dir.as_os_str().is_empty() {
            return Ok(());
        }
        guard.journal.take();
        let journal_path = replay_cursor_journal_path(&self.dir);
        let recovery = read_cursor_journal(&journal_path, self.max_lane_epochs)
            .wrap_err("failed to recover DA replay cursor journal after an interrupted record")?;
        for record in recovery.records {
            guard.apply_journal_record(record, self.max_lane_epochs)?;
        }
        let journal =
            open_cursor_journal(&journal_path, recovery.valid_bytes, recovery.had_torn_tail)?;
        journal
            .sync_all()
            .wrap_err("failed to sync recovered DA replay cursor journal")?;
        validate_open_cursor_journal(&journal_path, &journal)?;
        guard.journal = Some(journal);
        guard.journal_records = recovery.record_count;
        guard.checkpoint_pending = guard.journal_records >= self.max_lane_epochs.get();
        guard.journal_healthy = true;
        Ok(())
    }
    /// Force a durable checkpoint and truncate the applied journal.
    pub(crate) fn checkpoint(&self) -> eyre::Result<()> {
        let mut guard = self.lock_state();
        self.checkpoint_locked(&mut guard)
    }
    fn checkpoint_locked(&self, guard: &mut ReplayCursorState) -> eyre::Result<()> {
        if self.dir.as_os_str().is_empty() {
            guard.checkpoint_pending = false;
            guard.journal_records = 0;
            return Ok(());
        }
        if !guard.journal_healthy {
            return Err(eyre!(
                "DA replay cursor journal is unhealthy; refusing to checkpoint"
            ));
        }
        self.persist_snapshot(&guard.to_snapshot())?;
        validate_replay_cursor_dir_no_follow(&self.dir).wrap_err_with(|| {
            format!(
                "failed to inspect DA replay journal directory at {}",
                self.dir.display()
            )
        })?;
        let journal = guard
            .journal
            .as_mut()
            .ok_or_else(|| eyre!("DA replay cursor journal handle is missing"))?;
        journal
            .set_len(0)
            .wrap_err("failed to truncate DA replay cursor journal after checkpoint")?;
        journal
            .seek(SeekFrom::Start(0))
            .wrap_err("failed to rewind DA replay cursor journal after checkpoint")?;
        journal
            .sync_all()
            .wrap_err("failed to sync truncated DA replay cursor journal")?;
        sync_dir(&self.dir).wrap_err("failed to sync DA replay cursor checkpoint directory")?;
        guard.journal_records = 0;
        guard.checkpoint_pending = false;
        Ok(())
    }
    fn lock_state(&self) -> NonPoisoningMutexGuard<'_, ReplayCursorState> {
        self.inner.lock()
    }
    fn persist_snapshot(&self, snapshot: &CursorSnapshot) -> eyre::Result<()> {
        if self.dir.as_os_str().is_empty() {
            // Persistence disabled; operate in-memory only.
            return Ok(());
        }
        let data = json::to_vec(snapshot).wrap_err("failed to encode DA replay snapshot")?;
        let file_path = self.dir.join(CURSOR_FILE_NAME);
        let tmp_path = replay_cursor_temp_path(&file_path);
        validate_replay_cursor_dir_no_follow(&self.dir).wrap_err_with(|| {
            format!(
                "failed to inspect DA replay snapshot directory at {}",
                self.dir.display()
            )
        })?;
        {
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp_path)
                .wrap_err_with(|| {
                    format!(
                        "failed to create DA replay snapshot temp file at {}",
                        tmp_path.display()
                    )
                })?;
            file.write_all(&data).wrap_err_with(|| {
                format!(
                    "failed to write DA replay snapshot temp file at {}",
                    tmp_path.display()
                )
            })?;
            file.sync_all().wrap_err_with(|| {
                format!(
                    "failed to sync DA replay snapshot temp file at {}",
                    tmp_path.display()
                )
            })?;
        }
        validate_replay_cursor_dir_no_follow(&self.dir).wrap_err_with(|| {
            format!(
                "failed to inspect DA replay snapshot directory at {}",
                self.dir.display()
            )
        })?;
        fs::rename(&tmp_path, &file_path).wrap_err_with(|| {
            format!(
                "failed to move DA replay snapshot temp file {} into place {}",
                tmp_path.display(),
                file_path.display()
            )
        })?;
        if let Some(parent) = file_path.parent() {
            if !parent.as_os_str().is_empty() {
                validate_replay_cursor_dir_no_follow(parent).wrap_err_with(|| {
                    format!(
                        "failed to inspect DA replay snapshot directory at {}",
                        parent.display()
                    )
                })?;
                sync_dir(parent).wrap_err_with(|| {
                    format!(
                        "failed to sync DA replay snapshot directory at {}",
                        parent.display()
                    )
                })?;
            }
        }
        Ok(())
    }
}
struct CursorJournalRecovery {
    records: Vec<CursorJournalRecord>,
    record_count: usize,
    valid_bytes: u64,
    had_torn_tail: bool,
}
fn read_cursor_journal(
    path: &Path,
    max_lane_epochs: NonZeroUsize,
) -> eyre::Result<CursorJournalRecovery> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Ok(CursorJournalRecovery {
                records: Vec::new(),
                record_count: 0,
                valid_bytes: 0,
                had_torn_tail: false,
            });
        }
        Err(err) => {
            return Err(eyre!(err)).wrap_err_with(|| {
                format!("failed to inspect DA replay journal at {}", path.display())
            });
        }
    };
    if !metadata.file_type().is_file() {
        return Err(eyre!(
            "DA replay cursor journal {} is not a regular file",
            path.display()
        ));
    }
    let max_bytes = max_cursor_journal_bytes(max_lane_epochs)?;
    if metadata.len() > max_bytes {
        return Err(eyre!(
            "DA replay cursor journal {} is {} bytes, exceeding bounded maximum {}",
            path.display(),
            metadata.len(),
            max_bytes
        ));
    }
    let max_bytes = usize::try_from(max_bytes)
        .map_err(|_| eyre!("DA replay cursor journal bound does not fit usize"))?;
    let bytes = read_regular_spool_artifact(path, "DA replay cursor journal", max_bytes)
        .wrap_err_with(|| format!("failed to read DA replay journal at {}", path.display()))?;
    let mut records = Vec::new();
    let mut offset = 0usize;
    let mut had_torn_tail = false;
    while offset < bytes.len() {
        let frame_start = offset;
        let Some(prefix_end) = offset.checked_add(CURSOR_JOURNAL_FRAME_PREFIX_BYTES) else {
            return Err(eyre!("DA replay cursor journal frame offset overflowed"));
        };
        if prefix_end > bytes.len() {
            had_torn_tail = true;
            break;
        }
        let payload_len = u32::from_be_bytes(
            bytes[offset..prefix_end]
                .try_into()
                .expect("journal length prefix has fixed width"),
        ) as usize;
        if payload_len > CURSOR_JOURNAL_MAX_PAYLOAD_BYTES {
            return Err(eyre!(
                "DA replay cursor journal frame payload length {payload_len} exceeds maximum {}",
                CURSOR_JOURNAL_MAX_PAYLOAD_BYTES
            ));
        }
        let Some(payload_end) = prefix_end.checked_add(payload_len) else {
            return Err(eyre!("DA replay cursor journal payload length overflowed"));
        };
        let Some(frame_end) = payload_end.checked_add(CURSOR_JOURNAL_CHECKSUM_BYTES) else {
            return Err(eyre!("DA replay cursor journal frame length overflowed"));
        };
        if frame_end > bytes.len() {
            had_torn_tail = true;
            break;
        }
        let payload = &bytes[prefix_end..payload_end];
        let expected_checksum = cursor_journal_checksum(payload);
        if bytes[payload_end..frame_end] != expected_checksum {
            return Err(eyre!(
                "DA replay cursor journal frame checksum mismatch at byte {frame_start}"
            ));
        }
        let record: CursorJournalRecord = json::from_slice(payload).wrap_err_with(|| {
            format!("failed to decode DA replay cursor journal frame at byte {frame_start}")
        })?;
        if record.version != CURSOR_JOURNAL_VERSION {
            return Err(eyre!(
                "unsupported DA replay cursor journal version {} at byte {}",
                record.version,
                frame_start
            ));
        }
        records.push(record);
        if records.len() > max_lane_epochs.get() {
            return Err(eyre!(
                "DA replay cursor journal contains more than {} bounded records",
                max_lane_epochs
            ));
        }
        offset = frame_end;
    }
    Ok(CursorJournalRecovery {
        record_count: records.len(),
        records,
        valid_bytes: u64::try_from(offset)
            .map_err(|_| eyre!("DA replay cursor journal offset exceeds u64"))?,
        had_torn_tail,
    })
}
fn max_cursor_journal_bytes(max_lane_epochs: NonZeroUsize) -> eyre::Result<u64> {
    let max_frame_bytes = CURSOR_JOURNAL_FRAME_PREFIX_BYTES
        .checked_add(CURSOR_JOURNAL_MAX_PAYLOAD_BYTES)
        .and_then(|bytes| bytes.checked_add(CURSOR_JOURNAL_CHECKSUM_BYTES))
        .ok_or_else(|| eyre!("DA replay cursor journal frame bound overflowed"))?;
    let bytes = max_lane_epochs
        .get()
        .checked_mul(max_frame_bytes)
        .ok_or_else(|| eyre!("DA replay cursor journal size bound overflowed"))?;
    u64::try_from(bytes).map_err(|_| eyre!("DA replay cursor journal size bound exceeds u64"))
}
fn max_cursor_snapshot_bytes(max_lane_epochs: NonZeroUsize) -> eyre::Result<u64> {
    let entries_bytes = max_lane_epochs
        .get()
        .checked_mul(CURSOR_SNAPSHOT_MAX_ENTRY_BYTES)
        .ok_or_else(|| eyre!("DA replay cursor snapshot size bound overflowed"))?;
    let bytes = entries_bytes
        .checked_add(CURSOR_SNAPSHOT_FIXED_OVERHEAD_BYTES)
        .ok_or_else(|| eyre!("DA replay cursor snapshot size bound overflowed"))?;
    u64::try_from(bytes).map_err(|_| eyre!("DA replay cursor snapshot size bound exceeds u64"))
}
fn cursor_journal_checksum(payload: &[u8]) -> [u8; blake3::OUT_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CURSOR_JOURNAL_DOMAIN);
    hasher.update(payload);
    hasher.finalize().into()
}
fn encode_cursor_journal_frame(record: &CursorJournalRecord) -> eyre::Result<Vec<u8>> {
    let payload =
        json::to_vec(record).wrap_err("failed to encode DA replay cursor journal entry")?;
    if payload.len() > CURSOR_JOURNAL_MAX_PAYLOAD_BYTES {
        return Err(eyre!(
            "encoded DA replay cursor journal entry is {} bytes, exceeding maximum {}",
            payload.len(),
            CURSOR_JOURNAL_MAX_PAYLOAD_BYTES
        ));
    }
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| eyre!("DA replay cursor journal entry length exceeds u32"))?;
    let frame_capacity = CURSOR_JOURNAL_FRAME_PREFIX_BYTES
        .checked_add(payload.len())
        .and_then(|bytes| bytes.checked_add(CURSOR_JOURNAL_CHECKSUM_BYTES))
        .ok_or_else(|| eyre!("DA replay cursor journal frame length overflowed"))?;
    let mut frame = Vec::with_capacity(frame_capacity);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(&cursor_journal_checksum(&payload));
    Ok(frame)
}
fn replay_cursor_journal_path(dir: &Path) -> PathBuf {
    dir.join(CURSOR_JOURNAL_FILE_NAME)
}
fn cursor_journal_open_options(create_new: bool) -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    options.read(true).append(true).create_new(create_new);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        options
            // The store owns the only writer and keeps this handle for its complete lifetime.
            // Readers may inspect the journal, but replacement and competing mutation are denied.
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options
}
fn create_cursor_journal(path: &Path) -> eyre::Result<File> {
    let file = cursor_journal_open_options(true)
        .open(path)
        .wrap_err_with(|| {
            format!(
                "failed to create DA replay cursor journal at {}",
                path.display()
            )
        })?;
    validate_open_cursor_journal(path, &file)?;
    file.sync_all().wrap_err_with(|| {
        format!(
            "failed to sync new DA replay cursor journal at {}",
            path.display()
        )
    })?;
    validate_open_cursor_journal(path, &file)?;
    if let Some(parent) = path.parent() {
        sync_dir(parent).wrap_err_with(|| {
            format!(
                "failed to sync DA replay cursor directory after journal creation at {}",
                parent.display()
            )
        })?;
    }
    validate_open_cursor_journal(path, &file)?;
    Ok(file)
}
fn open_cursor_journal(path: &Path, valid_bytes: u64, had_torn_tail: bool) -> eyre::Result<File> {
    let mut file = match cursor_journal_open_options(false).open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => return create_cursor_journal(path),
        Err(err) => {
            return Err(eyre!(err)).wrap_err_with(|| {
                format!(
                    "failed to open DA replay cursor journal at {}",
                    path.display()
                )
            });
        }
    };
    validate_open_cursor_journal(path, &file)?;
    if had_torn_tail {
        file.set_len(valid_bytes).wrap_err_with(|| {
            format!(
                "failed to truncate torn DA replay cursor journal tail at {}",
                path.display()
            )
        })?;
        file.seek(SeekFrom::Start(valid_bytes)).wrap_err_with(|| {
            format!(
                "failed to seek recovered DA replay cursor journal at {}",
                path.display()
            )
        })?;
        file.sync_all().wrap_err_with(|| {
            format!(
                "failed to sync recovered DA replay cursor journal at {}",
                path.display()
            )
        })?;
        if let Some(parent) = path.parent() {
            sync_dir(parent).wrap_err_with(|| {
                format!(
                    "failed to sync DA replay cursor directory after journal recovery at {}",
                    parent.display()
                )
            })?;
        }
        validate_open_cursor_journal(path, &file)?;
    }
    Ok(file)
}
fn validate_open_cursor_journal(path: &Path, file: &File) -> eyre::Result<()> {
    let path_metadata = secure_file_metadata::from_path(path).wrap_err_with(|| {
        format!(
            "failed to inspect DA replay cursor journal at {}",
            path.display()
        )
    })?;
    if !secure_file_metadata::is_direct_file(&path_metadata)
        || secure_file_metadata::number_of_links(&path_metadata) != Some(1)
    {
        return Err(eyre!(
            "DA replay cursor journal {} is not a direct single-link regular file",
            path.display()
        ));
    }
    let file_metadata = secure_file_metadata::from_file(file).wrap_err_with(|| {
        format!(
            "failed to inspect open DA replay cursor journal at {}",
            path.display()
        )
    })?;
    if !secure_file_metadata::is_direct_file(&file_metadata)
        || secure_file_metadata::number_of_links(&file_metadata) != Some(1)
        || file_metadata.len() != path_metadata.len()
        || !secure_file_metadata::same_file(&path_metadata, &file_metadata)
        || !secure_file_metadata::unchanged(&path_metadata, &file_metadata)
    {
        return Err(eyre!(
            "DA replay cursor journal {} changed while open",
            path.display()
        ));
    }
    Ok(())
}
fn append_cursor_journal_record(
    dir: &Path,
    max_lane_epochs: NonZeroUsize,
    state: &mut ReplayCursorState,
    record: &CursorJournalRecord,
) -> eyre::Result<()> {
    validate_replay_cursor_dir_no_follow(dir).wrap_err_with(|| {
        format!(
            "failed to inspect DA replay journal directory at {}",
            dir.display()
        )
    })?;
    let journal_path = replay_cursor_journal_path(dir);
    let journal = state
        .journal
        .as_mut()
        .ok_or_else(|| eyre!("DA replay cursor journal handle is missing"))?;
    validate_open_cursor_journal(&journal_path, journal)?;
    let frame = encode_cursor_journal_frame(record)?;
    let current_len = journal
        .metadata()
        .wrap_err("failed to inspect DA replay cursor journal length")?
        .len();
    let appended_len = current_len
        .checked_add(
            u64::try_from(frame.len())
                .map_err(|_| eyre!("DA replay cursor journal frame length exceeds u64"))?,
        )
        .ok_or_else(|| eyre!("DA replay cursor journal length overflowed"))?;
    let max_len = max_cursor_journal_bytes(max_lane_epochs)?;
    if appended_len > max_len {
        return Err(eyre!(
            "DA replay cursor journal would exceed bounded maximum {max_len} bytes"
        ));
    }
    journal
        .write_all(&frame)
        .wrap_err("failed to append DA replay cursor journal entry")?;
    journal
        .sync_all()
        .wrap_err("failed to sync DA replay cursor journal entry")?;
    validate_open_cursor_journal(&journal_path, journal)?;
    Ok(())
}
fn create_replay_cursor_dir_no_follow(path: &Path) -> eyre::Result<()> {
    fs::create_dir_all(path)?;
    validate_replay_cursor_dir_no_follow(path)
}
fn validate_replay_cursor_dir_no_follow(path: &Path) -> eyre::Result<()> {
    let metadata = secure_file_metadata::from_path(path)?;
    validate_replay_cursor_dir_metadata(path, &metadata)
}
fn validate_replay_cursor_dir_metadata(
    path: &Path,
    metadata: &secure_file_metadata::SecureMetadata,
) -> eyre::Result<()> {
    if !secure_file_metadata::is_direct_directory(metadata) {
        return Err(eyre!(
            "DA replay directory at {} is not a direct directory",
            path.display()
        ));
    }
    Ok(())
}
pub(super) fn replay_cursor_temp_path(path: &Path) -> PathBuf {
    path.with_added_extension("tmp")
}
fn sync_dir(path: &Path) -> std::io::Result<()> {
    crate::durable_fs::sync_direct_directory(path)
}
fn read_cursor_snapshot(
    path: &Path,
    max_lane_epochs: NonZeroUsize,
) -> eyre::Result<Option<CursorSnapshot>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(eyre!(err)).wrap_err_with(|| {
                format!("failed to inspect DA replay snapshot at {}", path.display())
            });
        }
    };
    if !metadata.file_type().is_file() {
        return Err(eyre!(
            "DA replay snapshot {} is not a regular file",
            path.display()
        ));
    }
    let max_bytes = max_cursor_snapshot_bytes(max_lane_epochs)?;
    if metadata.len() > max_bytes {
        return Err(eyre!(
            "DA replay snapshot {} is {} bytes, exceeding bounded maximum {}",
            path.display(),
            metadata.len(),
            max_bytes
        ));
    }
    let max_bytes = usize::try_from(max_bytes)
        .map_err(|_| eyre!("DA replay cursor snapshot bound does not fit usize"))?;
    let data = read_regular_spool_artifact(path, "DA replay cursor snapshot", max_bytes)
        .wrap_err_with(|| format!("failed to read DA replay snapshot at {}", path.display()))?;
    let snapshot: CursorSnapshot = json::from_slice(&data)
        .wrap_err_with(|| format!("failed to decode DA replay snapshot at {}", path.display()))?;
    validate_cursor_snapshot(path, &snapshot, max_lane_epochs)?;
    Ok(Some(snapshot))
}
fn validate_cursor_snapshot(
    path: &Path,
    snapshot: &CursorSnapshot,
    max_lane_epochs: NonZeroUsize,
) -> eyre::Result<()> {
    if snapshot.version != CURSOR_SNAPSHOT_VERSION {
        return Err(eyre!(
            "unsupported DA replay snapshot version {} at {}",
            snapshot.version,
            path.display()
        ));
    }
    if snapshot.entries.len() > max_lane_epochs.get() {
        return Err(eyre!(
            "DA replay snapshot at {} contains {} lane/epoch cursors, exceeding configured maximum {}",
            path.display(),
            snapshot.entries.len(),
            max_lane_epochs
        ));
    }
    let mut seen = BTreeMap::new();
    for entry in &snapshot.entries {
        let lane_epoch = LaneEpoch::new(LaneId::from(entry.lane_id), entry.epoch);
        if seen.insert(lane_epoch, entry.highest_sequence).is_some() {
            return Err(eyre!(
                "duplicate DA replay cursor entry for lane {} epoch {} at {}",
                entry.lane_id,
                entry.epoch,
                path.display()
            ));
        }
    }
    Ok(())
}
fn compare_cursor_snapshots(
    current: &CursorSnapshot,
    candidate: &CursorSnapshot,
) -> CursorSnapshotRelation {
    let current_entries = cursor_snapshot_map(current);
    let candidate_entries = cursor_snapshot_map(candidate);
    let mut ahead = false;
    let mut behind = false;
    for key in current_entries.keys().chain(candidate_entries.keys()) {
        match (current_entries.get(key), candidate_entries.get(key)) {
            (Some(current), Some(candidate)) if candidate > current => ahead = true,
            (Some(current), Some(candidate)) if candidate < current => behind = true,
            (None, Some(_)) => ahead = true,
            (Some(_), None) => behind = true,
            _ => {}
        }
        if ahead && behind {
            return CursorSnapshotRelation::Conflicting;
        }
    }
    match (ahead, behind) {
        (false, false) => CursorSnapshotRelation::Equal,
        (true, false) => CursorSnapshotRelation::CandidateAhead,
        (false, true) => CursorSnapshotRelation::CandidateBehind,
        (true, true) => CursorSnapshotRelation::Conflicting,
    }
}
fn cursor_snapshot_map(snapshot: &CursorSnapshot) -> BTreeMap<LaneEpoch, u64> {
    let mut entries = BTreeMap::new();
    for entry in &snapshot.entries {
        let key = LaneEpoch::new(LaneId::from(entry.lane_id), entry.epoch);
        entries
            .entry(key)
            .and_modify(|current| {
                if entry.highest_sequence > *current {
                    *current = entry.highest_sequence;
                }
            })
            .or_insert(entry.highest_sequence);
    }
    entries
}
fn remove_replay_cursor_temp(tmp_path: &Path) -> eyre::Result<()> {
    match fs::remove_file(tmp_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(eyre!(err)).wrap_err_with(|| {
            format!(
                "failed to remove DA replay cursor temp snapshot {}",
                tmp_path.display()
            )
        }),
    }
}
fn promote_replay_cursor_temp(tmp_path: &Path, file_path: &Path) -> eyre::Result<()> {
    match fs::rename(tmp_path, file_path) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            fs::remove_file(file_path).wrap_err_with(|| {
                format!(
                    "failed to remove DA replay cursor snapshot before promoting temp {}",
                    file_path.display()
                )
            })?;
            fs::rename(tmp_path, file_path).wrap_err_with(|| {
                format!(
                    "failed to promote DA replay cursor temp snapshot {} after removal",
                    tmp_path.display()
                )
            })?;
        }
        Err(err) => {
            return Err(eyre!(err)).wrap_err_with(|| {
                format!(
                    "failed to promote DA replay cursor temp snapshot {} into {}",
                    tmp_path.display(),
                    file_path.display()
                )
            });
        }
    }
    if let Some(parent) = file_path.parent() {
        if !parent.as_os_str().is_empty() {
            sync_dir(parent).wrap_err_with(|| {
                format!(
                    "failed to sync DA replay cursor directory after temp promotion at {}",
                    parent.display()
                )
            })?;
        }
    }
    Ok(())
}
/// Receipt entry captured in the durable receipt log.
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct DaReceiptLogEntry {
    /// Sequence number scoped to the lane/epoch.
    pub sequence: u64,
    /// Manifest hash referenced by the receipt.
    pub manifest_hash: BlobDigest,
}
#[derive(
    Clone,
    Debug,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii::da::persistence::DaReceiptSigningPayload")]
struct DaReceiptSigningPayload {
    version: u16,
    sequence: u64,
    receipt: DaIngestReceipt,
}
fn archive_receipts_outside_allow_set(
    dir: &Path,
    retain: &impl Fn(LaneEpoch) -> bool,
) -> eyre::Result<BTreeSet<LaneEpoch>> {
    if dir.as_os_str().is_empty() {
        return Ok(BTreeSet::new());
    }
    let archive_dir = dir.join(RETIRED_RECEIPT_DIR_NAME);
    create_spool_dir_no_follow(&archive_dir).wrap_err_with(|| {
        format!(
            "failed to create retired DA receipt archive {}",
            archive_dir.display()
        )
    })?;
    let mut linked = Vec::new();
    let mut retired = BTreeSet::new();
    let Some(entries) = open_spool_dir_no_follow(dir)? else {
        return Ok(retired);
    };
    for entry in entries {
        let entry = entry?;
        let source = entry.path();
        if !artifact_path_matches(&source, RECEIPT_FILE_PREFIX)? {
            continue;
        }
        if !fs::symlink_metadata(&source)?.file_type().is_file() {
            return Err(eyre!(
                "durable DA receipt {} is not a regular file",
                source.display()
            ));
        }
        let key = parse_receipt_file_key(&source).wrap_err_with(|| {
            format!(
                "failed to parse durable DA receipt filename {} before retirement",
                source.display()
            )
        })?;
        let lane_epoch = LaneEpoch::new(key.lane_id, key.epoch);
        if retain(lane_epoch) {
            continue;
        }
        let file_name = source
            .file_name()
            .ok_or_else(|| eyre!("retired DA receipt path has no file name"))?;
        let destination = archive_dir.join(file_name);
        match fs::hard_link(&source, &destination) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                let source_bytes = read_linked_retirement_artifact(
                    &source,
                    "retired DA receipt source",
                    DA_RECEIPT_ARTIFACT_MAX_BYTES_V1,
                )?;
                let archived_bytes = read_linked_retirement_artifact(
                    &destination,
                    "retired DA receipt archive",
                    DA_RECEIPT_ARTIFACT_MAX_BYTES_V1,
                )?;
                if source_bytes != archived_bytes {
                    return Err(eyre!(
                        "retired DA receipt archive collision at {}",
                        destination.display()
                    ));
                }
            }
            Err(error) => {
                return Err(eyre!(error)).wrap_err_with(|| {
                    format!(
                        "failed to durably link retired DA receipt {} into {}",
                        source.display(),
                        destination.display()
                    )
                });
            }
        }
        linked.push(source);
        retired.insert(lane_epoch);
    }
    if linked.is_empty() {
        return Ok(retired);
    }
    sync_dir(&archive_dir).wrap_err_with(|| {
        format!(
            "failed to sync retired DA receipt archive {}",
            archive_dir.display()
        )
    })?;
    for source in linked {
        fs::remove_file(&source).wrap_err_with(|| {
            format!(
                "failed to remove active-prefix retired DA receipt {}",
                source.display()
            )
        })?;
    }
    sync_dir(dir).wrap_err_with(|| {
        format!(
            "failed to sync DA receipt directory {} after retirement",
            dir.display()
        )
    })?;
    Ok(retired)
}
/// Outcome returned after attempting to insert a receipt into the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptInsertOutcome {
    /// Receipt stored successfully.
    Stored {
        /// Whether the per-lane cursor advanced.
        cursor_advanced: bool,
    },
    /// Receipt was already present on disk.
    Duplicate {
        /// Path of the existing receipt file.
        path: PathBuf,
    },
    /// The same signed receipt body appeared under a different replay fingerprint.
    DuplicateFingerprintConflict {
        /// Path of the existing receipt file.
        path: PathBuf,
        /// Replay fingerprint first recorded for the receipt.
        expected: ReplayFingerprint,
        /// Replay fingerprint observed on the duplicate append.
        observed: ReplayFingerprint,
    },
    /// Receipt reused a sequence number with a different manifest hash.
    ManifestConflict {
        /// Manifest hash already recorded.
        expected: BlobDigest,
        /// Manifest hash observed in the new receipt.
        observed: BlobDigest,
    },
    /// Receipt reused a sequence number with different signed receipt evidence.
    ReceiptConflict {
        /// Path of the existing receipt file.
        path: PathBuf,
    },
    /// Sequence regressed relative to the latest stored entry.
    StaleSequence {
        /// Highest sequence currently recorded for the lane/epoch.
        highest: u64,
    },
    /// Sequence skipped over the next required slot, including sequence zero for a fresh
    /// lane/epoch.
    SequenceGap {
        /// Next sequence expected by the durable receipt log.
        expected_next: u64,
        /// Sequence supplied by the caller.
        observed: u64,
    },
}
#[derive(Clone)]
struct ReceiptHead {
    sequence: u64,
    manifest_hash: BlobDigest,
    fingerprint: ReplayFingerprint,
    path: PathBuf,
    receipt_digest: [u8; blake3::OUT_LEN],
}
type ReceiptIndex = BTreeMap<LaneEpoch, ReceiptHead>;
struct ReceiptScanSummary {
    count: u64,
    minimum_sequence: u64,
    maximum_sequence: u64,
    sequence_digest_xor: [u8; blake3::OUT_LEN],
    head: ReceiptHead,
}
impl ReceiptScanSummary {
    fn new(sequence: u64, head: ReceiptHead) -> Self {
        Self {
            count: 1,
            minimum_sequence: sequence,
            maximum_sequence: sequence,
            sequence_digest_xor: receipt_sequence_digest(sequence),
            head,
        }
    }
    fn observe(&mut self, sequence: u64, head: ReceiptHead) -> eyre::Result<()> {
        if sequence == self.head.sequence {
            if head.manifest_hash != self.head.manifest_hash {
                return Err(eyre!(
                    "conflicting receipt for sequence {sequence} at {} and {}",
                    self.head.path.display(),
                    head.path.display()
                ));
            }
            if head.receipt_digest != self.head.receipt_digest {
                return Err(eyre!(
                    "conflicting duplicate DA receipt for sequence {sequence} at {} and {}",
                    self.head.path.display(),
                    head.path.display()
                ));
            }
            if head.fingerprint != self.head.fingerprint {
                return Err(eyre!(
                    "duplicate DA receipt fingerprint conflict for sequence {sequence} at {} and {}",
                    self.head.path.display(),
                    head.path.display()
                ));
            }
            return Err(eyre!(
                "duplicate DA receipt path for sequence {sequence} at {} and {}",
                self.head.path.display(),
                head.path.display()
            ));
        }
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| eyre!("durable DA receipt count overflowed u64"))?;
        self.minimum_sequence = self.minimum_sequence.min(sequence);
        self.maximum_sequence = self.maximum_sequence.max(sequence);
        xor_digest(
            &mut self.sequence_digest_xor,
            receipt_sequence_digest(sequence),
        );
        if sequence > self.head.sequence {
            self.head = head;
        }
        Ok(())
    }
    fn validate_contiguous(&self, lane_epoch: LaneEpoch) -> eyre::Result<()> {
        if self.minimum_sequence != 0 {
            return Err(eyre!(
                "durable DA receipt sequence for lane {:?} starts at {}; expected 0",
                lane_epoch,
                self.minimum_sequence
            ));
        }
        let expected_count = self
            .maximum_sequence
            .checked_sub(self.minimum_sequence)
            .and_then(|distance| distance.checked_add(1))
            .ok_or_else(|| {
                eyre!(
                    "DA receipt sequence range overflowed for lane {:?}",
                    lane_epoch
                )
            })?;
        if self.count != expected_count {
            return Err(eyre!(
                "missing DA receipt sequence for lane {:?}: {} files cover {}..={}",
                lane_epoch,
                self.count,
                self.minimum_sequence,
                self.maximum_sequence
            ));
        }
        let mut expected_digest = [0_u8; blake3::OUT_LEN];
        for sequence in self.minimum_sequence..=self.maximum_sequence {
            xor_digest(&mut expected_digest, receipt_sequence_digest(sequence));
        }
        if expected_digest != self.sequence_digest_xor {
            return Err(eyre!(
                "duplicate or missing DA receipt sequence in lane {:?}",
                lane_epoch
            ));
        }
        Ok(())
    }
}
fn receipt_sequence_digest(sequence: u64) -> [u8; blake3::OUT_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iroha.da.receipt.sequence.v1\0");
    hasher.update(&sequence.to_be_bytes());
    *hasher.finalize().as_bytes()
}
fn xor_digest(target: &mut [u8; blake3::OUT_LEN], value: [u8; blake3::OUT_LEN]) {
    for (target, value) in target.iter_mut().zip(value) {
        *target ^= value;
    }
}
pub(super) fn unsigned_receipt_bytes(
    receipt: &DaIngestReceipt,
    sequence: u64,
) -> eyre::Result<Vec<u8>> {
    let mut unsigned = receipt.clone();
    unsigned.operator_signature = receipt_signature_placeholder();
    to_bytes(&DaReceiptSigningPayload {
        version: RECEIPT_SIGNING_PAYLOAD_VERSION,
        sequence,
        receipt: unsigned,
    })
    .map_err(|err| eyre!(err))
}
fn verify_receipt_signature(
    receipt: &DaIngestReceipt,
    sequence: u64,
    signer_public_key: &PublicKey,
) -> eyre::Result<()> {
    let unsigned_bytes = unsigned_receipt_bytes(receipt, sequence)?;
    match signer_public_key.try_algorithm() {
        Ok(Algorithm::Ed25519) => {
            iroha_crypto::ed25519_parse_signature(receipt.operator_signature.payload())
                .map_err(|err| eyre!("DA receipt signature material is malformed: {err}"))?;
        }
        Ok(Algorithm::MlDsa) => {
            iroha_crypto::mldsa65_parse_signature(receipt.operator_signature.payload())
                .map_err(|err| eyre!("DA receipt signature material is malformed: {err}"))?;
        }
        _ => {}
    }
    receipt
        .operator_signature
        .verify(signer_public_key, &unsigned_bytes)
        .map_err(|err| eyre!(err))
}
fn validate_receipt_resource_bounds(receipt: &DaIngestReceipt) -> eyre::Result<()> {
    if receipt
        .pdp_commitment
        .as_ref()
        .is_some_and(|commitment| commitment.len() > PDP_COMMITMENT_MAX_CANONICAL_BYTES_V1)
    {
        return Err(eyre!(
            "DA receipt PDP commitment exceeds the first-release {}-byte limit",
            PDP_COMMITMENT_MAX_CANONICAL_BYTES_V1
        ));
    }
    if receipt.operator_signature.payload().len() > DA_RECEIPT_SIGNATURE_MAX_BYTES_V1 {
        return Err(eyre!(
            "DA receipt signature exceeds the first-release {}-byte limit",
            DA_RECEIPT_SIGNATURE_MAX_BYTES_V1
        ));
    }
    Ok(())
}
/// Durable log of DA ingest receipts keyed by `(lane, epoch, sequence)`.
#[derive(Clone)]
pub struct DaReceiptLog {
    dir: PathBuf,
    cursor_store: Arc<ReplayCursorStore>,
    signer_public_key: PublicKey,
    // Spool actions are deliberately caught at the worker boundary. A non-poisoning mutex keeps a
    // caught panic from permanently disabling the receipt log and serializes durable appends. The
    // map contains exactly one compact high-water record per bounded lane/epoch; historical receipt
    // payloads are loaded directly from their deterministic paths instead of accumulating here.
    index: Arc<NonPoisoningMutex<ReceiptIndex>>,
}
impl DaReceiptLog {
    /// Open (or create) a receipt log rooted at `dir`.
    pub fn open(
        dir: PathBuf,
        cursor_store: Arc<ReplayCursorStore>,
        signer_public_key: PublicKey,
    ) -> eyre::Result<Self> {
        Self::open_with_lane_epoch_filter(dir, cursor_store, signer_public_key, |_| true)
    }
    /// Open a receipt log while retiring excluded lane/epoch windows.
    ///
    /// Excluded receipt files are durably moved out of the active filename
    /// namespace before the cursor checkpoint is pruned. This ordering makes a
    /// crash retryable and prevents a later restart from resurrecting capacity.
    pub(crate) fn open_with_lane_epoch_filter(
        dir: PathBuf,
        cursor_store: Arc<ReplayCursorStore>,
        signer_public_key: PublicKey,
        retain: impl Fn(LaneEpoch) -> bool,
    ) -> eyre::Result<Self> {
        if dir.as_os_str().is_empty() {
            return Err(eyre!("receipt log directory must not be empty"));
        }
        create_spool_dir_no_follow(&dir)
            .wrap_err_with(|| format!("failed to create DA receipt directory {}", dir.display()))?;
        archive_receipts_outside_allow_set(&dir, &retain)?;
        cursor_store.retain_lane_epochs(&retain)?;
        let index = Self::load_existing(
            &dir,
            &signer_public_key,
            cursor_store.max_lane_epochs(),
            &retain,
        )?;
        let mut known_lane_epochs = BTreeSet::new();
        for (lane_epoch, _) in cursor_store.highest_sequences() {
            known_lane_epochs.insert(lane_epoch);
        }
        for lane_epoch in index.keys().copied() {
            if !known_lane_epochs.contains(&lane_epoch)
                && known_lane_epochs.len() >= cursor_store.max_lane_epochs().get()
            {
                return Err(eyre!(
                    "durable DA receipt log and replay cursor contain more than {} lane/epoch windows",
                    cursor_store.max_lane_epochs()
                ));
            }
            known_lane_epochs.insert(lane_epoch);
        }
        for (lane_epoch, head) in &index {
            cursor_store
                .record(*lane_epoch, head.sequence)
                .wrap_err_with(|| {
                    format!("failed to seed receipt cursor from disk for {lane_epoch:?}")
                })?;
        }
        Ok(Self {
            dir,
            cursor_store,
            signer_public_key,
            index: Arc::new(NonPoisoningMutex::new(index)),
        })
    }

    /// Reconcile active receipts and cursors with one authoritative allow-set.
    ///
    /// Active-prefix receipt files are archived and directory-synced first,
    /// then the durable cursor checkpoint is pruned, and finally the in-memory
    /// receipt head is removed. Callers may clear returned replay-cache scopes
    /// after this method succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error if archival, directory synchronization, or cursor
    /// checkpointing fails. Partial archival is safe to retry.
    pub(crate) fn retain_lane_epochs(
        &self,
        retain: impl Fn(LaneEpoch) -> bool,
    ) -> eyre::Result<Vec<LaneEpoch>> {
        let mut guard = self.lock_index();
        let mut known = BTreeSet::new();
        known.extend(guard.keys().copied());
        known.extend(
            self.cursor_store
                .highest_sequences()
                .into_iter()
                .map(|(lane_epoch, _)| lane_epoch),
        );
        known.extend(archive_receipts_outside_allow_set(&self.dir, &retain)?);
        let retired = known
            .into_iter()
            .filter(|lane_epoch| !retain(*lane_epoch))
            .collect::<Vec<_>>();
        self.cursor_store.retain_lane_epochs(&retain)?;
        guard.retain(|lane_epoch, _| retain(*lane_epoch));
        Ok(retired)
    }
    /// Construct a non-durable in-memory receipt log.
    ///
    /// This is suitable for tests and diagnostics only. Production startup rejects an unavailable
    /// or unverifiable durable receipt directory instead of exposing a Torii instance whose DA
    /// ingest route can never acknowledge a request.
    pub fn in_memory(cursor_store: Arc<ReplayCursorStore>, signer_public_key: PublicKey) -> Self {
        Self {
            dir: PathBuf::new(),
            cursor_store,
            signer_public_key,
            index: Arc::new(NonPoisoningMutex::new(BTreeMap::new())),
        }
    }
    /// Append a receipt to the log, enforcing a zero origin and contiguous ordering per
    /// lane/epoch.
    pub fn append(
        &self,
        lane_epoch: LaneEpoch,
        sequence: u64,
        receipt: DaIngestReceipt,
        fingerprint: ReplayFingerprint,
    ) -> eyre::Result<ReceiptInsertOutcome> {
        if receipt.lane_id != lane_epoch.lane_id || receipt.epoch != lane_epoch.epoch {
            return Err(eyre!(
                "receipt lane/epoch mismatch: key {lane_epoch:?} vs receipt {}@{}",
                receipt.lane_id.as_u32(),
                receipt.epoch
            ));
        }
        if self.dir.as_os_str().is_empty() {
            return Err(eyre!(
                "DA receipt log is not durable; refusing to acknowledge ingest without a receipt file"
            ));
        }
        validate_receipt_fingerprint(&receipt, &fingerprint)?;
        validate_receipt_resource_bounds(&receipt)?;
        verify_receipt_signature(&receipt, sequence, &self.signer_public_key)
            .wrap_err("DA receipt signature verification failed")?;
        let encoded = encode_stored_da_receipt(&receipt, sequence).map_err(|err| eyre!(err))?;
        let receipt_digest = *blake3::hash(&encoded).as_bytes();
        let manifest_hash = receipt.manifest_hash;
        let mut guard = self.lock_index();
        let has_receipt_head = guard.contains_key(&lane_epoch);
        if let Some(existing) = guard.get(&lane_epoch) {
            if sequence == existing.sequence && existing.receipt_digest == receipt_digest {
                if existing.fingerprint != fingerprint {
                    return Ok(ReceiptInsertOutcome::DuplicateFingerprintConflict {
                        path: existing.path.clone(),
                        expected: existing.fingerprint,
                        observed: fingerprint,
                    });
                }
                return Ok(ReceiptInsertOutcome::Duplicate {
                    path: existing.path.clone(),
                });
            }
            if sequence == existing.sequence && existing.manifest_hash == manifest_hash {
                return Ok(ReceiptInsertOutcome::ReceiptConflict {
                    path: existing.path.clone(),
                });
            }
            if sequence == existing.sequence {
                return Ok(ReceiptInsertOutcome::ManifestConflict {
                    expected: existing.manifest_hash,
                    observed: manifest_hash,
                });
            }
            if sequence < existing.sequence {
                return Ok(ReceiptInsertOutcome::StaleSequence {
                    highest: existing.sequence,
                });
            }
            if let Some(expected_next) = existing.sequence.checked_add(1)
                && sequence != expected_next
            {
                return Ok(ReceiptInsertOutcome::SequenceGap {
                    expected_next,
                    observed: sequence,
                });
            }
        } else if guard.len() >= self.cursor_store.max_lane_epochs().get() {
            return Err(eyre!(
                "DA receipt lane/epoch capacity {} is exhausted",
                self.cursor_store.max_lane_epochs()
            ));
        }
        let cursor_highest = self.cursor_store.highest_sequence(lane_epoch);
        if let Some(highest) = cursor_highest {
            if sequence <= highest {
                return Ok(ReceiptInsertOutcome::StaleSequence { highest });
            }
            if let Some(expected_next) = highest.checked_add(1)
                && sequence != expected_next
            {
                return Ok(ReceiptInsertOutcome::SequenceGap {
                    expected_next,
                    observed: sequence,
                });
            }
        }
        if !has_receipt_head && cursor_highest.is_none() && sequence != 0 {
            return Ok(ReceiptInsertOutcome::SequenceGap {
                expected_next: 0,
                observed: sequence,
            });
        }
        let path = self.write_receipt_file(&receipt, sequence, &fingerprint, &encoded)?;
        self.cursor_store
            .record(lane_epoch, sequence)
            .wrap_err("failed to persist receipt cursor")?;
        guard.insert(
            lane_epoch,
            ReceiptHead {
                sequence,
                manifest_hash,
                fingerprint,
                path: path.clone(),
                receipt_digest,
            },
        );
        Ok(ReceiptInsertOutcome::Stored {
            cursor_advanced: true,
        })
    }
    /// Return a logged durable receipt for an idempotent ingest retry.
    ///
    /// The receipt is reloaded from disk before returning it so duplicate acknowledgements do not
    /// rely on process-local state.
    pub(crate) fn receipt_for_duplicate(
        &self,
        lane_epoch: LaneEpoch,
        sequence: u64,
        fingerprint: ReplayFingerprint,
    ) -> eyre::Result<Option<(PathBuf, DaIngestReceipt)>> {
        if self.dir.as_os_str().is_empty() {
            return Err(eyre!(
                "DA receipt log is not durable; duplicate receipt cannot be recovered from disk"
            ));
        }
        let path = receipt_file_path(&self.dir, lane_epoch, sequence, fingerprint);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        }
        let (receipt_key, stored) = Self::decode_receipt_with_key(&path)
            .wrap_err_with(|| format!("failed to reload durable DA receipt {}", path.display()))?;
        if stored.sequence != sequence
            || stored.receipt.lane_id != lane_epoch.lane_id
            || stored.receipt.epoch != lane_epoch.epoch
            || stored.receipt.storage_ticket.as_bytes() != fingerprint.as_bytes()
        {
            return Err(eyre!(
                "durable DA receipt {} no longer matches its requested lane/epoch/sequence/fingerprint",
                path.display()
            ));
        }
        verify_receipt_signature(&stored.receipt, stored.sequence, &self.signer_public_key)
            .wrap_err_with(|| {
                format!(
                    "failed to verify reloaded durable DA receipt {}",
                    path.display()
                )
            })?;
        validate_receipt_manifest_artifact_if_present(&self.dir, &receipt_key, &stored.receipt)
            .wrap_err_with(|| {
                format!(
                    "failed to validate reloaded durable DA receipt {} against manifest spool",
                    path.display()
                )
            })?;
        let encoded = encode_stored_da_receipt(&stored.receipt, stored.sequence)?;
        let receipt_digest = *blake3::hash(&encoded).as_bytes();
        let manifest_hash = stored.receipt.manifest_hash;
        let mut guard = self.lock_index();
        if let Some(existing) = guard.get(&lane_epoch) {
            if existing.sequence > sequence {
                return Ok(Some((path, stored.receipt)));
            }
            if existing.sequence == sequence {
                if existing.receipt_digest != receipt_digest
                    || existing.manifest_hash != manifest_hash
                    || existing.fingerprint != fingerprint
                    || existing.path != path
                {
                    return Err(eyre!(
                        "durable duplicate DA receipt conflicts with the in-memory receipt head"
                    ));
                }
                self.cursor_store.recover_failed_journal()?;
                self.cursor_store
                    .record(lane_epoch, sequence)
                    .wrap_err("failed to reconcile duplicate DA receipt cursor")?;
                return Ok(Some((path, stored.receipt)));
            }
            let expected_next = existing.sequence.checked_add(1).ok_or_else(|| {
                eyre!("durable DA receipt head sequence cannot advance beyond u64::MAX")
            })?;
            if sequence != expected_next {
                return Err(eyre!(
                    "durable duplicate DA receipt sequence {sequence} skips in-memory head {expected_next}"
                ));
            }
        } else if guard.len() >= self.cursor_store.max_lane_epochs().get() {
            return Err(eyre!(
                "DA receipt lane/epoch capacity {} is exhausted while recovering a duplicate",
                self.cursor_store.max_lane_epochs()
            ));
        }
        self.cursor_store.recover_failed_journal()?;
        match self.cursor_store.highest_sequence(lane_epoch) {
            Some(highest) if highest > sequence => {
                return Err(eyre!(
                    "durable duplicate DA receipt sequence {sequence} is behind cursor {highest} without a matching in-memory head"
                ));
            }
            Some(highest) if highest < sequence => {
                let expected_next = highest.checked_add(1).ok_or_else(|| {
                    eyre!("durable DA receipt cursor cannot advance beyond u64::MAX")
                })?;
                if sequence != expected_next {
                    return Err(eyre!(
                        "durable duplicate DA receipt sequence {sequence} skips cursor {expected_next}"
                    ));
                }
            }
            None if sequence != 0 => {
                return Err(eyre!(
                    "durable duplicate DA receipt sequence {sequence} has no zero-origin cursor"
                ));
            }
            Some(_) | None => {}
        }
        self.cursor_store
            .record(lane_epoch, sequence)
            .wrap_err("failed to reconcile duplicate DA receipt cursor")?;
        guard.insert(
            lane_epoch,
            ReceiptHead {
                sequence,
                manifest_hash,
                fingerprint,
                path: path.clone(),
                receipt_digest,
            },
        );
        Ok(Some((path, stored.receipt)))
    }
    /// Inspect the recovered in-memory head without reading or adopting durable receipts.
    #[cfg(test)]
    pub fn indexed_sequence_for(&self, lane_epoch: LaneEpoch) -> Option<u64> {
        self.lock_index().get(&lane_epoch).map(|head| head.sequence)
    }
    /// Load receipts for a `(lane, epoch)` window in sequence order.
    #[cfg(test)]
    pub fn receipts_for(&self, lane_epoch: LaneEpoch) -> Vec<DaReceiptLogEntry> {
        load_da_receipts(&self.dir)
            .expect("test receipt log must remain readable")
            .into_iter()
            .filter(|stored| {
                stored.receipt.lane_id == lane_epoch.lane_id
                    && stored.receipt.epoch == lane_epoch.epoch
            })
            .map(|stored| DaReceiptLogEntry {
                sequence: stored.sequence,
                manifest_hash: stored.receipt.manifest_hash,
            })
            .collect()
    }
    fn load_existing(
        dir: &Path,
        signer_public_key: &PublicKey,
        max_lane_epochs: NonZeroUsize,
        retain: &impl Fn(LaneEpoch) -> bool,
    ) -> eyre::Result<ReceiptIndex> {
        let mut summaries: BTreeMap<LaneEpoch, ReceiptScanSummary> = BTreeMap::new();
        let Some(dir_entries) = open_spool_dir_no_follow(dir)? else {
            return Ok(BTreeMap::new());
        };
        // Keep a single error while scanning: directory enumeration order must not
        // choose which independently invalid receipt is reported. Recovery publishes
        // no recovered cursor seeding or index until the scan succeeds, and memory remains
        // bounded by the lane/epoch summaries plus this one error.
        let mut first_error: Option<(PathBuf, eyre::Report)> = None;
        for entry in dir_entries {
            let entry = entry?;
            let path = entry.path();
            let outcome = (|| -> eyre::Result<()> {
                if !artifact_path_matches(&path, RECEIPT_FILE_PREFIX)? {
                    return Ok(());
                }
                if !fs::symlink_metadata(&path)?.file_type().is_file() {
                    return Err(eyre!(
                        "durable DA receipt {} is not a regular file",
                        path.display()
                    ));
                }
                let filename_key = parse_receipt_file_key(&path).wrap_err_with(|| {
                    format!(
                        "failed to parse durable DA receipt filename {}",
                        path.display()
                    )
                })?;
                let filename_lane_epoch = LaneEpoch::new(filename_key.lane_id, filename_key.epoch);
                if !retain(filename_lane_epoch) {
                    return Ok(());
                }
                let (receipt_key, stored) =
                    Self::decode_receipt_with_key(&path).wrap_err_with(|| {
                        format!("failed to load durable DA receipt {}", path.display())
                    })?;
                let StoredDaReceipt {
                    sequence, receipt, ..
                } = stored;
                verify_receipt_signature(&receipt, sequence, signer_public_key).wrap_err_with(
                    || format!("failed to verify durable DA receipt {}", path.display()),
                )?;
                validate_receipt_manifest_artifact_if_present(dir, &receipt_key, &receipt)
                    .wrap_err_with(|| {
                        format!(
                            "failed to validate durable DA receipt {} against manifest spool",
                            path.display()
                        )
                    })?;
                let lane_epoch = LaneEpoch::new(receipt.lane_id, receipt.epoch);
                if !summaries.contains_key(&lane_epoch) && summaries.len() >= max_lane_epochs.get()
                {
                    return Err(eyre!(
                        "durable DA receipt log exceeds lane/epoch capacity {}",
                        max_lane_epochs
                    ));
                }
                let encoded =
                    encode_stored_da_receipt(&receipt, sequence).map_err(|err| eyre!(err))?;
                let head = ReceiptHead {
                    sequence,
                    manifest_hash: receipt.manifest_hash,
                    fingerprint: receipt_key.fingerprint,
                    path: path.clone(),
                    receipt_digest: *blake3::hash(&encoded).as_bytes(),
                };
                match summaries.entry(lane_epoch) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(ReceiptScanSummary::new(sequence, head));
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        entry.get_mut().observe(sequence, head)?;
                    }
                }
                Ok(())
            })();
            if let Err(error) = outcome
                && first_error
                    .as_ref()
                    .is_none_or(|(first_path, _)| path < *first_path)
            {
                first_error = Some((path, error));
            }
        }
        if let Some((_, error)) = first_error {
            return Err(error);
        }
        let mut index = BTreeMap::new();
        for (lane_epoch, summary) in summaries {
            summary.validate_contiguous(lane_epoch)?;
            index.insert(lane_epoch, summary.head);
        }
        Ok(index)
    }
    fn lock_index(&self) -> NonPoisoningMutexGuard<'_, ReceiptIndex> {
        self.index.lock()
    }
    fn write_receipt_file(
        &self,
        receipt: &DaIngestReceipt,
        sequence: u64,
        fingerprint: &ReplayFingerprint,
        encoded: &[u8],
    ) -> eyre::Result<PathBuf> {
        if self.dir.as_os_str().is_empty() {
            return Ok(PathBuf::new());
        }
        match persist_encoded_da_receipt(&self.dir, receipt, sequence, fingerprint, encoded) {
            Ok(Some(path)) => Ok(path),
            Ok(None) => Ok(PathBuf::new()),
            Err(err) => Err(err.into()),
        }
    }
    fn decode_receipt_with_key(path: &Path) -> eyre::Result<(ReceiptFileKey, StoredDaReceipt)> {
        let data = read_regular_spool_artifact(
            path,
            "durable DA receipt",
            DA_RECEIPT_ARTIFACT_MAX_BYTES_V1,
        )?;
        let stored = decode_from_bytes::<StoredDaReceipt>(&data).map_err(|err| eyre!(err))?;
        if stored.version != StoredDaReceipt::VERSION {
            return Err(eyre!(
                "unsupported DA receipt version {} (expected {})",
                stored.version,
                StoredDaReceipt::VERSION
            ));
        }
        validate_receipt_resource_bounds(&stored.receipt).wrap_err_with(|| {
            format!(
                "durable DA receipt {} exceeds resource bounds",
                path.display()
            )
        })?;
        let key = validate_receipt_filename(path, &stored)?;
        Ok((key, stored))
    }
}
#[derive(Clone, Copy)]
struct ReceiptFileKey {
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: StorageTicketId,
    fingerprint: ReplayFingerprint,
}
fn receipt_file_path(
    spool_dir: &Path,
    lane_epoch: LaneEpoch,
    sequence: u64,
    fingerprint: ReplayFingerprint,
) -> PathBuf {
    let lane = lane_epoch.lane_id.as_u32();
    let ticket_hex = hex::encode(fingerprint.as_bytes());
    let fingerprint_hex = ticket_hex.as_str();
    spool_dir.join(format!(
        "{RECEIPT_FILE_PREFIX}-{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.norito",
        epoch = lane_epoch.epoch,
    ))
}
fn parse_receipt_file_key(path: &Path) -> eyre::Result<ReceiptFileKey> {
    let name = path
        .file_name()
        .and_then(|raw| raw.to_str())
        .ok_or_else(|| eyre!("receipt filename is not valid UTF-8"))?;
    let rest = name
        .strip_prefix(RECEIPT_FILE_PREFIX)
        .and_then(|name| name.strip_prefix('-'))
        .and_then(|name| name.strip_suffix(".norito"))
        .ok_or_else(|| eyre!("receipt filename does not use the expected prefix/suffix"))?;
    let mut fields = rest.split('-');
    let lane_hex = fields
        .next()
        .ok_or_else(|| eyre!("receipt filename is missing lane id"))?;
    let epoch_hex = fields
        .next()
        .ok_or_else(|| eyre!("receipt filename is missing epoch"))?;
    let sequence_hex = fields
        .next()
        .ok_or_else(|| eyre!("receipt filename is missing sequence"))?;
    let ticket_hex = fields
        .next()
        .ok_or_else(|| eyre!("receipt filename is missing storage ticket"))?;
    let fingerprint_hex = fields
        .next()
        .ok_or_else(|| eyre!("receipt filename is missing fingerprint"))?;
    if fields.next().is_some() {
        return Err(eyre!("receipt filename contains extra fields"));
    }
    let lane_id = parse_fixed_hex_u32(lane_hex, 8)
        .map(LaneId::new)
        .ok_or_else(|| eyre!("receipt filename lane id is not fixed-width hexadecimal u32"))?;
    let epoch = parse_fixed_hex_u64(epoch_hex, 16)
        .ok_or_else(|| eyre!("receipt filename epoch is not fixed-width hexadecimal u64"))?;
    let sequence = parse_fixed_hex_u64(sequence_hex, 16)
        .ok_or_else(|| eyre!("receipt filename sequence is not fixed-width hexadecimal u64"))?;
    let storage_ticket = StorageTicketId::new(
        parse_fixed_hex_32(ticket_hex)
            .ok_or_else(|| eyre!("receipt filename storage ticket is not 32-byte hex"))?,
    );
    let fingerprint = parse_fixed_hex_32(fingerprint_hex)
        .map(ReplayFingerprint::from)
        .ok_or_else(|| eyre!("receipt filename fingerprint is not 32-byte hex"))?;
    Ok(ReceiptFileKey {
        lane_id,
        epoch,
        sequence,
        storage_ticket,
        fingerprint,
    })
}
fn validate_receipt_filename(
    path: &Path,
    stored: &StoredDaReceipt,
) -> eyre::Result<ReceiptFileKey> {
    let key = parse_receipt_file_key(path)?;
    if key.lane_id != stored.receipt.lane_id
        || key.epoch != stored.receipt.epoch
        || key.sequence != stored.sequence
        || key.storage_ticket != stored.receipt.storage_ticket
    {
        return Err(eyre!(
            "receipt filename tuple {:?}/{}:{}/{:?} mismatches body {:?}/{}:{}/{:?}",
            key.lane_id,
            key.epoch,
            key.sequence,
            key.storage_ticket,
            stored.receipt.lane_id,
            stored.receipt.epoch,
            stored.sequence,
            stored.receipt.storage_ticket
        ));
    }
    if key.fingerprint.as_bytes() != stored.receipt.storage_ticket.as_bytes() {
        return Err(eyre!(
            "receipt filename fingerprint {} mismatches body storage ticket {}",
            hex::encode(key.fingerprint.as_bytes()),
            hex::encode(stored.receipt.storage_ticket.as_bytes())
        ));
    }
    Ok(key)
}
fn receipt_fingerprint_from_storage_ticket(receipt: &DaIngestReceipt) -> ReplayFingerprint {
    ReplayFingerprint::from(*receipt.storage_ticket.as_bytes())
}
fn validate_receipt_fingerprint(
    receipt: &DaIngestReceipt,
    fingerprint: &ReplayFingerprint,
) -> eyre::Result<()> {
    let expected = receipt_fingerprint_from_storage_ticket(receipt);
    if expected != *fingerprint {
        return Err(eyre!(
            "DA receipt replay fingerprint {} does not match storage ticket {}",
            hex::encode(fingerprint.as_bytes()),
            hex::encode(receipt.storage_ticket.as_bytes())
        ));
    }
    Ok(())
}
fn validate_receipt_manifest_artifact_if_present(
    spool_dir: &Path,
    receipt_key: &ReceiptFileKey,
    receipt: &DaIngestReceipt,
) -> eyre::Result<()> {
    let manifest = match load_manifest_artifact_from_spool(spool_dir, &receipt_key.storage_ticket) {
        Ok(manifest) => manifest,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    let fingerprint_matches =
        manifest.storage_ticket.as_bytes() == receipt_key.fingerprint.as_bytes();
    if manifest.lane_id != receipt_key.lane_id
        || manifest.epoch != receipt_key.epoch
        || manifest.storage_ticket != receipt_key.storage_ticket
        || !fingerprint_matches
    {
        return Err(eyre!(
            "receipt filename tuple does not match ticket-indexed DA manifest artifact"
        ));
    }
    let manifest_hash = BlobDigest::from_hash(blake3::hash(&manifest.bytes));
    if receipt.manifest_hash != manifest_hash {
        return Err(eyre!(
            "receipt manifest hash does not match ticket-indexed DA manifest artifact"
        ));
    }
    Ok(())
}
fn read_regular_spool_artifact(
    path: &Path,
    artifact: &str,
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    read_regular_spool_artifact_with_link_policy(path, artifact, max_bytes, false)
}
fn read_linked_retirement_artifact(
    path: &Path,
    artifact: &str,
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    read_regular_spool_artifact_with_link_policy(path, artifact, max_bytes, true)
}
fn map_spool_artifact_open_error(
    path: &Path,
    artifact: &str,
    err: std::io::Error,
) -> std::io::Error {
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::ELOOP) {
        return std::io::Error::new(
            ErrorKind::InvalidData,
            format!("{artifact} {} is not a direct regular file", path.display()),
        );
    }
    #[cfg(not(unix))]
    let _ = (path, artifact);
    err
}
fn read_regular_spool_artifact_with_link_policy(
    path: &Path,
    artifact: &str,
    max_bytes: usize,
    allow_multiple_links: bool,
) -> std::io::Result<Vec<u8>> {
    let path_metadata = secure_file_metadata::from_path(path)
        .map_err(|err| map_spool_artifact_open_error(path, artifact, err))?;
    if !secure_file_metadata::is_direct_file(&path_metadata)
        || (!allow_multiple_links
            && secure_file_metadata::number_of_links(&path_metadata) != Some(1))
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("{artifact} {} is not a direct regular file", path.display()),
        ));
    }
    let max_bytes_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    if path_metadata.len() > max_bytes_u64 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "{artifact} {} is {} bytes, exceeding the {max_bytes}-byte limit",
                path.display(),
                path_metadata.len()
            ),
        ));
    }
    #[cfg(windows)]
    let mut file = secure_file_metadata::open_direct_file(path)
        .map_err(|err| map_spool_artifact_open_error(path, artifact, err))?;
    #[cfg(not(windows))]
    let mut file = {
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        options
            .open(path)
            .map_err(|err| map_spool_artifact_open_error(path, artifact, err))?
    };
    let opened_metadata = secure_file_metadata::from_file(&file)?;
    if !secure_file_metadata::is_direct_file(&opened_metadata)
        || opened_metadata.len() != path_metadata.len()
        || !secure_file_metadata::same_file(&path_metadata, &opened_metadata)
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("{artifact} {} changed while it was opened", path.display()),
        ));
    }
    let expected_len = usize::try_from(opened_metadata.len()).map_err(|_| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("{artifact} {} length does not fit usize", path.display()),
        )
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(expected_len).map_err(|_| {
        std::io::Error::new(
            ErrorKind::OutOfMemory,
            format!(
                "failed to reserve {expected_len} bytes for {artifact} {}",
                path.display()
            ),
        )
    })?;
    bytes.resize(expected_len, 0);
    file.read_exact(&mut bytes)?;
    let mut growth_probe = [0_u8; 1];
    if file.read(&mut growth_probe)? != 0 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "{artifact} {} grew beyond its admitted {expected_len}-byte length while reading",
                path.display(),
            ),
        ));
    }
    let final_metadata = secure_file_metadata::from_file(&file)?;
    let named_after = secure_file_metadata::from_path(path)
        .map_err(|err| map_spool_artifact_open_error(path, artifact, err))?;
    if !secure_file_metadata::is_direct_file(&final_metadata)
        || !secure_file_metadata::is_direct_file(&named_after)
        || !secure_file_metadata::unchanged(&opened_metadata, &final_metadata)
        || !secure_file_metadata::unchanged(&final_metadata, &named_after)
        || u64::try_from(bytes.len()).ok() != Some(opened_metadata.len())
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("{artifact} {} changed while reading", path.display()),
        ));
    }
    Ok(bytes)
}
impl ReplayCursorState {
    fn empty() -> Self {
        Self {
            highest: BTreeMap::new(),
            journal: None,
            journal_records: 0,
            checkpoint_pending: false,
            journal_healthy: true,
        }
    }
    fn from_snapshot(snapshot: CursorSnapshot) -> Self {
        let mut state = Self::empty();
        for entry in snapshot.entries {
            let lane_epoch = LaneEpoch::new(LaneId::from(entry.lane_id), entry.epoch);
            state.highest.insert(lane_epoch, entry.highest_sequence);
        }
        state
    }
    fn apply_journal_record(
        &mut self,
        record: CursorJournalRecord,
        max_lane_epochs: NonZeroUsize,
    ) -> eyre::Result<()> {
        let lane_epoch = LaneEpoch::new(LaneId::from(record.lane_id), record.epoch);
        if !self.highest.contains_key(&lane_epoch) && self.highest.len() >= max_lane_epochs.get() {
            return Err(eyre!(
                "DA replay cursor journal exceeds configured lane/epoch capacity {}",
                max_lane_epochs
            ));
        }
        self.highest
            .entry(lane_epoch)
            .and_modify(|highest| *highest = (*highest).max(record.highest_sequence))
            .or_insert(record.highest_sequence);
        Ok(())
    }
    fn to_snapshot(&self) -> CursorSnapshot {
        let mut entries = Vec::with_capacity(self.highest.len());
        for (lane_epoch, highest_sequence) in &self.highest {
            entries.push(CursorEntry {
                lane_id: lane_epoch.lane_id.as_u32(),
                epoch: lane_epoch.epoch,
                highest_sequence: *highest_sequence,
            });
        }
        entries.sort_by_key(|entry| (entry.lane_id, entry.epoch));
        CursorSnapshot {
            version: CURSOR_SNAPSHOT_VERSION,
            entries,
        }
    }
}
fn existing_artifact_path_if_matching(
    target_path: &Path,
    expected: &[u8],
    artifact: &str,
) -> std::io::Result<Option<PathBuf>> {
    let metadata = match fs::symlink_metadata(target_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "{artifact} already exists at {} but is not a regular file",
                target_path.display()
            ),
        ));
    }
    let existing = read_regular_spool_artifact(target_path, artifact, expected.len())?;
    if existing == expected {
        return Ok(Some(target_path.to_path_buf()));
    }
    Err(std::io::Error::new(
        ErrorKind::InvalidData,
        format!(
            "{artifact} already exists at {} with different bytes",
            target_path.display()
        ),
    ))
}
// Publish one existing file without ever exposing a second hard link. Unsupported
// platforms/filesystems fail closed: hard-link publication violates the spool's
// single-link admission rule while the temporary name is still present.
fn rename_artifact_without_overwrite(tmp_path: &Path, target_path: &Path) -> std::io::Result<()> {
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            tmp_path,
            rustix::fs::CWD,
            target_path,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)
    }
    #[cfg(windows)]
    {
        // tempfile's Windows implementation uses MoveFileExW without replacement.
        // Keep cleanup explicit in our caller, including on publication failure.
        let mut temporary = tempfile::TempPath::try_from_path(tmp_path.to_path_buf())?;
        temporary.disable_cleanup(true);
        temporary
            .persist_noclobber(target_path)
            .map_err(|err| err.error)
    }
    #[cfg(not(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        windows
    )))]
    {
        let _ = (tmp_path, target_path);
        Err(std::io::Error::new(
            ErrorKind::Unsupported,
            "atomic no-replace DA artifact publication is unavailable on this platform",
        ))
    }
}
fn install_artifact_without_overwrite(
    tmp_path: &Path,
    target_path: &Path,
    expected: &[u8],
    artifact: &str,
) -> std::io::Result<()> {
    let publication = (|| {
        // Renaming can move directories and linked files; admit only the exact
        // single-link temporary artifact that the production writer just synced.
        let temporary = read_regular_spool_artifact(tmp_path, artifact, expected.len())?;
        if temporary != expected {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "{artifact} temporary file {} has different bytes",
                    tmp_path.display()
                ),
            ));
        }
        rename_artifact_without_overwrite(tmp_path, target_path)
    })();
    match publication {
        Ok(()) => sync_parent_dir(target_path),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            let existing_result =
                existing_artifact_path_if_matching(target_path, expected, artifact).and_then(
                    |existing| {
                        existing.map(|_| ()).ok_or_else(|| {
                            std::io::Error::new(
                                ErrorKind::NotFound,
                                format!(
                                    "{artifact} {} disappeared during publication",
                                    target_path.display()
                                ),
                            )
                        })
                    },
                );
            let remove_result = remove_temp_artifact(tmp_path);
            existing_result?;
            remove_result?;
            sync_parent_dir(target_path)
        }
        Err(err) => {
            remove_temp_artifact(tmp_path)?;
            Err(err)
        }
    }
}
fn write_temp_artifact(tmp_path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(tmp_path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
fn temp_artifact_write_error(tmp_path: &Path, err: std::io::Error) -> std::io::Error {
    if err.kind() == ErrorKind::AlreadyExists {
        return err;
    }
    remove_temp_artifact(tmp_path).err().unwrap_or(err)
}
fn allocate_artifact_temp_counter(counter: &AtomicU64) -> std::io::Result<u64> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| {
            std::io::Error::new(
                ErrorKind::Other,
                "DA artifact temp suffix counter exhausted",
            )
        })
}
fn artifact_temp_suffix() -> std::io::Result<String> {
    let counter = allocate_artifact_temp_counter(&ARTIFACT_TEMP_COUNTER)?;
    Ok(format!("{}-{counter:016x}", std::process::id()))
}
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        sync_dir(parent)?;
    }
    Ok(())
}
fn remove_temp_artifact(tmp_path: &Path) -> std::io::Result<()> {
    match fs::remove_file(tmp_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(std::io::Error::new(
            err.kind(),
            format!(
                "failed to remove DA temp artifact {}: {err}",
                tmp_path.display()
            ),
        )),
    }
}
#[cfg(test)]
mod temp_artifact_tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use tempfile::tempdir;
    fn checked_signature(private_key: &iroha_crypto::PrivateKey, payload: &[u8]) -> Signature {
        Signature::try_new(private_key, payload).expect("test fixture signing should succeed")
    }
    fn checked_random_keypair(context: &str) -> KeyPair {
        KeyPair::try_random()
            .unwrap_or_else(|err| panic!("{context}: checked random key generation failed: {err}"))
    }
    fn checked_ed25519_keypair(context: &str) -> KeyPair {
        KeyPair::try_random_with_algorithm(Algorithm::Ed25519).unwrap_or_else(|err| {
            panic!("{context}: checked Ed25519 random key generation failed: {err}")
        })
    }
    fn checked_mldsa_keypair(context: &str) -> KeyPair {
        KeyPair::try_random_with_algorithm(Algorithm::MlDsa).unwrap_or_else(|err| {
            panic!("{context}: checked ML-DSA random key generation failed: {err}")
        })
    }
    const SMALL_ORDER_ED25519_SIGNATURE_R: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const NONCANONICAL_ED25519_SIGNATURE_R: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    fn signature_with_malformed_ed25519_r(
        signature: &Signature,
        replacement_r: &[u8; 32],
    ) -> Signature {
        let mut payload = signature.payload().to_vec();
        payload[..replacement_r.len()].copy_from_slice(replacement_r);
        Signature::from_bytes(&payload)
    }
    fn panic_while_holding_replay_cursor_store(store: &ReplayCursorStore) {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = store.inner.lock();
            panic!("panic while holding DA replay cursor mutex");
        }));
        assert!(result.is_err(), "replay-cursor panic should be caught");
    }
    fn panic_while_holding_receipt_log(log: &DaReceiptLog) {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = log.index.lock();
            panic!("panic while holding DA receipt log mutex");
        }));
        assert!(result.is_err(), "receipt-log panic should be caught");
    }
    fn test_fingerprint(seed: u8) -> ReplayFingerprint {
        ReplayFingerprint::from([seed; blake3::OUT_LEN])
    }
    fn test_receipt(
        signer: &KeyPair,
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        seed: u8,
    ) -> DaIngestReceipt {
        let mut receipt = DaIngestReceipt {
            client_blob_id: BlobDigest::new([seed; 32]),
            lane_id,
            epoch,
            blob_hash: BlobDigest::new([seed.wrapping_add(1); 32]),
            chunk_root: BlobDigest::new([seed.wrapping_add(2); 32]),
            manifest_hash: BlobDigest::new([seed.wrapping_add(3); 32]),
            storage_ticket: StorageTicketId::new([seed; 32]),
            pdp_commitment: Some(vec![seed]),
            stripe_layout: DaStripeLayout::default(),
            queued_at_unix: 1234,
            rent_quote: DaRentQuote::default(),
            operator_signature: receipt_signature_placeholder(),
        };
        let unsigned = unsigned_receipt_bytes(&receipt, sequence).expect("test receipt encodes");
        receipt.operator_signature = checked_signature(signer.private_key(), &unsigned);
        receipt
    }
    #[test]
    fn unsigned_receipt_bytes_use_checked_nonzero_placeholder_signature() {
        let signer = checked_random_keypair("receipt placeholder");
        let receipt = test_receipt(&signer, LaneId::new(7), 3, 11, 0x42);
        let unsigned = unsigned_receipt_bytes(&receipt, 11).expect("unsigned receipt encodes");
        let payload: DaReceiptSigningPayload =
            decode_from_bytes(&unsigned).expect("unsigned receipt payload decodes");
        crate::frame_test_support::assert_current_frame(
            &payload,
            "iroha_torii::da::persistence::DaReceiptSigningPayload",
        );
        let assignment = DaIngestSignedReceiptAssignmentV1 {
            version: DA_INGEST_SIGNED_RECEIPT_ASSIGNMENT_VERSION,
            request_digest: [0x43; 32],
            lane_id: receipt.lane_id,
            epoch: receipt.epoch,
            sequence: 11,
            operator_public_key: signer.public_key().clone(),
            receipt: receipt.clone(),
        };
        crate::frame_test_support::assert_current_frame(
            &assignment,
            "iroha_torii::da::persistence::DaIngestSignedReceiptAssignmentV1",
        );
        let placeholder = payload.receipt.operator_signature.payload();
        assert_eq!(placeholder, RECEIPT_SIGNATURE_PLACEHOLDER);
        assert!(!placeholder.iter().all(|byte| *byte == 0));
        assert_eq!(placeholder, receipt_signature_placeholder().payload());
    }
    #[test]
    fn da_receipt_log_rejects_malformed_ed25519_signature_r() {
        let dir = tempdir().expect("tempdir");
        let cursor_store =
            Arc::new(ReplayCursorStore::empty(dir.path().join("cursors")).expect("cursor store"));
        let signer = checked_ed25519_keypair("DA receipt malformed signature fixture");
        let log = DaReceiptLog::open(
            dir.path().join("receipts"),
            cursor_store,
            signer.public_key().clone(),
        )
        .expect("receipt log");
        let lane_epoch = LaneEpoch::new(LaneId::new(8), 13);
        let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 0xB2);
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_ED25519_SIGNATURE_R),
            ("noncanonical", NONCANONICAL_ED25519_SIGNATURE_R),
        ] {
            let mut invalid_receipt = receipt.clone();
            invalid_receipt.operator_signature =
                signature_with_malformed_ed25519_r(&receipt.operator_signature, &replacement_r);
            let err = log
                .append(lane_epoch, 1, invalid_receipt, test_fingerprint(0xB2))
                .expect_err("DA receipt log must reject malformed Ed25519 signature R");
            let message = format!("{err:?}");
            assert!(
                message.contains("DA receipt signature verification failed")
                    && message.contains("signature material is malformed"),
                "{label} DA receipt signature R produced unexpected admission error: {message}"
            );
        }
    }
    #[test]
    fn da_receipt_log_rejects_malformed_mldsa_signature_lengths() {
        let dir = tempdir().expect("tempdir");
        let cursor_store =
            Arc::new(ReplayCursorStore::empty(dir.path().join("cursors")).expect("cursor store"));
        let signer = checked_mldsa_keypair("DA receipt malformed ML-DSA signature fixture");
        let log = DaReceiptLog::open(
            dir.path().join("receipts"),
            cursor_store,
            signer.public_key().clone(),
        )
        .expect("receipt log");
        let lane_epoch = LaneEpoch::new(LaneId::new(9), 14);
        let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 0xB3);
        let mut extended = receipt.operator_signature.payload().to_vec();
        extended.push(0);
        for (label, malformed_payload) in [
            (
                "truncated",
                receipt.operator_signature.payload()
                    [..receipt.operator_signature.payload().len() - 1]
                    .to_vec(),
            ),
            ("extended", extended),
        ] {
            let mut invalid_receipt = receipt.clone();
            invalid_receipt.operator_signature = Signature::from_bytes(&malformed_payload);
            let err = log
                .append(lane_epoch, 1, invalid_receipt, test_fingerprint(0xB3))
                .expect_err("DA receipt log must reject malformed ML-DSA signature length");
            let message = format!("{err:?}");
            assert!(
                message.contains("DA receipt signature verification failed")
                    && message.contains("signature material is malformed"),
                "{label} DA receipt ML-DSA signature length produced unexpected admission error: {message}"
            );
        }
    }
    #[test]
    fn da_temp_artifact_cleanup_reports_unremovable_path() {
        let dir = tempdir().expect("tempdir");
        let tmp_path = dir.path().join(".da.tmp");
        fs::create_dir(&tmp_path).expect("block temp cleanup");
        let err = remove_temp_artifact(&tmp_path).expect_err("directory cleanup should fail");
        assert!(
            err.to_string()
                .contains("failed to remove DA temp artifact"),
            "unexpected error: {err}"
        );
        assert!(
            tmp_path.is_dir(),
            "failed cleanup should leave temp path visible for operator repair"
        );
    }
    #[test]
    fn da_temp_artifact_write_rejects_existing_path_without_truncating() {
        let dir = tempdir().expect("tempdir");
        let tmp_path = dir.path().join(".da.tmp");
        fs::write(&tmp_path, b"existing").expect("seed temp artifact");
        let err = write_temp_artifact(&tmp_path, b"replacement")
            .expect_err("existing temp artifact should not be overwritten");
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(&tmp_path).expect("read existing temp artifact"),
            b"existing"
        );
        let err =
            temp_artifact_write_error(&tmp_path, std::io::Error::from(ErrorKind::AlreadyExists));
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(&tmp_path).expect("read existing temp artifact after cleanup helper"),
            b"existing"
        );
    }
    #[cfg(unix)]
    #[test]
    fn da_temp_artifact_write_uses_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().expect("tempdir");
        let tmp_path = dir.path().join(".da.tmp");
        write_temp_artifact(&tmp_path, b"sensitive DA artifact")
            .expect("write owner-only temp artifact");
        let mode = fs::metadata(&tmp_path)
            .expect("inspect temp artifact")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "DA temp artifact must not grant group or world access"
        );
    }
    #[test]
    fn da_temp_artifact_counter_rejects_exhaustion_without_wrapping() {
        let counter = AtomicU64::new(u64::MAX);
        let err =
            allocate_artifact_temp_counter(&counter).expect_err("exhausted counter must reject");
        assert_eq!(err.kind(), ErrorKind::Other);
        assert!(
            err.to_string().contains("temp suffix counter exhausted"),
            "unexpected error: {err}"
        );
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
    #[test]
    fn da_temp_artifact_counter_allocates_pre_exhaustion_suffix_once() {
        let counter = AtomicU64::new(u64::MAX - 1);
        let suffix = allocate_artifact_temp_counter(&counter)
            .expect("last non-exhausted temp counter should allocate");
        assert_eq!(suffix, u64::MAX - 1);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        assert!(
            allocate_artifact_temp_counter(&counter).is_err(),
            "counter must fail closed once exhausted"
        );
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        windows
    ))]
    #[test]
    fn da_artifact_atomic_rename_never_overwrites_and_publishes_one_link() {
        let dir = tempdir().expect("tempdir");
        let tmp_path = dir.path().join(".da.tmp");
        let target_path = dir.path().join("da-target.norito");
        write_temp_artifact(&tmp_path, b"new").expect("temporary artifact");
        fs::write(&target_path, b"existing").expect("existing artifact");
        let err = rename_artifact_without_overwrite(&tmp_path, &target_path)
            .expect_err("atomic publication must not replace an existing path");
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(&target_path).expect("original artifact"),
            b"existing"
        );
        assert_eq!(fs::read(&tmp_path).expect("unpublished artifact"), b"new");

        fs::remove_file(&target_path).expect("remove original fixture");
        rename_artifact_without_overwrite(&tmp_path, &target_path).expect("atomic publication");
        assert!(!tmp_path.exists(), "rename must consume the temporary name");
        let metadata = secure_file_metadata::from_path(&target_path).expect("published metadata");
        assert!(secure_file_metadata::is_direct_file(&metadata));
        assert_eq!(secure_file_metadata::number_of_links(&metadata), Some(1));
        assert_eq!(
            read_regular_spool_artifact(&target_path, "DA artifact", 3).expect("strict read"),
            b"new"
        );
    }
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        windows
    ))]
    #[test]
    fn da_artifact_publication_converges_only_for_identical_bytes() {
        let dir = tempdir().expect("tempdir");
        let target_path = dir.path().join("da-target.norito");
        for suffix in ["first", "duplicate"] {
            let tmp_path = dir.path().join(format!(".da-{suffix}.tmp"));
            write_temp_artifact(&tmp_path, b"expected").expect("temporary artifact");
            install_artifact_without_overwrite(&tmp_path, &target_path, b"expected", "DA artifact")
                .expect("identical publication converges");
            assert!(
                !tmp_path.exists(),
                "publication must remove its temporary name"
            );
            assert_eq!(
                read_regular_spool_artifact(&target_path, "DA artifact", 8).expect("strict read"),
                b"expected"
            );
        }
        let tmp_path = dir.path().join(".da-conflict.tmp");
        write_temp_artifact(&tmp_path, b"conflict").expect("conflicting temporary artifact");
        let err =
            install_artifact_without_overwrite(&tmp_path, &target_path, b"conflict", "DA artifact")
                .expect_err("different content must not replace the published artifact");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(!tmp_path.exists());
        assert_eq!(
            fs::read(&target_path).expect("original artifact"),
            b"expected"
        );

        let tmp_path = dir.path().join(".da-mismatched.tmp");
        let rejected_target = dir.path().join("rejected.norito");
        write_temp_artifact(&tmp_path, b"conflict").expect("mismatched temporary artifact");
        let err = install_artifact_without_overwrite(
            &tmp_path,
            &rejected_target,
            b"expected",
            "DA artifact",
        )
        .expect_err("temporary content must match the intended publication");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(!tmp_path.exists());
        assert!(!rejected_target.exists());
    }
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        windows
    ))]
    #[test]
    fn da_artifact_publication_rejects_hardlinked_source_and_destination() {
        let dir = tempdir().expect("tempdir");
        let target_path = dir.path().join("da-target.norito");
        let target_alias = dir.path().join("external-target-alias");
        let tmp_path = dir.path().join(".da.tmp");
        fs::write(&target_path, b"expected").expect("target artifact");
        fs::hard_link(&target_path, &target_alias).expect("hostile target link");
        write_temp_artifact(&tmp_path, b"expected").expect("temporary artifact");
        let err =
            install_artifact_without_overwrite(&tmp_path, &target_path, b"expected", "DA artifact")
                .expect_err("matching bytes do not authorize a hardlinked destination");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(!tmp_path.exists());
        assert_eq!(
            fs::read(&target_alias).expect("retained target alias"),
            b"expected"
        );

        let rejected_target = dir.path().join("rejected.norito");
        let source_alias = dir.path().join("external-source-alias");
        write_temp_artifact(&tmp_path, b"expected").expect("temporary artifact");
        fs::hard_link(&tmp_path, &source_alias).expect("hostile source link");
        let err = install_artifact_without_overwrite(
            &tmp_path,
            &rejected_target,
            b"expected",
            "DA artifact",
        )
        .expect_err("hardlinked temporary artifact must never be published");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(!tmp_path.exists());
        assert!(!rejected_target.exists());
        assert_eq!(
            fs::read(&source_alias).expect("retained source alias"),
            b"expected"
        );
    }
    #[cfg(unix)]
    #[test]
    fn bounded_spool_reader_rejects_symlinks_with_direct_file_error() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().expect("tempdir");
        let target_path = dir.path().join("target.norito");
        let link_path = dir.path().join("artifact.norito");
        fs::write(&target_path, b"expected").expect("target artifact");
        assert_eq!(
            read_regular_spool_artifact(&target_path, "DA artifact", 8).expect("direct control"),
            b"expected"
        );
        symlink(&target_path, &link_path).expect("hostile artifact symlink");
        let err = read_regular_spool_artifact(&link_path, "DA artifact", 8)
            .expect_err("symbolic link must be rejected without following it");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("not a direct regular file"));
        assert_eq!(
            fs::read(&target_path).expect("unchanged target"),
            b"expected"
        );
    }
    #[test]
    fn da_install_artifact_reports_temp_cleanup_failure_after_link_error() {
        let dir = tempdir().expect("tempdir");
        let tmp_path = dir.path().join(".da.tmp");
        let target_path = dir.path().join("da-target.norito");
        fs::create_dir(&tmp_path).expect("block temp cleanup");
        let err =
            install_artifact_without_overwrite(&tmp_path, &target_path, b"expected", "DA artifact")
                .expect_err("directory temp artifact should fail cleanup");
        assert!(
            err.to_string()
                .contains("failed to remove DA temp artifact"),
            "unexpected error: {err}"
        );
        assert!(
            tmp_path.is_dir(),
            "failed cleanup should leave temp path visible for operator repair"
        );
        assert!(
            !target_path.exists(),
            "failed publication must not create the target artifact"
        );
    }
    #[test]
    fn da_replay_cursor_store_remains_usable_after_caught_action_panic() {
        let store = ReplayCursorStore::in_memory();
        panic_while_holding_replay_cursor_store(&store);
        assert!(
            store.highest_sequences().is_empty(),
            "caught panic must leave the unchanged cursor state readable"
        );
        let lane_epoch = LaneEpoch::new(LaneId::new(3), 9);
        store
            .record(lane_epoch, 42)
            .expect("cursor store remains usable after a caught panic");
        assert_eq!(
            store.highest_sequences(),
            vec![(lane_epoch, 42)],
            "later cursor updates must remain visible"
        );
    }
    #[test]
    fn governed_cursor_retirement_survives_restart() {
        let dir = tempdir().expect("tempdir");
        let cursor_dir = dir.path().join("cursors");
        let retained = LaneEpoch::new(LaneId::new(1), 8);
        let retired = LaneEpoch::new(LaneId::new(1), 7);
        let store = ReplayCursorStore::empty(cursor_dir.clone()).expect("cursor store");
        store.record(retired, 4).expect("record retired cursor");
        store.record(retained, 2).expect("record retained cursor");
        assert_eq!(
            store
                .retain_lane_epochs(|lane_epoch| lane_epoch == retained)
                .expect("retire old cursor"),
            1
        );
        drop(store);

        let reopened = ReplayCursorStore::open(cursor_dir).expect("reopen filtered cursor store");
        assert_eq!(reopened.highest_sequences(), vec![(retained, 2)]);
    }
    #[test]
    fn retired_receipt_window_cannot_repopulate_cursor_on_restart() {
        let dir = tempdir().expect("tempdir");
        let cursor_dir = dir.path().join("cursors");
        let receipt_dir = dir.path().join("receipts");
        let lane_epoch = LaneEpoch::new(LaneId::new(2), 99);
        let signer = checked_ed25519_keypair("retired DA receipt fixture");
        let cursor_store =
            Arc::new(ReplayCursorStore::empty(cursor_dir.clone()).expect("initial cursor store"));
        let log = DaReceiptLog::open(
            receipt_dir.clone(),
            Arc::clone(&cursor_store),
            signer.public_key().clone(),
        )
        .expect("initial receipt log");
        let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, 0xCC);
        assert!(matches!(
            log.append(lane_epoch, 0, receipt, test_fingerprint(0xCC))
                .expect("append retired receipt"),
            ReceiptInsertOutcome::Stored { .. }
        ));
        let active_receipt = receipt_file_path(&receipt_dir, lane_epoch, 0, test_fingerprint(0xCC));
        assert!(active_receipt.exists());
        drop(log);
        drop(cursor_store);

        let cursor_store =
            Arc::new(ReplayCursorStore::open(cursor_dir).expect("reopen populated cursor store"));
        let log = DaReceiptLog::open_with_lane_epoch_filter(
            receipt_dir.clone(),
            Arc::clone(&cursor_store),
            signer.public_key().clone(),
            |_| false,
        )
        .expect("open receipt log with governed retirement filter");
        assert!(log.index.lock().is_empty());
        assert!(cursor_store.highest_sequences().is_empty());
        assert!(!active_receipt.exists());
        assert!(
            receipt_dir
                .join(RETIRED_RECEIPT_DIR_NAME)
                .join(active_receipt.file_name().expect("receipt file name"))
                .exists(),
            "retired receipt must remain in the audit archive"
        );
    }
    #[test]
    fn runtime_receipt_retirement_archives_before_pruning_cursor() {
        let dir = tempdir().expect("tempdir");
        let receipt_dir = dir.path().join("receipts");
        let cursor_store =
            Arc::new(ReplayCursorStore::empty(dir.path().join("cursors")).expect("cursor store"));
        let signer = checked_ed25519_keypair("runtime DA retirement fixture");
        let log = DaReceiptLog::open(
            receipt_dir.clone(),
            Arc::clone(&cursor_store),
            signer.public_key().clone(),
        )
        .expect("receipt log");
        let retained = LaneEpoch::new(LaneId::new(3), 8);
        let retired = LaneEpoch::new(LaneId::new(3), 7);
        for (lane_epoch, marker) in [(retired, 0xC1), (retained, 0xC2)] {
            let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, marker);
            assert!(matches!(
                log.append(lane_epoch, 0, receipt, test_fingerprint(marker))
                    .expect("append receipt"),
                ReceiptInsertOutcome::Stored { .. }
            ));
        }
        let retired_path = receipt_file_path(&receipt_dir, retired, 0, test_fingerprint(0xC1));
        assert_eq!(
            log.retain_lane_epochs(|lane_epoch| lane_epoch == retained)
                .expect("runtime retirement"),
            vec![retired]
        );
        assert_eq!(cursor_store.highest_sequences(), vec![(retained, 0)]);
        assert_eq!(
            log.index.lock().keys().copied().collect::<Vec<_>>(),
            vec![retained]
        );
        assert!(!retired_path.exists());
        assert!(
            receipt_dir
                .join(RETIRED_RECEIPT_DIR_NAME)
                .join(retired_path.file_name().expect("receipt file name"))
                .exists()
        );
    }
    #[test]
    fn da_receipt_log_remains_usable_after_caught_action_panic() {
        let dir = tempdir().expect("tempdir");
        let cursor_store =
            Arc::new(ReplayCursorStore::empty(dir.path().join("cursors")).expect("cursor store"));
        let signer = checked_random_keypair("DA receipt log poison fixture");
        let log = DaReceiptLog::open(
            dir.path().join("receipts"),
            cursor_store,
            signer.public_key().clone(),
        )
        .expect("receipt log");
        let lane_epoch = LaneEpoch::new(LaneId::new(4), 10);
        panic_while_holding_receipt_log(&log);
        assert!(
            log.receipts_for(lane_epoch).is_empty(),
            "caught panic must not fabricate receipt-log entries"
        );
        assert!(
            log.receipt_for_duplicate(lane_epoch, 0, test_fingerprint(0xA1))
                .expect("receipt-log lookup after caught panic")
                .is_none(),
            "empty receipt log must not report a duplicate"
        );
        let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, 0xA1);
        assert!(
            matches!(
                log.append(lane_epoch, 0, receipt.clone(), test_fingerprint(0xA1))
                    .expect("receipt append after caught panic"),
                ReceiptInsertOutcome::Stored { .. }
            ),
            "caught action panic must not permanently disable receipt persistence"
        );
        let (_, recovered) = log
            .receipt_for_duplicate(lane_epoch, 0, test_fingerprint(0xA1))
            .expect("duplicate lookup after recovered append")
            .expect("durable receipt should be recoverable");
        assert_eq!(recovered, receipt);
    }
    fn receipt_head(sequence: u64, seed: u8) -> ReceiptHead {
        ReceiptHead {
            sequence,
            manifest_hash: BlobDigest::new([seed; blake3::OUT_LEN]),
            fingerprint: test_fingerprint(seed),
            path: PathBuf::from(format!("receipt-{sequence}")),
            receipt_digest: [seed.wrapping_add(1); blake3::OUT_LEN],
        }
    }
    #[test]
    fn receipt_scan_summary_is_constant_size_and_rejects_gaps_and_duplicates() {
        let lane_epoch = LaneEpoch::new(LaneId::new(8), 21);
        let mut valid = ReceiptScanSummary::new(0, receipt_head(0, 1));
        valid.observe(1, receipt_head(1, 2)).expect("observe one");
        valid.observe(2, receipt_head(2, 3)).expect("observe two");
        valid
            .validate_contiguous(lane_epoch)
            .expect("contiguous receipt summary");
        assert_eq!(valid.head.sequence, 2);
        let mut corrupt = ReceiptScanSummary::new(0, receipt_head(0, 1));
        assert!(
            corrupt.observe(0, receipt_head(0, 4)).is_err(),
            "duplicate sequence must reject without growing retained state"
        );
        let mut corrupt = ReceiptScanSummary::new(0, receipt_head(0, 1));
        corrupt.observe(2, receipt_head(2, 3)).expect("observe gap");
        assert!(
            corrupt.validate_contiguous(lane_epoch).is_err(),
            "a duplicate must not conceal a missing sequence"
        );
    }
    #[test]
    fn bounded_spool_reader_rejects_oversize_before_reading_body() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("oversize.norito");
        fs::write(&path, [0_u8; 17]).expect("write oversize fixture");
        let err = read_regular_spool_artifact(&path, "test artifact", 16)
            .expect_err("oversize artifact must reject");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeding the 16-byte limit"));
    }
    #[test]
    fn bounded_spool_reader_accepts_the_exact_file_length() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("exact.norito");
        let expected = [0xA5_u8; 16];
        fs::write(&path, expected).expect("write exact fixture");
        let observed = read_regular_spool_artifact(&path, "test artifact", expected.len())
            .expect("read exact-size artifact");
        assert_eq!(observed, expected);
    }
    #[test]
    fn receipt_log_retains_only_one_head_per_lane() {
        let dir = tempdir().expect("tempdir");
        let cursor_store =
            Arc::new(ReplayCursorStore::empty(dir.path().join("cursors")).expect("cursor store"));
        let signer = checked_random_keypair("bounded DA receipt head fixture");
        let log = DaReceiptLog::open(
            dir.path().join("receipts"),
            cursor_store,
            signer.public_key().clone(),
        )
        .expect("receipt log");
        let lane_epoch = LaneEpoch::new(LaneId::new(5), 12);
        for (sequence, seed) in [(0, 0x31), (1, 0x32)] {
            let receipt = test_receipt(
                &signer,
                lane_epoch.lane_id,
                lane_epoch.epoch,
                sequence,
                seed,
            );
            assert!(matches!(
                log.append(lane_epoch, sequence, receipt, test_fingerprint(seed))
                    .expect("append receipt"),
                ReceiptInsertOutcome::Stored { .. }
            ));
        }
        let index = log.lock_index();
        assert_eq!(index.len(), 1);
        assert_eq!(index.get(&lane_epoch).map(|head| head.sequence), Some(1));
    }
}
#[cfg(test)]
pub(super) fn persist_da_receipt(
    spool_dir: &Path,
    receipt: &DaIngestReceipt,
    sequence: u64,
    fingerprint: &ReplayFingerprint,
) -> std::io::Result<Option<PathBuf>> {
    if spool_dir.as_os_str().is_empty() {
        return Ok(None);
    }
    validate_receipt_resource_bounds(receipt)
        .map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err.to_string()))?;
    let encoded = encode_stored_da_receipt(receipt, sequence)?;
    persist_encoded_da_receipt(spool_dir, receipt, sequence, fingerprint, &encoded)
}
fn encode_stored_da_receipt(receipt: &DaIngestReceipt, sequence: u64) -> std::io::Result<Vec<u8>> {
    let encoded = to_bytes(&StoredDaReceipt {
        version: StoredDaReceipt::VERSION,
        sequence,
        receipt: receipt.clone(),
    })
    .map_err(|err| std::io::Error::new(ErrorKind::Other, err))?;
    if encoded.len() > DA_RECEIPT_ARTIFACT_MAX_BYTES_V1 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "DA receipt is {} bytes, exceeding the first-release {}-byte limit",
                encoded.len(),
                DA_RECEIPT_ARTIFACT_MAX_BYTES_V1
            ),
        ));
    }
    Ok(encoded)
}
fn persist_encoded_da_receipt(
    spool_dir: &Path,
    receipt: &DaIngestReceipt,
    sequence: u64,
    fingerprint: &ReplayFingerprint,
    encoded: &[u8],
) -> std::io::Result<Option<PathBuf>> {
    if spool_dir.as_os_str().is_empty() {
        return Ok(None);
    }
    create_spool_dir_no_follow(spool_dir)?;
    if receipt_fingerprint_from_storage_ticket(receipt) != *fingerprint {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "DA receipt replay fingerprint {} does not match storage ticket {}",
                hex::encode(fingerprint.as_bytes()),
                hex::encode(receipt.storage_ticket.as_bytes())
            ),
        ));
    }
    if encoded.len() > DA_RECEIPT_ARTIFACT_MAX_BYTES_V1 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "DA receipt is {} bytes, exceeding the first-release {}-byte limit",
                encoded.len(),
                DA_RECEIPT_ARTIFACT_MAX_BYTES_V1
            ),
        ));
    }
    let lane = receipt.lane_id.as_u32();
    let ticket_hex = hex::encode(receipt.storage_ticket.as_ref());
    let fingerprint_hex = hex::encode(fingerprint.as_bytes());
    let target_path = receipt_file_path(
        spool_dir,
        LaneEpoch::new(receipt.lane_id, receipt.epoch),
        sequence,
        *fingerprint,
    );
    if let Some(path) =
        existing_artifact_path_if_matching(&target_path, encoded, "DA receipt artifact")?
    {
        return Ok(Some(path));
    }
    let tmp_name = format!(
        ".{RECEIPT_FILE_PREFIX}-{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.tmp-{}",
        artifact_temp_suffix()?,
        epoch = receipt.epoch,
    );
    let tmp_path = spool_dir.join(tmp_name);
    match write_temp_artifact(&tmp_path, encoded) {
        Ok(()) => {}
        Err(err) => return Err(temp_artifact_write_error(&tmp_path, err)),
    }
    install_artifact_without_overwrite(&tmp_path, &target_path, encoded, "DA receipt artifact")?;
    debug!(
        path = ?target_path,
        lane = lane,
        epoch = receipt.epoch,
        sequence,
        ticket = %ticket_hex,
        "queued DA ingest receipt for fanout spool"
    );
    Ok(Some(target_path))
}
fn open_spool_dir_no_follow(spool_dir: &Path) -> std::io::Result<Option<fs::ReadDir>> {
    let metadata = match secure_file_metadata::from_path(spool_dir) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(map_spool_dir_open_error(spool_dir, err)),
    };
    validate_spool_dir_metadata(spool_dir, &metadata)?;
    fs::read_dir(spool_dir).map(Some)
}
fn create_spool_dir_no_follow(spool_dir: &Path) -> std::io::Result<()> {
    match secure_file_metadata::from_path(spool_dir) {
        Ok(metadata) => return validate_spool_dir_metadata(spool_dir, &metadata),
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(map_spool_dir_open_error(spool_dir, err)),
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(spool_dir)?;
    let metadata = secure_file_metadata::from_path(spool_dir)
        .map_err(|err| map_spool_dir_open_error(spool_dir, err))?;
    validate_spool_dir_metadata(spool_dir, &metadata)
}
fn map_spool_dir_open_error(spool_dir: &Path, err: std::io::Error) -> std::io::Error {
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::ELOOP) {
        return invalid_spool_dir_type(spool_dir);
    }
    err
}
fn invalid_spool_dir_type(spool_dir: &Path) -> std::io::Error {
    std::io::Error::new(
        ErrorKind::InvalidData,
        format!(
            "DA spool path `{}` is not a direct directory",
            spool_dir.display()
        ),
    )
}
fn validate_spool_dir_metadata(
    spool_dir: &Path,
    metadata: &secure_file_metadata::SecureMetadata,
) -> std::io::Result<()> {
    if !secure_file_metadata::is_direct_directory(metadata) {
        return Err(invalid_spool_dir_type(spool_dir));
    }
    Ok(())
}
pub(super) fn ticket_artifact_dir(spool_dir: &Path, storage_ticket: &StorageTicketId) -> PathBuf {
    let ticket_hex = hex::encode(storage_ticket.as_bytes());
    let shard = format!("{:02x}", storage_ticket.as_bytes()[0]);
    spool_dir
        .join(TICKET_ARTIFACTS_DIR)
        .join(shard)
        .join(ticket_hex)
}
fn create_ticket_artifact_dir(
    spool_dir: &Path,
    storage_ticket: &StorageTicketId,
) -> std::io::Result<PathBuf> {
    create_spool_dir_no_follow(spool_dir)?;
    let artifacts_dir = spool_dir.join(TICKET_ARTIFACTS_DIR);
    create_spool_dir_no_follow(&artifacts_dir)?;
    let shard_dir = artifacts_dir.join(format!("{:02x}", storage_ticket.as_bytes()[0]));
    create_spool_dir_no_follow(&shard_dir)?;
    let ticket_dir = ticket_artifact_dir(spool_dir, storage_ticket);
    create_spool_dir_no_follow(&ticket_dir)?;
    Ok(ticket_dir)
}
fn existing_ticket_artifact_dir(
    spool_dir: &Path,
    storage_ticket: &StorageTicketId,
) -> std::io::Result<Option<PathBuf>> {
    let ticket_dir = ticket_artifact_dir(spool_dir, storage_ticket);
    let artifacts_dir = spool_dir.join(TICKET_ARTIFACTS_DIR);
    let shard_dir = artifacts_dir.join(format!("{:02x}", storage_ticket.as_bytes()[0]));
    for path in [
        spool_dir,
        artifacts_dir.as_path(),
        shard_dir.as_path(),
        ticket_dir.as_path(),
    ] {
        let metadata = match secure_file_metadata::from_path(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(map_spool_dir_open_error(path, err)),
        };
        validate_spool_dir_metadata(path, &metadata)?;
    }
    Ok(Some(ticket_dir))
}
#[cfg(test)]
pub(super) fn load_da_receipts(spool_dir: &Path) -> std::io::Result<Vec<StoredDaReceipt>> {
    if spool_dir.as_os_str().is_empty() {
        return Ok(Vec::new());
    }
    let mut receipts = Vec::new();
    let mut by_key: BTreeMap<(u32, u64, u64), (usize, ReplayFingerprint)> = BTreeMap::new();
    let mut paths = Vec::new();
    let Some(dir_entries) = open_spool_dir_no_follow(spool_dir)? else {
        return Ok(Vec::new());
    };
    for entry in dir_entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = artifact_file_name(&file_name, RECEIPT_FILE_PREFIX)? else {
            continue;
        };
        paths.push((name.to_owned(), entry.path()));
    }
    paths.sort_by(|lhs, rhs| lhs.1.cmp(&rhs.1));
    for (name, path) in paths {
        if !fs::symlink_metadata(&path)?.file_type().is_file() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("DA receipt artifact `{name}` is not a regular file"),
            ));
        }
        let (receipt_key, stored) =
            DaReceiptLog::decode_receipt_with_key(&path).map_err(|err| {
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to load DA receipt {}: {err}", path.display()),
                )
            })?;
        let key = (
            stored.receipt.lane_id.as_u32(),
            stored.receipt.epoch,
            stored.sequence,
        );
        if let Some((existing_idx, existing_fingerprint)) = by_key.get(&key).copied() {
            let existing: &StoredDaReceipt = &receipts[existing_idx];
            if existing.receipt != stored.receipt {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "conflicting duplicate DA receipt for lane {} epoch {} sequence {}",
                        key.0, key.1, key.2
                    ),
                ));
            }
            if existing_fingerprint != receipt_key.fingerprint {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "duplicate DA receipt fingerprint conflict for lane {} epoch {} sequence {}",
                        key.0, key.1, key.2
                    ),
                ));
            }
            continue;
        }
        by_key.insert(key, (receipts.len(), receipt_key.fingerprint));
        receipts.push(stored);
    }
    receipts.sort_by(|lhs, rhs| {
        (
            lhs.receipt.lane_id.as_u32(),
            lhs.receipt.epoch,
            lhs.sequence,
            lhs.receipt.manifest_hash.as_ref(),
        )
            .cmp(&(
                rhs.receipt.lane_id.as_u32(),
                rhs.receipt.epoch,
                rhs.sequence,
                rhs.receipt.manifest_hash.as_ref(),
            ))
    });
    Ok(receipts)
}
#[cfg(test)]
pub(super) fn load_manifest_from_spool(
    spool_dir: &Path,
    ticket: &StorageTicketId,
) -> std::io::Result<Vec<u8>> {
    load_manifest_artifact_from_spool(spool_dir, ticket).map(|artifact| artifact.bytes)
}
pub(super) struct LoadedManifestArtifact {
    pub(super) bytes: Vec<u8>,
    lane_id: LaneId,
    epoch: u64,
    storage_ticket: StorageTicketId,
}
pub(super) fn load_manifest_artifact_from_spool(
    spool_dir: &Path,
    ticket: &StorageTicketId,
) -> std::io::Result<LoadedManifestArtifact> {
    let path = load_ticket_artifact_path(
        spool_dir,
        ticket,
        MANIFEST_ARTIFACT_FILE_NAME,
        "manifest spool directory is not configured",
        "manifest not found for storage ticket",
    )?;
    let bytes = read_regular_spool_artifact(
        &path,
        "DA manifest artifact",
        DA_MANIFEST_ARTIFACT_MAX_BYTES_V1,
    )?;
    let (manifest, _) = decode_manifest_spool_body(&bytes)?;
    if manifest.storage_ticket != *ticket {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "manifest storage ticket does not match its ticket-indexed path",
        ));
    }
    Ok(LoadedManifestArtifact {
        bytes,
        lane_id: manifest.lane_id,
        epoch: manifest.epoch,
        storage_ticket: manifest.storage_ticket,
    })
}
#[cfg(test)]
pub(super) fn load_pdp_commitment_from_spool(
    spool_dir: &Path,
    ticket: &StorageTicketId,
) -> std::io::Result<Vec<u8>> {
    let path = load_ticket_artifact_path(
        spool_dir,
        ticket,
        PDP_COMMITMENT_ARTIFACT_FILE_NAME,
        "PDP spool directory is not configured",
        "PDP commitment not found for storage ticket",
    )?;
    let bytes = read_regular_spool_artifact(
        &path,
        "PDP commitment artifact",
        PDP_COMMITMENT_MAX_CANONICAL_BYTES_V1,
    )?;
    validate_pdp_commitment_spool_body(&bytes)?;
    Ok(bytes)
}
pub(super) fn load_pdp_commitment_for_manifest_artifact(
    spool_dir: &Path,
    manifest: &LoadedManifestArtifact,
    manifest_hash: &BlobDigest,
) -> std::io::Result<Vec<u8>> {
    let path = load_ticket_artifact_path(
        spool_dir,
        &manifest.storage_ticket,
        PDP_COMMITMENT_ARTIFACT_FILE_NAME,
        "PDP spool directory is not configured",
        "PDP commitment not found for manifest artifact",
    )?;
    let bytes = read_regular_spool_artifact(
        &path,
        "PDP commitment artifact",
        PDP_COMMITMENT_MAX_CANONICAL_BYTES_V1,
    )?;
    validate_pdp_commitment_spool_body_for_manifest(&bytes, manifest_hash)?;
    Ok(bytes)
}
pub(super) fn load_da_pin_intent(
    spool_dir: &Path,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> std::io::Result<DaPinIntent> {
    if spool_dir.as_os_str().is_empty() {
        return Err(std::io::Error::new(
            ErrorKind::NotFound,
            "DA pin-intent spool directory is not configured",
        ));
    }
    validate_ticket_fingerprint(storage_ticket, fingerprint).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("invalid DA pin-intent lookup tuple: {err}"),
        )
    })?;
    if open_spool_dir_no_follow(spool_dir)?.is_none() {
        return Err(std::io::Error::new(
            ErrorKind::NotFound,
            "DA pin-intent spool directory does not exist",
        ));
    }
    let path = da_pin_intent_file_path(
        spool_dir,
        lane_id,
        epoch,
        sequence,
        storage_ticket,
        fingerprint,
    );
    let bytes = read_regular_spool_artifact(
        &path,
        "DA pin-intent artifact",
        DA_PIN_INTENT_ARTIFACT_MAX_BYTES_V1,
    )?;
    let intent = decode_from_bytes::<DaPinIntent>(&bytes).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "failed to decode DA pin-intent artifact {}: {err}",
                path.display()
            ),
        )
    })?;
    validate_pin_intent_artifact_inputs(&intent, lane_id, epoch, sequence, storage_ticket)
        .map_err(|err| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "DA pin-intent artifact {} does not match its filename: {err}",
                    path.display()
                ),
            )
        })?;
    Ok(intent)
}
pub(super) fn load_da_pin_scope(
    spool_dir: &Path,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> std::io::Result<DaPinScopeV1> {
    if spool_dir.as_os_str().is_empty() {
        return Err(std::io::Error::new(
            ErrorKind::NotFound,
            "DA pin-scope spool directory is not configured",
        ));
    }
    validate_ticket_fingerprint(storage_ticket, fingerprint).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("invalid DA pin-scope lookup tuple: {err}"),
        )
    })?;
    if open_spool_dir_no_follow(spool_dir)?.is_none() {
        return Err(std::io::Error::new(
            ErrorKind::NotFound,
            "DA pin-scope spool directory does not exist",
        ));
    }
    let path = da_pin_scope_file_path(
        spool_dir,
        lane_id,
        epoch,
        sequence,
        storage_ticket,
        fingerprint,
    );
    let bytes = read_regular_spool_artifact(
        &path,
        "DA pin-scope artifact",
        DA_PIN_SCOPE_ARTIFACT_MAX_BYTES_V1,
    )?;
    let scope = decode_from_bytes::<DaPinScopeV1>(&bytes).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "failed to decode DA pin-scope artifact {}: {err}",
                path.display()
            ),
        )
    })?;
    validate_pin_scope_artifact_inputs(&scope, lane_id, epoch, sequence, storage_ticket).map_err(
        |err| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "DA pin-scope artifact {} does not match its filename: {err}",
                    path.display()
                ),
            )
        },
    )?;
    Ok(scope)
}
fn load_ticket_artifact_path(
    spool_dir: &Path,
    ticket: &StorageTicketId,
    file_name: &str,
    unconfigured_message: &'static str,
    not_found_message: &'static str,
) -> std::io::Result<PathBuf> {
    if spool_dir.as_os_str().is_empty() {
        return Err(std::io::Error::new(
            ErrorKind::NotFound,
            unconfigured_message,
        ));
    }
    let Some(ticket_dir) = existing_ticket_artifact_dir(spool_dir, ticket)? else {
        return Err(std::io::Error::new(ErrorKind::NotFound, not_found_message));
    };
    let path = ticket_dir.join(file_name);
    match fs::symlink_metadata(&path) {
        Ok(_) => Ok(path),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            Err(std::io::Error::new(ErrorKind::NotFound, not_found_message))
        }
        Err(err) => Err(err),
    }
}
fn artifact_path_matches(path: &Path, prefix: &str) -> std::io::Result<bool> {
    let Some(name) = path.file_name() else {
        return Ok(false);
    };
    artifact_file_name(name, prefix).map(|name| name.is_some())
}
fn artifact_file_name<'a>(name: &'a OsStr, prefix: &str) -> std::io::Result<Option<&'a str>> {
    if let Some(name) = name.to_str() {
        return Ok((name.starts_with(prefix) && name.ends_with(".norito")).then_some(name));
    }
    if non_utf8_artifact_name_matches(name, prefix.as_bytes(), b".norito") {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("spool artifact filename with prefix `{prefix}` is not valid UTF-8"),
        ));
    }
    Ok(None)
}
#[cfg(unix)]
fn non_utf8_artifact_name_matches(name: &OsStr, prefix: &[u8], suffix: &[u8]) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let bytes = name.as_bytes();
    bytes.starts_with(prefix) && bytes.ends_with(suffix)
}
#[cfg(not(unix))]
fn non_utf8_artifact_name_matches(_name: &OsStr, _prefix: &[u8], _suffix: &[u8]) -> bool {
    false
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn artifact_file_name_rejects_non_utf8_shaped_names() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        for (prefix, raw_name) in [
            ("manifest-", b"manifest-\xFF.norito".to_vec()),
            ("pdp-commitment-", b"pdp-commitment-\xFF.norito".to_vec()),
            (RECEIPT_FILE_PREFIX, b"da-receipt-\xFF.norito".to_vec()),
        ] {
            let name = OsString::from_vec(raw_name);
            let err = artifact_file_name(name.as_os_str(), prefix)
                .expect_err("non-UTF8 shaped artifact name rejects");
            assert_eq!(err.kind(), ErrorKind::InvalidData);
        }
    }
    #[cfg(unix)]
    #[test]
    fn artifact_file_name_ignores_unrelated_non_utf8_names() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        let name = OsString::from_vec(b"unrelated-\xFF.norito".to_vec());
        assert!(
            artifact_file_name(name.as_os_str(), "manifest-")
                .expect("unrelated non-UTF8 name is ignored")
                .is_none()
        );
    }
}
fn decode_manifest_spool_body(bytes: &[u8]) -> std::io::Result<(DaManifestV1, ReplayFingerprint)> {
    let manifest = decode_from_bytes::<DaManifestV1>(bytes).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("manifest spool body is not a DA manifest: {err}"),
        )
    })?;
    let mut template = manifest.clone();
    template.storage_ticket = StorageTicketId::default();
    template.issued_at_unix = 0;
    let encoded_template = to_bytes(&template).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("failed to encode manifest fingerprint template: {err}"),
        )
    })?;
    let fingerprint = ReplayFingerprint::from_hash(blake3::hash(&encoded_template));
    if manifest.storage_ticket.as_bytes() != fingerprint.as_bytes() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "manifest storage ticket does not match its canonical fingerprint",
        ));
    }
    Ok((manifest, fingerprint))
}
#[cfg(test)]
fn validate_pdp_commitment_spool_body(bytes: &[u8]) -> std::io::Result<()> {
    decode_pdp_commitment_spool_body(bytes).map(|_| ())
}
fn validate_pdp_commitment_spool_body_for_manifest(
    bytes: &[u8],
    manifest_hash: &BlobDigest,
) -> std::io::Result<()> {
    let commitment = decode_pdp_commitment_spool_body(bytes)?;
    if commitment.manifest_digest != *manifest_hash.as_bytes() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "PDP commitment manifest digest does not match DA manifest artifact",
        ));
    }
    Ok(())
}
fn decode_pdp_commitment_spool_body(bytes: &[u8]) -> std::io::Result<PdpCommitmentV1> {
    let commitment = decode_from_bytes::<PdpCommitmentV1>(bytes).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("PDP commitment spool body is not a PDP commitment: {err}"),
        )
    })?;
    commitment.validate().map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("PDP commitment spool body is invalid: {err}"),
        )
    })?;
    Ok(commitment)
}
fn invalid_artifact_input(message: &'static str) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidInput, message)
}
fn validate_manifest_artifact_inputs(
    manifest_bytes: &[u8],
    lane_id: LaneId,
    epoch: u64,
    _sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> std::io::Result<()> {
    let (manifest, observed_fingerprint) =
        decode_manifest_spool_body(manifest_bytes).map_err(|err| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("DA manifest artifact inputs do not match body: {err}"),
            )
        })?;
    if manifest.lane_id != lane_id
        || manifest.epoch != epoch
        || &manifest.storage_ticket != storage_ticket
        || observed_fingerprint != *fingerprint
    {
        return Err(invalid_artifact_input(
            "DA manifest artifact inputs do not match body",
        ));
    }
    Ok(())
}
fn validate_pdp_commitment_artifact_inputs(commitment: &PdpCommitmentV1) -> std::io::Result<()> {
    commitment.validate().map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("PDP commitment artifact body is invalid: {err}"),
        )
    })
}
fn validate_ticket_fingerprint(
    storage_ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> std::io::Result<()> {
    if storage_ticket.as_bytes() != fingerprint.as_bytes() {
        return Err(invalid_artifact_input(
            "DA artifact replay fingerprint does not match storage ticket",
        ));
    }
    Ok(())
}
fn validate_da_commitment_artifact_inputs(
    record: &DaCommitmentRecord,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
) -> std::io::Result<()> {
    if record.lane_id != lane_id
        || record.epoch != epoch
        || record.sequence != sequence
        || &record.storage_ticket != storage_ticket
    {
        return Err(invalid_artifact_input(
            "DA commitment artifact filename tuple does not match record body",
        ));
    }
    Ok(())
}
fn validate_da_schedule_artifact_inputs(
    record: &DaCommitmentRecord,
    pdp_commitment_bytes: &[u8],
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
) -> std::io::Result<()> {
    validate_da_commitment_artifact_inputs(record, lane_id, epoch, sequence, storage_ticket)?;
    let pdp_commitment = decode_pdp_commitment_spool_body(pdp_commitment_bytes).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("DA commitment schedule PDP body is invalid: {err}"),
        )
    })?;
    if pdp_commitment.manifest_digest != *record.manifest_hash.as_bytes() {
        return Err(invalid_artifact_input(
            "DA commitment schedule PDP manifest digest does not match record manifest hash",
        ));
    }
    let pdp_digest = Hash::new(pdp_commitment_bytes);
    if record.proof_digest.as_ref() != Some(&pdp_digest) {
        return Err(invalid_artifact_input(
            "DA commitment schedule PDP bytes do not match record proof digest",
        ));
    }
    Ok(())
}
fn validate_pin_intent_artifact_inputs(
    intent: &DaPinIntent,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
) -> std::io::Result<()> {
    if intent.lane_id != lane_id
        || intent.epoch != epoch
        || intent.sequence != sequence
        || &intent.storage_ticket != storage_ticket
    {
        return Err(invalid_artifact_input(
            "DA pin-intent artifact filename tuple does not match intent body",
        ));
    }
    if intent.authorization.lane_id != intent.lane_id
        || intent.authorization.epoch != intent.epoch
        || intent.authorization.sequence != intent.sequence
    {
        return Err(invalid_artifact_input(
            "DA pin-intent authorization tuple does not match intent body",
        ));
    }
    if !intent.authorization.has_valid_canonical_signatures() {
        return Err(invalid_artifact_input(
            "DA pin-intent authorization signatures are invalid",
        ));
    }
    if !intent
        .pin_scope_authorization
        .scope
        .matches_authorization(&intent.authorization)
        || intent.pin_scope_authorization.scope.storage_ticket != intent.storage_ticket
        || intent.pin_scope_authorization.scope.manifest_hash != intent.manifest_hash
        || intent.pin_scope_authorization.scope.alias != intent.alias
        || !intent
            .pin_scope_authorization
            .has_valid_canonical_signatures()
    {
        return Err(invalid_artifact_input(
            "DA pin-intent scope authorization does not match intent body",
        ));
    }
    Ok(())
}

fn da_pin_intents_have_same_signed_identity(
    existing: &DaPinIntent,
    candidate: &DaPinIntent,
) -> bool {
    let authorization_signers_match = existing
        .authorization
        .signatures
        .iter()
        .map(|signature| &signature.signer)
        .eq(candidate
            .authorization
            .signatures
            .iter()
            .map(|signature| &signature.signer));
    let pin_scope_signers_match = existing
        .pin_scope_authorization
        .signatures
        .iter()
        .map(|signature| &signature.signer)
        .eq(candidate
            .pin_scope_authorization
            .signatures
            .iter()
            .map(|signature| &signature.signer));
    existing.lane_id == candidate.lane_id
        && existing.epoch == candidate.epoch
        && existing.sequence == candidate.sequence
        && existing.storage_ticket == candidate.storage_ticket
        && existing.manifest_hash == candidate.manifest_hash
        && existing.alias == candidate.alias
        && existing.authorization.signing_digest() == candidate.authorization.signing_digest()
        && authorization_signers_match
        && existing.authorization.has_valid_canonical_signatures()
        && candidate.authorization.has_valid_canonical_signatures()
        && existing.pin_scope_authorization.scope == candidate.pin_scope_authorization.scope
        && pin_scope_signers_match
        && existing
            .pin_scope_authorization
            .has_valid_canonical_signatures()
        && candidate
            .pin_scope_authorization
            .has_valid_canonical_signatures()
}

fn da_pin_intent_has_same_request_authorization(
    intent: &DaPinIntent,
    authorization: &DaIngestAuthorizationV1,
) -> bool {
    intent.authorization.signing_digest() == authorization.signing_digest()
        && intent
            .authorization
            .signatures
            .iter()
            .map(|signature| &signature.signer)
            .eq(authorization
                .signatures
                .iter()
                .map(|signature| &signature.signer))
        && intent.authorization.has_valid_canonical_signatures()
        && authorization.has_valid_canonical_signatures()
}

/// Validate that a retry retains the primary signer set frozen into a pin intent.
pub(super) fn validate_da_pin_intent_retry_authorization(
    intent: &DaPinIntent,
    authorization: &DaIngestAuthorizationV1,
) -> std::io::Result<()> {
    if da_pin_intent_has_same_request_authorization(intent, authorization) {
        return Ok(());
    }
    Err(std::io::Error::new(
        ErrorKind::AlreadyExists,
        "DA pin intent replay slot is bound to a different request signer set",
    ))
}

/// Select the first durable semantic pin intent while tolerating randomized signature bytes.
pub(super) fn select_da_pin_intent_for_persistence(
    spool_dir: &Path,
    candidate: &DaPinIntent,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> std::io::Result<DaPinIntent> {
    validate_pin_intent_artifact_inputs(candidate, lane_id, epoch, sequence, storage_ticket)?;
    validate_ticket_fingerprint(storage_ticket, fingerprint)?;
    if spool_dir.as_os_str().is_empty() {
        return Ok(candidate.clone());
    }
    match load_da_pin_intent(
        spool_dir,
        lane_id,
        epoch,
        sequence,
        storage_ticket,
        fingerprint,
    ) {
        Ok(existing) if da_pin_intents_have_same_signed_identity(&existing, candidate) => {
            Ok(existing)
        }
        Ok(_) => Err(std::io::Error::new(
            ErrorKind::AlreadyExists,
            "DA pin intent replay slot already contains a different signed identity",
        )),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(candidate.clone()),
        Err(err) => Err(err),
    }
}

fn validate_pin_scope_artifact_inputs(
    scope: &DaPinScopeV1,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
) -> std::io::Result<()> {
    if scope.lane_id != lane_id
        || scope.epoch != epoch
        || scope.sequence != sequence
        || &scope.storage_ticket != storage_ticket
    {
        return Err(invalid_artifact_input(
            "DA pin-scope artifact filename tuple does not match scope body",
        ));
    }
    Ok(())
}
fn parse_fixed_hex_u32(value: &str, width: usize) -> Option<u32> {
    (value.len() == width && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(value, 16).ok())
        .flatten()
}
fn parse_fixed_hex_u64(value: &str, width: usize) -> Option<u64> {
    (value.len() == width && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| u64::from_str_radix(value, 16).ok())
        .flatten()
}
fn parse_fixed_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).ok()?;
    Some(bytes)
}
pub(super) fn persist_manifest_for_sorafs(
    spool_dir: &Path,
    manifest_bytes: &[u8],
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> std::io::Result<Option<PathBuf>> {
    if spool_dir.as_os_str().is_empty() {
        return Ok(None);
    }
    if manifest_bytes.len() > DA_MANIFEST_ARTIFACT_MAX_BYTES_V1 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "DA manifest is {} bytes, exceeding the first-release {}-byte limit",
                manifest_bytes.len(),
                DA_MANIFEST_ARTIFACT_MAX_BYTES_V1
            ),
        ));
    }
    validate_manifest_artifact_inputs(
        manifest_bytes,
        lane_id,
        epoch,
        sequence,
        storage_ticket,
        fingerprint,
    )?;
    let lane = lane_id.as_u32();
    let ticket_hex = hex::encode(storage_ticket.as_ref());
    let artifact_dir = create_ticket_artifact_dir(spool_dir, storage_ticket)?;
    let target_path = artifact_dir.join(MANIFEST_ARTIFACT_FILE_NAME);
    if let Some(path) =
        existing_artifact_path_if_matching(&target_path, manifest_bytes, "DA manifest artifact")?
    {
        return Ok(Some(path));
    }
    let tmp_name = format!(
        ".{MANIFEST_ARTIFACT_FILE_NAME}.tmp-{}",
        artifact_temp_suffix()?
    );
    let tmp_path = artifact_dir.join(tmp_name);
    match write_temp_artifact(&tmp_path, manifest_bytes) {
        Ok(()) => {}
        Err(err) => return Err(temp_artifact_write_error(&tmp_path, err)),
    }
    install_artifact_without_overwrite(
        &tmp_path,
        &target_path,
        manifest_bytes,
        "DA manifest artifact",
    )?;
    debug!(
        path = ?target_path,
        lane = lane,
        epoch,
        sequence,
        ticket = %ticket_hex,
        "queued DA manifest for SoraFS orchestration"
    );
    Ok(Some(target_path))
}
pub(super) fn persist_pdp_commitment(
    spool_dir: &Path,
    commitment: &PdpCommitmentV1,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> std::io::Result<Option<PathBuf>> {
    if spool_dir.as_os_str().is_empty() {
        return Ok(None);
    }
    validate_pdp_commitment_artifact_inputs(commitment)?;
    validate_ticket_fingerprint(storage_ticket, fingerprint)?;
    let lane = lane_id.as_u32();
    let ticket_hex = hex::encode(storage_ticket.as_ref());
    let artifact_dir = create_ticket_artifact_dir(spool_dir, storage_ticket)?;
    let target_path = artifact_dir.join(PDP_COMMITMENT_ARTIFACT_FILE_NAME);
    let encoded =
        to_bytes(commitment).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    if let Some(path) =
        existing_artifact_path_if_matching(&target_path, &encoded, "PDP commitment artifact")?
    {
        return Ok(Some(path));
    }
    let tmp_name = format!(
        ".{PDP_COMMITMENT_ARTIFACT_FILE_NAME}.tmp-{}",
        artifact_temp_suffix()?
    );
    let tmp_path = artifact_dir.join(tmp_name);
    match write_temp_artifact(&tmp_path, &encoded) {
        Ok(()) => {}
        Err(err) => return Err(temp_artifact_write_error(&tmp_path, err)),
    }
    install_artifact_without_overwrite(
        &tmp_path,
        &target_path,
        &encoded,
        "PDP commitment artifact",
    )?;
    debug!(
        path = ?target_path,
        lane = lane,
        epoch,
        sequence,
        ticket = %ticket_hex,
        "queued PDP commitment for SoraFS orchestration"
    );
    Ok(Some(target_path))
}
pub(super) fn persist_da_commitment_record(
    spool_dir: &Path,
    record: &DaCommitmentRecord,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> std::io::Result<Option<PathBuf>> {
    if spool_dir.as_os_str().is_empty() {
        return Ok(None);
    }
    validate_da_commitment_artifact_inputs(record, lane_id, epoch, sequence, storage_ticket)?;
    create_spool_dir_no_follow(spool_dir)?;
    let lane = lane_id.as_u32();
    let ticket_hex = hex::encode(storage_ticket.as_ref());
    let fingerprint_hex = hex::encode(fingerprint.as_bytes());
    let file_name = format!(
        "da-commitment-{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.norito"
    );
    let target_path = spool_dir.join(file_name);
    let encoded =
        to_bytes(record).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    if let Some(path) =
        existing_artifact_path_if_matching(&target_path, &encoded, "DA commitment artifact")?
    {
        return Ok(Some(path));
    }
    let tmp_name = format!(
        ".da-commitment-{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.tmp-{}",
        artifact_temp_suffix()?
    );
    let tmp_path = spool_dir.join(tmp_name);
    match write_temp_artifact(&tmp_path, &encoded) {
        Ok(()) => {}
        Err(err) => return Err(temp_artifact_write_error(&tmp_path, err)),
    }
    install_artifact_without_overwrite(
        &tmp_path,
        &target_path,
        &encoded,
        "DA commitment artifact",
    )?;
    debug!(
        path = ?target_path,
        lane = lane,
        epoch,
        sequence,
        ticket = %ticket_hex,
        "queued DA commitment record for bundle ingestion"
    );
    Ok(Some(target_path))
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::da::persistence::DaCommitmentScheduleEntry")]
#[derive(Clone, Debug, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize)]
/// On-disk schedule entry combining commitment record and PDP commitment bytes.
pub(super) struct DaCommitmentScheduleEntry {
    /// Entry layout version for future migrations.
    pub(super) version: u16,
    /// Commitment record payload.
    pub(super) record: DaCommitmentRecord,
    /// Encoded PDP commitment bytes.
    pub(super) pdp_commitment: Vec<u8>,
}
#[allow(clippy::too_many_arguments)]
pub(super) fn persist_da_commitment_schedule_entry(
    spool_dir: &Path,
    record: &DaCommitmentRecord,
    pdp_commitment_bytes: &[u8],
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> std::io::Result<Option<PathBuf>> {
    if spool_dir.as_os_str().is_empty() {
        return Ok(None);
    }
    validate_da_schedule_artifact_inputs(
        record,
        pdp_commitment_bytes,
        lane_id,
        epoch,
        sequence,
        storage_ticket,
    )?;
    create_spool_dir_no_follow(spool_dir)?;
    let lane = lane_id.as_u32();
    let ticket_hex = hex::encode(storage_ticket.as_ref());
    let fingerprint_hex = hex::encode(fingerprint.as_bytes());
    let file_name = format!(
        "da-commitment-schedule-{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.norito"
    );
    let target_path = spool_dir.join(file_name);
    let entry = DaCommitmentScheduleEntry {
        version: DA_COMMITMENT_SCHEDULE_ENTRY_VERSION,
        record: record.clone(),
        pdp_commitment: pdp_commitment_bytes.to_vec(),
    };
    let encoded =
        to_bytes(&entry).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    if let Some(path) = existing_artifact_path_if_matching(
        &target_path,
        &encoded,
        "DA commitment schedule artifact",
    )? {
        return Ok(Some(path));
    }
    let tmp_name = format!(
        ".da-commitment-schedule-{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.tmp-{}",
        artifact_temp_suffix()?
    );
    let tmp_path = spool_dir.join(tmp_name);
    match write_temp_artifact(&tmp_path, &encoded) {
        Ok(()) => {}
        Err(err) => return Err(temp_artifact_write_error(&tmp_path, err)),
    }
    install_artifact_without_overwrite(
        &tmp_path,
        &target_path,
        &encoded,
        "DA commitment schedule artifact",
    )?;
    debug!(
        path = ?target_path,
        lane = lane,
        epoch,
        sequence,
        ticket = %ticket_hex,
        "queued DA commitment schedule entry for bundle ingestion"
    );
    Ok(Some(target_path))
}
pub(super) fn persist_da_pin_intent(
    spool_dir: &Path,
    intent: &DaPinIntent,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> std::io::Result<Option<PathBuf>> {
    if spool_dir.as_os_str().is_empty() {
        return Ok(None);
    }
    let selected_intent = select_da_pin_intent_for_persistence(
        spool_dir,
        intent,
        lane_id,
        epoch,
        sequence,
        storage_ticket,
        fingerprint,
    )?;
    let intent = &selected_intent;
    create_spool_dir_no_follow(spool_dir)?;
    let lane = lane_id.as_u32();
    let ticket_hex = hex::encode(storage_ticket.as_ref());
    let fingerprint_hex = hex::encode(fingerprint.as_bytes());
    let target_path = da_pin_intent_file_path(
        spool_dir,
        lane_id,
        epoch,
        sequence,
        storage_ticket,
        fingerprint,
    );
    let encoded =
        to_bytes(intent).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    if encoded.len() > DA_PIN_INTENT_ARTIFACT_MAX_BYTES_V1 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "DA pin intent is {} bytes, exceeding the first-release {}-byte limit",
                encoded.len(),
                DA_PIN_INTENT_ARTIFACT_MAX_BYTES_V1
            ),
        ));
    }
    let tmp_name = format!(
        ".da-pin-intent-{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.tmp-{}",
        artifact_temp_suffix()?
    );
    let tmp_path = spool_dir.join(tmp_name);
    match write_temp_artifact(&tmp_path, &encoded) {
        Ok(()) => {}
        Err(err) => return Err(temp_artifact_write_error(&tmp_path, err)),
    }
    if let Err(install_error) = install_artifact_without_overwrite(
        &tmp_path,
        &target_path,
        &encoded,
        "DA pin intent artifact",
    ) {
        match load_da_pin_intent(
            spool_dir,
            lane_id,
            epoch,
            sequence,
            storage_ticket,
            fingerprint,
        ) {
            Ok(existing) if da_pin_intents_have_same_signed_identity(&existing, intent) => {
                return Ok(Some(target_path));
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    ErrorKind::AlreadyExists,
                    "DA pin intent replay slot was concurrently bound to a different signed identity",
                ));
            }
            Err(_) => return Err(install_error),
        }
    }
    debug!(
        path = ?target_path,
        lane = lane,
        epoch,
        sequence,
        ticket = %ticket_hex,
        "queued DA pin intent for registry ingestion"
    );
    Ok(Some(target_path))
}

pub(super) fn persist_da_pin_scope(
    spool_dir: &Path,
    scope: &DaPinScopeV1,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> std::io::Result<Option<PathBuf>> {
    if spool_dir.as_os_str().is_empty() {
        return Ok(None);
    }
    validate_pin_scope_artifact_inputs(scope, lane_id, epoch, sequence, storage_ticket)?;
    validate_ticket_fingerprint(storage_ticket, fingerprint)?;
    create_spool_dir_no_follow(spool_dir)?;
    let lane = lane_id.as_u32();
    let ticket_hex = hex::encode(storage_ticket.as_ref());
    let fingerprint_hex = hex::encode(fingerprint.as_bytes());
    let target_path = da_pin_scope_file_path(
        spool_dir,
        lane_id,
        epoch,
        sequence,
        storage_ticket,
        fingerprint,
    );
    let encoded =
        to_bytes(scope).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    if encoded.len() > DA_PIN_SCOPE_ARTIFACT_MAX_BYTES_V1 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "DA pin scope is {} bytes, exceeding the first-release {}-byte limit",
                encoded.len(),
                DA_PIN_SCOPE_ARTIFACT_MAX_BYTES_V1
            ),
        ));
    }
    if let Some(path) =
        existing_artifact_path_if_matching(&target_path, &encoded, "DA pin-scope artifact")?
    {
        return Ok(Some(path));
    }
    let tmp_name = format!(
        ".da-pin-scope-{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.tmp-{}",
        artifact_temp_suffix()?
    );
    let tmp_path = spool_dir.join(tmp_name);
    match write_temp_artifact(&tmp_path, &encoded) {
        Ok(()) => {}
        Err(err) => return Err(temp_artifact_write_error(&tmp_path, err)),
    }
    install_artifact_without_overwrite(&tmp_path, &target_path, &encoded, "DA pin-scope artifact")?;
    debug!(
        path = ?target_path,
        lane,
        epoch,
        sequence,
        ticket = %ticket_hex,
        "persisted DA producer pin-scope challenge"
    );
    Ok(Some(target_path))
}

fn da_pin_intent_file_path(
    spool_dir: &Path,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> PathBuf {
    let lane = lane_id.as_u32();
    let ticket_hex = hex::encode(storage_ticket.as_ref());
    let fingerprint_hex = hex::encode(fingerprint.as_bytes());
    spool_dir.join(format!(
        "da-pin-intent-{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.norito"
    ))
}

fn da_pin_scope_file_path(
    spool_dir: &Path,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> PathBuf {
    let lane = lane_id.as_u32();
    let ticket_hex = hex::encode(storage_ticket.as_ref());
    let fingerprint_hex = hex::encode(fingerprint.as_bytes());
    spool_dir.join(format!(
        "da-pin-scope-{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.norito"
    ))
}
