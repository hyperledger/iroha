//! Runtime streaming handshake state.
//!
//! The handle maintained here keeps per-peer `StreamingSession` records so that incoming
//! control-plane frames (key updates, content-key rotations) can be validated and made
//! available to higher-level components.
#[cfg(feature = "telemetry")]
use crate::telemetry::StreamingTelemetry;
use crate::{
    IrohaNetwork, NetworkMessage,
    secure_file_metadata::{self, SecureMetadata},
};
#[cfg(test)]
use data_events::StreamingPrivacyRelay;
use data_events::{
    DomainEvent, StreamingPrivacyRoute, StreamingRouteBinding, StreamingTicketReady,
    StreamingTicketRevoked,
};
use iroha_config::parameters::{actual, defaults as config_defaults};
use iroha_crypto::{
    PrivateKey, SessionKey,
    encryption::{ChaCha20Poly1305, Error as EncryptionError, SymmetricEncryptor},
    streaming::{
        FeedbackStateSnapshot, HandshakeError, KeyMaterialError, StreamingKeyMaterial,
        StreamingSession, StreamingSessionSnapshot,
    },
};
#[cfg(test)]
use iroha_data_model::soranet::ticket::{TicketBodyV1, TicketEnvelopeV1, TicketScopeV1};
use iroha_data_model::{
    events::{
        EventBox,
        data::{DataEvent, prelude as data_events},
    },
    peer::Peer,
    soranet::ticket::TicketCommitmentError,
};
use iroha_logger::warn;
use iroha_model_base::domain::DomainId;
#[cfg(test)]
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
#[cfg(feature = "quic")]
use iroha_p2p::streaming::{CapabilityNegotiation, StreamingConnection};
use iroha_p2p::{Post, Priority};
#[cfg(test)]
use norito::streaming::PrivacyCapabilities;
#[cfg(feature = "quic")]
use norito::streaming::{CapabilityAck, CapabilityReport, TransportCapabilities};
use norito::{
    Error as NoritoError, NoritoDeserialize, NoritoSerialize,
    core::{self as norito_core},
    streaming::{
        BUNDLED_RANS_BUILD_AVAILABLE, BUNDLED_RANS_GPU_BUILD_AVAILABLE, BundleAnsTables,
        BundleTableError, CapabilityFlags, CapabilityRole, ContentKeyUpdate, ControlFrame,
        EncryptionSuite, EntropyMode, FeedbackHintFrame, Hash, KeyUpdate, ManifestAnnounceFrame,
        ManifestV1, PrivacyRelay, PrivacyRoute, PrivacyRouteUpdate, ReceiverReport,
        SyncDiagnostics, TransportCapabilityResolution, crypto::TransportKeys,
        default_bundle_tables, load_bundle_tables_from_toml,
    },
};
use soranet_pq::MlKemSuite;
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    fmt, fs, io,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock, RwLock},
};
use thiserror::Error;
use tokio::sync::broadcast;
#[derive(Debug)]
struct StreamingState {
    viewer_sessions: RwLock<BTreeMap<PeerId, StreamingSession>>,
    publisher_sessions: RwLock<BTreeMap<PeerId, StreamingSession>>,
    stream_tickets: RwLock<BTreeMap<Hash, StreamTicketState>>,
    route_index: RwLock<BTreeMap<Hash, Hash>>,
    ticket_nullifiers: RwLock<BTreeMap<Hash, Hash>>,
}
impl StreamingState {
    fn new() -> Self {
        Self {
            viewer_sessions: RwLock::new(BTreeMap::new()),
            publisher_sessions: RwLock::new(BTreeMap::new()),
            stream_tickets: RwLock::new(BTreeMap::new()),
            route_index: RwLock::new(BTreeMap::new()),
            ticket_nullifiers: RwLock::new(BTreeMap::new()),
        }
    }
}
#[inline]
fn stream_hash_from_crypto(hash: &iroha_crypto::Hash) -> Hash {
    (*hash).into()
}
fn global_handle_storage() -> &'static RwLock<Option<StreamingHandle>> {
    static GLOBAL_HANDLE: OnceLock<RwLock<Option<StreamingHandle>>> = OnceLock::new();
    GLOBAL_HANDLE.get_or_init(|| RwLock::new(None))
}
/// Register the process-wide streaming handle so other subsystems (e.g. overlays)
/// can reference negotiated transport metadata when needed.
pub fn set_global_handle(handle: StreamingHandle) {
    let mut guard = global_handle_storage()
        .write()
        .expect("global streaming handle lock poisoned");
    *guard = Some(handle);
}
/// Retrieve the registered streaming handle (if any).
#[must_use]
pub fn global_handle() -> Option<StreamingHandle> {
    global_handle_storage()
        .read()
        .expect("global streaming handle lock poisoned")
        .clone()
}
#[derive(Clone)]
struct RouteProvisionState {
    route: StreamingPrivacyRoute,
    last_provisioned_segment: Option<u64>,
    acked: bool,
}
impl fmt::Debug for RouteProvisionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteProvisionState")
            .field("route_id", &self.route.route_id)
            .field("expiry_segment", &self.route.expiry_segment)
            .field("route_credentials", &"<redacted>")
            .field("last_provisioned_segment", &self.last_provisioned_segment)
            .field("acked", &self.acked)
            .finish()
    }
}
#[derive(Clone, Debug)]
struct StreamTicketState {
    domain: DomainId,
    ticket: data_events::StreamingTicketRecord,
    routes: BTreeMap<Hash, RouteProvisionState>,
    order: Vec<Hash>,
}
/// Prepared privacy-route update coupled with the corresponding exit relay metadata.
#[derive(Clone)]
pub struct PreparedPrivacyRouteUpdate {
    /// Exit relay that must receive the update.
    pub exit_relay: PrivacyRelay,
    /// Payload delivered over the control plane.
    pub update: PrivacyRouteUpdate,
}
impl fmt::Debug for PreparedPrivacyRouteUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPrivacyRouteUpdate")
            .field("exit_relay", &self.exit_relay)
            .field("route_id", &self.update.route_id)
            .field("stream_id", &self.update.stream_id)
            .field("content_key_id", &self.update.content_key_id)
            .field("valid_from_segment", &self.update.valid_from_segment)
            .field("valid_until_segment", &self.update.valid_until_segment)
            .field(
                "exit_token",
                &format_args!("<redacted:{} bytes>", self.update.exit_token.len()),
            )
            .field("soranet", &self.update.soranet)
            .finish()
    }
}
impl Drop for PreparedPrivacyRouteUpdate {
    fn drop(&mut self) {
        self.update.exit_token.fill(0);
        std::hint::black_box(self.update.exit_token.as_mut_slice());
    }
}
#[cfg(test)]
#[derive(Clone, Debug)]
struct PendingPrivacyRouteUpdate {
    prepared: PreparedPrivacyRouteUpdate,
    expiry: u64,
}
#[cfg(test)]
fn mark_privacy_route_provisioned_in_state(
    state: &StreamingState,
    stream_id: &Hash,
    route_id: &Hash,
    expiry: u64,
) -> Result<(), StreamingProcessError> {
    let mut tickets = state
        .stream_tickets
        .write()
        .map_err(|_| StreamingProcessError::StatePoisoned)?;
    let state = tickets
        .get_mut(stream_id)
        .ok_or(StreamingProcessError::MissingStreamTicket { stream: *stream_id })?;
    let route_state =
        state
            .routes
            .get_mut(route_id)
            .ok_or(StreamingProcessError::UnknownPrivacyRoute {
                route_id: *route_id,
            })?;
    route_state.last_provisioned_segment = Some(expiry);
    route_state.acked = false;
    Ok(())
}
#[cfg(test)]
fn handle_provisioned_state_update(
    result: Result<(), StreamingProcessError>,
    stream_id: Hash,
    route_id: Hash,
) -> Result<(), StreamingProcessError> {
    match result {
        Ok(()) => Ok(()),
        Err(
            StreamingProcessError::MissingStreamTicket { .. }
            | StreamingProcessError::UnknownPrivacyRoute { .. },
        ) => {
            warn!(
                ?stream_id,
                ?route_id,
                "privacy route state removed during provisioning; skipping update"
            );
            Ok(())
        }
        Err(err) => Err(err),
    }
}
const SNAPSHOT_VERSION: u8 = 1;
const SNAPSHOT_AAD: &[u8] = b"iroha.streaming.snapshot.v1";
/// First-release ceiling across viewer and publisher entries in one snapshot.
const SNAPSHOT_MAX_ENTRIES_V1: usize = 4_096;
/// First-release ceiling for one canonical decrypted snapshot.
const SNAPSHOT_MAX_PLAINTEXT_BYTES_V1: usize = 16 * 1024 * 1024;
/// ChaCha20-Poly1305 easy envelopes prefix a 12-byte nonce and append a 16-byte tag.
const SNAPSHOT_AEAD_OVERHEAD_BYTES_V1: usize = 12 + 16;
/// First-release ceiling for one encrypted snapshot file.
const SNAPSHOT_MAX_CIPHERTEXT_BYTES_V1: usize =
    SNAPSHOT_MAX_PLAINTEXT_BYTES_V1 + SNAPSHOT_AEAD_OVERHEAD_BYTES_V1;
/// A snapshot can retain at most one local and one remote key from the largest v1 ML-KEM suite.
const SNAPSHOT_MAX_KEM_PUBLIC_KEY_BYTES_V1: usize = MlKemSuite::MlKem1024.public_key_len();
/// Group content keys are fixed-width inputs to streaming CEK derivation.
const SNAPSHOT_GROUP_CONTENT_KEY_BYTES_V1: usize = 32;
/// Decode budget applied before Norito allocates any snapshot-owned sequence.
const SNAPSHOT_DECODE_LIMITS_V1: norito_core::DecodeLimits = norito_core::DecodeLimits::new(
    SNAPSHOT_MAX_ENTRIES_V1,
    SNAPSHOT_MAX_PLAINTEXT_BYTES_V1,
    SNAPSHOT_MAX_PLAINTEXT_BYTES_V1,
    SNAPSHOT_MAX_PLAINTEXT_BYTES_V1 * 4,
    32,
);
#[cfg(feature = "quic")]
const FEATURE_PRIVACY_REQUIRED: u32 = 1 << 10;
const BUNDLE_ACCEL_CPU_SIMD_BIT: u32 = 1 << 13;
const BUNDLE_ACCEL_GPU_BIT: u32 = 1 << 14;
const BUNDLE_ACCEL_CAPABILITY_MASK: u32 = BUNDLE_ACCEL_CPU_SIMD_BIT | BUNDLE_ACCEL_GPU_BIT;
#[cfg(feature = "quic")]
const FEATURE_PRIVACY_PROVIDER: u32 = 1 << 11;
/// Persisted snapshot entry for a streaming session keyed by peer and role.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::streaming::StreamingSnapshotEntry")]
#[derive(Clone, Debug, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct StreamingSnapshotEntry {
    /// Role associated with the stored session.
    pub role: CapabilityRole,
    /// Peer identifier owning the session state.
    pub peer: PeerId,
    /// Snapshot exported from [`StreamingSession::snapshot_state`].
    pub snapshot: StreamingSessionSnapshot,
}
#[derive(Debug, NoritoSerialize, NoritoDeserialize, PartialEq, Eq, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::streaming::StreamingSnapshotFile")]
struct StreamingSnapshotFile {
    version: u8,
    entries: Vec<StreamingSnapshotEntry>,
}
enum AlignedSlice<'a> {
    Borrowed(&'a [u8]),
    Owned(OwnedAligned),
}
impl AlignedSlice<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(buffer) => buffer.as_slice(),
        }
    }
}
struct OwnedAligned {
    storage: Vec<u8>,
    start: usize,
    len: usize,
}
impl OwnedAligned {
    fn new(
        bytes: &[u8],
        align: usize,
        payload_offset: usize,
    ) -> Result<Self, StreamingSnapshotError> {
        let buf_len = bytes
            .len()
            .checked_add(align)
            .ok_or(StreamingSnapshotError::Codec(NoritoError::LengthMismatch))?;
        let mut storage = vec![0u8; buf_len];
        let base = storage.as_ptr() as usize;
        let payload_ptr = base + payload_offset;
        let misalign = payload_ptr % align;
        let offset = if misalign == 0 { 0 } else { align - misalign };
        let start = offset;
        let end = start
            .checked_add(bytes.len())
            .ok_or(StreamingSnapshotError::Codec(NoritoError::LengthMismatch))?;
        if end > storage.len() {
            return Err(StreamingSnapshotError::Codec(NoritoError::LengthMismatch));
        }
        storage[start..end].copy_from_slice(bytes);
        Ok(Self {
            storage,
            start,
            len: bytes.len(),
        })
    }
    fn as_slice(&self) -> &[u8] {
        &self.storage[self.start..self.start + self.len]
    }
}
fn align_slice(
    bytes: &[u8],
    align: usize,
    payload_offset: usize,
) -> Result<AlignedSlice<'_>, StreamingSnapshotError> {
    if align <= 1 || (bytes.as_ptr() as usize + payload_offset).is_multiple_of(align) {
        Ok(AlignedSlice::Borrowed(bytes))
    } else {
        OwnedAligned::new(bytes, align, payload_offset).map(AlignedSlice::Owned)
    }
}
/// Derive the symmetric session key used to encrypt streaming snapshots.
#[must_use]
pub fn snapshot_session_key(material: &StreamingKeyMaterial) -> SessionKey {
    material.snapshot_session_key()
}
/// Errors emitted while handling streaming control frames.
#[derive(Debug, Error)]
pub enum StreamingProcessError {
    /// Underlying handshake failure.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    /// Negotiated transport capabilities were not recorded for the peer.
    #[error("transport capabilities not negotiated for peer {peer}")]
    MissingTransportCapabilities {
        /// Peer whose negotiated capabilities were missing from state.
        peer: PeerId,
    },
    /// Feedback parity was requested before any feedback frames were processed for the peer.
    #[error("feedback parity not recorded for peer {peer}")]
    MissingFeedbackParity {
        /// Peer whose feedback state has not been established.
        peer: PeerId,
    },
    /// Manifest advertised a hash that does not match the negotiated capabilities.
    #[error(
        "transport capabilities hash mismatch for peer {peer} (expected {expected:?}, found {found:?})"
    )]
    TransportCapabilitiesHashMismatch {
        /// Peer whose manifest failed verification.
        peer: PeerId,
        /// Hash recorded during capability negotiation.
        expected: Hash,
        /// Hash stored in the manifest.
        found: Hash,
    },
    /// Viewer requested feature bits that this node does not support.
    #[error(
        "streaming feature mismatch (requested={requested_bits:#010x}, supported={supported_bits:#010x})"
    )]
    UnsupportedFeatures {
        /// Raw feature bits requested by the peer.
        requested_bits: u32,
        /// Feature bits exposed locally.
        supported_bits: u32,
    },
    /// Peer advertised an invalid streaming protocol version.
    #[error("invalid streaming protocol version {found}")]
    InvalidProtocolVersion {
        /// Protocol version received from the peer.
        found: u16,
    },
    /// Peer advertised a capability report for the wrong endpoint role.
    #[error("invalid capability report role (expected {expected:?}, found {found:?})")]
    InvalidCapabilityReportRole {
        /// Endpoint role required for the frame.
        expected: CapabilityRole,
        /// Endpoint role received from the peer.
        found: CapabilityRole,
    },
    /// Viewer requires privacy overlay while the publisher cannot provide it.
    #[error(
        "viewer requires privacy overlay but publisher capabilities do not advertise a provider"
    )]
    PrivacyOverlayUnsupported,
    /// Viewer does not advertise bundled rANS even though it is required by the publisher.
    #[error("viewer does not advertise bundled rANS support required by the publisher")]
    BundledEntropyUnsupported,
    /// Viewer does not advertise the configured bundled acceleration backend.
    #[error(
        "viewer does not advertise bundled acceleration {required:?} required by the publisher"
    )]
    BundledAccelerationUnsupported {
        /// Acceleration backend configured locally.
        required: actual::BundleAcceleration,
    },
    /// Publisher attempted to emit a bundled manifest without bundled encoder support.
    #[error(
        "manifest entropy mode {manifest:?} is not supported under node configuration {configured:?}"
    )]
    ManifestEntropyModeUnsupported {
        /// Local encoder configuration.
        configured: EntropyMode,
        /// Manifest entropy mode being emitted.
        manifest: EntropyMode,
    },
    /// Bundled manifest advertised a checksum that does not match the configured tables.
    #[error("manifest entropy tables checksum mismatch (expected {expected:?}, found {found:?})")]
    ManifestEntropyTablesMismatch {
        /// Hash of the local bundle tables.
        expected: Hash,
        /// Hash advertised in the manifest (or `None` when not provided).
        found: Option<Hash>,
    },
    /// Viewer received a bundled manifest without negotiating the bundled feature bit.
    #[error(
        "manifest entropy mode {manifest:?} requires FEATURE_ENTROPY_BUNDLED but peer {peer} negotiated bits {negotiated_bits:#010x}"
    )]
    ManifestEntropyModeNotNegotiated {
        /// Peer whose negotiated feature bits were missing the bundled flag.
        peer: PeerId,
        /// Manifest entropy mode being validated.
        manifest: EntropyMode,
        /// Negotiated capability bits recorded for the session.
        negotiated_bits: u32,
    },
    /// Bundled manifest required an acceleration backend that was not negotiated.
    #[error(
        "peer {peer} did not negotiate bundled acceleration {required:?} (bits {negotiated_bits:#010x})"
    )]
    ManifestAccelerationNotNegotiated {
        /// Peer whose negotiated features were missing the acceleration bit.
        peer: PeerId,
        /// Local acceleration requirement.
        required: actual::BundleAcceleration,
        /// Negotiated capability bits recorded for the session.
        negotiated_bits: u32,
    },
    /// Streaming capability ticket has not been registered for the stream.
    #[error("stream {stream:?} has no registered capability ticket")]
    MissingStreamTicket {
        /// Stream identifier.
        stream: Hash,
    },
    /// Privacy route identifier not known to the streaming state.
    #[error("privacy route {route_id:?} is not registered")]
    UnknownPrivacyRoute {
        /// Route identifier.
        route_id: Hash,
    },
    /// Privacy route has not been acknowledged by the exit relay yet.
    #[error("privacy route {route_id:?} has not been acknowledged by the exit relay")]
    PrivacyRouteUnacknowledged {
        /// Route identifier.
        route_id: Hash,
    },
    /// No active privacy routes available when preparing a manifest.
    #[error("stream {stream:?} has no active privacy routes for segment {segment}")]
    NoActivePrivacyRoutes {
        /// Stream identifier.
        stream: Hash,
        /// Segment number being prepared.
        segment: u64,
    },
    /// Access policy ticket mismatch while stamping or validating the manifest.
    #[error(
        "manifest ticket mismatch for stream {stream:?} (expected {expected:?}, found {found:?})"
    )]
    TicketMismatch {
        /// Stream identifier.
        stream: Hash,
        /// Ticket expected by streaming state.
        expected: Hash,
        /// Ticket advertised in the manifest.
        found: Option<Hash>,
    },
    /// Privacy route identifier reused across streams.
    #[error("privacy route {route_id:?} already registered for stream {stream:?}")]
    DuplicatePrivacyRoute {
        /// Route identifier.
        route_id: Hash,
        /// Stream identifier currently owning the route.
        stream: Hash,
    },
    /// Ticket nullifier reused across streams.
    #[error("ticket nullifier {nullifier:?} already registered for stream {stream:?}")]
    DuplicateTicketNullifier {
        /// Ticket nullifier value.
        nullifier: Hash,
        /// Stream identifier currently owning the nullifier.
        stream: Hash,
    },
    /// Ticket envelope attached to a privacy route failed verification.
    #[error("ticket envelope for privacy route {route_id:?} failed verification")]
    TicketEnvelopeInvalid {
        /// Route identifier associated with the invalid envelope.
        route_id: Hash,
        /// Underlying commitment verification error.
        #[source]
        source: TicketCommitmentError,
    },
    /// Ticket nullifier mismatch while processing a revocation.
    #[error(
        "ticket nullifier mismatch for stream {stream:?} (expected {expected:?}, found {found:?})"
    )]
    TicketNullifierMismatch {
        /// Stream identifier.
        stream: Hash,
        /// Nullifier expected by streaming state.
        expected: Hash,
        /// Nullifier advertised in the payload.
        found: Hash,
    },
    /// Privacy routes advertised in the manifest do not match the registered ticket state.
    #[error("manifest privacy routes mismatch for stream {stream:?}")]
    ManifestPrivacyRoutesMismatch {
        /// Stream identifier.
        stream: Hash,
    },
    /// Privacy route expired before the requested provisioning window.
    #[error(
        "privacy route {route_id:?} expired at segment {expiry_segment}, requested window starting at {requested_segment}"
    )]
    PrivacyRouteExpired {
        /// Route identifier.
        route_id: Hash,
        /// Last segment the route is valid for.
        expiry_segment: u64,
        /// First segment requested for provisioning.
        requested_segment: u64,
    },
    /// Transport-level negotiation failure.
    #[cfg(feature = "quic")]
    #[error("streaming transport negotiation failed: {0}")]
    Transport(#[from] iroha_p2p::streaming::quic::Error),
    /// Internal state lock was poisoned.
    #[error("streaming session state poisoned")]
    StatePoisoned,
    /// Viewer telemetry reported sustained audio/video drift beyond the configured thresholds.
    #[error("audio/video sync violation for peer {peer}: {reason}")]
    AudioSyncViolation {
        /// Peer identifier associated with the violation.
        peer: PeerId,
        /// Drift classification that triggered the rejection.
        reason: SyncViolation,
    },
    /// Streaming key material was missing or invalid.
    #[error(transparent)]
    KeyMaterial(#[from] KeyMaterialError),
    /// No key material configured for this handle.
    #[error("streaming key material not configured")]
    MissingKeyMaterial,
    /// A snapshot source or restore stream exceeded the first-release session ceiling.
    #[error("streaming snapshot entry limit exceeded (attempted {attempted}, limit {limit})")]
    SnapshotEntryLimitExceeded {
        /// One-based entry count that crossed the ceiling.
        attempted: usize,
        /// Maximum entries accepted by snapshot version 1.
        limit: usize,
    },
}
/// Classification of audio/video sync violations.
#[derive(Clone, Copy, Debug)]
pub enum SyncViolation {
    /// A single sample exceeded the configured hard cap.
    HardCap {
        /// Observed drift in milliseconds.
        observed_ms: u16,
        /// Configured hard cap in milliseconds.
        hard_cap_ms: u16,
        /// Diagnostic window length in milliseconds.
        window_ms: u16,
    },
    /// The EWMA drift exceeded the sustained threshold.
    Ewma {
        /// EWMA drift magnitude (milliseconds).
        ewma_ms: u16,
        /// Configured threshold (milliseconds).
        threshold_ms: u16,
        /// Diagnostic window length in milliseconds.
        window_ms: u16,
    },
}
impl fmt::Display for SyncViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HardCap {
                observed_ms,
                hard_cap_ms,
                window_ms,
            } => write!(
                f,
                "max drift {observed_ms} ms (> {hard_cap_ms} ms cap) within {window_ms} ms window"
            ),
            Self::Ewma {
                ewma_ms,
                threshold_ms,
                window_ms,
            } => write!(
                f,
                "EWMA drift {ewma_ms} ms (> {threshold_ms} ms threshold) within {window_ms} ms window"
            ),
        }
    }
}
/// Errors surfaced while loading or persisting streaming session snapshots.
#[derive(Debug, Error)]
pub enum StreamingSnapshotError {
    /// File-system level persistence failure.
    #[error("streaming snapshot IO error: {0}")]
    Io(#[from] io::Error),
    /// Norito codec failure while encoding or decoding the snapshot set.
    #[error("streaming snapshot codec error: {0}")]
    Codec(#[from] NoritoError),
    /// Encryption or decryption failure while handling snapshot payload.
    #[error("streaming snapshot encryption error: {0}")]
    Encryption(#[from] EncryptionError),
    /// Attempted to persist or load snapshots without configuring an encryption key.
    #[error("streaming snapshot encryption key not configured")]
    MissingEncryptionKey,
    /// Snapshot payload advertised an unsupported version.
    #[error("unsupported streaming snapshot version {found}")]
    UnsupportedVersion {
        /// Version value encountered on disk.
        found: u8,
    },
    /// A snapshot resource exceeded its first-release protocol ceiling.
    #[error("streaming snapshot {resource} exceeds limit (observed {observed}, limit {limit})")]
    ResourceLimitExceeded {
        /// Resource whose size crossed the ceiling.
        resource: &'static str,
        /// Observed byte or element count.
        observed: u64,
        /// Maximum byte or element count accepted by snapshot version 1.
        limit: u64,
    },
    /// Session restoration failed due to handshake invariants.
    #[error(transparent)]
    Process(#[from] StreamingProcessError),
}
/// Errors surfaced while applying codec-related configuration.
#[derive(Debug, Error)]
pub enum StreamingCodecConfigError {
    /// Loading or parsing the `SignedRansTablesV1` artefact failed.
    #[error("failed to load bundled rANS tables from `{path}`: {source}")]
    BundleTables {
        /// Path that failed to load.
        path: PathBuf,
        /// Detailed loader error.
        #[source]
        source: BundleTableError,
    },
    /// Configured bundle width exceeds what the artefact provides.
    #[error("configured bundle width {requested} exceeds the available table width {available}")]
    BundleWidth {
        /// Requested width from configuration.
        requested: u8,
        /// Maximum width supported by the artefact.
        available: u8,
    },
    /// Configured a GPU bundle-acceleration backend without compiling GPU support.
    #[error(
        "bundle acceleration {requested:?} requires a GPU-enabled bundled build \
         (ENABLE_RANS_BUNDLES=1 plus `codec-gpu-metal`/`codec-gpu-cuda`)"
    )]
    BundleAccelerationUnavailable {
        /// Acceleration backend requested by configuration.
        requested: actual::BundleAcceleration,
    },
    /// The binary was compiled without bundled rANS support.
    #[error(
        "bundled rANS profile requires ENABLE_RANS_BUNDLES=1; rebuild with bundled support enabled"
    )]
    BundledSupportUnavailable,
}
/// Lightweight handle for processing streaming control frames and querying session state.
#[derive(Clone)]
pub struct StreamingHandle {
    inner: Arc<StreamingState>,
    key_material: Option<StreamingKeyMaterial>,
    snapshot_path: Option<PathBuf>,
    snapshot_encryptor: Option<SymmetricEncryptor<ChaCha20Poly1305>>,
    capabilities: CapabilityFlags,
    sync_policy: SyncPolicy,
    entropy_mode: EntropyMode,
    bundle_width: u8,
    bundle_accel: actual::BundleAcceleration,
    bundle_tables: Arc<BundleAnsTables>,
    bundle_tables_hash: Hash,
    #[cfg(feature = "telemetry")]
    telemetry: Option<StreamingTelemetry>,
}
#[derive(Clone, Debug)]
struct SyncPolicy {
    enabled: bool,
    observe_only: bool,
    min_window_ms: u16,
    ewma_threshold_ms: u16,
    hard_cap_ms: u16,
}
impl SyncPolicy {
    const fn disabled() -> Self {
        Self {
            enabled: false,
            observe_only: true,
            min_window_ms: 0,
            ewma_threshold_ms: u16::MAX,
            hard_cap_ms: u16::MAX,
        }
    }
    fn from_config(config: actual::StreamingSync) -> Self {
        Self {
            enabled: config.enabled,
            observe_only: config.observe_only,
            min_window_ms: config.min_window_ms,
            ewma_threshold_ms: config.ewma_threshold_ms,
            hard_cap_ms: config.hard_cap_ms,
        }
    }
    fn violation(&self, diagnostics: &SyncDiagnostics) -> Option<SyncViolation> {
        if !self.enabled {
            return None;
        }
        if diagnostics.window_ms < self.min_window_ms {
            return None;
        }
        if diagnostics.max_av_drift_ms > self.hard_cap_ms {
            return Some(SyncViolation::HardCap {
                observed_ms: diagnostics.max_av_drift_ms,
                hard_cap_ms: self.hard_cap_ms,
                window_ms: diagnostics.window_ms,
            });
        }
        let ewma_abs = diagnostics.ewma_av_drift_ms.unsigned_abs();
        if ewma_abs > self.ewma_threshold_ms {
            return Some(SyncViolation::Ewma {
                ewma_ms: ewma_abs,
                threshold_ms: self.ewma_threshold_ms,
                window_ms: diagnostics.window_ms,
            });
        }
        None
    }
    fn observe_only(&self) -> bool {
        self.observe_only
    }
}
/// Parameters required to construct a signed key-update frame.
pub struct KeyUpdateSpec<'suite> {
    /// Identifier of the session being updated.
    pub session_id: Hash,
    /// Encryption suite negotiated for the session.
    pub suite: &'suite EncryptionSuite,
    /// Protocol version carried alongside the frame.
    pub protocol_version: u16,
    /// Monotonic key counter used for replay protection.
    pub key_counter: u64,
}
impl fmt::Debug for StreamingHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let viewer_sessions = self
            .inner
            .viewer_sessions
            .read()
            .map(|map| map.len())
            .unwrap_or_default();
        let publisher_sessions = self
            .inner
            .publisher_sessions
            .read()
            .map(|map| map.len())
            .unwrap_or_default();
        let mut debug = f.debug_struct("StreamingHandle");
        debug
            .field("viewer_sessions", &viewer_sessions)
            .field("publisher_sessions", &publisher_sessions)
            .field(
                "key_material",
                &self.key_material.as_ref().map(|_| "configured"),
            )
            .field("snapshot_path", &self.snapshot_path)
            .field(
                "snapshot_encryptor",
                &self.snapshot_encryptor.as_ref().map(|_| "configured"),
            )
            .field(
                "capabilities_bits",
                &format_args!("{:#010x}", self.capabilities.bits()),
            );
        debug
            .field("entropy_mode", &self.entropy_mode)
            .field("bundle_width", &self.bundle_width)
            .field("bundle_accel", &self.bundle_accel)
            .field(
                "bundle_tables_precision_bits",
                &self.bundle_tables.precision_bits(),
            );
        debug.field(
            "bundle_tables_checksum",
            &hex::encode(self.bundle_tables_hash),
        );
        debug.field("sync_policy", &self.sync_policy);
        #[cfg(feature = "telemetry")]
        debug.field("telemetry", &self.telemetry.as_ref().map(|_| "configured"));
        debug.finish_non_exhaustive()
    }
}
impl StreamingHandle {
    /// Construct a new, empty streaming state handle.
    #[must_use]
    pub fn new() -> Self {
        let tables = default_bundle_tables();
        let tables_hash = tables.checksum();
        Self {
            inner: Arc::new(StreamingState::new()),
            key_material: None,
            snapshot_path: None,
            snapshot_encryptor: None,
            capabilities: CapabilityFlags::from_bits(config_defaults::streaming::FEATURE_BITS)
                .insert(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            sync_policy: SyncPolicy::disabled(),
            entropy_mode: EntropyMode::RansBundled,
            bundle_width: config_defaults::streaming::codec::bundle_width(),
            bundle_accel: actual::BundleAcceleration::None,
            bundle_tables: tables,
            bundle_tables_hash: tables_hash,
            #[cfg(feature = "telemetry")]
            telemetry: None,
        }
    }
    /// Construct a streaming handle preloaded with node key material.
    #[must_use]
    pub fn with_key_material(key_material: StreamingKeyMaterial) -> Self {
        let tables = default_bundle_tables();
        let tables_hash = tables.checksum();
        Self {
            inner: Arc::new(StreamingState::new()),
            key_material: Some(key_material),
            snapshot_path: None,
            snapshot_encryptor: None,
            capabilities: CapabilityFlags::from_bits(config_defaults::streaming::FEATURE_BITS)
                .insert(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            sync_policy: SyncPolicy::disabled(),
            entropy_mode: EntropyMode::RansBundled,
            bundle_width: config_defaults::streaming::codec::bundle_width(),
            bundle_accel: actual::BundleAcceleration::None,
            bundle_tables: tables,
            bundle_tables_hash: tables_hash,
            #[cfg(feature = "telemetry")]
            telemetry: None,
        }
    }
    /// Apply the sync enforcement policy derived from configuration.
    pub fn apply_sync_config(&mut self, config: &actual::StreamingSync) {
        self.sync_policy = SyncPolicy::from_config(*config);
    }
    /// Override the sync policy during tests.
    #[cfg(test)]
    #[must_use]
    fn with_sync_policy(mut self, policy: SyncPolicy) -> Self {
        self.sync_policy = policy;
        self
    }
    /// Apply entropy-coder toggles derived from configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configured bundle tables cannot be loaded.
    pub fn apply_codec_config(
        &mut self,
        config: &actual::StreamingCodec,
    ) -> Result<(), StreamingCodecConfigError> {
        if !BUNDLED_RANS_BUILD_AVAILABLE {
            return Err(StreamingCodecConfigError::BundledSupportUnavailable);
        }
        self.entropy_mode = config.entropy_mode;
        self.bundle_accel = config.bundle_accel;
        if self.bundle_accel == actual::BundleAcceleration::Gpu && !BUNDLED_RANS_GPU_BUILD_AVAILABLE
        {
            return Err(StreamingCodecConfigError::BundleAccelerationUnavailable {
                requested: self.bundle_accel,
            });
        }
        let tables = load_bundle_tables_from_toml(&config.rans_tables_path).map_err(|source| {
            StreamingCodecConfigError::BundleTables {
                path: config.rans_tables_path.clone(),
                source,
            }
        })?;
        if config.bundle_width > tables.max_width() {
            return Err(StreamingCodecConfigError::BundleWidth {
                requested: config.bundle_width,
                available: tables.max_width(),
            });
        }
        self.bundle_width = config.bundle_width.min(tables.max_width());
        self.bundle_tables = Arc::clone(&tables);
        self.bundle_tables_hash = tables.checksum();
        self.capabilities = self
            .capabilities
            .insert(CapabilityFlags::FEATURE_ENTROPY_BUNDLED);
        self.capabilities = self.capabilities.remove(BUNDLE_ACCEL_CAPABILITY_MASK);
        let accel_mask = self.bundle_accel_capability_mask();
        if accel_mask != 0 {
            self.capabilities = self.capabilities.insert(accel_mask);
        }
        Ok(())
    }
    /// Builder-style variant of [`apply_codec_config`].
    ///
    /// # Errors
    ///
    /// Propagates errors emitted by [`apply_codec_config`].
    pub fn with_codec_config(
        mut self,
        config: &actual::StreamingCodec,
    ) -> Result<Self, StreamingCodecConfigError> {
        self.apply_codec_config(config)?;
        Ok(self)
    }
    /// Override the advertised capability flags using a builder-style API.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: CapabilityFlags) -> Self {
        self.capabilities = self.normalize_viewer_feature_bits(capabilities);
        self
    }
    /// Hash of the currently configured bundle tables.
    #[must_use]
    pub fn bundle_tables_checksum(&self) -> Hash {
        self.bundle_tables_hash
    }
    /// Clone the currently configured bundle table set.
    #[must_use]
    pub fn bundle_tables(&self) -> Arc<BundleAnsTables> {
        Arc::clone(&self.bundle_tables)
    }
    fn bundle_accel_capability_mask(&self) -> u32 {
        match self.bundle_accel {
            actual::BundleAcceleration::None => 0,
            actual::BundleAcceleration::CpuSimd => BUNDLE_ACCEL_CPU_SIMD_BIT,
            actual::BundleAcceleration::Gpu => BUNDLE_ACCEL_GPU_BIT,
        }
    }
    #[cfg_attr(not(feature = "quic"), allow(dead_code))]
    fn bundled_entropy_required(&self) -> bool {
        self.entropy_mode.is_bundled()
    }
    #[cfg_attr(not(feature = "quic"), allow(dead_code))]
    fn normalize_viewer_feature_bits(&self, bits: CapabilityFlags) -> CapabilityFlags {
        let bits = bits.insert(CapabilityFlags::FEATURE_ENTROPY_BUNDLED);
        self.normalize_bundle_accel_bits(bits)
    }
    fn normalize_bundle_accel_bits(&self, bits: CapabilityFlags) -> CapabilityFlags {
        let cleared = bits.remove(BUNDLE_ACCEL_CAPABILITY_MASK);
        let mask = self.bundle_accel_capability_mask();
        if mask == 0 {
            cleared
        } else {
            cleared.insert(mask)
        }
    }
    fn ensure_manifest_entropy_mode_supported(
        &self,
        manifest: &ManifestV1,
    ) -> Result<(), StreamingProcessError> {
        if !manifest.entropy_mode.is_bundled() {
            return Err(StreamingProcessError::ManifestEntropyModeUnsupported {
                configured: self.entropy_mode,
                manifest: manifest.entropy_mode,
            });
        }
        if !self.entropy_mode.is_bundled() {
            return Err(StreamingProcessError::ManifestEntropyModeUnsupported {
                configured: self.entropy_mode,
                manifest: manifest.entropy_mode,
            });
        }
        let expected = self.bundle_tables_checksum();
        if manifest.entropy_tables_checksum != Some(expected) {
            return Err(StreamingProcessError::ManifestEntropyTablesMismatch {
                expected,
                found: manifest.entropy_tables_checksum,
            });
        }
        Ok(())
    }
    fn ensure_manifest_entropy_mode_negotiated(
        &self,
        peer_id: &PeerId,
        manifest: &ManifestV1,
    ) -> Result<(), StreamingProcessError> {
        if !manifest.entropy_mode.is_bundled() {
            return Err(StreamingProcessError::ManifestEntropyModeUnsupported {
                configured: self.entropy_mode,
                manifest: manifest.entropy_mode,
            });
        }
        let negotiated = self.negotiated_capabilities(peer_id).ok_or_else(|| {
            StreamingProcessError::MissingTransportCapabilities {
                peer: peer_id.clone(),
            }
        })?;
        if !negotiated.contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED) {
            return Err(StreamingProcessError::ManifestEntropyModeNotNegotiated {
                peer: peer_id.clone(),
                manifest: manifest.entropy_mode,
                negotiated_bits: negotiated.bits(),
            });
        }
        let accel_mask = self.bundle_accel_capability_mask();
        if accel_mask != 0 && !negotiated.contains(accel_mask) {
            return Err(StreamingProcessError::ManifestAccelerationNotNegotiated {
                peer: peer_id.clone(),
                required: self.bundle_accel,
                negotiated_bits: negotiated.bits(),
            });
        }
        Ok(())
    }
    /// Apply crypto configuration gating to the advertised capability mask.
    pub fn apply_crypto_config(&mut self, crypto: &actual::Crypto) {
        #[cfg(feature = "sm")]
        {
            if crypto.sm_helpers_enabled() {
                self.capabilities = self
                    .capabilities
                    .insert(CapabilityFlags::FEATURE_SM_TRANSACTIONS);
            } else {
                self.capabilities = self
                    .capabilities
                    .remove(CapabilityFlags::FEATURE_SM_TRANSACTIONS);
            }
        }
        #[cfg(not(feature = "sm"))]
        {
            let _ = crypto;
            self.capabilities = self
                .capabilities
                .remove(CapabilityFlags::FEATURE_SM_TRANSACTIONS);
        }
    }
    /// Install a telemetry sink used to emit streaming metrics.
    #[cfg(feature = "telemetry")]
    #[must_use]
    pub fn with_telemetry(mut self, telemetry: StreamingTelemetry) -> Self {
        self.telemetry = Some(telemetry);
        self
    }
    /// Return the configured streaming telemetry handle, if any.
    #[cfg(feature = "telemetry")]
    #[must_use]
    pub fn telemetry_handle(&self) -> Option<StreamingTelemetry> {
        self.telemetry.clone()
    }
    /// Return the capability flags currently advertised by this handle.
    #[must_use]
    pub fn capabilities(&self) -> CapabilityFlags {
        self.capabilities
    }
    #[cfg(test)]
    /// Attach a snapshot path so session state is persisted to disk automatically.
    #[must_use]
    pub fn with_snapshot_path(mut self, path: PathBuf) -> Self {
        self.snapshot_path = Some(path);
        self
    }
    #[cfg(test)]
    /// Configure the encryption key used when persisting or loading snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`EncryptionError`] if the provided key has the wrong length for the cipher.
    pub fn with_snapshot_encryption_key(
        mut self,
        key: &SessionKey,
    ) -> Result<Self, EncryptionError> {
        self.set_snapshot_encryption_key(key)?;
        Ok(self)
    }
    /// Install or update the snapshot path after construction.
    pub fn set_snapshot_path(&mut self, path: PathBuf) {
        self.snapshot_path = Some(path);
    }
    /// Install or update the snapshot encryption key after construction.
    ///
    /// # Errors
    ///
    /// Returns [`EncryptionError`] if the provided key has the wrong length for the cipher.
    pub fn set_snapshot_encryption_key(&mut self, key: &SessionKey) -> Result<(), EncryptionError> {
        let encryptor = SymmetricEncryptor::<ChaCha20Poly1305>::new_from_session_key(key)?;
        self.snapshot_encryptor = Some(encryptor);
        Ok(())
    }
    /// Return the configured snapshot path if persistence is enabled.
    #[must_use]
    pub fn snapshot_path(&self) -> Option<&Path> {
        self.snapshot_path.as_deref()
    }
    /// Process an incoming control frame from the given peer.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError`] if session state is poisoned or frame verification fails.
    pub fn process_control_frame(
        &self,
        peer: &Peer,
        frame: &ControlFrame,
    ) -> Result<(), StreamingProcessError> {
        let mut persist = false;
        match frame {
            ControlFrame::KeyUpdate(update) => {
                self.handle_key_update(peer, update)?;
                persist = true;
            }
            ControlFrame::ContentKeyUpdate(update) => {
                self.handle_content_key_update(peer, update)?;
                persist = true;
            }
            ControlFrame::FeedbackHint(hint) => {
                self.handle_feedback_hint(peer, hint)?;
                persist = true;
            }
            ControlFrame::ReceiverReport(report) => {
                self.handle_receiver_report(peer, report)?;
                persist = true;
            }
            ControlFrame::ManifestAnnounce(frame) => {
                self.validate_manifest_transport_capabilities(peer.id(), &frame.manifest)?;
                self.validate_manifest_ticket_and_routes(&frame.manifest)?;
            }
            ControlFrame::PrivacyRouteAck(frame) => {
                self.record_privacy_route_ack(&frame.route_id)?;
            }
            _ => {}
        }
        if persist {
            self.try_persist_snapshots();
        }
        Ok(())
    }
    /// Build a signed `KeyUpdate` frame for the given peer and role.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::StatePoisoned`] if the session map lock is poisoned or
    /// propagates lower-level handshake errors surfaced while constructing the frame.
    pub fn build_key_update(
        &self,
        peer: &Peer,
        role: CapabilityRole,
        spec: &KeyUpdateSpec<'_>,
        signer: &PrivateKey,
    ) -> Result<KeyUpdate, StreamingProcessError> {
        let frame = self.with_session(peer, role, |session| {
            session.build_key_update(
                spec.session_id,
                spec.suite,
                spec.protocol_version,
                spec.key_counter,
                signer,
            )
        })?;
        self.try_persist_snapshots();
        Ok(frame)
    }
    #[cfg(test)]
    /// Build a signed `KeyUpdate` frame using the configured key material.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::MissingKeyMaterial`] if no key material was provided when
    /// constructing the handle, or propagates handshake/key-material failures.
    pub fn build_key_update_with_material(
        &self,
        peer: &Peer,
        role: CapabilityRole,
        spec: &KeyUpdateSpec<'_>,
    ) -> Result<KeyUpdate, StreamingProcessError> {
        let material = self
            .key_material
            .as_ref()
            .ok_or(StreamingProcessError::MissingKeyMaterial)?;
        let frame = self.with_session(peer, role, |session| {
            material.build_key_update(
                session,
                spec.session_id,
                spec.suite,
                spec.protocol_version,
                spec.key_counter,
            )
        })?;
        self.try_persist_snapshots();
        Ok(frame)
    }
    /// Build a `ContentKeyUpdate` frame for the given viewer peer.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::StatePoisoned`] if the session map lock is poisoned or
    /// propagates handshake errors when the underlying session has not negotiated transport keys.
    pub fn build_content_key_update(
        &self,
        peer: &Peer,
        gck_plaintext: &[u8],
        content_key_id: u64,
        valid_from_segment: u64,
    ) -> Result<ContentKeyUpdate, StreamingProcessError> {
        let frame = self.with_session(peer, CapabilityRole::Publisher, |session| {
            session.build_content_key_update(gck_plaintext, content_key_id, valid_from_segment)
        })?;
        self.try_persist_snapshots();
        Ok(frame)
    }
    /// Record the negotiated transport capabilities for a peer session.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::StatePoisoned`] if the session map lock is poisoned.
    pub fn record_transport_capabilities(
        &self,
        peer: &Peer,
        role: CapabilityRole,
        resolution: TransportCapabilityResolution,
    ) -> Result<(), StreamingProcessError> {
        self.with_session(peer, role, |session| {
            session.record_transport_capabilities(resolution)
        })?;
        self.try_persist_snapshots();
        Ok(())
    }
    /// Record the negotiated feature flags for a peer session.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::StatePoisoned`] if the session map lock is poisoned.
    pub fn record_negotiated_capabilities(
        &self,
        peer: &Peer,
        role: CapabilityRole,
        capabilities: CapabilityFlags,
    ) -> Result<(), StreamingProcessError> {
        self.with_session(peer, role, |session| {
            session.record_capabilities(capabilities);
            Ok(())
        })?;
        self.try_persist_snapshots();
        Ok(())
    }
    #[cfg(test)]
    fn convert_privacy_relay(relay: &StreamingPrivacyRelay) -> PrivacyRelay {
        PrivacyRelay {
            relay_id: relay.relay_id,
            endpoint: relay.endpoint.clone(),
            key_fingerprint: relay.key_fingerprint,
            capabilities: PrivacyCapabilities::from_bits(relay.capabilities_bits),
        }
    }
    fn convert_privacy_route(route: &StreamingPrivacyRoute) -> PrivacyRoute {
        PrivacyRoute::from(route)
    }
    /// Register or replace the streaming capability ticket and associated privacy routes for a
    /// stream.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::DuplicatePrivacyRoute`] when the provided route list
    /// contains duplicate identifiers or when a route is already linked to a different stream,
    /// [`StreamingProcessError::DuplicateTicketNullifier`] if the ticket nullifier collides with an
    /// existing stream, or [`StreamingProcessError::StatePoisoned`] when internal locks are
    /// poisoned.
    pub fn register_stream_ticket(
        &self,
        ready: &StreamingTicketReady,
        routes: Vec<StreamingPrivacyRoute>,
    ) -> Result<(), StreamingProcessError> {
        let stream_id = stream_hash_from_crypto(ready.stream_id());
        let ticket_nullifier = stream_hash_from_crypto(ready.ticket().nullifier());
        // Build and cryptographically validate the complete replacement before
        // touching authoritative state. A rejected candidate must not erase a
        // previously valid ticket, route index, or nullifier binding.
        let mut seen = BTreeSet::new();
        let mut order = Vec::with_capacity(routes.len());
        let mut route_states = BTreeMap::new();
        for route in routes {
            let route_id = route.route_id;
            if !seen.insert(route_id) {
                return Err(StreamingProcessError::DuplicatePrivacyRoute {
                    route_id,
                    stream: stream_id,
                });
            }
            if let Some(envelope) = route.ticket_envelope() {
                envelope.verify_commitment().map_err(|error| {
                    StreamingProcessError::TicketEnvelopeInvalid {
                        route_id,
                        source: error,
                    }
                })?;
            }
            order.push(route_id);
            route_states.insert(
                route_id,
                RouteProvisionState {
                    route,
                    last_provisioned_segment: None,
                    acked: false,
                },
            );
        }
        let mut route_index = self
            .inner
            .route_index
            .write()
            .map_err(|_| StreamingProcessError::StatePoisoned)?;
        let mut tickets = self
            .inner
            .stream_tickets
            .write()
            .map_err(|_| StreamingProcessError::StatePoisoned)?;
        let mut nullifiers = self
            .inner
            .ticket_nullifiers
            .write()
            .map_err(|_| StreamingProcessError::StatePoisoned)?;
        if let Some(existing_stream) = nullifiers.get(&ticket_nullifier) {
            if *existing_stream != stream_id {
                return Err(StreamingProcessError::DuplicateTicketNullifier {
                    nullifier: ticket_nullifier,
                    stream: *existing_stream,
                });
            }
        }
        for route_id in &order {
            if let Some(owner) = route_index.get(route_id) {
                if *owner != stream_id {
                    return Err(StreamingProcessError::DuplicatePrivacyRoute {
                        route_id: *route_id,
                        stream: *owner,
                    });
                }
            }
        }
        if let Some(previous) = tickets.remove(&stream_id) {
            for route_id in previous.order {
                route_index.remove(&route_id);
            }
            let previous_nullifier = stream_hash_from_crypto(previous.ticket.nullifier());
            nullifiers.remove(&previous_nullifier);
        }
        for route_id in &order {
            route_index.insert(*route_id, stream_id);
        }
        nullifiers.insert(ticket_nullifier, stream_id);
        tickets.insert(
            stream_id,
            StreamTicketState {
                domain: ready.domain().clone(),
                ticket: ready.ticket().clone(),
                routes: route_states,
                order,
            },
        );
        Ok(())
    }
    /// Remove a stream ticket and its associated privacy routes from state.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::MissingStreamTicket`] if the stream does not have a ticket
    /// registered.
    pub fn unregister_stream_ticket(&self, stream_id: &Hash) -> Result<(), StreamingProcessError> {
        let mut route_index = self
            .inner
            .route_index
            .write()
            .map_err(|_| StreamingProcessError::StatePoisoned)?;
        let mut tickets = self
            .inner
            .stream_tickets
            .write()
            .map_err(|_| StreamingProcessError::StatePoisoned)?;
        let mut nullifiers = self
            .inner
            .ticket_nullifiers
            .write()
            .map_err(|_| StreamingProcessError::StatePoisoned)?;
        let Some(state) = tickets.remove(stream_id) else {
            return Err(StreamingProcessError::MissingStreamTicket { stream: *stream_id });
        };
        let nullifier = stream_hash_from_crypto(state.ticket.nullifier());
        for route_id in state.order {
            route_index.remove(&route_id);
        }
        nullifiers.remove(&nullifier);
        Ok(())
    }
    #[cfg(test)]
    /// Prepare `PrivacyRouteUpdate` frames to provision exit relays for the given stream.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::MissingStreamTicket`] if the stream does not have a
    /// registered ticket or [`StreamingProcessError::PrivacyRouteExpired`] when a route has
    /// exceeded its validity window.
    pub fn prepare_privacy_route_updates(
        &self,
        stream_id: &Hash,
        content_key_id: u64,
        valid_from_segment: u64,
        valid_until_segment: u64,
    ) -> Result<Vec<PreparedPrivacyRouteUpdate>, StreamingProcessError> {
        let pending_updates = self.pending_privacy_route_updates(
            stream_id,
            content_key_id,
            valid_from_segment,
            valid_until_segment,
        )?;
        let mut updates = Vec::with_capacity(pending_updates.len());
        for pending in pending_updates {
            handle_provisioned_state_update(
                self.mark_privacy_route_provisioned(
                    &pending.prepared.update.stream_id,
                    &pending.prepared.update.route_id,
                    pending.expiry,
                ),
                pending.prepared.update.stream_id,
                pending.prepared.update.route_id,
            )?;
            updates.push(pending.prepared.clone());
        }
        Ok(updates)
    }
    #[cfg(test)]
    fn pending_privacy_route_updates(
        &self,
        stream_id: &Hash,
        content_key_id: u64,
        valid_from_segment: u64,
        valid_until_segment: u64,
    ) -> Result<Vec<PendingPrivacyRouteUpdate>, StreamingProcessError> {
        let (pending_updates, expired_route, has_viable_route) = {
            let mut tickets = self
                .inner
                .stream_tickets
                .write()
                .map_err(|_| StreamingProcessError::StatePoisoned)?;
            let Some(state) = tickets.get_mut(stream_id) else {
                return Err(StreamingProcessError::MissingStreamTicket { stream: *stream_id });
            };
            let mut pending = Vec::new();
            let mut expired_route: Option<(Hash, u64)> = None;
            let mut has_viable_route = false;
            for route_id in &state.order {
                let Some(route_state) = state.routes.get_mut(route_id) else {
                    continue;
                };
                let expiry_segment = route_state.route.expiry_segment;
                if expiry_segment < valid_from_segment {
                    expired_route = Some((route_state.route.route_id, expiry_segment));
                    continue;
                }
                has_viable_route = true;
                let expiry = std::cmp::min(expiry_segment, valid_until_segment);
                if expiry < valid_from_segment {
                    continue;
                }
                let needs_update = match route_state.last_provisioned_segment {
                    None => true,
                    Some(last) if expiry > last => true,
                    Some(_) if !route_state.acked => true,
                    _ => false,
                };
                if needs_update {
                    let route_id = route_state.route.route_id;
                    let prepared = PreparedPrivacyRouteUpdate {
                        exit_relay: Self::convert_privacy_relay(route_state.route.exit()),
                        update: PrivacyRouteUpdate {
                            route_id,
                            stream_id: *stream_id,
                            content_key_id,
                            valid_from_segment,
                            valid_until_segment: expiry,
                            exit_token: route_state.route.ticket_exit().clone(),
                            soranet: Self::convert_privacy_route(&route_state.route).soranet,
                        },
                    };
                    pending.push(PendingPrivacyRouteUpdate { prepared, expiry });
                }
            }
            (pending, expired_route, has_viable_route)
        };
        if !has_viable_route {
            if let Some((route_id, expiry)) = expired_route {
                return Err(StreamingProcessError::PrivacyRouteExpired {
                    route_id,
                    expiry_segment: expiry,
                    requested_segment: valid_from_segment,
                });
            }
            return Err(StreamingProcessError::NoActivePrivacyRoutes {
                stream: *stream_id,
                segment: valid_from_segment,
            });
        }
        Ok(pending_updates)
    }
    #[cfg(test)]
    fn mark_privacy_route_provisioned(
        &self,
        stream_id: &Hash,
        route_id: &Hash,
        expiry: u64,
    ) -> Result<(), StreamingProcessError> {
        mark_privacy_route_provisioned_in_state(self.inner.as_ref(), stream_id, route_id, expiry)
    }
    /// Record an acknowledgement emitted by an exit relay after receiving a `PrivacyRouteUpdate`.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::UnknownPrivacyRoute`] if the acknowledgement references an
    /// unregistered route.
    pub fn record_privacy_route_ack(&self, route_id: &Hash) -> Result<(), StreamingProcessError> {
        let stream_id = {
            let route_index = self
                .inner
                .route_index
                .read()
                .map_err(|_| StreamingProcessError::StatePoisoned)?;
            route_index.get(route_id).copied().ok_or(
                StreamingProcessError::UnknownPrivacyRoute {
                    route_id: *route_id,
                },
            )?
        };
        let mut tickets = self
            .inner
            .stream_tickets
            .write()
            .map_err(|_| StreamingProcessError::StatePoisoned)?;
        let state = tickets
            .get_mut(&stream_id)
            .ok_or(StreamingProcessError::MissingStreamTicket { stream: stream_id })?;
        let route_state =
            state
                .routes
                .get_mut(route_id)
                .ok_or(StreamingProcessError::UnknownPrivacyRoute {
                    route_id: *route_id,
                })?;
        route_state.acked = true;
        Ok(())
    }
    fn manifest_ticket_and_routes(
        &self,
        stream_id: Hash,
        segment_number: u64,
    ) -> Result<(Hash, Vec<PrivacyRoute>), StreamingProcessError> {
        let tickets = self
            .inner
            .stream_tickets
            .read()
            .map_err(|_| StreamingProcessError::StatePoisoned)?;
        let ticket_state = tickets
            .get(&stream_id)
            .ok_or(StreamingProcessError::MissingStreamTicket { stream: stream_id })?;
        let mut routes = Vec::new();
        for route_id in &ticket_state.order {
            let Some(state) = ticket_state.routes.get(route_id) else {
                continue;
            };
            if state.route.expiry_segment < segment_number {
                continue;
            }
            if !state.acked {
                return Err(StreamingProcessError::PrivacyRouteUnacknowledged {
                    route_id: state.route.route_id,
                });
            }
            routes.push(Self::convert_privacy_route(&state.route));
        }
        if routes.is_empty() {
            return Err(StreamingProcessError::NoActivePrivacyRoutes {
                stream: stream_id,
                segment: segment_number,
            });
        }
        let ticket_id = stream_hash_from_crypto(ticket_state.ticket.ticket_id());
        Ok((ticket_id, routes))
    }
    fn apply_manifest_ticket_and_routes(
        &self,
        manifest: &mut ManifestV1,
    ) -> Result<(), StreamingProcessError> {
        let stream_id = manifest.stream_id;
        let segment_number = manifest.segment_number;
        let (ticket_id, routes) = self.manifest_ticket_and_routes(stream_id, segment_number)?;
        match &manifest.public_metadata.access_policy_id {
            Some(existing) if existing != &ticket_id => {
                return Err(StreamingProcessError::TicketMismatch {
                    stream: stream_id,
                    expected: ticket_id,
                    found: Some(*existing),
                });
            }
            None => manifest.public_metadata.access_policy_id = Some(ticket_id),
            _ => {}
        }
        manifest.privacy_routes = routes;
        Ok(())
    }
    fn validate_manifest_ticket_and_routes(
        &self,
        manifest: &ManifestV1,
    ) -> Result<(), StreamingProcessError> {
        let tickets = self
            .inner
            .stream_tickets
            .read()
            .map_err(|_| StreamingProcessError::StatePoisoned)?;
        let Some(ticket_state) = tickets.get(&manifest.stream_id) else {
            return Ok(());
        };
        let expected_ticket = stream_hash_from_crypto(ticket_state.ticket.ticket_id());
        match manifest.public_metadata.access_policy_id {
            Some(id) if id == expected_ticket => {}
            other => {
                return Err(StreamingProcessError::TicketMismatch {
                    stream: manifest.stream_id,
                    expected: expected_ticket,
                    found: other,
                });
            }
        }
        let mut expected_routes: Vec<PrivacyRoute> = ticket_state
            .order
            .iter()
            .filter_map(|route_id| ticket_state.routes.get(route_id))
            .map(|state| Self::convert_privacy_route(&state.route))
            .collect();
        let mut provided = manifest.privacy_routes.clone();
        expected_routes.sort_by_key(|route| route.route_id);
        provided.sort_by_key(|route| route.route_id);
        if expected_routes != provided {
            return Err(StreamingProcessError::ManifestPrivacyRoutesMismatch {
                stream: manifest.stream_id,
            });
        }
        Ok(())
    }
    fn update_route_binding_state(
        state: &mut StreamTicketState,
        binding: &StreamingRouteBinding,
    ) -> Result<(), StreamingProcessError> {
        let route_id: [u8; iroha_crypto::Hash::LENGTH] = binding.route.route_id;
        let Some(route_state) = state.routes.get_mut(&route_id) else {
            return Err(StreamingProcessError::UnknownPrivacyRoute { route_id });
        };
        route_state.route = binding.route.clone();
        route_state.last_provisioned_segment = Some(binding.valid_until_segment);
        route_state.acked = binding.acknowledged;
        Ok(())
    }
    /// Apply a streaming ticket readiness event to the in-memory state.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::MissingStreamTicket`] if the ticket has not been
    /// registered, `StreamingProcessError::DuplicatePrivacyRoute` when the payload reuses an
    /// existing route identifier, or [`StreamingProcessError::StatePoisoned`] if the internal
    /// state mutexes are poisoned.
    pub fn apply_ticket_ready(
        &self,
        ready: &StreamingTicketReady,
    ) -> Result<(), StreamingProcessError> {
        let stream_id = stream_hash_from_crypto(ready.stream_id());
        let routes: Vec<StreamingPrivacyRoute> = ready
            .routes()
            .iter()
            .map(|binding| binding.route.clone())
            .collect();
        self.register_stream_ticket(ready, routes)?;
        let mut tickets = self
            .inner
            .stream_tickets
            .write()
            .map_err(|_| StreamingProcessError::StatePoisoned)?;
        let state = tickets
            .get_mut(&stream_id)
            .ok_or(StreamingProcessError::MissingStreamTicket { stream: stream_id })?;
        for binding in ready.routes() {
            Self::update_route_binding_state(state, binding)?;
        }
        Ok(())
    }
    /// Apply a streaming ticket revocation event to the in-memory state.
    /// Record a streaming ticket revocation event and drop the associated state.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::MissingStreamTicket`] when the ticket is unknown or is
    /// associated with a different domain/stream, or [`StreamingProcessError::StatePoisoned`] if
    /// the internal state mutexes are poisoned.
    pub fn apply_ticket_revoked(
        &self,
        revoked: &StreamingTicketRevoked,
    ) -> Result<(), StreamingProcessError> {
        let stream_id = stream_hash_from_crypto(revoked.stream_id());
        let ticket_id = stream_hash_from_crypto(revoked.ticket_id());
        let nullifier = stream_hash_from_crypto(revoked.nullifier());
        if let Some(state) = self
            .inner
            .stream_tickets
            .read()
            .map_err(|_| StreamingProcessError::StatePoisoned)?
            .get(&stream_id)
        {
            let expected_ticket = stream_hash_from_crypto(state.ticket.ticket_id());
            if expected_ticket != ticket_id {
                return Err(StreamingProcessError::TicketMismatch {
                    stream: stream_id,
                    expected: expected_ticket,
                    found: Some(ticket_id),
                });
            }
            if state.domain != *revoked.domain() {
                return Err(StreamingProcessError::TicketMismatch {
                    stream: stream_id,
                    expected: expected_ticket,
                    found: Some(ticket_id),
                });
            }
            let expected_nullifier = stream_hash_from_crypto(state.ticket.nullifier());
            if expected_nullifier != nullifier {
                return Err(StreamingProcessError::TicketNullifierMismatch {
                    stream: stream_id,
                    expected: expected_nullifier,
                    found: nullifier,
                });
            }
        }
        self.unregister_stream_ticket(&stream_id)
    }
    #[cfg(feature = "quic")]
    /// Perform viewer-side transport negotiation over QUIC and record the resolved capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::Transport`] if the QUIC exchange fails or
    /// [`StreamingProcessError::StatePoisoned`] if session state is poisoned.
    pub async fn negotiate_viewer_transport(
        &self,
        peer: &Peer,
        conn: &mut StreamingConnection,
        capabilities: TransportCapabilities,
        mut report: CapabilityReport,
    ) -> Result<(CapabilityAck, TransportCapabilityResolution), StreamingProcessError> {
        report.feature_bits = self.normalize_viewer_feature_bits(report.feature_bits);
        let (ack, resolution) =
            CapabilityNegotiation::viewer_handshake(conn, capabilities, report, |_| {})
                .await
                .map_err(StreamingProcessError::Transport)?;
        self.record_transport_capabilities(peer, CapabilityRole::Viewer, resolution)?;
        self.record_negotiated_capabilities(peer, CapabilityRole::Viewer, ack.negotiated_features)?;
        Ok((ack, resolution))
    }
    #[cfg(feature = "quic")]
    /// Perform publisher-side transport negotiation over QUIC, emit the resulting acknowledgement,
    /// and record the resolved capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::Transport`] if the QUIC exchange fails or
    /// [`StreamingProcessError::StatePoisoned`] if session state is poisoned.
    pub async fn negotiate_publisher_transport(
        &self,
        peer: &Peer,
        conn: &mut StreamingConnection,
        capabilities: TransportCapabilities,
    ) -> Result<(CapabilityAck, TransportCapabilityResolution), StreamingProcessError> {
        let (report, resolution) =
            CapabilityNegotiation::publisher_handshake(conn, capabilities, |_| {})
                .await
                .map_err(StreamingProcessError::Transport)?;
        let ack = self.build_capability_ack(&report, resolution)?;
        conn.send_control_frame(&ControlFrame::CapabilityAck(ack))
            .await
            .map_err(StreamingProcessError::Transport)?;
        self.record_transport_capabilities(peer, CapabilityRole::Publisher, resolution)?;
        self.record_negotiated_capabilities(
            peer,
            CapabilityRole::Publisher,
            ack.negotiated_features,
        )?;
        Ok((ack, resolution))
    }
    #[cfg(feature = "quic")]
    fn build_capability_ack(
        &self,
        report: &CapabilityReport,
        resolution: TransportCapabilityResolution,
    ) -> Result<CapabilityAck, StreamingProcessError> {
        if report.endpoint_role != CapabilityRole::Viewer {
            return Err(StreamingProcessError::InvalidCapabilityReportRole {
                expected: CapabilityRole::Viewer,
                found: report.endpoint_role,
            });
        }
        if report.protocol_version == 0 {
            return Err(StreamingProcessError::InvalidProtocolVersion {
                found: report.protocol_version,
            });
        }
        let report_bits = report.feature_bits.bits();
        let supported_bits = self.capabilities.bits();
        let viewer_requires_privacy = (report_bits & FEATURE_PRIVACY_REQUIRED) != 0;
        let publisher_advertises_privacy = (supported_bits & FEATURE_PRIVACY_PROVIDER) != 0;
        let viewer_supports_bundled = report
            .feature_bits
            .contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED);
        if viewer_requires_privacy && !publisher_advertises_privacy {
            return Err(StreamingProcessError::PrivacyOverlayUnsupported);
        }
        if self.bundled_entropy_required() && !viewer_supports_bundled {
            return Err(StreamingProcessError::BundledEntropyUnsupported);
        }
        if self.bundled_entropy_required() {
            let accel_mask = self.bundle_accel_capability_mask();
            if accel_mask != 0 && (report_bits & accel_mask) != accel_mask {
                return Err(StreamingProcessError::BundledAccelerationUnsupported {
                    required: self.bundle_accel,
                });
            }
        }
        let allowed_viewer_bits = supported_bits | FEATURE_PRIVACY_REQUIRED;
        let unsupported = report_bits & !allowed_viewer_bits;
        if unsupported != 0 {
            return Err(StreamingProcessError::UnsupportedFeatures {
                requested_bits: unsupported,
                supported_bits,
            });
        }
        let mut negotiated_bits = report_bits & supported_bits;
        negotiated_bits |= report_bits & FEATURE_PRIVACY_REQUIRED;
        if publisher_advertises_privacy {
            negotiated_bits |= FEATURE_PRIVACY_PROVIDER;
        } else {
            negotiated_bits &= !FEATURE_PRIVACY_PROVIDER;
        }
        let negotiated_features = CapabilityFlags::from_bits(negotiated_bits);
        Ok(CapabilityAck {
            stream_id: report.stream_id,
            accepted_version: report.protocol_version,
            negotiated_features,
            max_datagram_size: resolution.max_segment_datagram_size,
            dplpmtud: report.dplpmtud,
        })
    }
    fn with_session<F, R>(
        &self,
        peer: &Peer,
        role: CapabilityRole,
        mutate: F,
    ) -> Result<R, StreamingProcessError>
    where
        F: FnOnce(&mut StreamingSession) -> Result<R, HandshakeError>,
    {
        let map = self.map_for_role(role);
        let mut guard = map
            .write()
            .map_err(|_| StreamingProcessError::StatePoisoned)?;
        let entry = guard.entry(peer.id().clone());
        let session = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let mut session = StreamingSession::new(role);
                if let Some(material) = &self.key_material {
                    material
                        .install_into_session(&mut session)
                        .map_err(StreamingProcessError::from)?;
                }
                entry.insert(session)
            }
        };
        mutate(session).map_err(StreamingProcessError::from)
    }
    fn map_for_role(&self, role: CapabilityRole) -> &RwLock<BTreeMap<PeerId, StreamingSession>> {
        match role {
            CapabilityRole::Publisher => &self.inner.publisher_sessions,
            CapabilityRole::Viewer => &self.inner.viewer_sessions,
        }
    }
    fn snapshot_role(
        &self,
        role: CapabilityRole,
        entries: &mut Vec<StreamingSnapshotEntry>,
    ) -> Result<(), StreamingProcessError> {
        let guard = self
            .map_for_role(role)
            .read()
            .map_err(|_| StreamingProcessError::StatePoisoned)?;
        for (peer, session) in guard.iter() {
            if let Some(snapshot) = session.snapshot_state() {
                let attempted = entries.len().saturating_add(1);
                if attempted > SNAPSHOT_MAX_ENTRIES_V1 {
                    return Err(StreamingProcessError::SnapshotEntryLimitExceeded {
                        attempted,
                        limit: SNAPSHOT_MAX_ENTRIES_V1,
                    });
                }
                entries.push(StreamingSnapshotEntry {
                    role,
                    peer: peer.clone(),
                    snapshot,
                });
            }
        }
        Ok(())
    }
    fn collect_snapshots(&self) -> Result<Vec<StreamingSnapshotEntry>, StreamingProcessError> {
        let mut entries = Vec::new();
        self.snapshot_role(CapabilityRole::Viewer, &mut entries)?;
        self.snapshot_role(CapabilityRole::Publisher, &mut entries)?;
        Ok(entries)
    }
    /// Persist current session snapshots to the configured path, if any.
    fn try_persist_snapshots(&self) {
        if let Err(err) = self.persist_snapshots() {
            iroha_logger::warn!(?err, "failed to persist streaming session snapshots");
        }
    }
    fn latest_gck_for_role(&self, role: CapabilityRole, peer_id: &PeerId) -> Option<Vec<u8>> {
        self.map_for_role(role).read().ok().and_then(|sessions| {
            sessions
                .get(peer_id)
                .and_then(|s| s.latest_gck().map(Vec::from))
        })
    }
    fn transport_keys_for_role(
        &self,
        role: CapabilityRole,
        peer_id: &PeerId,
    ) -> Option<TransportKeys> {
        self.map_for_role(role).read().ok().and_then(|sessions| {
            sessions
                .get(peer_id)
                .and_then(|s| s.transport_keys().copied())
        })
    }
    fn transport_capabilities_for_role(
        &self,
        role: CapabilityRole,
        peer_id: &PeerId,
    ) -> Option<TransportCapabilityResolution> {
        self.map_for_role(role).read().ok().and_then(|sessions| {
            sessions
                .get(peer_id)
                .and_then(|s| s.transport_capabilities().copied())
        })
    }
    fn capabilities_for_role(
        &self,
        role: CapabilityRole,
        peer_id: &PeerId,
    ) -> Option<CapabilityFlags> {
        self.map_for_role(role).read().ok().and_then(|sessions| {
            sessions
                .get(peer_id)
                .and_then(StreamingSession::capabilities)
        })
    }
    fn feedback_parity_for_role(&self, role: CapabilityRole, peer_id: &PeerId) -> Option<u8> {
        self.map_for_role(role).read().ok().and_then(|sessions| {
            sessions
                .get(peer_id)
                .and_then(StreamingSession::latest_feedback_parity)
        })
    }
    fn feedback_snapshot_for_role(
        &self,
        role: CapabilityRole,
        peer_id: &PeerId,
    ) -> Option<FeedbackStateSnapshot> {
        self.map_for_role(role).read().ok().and_then(|sessions| {
            sessions
                .get(peer_id)
                .and_then(StreamingSession::feedback_snapshot)
        })
    }
    /// Encode the current session snapshots and persist them to the provided path.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingSnapshotError`] if collecting the snapshots fails, no encryption key is
    /// configured, encryption fails, or the snapshots cannot be written atomically to disk.
    pub fn persist_snapshots_to_path<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<(), StreamingSnapshotError> {
        let snapshots = self.collect_snapshots()?;
        let file = StreamingSnapshotFile {
            version: SNAPSHOT_VERSION,
            entries: snapshots,
        };
        validate_snapshot_file_bounds(&file)?;
        let plaintext = norito_core::to_bytes(&file).map_err(StreamingSnapshotError::Codec)?;
        ensure_snapshot_resource_limit(
            "plaintext bytes",
            plaintext.len(),
            SNAPSHOT_MAX_PLAINTEXT_BYTES_V1,
        )?;
        let encryptor = self
            .snapshot_encryptor
            .as_ref()
            .ok_or(StreamingSnapshotError::MissingEncryptionKey)?;
        let mut bytes = Vec::new();
        encryptor.encrypt_easy_into(SNAPSHOT_AAD, plaintext.as_slice(), &mut bytes)?;
        ensure_snapshot_resource_limit(
            "ciphertext bytes",
            bytes.len(),
            SNAPSHOT_MAX_CIPHERTEXT_BYTES_V1,
        )?;
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let tmp_path = snapshot_temp_path(path);
        {
            let mut file = fs::File::create(&tmp_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        if let Err(err) = fs::rename(&tmp_path, path) {
            if err.kind() == io::ErrorKind::AlreadyExists {
                fs::remove_file(path)?;
                fs::rename(&tmp_path, path)?;
            } else {
                return Err(err.into());
            }
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                sync_dir(parent)?;
            }
        }
        Ok(())
    }
    /// Persist snapshots using the configured snapshot path, if any.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingSnapshotError`] from [`Self::persist_snapshots_to_path`] when snapshot
    /// persistence fails.
    pub fn persist_snapshots(&self) -> Result<(), StreamingSnapshotError> {
        self.snapshot_path
            .as_ref()
            .map_or(Ok(()), |path| self.persist_snapshots_to_path(path))
    }
    /// Load snapshots using the configured snapshot path, if any.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingSnapshotError`] from [`Self::load_snapshots_from_path`] when snapshot
    /// loading fails.
    pub fn load_snapshots(&self) -> Result<(), StreamingSnapshotError> {
        self.snapshot_path
            .as_ref()
            .map_or(Ok(()), |path| self.load_snapshots_from_path(path))
    }
    /// Load snapshots from disk, replacing any existing in-memory sessions.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingSnapshotError`] if the snapshot file cannot be read, decrypted, decoded,
    /// or validated against the expected version.
    pub fn load_snapshots_from_path<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<(), StreamingSnapshotError> {
        let path = path.as_ref();
        let tmp_path = snapshot_temp_path(path);
        let mut tmp_error = None;
        match read_snapshot_bytes(&tmp_path) {
            Ok(Some(bytes)) => {
                let encryptor = self
                    .snapshot_encryptor
                    .as_ref()
                    .ok_or(StreamingSnapshotError::MissingEncryptionKey)?;
                match decode_snapshot_bytes(bytes, encryptor) {
                    Ok(file) => {
                        warn!(
                            path = %tmp_path.display(),
                            "streaming snapshot temp file detected; promoting"
                        );
                        promote_snapshot_temp(&tmp_path, path);
                        self.restore_snapshots(file.entries)?;
                        return Ok(());
                    }
                    Err(err) => tmp_error = Some(err),
                }
            }
            Ok(None) => {}
            Err(err) => tmp_error = Some(err),
        }
        if let Some(err) = tmp_error.as_ref() {
            warn!(
                ?err,
                path = %tmp_path.display(),
                "streaming snapshot temp file is not usable"
            );
        }
        if let Some(bytes) = read_snapshot_bytes(path)? {
            let encryptor = self
                .snapshot_encryptor
                .as_ref()
                .ok_or(StreamingSnapshotError::MissingEncryptionKey)?;
            let file = decode_snapshot_bytes(bytes, encryptor)?;
            self.restore_snapshots(file.entries)?;
            return Ok(());
        }
        if let Some(err) = tmp_error {
            return Err(err);
        }
        Ok(())
    }
    /// Restore snapshots into the in-memory session map, creating sessions as needed.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError`] if the session map is poisoned, installing key material
    /// fails, or restoring an individual session encounters an error.
    pub fn restore_snapshots<I>(&self, entries: I) -> Result<(), StreamingProcessError>
    where
        I: IntoIterator<Item = StreamingSnapshotEntry>,
    {
        for (index, entry) in entries.into_iter().enumerate() {
            let attempted = index.saturating_add(1);
            if attempted > SNAPSHOT_MAX_ENTRIES_V1 {
                return Err(StreamingProcessError::SnapshotEntryLimitExceeded {
                    attempted,
                    limit: SNAPSHOT_MAX_ENTRIES_V1,
                });
            }
            let map = self.map_for_role(entry.role);
            let mut guard = map
                .write()
                .map_err(|_| StreamingProcessError::StatePoisoned)?;
            let needs_install = !guard.contains_key(&entry.peer);
            let session = guard
                .entry(entry.peer.clone())
                .or_insert_with(|| StreamingSession::new(entry.role));
            if needs_install {
                if let Some(material) = &self.key_material {
                    material
                        .install_into_session(session)
                        .map_err(StreamingProcessError::from)?;
                }
            }
            session
                .restore_from_snapshot(entry.snapshot)
                .map_err(StreamingProcessError::from)?;
        }
        Ok(())
    }
    fn has_publisher_session(&self, peer_id: &PeerId) -> bool {
        self.inner
            .publisher_sessions
            .read()
            .ok()
            .is_some_and(|sessions| sessions.contains_key(peer_id))
    }
    fn handle_key_update(
        &self,
        peer: &Peer,
        update: &KeyUpdate,
    ) -> Result<(), StreamingProcessError> {
        let role = if self.has_publisher_session(peer.id()) {
            CapabilityRole::Publisher
        } else {
            CapabilityRole::Viewer
        };
        let suite = self.with_session(peer, role, |session| {
            session.process_remote_key_update(update, peer.id().public_key())?;
            Ok(session.negotiated_suite().copied())
        })?;
        #[cfg(feature = "telemetry")]
        if let (Some(telemetry), Some(suite)) = (&self.telemetry, suite) {
            telemetry.record_hpke_rekey(&suite);
        }
        #[cfg(not(feature = "telemetry"))]
        let _ = suite;
        Ok(())
    }
    fn handle_content_key_update(
        &self,
        peer: &Peer,
        update: &ContentKeyUpdate,
    ) -> Result<(), StreamingProcessError> {
        let role = if self.has_publisher_session(peer.id()) {
            CapabilityRole::Publisher
        } else {
            CapabilityRole::Viewer
        };
        let suite = self.with_session(peer, role, |session| {
            let suite = session.negotiated_suite().copied();
            session.process_content_key_update(update)?;
            Ok(suite)
        })?;
        #[cfg(feature = "telemetry")]
        if let Some(telemetry) = &self.telemetry {
            telemetry.record_content_key_update(suite.as_ref(), update);
        }
        #[cfg(not(feature = "telemetry"))]
        let _ = suite;
        Ok(())
    }
    fn handle_feedback_hint(
        &self,
        peer: &Peer,
        hint: &FeedbackHintFrame,
    ) -> Result<(), StreamingProcessError> {
        let role = if self.has_publisher_session(peer.id()) {
            CapabilityRole::Publisher
        } else {
            CapabilityRole::Viewer
        };
        self.with_session(peer, role, |session| session.process_feedback_hint(hint))
    }
    fn handle_receiver_report(
        &self,
        peer: &Peer,
        report: &ReceiverReport,
    ) -> Result<(), StreamingProcessError> {
        let parity = self.with_session(peer, CapabilityRole::Publisher, |session| {
            session.process_receiver_report(report)
        })?;
        #[cfg(feature = "telemetry")]
        if let Some(telemetry) = &self.telemetry {
            telemetry.record_fec_parity(peer.id(), parity);
            if let Some(diagnostics) = &report.sync_diagnostics {
                telemetry.record_sync_diagnostics(diagnostics);
            }
        }
        #[cfg(not(feature = "telemetry"))]
        let _ = parity;
        if let Some(diagnostics) = &report.sync_diagnostics {
            if let Some(violation) = self.sync_policy.violation(diagnostics) {
                if self.sync_policy.observe_only() {
                    warn!(
                        peer = %peer.id(),
                        ?diagnostics,
                        %violation,
                        "observed streaming A/V sync violation (observe-only)"
                    );
                } else {
                    return Err(StreamingProcessError::AudioSyncViolation {
                        peer: peer.id().clone(),
                        reason: violation,
                    });
                }
            }
        }
        Ok(())
    }
    /// Retrieve the latest unwrap key (GCK) recorded for the given peer.
    #[must_use]
    pub fn latest_gck(&self, peer_id: &PeerId) -> Option<Vec<u8>> {
        self.latest_gck_for_role(CapabilityRole::Viewer, peer_id)
            .or_else(|| self.latest_gck_for_role(CapabilityRole::Publisher, peer_id))
    }
    /// Retrieve the current transport keys for the given peer, if negotiated.
    #[must_use]
    pub fn transport_keys(&self, peer_id: &PeerId) -> Option<TransportKeysSnapshot> {
        self.transport_keys_for_role(CapabilityRole::Viewer, peer_id)
            .or_else(|| self.transport_keys_for_role(CapabilityRole::Publisher, peer_id))
            .map(TransportKeysSnapshot)
    }
    /// Retrieve the negotiated transport capability hash for the given peer, if recorded.
    #[must_use]
    pub fn transport_capabilities_hash(&self, peer_id: &PeerId) -> Option<Hash> {
        self.transport_capabilities_for_role(CapabilityRole::Viewer, peer_id)
            .or_else(|| self.transport_capabilities_for_role(CapabilityRole::Publisher, peer_id))
            .map(|resolution| resolution.capabilities_hash())
    }
    /// Retrieve the negotiated transport capabilities for the given peer, if recorded.
    #[must_use]
    pub fn transport_capabilities(
        &self,
        peer_id: &PeerId,
    ) -> Option<TransportCapabilityResolution> {
        self.transport_capabilities_for_role(CapabilityRole::Viewer, peer_id)
            .or_else(|| self.transport_capabilities_for_role(CapabilityRole::Publisher, peer_id))
    }
    /// Retrieve the negotiated capability flags for the given peer, if recorded.
    #[must_use]
    pub fn negotiated_capabilities(&self, peer_id: &PeerId) -> Option<CapabilityFlags> {
        self.capabilities_for_role(CapabilityRole::Viewer, peer_id)
            .or_else(|| self.capabilities_for_role(CapabilityRole::Publisher, peer_id))
    }
    /// Populate a `FeedbackHintFrame` with the negotiated cadence and parity budget.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::MissingFeedbackParity`] if no feedback has been recorded
    /// for the peer.
    pub fn apply_feedback_hint(
        &self,
        peer_id: &PeerId,
        manifest: &ManifestV1,
        hint: &mut FeedbackHintFrame,
    ) -> Result<(), StreamingProcessError> {
        let snapshot = self.feedback_snapshot(peer_id).ok_or_else(|| {
            StreamingProcessError::MissingFeedbackParity {
                peer: peer_id.clone(),
            }
        })?;
        hint.stream_id = manifest.stream_id;
        hint.loss_ewma_q16 = snapshot.loss_ewma_q16.unwrap_or(0);
        hint.latency_gradient_q16 = snapshot.latency_gradient_q16;
        hint.observed_rtt_ms = snapshot.observed_rtt_ms;
        hint.parity_chunks = snapshot.parity_chunks;
        if hint.report_interval_ms == 0 {
            if let Some(resolution) = self
                .transport_capabilities_for_role(CapabilityRole::Publisher, peer_id)
                .or_else(|| self.transport_capabilities_for_role(CapabilityRole::Viewer, peer_id))
            {
                hint.report_interval_ms = resolution.fec_feedback_interval_ms;
            }
        }
        Ok(())
    }
    /// Populate both the manifest capabilities hash and feedback hint frame using the negotiated
    /// session state recorded for the peer.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError`] if the peer does not have negotiated transport
    /// capabilities or an associated feedback session to derive parity hints from.
    pub fn populate_manifest(
        &self,
        peer_id: &PeerId,
        manifest: &mut ManifestV1,
        hint: &mut FeedbackHintFrame,
    ) -> Result<(), StreamingProcessError> {
        self.apply_manifest_ticket_and_routes(manifest)?;
        self.ensure_manifest_entropy_mode_supported(manifest)?;
        self.apply_manifest_transport_capabilities(peer_id, manifest)?;
        self.apply_feedback_hint(peer_id, manifest, hint)?;
        Ok(())
    }
    /// Retrieve the current parity budget inferred from viewer feedback, if available.
    #[must_use]
    pub fn feedback_parity(&self, peer_id: &PeerId) -> Option<u8> {
        self.feedback_parity_for_role(CapabilityRole::Publisher, peer_id)
            .or_else(|| self.feedback_parity_for_role(CapabilityRole::Viewer, peer_id))
    }
    /// Retrieve the aggregated feedback snapshot for a peer, if available.
    #[must_use]
    pub fn feedback_snapshot(&self, peer_id: &PeerId) -> Option<FeedbackStateSnapshot> {
        self.feedback_snapshot_for_role(CapabilityRole::Publisher, peer_id)
            .or_else(|| self.feedback_snapshot_for_role(CapabilityRole::Viewer, peer_id))
    }
    /// Populate a manifest with the negotiated transport capability hash for the peer.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::MissingTransportCapabilities`] if negotiation has not
    /// completed for the specified peer.
    pub fn apply_manifest_transport_capabilities(
        &self,
        peer_id: &PeerId,
        manifest: &mut ManifestV1,
    ) -> Result<(), StreamingProcessError> {
        self.ensure_manifest_entropy_mode_negotiated(peer_id, manifest)?;
        let hash = self.transport_capabilities_hash(peer_id).ok_or_else(|| {
            StreamingProcessError::MissingTransportCapabilities {
                peer: peer_id.clone(),
            }
        })?;
        manifest.transport_capabilities_hash = hash;
        // Ensure the manifest mirrors the actual entropy/acceleration configuration even if
        // callers forget to normalise the advertised feature bits when toggling codecs.
        let normalized = self.normalize_viewer_feature_bits(self.capabilities());
        manifest.capabilities = normalized;
        manifest.entropy_tables_checksum = Some(self.bundle_tables_hash);
        Ok(())
    }
    /// Ensure the manifest's advertised transport capabilities hash matches the negotiated value.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError::MissingTransportCapabilities`] if the peer has not
    /// completed negotiation and [`StreamingProcessError::TransportCapabilitiesHashMismatch`]
    /// when the manifest hash differs from the recorded resolution.
    pub fn validate_manifest_transport_capabilities(
        &self,
        peer_id: &PeerId,
        manifest: &ManifestV1,
    ) -> Result<(), StreamingProcessError> {
        self.ensure_manifest_entropy_mode_supported(manifest)?;
        let expected = self.transport_capabilities_hash(peer_id).ok_or_else(|| {
            StreamingProcessError::MissingTransportCapabilities {
                peer: peer_id.clone(),
            }
        })?;
        if manifest.transport_capabilities_hash != expected {
            return Err(StreamingProcessError::TransportCapabilitiesHashMismatch {
                peer: peer_id.clone(),
                expected,
                found: manifest.transport_capabilities_hash,
            });
        }
        self.ensure_manifest_entropy_mode_negotiated(peer_id, manifest)?;
        Ok(())
    }
}
fn snapshot_temp_path(path: &Path) -> PathBuf {
    path.with_added_extension("tmp")
}
fn snapshot_resource_limit_error(
    resource: &'static str,
    observed: u64,
    limit: usize,
) -> StreamingSnapshotError {
    StreamingSnapshotError::ResourceLimitExceeded {
        resource,
        observed,
        limit: u64::try_from(limit).unwrap_or(u64::MAX),
    }
}
fn ensure_snapshot_resource_limit(
    resource: &'static str,
    observed: usize,
    limit: usize,
) -> Result<(), StreamingSnapshotError> {
    if observed > limit {
        return Err(snapshot_resource_limit_error(
            resource,
            u64::try_from(observed).unwrap_or(u64::MAX),
            limit,
        ));
    }
    Ok(())
}
fn validate_snapshot_file_bounds(
    file: &StreamingSnapshotFile,
) -> Result<(), StreamingSnapshotError> {
    ensure_snapshot_resource_limit("entries", file.entries.len(), SNAPSHOT_MAX_ENTRIES_V1)?;
    for entry in &file.entries {
        if let Some(gck) = entry.snapshot.latest_gck.as_ref() {
            ensure_snapshot_resource_limit(
                "group content key bytes",
                gck.len(),
                SNAPSHOT_GROUP_CONTENT_KEY_BYTES_V1,
            )?;
        }
        if let Some(public_key) = entry.snapshot.kyber_remote_public.as_ref() {
            ensure_snapshot_resource_limit(
                "remote ML-KEM public key bytes",
                public_key.len(),
                SNAPSHOT_MAX_KEM_PUBLIC_KEY_BYTES_V1,
            )?;
        }
        if let Some(public_key) = entry.snapshot.kyber_local_public.as_ref() {
            ensure_snapshot_resource_limit(
                "local ML-KEM public key bytes",
                public_key.len(),
                SNAPSHOT_MAX_KEM_PUBLIC_KEY_BYTES_V1,
            )?;
        }
    }
    Ok(())
}
fn read_snapshot_bytes(path: &Path) -> Result<Option<Vec<u8>>, StreamingSnapshotError> {
    read_snapshot_bytes_with_limit(path, SNAPSHOT_MAX_CIPHERTEXT_BYTES_V1)
}
fn read_snapshot_bytes_with_limit(
    path: &Path,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, StreamingSnapshotError> {
    let path_before = match secure_file_metadata::from_path(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    if path_before.file_type().is_symlink() || !path_before.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "streaming snapshot must be a direct regular file",
        )
        .into());
    }
    let max_bytes_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    if path_before.len() > max_bytes_u64 {
        return Err(snapshot_resource_limit_error(
            "ciphertext bytes",
            path_before.len(),
            max_bytes,
        ));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    let opened_before = secure_file_metadata::from_file(&file)?;
    if !snapshot_file_metadata_unchanged(&path_before, &opened_before) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "streaming snapshot identity changed while opening",
        )
        .into());
    }
    let capacity = usize::try_from(opened_before.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "streaming snapshot length does not fit in memory",
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    io::Read::by_ref(&mut file)
        .take(max_bytes_u64.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(snapshot_resource_limit_error(
            "ciphertext bytes",
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            max_bytes,
        ));
    }
    let opened_after = secure_file_metadata::from_file(&file)?;
    let path_after = secure_file_metadata::from_path(path)?;
    if path_after.file_type().is_symlink()
        || !path_after.is_file()
        || !snapshot_file_metadata_unchanged(&opened_before, &opened_after)
        || !snapshot_file_metadata_unchanged(&opened_before, &path_after)
        || opened_after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "streaming snapshot changed while reading",
        )
        .into());
    }
    Ok(Some(bytes))
}
fn decode_snapshot_bytes(
    mut bytes: Vec<u8>,
    encryptor: &SymmetricEncryptor<ChaCha20Poly1305>,
) -> Result<StreamingSnapshotFile, StreamingSnapshotError> {
    ensure_snapshot_resource_limit(
        "ciphertext bytes",
        bytes.len(),
        SNAPSHOT_MAX_CIPHERTEXT_BYTES_V1,
    )?;
    let plaintext = encryptor.decrypt_easy_in_place(SNAPSHOT_AAD, bytes.as_mut_slice())?;
    ensure_snapshot_resource_limit(
        "plaintext bytes",
        plaintext.len(),
        SNAPSHOT_MAX_PLAINTEXT_BYTES_V1,
    )?;
    let file = decode_snapshot_plaintext(plaintext)?;
    if file.version != SNAPSHOT_VERSION {
        return Err(StreamingSnapshotError::UnsupportedVersion {
            found: file.version,
        });
    }
    Ok(file)
}
#[cfg(unix)]
fn snapshot_file_metadata_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.is_file()
        && right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
#[cfg(windows)]
fn snapshot_file_metadata_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
    left.is_file()
        && right.is_file()
        && left.volume_serial_number().is_some()
        && left.file_index().is_some()
        && left.volume_serial_number() == right.volume_serial_number()
        && left.file_index() == right.file_index()
        && left.file_size() == right.file_size()
        && left.last_write_time() == right.last_write_time()
        && left.creation_time() == right.creation_time()
}
#[cfg(not(any(unix, windows)))]
fn snapshot_file_metadata_unchanged(_left: &SecureMetadata, _right: &SecureMetadata) -> bool {
    false
}
fn promote_snapshot_temp(tmp_path: &Path, main_path: &Path) {
    let promoted = match fs::rename(tmp_path, main_path) {
        Ok(()) => true,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            if let Err(remove_err) = fs::remove_file(main_path) {
                warn!(
                    ?remove_err,
                    path = %main_path.display(),
                    "failed to remove streaming snapshot before promotion"
                );
                false
            } else if let Err(rename_err) = fs::rename(tmp_path, main_path) {
                warn!(
                    ?rename_err,
                    path = %tmp_path.display(),
                    "failed to promote streaming snapshot temp file after removal"
                );
                false
            } else {
                true
            }
        }
        Err(err) => {
            warn!(
                ?err,
                path = %tmp_path.display(),
                "failed to promote streaming snapshot temp file"
            );
            false
        }
    };
    if promoted {
        if let Some(parent) = main_path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(err) = sync_dir(parent) {
                    warn!(
                        ?err,
                        path = %parent.display(),
                        "failed to sync streaming snapshot directory"
                    );
                }
            }
        }
    }
}
fn decode_snapshot_plaintext(
    plaintext: &[u8],
) -> Result<StreamingSnapshotFile, StreamingSnapshotError> {
    ensure_snapshot_resource_limit(
        "plaintext bytes",
        plaintext.len(),
        SNAPSHOT_MAX_PLAINTEXT_BYTES_V1,
    )?;
    if plaintext.len() < norito_core::Header::SIZE || !plaintext.starts_with(&norito_core::MAGIC) {
        return Err(StreamingSnapshotError::Codec(NoritoError::LengthMismatch));
    }
    let align = norito_core::archived_payload_align::<StreamingSnapshotFile>();
    let aligned = align_slice(plaintext, align, norito_core::Header::SIZE)?;
    let file = norito_core::with_decode_limits(SNAPSHOT_DECODE_LIMITS_V1, || {
        norito_core::from_bytes_view(aligned.as_slice()).and_then(|view| {
            view.decode_exact_with::<StreamingSnapshotFile, _, _>(
                norito_core::decode_field_canonical::<StreamingSnapshotFile>,
            )
        })
    })
    .map_err(StreamingSnapshotError::Codec)?;
    validate_snapshot_file_bounds(&file)?;
    Ok(file)
}
fn sync_dir(path: &Path) -> io::Result<()> {
    let file = fs::File::open(path)?;
    file.sync_all()
}
/// Abstraction over the transport used to deliver streaming control frames.
pub trait StreamingControlTx: Clone + Send + Sync + 'static {
    /// Send a control frame to the specified peer.
    fn send_control(&self, peer_id: &PeerId, frame: ControlFrame);
}
impl StreamingControlTx for IrohaNetwork {
    fn send_control(&self, peer_id: &PeerId, frame: ControlFrame) {
        self.post(Post {
            data: NetworkMessage::StreamingControl(Box::new(frame)),
            peer_id: peer_id.clone(),
            priority: Priority::High,
        });
    }
}
/// Helper responsible for stamping manifests with negotiated session state and delivering the
/// resulting control frames to viewers.
#[derive(Clone)]
pub struct ManifestPublisher<Tx>
where
    Tx: StreamingControlTx,
{
    streaming: StreamingHandle,
    sender: Tx,
}
impl<Tx> ManifestPublisher<Tx>
where
    Tx: StreamingControlTx,
{
    /// Construct a new manifest publisher using the provided streaming state and control-frame
    /// transport.
    #[must_use]
    pub fn new(streaming: StreamingHandle, sender: Tx) -> Self {
        Self { streaming, sender }
    }
    /// Populate manifest metadata and emit a `ManifestAnnounce` control frame.
    ///
    /// When feedback statistics are available, a `FeedbackHint` frame is emitted immediately after
    /// the manifest so viewers receive the latest parity guidance. If no feedback has been recorded
    /// yet, the publisher still transmits the manifest after stamping the negotiated transport
    /// capabilities and defers feedback until the next window.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingProcessError`] if transport capabilities are missing or the manifest could
    /// not be populated with the negotiated session state.
    pub fn announce(
        &self,
        peer: &Peer,
        manifest: ManifestV1,
        hint: Option<FeedbackHintFrame>,
    ) -> Result<(), StreamingProcessError> {
        let mut manifest = manifest;
        let mut hint = hint.unwrap_or(FeedbackHintFrame {
            stream_id: manifest.stream_id,
            loss_ewma_q16: 0,
            latency_gradient_q16: 0,
            observed_rtt_ms: 0,
            report_interval_ms: 0,
            parity_chunks: 0,
        });
        if hint.stream_id != manifest.stream_id {
            hint.stream_id = manifest.stream_id;
        }
        match self
            .streaming
            .populate_manifest(peer.id(), &mut manifest, &mut hint)
        {
            Ok(()) => {
                self.send_manifest(peer, manifest);
                self.send_feedback_hint(peer, hint);
                Ok(())
            }
            Err(StreamingProcessError::MissingFeedbackParity { .. }) => {
                self.streaming
                    .apply_manifest_transport_capabilities(peer.id(), &mut manifest)?;
                self.send_manifest(peer, manifest);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
    fn send_manifest(&self, peer: &Peer, manifest: ManifestV1) {
        self.sender.send_control(
            peer.id(),
            ControlFrame::ManifestAnnounce(Box::new(ManifestAnnounceFrame { manifest })),
        );
    }
    fn send_feedback_hint(&self, peer: &Peer, hint: FeedbackHintFrame) {
        self.sender
            .send_control(peer.id(), ControlFrame::FeedbackHint(hint));
    }
}
impl Default for StreamingHandle {
    fn default() -> Self {
        Self::new()
    }
}
/// Consume streaming-related domain events and update the runtime ticket state accordingly.
pub async fn run_ticket_event_listener(
    streaming: StreamingHandle,
    mut events: broadcast::Receiver<EventBox>,
) {
    loop {
        match events.recv().await {
            Ok(event) => {
                if let Err(err) = process_streaming_event(&streaming, event) {
                    warn!(?err, "failed to process streaming ticket event");
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(
                    skipped,
                    "dropped {skipped} streaming ticket events due to lag"
                );
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}
fn process_streaming_event(
    streaming: &StreamingHandle,
    event: EventBox,
) -> Result<(), StreamingProcessError> {
    match event {
        EventBox::Data(event) => match event.as_ref() {
            DataEvent::Domain(domain) => process_streaming_domain_event(streaming, domain),
            _ => Ok(()),
        },
        _ => Ok(()),
    }
}
fn process_streaming_domain_event(
    streaming: &StreamingHandle,
    domain: &DomainEvent,
) -> Result<(), StreamingProcessError> {
    match domain {
        DomainEvent::StreamingTicketReady(ready) => streaming.apply_ticket_ready(ready),
        DomainEvent::StreamingTicketRevoked(revoked) => streaming.apply_ticket_revoked(revoked),
        _ => Ok(()),
    }
}
/// Snapshot wrapper for transport keys to avoid leaking the internal representation.
#[derive(Clone, Copy, Debug)]
pub struct TransportKeysSnapshot(TransportKeys);
impl TransportKeysSnapshot {
    /// Viewer-side send key (broadcast to publisher).
    #[must_use]
    pub fn send(&self) -> &[u8; 32] {
        &self.0.send
    }
    /// Viewer-side receive key (used to decrypt publisher payloads).
    #[must_use]
    pub fn recv(&self) -> &[u8; 32] {
        &self.0.recv
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::parameters::defaults as config_defaults;
    use iroha_crypto::{
        Algorithm, Hash as CryptoHash, KeyPair, PublicKey,
        streaming::{
            SessionCadenceSnapshot, StreamingKeyMaterial, StreamingSessionSnapshot,
            TransportCapabilityResolutionSnapshot,
        },
    };
    use iroha_data_model::events::SharedDataEvent;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::peer::PeerId;
    use iroha_primitives::addr::SocketAddr;
    use norito::streaming::{
        CapabilityFlags, ChunkDescriptor, EncryptionSuite, EntropyMode, FecScheme,
        FeedbackHintFrame, HpkeSuite, ManifestAnnounceFrame, ManifestV1, Multiaddr,
        PrivacyBucketGranularity, PrivacyCapabilities, PrivacyRelay, PrivacyRoute,
        PrivacyRouteUpdate, ProfileId, ReceiverReport, Resolution, SoranetAccessKind,
        SoranetChannelId, SoranetRoute, SoranetStreamTag, StreamMetadata,
        TransportCapabilityResolution,
    };
    use std::{
        fs,
        path::PathBuf,
        str::FromStr,
        sync::{Arc, Mutex},
    };
    use tempfile::tempdir;
    fn checked_random_keypair() -> KeyPair {
        KeyPair::try_random().expect("generate checked streaming fixture keypair")
    }
    fn checked_random_ed25519_keypair() -> KeyPair {
        KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("generate checked streaming Ed25519 fixture keypair")
    }
    #[test]
    fn snapshot_temp_path_appends_suffix() {
        let base = Path::new("/var/lib/iroha/streaming.snap.norito");
        let tmp = snapshot_temp_path(base);
        assert_eq!(tmp, Path::new("/var/lib/iroha/streaming.snap.norito.tmp"));
    }
    #[test]
    fn snapshot_reader_enforces_exact_byte_boundary() {
        const TEST_LIMIT: usize = 64;
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("snapshot.norito");
        let exact = vec![0xA5; TEST_LIMIT];
        fs::write(&path, &exact).expect("write exact-boundary fixture");
        let bytes = read_snapshot_bytes_with_limit(&path, TEST_LIMIT)
            .expect("read exact-boundary snapshot")
            .expect("snapshot exists");
        assert_eq!(bytes, exact);
        fs::write(&path, vec![0x5A; TEST_LIMIT + 1]).expect("write oversized fixture");
        let err = read_snapshot_bytes_with_limit(&path, TEST_LIMIT)
            .expect_err("max plus one must be rejected");
        assert!(matches!(
            err,
            StreamingSnapshotError::ResourceLimitExceeded {
                resource: "ciphertext bytes",
                observed: 65,
                limit: 64,
            }
        ));
    }
    #[cfg(unix)]
    #[test]
    fn snapshot_reader_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().expect("create temp dir");
        let target = dir.path().join("target.norito");
        let link = dir.path().join("snapshot.norito");
        fs::write(&target, [0x11; 8]).expect("write target");
        symlink(&target, &link).expect("create symlink");
        let err = read_snapshot_bytes_with_limit(&link, 64)
            .expect_err("snapshot symlinks must be rejected");
        assert!(matches!(
            err,
            StreamingSnapshotError::Io(ref source)
                if source.kind() == io::ErrorKind::InvalidData
        ));
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn streaming_handle_exposes_telemetry_handle() {
        let metrics = Arc::new(crate::telemetry::Metrics::default());
        let telemetry = crate::telemetry::StreamingTelemetry::new(metrics, true);
        let handle = StreamingHandle::new();
        assert!(handle.telemetry_handle().is_none());
        let handle = handle.with_telemetry(telemetry);
        assert!(handle.telemetry_handle().is_some());
    }
    fn make_peer(key_pair: &KeyPair, port: u16) -> Peer {
        let addr = SocketAddr::from_str(&format!("127.0.0.1:{port}")).expect("valid addr");
        Peer::new(addr, key_pair.public_key().clone())
    }
    fn hash_with(byte: u8) -> Hash {
        let mut out = [0u8; 32];
        out.fill(byte);
        out
    }
    #[test]
    fn stream_hash_conversion_matches_bytes() {
        let hash = CryptoHash::new(b"stream-hash");
        let bytes = stream_hash_from_crypto(&hash);
        let expected: [u8; CryptoHash::LENGTH] = hash.into();
        assert_eq!(bytes, expected);
    }
    fn sample_resolution() -> TransportCapabilityResolution {
        TransportCapabilityResolution {
            hpke_suite: HpkeSuite::Kyber768AuthPsk,
            use_datagram: true,
            max_segment_datagram_size: 1_200,
            fec_feedback_interval_ms: 250,
            privacy_bucket_granularity: PrivacyBucketGranularity::StandardV1,
        }
    }
    fn sample_snapshot_entry(port: u16) -> StreamingSnapshotEntry {
        let key_pair = checked_random_keypair();
        let peer = make_peer(&key_pair, port);
        StreamingSnapshotEntry {
            role: CapabilityRole::Viewer,
            peer: peer.id().clone(),
            snapshot: StreamingSessionSnapshot {
                role: CapabilityRole::Viewer,
                session_id: hash_with(0x91),
                key_counter: 1,
                suite: EncryptionSuite::X25519ChaCha20Poly1305(hash_with(0x92)),
                kem_suite_id: 1,
                sts_root: hash_with(0x93),
                latest_gck: None,
                last_content_key_id: None,
                last_content_key_valid_from: None,
                cadence: None,
                transport_capabilities: None,
                negotiated_capabilities: None,
                kyber_remote_public: None,
                kyber_remote_fingerprint: None,
                kyber_local_public: None,
                kyber_local_fingerprint: None,
            },
        }
    }
    #[test]
    fn streaming_snapshot_frame_uses_its_owner_at_the_plaintext_boundary() {
        let file = StreamingSnapshotFile {
            version: SNAPSHOT_VERSION,
            entries: vec![sample_snapshot_entry(16123)],
        };
        crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
            &file,
            "iroha_core::streaming::StreamingSnapshotFile",
        );
        let frame = norito::encode_canonical(&file).expect("canonical streaming snapshot frame");
        assert_eq!(
            decode_snapshot_plaintext(&frame).expect("bounded production plaintext decoder"),
            file
        );
        let mut wrong_owner = frame.clone();
        wrong_owner[6..22].copy_from_slice(&norito::schema::identity::frame_hash::<CryptoHash>());
        assert!(matches!(
            decode_snapshot_plaintext(&wrong_owner),
            Err(StreamingSnapshotError::Codec(NoritoError::SchemaMismatch))
        ));
        assert!(decode_snapshot_plaintext(&frame[..frame.len() - 1]).is_err());
        let mut trailing = frame;
        trailing.push(0);
        assert!(decode_snapshot_plaintext(&trailing).is_err());
    }
    fn sample_manifest() -> ManifestV1 {
        ManifestV1 {
            stream_id: hash_with(0x11),
            protocol_version: 1,
            segment_number: 7,
            published_at: 1_702_000_000,
            profile: ProfileId::BASELINE,
            entropy_mode: EntropyMode::RansBundled,
            entropy_tables_checksum: Some(default_bundle_tables().checksum()),
            da_endpoint: Multiaddr::from("/ip4/127.0.0.1/udp/9000/quic"),
            chunk_root: hash_with(0x22),
            content_key_id: 42,
            nonce_salt: hash_with(0x33),
            chunk_descriptors: vec![ChunkDescriptor {
                chunk_id: 0,
                offset: 0,
                length: 1,
                commitment: hash_with(0x44),
                parity: false,
            }],
            transport_capabilities_hash: [0; 32],
            encryption_suite: EncryptionSuite::X25519ChaCha20Poly1305(hash_with(0x55)),
            fec_suite: FecScheme::Rs12_10,
            privacy_routes: Vec::new(),
            neural_bundle: None,
            audio_summary: None,
            public_metadata: StreamMetadata {
                title: "Sample Stream".into(),
                description: None,
                access_policy_id: None,
                tags: vec!["nsc".into()],
            },
            capabilities: CapabilityFlags::from_bits(
                0b101 | CapabilityFlags::FEATURE_ENTROPY_BUNDLED,
            ),
            signature: [0xAA; 64],
        }
    }
    fn sample_domain_id(name: &str) -> DomainId {
        DomainId::try_new(name, "universal").expect("domain id")
    }
    fn repo_rans_tables_path() -> PathBuf {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        while !dir.join("Cargo.lock").exists() {
            let parent = dir
                .parent()
                .expect("workspace root should contain Cargo.lock")
                .to_path_buf();
            dir = parent;
        }
        dir.join("codec/rans/tables/rans_seed0.toml")
    }
    #[test]
    fn codec_config_loads_default_bundle_tables() {
        let mut handle = StreamingHandle::new();
        let mut codec = actual::StreamingCodec::from_defaults();
        codec.rans_tables_path = repo_rans_tables_path();
        handle
            .apply_codec_config(&codec)
            .expect("default bundle tables must load");
        assert_eq!(
            handle.entropy_mode, codec.entropy_mode,
            "codec config must update entropy mode"
        );
        let expected_tables =
            load_bundle_tables_from_toml(&codec.rans_tables_path).expect("bundle tables");
        assert_eq!(
            handle.bundle_tables.precision_bits(),
            default_bundle_tables().precision_bits(),
            "handle should cache loaded bundle tables"
        );
        assert_eq!(
            handle.bundle_tables_checksum(),
            expected_tables.checksum(),
            "bundle table checksum should reflect loaded artefact"
        );
    }
    #[test]
    fn codec_config_reports_missing_bundle_tables() {
        let mut handle = StreamingHandle::new();
        let dir = tempdir().expect("tempdir");
        let mut codec = actual::StreamingCodec::from_defaults();
        codec.rans_tables_path = dir.path().join("missing_tables.toml");
        let err = handle
            .apply_codec_config(&codec)
            .expect_err("should error for missing tables");
        match err {
            StreamingCodecConfigError::BundleTables { path, .. } => {
                assert_eq!(path, codec.rans_tables_path);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn codec_config_rejects_bundle_width_above_tables() {
        let mut handle = StreamingHandle::new();
        let mut codec = actual::StreamingCodec::from_defaults();
        codec.rans_tables_path = repo_rans_tables_path();
        codec.entropy_mode = EntropyMode::RansBundled;
        codec.bundle_width = 5;
        let err = handle
            .apply_codec_config(&codec)
            .expect_err("width above tables should error");
        match err {
            StreamingCodecConfigError::BundleWidth {
                requested,
                available,
            } => {
                assert_eq!(requested, 5);
                assert_eq!(available, 3);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn codec_config_sets_cpu_bundle_acceleration_capabilities() {
        let mut handle = StreamingHandle::new();
        let mut codec = actual::StreamingCodec::from_defaults();
        codec.rans_tables_path = repo_rans_tables_path();
        codec.entropy_mode = EntropyMode::RansBundled;
        codec.bundle_accel = actual::BundleAcceleration::CpuSimd;
        handle
            .apply_codec_config(&codec)
            .expect("cpu-accelerated bundled config must load");
        assert!(
            handle
                .capabilities
                .contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            "bundled manifests must advertise FEATURE_ENTROPY_BUNDLED"
        );
        assert!(
            handle
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "cpu-accelerated manifests must advertise FEATURE_BUNDLE_ACCEL_CPU_SIMD"
        );
        assert!(
            !handle
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
            "cpu-only configs must not leak GPU capability bits"
        );
    }
    #[test]
    fn codec_config_sets_gpu_bundle_acceleration_capabilities() {
        let mut handle = StreamingHandle::new();
        let mut codec = actual::StreamingCodec::from_defaults();
        codec.rans_tables_path = repo_rans_tables_path();
        codec.entropy_mode = EntropyMode::RansBundled;
        codec.bundle_accel = actual::BundleAcceleration::Gpu;
        let result = handle.apply_codec_config(&codec);
        if !norito::streaming::BUNDLED_RANS_GPU_BUILD_AVAILABLE {
            let err = result.expect_err("cpu-only builds must reject GPU bundle acceleration");
            match err {
                StreamingCodecConfigError::BundleAccelerationUnavailable { requested } => {
                    assert_eq!(requested, actual::BundleAcceleration::Gpu);
                }
                other => panic!("unexpected error: {other:?}"),
            }
            return;
        }
        result.expect("gpu-accelerated bundled config must load");
        assert!(
            handle
                .capabilities
                .contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            "bundled manifests must advertise FEATURE_ENTROPY_BUNDLED"
        );
        assert!(
            handle
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
            "gpu-accelerated manifests must advertise FEATURE_BUNDLE_ACCEL_GPU"
        );
        assert!(
            !handle
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "gpu configs must not leak CPU capability bits"
        );
    }
    #[test]
    fn normalize_viewer_bits_reflects_handle_capabilities() {
        let mut handle = StreamingHandle::new();
        handle.entropy_mode = EntropyMode::RansBundled;
        handle.bundle_accel = actual::BundleAcceleration::CpuSimd;
        let viewer_bits = CapabilityFlags::from_bits(0);
        let normalized = handle.normalize_viewer_feature_bits(viewer_bits);
        assert!(
            normalized.contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            "bundled handles must force FEATURE_ENTROPY_BUNDLED"
        );
        assert!(
            normalized.contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "bundled handles must propagate the configured acceleration bit"
        );
        assert!(
            !normalized.contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
            "cpu handles must not leak GPU capability bits"
        );
    }
    #[test]
    fn normalize_viewer_bits_clear_unavailable_capabilities() {
        let mut handle = StreamingHandle::new();
        handle.entropy_mode = EntropyMode::RansBundled;
        handle.bundle_accel = actual::BundleAcceleration::None;
        let viewer_bits = CapabilityFlags::from_bits(
            CapabilityFlags::FEATURE_ENTROPY_BUNDLED
                | CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD
                | CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU,
        );
        let normalized = handle.normalize_viewer_feature_bits(viewer_bits);
        assert!(
            normalized.contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            "bundled handles must enforce bundled entropy capability bits"
        );
        assert!(
            !normalized.contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "handles without acceleration must strip CPU acceleration bits"
        );
        assert!(
            !normalized.contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
            "handles without acceleration must strip GPU acceleration bits"
        );
    }
    fn sample_privacy_route() -> PrivacyRoute {
        PrivacyRoute {
            route_id: hash_with(0x90),
            entry: PrivacyRelay {
                relay_id: hash_with(0x91),
                endpoint: Multiaddr::from("/ip4/127.0.0.1/udp/9100/quic"),
                key_fingerprint: hash_with(0x92),
                capabilities: PrivacyCapabilities::from_bits(0b001),
            },
            exit: PrivacyRelay {
                relay_id: hash_with(0x93),
                endpoint: Multiaddr::from("/ip4/127.0.0.1/udp/9200/quic"),
                key_fingerprint: hash_with(0x94),
                capabilities: PrivacyCapabilities::from_bits(0b010),
            },
            ticket_entry: vec![0xE1, 0xE2],
            ticket_exit: vec![0xF1, 0xF2],
            expiry_segment: 1_000,
            soranet: None,
        }
    }
    fn streaming_route_from_privacy(route: &PrivacyRoute) -> StreamingPrivacyRoute {
        StreamingPrivacyRoute::from(route.clone())
    }
    #[test]
    fn process_streaming_event_registers_ticket_from_ready_event() {
        let handle = StreamingHandle::new();
        let ready = sample_ticket_ready("stream-ready", 0xA0, 0xB0);
        let stream_key = stream_hash_from_crypto(ready.stream_id());
        let event = EventBox::Data(SharedDataEvent::from(DataEvent::Domain(
            DomainEvent::StreamingTicketReady(ready),
        )));
        process_streaming_event(&handle, event).expect("ready event processed");
        let tickets = handle
            .inner
            .stream_tickets
            .read()
            .expect("ticket state lock");
        assert!(tickets.contains_key(&stream_key));
    }
    #[test]
    fn process_streaming_event_revokes_ticket() {
        let handle = StreamingHandle::new();
        let ready = sample_ticket_ready("stream-revoke", 0xC0, 0xD0);
        let stream_key = stream_hash_from_crypto(ready.stream_id());
        let ready_event = EventBox::Data(SharedDataEvent::from(DataEvent::Domain(
            DomainEvent::StreamingTicketReady(ready.clone()),
        )));
        process_streaming_event(&handle, ready_event).expect("ready event processed");
        {
            let tickets = handle
                .inner
                .stream_tickets
                .read()
                .expect("ticket state lock");
            assert!(tickets.contains_key(&stream_key));
        }
        let revoked = StreamingTicketRevoked::new(
            ready.domain().clone(),
            *ready.stream_id(),
            *ready.ticket_id(),
            *ready.ticket().nullifier(),
            17,
            [0xCC; 64],
        );
        let revoked_event = EventBox::Data(SharedDataEvent::from(DataEvent::Domain(
            DomainEvent::StreamingTicketRevoked(revoked),
        )));
        process_streaming_event(&handle, revoked_event).expect("revoked event processed");
        let tickets = handle
            .inner
            .stream_tickets
            .read()
            .expect("ticket state lock");
        assert!(!tickets.contains_key(&stream_key));
    }
    fn sample_ticket_ready(domain: &str, stream_seed: u8, ticket_seed: u8) -> StreamingTicketReady {
        let binding = StreamingRouteBinding::new(
            streaming_route_from_privacy(&sample_privacy_route()),
            0,
            32,
            true,
        );
        let owner_key: PublicKey =
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
                .parse()
                .expect("public key literal");
        let owner = iroha_data_model::account::AccountId::new(owner_key);
        let ticket = data_events::StreamingTicketRecord {
            ticket_id: iroha_crypto::Hash::prehashed(hash_with(ticket_seed)),
            owner,
            dsid: iroha_model_base::topology::DataSpaceId::new(7),
            lane_id: iroha_model_base::topology::LaneId::new(5),
            settlement_bucket: 2_048,
            start_slot: 21_000,
            expire_slot: 24_000,
            prepaid_teu: 120_000,
            chunk_teu: 64,
            fanout_quota: 12,
            key_commitment: iroha_crypto::Hash::prehashed(hash_with(ticket_seed.wrapping_add(1))),
            nonce: 42,
            contract_signature: [0x66; 64],
            commitment: iroha_crypto::Hash::prehashed(hash_with(ticket_seed.wrapping_add(2))),
            nullifier: iroha_crypto::Hash::prehashed(hash_with(ticket_seed.wrapping_add(3))),
            proof_id: hash_with(ticket_seed.wrapping_add(4)),
            issued_at: 1_701_234_567,
            expires_at: 1_701_834_567,
            policy: Some(data_events::StreamingTicketPolicy::new(
                4,
                vec!["us".into(), "jp".into()],
                Some(15_000),
            )),
            capabilities: data_events::StreamingTicketCapabilities::from_bits(
                data_events::StreamingTicketCapabilities::LIVE
                    | data_events::StreamingTicketCapabilities::HDR,
            ),
        };
        StreamingTicketReady::new(
            sample_domain_id(domain),
            iroha_crypto::Hash::prehashed(hash_with(stream_seed)),
            ticket,
            vec![binding],
        )
    }
    fn make_privacy_relay(seed: u8, capabilities: u32) -> PrivacyRelay {
        PrivacyRelay {
            relay_id: hash_with(seed),
            endpoint: Multiaddr::from(format!("/dns/relay-{seed}.nsc/quic")),
            key_fingerprint: hash_with(seed.wrapping_add(1)),
            capabilities: PrivacyCapabilities::from_bits(capabilities),
        }
    }
    fn privacy_route_with_seed(route_seed: u8, expiry_segment: u64) -> PrivacyRoute {
        PrivacyRoute {
            route_id: hash_with(route_seed),
            entry: make_privacy_relay(route_seed.wrapping_add(1), 0b001),
            exit: make_privacy_relay(route_seed.wrapping_add(2), 0b010),
            ticket_entry: vec![
                route_seed,
                route_seed.wrapping_add(3),
                route_seed.wrapping_add(6),
            ],
            ticket_exit: vec![
                route_seed.wrapping_add(9),
                route_seed.wrapping_add(12),
                route_seed.wrapping_add(15),
            ],
            expiry_segment,
            soranet: None,
        }
    }
    fn soranet_privacy_route(route_seed: u8, expiry_segment: u64) -> PrivacyRoute {
        let mut route = privacy_route_with_seed(route_seed, expiry_segment);
        route.soranet = Some(SoranetRoute {
            channel_id: SoranetChannelId::new(hash_with(route_seed.wrapping_add(3))),
            exit_multiaddr: Multiaddr::from(format!(
                "/dns/exit-{route_seed}.soranet.example/udp/9443/quic"
            )),
            padding_budget_ms: Some(25),
            access_kind: SoranetAccessKind::Authenticated,
            stream_tag: SoranetStreamTag::NoritoStream,
        });
        route
    }
    #[derive(Clone, Default)]
    struct TestControlTx {
        frames: Arc<Mutex<Vec<(PeerId, ControlFrame)>>>,
    }
    impl TestControlTx {
        fn frames(&self) -> Vec<(PeerId, ControlFrame)> {
            self.frames.lock().expect("frames lock").clone()
        }
    }
    impl StreamingControlTx for TestControlTx {
        fn send_control(&self, peer_id: &PeerId, frame: ControlFrame) {
            self.frames
                .lock()
                .expect("frames lock")
                .push((peer_id.clone(), frame));
        }
    }
    #[test]
    fn publisher_viewer_gck_roundtrip() {
        let publisher_keys = checked_random_keypair();
        let viewer_keys = checked_random_keypair();
        let publisher_peer = make_peer(&publisher_keys, 12001);
        let viewer_peer = make_peer(&viewer_keys, 12002);
        let session_id = hash_with(0x11);
        let suite = EncryptionSuite::X25519ChaCha20Poly1305(hash_with(0x22));
        let protocol_version = 1;
        let handle_publisher = StreamingHandle::new();
        let handle_viewer = StreamingHandle::new();
        let publisher_update = handle_publisher
            .build_key_update(
                &viewer_peer,
                CapabilityRole::Publisher,
                &KeyUpdateSpec {
                    session_id,
                    suite: &suite,
                    protocol_version,
                    key_counter: 1,
                },
                publisher_keys.private_key(),
            )
            .expect("publisher key update");
        let publisher_frame = ControlFrame::KeyUpdate(publisher_update.clone());
        handle_viewer
            .process_control_frame(&publisher_peer, &publisher_frame)
            .expect("viewer processes publisher KeyUpdate");
        let viewer_update = handle_viewer
            .build_key_update(
                &publisher_peer,
                CapabilityRole::Viewer,
                &KeyUpdateSpec {
                    session_id,
                    suite: &suite,
                    protocol_version,
                    key_counter: 2,
                },
                viewer_keys.private_key(),
            )
            .expect("viewer key update");
        let viewer_frame = ControlFrame::KeyUpdate(viewer_update);
        handle_publisher
            .process_control_frame(&viewer_peer, &viewer_frame)
            .expect("publisher processes viewer KeyUpdate");
        let resolution = sample_resolution();
        handle_publisher
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Publisher, resolution)
            .expect("publisher records capabilities");
        handle_viewer
            .record_transport_capabilities(&publisher_peer, CapabilityRole::Viewer, resolution)
            .expect("viewer records capabilities");
        assert!(
            handle_publisher.transport_keys(viewer_peer.id()).is_some(),
            "publisher should have negotiated transport keys"
        );
        assert!(
            handle_viewer.transport_keys(publisher_peer.id()).is_some(),
            "viewer should have negotiated transport keys"
        );
        assert_eq!(
            handle_publisher.transport_capabilities_hash(viewer_peer.id()),
            Some(resolution.capabilities_hash())
        );
        assert_eq!(
            handle_viewer.transport_capabilities_hash(publisher_peer.id()),
            Some(resolution.capabilities_hash())
        );
        let gck = vec![0xAB; 32];
        let content_update = handle_publisher
            .build_content_key_update(&viewer_peer, &gck, 1, 42)
            .expect("publisher content key update");
        let publisher_gck = handle_publisher
            .latest_gck(viewer_peer.id())
            .expect("publisher stores latest gck");
        assert_eq!(publisher_gck, gck);
        let content_frame = ControlFrame::ContentKeyUpdate(content_update);
        handle_viewer
            .process_control_frame(&publisher_peer, &content_frame)
            .expect("viewer processes content key update");
        let viewer_gck = handle_viewer
            .latest_gck(publisher_peer.id())
            .expect("viewer stores latest gck");
        assert_eq!(viewer_gck, gck);
        let duplicate_err = handle_publisher
            .build_content_key_update(&viewer_peer, &gck, 1, 84)
            .expect_err("non-monotonic content key id must fail");
        assert!(matches!(duplicate_err, StreamingProcessError::Handshake(_)));
    }
    #[test]
    fn content_key_update_requires_negotiation() {
        let handle = StreamingHandle::new();
        let publisher_keys = checked_random_keypair();
        let remote_peer = make_peer(&publisher_keys, 13000);
        let gck = vec![0x44; 32];
        let err = handle
            .build_content_key_update(&remote_peer, &gck, 1, 1)
            .expect_err("suite must be negotiated first");
        assert!(matches!(
            err,
            StreamingProcessError::Handshake(
                HandshakeError::SuiteNotNegotiated | HandshakeError::MissingTransportKeys
            )
        ));
    }
    #[test]
    fn build_key_update_with_material_requires_config() {
        let handle = StreamingHandle::new();
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 15000);
        let suite = EncryptionSuite::X25519ChaCha20Poly1305(hash_with(0x33));
        let session_id = hash_with(0x44);
        let err = handle
            .build_key_update_with_material(
                &viewer_peer,
                CapabilityRole::Publisher,
                &KeyUpdateSpec {
                    session_id,
                    suite: &suite,
                    protocol_version: 1,
                    key_counter: 1,
                },
            )
            .expect_err("missing key material must be reported");
        assert!(matches!(err, StreamingProcessError::MissingKeyMaterial));
    }
    #[test]
    fn build_key_update_with_material_uses_identity() {
        let publisher_keys = checked_random_ed25519_keypair();
        let viewer_keys = checked_random_keypair();
        let publisher_peer = make_peer(&publisher_keys, 15001);
        let viewer_peer = make_peer(&viewer_keys, 15002);
        let suite = EncryptionSuite::X25519ChaCha20Poly1305(hash_with(0x77));
        let session_id = hash_with(0x88);
        let material =
            StreamingKeyMaterial::new(publisher_keys.clone()).expect("ed25519 identity required");
        let publisher_handle = StreamingHandle::with_key_material(material);
        let key_update = publisher_handle
            .build_key_update_with_material(
                &viewer_peer,
                CapabilityRole::Publisher,
                &KeyUpdateSpec {
                    session_id,
                    suite: &suite,
                    protocol_version: 1,
                    key_counter: 1,
                },
            )
            .expect("publisher key update");
        let viewer_handle = StreamingHandle::new();
        let key_update_frame = ControlFrame::KeyUpdate(key_update);
        viewer_handle
            .process_control_frame(&publisher_peer, &key_update_frame)
            .expect("viewer processes key update");
    }
    #[test]
    fn records_transport_capabilities_and_exposes_hash() {
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13500);
        let handle = StreamingHandle::new();
        let resolution = sample_resolution();
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Viewer, resolution)
            .expect("record capabilities");
        handle
            .record_negotiated_capabilities(
                &viewer_peer,
                CapabilityRole::Viewer,
                CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            )
            .expect("record negotiated capabilities");
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Publisher, resolution)
            .expect("record publisher capabilities");
        handle
            .record_negotiated_capabilities(
                &viewer_peer,
                CapabilityRole::Publisher,
                CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            )
            .expect("record publisher negotiated capabilities");
        handle
            .record_negotiated_capabilities(
                &viewer_peer,
                CapabilityRole::Viewer,
                CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            )
            .expect("record negotiated capabilities");
        assert_eq!(
            handle.transport_capabilities_hash(viewer_peer.id()),
            Some(resolution.capabilities_hash())
        );
    }
    #[test]
    fn rejects_invalid_transport_capabilities_without_overwriting_hash() {
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13550);
        let handle = StreamingHandle::new();
        let valid = sample_resolution();
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Viewer, valid)
            .expect("record valid capabilities");
        for (invalid_transport, expected_reason) in [
            (
                TransportCapabilityResolution {
                    use_datagram: true,
                    max_segment_datagram_size: 0,
                    ..valid
                },
                "datagram transport resolution requires nonzero datagram size",
            ),
            (
                TransportCapabilityResolution {
                    use_datagram: false,
                    max_segment_datagram_size: 1_200,
                    ..valid
                },
                "stream transport resolution must not carry datagram size",
            ),
        ] {
            let err = handle
                .record_transport_capabilities(
                    &viewer_peer,
                    CapabilityRole::Viewer,
                    invalid_transport,
                )
                .expect_err("invalid transport capabilities rejected");
            match err {
                StreamingProcessError::Handshake(HandshakeError::InvalidTransportCapabilities(
                    reason,
                )) => {
                    assert!(reason.contains(expected_reason));
                }
                other => panic!("unexpected error: {other:?}"),
            }
            assert_eq!(handle.transport_capabilities(viewer_peer.id()), Some(valid));
            assert_eq!(
                handle.transport_capabilities_hash(viewer_peer.id()),
                Some(valid.capabilities_hash())
            );
        }
    }
    #[test]
    fn default_capabilities_match_config_default() {
        let handle = StreamingHandle::new();
        assert_eq!(
            handle.capabilities().bits(),
            config_defaults::streaming::FEATURE_BITS,
            "StreamingHandle::new should seed capability mask from defaults",
        );
        let kp = checked_random_ed25519_keypair();
        let material = StreamingKeyMaterial::new(kp).expect("material");
        let handle_with_material = StreamingHandle::with_key_material(material);
        assert_eq!(
            handle_with_material.capabilities().bits(),
            config_defaults::streaming::FEATURE_BITS,
            "StreamingHandle::with_key_material should seed capability mask from defaults",
        );
    }
    #[test]
    fn validate_manifest_detects_hash_mismatch() {
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13600);
        let handle = StreamingHandle::new();
        let resolution = sample_resolution();
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Viewer, resolution)
            .expect("record capabilities");
        handle
            .record_negotiated_capabilities(
                &viewer_peer,
                CapabilityRole::Viewer,
                CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            )
            .expect("record negotiated capabilities");
        let mut manifest = sample_manifest();
        handle
            .apply_manifest_transport_capabilities(viewer_peer.id(), &mut manifest)
            .expect("apply hash");
        manifest.transport_capabilities_hash = hash_with(0xFE);
        let err = handle
            .validate_manifest_transport_capabilities(viewer_peer.id(), &manifest)
            .expect_err("mismatch must raise error");
        assert!(matches!(
            err,
            StreamingProcessError::TransportCapabilitiesHashMismatch { .. }
        ));
    }
    #[test]
    fn process_control_frame_rejects_invalid_manifest() {
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13700);
        let handle = StreamingHandle::new();
        let resolution = sample_resolution();
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Viewer, resolution)
            .expect("record capabilities");
        handle
            .record_negotiated_capabilities(
                &viewer_peer,
                CapabilityRole::Viewer,
                CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            )
            .expect("record negotiated capabilities");
        let mut manifest = sample_manifest();
        manifest.transport_capabilities_hash = hash_with(0xEE);
        let frame = ControlFrame::ManifestAnnounce(Box::new(ManifestAnnounceFrame { manifest }));
        let err = handle
            .process_control_frame(&viewer_peer, &frame)
            .expect_err("manifest hash mismatch must be reported");
        assert!(matches!(
            err,
            StreamingProcessError::TransportCapabilitiesHashMismatch { .. }
        ));
    }
    #[test]
    fn process_control_frame_accepts_valid_manifest() {
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13800);
        let handle = StreamingHandle::new();
        let resolution = sample_resolution();
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Viewer, resolution)
            .expect("record capabilities");
        handle
            .record_negotiated_capabilities(
                &viewer_peer,
                CapabilityRole::Viewer,
                CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            )
            .expect("record negotiated capabilities");
        let mut manifest = sample_manifest();
        handle
            .apply_manifest_transport_capabilities(viewer_peer.id(), &mut manifest)
            .expect("apply hash");
        let frame = ControlFrame::ManifestAnnounce(Box::new(ManifestAnnounceFrame { manifest }));
        handle
            .process_control_frame(&viewer_peer, &frame)
            .expect("valid manifest must be accepted");
    }
    #[test]
    fn feedback_frames_update_handle_parity() {
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13850);
        let handle = StreamingHandle::new();
        let resolution = sample_resolution();
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Viewer, resolution)
            .expect("record capabilities");
        let hint = FeedbackHintFrame {
            stream_id: hash_with(0x99),
            loss_ewma_q16: 5_243,
            latency_gradient_q16: 0,
            observed_rtt_ms: 42,
            report_interval_ms: 0,
            parity_chunks: 0,
        };
        let report = ReceiverReport {
            stream_id: hint.stream_id,
            latest_segment: 8,
            layer_mask: 0,
            measured_throughput_kbps: 1_400,
            rtt_ms: 45,
            loss_percent_x100: 700,
            decoder_buffer_ms: 100,
            active_resolution: Resolution::R720p,
            hdr_active: false,
            ecn_ce_count: 0,
            jitter_ms: 5,
            delivered_sequence: 256,
            parity_applied: 1,
            fec_budget: 1,
            sync_diagnostics: None,
        };
        handle
            .process_control_frame(&viewer_peer, &ControlFrame::FeedbackHint(hint))
            .expect("feedback hint accepted");
        handle
            .process_control_frame(&viewer_peer, &ControlFrame::ReceiverReport(report))
            .expect("receiver report accepted");
        assert_eq!(handle.feedback_parity(viewer_peer.id()), Some(2));
        // Refresh negotiated state to mirror a completed capability handshake before stamping manifests.
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Viewer, resolution)
            .expect("record capabilities before manifest");
        handle
            .record_negotiated_capabilities(
                &viewer_peer,
                CapabilityRole::Viewer,
                CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            )
            .expect("record negotiated capabilities before manifest");
        let ready = sample_ticket_ready("feedback-parity", 0x11, 0xA0);
        handle
            .apply_ticket_ready(&ready)
            .expect("ticket ready must register before manifest");
        let mut outbound_hint = FeedbackHintFrame {
            stream_id: Hash::default(),
            loss_ewma_q16: 0,
            latency_gradient_q16: 0,
            observed_rtt_ms: 0,
            report_interval_ms: 0,
            parity_chunks: 0,
        };
        let mut manifest = sample_manifest();
        manifest.transport_capabilities_hash = [0; 32];
        handle
            .populate_manifest(viewer_peer.id(), &mut manifest, &mut outbound_hint)
            .expect("populate manifest and hint");
        assert_eq!(
            manifest.transport_capabilities_hash,
            resolution.capabilities_hash()
        );
        assert_eq!(
            outbound_hint.report_interval_ms,
            resolution.fec_feedback_interval_ms
        );
        assert_eq!(outbound_hint.parity_chunks, 2);
    }
    #[test]
    fn apply_ticket_ready_populates_manifest_routes() {
        let handle = StreamingHandle::new();
        let mut manifest = sample_manifest();
        let route = streaming_route_from_privacy(&sample_privacy_route());
        let base_ready = sample_ticket_ready("route-ready", 0x11, 0xA0);
        let binding = StreamingRouteBinding::new(route.clone(), 0, 16, true);
        let ready = StreamingTicketReady::new(
            base_ready.domain().clone(),
            *base_ready.stream_id(),
            base_ready.ticket().clone(),
            vec![binding],
        );
        let ticket_id = stream_hash_from_crypto(ready.ticket_id());
        handle
            .apply_ticket_ready(&ready)
            .expect("ticket ready must apply");
        handle
            .apply_manifest_ticket_and_routes(&mut manifest)
            .expect("manifest populated");
        assert_eq!(manifest.public_metadata.access_policy_id, Some(ticket_id));
        assert_eq!(manifest.privacy_routes.len(), 1);
        let expected_route_id: [u8; iroha_crypto::Hash::LENGTH] = route.route_id;
        assert_eq!(manifest.privacy_routes[0].route_id, expected_route_id);
    }
    #[test]
    fn invalid_ticket_replacement_preserves_prior_authoritative_state() {
        let handle = StreamingHandle::new();
        let ready = sample_ticket_ready("replacement-state", 0x31, 0xA4);
        let stream_id = stream_hash_from_crypto(ready.stream_id());
        let nullifier = stream_hash_from_crypto(ready.ticket().nullifier());
        let original = streaming_route_from_privacy(&sample_privacy_route());
        let original_route_id = original.route_id;
        handle
            .register_stream_ticket(&ready, vec![original])
            .expect("register original ticket");

        let mut duplicate = streaming_route_from_privacy(&sample_privacy_route());
        duplicate.route_id = hash_with(0xA6);
        let duplicate_route_id = duplicate.route_id;
        let error = handle
            .register_stream_ticket(&ready, vec![duplicate.clone(), duplicate])
            .expect_err("duplicate replacement must fail");
        assert!(matches!(
            error,
            StreamingProcessError::DuplicatePrivacyRoute { route_id, stream }
                if route_id == duplicate_route_id && stream == stream_id
        ));

        let tickets = handle
            .inner
            .stream_tickets
            .read()
            .expect("ticket state lock");
        let retained = tickets.get(&stream_id).expect("original ticket retained");
        assert_eq!(retained.order, vec![original_route_id]);
        assert!(retained.routes.contains_key(&original_route_id));
        drop(tickets);
        assert_eq!(
            handle
                .inner
                .route_index
                .read()
                .expect("route index lock")
                .get(&original_route_id),
            Some(&stream_id)
        );
        assert_eq!(
            handle
                .inner
                .ticket_nullifiers
                .read()
                .expect("nullifier lock")
                .get(&nullifier),
            Some(&stream_id)
        );
    }
    #[test]
    fn apply_manifest_requires_acknowledged_routes() {
        let handle = StreamingHandle::new();
        let mut manifest = sample_manifest();
        let route = streaming_route_from_privacy(&sample_privacy_route());
        let base_ready = sample_ticket_ready("route-ready", 0x11, 0xA1);
        let binding = StreamingRouteBinding::new(route.clone(), 0, 8, false);
        let ready = StreamingTicketReady::new(
            base_ready.domain().clone(),
            *base_ready.stream_id(),
            base_ready.ticket().clone(),
            vec![binding],
        );
        handle
            .apply_ticket_ready(&ready)
            .expect("ticket ready must apply");
        let err = handle
            .apply_manifest_ticket_and_routes(&mut manifest)
            .expect_err("manifest must require acknowledged routes");
        match err {
            StreamingProcessError::PrivacyRouteUnacknowledged { route_id } => {
                let expected_route_id: [u8; iroha_crypto::Hash::LENGTH] = route.route_id;
                assert_eq!(route_id, expected_route_id);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn ticket_revoked_removes_registered_state() {
        let handle = StreamingHandle::new();
        let mut manifest = sample_manifest();
        let stream_id = manifest.stream_id;
        let route = streaming_route_from_privacy(&sample_privacy_route());
        let base_ready = sample_ticket_ready("route-ready", 0x11, 0xA2);
        let binding = StreamingRouteBinding::new(route, 0, 32, true);
        let domain_id = sample_domain_id("route-ready");
        let ready = StreamingTicketReady::new(
            domain_id.clone(),
            *base_ready.stream_id(),
            base_ready.ticket().clone(),
            vec![binding],
        );
        handle.apply_ticket_ready(&ready).expect("ticket ready");
        let revoked = StreamingTicketRevoked::new(
            domain_id,
            *ready.stream_id(),
            *ready.ticket_id(),
            *ready.ticket().nullifier(),
            17,
            [0xCC; 64],
        );
        handle
            .apply_ticket_revoked(&revoked)
            .expect("ticket revoked");
        let err = handle
            .apply_manifest_ticket_and_routes(&mut manifest)
            .expect_err("manifest should fail without ticket");
        match err {
            StreamingProcessError::MissingStreamTicket { stream } => {
                assert_eq!(stream, stream_id);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn duplicate_ticket_nullifier_is_rejected() {
        let handle = StreamingHandle::new();
        let first_ready = sample_ticket_ready("dup-nullifier", 0x21, 0x31);
        let first_routes: Vec<StreamingPrivacyRoute> = first_ready
            .routes()
            .iter()
            .map(|binding| binding.route.clone())
            .collect();
        handle
            .register_stream_ticket(&first_ready, first_routes)
            .expect("initial ticket registered");
        let conflicting_ready = StreamingTicketReady::new(
            sample_domain_id("dup-nullifier-alt"),
            iroha_crypto::Hash::prehashed(hash_with(0x22)),
            first_ready.ticket().clone(),
            first_ready.routes().clone(),
        );
        let conflict_routes: Vec<StreamingPrivacyRoute> = conflicting_ready
            .routes()
            .iter()
            .map(|binding| binding.route.clone())
            .collect();
        let err = handle
            .register_stream_ticket(&conflicting_ready, conflict_routes)
            .expect_err("duplicate nullifier should be rejected");
        assert!(
            matches!(err, StreamingProcessError::DuplicateTicketNullifier { .. }),
            "unexpected error: {err:?}"
        );
    }
    #[test]
    fn ticket_envelope_commitment_mismatch_is_rejected() {
        let handle = StreamingHandle::new();
        let base_ready = sample_ticket_ready("ticket-envelope-mismatch", 0x31, 0x41);
        let mut streaming_route = streaming_route_from_privacy(&sample_privacy_route());
        let body = TicketBodyV1 {
            blinded_cid: [0xAA; 32],
            scope: TicketScopeV1::Read,
            max_uses: 1,
            valid_after: 1_701_000_000,
            valid_until: 1_701_000_600,
            issuer_id: base_ready.ticket().owner().clone(),
            salt_epoch: 7,
            policy_flags: 0,
            metadata: Metadata::default(),
        };
        let mut commitment = body.compute_commitment();
        commitment[0] ^= 0xFF;
        let envelope = TicketEnvelopeV1 {
            body,
            commitment,
            zk_proof: Vec::new(),
            signature: iroha_crypto::Signature::from_hex("00").expect("signature"),
            nullifier: [0xBB; 32],
        };
        streaming_route = streaming_route.with_ticket(envelope);
        let binding = StreamingRouteBinding::new(streaming_route.clone(), 0, 16, true);
        let ready = StreamingTicketReady::new(
            base_ready.domain().clone(),
            *base_ready.stream_id(),
            base_ready.ticket().clone(),
            vec![binding],
        );
        let err = handle
            .apply_ticket_ready(&ready)
            .expect_err("mismatched ticket commitment should be rejected");
        match err {
            StreamingProcessError::TicketEnvelopeInvalid { route_id, .. } => {
                let expected: [u8; iroha_crypto::Hash::LENGTH] = streaming_route.route_id;
                assert_eq!(route_id, expected);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn manifest_publisher_sends_manifest_and_hint() {
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13900);
        let handle = StreamingHandle::new();
        let resolution = sample_resolution();
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Publisher, resolution)
            .expect("record capabilities");
        handle
            .record_negotiated_capabilities(
                &viewer_peer,
                CapabilityRole::Publisher,
                CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            )
            .expect("record negotiated capabilities");
        let ready = sample_ticket_ready("manifest-publisher", 0x11, 0xA0);
        handle
            .apply_ticket_ready(&ready)
            .expect("ticket ready must register before announce");
        let hint = FeedbackHintFrame {
            stream_id: hash_with(0x55),
            loss_ewma_q16: 5_243,
            latency_gradient_q16: 0,
            observed_rtt_ms: 40,
            report_interval_ms: 0,
            parity_chunks: 0,
        };
        let report = ReceiverReport {
            stream_id: hint.stream_id,
            latest_segment: 9,
            layer_mask: 0,
            measured_throughput_kbps: 1_500,
            rtt_ms: 44,
            loss_percent_x100: 700,
            decoder_buffer_ms: 120,
            active_resolution: Resolution::R1080p,
            hdr_active: false,
            ecn_ce_count: 0,
            jitter_ms: 4,
            delivered_sequence: 300,
            parity_applied: 1,
            fec_budget: 2,
            sync_diagnostics: None,
        };
        handle
            .process_control_frame(&viewer_peer, &ControlFrame::FeedbackHint(hint))
            .expect("feedback hint accepted");
        handle
            .process_control_frame(&viewer_peer, &ControlFrame::ReceiverReport(report))
            .expect("receiver report accepted");
        let tx = TestControlTx::default();
        let publisher = ManifestPublisher::new(handle.clone(), tx.clone());
        let manifest = sample_manifest();
        let transport_hash = resolution.capabilities_hash();
        publisher
            .announce(&viewer_peer, manifest, None)
            .expect("manifest announce");
        let frames = tx.frames();
        assert_eq!(frames.len(), 2, "manifest and feedback hint expected");
        assert_eq!(frames[0].0, viewer_peer.id().clone());
        match &frames[0].1 {
            ControlFrame::ManifestAnnounce(frame) => {
                assert_eq!(frame.manifest.transport_capabilities_hash, transport_hash);
                assert_eq!(frame.manifest.stream_id, hash_with(0x11));
            }
            other => panic!("unexpected frame: {other:?}"),
        }
        match &frames[1].1 {
            ControlFrame::FeedbackHint(out_hint) => {
                assert_eq!(out_hint.stream_id, hash_with(0x11));
                assert_eq!(out_hint.parity_chunks, 2);
                assert_eq!(
                    out_hint.report_interval_ms,
                    resolution.fec_feedback_interval_ms
                );
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }
    #[test]
    fn manifest_publisher_emits_manifest_without_feedback_when_missing_state() {
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13950);
        let handle = StreamingHandle::new();
        let resolution = sample_resolution();
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Publisher, resolution)
            .expect("record capabilities");
        handle
            .record_negotiated_capabilities(
                &viewer_peer,
                CapabilityRole::Publisher,
                CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            )
            .expect("record negotiated capabilities");
        let ready = sample_ticket_ready("manifest-publisher-no-feedback", 0x11, 0xA0);
        handle
            .apply_ticket_ready(&ready)
            .expect("ticket ready must register before announce");
        let tx = TestControlTx::default();
        let publisher = ManifestPublisher::new(handle.clone(), tx.clone());
        let manifest = sample_manifest();
        let transport_hash = resolution.capabilities_hash();
        publisher
            .announce(&viewer_peer, manifest, None)
            .expect("manifest announce without feedback");
        let frames = tx.frames();
        assert_eq!(frames.len(), 1, "only manifest expected without feedback");
        match &frames[0].1 {
            ControlFrame::ManifestAnnounce(frame) => {
                assert_eq!(frame.manifest.transport_capabilities_hash, transport_hash);
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }
    #[test]
    fn manifest_requires_privacy_route_ack_before_delivery() {
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13960);
        let handle = StreamingHandle::new();
        let tx = TestControlTx::default();
        let publisher = ManifestPublisher::new(handle.clone(), tx.clone());
        let resolution = sample_resolution();
        let negotiated =
            CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED | 0b101);
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Publisher, resolution)
            .expect("record capabilities");
        handle
            .record_negotiated_capabilities(&viewer_peer, CapabilityRole::Publisher, negotiated)
            .expect("record negotiated capabilities");
        let stream_id = hash_with(0x91);
        let route = privacy_route_with_seed(0xA1, 24);
        let streaming_route = streaming_route_from_privacy(&route);
        let base_ready = sample_ticket_ready("nsc", 0x91, 0x92);
        let ready = StreamingTicketReady::new(
            base_ready.domain().clone(),
            *base_ready.stream_id(),
            base_ready.ticket().clone(),
            vec![StreamingRouteBinding::new(
                streaming_route.clone(),
                0,
                route.expiry_segment,
                false,
            )],
        );
        let ticket_id = stream_hash_from_crypto(ready.ticket_id());
        let routes = vec![streaming_route];
        handle
            .register_stream_ticket(&ready, routes)
            .expect("register stream ticket");
        let mut manifest = sample_manifest();
        manifest.stream_id = stream_id;
        manifest.segment_number = 8;
        manifest.content_key_id = 77;
        manifest.public_metadata.access_policy_id = None;
        manifest.privacy_routes.clear();
        let updates = handle
            .prepare_privacy_route_updates(
                &stream_id,
                manifest.content_key_id,
                manifest.segment_number,
                manifest.segment_number + 3,
            )
            .expect("prepare privacy route updates");
        assert_eq!(updates.len(), 1, "single route provision expected");
        let prepared = &updates[0];
        assert_eq!(prepared.update.route_id, route.route_id);
        assert_eq!(prepared.update.stream_id, stream_id);
        assert_eq!(prepared.update.content_key_id, manifest.content_key_id);
        assert_eq!(prepared.update.valid_from_segment, manifest.segment_number);
        assert_eq!(
            prepared.update.valid_until_segment,
            route.expiry_segment.min(manifest.segment_number + 3)
        );
        assert_eq!(prepared.update.exit_token, route.ticket_exit);
        assert_eq!(prepared.exit_relay, route.exit);
        let err = publisher
            .announce(&viewer_peer, manifest.clone(), None)
            .expect_err("manifest must be gated until privacy route is acknowledged");
        assert!(matches!(
            err,
            StreamingProcessError::PrivacyRouteUnacknowledged { route_id } if route_id == route.route_id
        ));
        assert!(
            tx.frames().is_empty(),
            "no frames should be sent before the privacy route is acknowledged"
        );
        handle
            .record_privacy_route_ack(&route.route_id)
            .expect("record privacy route acknowledgement");
        publisher
            .announce(&viewer_peer, manifest.clone(), None)
            .expect("manifest should be delivered once the route is acknowledged");
        let frames = tx.frames();
        assert!(
            !frames.is_empty(),
            "expected manifest frames once privacy route is acknowledged"
        );
        let manifest_frame = frames
            .iter()
            .find_map(|(_, frame)| match frame {
                ControlFrame::ManifestAnnounce(frame) => Some(&frame.manifest),
                _ => None,
            })
            .expect("manifest announce frame present");
        assert_eq!(
            manifest_frame.privacy_routes,
            vec![route.clone()],
            "acknowledged routes should populate the manifest"
        );
        assert_eq!(
            manifest_frame.public_metadata.access_policy_id,
            Some(ticket_id),
            "manifest should advertise the ticket id as access policy"
        );
    }
    #[test]
    fn prepare_privacy_route_updates_preserves_explicit_soranet_metadata() {
        let handle = StreamingHandle::new();
        let route = soranet_privacy_route(0xB5, 24);
        let streaming_route = streaming_route_from_privacy(&route);
        let base_ready = sample_ticket_ready("nsc", 0x31, 0x32);
        let ready = StreamingTicketReady::new(
            base_ready.domain().clone(),
            *base_ready.stream_id(),
            base_ready.ticket().clone(),
            vec![StreamingRouteBinding::new(
                streaming_route.clone(),
                0,
                route.expiry_segment,
                false,
            )],
        );
        handle
            .register_stream_ticket(&ready, vec![streaming_route])
            .expect("register stream ticket");
        let stream_id = stream_hash_from_crypto(ready.stream_id());
        let updates = handle
            .prepare_privacy_route_updates(&stream_id, 77, 0, 8)
            .expect("prepare privacy route updates");
        assert_eq!(updates.len(), 1, "single route provision expected");
        assert_eq!(
            updates[0].update.soranet.as_ref(),
            route.soranet.as_ref(),
            "explicit preparation must preserve the signed SoraNet descriptor exactly"
        );
    }
    #[test]
    fn prepared_privacy_route_debug_redacts_and_owned_copies_require_drop() {
        let prepared = PreparedPrivacyRouteUpdate {
            exit_relay: PrivacyRelay {
                relay_id: hash_with(0xE1),
                endpoint: Multiaddr::from("/dns/exit-relay/udp/9443/quic"),
                key_fingerprint: hash_with(0xE2),
                capabilities: PrivacyCapabilities::from_bits(1),
            },
            update: PrivacyRouteUpdate {
                route_id: hash_with(0xA1),
                stream_id: hash_with(0xB2),
                content_key_id: 17,
                valid_from_segment: 0,
                valid_until_segment: u64::MAX,
                exit_token: vec![0xDE, 0xAD, 0xBE, 0xEF],
                soranet: None,
            },
        };
        let rendered = format!("{prepared:?}");
        assert!(rendered.contains("exit_token: <redacted:4 bytes>"));
        assert!(!rendered.contains("222, 173, 190, 239"));
        assert!(std::mem::needs_drop::<PreparedPrivacyRouteUpdate>());
    }
    #[test]
    fn provision_state_update_ignores_missing_ticket() {
        let handle = StreamingHandle::new();
        let route = sample_privacy_route();
        let streaming_route = streaming_route_from_privacy(&route);
        let ready = sample_ticket_ready("nsc", 0x52, 0x62);
        handle
            .register_stream_ticket(&ready, vec![streaming_route])
            .expect("register stream ticket");
        let stream_id = stream_hash_from_crypto(ready.stream_id());
        handle
            .unregister_stream_ticket(&stream_id)
            .expect("unregister stream ticket");
        let result = mark_privacy_route_provisioned_in_state(
            handle.inner.as_ref(),
            &stream_id,
            &route.route_id,
            1,
        );
        assert!(
            handle_provisioned_state_update(result, stream_id, route.route_id).is_ok(),
            "missing tickets should be ignored after provisioning races"
        );
    }
    #[test]
    fn privacy_route_expiry_blocks_updates_and_manifest() {
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13961);
        let handle = StreamingHandle::new();
        let tx = TestControlTx::default();
        let publisher = ManifestPublisher::new(handle.clone(), tx);
        let resolution = sample_resolution();
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Publisher, resolution)
            .expect("record capabilities");
        handle
            .record_negotiated_capabilities(
                &viewer_peer,
                CapabilityRole::Publisher,
                CapabilityFlags::from_bits(0b11),
            )
            .expect("record negotiated capabilities");
        let stream_id = hash_with(0xA3);
        let route = privacy_route_with_seed(0xB1, 5);
        let streaming_route = streaming_route_from_privacy(&route);
        let base_ready = sample_ticket_ready("nsc", 0xA3, 0xA4);
        let ready = StreamingTicketReady::new(
            base_ready.domain().clone(),
            *base_ready.stream_id(),
            base_ready.ticket().clone(),
            vec![StreamingRouteBinding::new(
                streaming_route.clone(),
                0,
                route.expiry_segment,
                false,
            )],
        );
        handle
            .register_stream_ticket(&ready, vec![streaming_route])
            .expect("register stream ticket");
        let mut manifest = sample_manifest();
        manifest.stream_id = stream_id;
        manifest.segment_number = 4;
        manifest.content_key_id = 33;
        manifest.public_metadata.access_policy_id = None;
        manifest.privacy_routes.clear();
        let initial_updates = handle
            .prepare_privacy_route_updates(&stream_id, 33, 3, 5)
            .expect("prepare updates within validity window");
        assert_eq!(initial_updates.len(), 1, "expected one initial update");
        handle
            .record_privacy_route_ack(&route.route_id)
            .expect("ack initial route provisioning");
        let expired_err = handle
            .prepare_privacy_route_updates(&stream_id, 33, 6, 7)
            .expect_err("updates beyond expiry must fail");
        assert!(matches!(
            expired_err,
            StreamingProcessError::PrivacyRouteExpired {
                route_id,
                expiry_segment,
                requested_segment
            } if route_id == route.route_id && expiry_segment == 5 && requested_segment == 6
        ));
        manifest.segment_number = 6;
        let announce_err = publisher
            .announce(&viewer_peer, manifest, None)
            .expect_err("manifest past expiry must be rejected");
        assert!(matches!(
        announce_err,
        StreamingProcessError::NoActivePrivacyRoutes { stream, segment }
            if stream == stream_id && segment == 6
        ));
    }
    #[test]
    fn sync_policy_detects_hard_cap() {
        let policy = SyncPolicy {
            enabled: true,
            observe_only: false,
            min_window_ms: 100,
            ewma_threshold_ms: 10,
            hard_cap_ms: 12,
        };
        let diagnostics = SyncDiagnostics {
            window_ms: 250,
            samples: 96,
            avg_audio_jitter_ms: 4,
            max_audio_jitter_ms: 7,
            avg_av_drift_ms: 3,
            max_av_drift_ms: 15,
            ewma_av_drift_ms: 4,
            violation_count: 1,
        };
        assert!(matches!(
            policy.violation(&diagnostics),
            Some(SyncViolation::HardCap {
                observed_ms: 15,
                hard_cap_ms: 12,
                window_ms: 250
            })
        ));
    }
    #[test]
    fn receiver_report_violation_returns_error() {
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13855);
        let handle = StreamingHandle::new().with_sync_policy(SyncPolicy {
            enabled: true,
            observe_only: false,
            min_window_ms: 100,
            ewma_threshold_ms: 8,
            hard_cap_ms: 14,
        });
        let resolution = sample_resolution();
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Viewer, resolution)
            .expect("record capabilities");
        let report = ReceiverReport {
            stream_id: hash_with(0xAB),
            latest_segment: 16,
            layer_mask: 0,
            measured_throughput_kbps: 1_800,
            rtt_ms: 40,
            loss_percent_x100: 500,
            decoder_buffer_ms: 120,
            active_resolution: Resolution::R720p,
            hdr_active: false,
            ecn_ce_count: 0,
            jitter_ms: 4,
            delivered_sequence: 512,
            parity_applied: 0,
            fec_budget: 0,
            sync_diagnostics: Some(SyncDiagnostics {
                window_ms: 200,
                samples: 128,
                avg_audio_jitter_ms: 5,
                max_audio_jitter_ms: 9,
                avg_av_drift_ms: -6,
                max_av_drift_ms: 10,
                ewma_av_drift_ms: 12,
                violation_count: 4,
            }),
        };
        let err = handle
            .process_control_frame(&viewer_peer, &ControlFrame::ReceiverReport(report))
            .expect_err("violation must be surfaced");
        assert!(matches!(
            err,
            StreamingProcessError::AudioSyncViolation { .. }
        ));
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn privacy_route_reprovision_required_for_extended_window() {
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13962);
        let handle = StreamingHandle::new();
        let resolution = sample_resolution();
        let negotiated =
            CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED | 0b101);
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Publisher, resolution)
            .expect("record capabilities");
        handle
            .record_negotiated_capabilities(&viewer_peer, CapabilityRole::Publisher, negotiated)
            .expect("record negotiated capabilities");
        let stream_id = hash_with(0xC1);
        let route = privacy_route_with_seed(0xD1, 40);
        let streaming_route = streaming_route_from_privacy(&route);
        let base_ready = sample_ticket_ready("nsc", 0xC1, 0xC2);
        let ready = StreamingTicketReady::new(
            base_ready.domain().clone(),
            *base_ready.stream_id(),
            base_ready.ticket().clone(),
            vec![StreamingRouteBinding::new(
                streaming_route.clone(),
                0,
                route.expiry_segment,
                false,
            )],
        );
        let ticket_id = stream_hash_from_crypto(ready.ticket_id());
        handle
            .register_stream_ticket(&ready, vec![streaming_route])
            .expect("register stream ticket");
        let mut manifest = sample_manifest();
        manifest.stream_id = stream_id;
        manifest.segment_number = 8;
        manifest.content_key_id = 55;
        manifest.public_metadata.access_policy_id = None;
        manifest.privacy_routes.clear();
        // First provisioning window covers the initial segment range.
        let initial_updates = handle
            .prepare_privacy_route_updates(&stream_id, manifest.content_key_id, 8, 12)
            .expect("prepare initial route updates");
        assert_eq!(initial_updates.len(), 1);
        let prepared = &initial_updates[0];
        assert_eq!(prepared.update.route_id, route.route_id);
        assert_eq!(prepared.update.valid_from_segment, 8);
        assert_eq!(prepared.update.valid_until_segment, 12);
        handle
            .record_privacy_route_ack(&route.route_id)
            .expect("acknowledge initial provisioning");
        let tx_initial = TestControlTx::default();
        let publisher_initial = ManifestPublisher::new(handle.clone(), tx_initial.clone());
        publisher_initial
            .announce(&viewer_peer, manifest.clone(), None)
            .expect("manifest delivered after initial ack");
        assert!(
            tx_initial
                .frames()
                .iter()
                .any(|(_, frame)| matches!(frame, ControlFrame::ManifestAnnounce(_))),
            "initial manifest announce expected after ack"
        );
        // Extend the validity window; reprovisioning should be required.
        let next_segment = 13;
        let extended_updates = handle
            .prepare_privacy_route_updates(&stream_id, manifest.content_key_id, next_segment, 18)
            .expect("prepare extended route updates");
        assert_eq!(extended_updates.len(), 1);
        let reprovisioned = &extended_updates[0];
        assert_eq!(reprovisioned.update.valid_from_segment, next_segment);
        assert_eq!(reprovisioned.update.valid_until_segment, 18);
        let mut next_manifest = manifest.clone();
        next_manifest.segment_number = next_segment;
        next_manifest.public_metadata.access_policy_id = None;
        next_manifest.privacy_routes.clear();
        let tx_next = TestControlTx::default();
        let publisher_next = ManifestPublisher::new(handle.clone(), tx_next.clone());
        let reprovision_err = publisher_next
            .announce(&viewer_peer, next_manifest.clone(), None)
            .expect_err("manifest must be gated until reprovisioned route is acknowledged");
        assert!(matches!(
            reprovision_err,
            StreamingProcessError::PrivacyRouteUnacknowledged { route_id } if route_id == route.route_id
        ));
        assert!(
            tx_next.frames().is_empty(),
            "no frames should be sent before extended window is acknowledged"
        );
        handle
            .record_privacy_route_ack(&route.route_id)
            .expect("acknowledge extended provisioning");
        publisher_next
            .announce(&viewer_peer, next_manifest.clone(), None)
            .expect("manifest delivered after extended ack");
        let frames = tx_next.frames();
        let manifest_frame = frames
            .iter()
            .find_map(|(_, frame)| match frame {
                ControlFrame::ManifestAnnounce(frame) => Some(&frame.manifest),
                _ => None,
            })
            .expect("manifest announce frame present after extended ack");
        assert_eq!(
            manifest_frame.segment_number, next_segment,
            "manifest should target the extended segment"
        );
        assert_eq!(
            manifest_frame.privacy_routes,
            vec![route.clone()],
            "acknowledged route should populate manifest after reprovision"
        );
        assert_eq!(
            manifest_frame.public_metadata.access_policy_id,
            Some(ticket_id),
            "manifest should advertise ticket id once reprovisioned route is acknowledged"
        );
    }
    #[test]
    fn apply_manifest_capabilities_reflect_configured_features() {
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13990);
        let capabilities = CapabilityFlags::from_bits(0b101);
        let handle = StreamingHandle::new().with_capabilities(capabilities);
        let resolution = sample_resolution();
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Publisher, resolution)
            .expect("record capabilities");
        handle
            .record_negotiated_capabilities(
                &viewer_peer,
                CapabilityRole::Publisher,
                CapabilityFlags::from_bits(
                    CapabilityFlags::FEATURE_ENTROPY_BUNDLED
                        | CapabilityFlags::FEATURE_FEEDBACK_HINTS,
                ),
            )
            .expect("record negotiated capabilities");
        let mut manifest = sample_manifest();
        // overwrite capability field to ensure method updates it
        manifest.capabilities = CapabilityFlags::from_bits(0);
        handle
            .apply_manifest_transport_capabilities(viewer_peer.id(), &mut manifest)
            .expect("apply transport hash");
        assert_eq!(manifest.capabilities, handle.capabilities());
    }
    #[test]
    fn bundled_manifest_capabilities_include_entropy_and_accel_bits() {
        let bundled_bits = CapabilityFlags::from_bits(
            CapabilityFlags::FEATURE_ENTROPY_BUNDLED
                | CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD,
        );
        let mut handle = StreamingHandle::new().with_capabilities(bundled_bits);
        handle.entropy_mode = EntropyMode::RansBundled;
        handle.bundle_accel = actual::BundleAcceleration::CpuSimd;
        let viewer_keys = checked_random_keypair();
        let viewer_peer = make_peer(&viewer_keys, 13991);
        let resolution = sample_resolution();
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Publisher, resolution)
            .expect("record capabilities");
        handle
            .record_negotiated_capabilities(
                &viewer_peer,
                CapabilityRole::Publisher,
                CapabilityFlags::from_bits(
                    CapabilityFlags::FEATURE_ENTROPY_BUNDLED
                        | CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD,
                ),
            )
            .expect("record negotiated capabilities");
        let mut manifest = sample_manifest();
        manifest.capabilities = CapabilityFlags::from_bits(0);
        handle
            .apply_manifest_transport_capabilities(viewer_peer.id(), &mut manifest)
            .expect("apply transport hash");
        assert!(
            manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            "manifest should advertise bundled entropy capability"
        );
        assert!(
            manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "manifest should advertise configured acceleration capability"
        );
    }
    #[cfg(feature = "quic")]
    #[tokio::test(flavor = "multi_thread")]
    async fn negotiate_transport_records_hashes() {
        use iroha_p2p::streaming::{
            StreamingServer,
            quic::{Error, TransportConfigSettings},
        };
        use norito::streaming::{
            AudioCapability, Resolution, TransportCapabilities, resolve_transport_capabilities,
        };
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let refused = match StreamingServer::bind(server_addr, TransportConfigSettings::default())
            .await
        {
            Ok(_) => panic!("shipping QUIC must remain closed pending transport requalification"),
            Err(error) => error,
        };
        assert!(
            matches!(refused, Error::TransportConfig(ref reason) if reason.contains("transport requalification"))
        );

        // Exercise the canonical negotiation codec and session owners directly.
        // A component exchange does not qualify the deliberately closed shipping transport.
        let publisher_keys = checked_random_ed25519_keypair();
        let viewer_keys = checked_random_keypair();
        let publisher_peer = make_peer(&publisher_keys, 21001);
        let viewer_peer = make_peer(&viewer_keys, 21002);
        let publisher_handle =
            StreamingHandle::new().with_capabilities(CapabilityFlags::from_bits(0b101));
        let viewer_handle =
            StreamingHandle::new().with_capabilities(CapabilityFlags::from_bits(0b101));
        let mut publisher_caps = TransportCapabilities::kyber768_default();
        publisher_caps.max_segment_datagram_size = 1_100;
        let mut viewer_caps = TransportCapabilities::kyber768_default();
        viewer_caps.max_segment_datagram_size = 1_000;
        let resolution = resolve_transport_capabilities(&publisher_caps, &viewer_caps)
            .expect("publisher resolution");
        let viewer_resolution = resolve_transport_capabilities(&viewer_caps, &publisher_caps)
            .expect("viewer resolution");
        assert_eq!(resolution, viewer_resolution);
        let report = CapabilityReport {
            stream_id: hash_with(0x99),
            endpoint_role: CapabilityRole::Viewer,
            protocol_version: 1,
            max_resolution: Resolution::R1080p,
            hdr_supported: true,
            capture_hdr: false,
            neural_bundles: vec!["bundle".into()],
            audio_caps: AudioCapability {
                sample_rates: vec![48_000],
                ambisonics: false,
                max_channels: 2,
            },
            feature_bits: viewer_handle
                .normalize_viewer_feature_bits(CapabilityFlags::from_bits(0b101)),
            max_datagram_size: 950,
            dplpmtud: true,
        };
        let report_frame = ControlFrame::CapabilityReport(report.clone());
        let report_wire = norito::to_bytes(&report_frame).expect("encode viewer report");
        let ControlFrame::CapabilityReport(decoded_report) =
            norito::decode_canonical::<ControlFrame>(&report_wire).expect("decode viewer report")
        else {
            panic!("canonical viewer report retains its frame kind");
        };
        assert_eq!(decoded_report, report);
        let ack = publisher_handle
            .build_capability_ack(&decoded_report, resolution)
            .expect("publisher acknowledgement");
        let ack_wire = norito::to_bytes(&ControlFrame::CapabilityAck(ack))
            .expect("encode publisher acknowledgement");
        let ControlFrame::CapabilityAck(viewer_ack) =
            norito::decode_canonical::<ControlFrame>(&ack_wire)
                .expect("decode publisher acknowledgement")
        else {
            panic!("canonical publisher acknowledgement retains its frame kind");
        };
        assert_eq!(viewer_ack, ack);
        assert_eq!(ack.max_datagram_size, resolution.max_segment_datagram_size);
        assert_eq!(
            viewer_ack.max_datagram_size,
            viewer_resolution.max_segment_datagram_size
        );
        for (handle, peer, role, resolved) in [
            (
                &publisher_handle,
                &viewer_peer,
                CapabilityRole::Publisher,
                resolution,
            ),
            (
                &viewer_handle,
                &publisher_peer,
                CapabilityRole::Viewer,
                viewer_resolution,
            ),
        ] {
            handle
                .record_transport_capabilities(peer, role, resolved)
                .expect("retain original resolved transport");
            handle
                .record_negotiated_capabilities(peer, role, ack.negotiated_features)
                .expect("retain acknowledged features");
            assert_eq!(
                handle.transport_capabilities_hash(peer.id()),
                Some(resolved.capabilities_hash())
            );
        }
        assert!(
            publisher_handle
                .transport_capabilities_hash(viewer_peer.id())
                .is_some()
        );
        assert!(
            viewer_handle
                .transport_capabilities_hash(publisher_peer.id())
                .is_some()
        );
        let mut manifest = sample_manifest();
        publisher_handle
            .apply_manifest_transport_capabilities(viewer_peer.id(), &mut manifest)
            .expect("apply transport hash");
        assert_eq!(
            manifest.transport_capabilities_hash,
            publisher_handle
                .transport_capabilities_hash(viewer_peer.id())
                .expect("publisher hash recorded")
        );
        viewer_handle
            .validate_manifest_transport_capabilities(publisher_peer.id(), &manifest)
            .expect("manifest matches negotiated capabilities");
    }
    #[cfg(feature = "quic")]
    #[test]
    fn privacy_requirement_without_provider_rejected() {
        use norito::streaming::{AudioCapability, CapabilityReport, Resolution};
        let handle = StreamingHandle::new().with_capabilities(CapabilityFlags::from_bits(0));
        let report = CapabilityReport {
            stream_id: hash_with(0xCA),
            endpoint_role: CapabilityRole::Viewer,
            protocol_version: 1,
            max_resolution: Resolution::R720p,
            hdr_supported: false,
            capture_hdr: false,
            neural_bundles: Vec::new(),
            audio_caps: AudioCapability {
                sample_rates: vec![48_000],
                ambisonics: false,
                max_channels: 2,
            },
            feature_bits: CapabilityFlags::from_bits(FEATURE_PRIVACY_REQUIRED),
            max_datagram_size: 900,
            dplpmtud: false,
        };
        let resolution = sample_resolution();
        let err = handle
            .build_capability_ack(&report, resolution)
            .expect_err("publisher without privacy provider must reject viewer");
        assert!(matches!(
            err,
            StreamingProcessError::PrivacyOverlayUnsupported
        ));
    }
    #[test]
    fn publisher_rejects_bundled_manifest_without_support() {
        let handle = StreamingHandle::new();
        let mut manifest = sample_manifest();
        manifest.entropy_mode = EntropyMode::RansBundled;
        handle
            .ensure_manifest_entropy_mode_supported(&manifest)
            .expect("bundled manifests should be accepted when bundled support is required");
    }
    #[test]
    fn bundled_manifest_without_checksum_rejected() {
        let handle = StreamingHandle::new();
        let mut manifest = sample_manifest();
        manifest.entropy_mode = EntropyMode::RansBundled;
        manifest.entropy_tables_checksum = None;
        let err = handle
            .ensure_manifest_entropy_mode_supported(&manifest)
            .expect_err("bundled manifests must carry a checksum");
        assert!(matches!(
            err,
            StreamingProcessError::ManifestEntropyTablesMismatch { .. }
        ));
    }
    #[test]
    fn bundled_manifest_checksum_mismatch_rejected() {
        let mut handle = StreamingHandle::new();
        let mut codec = actual::StreamingCodec::from_defaults();
        codec.bundle_width = 2;
        codec.rans_tables_path = repo_rans_tables_path();
        handle
            .apply_codec_config(&codec)
            .expect("bundle tables should load");
        assert!(handle.entropy_mode.is_bundled(), "handle must be bundled");
        let mut manifest = sample_manifest();
        manifest.entropy_mode = EntropyMode::RansBundled;
        manifest.entropy_tables_checksum = Some(handle.bundle_tables_checksum());
        manifest
            .entropy_tables_checksum
            .as_mut()
            .expect("checksum set")[0] ^= 0xFF;
        assert!(
            manifest.entropy_mode.is_bundled(),
            "manifest must advertise bundled entropy mode"
        );
        assert_ne!(
            manifest.entropy_tables_checksum,
            Some(handle.bundle_tables_checksum()),
            "checksum mutation must differ"
        );
        let err = handle
            .ensure_manifest_entropy_mode_supported(&manifest)
            .expect_err("checksum should be enforced");
        assert!(matches!(
            err,
            StreamingProcessError::ManifestEntropyTablesMismatch { .. }
        ));
    }
    #[test]
    fn viewer_requires_negotiated_bundled_capability() {
        let mut handle = StreamingHandle::new();
        let mut codec = actual::StreamingCodec::from_defaults();
        codec.bundle_width = 2;
        codec.rans_tables_path = repo_rans_tables_path();
        handle
            .apply_codec_config(&codec)
            .expect("bundle tables should load");
        let publisher_keys = checked_random_ed25519_keypair();
        let publisher_peer = make_peer(&publisher_keys, 19001);
        let resolution = sample_resolution();
        handle
            .record_transport_capabilities(&publisher_peer, CapabilityRole::Publisher, resolution)
            .expect("record transport capabilities");
        handle
            .record_negotiated_capabilities(
                &publisher_peer,
                CapabilityRole::Publisher,
                CapabilityFlags::from_bits(0),
            )
            .expect("record negotiated bits");
        let mut manifest = sample_manifest();
        manifest.entropy_mode = EntropyMode::RansBundled;
        manifest.entropy_tables_checksum = Some(handle.bundle_tables_checksum());
        manifest.transport_capabilities_hash = resolution.capabilities_hash();
        let err = handle
            .validate_manifest_transport_capabilities(publisher_peer.id(), &manifest)
            .expect_err("viewer must reject bundled manifest without negotiated flag");
        assert!(matches!(
            err,
            StreamingProcessError::ManifestEntropyModeNotNegotiated { .. }
        ));
    }
    #[test]
    fn viewer_requires_negotiated_bundle_acceleration() {
        let mut handle = StreamingHandle::new();
        let mut codec = actual::StreamingCodec::from_defaults();
        codec.entropy_mode = EntropyMode::RansBundled;
        codec.bundle_width = 2;
        codec.bundle_accel = actual::BundleAcceleration::CpuSimd;
        codec.rans_tables_path = repo_rans_tables_path();
        handle
            .apply_codec_config(&codec)
            .expect("bundle tables should load");
        let publisher_keys = checked_random_ed25519_keypair();
        let publisher_peer = make_peer(&publisher_keys, 19011);
        let resolution = sample_resolution();
        handle
            .record_transport_capabilities(&publisher_peer, CapabilityRole::Publisher, resolution)
            .expect("record transport capabilities");
        handle
            .record_negotiated_capabilities(
                &publisher_peer,
                CapabilityRole::Publisher,
                CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            )
            .expect("record negotiated bits");
        let mut manifest = sample_manifest();
        manifest.entropy_mode = EntropyMode::RansBundled;
        manifest.entropy_tables_checksum = Some(handle.bundle_tables_checksum());
        manifest.transport_capabilities_hash = resolution.capabilities_hash();
        let err = handle
            .validate_manifest_transport_capabilities(publisher_peer.id(), &manifest)
            .expect_err("viewer must reject bundled manifest without negotiated acceleration flag");
        assert!(matches!(
            err,
            StreamingProcessError::ManifestAccelerationNotNegotiated { .. }
        ));
    }
    #[test]
    fn manifest_capabilities_track_codec_config_changes() {
        let viewer_keys = checked_random_ed25519_keypair();
        let viewer_peer = make_peer(&viewer_keys, 19021);
        let resolution = sample_resolution();
        let mut handle =
            StreamingHandle::new().with_capabilities(CapabilityFlags::from_bits(0b111));
        let mut codec = actual::StreamingCodec::from_defaults();
        codec.rans_tables_path = repo_rans_tables_path();
        codec.entropy_mode = EntropyMode::RansBundled;
        codec.bundle_width = 2;
        handle
            .apply_codec_config(&codec)
            .expect("bundled codec config should load");
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Viewer, resolution)
            .expect("record viewer transport capabilities");
        handle
            .record_negotiated_capabilities(
                &viewer_peer,
                CapabilityRole::Viewer,
                CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            )
            .expect("record viewer negotiated capabilities");
        let mut bundled_manifest = sample_manifest();
        bundled_manifest.entropy_mode = EntropyMode::RansBundled;
        bundled_manifest.entropy_tables_checksum = Some(handle.bundle_tables_checksum());
        handle
            .apply_manifest_transport_capabilities(viewer_peer.id(), &mut bundled_manifest)
            .expect("stamp bundled manifest");
        assert!(
            bundled_manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            "bundled manifests must advertise FEATURE_ENTROPY_BUNDLED"
        );
    }
    #[test]
    fn bundled_manifest_updates_acceleration_bits_on_config_change() {
        let viewer_keys = checked_random_ed25519_keypair();
        let viewer_peer = make_peer(&viewer_keys, 19031);
        let resolution = sample_resolution();
        let mut handle =
            StreamingHandle::new().with_capabilities(CapabilityFlags::from_bits(0b111));
        let mut codec = actual::StreamingCodec::from_defaults();
        codec.entropy_mode = EntropyMode::RansBundled;
        codec.bundle_width = 2;
        codec.bundle_accel = actual::BundleAcceleration::CpuSimd;
        codec.rans_tables_path = repo_rans_tables_path();
        handle
            .apply_codec_config(&codec)
            .expect("bundled codec config should load");
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Viewer, resolution)
            .expect("record viewer transport capabilities");
        let negotiated = CapabilityFlags::from_bits(
            CapabilityFlags::FEATURE_ENTROPY_BUNDLED
                | CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD,
        );
        handle
            .record_negotiated_capabilities(&viewer_peer, CapabilityRole::Viewer, negotiated)
            .expect("record viewer negotiated capabilities");
        let mut manifest = sample_manifest();
        manifest.entropy_mode = EntropyMode::RansBundled;
        manifest.entropy_tables_checksum = Some(handle.bundle_tables_checksum());
        manifest.transport_capabilities_hash = resolution.capabilities_hash();
        handle
            .apply_manifest_transport_capabilities(viewer_peer.id(), &mut manifest)
            .expect("stamp bundled manifest");
        assert!(
            manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "CPU manifests must advertise FEATURE_BUNDLE_ACCEL_CPU_SIMD"
        );
        assert!(
            !manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
            "CPU manifests must not advertise the GPU acceleration bit"
        );
        codec.bundle_accel = actual::BundleAcceleration::Gpu;
        let gpu_config = handle.apply_codec_config(&codec);
        if !norito::streaming::BUNDLED_RANS_GPU_BUILD_AVAILABLE {
            let err = gpu_config.expect_err("cpu-only builds must reject GPU bundle acceleration");
            match err {
                StreamingCodecConfigError::BundleAccelerationUnavailable { requested } => {
                    assert_eq!(requested, actual::BundleAcceleration::Gpu);
                }
                other => panic!("unexpected GPU bundle acceleration error: {other:?}"),
            }
            return;
        }
        gpu_config.expect("GPU codec config should load");
        let gpu_negotiated = CapabilityFlags::from_bits(
            CapabilityFlags::FEATURE_ENTROPY_BUNDLED | CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU,
        );
        handle
            .record_negotiated_capabilities(&viewer_peer, CapabilityRole::Viewer, gpu_negotiated)
            .expect("record viewer GPU capabilities");
        handle
            .apply_manifest_transport_capabilities(viewer_peer.id(), &mut manifest)
            .expect("stamp manifest after switching acceleration");
        assert!(
            manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
            "GPU manifests must advertise FEATURE_BUNDLE_ACCEL_GPU"
        );
        assert!(
            !manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "GPU manifests must drop the CPU acceleration bit"
        );
    }
    #[cfg(feature = "quic")]
    #[test]
    fn bundled_entropy_requires_viewer_support() {
        use norito::streaming::{AudioCapability, CapabilityReport, Resolution};
        let mut handle =
            StreamingHandle::new().with_capabilities(CapabilityFlags::from_bits(0b101));
        let mut codec = actual::StreamingCodec::from_defaults();
        codec.entropy_mode = EntropyMode::RansBundled;
        codec.bundle_width = 2;
        codec.rans_tables_path = repo_rans_tables_path();
        handle
            .apply_codec_config(&codec)
            .expect("bundle tables should load");
        let report = CapabilityReport {
            stream_id: hash_with(0xCB),
            endpoint_role: CapabilityRole::Viewer,
            protocol_version: 1,
            max_resolution: Resolution::R720p,
            hdr_supported: false,
            capture_hdr: false,
            neural_bundles: Vec::new(),
            audio_caps: AudioCapability {
                sample_rates: vec![48_000],
                ambisonics: false,
                max_channels: 2,
            },
            feature_bits: CapabilityFlags::from_bits(0),
            max_datagram_size: 900,
            dplpmtud: false,
        };
        let resolution = sample_resolution();
        let err = handle
            .build_capability_ack(&report, resolution)
            .expect_err("publisher should reject viewers lacking bundled rANS support");
        assert!(matches!(
            err,
            StreamingProcessError::BundledEntropyUnsupported
        ));
    }
    #[test]
    fn normalize_viewer_feature_bits_tracks_codec_config() {
        let handle = StreamingHandle::new();
        let base = CapabilityFlags::from_bits(0);
        let normalized = handle.normalize_viewer_feature_bits(base);
        assert!(
            normalized.contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            "bundled mode should advertise FEATURE_ENTROPY_BUNDLED by default"
        );
        let mut bundled = handle.clone();
        let mut codec = actual::StreamingCodec::from_defaults();
        codec.bundle_width = 2;
        codec.bundle_accel = actual::BundleAcceleration::CpuSimd;
        codec.rans_tables_path = repo_rans_tables_path();
        bundled
            .apply_codec_config(&codec)
            .expect("bundle tables should load");
        let normalized = bundled.normalize_viewer_feature_bits(base);
        assert!(
            normalized.contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            "bundled mode should advertise FEATURE_ENTROPY_BUNDLED"
        );
        assert!(
            normalized.contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "bundled mode should advertise the configured acceleration bit"
        );
        let mut gpu = handle.clone();
        let mut gpu_codec = actual::StreamingCodec::from_defaults();
        gpu_codec.entropy_mode = EntropyMode::RansBundled;
        gpu_codec.bundle_width = 2;
        gpu_codec.bundle_accel = actual::BundleAcceleration::Gpu;
        gpu_codec.rans_tables_path = repo_rans_tables_path();
        let gpu_result = gpu.apply_codec_config(&gpu_codec);
        if !norito::streaming::BUNDLED_RANS_GPU_BUILD_AVAILABLE {
            let err = gpu_result.expect_err("cpu-only builds must reject GPU bundle acceleration");
            match err {
                StreamingCodecConfigError::BundleAccelerationUnavailable { requested } => {
                    assert_eq!(requested, actual::BundleAcceleration::Gpu);
                }
                other => panic!("unexpected GPU bundle acceleration error: {other:?}"),
            }
            return;
        }
        gpu_result.expect("bundle tables should load");
        let normalized_gpu = gpu.normalize_viewer_feature_bits(base);
        assert!(
            normalized_gpu.contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
            "GPU acceleration should set the GPU capability bit"
        );
    }
    #[test]
    fn normalize_viewer_feature_bits_strips_conflicting_acceleration_bits() {
        let mut cpu_handle = StreamingHandle::new();
        let mut codec = actual::StreamingCodec::from_defaults();
        codec.entropy_mode = EntropyMode::RansBundled;
        codec.bundle_width = 2;
        codec.bundle_accel = actual::BundleAcceleration::CpuSimd;
        codec.rans_tables_path = repo_rans_tables_path();
        cpu_handle
            .apply_codec_config(&codec)
            .expect("CPU bundler config should load");
        let gpu_bit = CapabilityFlags::from_bits(
            CapabilityFlags::FEATURE_ENTROPY_BUNDLED | CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU,
        );
        let normalized_cpu = cpu_handle.normalize_viewer_feature_bits(gpu_bit);
        assert!(
            normalized_cpu.contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            "bundled mode must preserve FEATURE_ENTROPY_BUNDLED"
        );
        assert!(
            normalized_cpu.contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "CPU handle must enforce FEATURE_BUNDLE_ACCEL_CPU_SIMD"
        );
        assert!(
            !normalized_cpu.contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
            "CPU handle must drop conflicting GPU bits"
        );
        let mut gpu_handle = StreamingHandle::new();
        codec.bundle_accel = actual::BundleAcceleration::Gpu;
        let gpu_result = gpu_handle.apply_codec_config(&codec);
        if norito::streaming::BUNDLED_RANS_GPU_BUILD_AVAILABLE {
            gpu_result.expect("GPU bundler config should load");
            let cpu_caps = CapabilityFlags::from_bits(
                CapabilityFlags::FEATURE_ENTROPY_BUNDLED
                    | CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD,
            );
            let normalized_gpu_caps = gpu_handle.normalize_viewer_feature_bits(cpu_caps);
            assert!(
                normalized_gpu_caps.contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
                "bundled mode must preserve FEATURE_ENTROPY_BUNDLED"
            );
            assert!(
                normalized_gpu_caps.contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
                "GPU handle must enforce FEATURE_BUNDLE_ACCEL_GPU"
            );
            assert!(
                !normalized_gpu_caps.contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
                "GPU handle must drop conflicting CPU bits"
            );
        } else {
            let err = gpu_result.expect_err("cpu-only builds must reject GPU bundle acceleration");
            match err {
                StreamingCodecConfigError::BundleAccelerationUnavailable { requested } => {
                    assert_eq!(requested, actual::BundleAcceleration::Gpu);
                }
                other => panic!("unexpected GPU bundle acceleration error: {other:?}"),
            }
        }
    }
    #[cfg(feature = "quic")]
    #[test]
    fn unsupported_feature_bits_rejected() {
        use norito::streaming::{AudioCapability, CapabilityReport, Resolution};
        let handle = StreamingHandle::new().with_capabilities(CapabilityFlags::from_bits(0));
        // Admit the mandatory codec bits, then request an unadvertised bit.
        let unsupported_bit = 1_u32 << 31;
        assert_eq!(handle.capabilities().bits() & unsupported_bit, 0);
        let report = CapabilityReport {
            stream_id: hash_with(0xDD),
            endpoint_role: CapabilityRole::Viewer,
            protocol_version: 1,
            max_resolution: Resolution::R720p,
            hdr_supported: false,
            capture_hdr: false,
            neural_bundles: Vec::new(),
            audio_caps: AudioCapability {
                sample_rates: vec![48_000],
                ambisonics: false,
                max_channels: 2,
            },
            feature_bits: handle.capabilities().insert(unsupported_bit),
            max_datagram_size: 900,
            dplpmtud: false,
        };
        let resolution = sample_resolution();
        let err = handle
            .build_capability_ack(&report, resolution)
            .expect_err("publisher should reject unsupported feature bits");
        assert!(matches!(
            err,
            StreamingProcessError::UnsupportedFeatures { requested_bits, supported_bits }
                if requested_bits == unsupported_bit && supported_bits == handle.capabilities().bits()
        ));
    }
    #[cfg(feature = "quic")]
    #[test]
    fn zero_capability_report_protocol_version_rejected() {
        use norito::streaming::{AudioCapability, CapabilityReport, Resolution};
        let handle = StreamingHandle::new().with_capabilities(CapabilityFlags::from_bits(0b101));
        let report = CapabilityReport {
            stream_id: hash_with(0xDE),
            endpoint_role: CapabilityRole::Viewer,
            protocol_version: 0,
            max_resolution: Resolution::R720p,
            hdr_supported: false,
            capture_hdr: false,
            neural_bundles: Vec::new(),
            audio_caps: AudioCapability {
                sample_rates: vec![48_000],
                ambisonics: false,
                max_channels: 2,
            },
            feature_bits: CapabilityFlags::from_bits(0),
            max_datagram_size: 900,
            dplpmtud: false,
        };
        let resolution = sample_resolution();
        let err = handle
            .build_capability_ack(&report, resolution)
            .expect_err("publisher should reject zero protocol version");
        assert!(matches!(
            err,
            StreamingProcessError::InvalidProtocolVersion { found: 0 }
        ));
    }
    #[cfg(feature = "quic")]
    #[test]
    fn non_viewer_capability_report_role_rejected() {
        use norito::streaming::{AudioCapability, CapabilityReport, Resolution};
        let handle = StreamingHandle::new().with_capabilities(CapabilityFlags::from_bits(0b101));
        let report = CapabilityReport {
            stream_id: hash_with(0xDF),
            endpoint_role: CapabilityRole::Publisher,
            protocol_version: 1,
            max_resolution: Resolution::R720p,
            hdr_supported: false,
            capture_hdr: false,
            neural_bundles: Vec::new(),
            audio_caps: AudioCapability {
                sample_rates: vec![48_000],
                ambisonics: false,
                max_channels: 2,
            },
            feature_bits: CapabilityFlags::from_bits(0),
            max_datagram_size: 900,
            dplpmtud: false,
        };
        let resolution = sample_resolution();
        let err = handle
            .build_capability_ack(&report, resolution)
            .expect_err("publisher should reject non-viewer report role");
        assert!(matches!(
            err,
            StreamingProcessError::InvalidCapabilityReportRole {
                expected: CapabilityRole::Viewer,
                found: CapabilityRole::Publisher
            }
        ));
    }
    include!("streaming/snapshot_bounds_and_capability_tests.rs");
}
