//! Norito Streaming Codec (NSC) manifest, control, and telemetry data structures.
//!
//! These types follow the specification in `norito_streaming.md` and provide the
//! serialization surface referenced by the roadmap implementation plan. They do
//! not perform any validation or crypto; callers are responsible for enforcing
//! protocol rules before encoding or after decoding values.
/// `true` when CABAC code paths were compiled (`ENABLE_CABAC=1` set at build time).
pub const CABAC_BUILD_AVAILABLE: bool = cfg!(norito_enable_cabac);
/// `true` when trellis scan code paths were compiled (`ENABLE_TRELLIS=1` set at build time).
pub const TRELLIS_BUILD_AVAILABLE: bool = cfg!(norito_enable_trellis);
/// `true` when bundled rANS code paths were compiled (`ENABLE_RANS_BUNDLES=1` set at build time).
pub const BUNDLED_RANS_BUILD_AVAILABLE: bool = cfg!(norito_enable_rans_bundles);
/// `true` when GPU bundle-acceleration hooks are compiled (requires bundled rANS plus a GPU feature flag).
pub const BUNDLED_RANS_GPU_BUILD_AVAILABLE: bool = cfg!(all(
    norito_enable_rans_bundles,
    any(
        feature = "codec-gpu",
        feature = "codec-gpu-metal",
        feature = "codec-gpu-cuda"
    )
));
use crate::{
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
    core::{self as norito_core, DecodeFromSlice, Error as CoreError},
    json,
    json::Value as NoritoJsonValue,
};
use core::{fmt, str::FromStr};
use thiserror::Error;
/// Blake3-based 32-byte hash used across NSC metadata (chunk commitments, IDs, etc.).
pub type Hash = [u8; 32];
/// Compute the canonical BLAKE3 digest used by content-addressed streaming artifacts.
///
/// Keeping this adapter in Norito gives direct dependants one pinned,
/// deterministic implementation without duplicating the hash function or
/// changing their dependency graph.
#[must_use]
pub fn blake3_hash(bytes: &[u8]) -> Hash {
    blake3::hash(bytes).into()
}
/// Opaque incremental BLAKE3 state for bounded content-addressed readers.
///
/// This keeps the concrete hashing dependency inside Norito while allowing
/// consumers to authenticate artifacts that cannot safely be materialized as
/// one contiguous allocation.
pub struct Blake3Hasher(blake3::Hasher);
impl Blake3Hasher {
    /// Start a canonical unkeyed BLAKE3 digest.
    #[must_use]
    pub fn new() -> Self {
        Self(blake3::Hasher::new())
    }
    /// Absorb the next exact byte range in canonical order.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    /// Finish and return the canonical 32-byte digest.
    #[must_use]
    pub fn finalize(self) -> Hash {
        self.0.finalize().into()
    }
}
impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}
/// Ed25519 signature bytes as specified for manifests and control frames.
pub type Signature = [u8; 64];
/// Timestamp field used by manifests. The spec leaves the exact unit to deployments; NSC uses unix time.
pub type Timestamp = u64;
/// Convenience alias for opaque byte payloads (tickets, encrypted keys, QUIC frames).
pub type Bytes = Vec<u8>;
/// Multi-address string identifying QUIC ingress/egress endpoints.
pub type Multiaddr = String;
/// Canonical account identifier used by the Nexus streaming contracts.
pub type AccountId = String;
/// Data Space identifier (DSID) used to scope tickets and manifests.
pub type DataSpaceId = u64;
/// Identifier referencing a registered zero-knowledge verifier.
pub type VerifierId = [u8; 32];
/// Contract signature emitted by on-chain streaming access contracts.
pub type ContractSignature = Signature;
/// ISO-style region code used in ticket policies (e.g., "us", "eu").
pub type RegionCode = String;
pub use codec::{
    BundleContextRemap, BundleContextStats, BundledStats, BundledTelemetry, BundledToken,
    load_bundle_context_remap_from_json,
};
#[inline]
fn saturating_usize_to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
#[inline]
fn saturating_usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
/// Video profile identifier (`baseline`, `uhd_main`, `uhd_ai`, etc.).
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::ProfileId")]
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, NoritoSerialize, NoritoDeserialize,
)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ProfileId(pub u16);
impl ProfileId {
    /// Baseline SDR profile (`ProfileId = 0`).
    pub const BASELINE: Self = Self(0);
    /// HDR main profile (`ProfileId = 1`).
    pub const UHD_MAIN: Self = Self(1);
    /// HDR + neural residual profile (`ProfileId = 2`).
    pub const UHD_AI: Self = Self(2);
}
/// Entropy coder advertised by manifests and segment headers.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::EntropyMode")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, Default)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum EntropyMode {
    /// Multi-bit bundled rANS encoder.
    #[default]
    RansBundled,
}
impl EntropyMode {
    #[must_use]
    pub const fn is_bundled(self) -> bool {
        true
    }
    #[must_use]
    fn as_str(self) -> &'static str {
        "rans_bundled"
    }
}
impl fmt::Display for EntropyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Rate-distortion optimizer mode for the bundled entropy path.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::RdoMode")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum RdoMode {
    /// Skip RDO and emit coefficients as-is.
    #[default]
    None,
    /// Trellis-free DP optimizer with explicit energy buckets.
    DynamicProgramming,
    /// DP optimizer guided by a small int8 neural predictor.
    Neural,
    /// Perceptual lambda schedule tuned for SSIM-like behaviour.
    Perceptual,
}
impl RdoMode {
    pub const fn is_enabled(self) -> bool {
        !matches!(self, Self::None)
    }
}
impl FromStr for EntropyMode {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "rans_bundled" | "rans-bundled" => Ok(Self::RansBundled),
            _ => Err(()),
        }
    }
}
/// Bitfield describing manifest feature flags (HDR, neural bundle, privacy overlay, etc.).
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::CapabilityFlags")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct CapabilityFlags(u32);
impl CapabilityFlags {
    /// Feature bit enabling feedback hint frames (`ManifestV1::feedback_hint`).
    pub const FEATURE_FEEDBACK_HINTS: u32 = 1 << 0;
    /// Feature bit marking the publisher as a privacy overlay provider.
    pub const FEATURE_PRIVACY_PROVIDER: u32 = 1 << 1;
    /// Feature bit advertising SM transaction/signature support across the streaming control plane.
    pub const FEATURE_SM_TRANSACTIONS: u32 = 1 << 8;
    /// Feature bit advertising bundled rANS entropy support.
    pub const FEATURE_ENTROPY_BUNDLED: u32 = 1 << 9;
    /// Feature bit indicating bundled rANS paths execute on CPU SIMD accelerators.
    pub const FEATURE_BUNDLE_ACCEL_CPU_SIMD: u32 = 1 << 13;
    /// Feature bit indicating bundled rANS paths execute on GPU accelerators.
    pub const FEATURE_BUNDLE_ACCEL_GPU: u32 = 1 << 14;
    /// Creates a new flag wrapper from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
    /// Returns the underlying bit representation.
    pub const fn bits(self) -> u32 {
        self.0
    }
    /// Checks whether all bits in `mask` are set.
    pub const fn contains(self, mask: u32) -> bool {
        (self.0 & mask) == mask
    }
    /// Returns a new flag set with the provided mask applied.
    pub const fn insert(self, mask: u32) -> Self {
        Self(self.0 | mask)
    }
    /// Returns a new flag set with the provided mask removed.
    pub const fn remove(self, mask: u32) -> Self {
        Self(self.0 & !mask)
    }
}
/// Acceleration backend used for bundled entropy pipelines.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::BundleAcceleration")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum BundleAcceleration {
    /// No dedicated acceleration.
    #[default]
    None,
    /// CPU SIMD accelerated bundle processing.
    CpuSimd,
    /// GPU accelerated bundle processing.
    Gpu,
}
impl BundleAcceleration {
    /// Capability bit mask representing this acceleration choice.
    pub const fn capability_mask(self) -> u32 {
        match self {
            Self::None => 0,
            Self::CpuSimd => CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD,
            Self::Gpu => CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU,
        }
    }
}
/// Privacy relay capabilities advertised in `PrivacyRoute`.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::PrivacyCapabilities")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct PrivacyCapabilities(u32);
impl PrivacyCapabilities {
    /// Creates a new capability wrapper from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
    /// Returns the raw bitset.
    pub const fn bits(self) -> u32 {
        self.0
    }
}
/// FEC configuration advertised at the manifest or feedback layer.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::FecParameters")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct FecParameters {
    /// Active scheme identifier.
    pub scheme: FecScheme,
    /// Optional sliding-window step (segments/chunks) when applicable.
    pub window_step: Option<u8>,
    /// Number of parity symbols emitted for each protected window.
    pub parity_symbols: Option<u8>,
}
/// Per-layer rate/FEC/storage hints emitted by the adaptive controller.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::LayerFeedback")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct LayerFeedback {
    /// Layer index (temporal/spatial combined bit index as defined in the spec).
    pub layer_id: u8,
    /// Lower bitrate bound in kbps for the target layer.
    pub min_target_kbps: u32,
    /// Upper bitrate bound in kbps for the target layer.
    pub max_target_kbps: u32,
    /// Optional override for the preferred storage class for this layer.
    pub storage_hint: Option<StorageClass>,
}
/// Feedback emitted per segment so viewers and relays can adapt.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::FeedbackHint")]
#[derive(Clone, Debug, PartialEq, Eq, Default, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct FeedbackHint {
    /// Bitrate hints per layer.
    pub layer_hints: Vec<LayerFeedback>,
    /// Optional cadence override for `ReceiverReport` frames (milliseconds).
    pub report_interval_ms: Option<u16>,
    /// Active FEC parameters.
    pub fec: Option<FecParameters>,
}
/// HPKE suites supported by the transport negotiation.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::HpkeSuite")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum HpkeSuite {
    /// Kyber768 + ChaCha20Poly1305 operated in AuthPsk mode (`suite_id = 0x0001`).
    Kyber768AuthPsk,
    /// Kyber1024 + ChaCha20Poly1305 operated in AuthPsk mode (`suite_id = 0x0002`).
    Kyber1024AuthPsk,
}
impl HpkeSuite {
    /// Numeric identifier used by transport capability hashing.
    #[must_use]
    pub const fn suite_id(self) -> u16 {
        match self {
            Self::Kyber768AuthPsk => 0x0001,
            Self::Kyber1024AuthPsk => 0x0002,
        }
    }
    /// Converts the suite into a bit index used by [`HpkeSuiteMask`].
    #[must_use]
    pub const fn bit(self) -> u16 {
        match self {
            Self::Kyber768AuthPsk => 0,
            Self::Kyber1024AuthPsk => 1,
        }
    }
}
/// Bitmask describing the HPKE suites supported by an endpoint.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::HpkeSuiteMask")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct HpkeSuiteMask(u16);
impl HpkeSuiteMask {
    /// Empty mask (no suites supported).
    pub const EMPTY: Self = Self(0);
    /// Convenience constant containing Suite #1 (Kyber768).
    pub const KYBER768: Self = Self(1 << HpkeSuite::Kyber768AuthPsk.bit());
    /// Convenience constant containing Suite #2 (Kyber1024).
    pub const KYBER1024: Self = Self(1 << HpkeSuite::Kyber1024AuthPsk.bit());
    /// Construct a mask that advertises a single suite.
    #[must_use]
    pub const fn from_suite(suite: HpkeSuite) -> Self {
        Self(1 << suite.bit())
    }
    /// Returns the raw bit representation.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }
    /// Construct a mask from raw bits.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }
    /// Returns true when the given suite is advertised in this mask.
    #[must_use]
    pub const fn contains(self, suite: HpkeSuite) -> bool {
        (self.0 & (1 << suite.bit())) != 0
    }
    /// Computes the intersection of two masks.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
    /// Returns the lowest-index suite present in the mask.
    #[must_use]
    pub const fn lowest(self) -> Option<HpkeSuite> {
        if self.contains(HpkeSuite::Kyber768AuthPsk) {
            Some(HpkeSuite::Kyber768AuthPsk)
        } else if self.contains(HpkeSuite::Kyber1024AuthPsk) {
            Some(HpkeSuite::Kyber1024AuthPsk)
        } else {
            None
        }
    }
}
/// Privacy bucket configuration used when redacting telemetry counters.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::PrivacyBucketGranularity")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum PrivacyBucketGranularity {
    /// Standard NSC v1 aggregation rules (1% loss buckets, 1 ms latency bands).
    StandardV1,
}
/// Transport capability advertisement exchanged during the QUIC handshake.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::TransportCapabilities")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct TransportCapabilities {
    /// HPKE suite mask describing supported cipher suites.
    pub hpke_suites: HpkeSuiteMask,
    /// Whether the endpoint can send/receive QUIC DATAGRAM frames.
    pub supports_datagram: bool,
    /// Maximum DATAGRAM payload size (bytes) the endpoint can accept per segment chunk.
    pub max_segment_datagram_size: u16,
    /// Preferred interval (milliseconds) between `FeedbackHint` frames.
    pub fec_feedback_interval_ms: u16,
    /// Privacy bucket configuration applied to telemetry exports.
    pub privacy_bucket_granularity: PrivacyBucketGranularity,
}
impl TransportCapabilities {
    /// Convenience helper building the mandatory Kyber768 + DATAGRAM profile.
    #[must_use]
    pub const fn kyber768_default() -> Self {
        Self {
            hpke_suites: HpkeSuiteMask::KYBER768,
            supports_datagram: true,
            max_segment_datagram_size: u16::MAX,
            fec_feedback_interval_ms: 250,
            privacy_bucket_granularity: PrivacyBucketGranularity::StandardV1,
        }
    }
}
/// Resolved transport configuration derived from the two advertised capability sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportCapabilityResolution {
    /// Selected HPKE suite.
    pub hpke_suite: HpkeSuite,
    /// Indicates whether DATAGRAM delivery is enabled for this session.
    pub use_datagram: bool,
    /// Maximum DATAGRAM payload size agreed upon by the peers.
    pub max_segment_datagram_size: u16,
    /// Interval (milliseconds) between feedback hints.
    pub fec_feedback_interval_ms: u16,
    /// Privacy bucket configuration negotiated for telemetry exports.
    pub privacy_bucket_granularity: PrivacyBucketGranularity,
}
impl TransportCapabilityResolution {
    /// Compute the canonical hash recorded inside manifests for auditing.
    #[must_use]
    pub fn capabilities_hash(&self) -> Hash {
        const DOMAIN: &[u8] = b"nsc-transport-capabilities";
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN);
        hasher.update(&self.hpke_suite.suite_id().to_le_bytes());
        hasher.update(&[self.use_datagram as u8]);
        hasher.update(&self.max_segment_datagram_size.to_le_bytes());
        hasher.update(&self.fec_feedback_interval_ms.to_le_bytes());
        hasher.update(&[self.privacy_bucket_granularity as u8]);
        hasher.finalize().into()
    }
}
/// Errors encountered when resolving advertised transport capabilities.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransportCapabilityError {
    /// The two endpoints have no compatible HPKE suites.
    #[error("no shared HPKE suite between peers")]
    NoSharedHpkeSuite,
    /// Privacy bucket configurations could not be reconciled.
    #[error("privacy bucket granularity mismatch: local {local:?}, remote {remote:?}")]
    PrivacyBucketMismatch {
        /// Local privacy bucket configuration.
        local: PrivacyBucketGranularity,
        /// Remote privacy bucket configuration.
        remote: PrivacyBucketGranularity,
    },
    /// The advertised DATAGRAM size was zero while the peer expected DATAGRAM support.
    #[error("invalid datagram size advertised ({0} bytes)")]
    InvalidDatagramSize(u16),
}
/// Resolve the transport capabilities advertised by two endpoints.
pub fn resolve_transport_capabilities(
    local: &TransportCapabilities,
    remote: &TransportCapabilities,
) -> Result<TransportCapabilityResolution, TransportCapabilityError> {
    let shared = local.hpke_suites.intersection(remote.hpke_suites);
    let hpke_suite = shared
        .lowest()
        .ok_or(TransportCapabilityError::NoSharedHpkeSuite)?;
    if local.privacy_bucket_granularity != remote.privacy_bucket_granularity {
        return Err(TransportCapabilityError::PrivacyBucketMismatch {
            local: local.privacy_bucket_granularity,
            remote: remote.privacy_bucket_granularity,
        });
    }
    let use_datagram = local.supports_datagram && remote.supports_datagram;
    let max_segment_datagram_size = if use_datagram {
        let negotiated = local
            .max_segment_datagram_size
            .min(remote.max_segment_datagram_size);
        if negotiated == 0 {
            return Err(TransportCapabilityError::InvalidDatagramSize(negotiated));
        }
        negotiated
    } else {
        0
    };
    let fec_feedback_interval_ms = local
        .fec_feedback_interval_ms
        .max(remote.fec_feedback_interval_ms);
    Ok(TransportCapabilityResolution {
        hpke_suite,
        use_datagram,
        max_segment_datagram_size,
        fec_feedback_interval_ms,
        privacy_bucket_granularity: local.privacy_bucket_granularity,
    })
}
/// Storage tier for a segment.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::StorageClass")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum StorageClass {
    /// Short-retention, lower-cost storage.
    Ephemeral,
    /// Long-retention, higher-cost storage.
    Permanent,
}
/// Available FEC schemes.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::FecScheme")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum FecScheme {
    /// Mandatory RS 12/10 configuration.
    Rs12_10,
    /// Sliding-window RS 14/10 variant.
    RsWin14_10,
    /// Sliding-window RS 18/14 variant.
    Rs18_14,
}
/// Encryption suite negotiated for segments/control frames.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::EncryptionSuite")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum EncryptionSuite {
    /// X25519 + ChaCha20-Poly1305 using the referenced key fingerprint.
    X25519ChaCha20Poly1305(Hash),
    /// Kyber768 + XChaCha20-Poly1305 using the referenced key fingerprint.
    Kyber768XChaCha20Poly1305(Hash),
}
/// Basic manifest metadata visible to viewers.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::StreamMetadata")]
#[derive(Clone, Debug, PartialEq, Eq, Default, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct StreamMetadata {
    pub title: String,
    pub description: Option<String>,
    pub access_policy_id: Option<Hash>,
    pub tags: Vec<String>,
}
/// Privacy relay descriptor used in manifest routes.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::PrivacyRelay")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct PrivacyRelay {
    pub relay_id: Hash,
    pub endpoint: Multiaddr,
    pub key_fingerprint: Hash,
    pub capabilities: PrivacyCapabilities,
}
/// Authentication posture applied when exiting a SoraNet circuit.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::SoranetAccessKind")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum SoranetAccessKind {
    /// Exit relays only expose read-only content (no authenticated mutations).
    ReadOnly,
    /// Exit relays require viewer authentication/tickets before forwarding.
    Authenticated,
}
/// Stream tags advertised by SoraNet relays to differentiate exit adapters.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::SoranetStreamTag")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum SoranetStreamTag {
    /// Norito RPC/streaming bridge.
    #[default]
    NoritoStream,
    /// Kaigi real-time conferencing bridge.
    Kaigi,
}
/// Blinded identifier for the streaming circuit advertised by a relay directory.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::SoranetChannelId")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct SoranetChannelId(pub [u8; 32]);
impl SoranetChannelId {
    /// Total number of bytes carried by the identifier.
    pub const LENGTH: usize = 32;
    /// Construct a blinded channel identifier from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Borrow the underlying byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl From<[u8; 32]> for SoranetChannelId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
impl From<SoranetChannelId> for [u8; 32] {
    fn from(id: SoranetChannelId) -> Self {
        id.0
    }
}
impl AsRef<[u8; 32]> for SoranetChannelId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Parameters required to bridge a privacy route over a SoraNet circuit.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::SoranetRoute")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct SoranetRoute {
    /// Blinded channel identifier negotiated during circuit admission.
    pub channel_id: SoranetChannelId,
    /// Exit relay multiaddr that forwards decrypted traffic to Torii.
    pub exit_multiaddr: Multiaddr,
    /// Optional padding budget (milliseconds) applied for low-latency tuning.
    pub padding_budget_ms: Option<u16>,
    /// Access posture enforced by the exit relay.
    pub access_kind: SoranetAccessKind,
    /// Stream tag describing the exit adapter.
    #[norito(default)]
    pub stream_tag: SoranetStreamTag,
}
impl<'a> DecodeFromSlice<'a> for SoranetRoute {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), CoreError> {
        norito_core::decode_field_canonical::<Self>(bytes)
    }
}
/// An entry/exit route authorizing privacy-preserving transport.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::PrivacyRoute")]
#[derive(Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct PrivacyRoute {
    pub route_id: Hash,
    pub entry: PrivacyRelay,
    pub exit: PrivacyRelay,
    pub ticket_entry: Bytes,
    pub ticket_exit: Bytes,
    pub expiry_segment: u64,
    #[norito(skip_serializing_if = "Option::is_none")]
    #[norito(default)]
    pub soranet: Option<SoranetRoute>,
}
impl fmt::Debug for PrivacyRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivacyRoute")
            .field("route_id", &self.route_id)
            .field("entry", &self.entry)
            .field("exit", &self.exit)
            .field(
                "ticket_entry",
                &format_args!("<redacted:{} bytes>", self.ticket_entry.len()),
            )
            .field(
                "ticket_exit",
                &format_args!("<redacted:{} bytes>", self.ticket_exit.len()),
            )
            .field("expiry_segment", &self.expiry_segment)
            .field("soranet", &self.soranet)
            .finish()
    }
}
/// Optional neural enhancement bundle metadata.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::NeuralBundle")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct NeuralBundle {
    pub bundle_id: String,
    pub weights_sha256: Hash,
    pub activation_scale: Vec<i16>,
    pub bias: Vec<i32>,
    pub metadata_signature: Signature,
    pub metal_shader_sha256: Option<Hash>,
    pub cuda_ptx_sha256: Option<Hash>,
}
/// Bitfield describing which playback profiles a capability ticket authorizes.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::TicketCapabilities")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct TicketCapabilities(u32);
impl TicketCapabilities {
    /// Capability flag allowing live streaming access.
    pub const LIVE: u32 = 1 << 0;
    /// Capability flag allowing video-on-demand playback.
    pub const VOD: u32 = 1 << 1;
    /// Capability flag unlocking premium rendering profiles (e.g., UHD AI).
    pub const PREMIUM_PROFILE: u32 = 1 << 2;
    /// Capability flag enabling HDR ladder selection.
    pub const HDR: u32 = 1 << 3;
    /// Capability flag enabling spatial audio playback.
    pub const SPATIAL_AUDIO: u32 = 1 << 4;
    /// Construct a capability flag wrapper from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
    /// Retrieve the underlying bit representation.
    pub const fn bits(self) -> u32 {
        self.0
    }
    /// Check whether all flags in `mask` are enabled.
    pub const fn contains(self, mask: u32) -> bool {
        (self.0 & mask) == mask
    }
    /// Return a new flag set with the provided `mask` inserted.
    pub const fn insert(self, mask: u32) -> Self {
        Self(self.0 | mask)
    }
    /// Return a new flag set with the provided `mask` cleared.
    pub const fn remove(self, mask: u32) -> Self {
        Self(self.0 & !mask)
    }
}
/// Optional policy constraints embedded in capability tickets.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::TicketPolicy")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct TicketPolicy {
    /// Maximum number of relays that may concurrently serve this ticket.
    pub max_relays: u16,
    /// Regions authorized to serve the ticket (ISO-style codes).
    pub allowed_regions: Vec<RegionCode>,
    /// Optional bandwidth cap in kilobits per second.
    pub max_bandwidth_kbps: Option<u32>,
}
/// Codec projection of streaming ticket metadata emitted by the ledger runtime.
///
/// This data-only type does not authenticate an issuer, verify a proof, debit
/// traffic entitlements, or authorize relay access. Those decisions belong to
/// the ledger event producer and the stateful streaming runtime; decoding this
/// structure alone never establishes ticket authority.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::StreamingTicket")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct StreamingTicket {
    pub ticket_id: Hash,
    pub owner: AccountId,
    pub dsid: DataSpaceId,
    pub lane_id: u8,
    pub settlement_bucket: u64,
    pub start_slot: u64,
    pub expire_slot: u64,
    pub prepaid_teu: u128,
    pub chunk_teu: u32,
    pub fanout_quota: u16,
    pub key_commitment: Hash,
    pub nonce: u64,
    pub contract_sig: ContractSignature,
    pub commitment: Hash,
    pub nullifier: Hash,
    pub proof_id: VerifierId,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub policy: Option<TicketPolicy>,
    pub capabilities: TicketCapabilities,
}
/// Ticket revocation payload carrying nullifier metadata.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::TicketRevocation")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct TicketRevocation {
    pub ticket_id: Hash,
    pub nullifier: Hash,
    pub reason_code: u16,
    pub revocation_signature: ContractSignature,
}
/// Manifest describing a single NSC segment.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::ManifestV1")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ManifestV1 {
    pub stream_id: Hash,
    pub protocol_version: u16,
    pub segment_number: u64,
    pub published_at: Timestamp,
    pub profile: ProfileId,
    #[norito(default)]
    pub entropy_mode: EntropyMode,
    #[norito(default)]
    pub entropy_tables_checksum: Option<Hash>,
    pub da_endpoint: Multiaddr,
    pub chunk_root: Hash,
    pub content_key_id: u64,
    pub nonce_salt: Hash,
    pub chunk_descriptors: Vec<ChunkDescriptor>,
    pub transport_capabilities_hash: Hash,
    pub encryption_suite: EncryptionSuite,
    pub fec_suite: FecScheme,
    pub privacy_routes: Vec<PrivacyRoute>,
    pub neural_bundle: Option<NeuralBundle>,
    pub audio_summary: Option<AudioTrackSummary>,
    pub public_metadata: StreamMetadata,
    pub capabilities: CapabilityFlags,
    pub signature: Signature,
}
/// Segment header persisted alongside chunk data.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::SegmentHeader")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct SegmentHeader {
    pub segment_number: u64,
    pub profile: ProfileId,
    #[norito(default)]
    pub entropy_mode: EntropyMode,
    #[norito(default)]
    pub entropy_tables_checksum: Option<Hash>,
    pub encryption_suite: EncryptionSuite,
    pub layer_bitmap: u32,
    pub chunk_merkle_root: Hash,
    pub chunk_count: u16,
    pub timeline_start_ns: u64,
    pub duration_ns: u32,
    pub feedback_hint: FeedbackHint,
    pub content_key_id: u64,
    pub nonce_salt: Hash,
    pub storage_class: StorageClass,
    pub audio_summary: Option<AudioTrackSummary>,
    #[norito(default)]
    pub bundle_acceleration: BundleAcceleration,
}
/// Chunk descriptor within a segment.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::ChunkDescriptor")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ChunkDescriptor {
    pub chunk_id: u16,
    pub offset: u32,
    pub length: u32,
    pub commitment: Hash,
    pub parity: bool,
}
/// Merkle proof for DA validation.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::MerkleProof")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct MerkleProof {
    pub chunk_id: u16,
    pub sibling_hashes: Vec<Hash>,
    pub directions: Vec<bool>,
}
/// Data availability proof submitted on-chain.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::DataAvailabilityProof")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct DataAvailabilityProof {
    pub segment_number: u64,
    pub chunk_root: Hash,
    pub content_key_id: u64,
    pub chunk_ids: Vec<u16>,
    pub merkle_proofs: Vec<MerkleProof>,
    pub storage_commitment: Hash,
    pub validator_signature: Signature,
}
/// Control stream frames exchanged over QUIC.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::ControlFrame")]
#[derive(Clone, Debug, PartialEq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum ControlFrame {
    ManifestAnnounce(Box<ManifestAnnounceFrame>),
    ChunkRequest(ChunkRequestFrame),
    ChunkAcknowledge(ChunkAcknowledgeFrame),
    TransportCapabilities(TransportCapabilitiesFrame),
    CapabilityReport(CapabilityReport),
    CapabilityAck(CapabilityAck),
    FeedbackHint(FeedbackHintFrame),
    ReceiverReport(ReceiverReport),
    KeyUpdate(KeyUpdate),
    ContentKeyUpdate(ContentKeyUpdate),
    PrivacyRouteUpdate(PrivacyRouteUpdate),
    PrivacyRouteAck(PrivacyRouteAckFrame),
    Error(ControlErrorFrame),
}
/// Error codes used in control frames.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::ErrorCode")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum ErrorCode {
    UnknownChunk,
    AccessDenied,
    RateLimited,
    ProtocolViolation,
}
/// Session key update frame payload.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::KeyUpdate")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct KeyUpdate {
    pub session_id: Hash,
    pub suite: EncryptionSuite,
    pub protocol_version: u16,
    pub pub_ephemeral: Bytes,
    pub key_counter: u64,
    pub signature: Signature,
}
/// Group content key update payload.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::ContentKeyUpdate")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ContentKeyUpdate {
    pub content_key_id: u64,
    pub gck_wrapped: Bytes,
    pub valid_from_segment: u64,
}
/// Privacy route provisioning payload.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::PrivacyRouteUpdate")]
#[derive(Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct PrivacyRouteUpdate {
    pub route_id: Hash,
    pub stream_id: Hash,
    pub content_key_id: u64,
    pub valid_from_segment: u64,
    pub valid_until_segment: u64,
    pub exit_token: Bytes,
    #[norito(skip_serializing_if = "Option::is_none")]
    #[norito(default)]
    pub soranet: Option<SoranetRoute>,
}
impl fmt::Debug for PrivacyRouteUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivacyRouteUpdate")
            .field("route_id", &self.route_id)
            .field("stream_id", &self.stream_id)
            .field("content_key_id", &self.content_key_id)
            .field("valid_from_segment", &self.valid_from_segment)
            .field("valid_until_segment", &self.valid_until_segment)
            .field(
                "exit_token",
                &format_args!("<redacted:{} bytes>", self.exit_token.len()),
            )
            .field("soranet", &self.soranet)
            .finish()
    }
}
/// Capability negotiation report.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::CapabilityReport")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct CapabilityReport {
    pub stream_id: Hash,
    pub endpoint_role: CapabilityRole,
    pub protocol_version: u16,
    pub max_resolution: Resolution,
    pub hdr_supported: bool,
    pub capture_hdr: bool,
    pub neural_bundles: Vec<String>,
    pub audio_caps: AudioCapability,
    pub feature_bits: CapabilityFlags,
    pub max_datagram_size: u16,
    pub dplpmtud: bool,
}
/// Capability negotiation acknowledgement.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::CapabilityAck")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct CapabilityAck {
    pub stream_id: Hash,
    pub accepted_version: u16,
    pub negotiated_features: CapabilityFlags,
    pub max_datagram_size: u16,
    pub dplpmtud: bool,
}
/// Endpoint role during capability negotiation.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::CapabilityRole")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum CapabilityRole {
    Publisher,
    Viewer,
}
/// Audio capability advertisement.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::AudioCapability")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioCapability {
    pub sample_rates: Vec<u32>,
    pub ambisonics: bool,
    pub max_channels: u8,
}
/// Supported output resolutions.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::Resolution")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum Resolution {
    R720p,
    R1080p,
    R1440p,
    R2160p,
    Custom(ResolutionCustom),
}
/// Audio frame layout (mono, stereo, ambisonics).
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::AudioLayout")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum AudioLayout {
    Mono,
    Stereo,
    FirstOrderAmbisonics,
}
impl AudioLayout {
    #[must_use]
    pub const fn channel_count(self) -> usize {
        match self {
            Self::Mono => 1,
            Self::Stereo => 2,
            Self::FirstOrderAmbisonics => 4,
        }
    }
}
impl From<AudioLayout> for iroha_audio::ChannelLayout {
    fn from(value: AudioLayout) -> Self {
        match value {
            AudioLayout::Mono => iroha_audio::ChannelLayout::Mono,
            AudioLayout::Stereo => iroha_audio::ChannelLayout::Stereo,
            AudioLayout::FirstOrderAmbisonics => iroha_audio::ChannelLayout::FirstOrderAmbisonics,
        }
    }
}
impl From<iroha_audio::ChannelLayout> for AudioLayout {
    fn from(value: iroha_audio::ChannelLayout) -> Self {
        match value {
            iroha_audio::ChannelLayout::Mono => AudioLayout::Mono,
            iroha_audio::ChannelLayout::Stereo => AudioLayout::Stereo,
            iroha_audio::ChannelLayout::FirstOrderAmbisonics => AudioLayout::FirstOrderAmbisonics,
        }
    }
}
/// Encoded audio frame aligned with a video segment.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::AudioFrame")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioFrame {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub fec_level: u8,
    pub channel_layout: AudioLayout,
    pub payload: Bytes,
}
/// Summary describing the audio track present in a segment.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::AudioTrackSummary")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioTrackSummary {
    pub sample_rate: u32,
    pub frame_samples: u16,
    pub frame_duration_ns: u32,
    pub frames_per_segment: u16,
    pub layout: AudioLayout,
    pub fec_level: u8,
}
/// Encoded audio payload accompanying a segment.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::SegmentAudio")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct SegmentAudio {
    pub summary: AudioTrackSummary,
    pub frames: Vec<AudioFrame>,
}
impl<'a> crate::core::DecodeFromSlice<'a> for SegmentAudio {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), crate::Error> {
        crate::core::decode_field_canonical::<SegmentAudio>(bytes)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioPcmLengthMismatchInfo {
    pub expected: u64,
    pub found: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioChannelCountMismatchInfo {
    pub expected: u8,
    pub found: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioEncoderSampleCountMismatchInfo {
    pub expected: u16,
    pub found: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioBackendFailureInfo {
    pub message: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioCodecLayoutMismatchInfo {
    pub expected: AudioLayout,
    pub found: AudioLayout,
}
/// Errors emitted by the audio encoding/decoding layer.
#[derive(Debug, Error)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum AudioCodecError {
    #[error(
        "expected {expected} PCM samples, got {found}",
        expected = .0.expected,
        found = .0.found
    )]
    InvalidPcmLength(AudioPcmLengthMismatchInfo),
    #[error(
        "audio layout mismatch: expected {expected:?}, found {found:?}",
        expected = .0.expected,
        found = .0.found
    )]
    LayoutMismatch(AudioCodecLayoutMismatchInfo),
    #[error("unsupported audio payload version {0}")]
    UnsupportedVersion(u8),
    #[error("audio packet too short")]
    PacketTooShort,
    #[error(
        "invalid channel count: expected {expected}, found {found}",
        expected = .0.expected,
        found = .0.found
    )]
    InvalidChannelCount(AudioChannelCountMismatchInfo),
    #[error(
        "invalid frame sample count: expected {expected}, found {found}",
        expected = .0.expected,
        found = .0.found
    )]
    InvalidSampleCount(AudioEncoderSampleCountMismatchInfo),
    #[error("audio backend unavailable for layout {0:?}")]
    BackendUnavailable(AudioLayout),
    #[error("audio backend failure: {message}", message = .0.message)]
    BackendFailure(AudioBackendFailureInfo),
    #[error("audio backend does not support layout {0:?}")]
    BackendUnsupportedLayout(AudioLayout),
}
impl AudioCodecError {
    fn from_backend(err: iroha_audio::CodecError) -> Self {
        match err {
            iroha_audio::CodecError::InvalidPcmLength { expected, found } => {
                Self::InvalidPcmLength(AudioPcmLengthMismatchInfo {
                    expected: saturating_usize_to_u64(expected),
                    found: saturating_usize_to_u64(found),
                })
            }
            iroha_audio::CodecError::UnsupportedVersion(version) => {
                Self::UnsupportedVersion(version)
            }
            iroha_audio::CodecError::PacketTooShort => Self::PacketTooShort,
            iroha_audio::CodecError::InvalidChannelCount { expected, found } => {
                let expected = expected.unwrap_or(found);
                Self::InvalidChannelCount(AudioChannelCountMismatchInfo { expected, found })
            }
            iroha_audio::CodecError::InvalidSampleCount { expected, found } => {
                Self::InvalidSampleCount(AudioEncoderSampleCountMismatchInfo { expected, found })
            }
            iroha_audio::CodecError::BackendUnavailable { layout } => {
                Self::BackendUnavailable(layout.into())
            }
            iroha_audio::CodecError::LibopusError { message } => {
                Self::BackendFailure(AudioBackendFailureInfo {
                    message: message.to_string(),
                })
            }
            iroha_audio::CodecError::UnsupportedLayout { layout } => {
                Self::BackendUnsupportedLayout(layout.into())
            }
        }
    }
}
impl SegmentAudio {
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}
/// Viewer-side congestion feedback emitted at the negotiated cadence.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::FeedbackHintFrame")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct FeedbackHintFrame {
    /// Stream identifier associated with the feedback sample.
    pub stream_id: Hash,
    /// Exponential weighted moving average of loss (Q16.16 fixed-point).
    pub loss_ewma_q16: u32,
    /// Latency gradient (Q16.16, signed) over the last interval.
    pub latency_gradient_q16: i32,
    /// Observed round-trip time in milliseconds.
    pub observed_rtt_ms: u16,
    /// Preferred interval (milliseconds) between `ReceiverReport` frames.
    pub report_interval_ms: u16,
    /// Publisher-selected parity budget for the next window.
    pub parity_chunks: u8,
}
/// Receiver telemetry sent during playback.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::ReceiverReport")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ReceiverReport {
    pub stream_id: Hash,
    pub latest_segment: u64,
    pub layer_mask: u32,
    pub measured_throughput_kbps: u32,
    pub rtt_ms: u16,
    pub loss_percent_x100: u16,
    pub decoder_buffer_ms: u16,
    pub active_resolution: Resolution,
    pub hdr_active: bool,
    pub ecn_ce_count: u32,
    pub jitter_ms: u16,
    /// Highest delivered datagram/sequence number in the last window.
    pub delivered_sequence: u64,
    /// Redundancy parity chunks applied by the viewer during the last window.
    pub parity_applied: u8,
    /// Recommended parity budget for the next window.
    pub fec_budget: u8,
    /// Optional viewer-provided sync diagnostics for validator enforcement.
    pub sync_diagnostics: Option<SyncDiagnostics>,
}
/// Result of an operational audit routed through the telemetry bridge.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::TelemetryAuditOutcome")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct TelemetryAuditOutcome {
    /// Identifier of the audit trace (e.g., `TRACE-TELEMETRY-BRIDGE`).
    pub trace_id: String,
    /// Slot height associated with the audit evaluation.
    pub slot_height: u64,
    /// Reviewer responsible for signing off the audit.
    pub reviewer: String,
    /// Audit verdict (`pass`, `fail`, `mitigated`, etc.).
    pub status: String,
    /// Optional mitigation URL with runbooks or RCA notes.
    pub mitigation_url: Option<String>,
}
/// Telemetry emitted by publisher/decoder implementations.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::TelemetryEvent")]
#[derive(Clone, Debug, PartialEq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum TelemetryEvent {
    Encode(TelemetryEncodeStats),
    Decode(TelemetryDecodeStats),
    Network(TelemetryNetworkStats),
    Security(TelemetrySecurityStats),
    Energy(TelemetryEnergyStats),
    AuditOutcome(TelemetryAuditOutcome),
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::ManifestAnnounceFrame")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ManifestAnnounceFrame {
    pub manifest: ManifestV1,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::ChunkRequestFrame")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ChunkRequestFrame {
    pub segment: u64,
    pub chunk_id: u16,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::ChunkAcknowledgeFrame")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ChunkAcknowledgeFrame {
    pub segment: u64,
    pub chunk_id: u16,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::TransportCapabilitiesFrame")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct TransportCapabilitiesFrame {
    pub endpoint_role: CapabilityRole,
    pub capabilities: TransportCapabilities,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::PrivacyRouteAckFrame")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct PrivacyRouteAckFrame {
    pub route_id: Hash,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::ControlErrorFrame")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ControlErrorFrame {
    pub code: ErrorCode,
    pub message: String,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::ResolutionCustom")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ResolutionCustom {
    pub width: u16,
    pub height: u16,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::TelemetryEncodeStats")]
#[derive(Clone, Copy, Debug, PartialEq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct TelemetryEncodeStats {
    pub segment: u64,
    pub avg_latency_ms: u16,
    pub dropped_layers: u32,
    pub avg_audio_jitter_ms: u16,
    pub max_audio_jitter_ms: u16,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::TelemetryDecodeStats")]
#[derive(Clone, Copy, Debug, PartialEq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct TelemetryDecodeStats {
    pub segment: u64,
    pub buffer_ms: u16,
    pub dropped_frames: u16,
    pub max_decode_queue_ms: u16,
    pub avg_av_drift_ms: i16,
    pub max_av_drift_ms: u16,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::TelemetryNetworkStats")]
#[derive(Clone, Copy, Debug, PartialEq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct TelemetryNetworkStats {
    pub rtt_ms: u16,
    pub loss_percent_x100: u16,
    pub fec_repairs: u32,
    pub fec_failures: u32,
    pub datagram_reinjects: u32,
}
/// Aggregated viewer sync diagnostics transmitted with [`ReceiverReport`] frames.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::SyncDiagnostics")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct SyncDiagnostics {
    /// Rolling aggregation window covering the metrics, in milliseconds.
    pub window_ms: u16,
    /// Number of samples collected during the window.
    pub samples: u16,
    /// Average audio jitter recorded over the window (milliseconds).
    pub avg_audio_jitter_ms: u16,
    /// Maximum audio jitter observed during the window (milliseconds).
    pub max_audio_jitter_ms: u16,
    /// Average audio/video drift over the window (milliseconds, signed).
    pub avg_av_drift_ms: i16,
    /// Maximum absolute audio/video drift observed (milliseconds).
    pub max_av_drift_ms: u16,
    /// Exponentially weighted moving average of the drift (milliseconds, signed).
    pub ewma_av_drift_ms: i16,
    /// Count of samples exceeding the configured sync threshold within the window.
    pub violation_count: u16,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::TelemetrySecurityStats")]
#[derive(Clone, Copy, Debug, PartialEq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct TelemetrySecurityStats {
    pub suite: EncryptionSuite,
    pub rekeys: u32,
    pub gck_rotations: u32,
    pub last_content_key_id: Option<u64>,
    pub last_content_key_valid_from: Option<u64>,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::TelemetryEnergyStats")]
#[derive(Clone, Copy, Debug, PartialEq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct TelemetryEnergyStats {
    pub segment: u64,
    /// Encoder power draw reported in milliwatts.
    pub encoder_milliwatts: u32,
    /// Decoder power draw reported in milliwatts.
    pub decoder_milliwatts: u32,
}
macro_rules! impl_decode_from_slice_via_archived {
    ($($ty:ty),* $(,)?) => {
        $(
            impl<'a> DecodeFromSlice<'a> for $ty {
                fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), CoreError> {
                    norito_core::decode_field_canonical::<$ty>(bytes)
                }
            }
        )*
    };
}
impl_decode_from_slice_via_archived!(
    NeuralBundle,
    FecParameters,
    StorageClass,
    FecScheme,
    CapabilityFlags,
    PrivacyCapabilities,
    FeedbackHint,
    LayerFeedback,
    PrivacyRoute,
    PrivacyRelay,
    StreamMetadata,
    AudioTrackSummary,
    ManifestV1,
    SegmentHeader,
    ChunkDescriptor,
    MerkleProof,
    DataAvailabilityProof,
    ControlFrame,
    FeedbackHintFrame,
    KeyUpdate,
    ContentKeyUpdate,
    PrivacyRouteUpdate,
    CapabilityRole,
    CapabilityReport,
    CapabilityAck,
    EncryptionSuite,
    AudioCapability,
    Resolution,
    AudioLayout,
    AudioFrame,
    PrivacyBucketGranularity,
    TicketCapabilities,
    TicketPolicy,
    StreamingTicket,
    TicketRevocation,
    SyncDiagnostics,
    ReceiverReport,
    TelemetryEvent,
);
/// Frequency table for a single rANS symbol group.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::RansGroupTableV1")]
#[derive(
    Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct RansGroupTableV1 {
    /// Bit width (`log2(group_size)`) covered by this table.
    #[norito(default = "default_group_width_bits")]
    pub width_bits: u8,
    /// Number of symbols covered by this table.
    pub group_size: u16,
    /// Precision bits used when normalising frequencies.
    pub precision_bits: u8,
    /// Normalised symbol frequencies.
    pub frequencies: Vec<u16>,
    /// Cumulative distribution (CDF) for the symbol group.
    pub cumulative: Vec<u32>,
}
/// Deterministic rANS table set body.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::RansTablesBodyV1")]
#[derive(
    Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct RansTablesBodyV1 {
    /// Seed used to derive the frequency tables.
    pub seed: u64,
    /// Maximum bundle width (in bits) covered by this artefact.
    #[norito(default = "default_bundle_width")]
    pub bundle_width: u8,
    /// Frequency/cumulative tables per symbol group.
    pub groups: Vec<RansGroupTableV1>,
}
impl RansTablesBodyV1 {
    /// Compute the V1 table checksum over the complete uncompressed Norito frame.
    ///
    /// This checksum domain explicitly selects fixed-width per-value lengths
    /// (`flags = 0x00`), independently of the ambient layout or encode default.
    /// The frame includes this body's canonical schema identity and header.
    ///
    /// # Errors
    /// Returns an error if the body cannot be serialized.
    pub fn checksum_sha256(&self) -> Result<[u8; 32], CoreError> {
        use sha2::Digest as _;
        let _flags = norito_core::DecodeFlagsGuard::enter(0);
        Ok(sha2::Sha256::digest(norito_core::to_bytes(self)?).into())
    }
}
const fn default_bundle_width() -> u8 {
    0
}
const fn default_group_width_bits() -> u8 {
    0
}
/// Manifest describing deterministic rANS tables and metadata.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::RansTablesV1")]
#[derive(
    Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct RansTablesV1 {
    /// Manifest version (currently `1`).
    pub version: u16,
    /// Generation timestamp in unix seconds.
    pub generated_at: Timestamp,
    /// Git commit hash of the generator producing the tables.
    pub generator_commit: String,
    /// Canonical V1 checksum produced by [`RansTablesBodyV1::checksum_sha256`].
    pub checksum_sha256: [u8; 32],
    /// Deterministic table body.
    pub body: RansTablesBodyV1,
}
/// Signature algorithms supported for rANS table manifests.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::SignatureAlgorithm")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[norito(tag = "algorithm")]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum SignatureAlgorithm {
    /// Ed25519 signature.
    #[norito(rename = "ed25519")]
    Ed25519,
}
impl json::FastJsonWrite for SignatureAlgorithm {
    fn write_json(&self, out: &mut String) {
        let label = match self {
            SignatureAlgorithm::Ed25519 => "ed25519",
        };
        json::write_json_string(label, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_string_to("ed25519", out)
    }
}
#[cfg(test)]
mod signature_algorithm_json_tests {
    use super::*;
    #[test]
    fn signature_algorithm_has_exact_checked_json_bytes() {
        let value = SignatureAlgorithm::Ed25519;
        let expected = json::to_json(&value).expect("serialize signature algorithm");
        assert_eq!(expected, "\"ed25519\"");
        assert_eq!(
            json::to_json_bounded(&value, expected.len()).expect("serialize at exact bound"),
            expected
        );
        assert_eq!(
            json::to_json_bounded(&value, expected.len() - 1),
            Err(json::BoundedJsonError::BodyTooLarge)
        );
    }
}
impl json::JsonDeserialize for SignatureAlgorithm {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = parser.parse_string()?;
        match value.as_str() {
            "ed25519" => Ok(SignatureAlgorithm::Ed25519),
            other => Err(json::Error::Message(format!(
                "unsupported signature algorithm `{other}`"
            ))),
        }
    }
}
/// Optional signature wrapper for [`RansTablesV1`] payloads.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::RansTablesSignatureV1")]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct RansTablesSignatureV1 {
    /// Signature algorithm identifier.
    pub algorithm: SignatureAlgorithm,
    /// Raw public key bytes matching the signature.
    pub public_key: [u8; 32],
    /// Signature payload bytes.
    pub signature: [u8; 64],
}
/// Signed rANS table artefact optionally including an Ed25519 signature.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::SignedRansTablesV1")]
#[derive(
    Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct SignedRansTablesV1 {
    /// Table manifest and deterministic body.
    pub payload: RansTablesV1,
    /// Optional signature attesting the payload.
    pub signature: Option<RansTablesSignatureV1>,
}
pub mod crypto {
    use super::{CapabilityRole, ContentKeyUpdate, EncryptionSuite, Hash, KeyUpdate};
    use chacha20poly1305::{
        ChaCha20Poly1305, XChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };
    use hkdf::Hkdf;
    use sha3::Sha3_256;
    use thiserror::Error;
    const STS_SALT: &[u8] = b"nsc-sts";
    const STS_ROOT_LABEL: &[u8] = b"nsc-sts-root";
    const STS_SEND_LABEL: &[u8] = b"nsc-sts-send";
    const CEK_LABEL: &[u8] = b"nsc-cek";
    const NONCE_LABEL: &[u8] = b"nsc-nonce";
    const GCK_AAD_LABEL: &[u8] = b"nsc-gck";
    const STS_SHARED_SECRET_LEN: usize = 32;
    const GROUP_CONTENT_KEY_LEN: usize = 32;
    const X25519_EPHEMERAL_PUBLIC_LEN: usize = 32;
    const KYBER768_CIPHERTEXT_LEN: usize = 1088;
    /// Errors emitted by NSC crypto helpers.
    #[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
    pub enum CryptoError {
        #[error("unsupported encryption suite")]
        UnsupportedSuite,
        #[error("hkdf expansion failed")]
        HkdfExpand,
        #[error("invalid ephemeral public key length (expected {expected}, found {found})")]
        InvalidEphemeralPublicKey { expected: usize, found: usize },
        #[error("invalid shared secret length (expected {expected}, found {found})")]
        InvalidSharedSecretLength { expected: usize, found: usize },
        #[error("nonce length mismatch: expected {expected}, found {found}")]
        InvalidNonceLength { expected: usize, found: usize },
        #[error("invalid group content key length (expected {expected}, found {found})")]
        InvalidGroupContentKeyLength { expected: usize, found: usize },
        #[error("aead operation failed")]
        AeadFailure,
        #[error("key counter must be strictly increasing (previous {previous}, found {found})")]
        NonMonotonicKeyCounter { previous: u64, found: u64 },
        #[error("key counter must be nonzero (found {found})")]
        InvalidKeyCounter { found: u64 },
        #[error("protocol version must be nonzero (found {found})")]
        InvalidProtocolVersion { found: u16 },
        #[error("encryption suite changed from {expected:?} to {found:?}")]
        SuiteChanged {
            expected: EncryptionSuite,
            found: EncryptionSuite,
        },
        #[error("content key id must increase (previous {previous}, found {found})")]
        ContentKeyRegression { previous: u64, found: u64 },
        #[error("content key update must not carry an empty wrapped key")]
        InvalidWrappedKey,
        #[error("content key valid_from must advance (previous {previous}, found {found})")]
        InvalidValidFrom { previous: u64, found: u64 },
        #[error("invalid content key state: {0}")]
        InvalidContentKeyState(&'static str),
    }
    /// Session transport keys derived for a given endpoint role.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct TransportKeys {
        pub send: [u8; 32],
        pub recv: [u8; 32],
    }
    fn gck_associated_data(content_key_id: u64, valid_from_segment: u64) -> [u8; 23] {
        let mut ad = [0u8; 23];
        ad[..GCK_AAD_LABEL.len()].copy_from_slice(GCK_AAD_LABEL);
        ad[GCK_AAD_LABEL.len()..GCK_AAD_LABEL.len() + 8]
            .copy_from_slice(&content_key_id.to_le_bytes());
        ad[GCK_AAD_LABEL.len() + 8..].copy_from_slice(&valid_from_segment.to_le_bytes());
        ad
    }
    fn validate_group_content_key(gck: &[u8]) -> Result<(), CryptoError> {
        if gck.len() != GROUP_CONTENT_KEY_LEN {
            return Err(CryptoError::InvalidGroupContentKeyLength {
                expected: GROUP_CONTENT_KEY_LEN,
                found: gck.len(),
            });
        }
        Ok(())
    }
    fn validate_shared_secret(shared_secret: &[u8]) -> Result<(), CryptoError> {
        if shared_secret.len() != STS_SHARED_SECRET_LEN {
            return Err(CryptoError::InvalidSharedSecretLength {
                expected: STS_SHARED_SECRET_LEN,
                found: shared_secret.len(),
            });
        }
        Ok(())
    }
    fn key_update_ephemeral_len_for_suite(suite: &EncryptionSuite) -> usize {
        match suite {
            EncryptionSuite::X25519ChaCha20Poly1305(_) => X25519_EPHEMERAL_PUBLIC_LEN,
            EncryptionSuite::Kyber768XChaCha20Poly1305(_) => KYBER768_CIPHERTEXT_LEN,
        }
    }
    fn validate_key_update_ephemeral(frame: &KeyUpdate) -> Result<(), CryptoError> {
        let expected = key_update_ephemeral_len_for_suite(&frame.suite);
        let found = frame.pub_ephemeral.len();
        if found != expected {
            return Err(CryptoError::InvalidEphemeralPublicKey { expected, found });
        }
        Ok(())
    }
    /// Track monotonic key update counters and negotiated suite.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct KeyUpdateState {
        last_counter: Option<u64>,
        suite: Option<EncryptionSuite>,
    }
    /// Persistable representation of [`KeyUpdateState`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct KeyUpdateSnapshot {
        /// Encryption suite negotiated for the session.
        pub suite: EncryptionSuite,
        /// Highest key counter accepted so far.
        pub last_counter: u64,
    }
    impl KeyUpdateState {
        pub fn record(&mut self, frame: &KeyUpdate) -> Result<(), CryptoError> {
            if frame.protocol_version == 0 {
                return Err(CryptoError::InvalidProtocolVersion {
                    found: frame.protocol_version,
                });
            }
            if frame.key_counter == 0 {
                return Err(CryptoError::InvalidKeyCounter {
                    found: frame.key_counter,
                });
            }
            if let Some(prev) = self.last_counter
                && frame.key_counter <= prev
            {
                return Err(CryptoError::NonMonotonicKeyCounter {
                    previous: prev,
                    found: frame.key_counter,
                });
            }
            if let Some(suite) = self.suite
                && suite != frame.suite
            {
                return Err(CryptoError::SuiteChanged {
                    expected: suite,
                    found: frame.suite,
                });
            }
            validate_key_update_ephemeral(frame)?;
            if self.suite.is_none() {
                self.suite = Some(frame.suite);
            }
            self.last_counter = Some(frame.key_counter);
            Ok(())
        }
        pub fn suite(&self) -> Option<&EncryptionSuite> {
            self.suite.as_ref()
        }
        pub fn last_counter(&self) -> Option<u64> {
            self.last_counter
        }
        pub fn restore(
            &mut self,
            last_counter: Option<u64>,
            suite: Option<EncryptionSuite>,
        ) -> Result<(), CryptoError> {
            if matches!(last_counter, Some(0)) {
                return Err(CryptoError::InvalidKeyCounter { found: 0 });
            }
            self.last_counter = last_counter;
            self.suite = suite;
            Ok(())
        }
        /// Produce a snapshot capturing the negotiated suite and last accepted counter.
        #[must_use]
        pub fn snapshot(&self) -> Option<KeyUpdateSnapshot> {
            let suite = self.suite?;
            let last_counter = self.last_counter?;
            Some(KeyUpdateSnapshot {
                suite,
                last_counter,
            })
        }
        /// Rehydrate a [`KeyUpdateState`] from a snapshot.
        pub fn from_snapshot(snapshot: KeyUpdateSnapshot) -> Result<Self, CryptoError> {
            let mut state = Self::default();
            state.restore(Some(snapshot.last_counter), Some(snapshot.suite))?;
            Ok(state)
        }
    }
    /// Track content key rotations.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ContentKeyState {
        last_id: Option<u64>,
        last_valid_from: Option<u64>,
    }
    /// Persistable representation of [`ContentKeyState`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ContentKeySnapshot {
        /// Highest content key identifier accepted so far.
        pub last_id: u64,
        /// Highest valid-from segment observed so far.
        pub last_valid_from: u64,
    }
    impl ContentKeyState {
        pub fn record(&mut self, update: &ContentKeyUpdate) -> Result<(), CryptoError> {
            if update.gck_wrapped.is_empty() {
                return Err(CryptoError::InvalidWrappedKey);
            }
            if let Some(prev) = self.last_id
                && update.content_key_id <= prev
            {
                return Err(CryptoError::ContentKeyRegression {
                    previous: prev,
                    found: update.content_key_id,
                });
            }
            if let Some(prev_valid) = self.last_valid_from
                && update.valid_from_segment < prev_valid
            {
                return Err(CryptoError::InvalidValidFrom {
                    previous: prev_valid,
                    found: update.valid_from_segment,
                });
            }
            self.last_id = Some(update.content_key_id);
            self.last_valid_from = Some(update.valid_from_segment);
            Ok(())
        }
        pub fn last_id(&self) -> Option<u64> {
            self.last_id
        }
        pub fn last_valid_from(&self) -> Option<u64> {
            self.last_valid_from
        }
        pub fn restore(
            &mut self,
            last_id: Option<u64>,
            last_valid_from: Option<u64>,
        ) -> Result<(), CryptoError> {
            if last_id.is_some() != last_valid_from.is_some() {
                return Err(CryptoError::InvalidContentKeyState(
                    "content key id and valid-from must be restored together",
                ));
            }
            self.last_id = last_id;
            self.last_valid_from = last_valid_from;
            Ok(())
        }
        /// Produce a snapshot capturing the last accepted identifiers.
        #[must_use]
        pub fn snapshot(&self) -> Option<ContentKeySnapshot> {
            let last_id = self.last_id?;
            let last_valid_from = self.last_valid_from?;
            Some(ContentKeySnapshot {
                last_id,
                last_valid_from,
            })
        }
        /// Rehydrate a [`ContentKeyState`] from a snapshot.
        pub fn from_snapshot(snapshot: ContentKeySnapshot) -> Result<Self, CryptoError> {
            let mut state = Self::default();
            state.restore(Some(snapshot.last_id), Some(snapshot.last_valid_from))?;
            Ok(state)
        }
    }
    fn role_tag_send(role: CapabilityRole) -> u8 {
        match role {
            CapabilityRole::Publisher => 0x01,
            CapabilityRole::Viewer => 0x02,
        }
    }
    fn opposite_role(role: CapabilityRole) -> CapabilityRole {
        match role {
            CapabilityRole::Publisher => CapabilityRole::Viewer,
            CapabilityRole::Viewer => CapabilityRole::Publisher,
        }
    }
    fn hkdf_expand_with_label(
        hk: &Hkdf<Sha3_256>,
        label: &[u8],
        suffix: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let mut info = Vec::with_capacity(label.len() + suffix.len());
        info.extend_from_slice(label);
        info.extend_from_slice(suffix);
        hk.expand(&info, out).map_err(|_| CryptoError::HkdfExpand)
    }
    fn hkdf_from_prk(prk: &[u8; 32]) -> Hkdf<Sha3_256> {
        // `from_prk` panics only if length < hash_len; 32 bytes meets Sha3-256 requirements.
        Hkdf::<Sha3_256>::from_prk(prk).expect("prk length must equal digest output")
    }
    fn suite_nonce_len(suite: &EncryptionSuite) -> usize {
        match suite {
            EncryptionSuite::X25519ChaCha20Poly1305(_) => 12,
            EncryptionSuite::Kyber768XChaCha20Poly1305(_) => 24,
        }
    }
    /// Return the nonce length required by the selected encryption suite.
    pub fn nonce_len_for_suite(suite: &EncryptionSuite) -> usize {
        suite_nonce_len(suite)
    }
    fn chunk_associated_data(segment_number: u64, chunk_id: u16, chunk_root: &Hash) -> [u8; 42] {
        let mut ad = [0u8; 42];
        ad[..8].copy_from_slice(&segment_number.to_le_bytes());
        ad[8..10].copy_from_slice(&chunk_id.to_le_bytes());
        ad[10..].copy_from_slice(chunk_root);
        ad
    }
    /// Derive the session transport secret root from the 32-byte shared secret output of the
    /// handshake.
    pub fn derive_sts_root(shared_secret: &[u8]) -> Result<[u8; 32], CryptoError> {
        validate_shared_secret(shared_secret)?;
        let hk = Hkdf::<Sha3_256>::new(Some(STS_SALT), shared_secret);
        let mut root = [0u8; 32];
        hk.expand(STS_ROOT_LABEL, &mut root)
            .map_err(|_| CryptoError::HkdfExpand)?;
        Ok(root)
    }
    /// Derive directional transport keys for the provided endpoint role.
    pub fn derive_transport_keys_for_role(
        shared_secret: &[u8],
        role: CapabilityRole,
    ) -> Result<TransportKeys, CryptoError> {
        let sts_root = derive_sts_root(shared_secret)?;
        derive_transport_keys_from_sts_root(&sts_root, role)
    }
    /// Re-derive transport keys given a previously computed STS root.
    pub fn derive_transport_keys_from_sts_root(
        sts_root: &[u8; 32],
        role: CapabilityRole,
    ) -> Result<TransportKeys, CryptoError> {
        let hk = hkdf_from_prk(sts_root);
        let mut send = [0u8; 32];
        let mut recv = [0u8; 32];
        hkdf_expand_with_label(&hk, STS_SEND_LABEL, &[role_tag_send(role)], &mut send)?;
        hkdf_expand_with_label(
            &hk,
            STS_SEND_LABEL,
            &[role_tag_send(opposite_role(role))],
            &mut recv,
        )?;
        Ok(TransportKeys { send, recv })
    }
    /// Derive the per-segment content encryption key from the GCK.
    pub fn derive_content_key(
        gck: &[u8; 32],
        segment_number: u64,
    ) -> Result<[u8; 32], CryptoError> {
        let hk = hkdf_from_prk(gck);
        let mut cek = [0u8; 32];
        let mut suffix = [0u8; 8];
        suffix.copy_from_slice(&segment_number.to_le_bytes());
        hkdf_expand_with_label(&hk, CEK_LABEL, &suffix, &mut cek)?;
        Ok(cek)
    }
    /// Derive the per-chunk AEAD nonce from the manifest salt.
    pub fn derive_chunk_nonce(
        nonce_salt: &[u8; 32],
        chunk_id: u16,
        suite: &EncryptionSuite,
    ) -> Result<Vec<u8>, CryptoError> {
        let hk = hkdf_from_prk(nonce_salt);
        let nonce_len = suite_nonce_len(suite);
        let mut nonce = vec![0u8; nonce_len];
        let suffix = chunk_id.to_le_bytes();
        hkdf_expand_with_label(&hk, NONCE_LABEL, &suffix, &mut nonce)?;
        Ok(nonce)
    }
    #[inline]
    fn chacha_key_from_bytes(bytes: &[u8; 32]) -> chacha20poly1305::Key {
        (*bytes).into()
    }
    #[inline]
    fn chacha_nonce_from_slice(bytes: &[u8]) -> Result<chacha20poly1305::Nonce, CryptoError> {
        let arr: [u8; 12] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength {
                expected: 12,
                found: bytes.len(),
            })?;
        Ok(arr.into())
    }
    #[inline]
    fn xchacha_nonce_from_slice(bytes: &[u8]) -> Result<chacha20poly1305::XNonce, CryptoError> {
        let arr: [u8; 24] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength {
                expected: 24,
                found: bytes.len(),
            })?;
        Ok(arr.into())
    }
    /// Encrypt a chunk payload for the selected suite.
    pub fn encrypt_chunk(
        suite: &EncryptionSuite,
        content_key: &[u8; 32],
        nonce: &[u8],
        segment_number: u64,
        chunk_id: u16,
        chunk_root: &Hash,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let ad = chunk_associated_data(segment_number, chunk_id, chunk_root);
        match suite {
            EncryptionSuite::X25519ChaCha20Poly1305(_) => {
                let key = chacha_key_from_bytes(content_key);
                let nonce = chacha_nonce_from_slice(nonce)?;
                let cipher = ChaCha20Poly1305::new(&key);
                cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: plaintext,
                            aad: &ad,
                        },
                    )
                    .map_err(|_| CryptoError::AeadFailure)
            }
            EncryptionSuite::Kyber768XChaCha20Poly1305(_) => {
                let key = chacha_key_from_bytes(content_key);
                let nonce = xchacha_nonce_from_slice(nonce)?;
                let cipher = XChaCha20Poly1305::new(&key);
                cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: plaintext,
                            aad: &ad,
                        },
                    )
                    .map_err(|_| CryptoError::AeadFailure)
            }
        }
    }
    /// Decrypt a chunk payload for the selected suite.
    pub fn decrypt_chunk(
        suite: &EncryptionSuite,
        content_key: &[u8; 32],
        nonce: &[u8],
        segment_number: u64,
        chunk_id: u16,
        chunk_root: &Hash,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let ad = chunk_associated_data(segment_number, chunk_id, chunk_root);
        match suite {
            EncryptionSuite::X25519ChaCha20Poly1305(_) => {
                let key = chacha_key_from_bytes(content_key);
                let nonce = chacha_nonce_from_slice(nonce)?;
                let cipher = ChaCha20Poly1305::new(&key);
                cipher
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: ciphertext,
                            aad: &ad,
                        },
                    )
                    .map_err(|_| CryptoError::AeadFailure)
            }
            EncryptionSuite::Kyber768XChaCha20Poly1305(_) => {
                let key = chacha_key_from_bytes(content_key);
                let nonce = xchacha_nonce_from_slice(nonce)?;
                let cipher = XChaCha20Poly1305::new(&key);
                cipher
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: ciphertext,
                            aad: &ad,
                        },
                    )
                    .map_err(|_| CryptoError::AeadFailure)
            }
        }
    }
    /// Wrap a 32-byte Group Content Key (GCK) using the negotiated transport send key and explicit
    /// nonce.
    ///
    /// The returned vector concatenates `nonce || ciphertext`, matching the payload layout used in
    /// [`ContentKeyUpdate::gck_wrapped`].
    pub fn wrap_gck(
        suite: &EncryptionSuite,
        transport_send_key: &[u8; 32],
        nonce: &[u8],
        gck_plaintext: &[u8],
        content_key_id: u64,
        valid_from_segment: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        validate_group_content_key(gck_plaintext)?;
        let aad = gck_associated_data(content_key_id, valid_from_segment);
        let ciphertext = match suite {
            EncryptionSuite::X25519ChaCha20Poly1305(_) => {
                let key = chacha_key_from_bytes(transport_send_key);
                let nonce = chacha_nonce_from_slice(nonce)?;
                let cipher = ChaCha20Poly1305::new(&key);
                cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: gck_plaintext,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| CryptoError::AeadFailure)?
            }
            EncryptionSuite::Kyber768XChaCha20Poly1305(_) => {
                let key = chacha_key_from_bytes(transport_send_key);
                let nonce = xchacha_nonce_from_slice(nonce)?;
                let cipher = XChaCha20Poly1305::new(&key);
                cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: gck_plaintext,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| CryptoError::AeadFailure)?
            }
        };
        let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
    /// Unwrap a 32-byte Group Content Key (GCK) using the transport receive key and inline nonce.
    pub fn unwrap_gck(
        suite: &EncryptionSuite,
        transport_recv_key: &[u8; 32],
        nonce: &[u8],
        ciphertext: &[u8],
        content_key_id: u64,
        valid_from_segment: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        let aad = gck_associated_data(content_key_id, valid_from_segment);
        let plaintext = match suite {
            EncryptionSuite::X25519ChaCha20Poly1305(_) => {
                let key = chacha_key_from_bytes(transport_recv_key);
                let nonce = chacha_nonce_from_slice(nonce)?;
                let cipher = ChaCha20Poly1305::new(&key);
                cipher
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: ciphertext,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| CryptoError::AeadFailure)
            }
            EncryptionSuite::Kyber768XChaCha20Poly1305(_) => {
                let key = chacha_key_from_bytes(transport_recv_key);
                let nonce = xchacha_nonce_from_slice(nonce)?;
                let cipher = XChaCha20Poly1305::new(&key);
                cipher
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: ciphertext,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| CryptoError::AeadFailure)
            }
        }?;
        validate_group_content_key(plaintext.as_slice())?;
        Ok(plaintext)
    }
    /// Build the associated data commitments for a ciphertext batch.
    pub fn chunk_commitments_for_ciphertexts(
        segment_number: u64,
        payloads: &[(u16, &[u8])],
    ) -> Vec<Hash> {
        payloads
            .iter()
            .map(|(chunk_id, payload)| {
                super::chunk::chunk_leaf_hash(segment_number, *chunk_id, payload)
            })
            .collect()
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::streaming::{
            CapabilityRole, ContentKeyUpdate, EncryptionSuite, Hash, KeyUpdate, Signature,
        };
        fn sample_suite() -> EncryptionSuite {
            EncryptionSuite::X25519ChaCha20Poly1305([0xAA; 32])
        }
        fn sample_suite_xchacha() -> EncryptionSuite {
            EncryptionSuite::Kyber768XChaCha20Poly1305([0xBB; 32])
        }
        fn sample_hash(seed: u8) -> Hash {
            let mut h = [0u8; 32];
            h.fill(seed);
            h
        }
        fn sample_signature(seed: u8) -> Signature {
            let mut sig = [0u8; 64];
            sig.fill(seed);
            sig
        }
        fn encrypt_gck_without_length_check(
            suite: &EncryptionSuite,
            transport_key: &[u8; 32],
            nonce: &[u8],
            gck_plaintext: &[u8],
            content_key_id: u64,
            valid_from_segment: u64,
        ) -> Vec<u8> {
            let aad = gck_associated_data(content_key_id, valid_from_segment);
            match suite {
                EncryptionSuite::X25519ChaCha20Poly1305(_) => {
                    let key = chacha_key_from_bytes(transport_key);
                    let nonce = chacha_nonce_from_slice(nonce).expect("valid chacha nonce");
                    let cipher = ChaCha20Poly1305::new(&key);
                    cipher
                        .encrypt(
                            &nonce,
                            Payload {
                                msg: gck_plaintext,
                                aad: &aad,
                            },
                        )
                        .expect("manual gck encrypt")
                }
                EncryptionSuite::Kyber768XChaCha20Poly1305(_) => {
                    let key = chacha_key_from_bytes(transport_key);
                    let nonce = xchacha_nonce_from_slice(nonce).expect("valid xchacha nonce");
                    let cipher = XChaCha20Poly1305::new(&key);
                    cipher
                        .encrypt(
                            &nonce,
                            Payload {
                                msg: gck_plaintext,
                                aad: &aad,
                            },
                        )
                        .expect("manual gck encrypt")
                }
            }
        }
        #[test]
        fn transport_keys_deterministic() {
            let secret = sample_hash(0x13);
            let publisher_keys =
                derive_transport_keys_for_role(&secret, CapabilityRole::Publisher).unwrap();
            let viewer_keys =
                derive_transport_keys_for_role(&secret, CapabilityRole::Viewer).unwrap();
            assert_eq!(publisher_keys.send, viewer_keys.recv);
            assert_eq!(publisher_keys.recv, viewer_keys.send);
            assert_ne!(publisher_keys.send, publisher_keys.recv);
            assert_ne!(viewer_keys.send, viewer_keys.recv);
        }
        #[test]
        fn transport_secret_derivation_rejects_invalid_shared_secret_length() {
            let short_secret = [0x14u8; 31];
            let err = derive_sts_root(&short_secret).expect_err("short STS secret rejected");
            assert!(matches!(
                err,
                CryptoError::InvalidSharedSecretLength {
                    expected: 32,
                    found: 31
                }
            ));
            let err = derive_transport_keys_for_role(&short_secret, CapabilityRole::Publisher)
                .expect_err("short transport secret rejected");
            assert!(matches!(
                err,
                CryptoError::InvalidSharedSecretLength {
                    expected: 32,
                    found: 31
                }
            ));
        }
        #[test]
        fn content_key_and_nonce_deterministic() {
            let gck = sample_hash(1);
            let nonce_salt = sample_hash(2);
            let cek_one = derive_content_key(&gck, 77).unwrap();
            let cek_two = derive_content_key(&gck, 77).unwrap();
            assert_eq!(cek_one, cek_two);
            let suite = sample_suite();
            let nonce_one = derive_chunk_nonce(&nonce_salt, 5, &suite).unwrap();
            let nonce_two = derive_chunk_nonce(&nonce_salt, 5, &suite).unwrap();
            assert_eq!(nonce_one, nonce_two);
            assert_eq!(nonce_one.len(), 12);
            let suite_x = sample_suite_xchacha();
            let nonce_x = derive_chunk_nonce(&nonce_salt, 9, &suite_x).unwrap();
            assert_eq!(nonce_x.len(), 24);
        }
        #[test]
        fn encrypt_decrypt_roundtrip_chacha() {
            let suite = sample_suite();
            let gck = sample_hash(4);
            let cek = derive_content_key(&gck, 10).unwrap();
            let nonce_salt = sample_hash(5);
            let nonce = derive_chunk_nonce(&nonce_salt, 1, &suite).unwrap();
            let chunk_root = sample_hash(9);
            let plaintext = b"deterministic chunk payload";
            let ciphertext =
                encrypt_chunk(&suite, &cek, &nonce, 42, 1, &chunk_root, plaintext).unwrap();
            assert_ne!(ciphertext, plaintext);
            let decrypted =
                decrypt_chunk(&suite, &cek, &nonce, 42, 1, &chunk_root, &ciphertext).unwrap();
            assert_eq!(decrypted, plaintext);
        }
        #[test]
        fn encrypt_decrypt_roundtrip_xchacha() {
            let suite = sample_suite_xchacha();
            let gck = sample_hash(7);
            let cek = derive_content_key(&gck, 55).unwrap();
            let nonce_salt = sample_hash(8);
            let nonce = derive_chunk_nonce(&nonce_salt, 3, &suite).unwrap();
            let chunk_root = sample_hash(10);
            let payload = b"extended nonce payload";
            let ciphertext =
                encrypt_chunk(&suite, &cek, &nonce, 99, 3, &chunk_root, payload).unwrap();
            let decrypted =
                decrypt_chunk(&suite, &cek, &nonce, 99, 3, &chunk_root, &ciphertext).unwrap();
            assert_eq!(decrypted, payload);
        }
        #[test]
        fn key_update_state_enforces_monotonicity_and_suite() {
            let mut state = KeyUpdateState::default();
            let mut frame = KeyUpdate {
                session_id: sample_hash(11),
                suite: sample_suite(),
                protocol_version: 1,
                pub_ephemeral: vec![0; 32],
                key_counter: 1,
                signature: sample_signature(12),
            };
            state.record(&frame).unwrap();
            assert_eq!(state.last_counter(), Some(1));
            assert!(state.suite().is_some());
            frame.key_counter = 2;
            state.record(&frame).unwrap();
            frame.key_counter = 2;
            let err = state.record(&frame).expect_err("non-monotonic counter");
            assert!(matches!(
                err,
                CryptoError::NonMonotonicKeyCounter {
                    previous: 2,
                    found: 2
                }
            ));
            let mut other_frame = frame.clone();
            other_frame.key_counter = 3;
            other_frame.suite = sample_suite_xchacha();
            let err = state
                .record(&other_frame)
                .expect_err("suite change rejected");
            assert!(matches!(err, CryptoError::SuiteChanged { .. }));
        }
        #[test]
        fn key_update_state_rejects_zero_counter_without_state_change() {
            let suite = sample_suite();
            let mut state = KeyUpdateState::default();
            let mut frame = KeyUpdate {
                session_id: sample_hash(13),
                suite,
                protocol_version: 1,
                pub_ephemeral: vec![0; X25519_EPHEMERAL_PUBLIC_LEN],
                key_counter: 0,
                signature: sample_signature(14),
            };
            let err = state.record(&frame).expect_err("zero counter rejected");
            assert_eq!(err, CryptoError::InvalidKeyCounter { found: 0 });
            assert_eq!(state.last_counter(), None);
            assert_eq!(state.suite(), None);
            frame.key_counter = 1;
            state.record(&frame).unwrap();
            assert_eq!(state.last_counter(), Some(1));
            assert_eq!(state.suite(), Some(&suite));
        }
        #[test]
        fn key_update_state_restore_rejects_zero_counter_without_state_change() {
            let suite = sample_suite();
            let mut state = KeyUpdateState::default();
            let frame = KeyUpdate {
                session_id: sample_hash(17),
                suite,
                protocol_version: 1,
                pub_ephemeral: vec![0; X25519_EPHEMERAL_PUBLIC_LEN],
                key_counter: 1,
                signature: sample_signature(18),
            };
            state.record(&frame).unwrap();
            let err = state
                .restore(Some(0), Some(suite))
                .expect_err("zero restore counter rejected");
            assert_eq!(err, CryptoError::InvalidKeyCounter { found: 0 });
            assert_eq!(state.last_counter(), Some(1));
            assert_eq!(state.suite(), Some(&suite));
            let snapshot = KeyUpdateSnapshot {
                suite,
                last_counter: 0,
            };
            let err = KeyUpdateState::from_snapshot(snapshot)
                .expect_err("zero snapshot counter rejected");
            assert_eq!(err, CryptoError::InvalidKeyCounter { found: 0 });
        }
        #[test]
        fn key_update_state_rejects_zero_protocol_version_without_state_change() {
            let suite = sample_suite();
            let mut state = KeyUpdateState::default();
            let mut frame = KeyUpdate {
                session_id: sample_hash(15),
                suite,
                protocol_version: 0,
                pub_ephemeral: vec![0; X25519_EPHEMERAL_PUBLIC_LEN],
                key_counter: 1,
                signature: sample_signature(16),
            };
            let err = state
                .record(&frame)
                .expect_err("zero protocol version rejected");
            assert_eq!(err, CryptoError::InvalidProtocolVersion { found: 0 });
            assert_eq!(state.last_counter(), None);
            assert_eq!(state.suite(), None);
            frame.protocol_version = 1;
            state.record(&frame).unwrap();
            assert_eq!(state.last_counter(), Some(1));
            assert_eq!(state.suite(), Some(&suite));
        }
        #[test]
        fn key_update_state_rejects_invalid_x25519_ephemeral_without_state_change() {
            let suite = sample_suite();
            let mut state = KeyUpdateState::default();
            let mut frame = KeyUpdate {
                session_id: sample_hash(11),
                suite,
                protocol_version: 1,
                pub_ephemeral: vec![0; X25519_EPHEMERAL_PUBLIC_LEN],
                key_counter: 1,
                signature: sample_signature(12),
            };
            state.record(&frame).unwrap();
            frame.key_counter = 2;
            frame
                .pub_ephemeral
                .truncate(X25519_EPHEMERAL_PUBLIC_LEN - 1);
            let err = state
                .record(&frame)
                .expect_err("short x25519 ephemeral rejected");
            assert_eq!(
                err,
                CryptoError::InvalidEphemeralPublicKey {
                    expected: X25519_EPHEMERAL_PUBLIC_LEN,
                    found: X25519_EPHEMERAL_PUBLIC_LEN - 1
                }
            );
            assert_eq!(state.last_counter(), Some(1));
            assert_eq!(state.suite(), Some(&suite));
            frame.pub_ephemeral.resize(X25519_EPHEMERAL_PUBLIC_LEN, 0);
            state.record(&frame).unwrap();
            assert_eq!(state.last_counter(), Some(2));
        }
        #[test]
        fn key_update_state_rejects_invalid_kyber_ephemeral_without_state_change() {
            let suite = sample_suite_xchacha();
            let mut state = KeyUpdateState::default();
            let mut frame = KeyUpdate {
                session_id: sample_hash(21),
                suite,
                protocol_version: 1,
                pub_ephemeral: vec![0; X25519_EPHEMERAL_PUBLIC_LEN],
                key_counter: 1,
                signature: sample_signature(22),
            };
            let err = state
                .record(&frame)
                .expect_err("short kyber ciphertext rejected");
            assert_eq!(
                err,
                CryptoError::InvalidEphemeralPublicKey {
                    expected: KYBER768_CIPHERTEXT_LEN,
                    found: X25519_EPHEMERAL_PUBLIC_LEN
                }
            );
            assert_eq!(state.last_counter(), None);
            assert_eq!(state.suite(), None);
            frame.pub_ephemeral.resize(KYBER768_CIPHERTEXT_LEN, 0);
            state.record(&frame).unwrap();
            assert_eq!(state.last_counter(), Some(1));
            assert_eq!(state.suite(), Some(&suite));
        }
        #[test]
        fn content_key_state_enforces_rotation_rules() {
            let mut state = ContentKeyState::default();
            let mut update = ContentKeyUpdate {
                content_key_id: 5,
                gck_wrapped: vec![1, 2, 3],
                valid_from_segment: 20,
            };
            state.record(&update).unwrap();
            update.content_key_id = 5;
            let err = state.record(&update).expect_err("id must increase");
            assert!(matches!(
                err,
                CryptoError::ContentKeyRegression {
                    previous: 5,
                    found: 5
                }
            ));
            update.content_key_id = 6;
            update.valid_from_segment = 10;
            let err = state.record(&update).expect_err("valid_from must advance");
            assert!(matches!(
                err,
                CryptoError::InvalidValidFrom {
                    previous: 20,
                    found: 10
                }
            ));
            let err = state
                .record(&ContentKeyUpdate {
                    content_key_id: 7,
                    gck_wrapped: Vec::new(),
                    valid_from_segment: 30,
                })
                .expect_err("empty gck");
            assert!(matches!(err, CryptoError::InvalidWrappedKey));
        }
        #[test]
        fn content_key_state_restore_rejects_partial_state_without_state_change() {
            let mut state = ContentKeyState::default();
            state
                .record(&ContentKeyUpdate {
                    content_key_id: 5,
                    gck_wrapped: vec![1, 2, 3],
                    valid_from_segment: 20,
                })
                .unwrap();
            for (last_id, last_valid_from) in [(Some(6), None), (None, Some(30))] {
                let err = state
                    .restore(last_id, last_valid_from)
                    .expect_err("partial content-key restore rejected");
                assert_eq!(
                    err,
                    CryptoError::InvalidContentKeyState(
                        "content key id and valid-from must be restored together"
                    )
                );
                assert_eq!(state.last_id(), Some(5));
                assert_eq!(state.last_valid_from(), Some(20));
            }
            state.restore(Some(6), Some(30)).unwrap();
            assert_eq!(state.last_id(), Some(6));
            assert_eq!(state.last_valid_from(), Some(30));
            let snapshot = ContentKeySnapshot {
                last_id: 7,
                last_valid_from: 40,
            };
            let restored =
                ContentKeyState::from_snapshot(snapshot).expect("complete snapshot restores");
            assert_eq!(restored.last_id(), Some(7));
            assert_eq!(restored.last_valid_from(), Some(40));
        }
        #[test]
        fn gck_wrap_unwrap_roundtrip() {
            let suite = sample_suite();
            let transport_key = sample_hash(33);
            let nonce_len = nonce_len_for_suite(&suite);
            let mut nonce = vec![0u8; nonce_len];
            for (idx, byte) in nonce.iter_mut().enumerate() {
                *byte = (idx as u8).wrapping_mul(9);
            }
            let gck = sample_hash(44);
            let wrapped = wrap_gck(&suite, &transport_key, &nonce, &gck, 9, 128).expect("wrap");
            assert_eq!(wrapped.len(), nonce_len + gck.len() + 16);
            let (nonce_part, ciphertext_part) = wrapped.split_at(nonce_len);
            assert_eq!(nonce_part, nonce.as_slice());
            let unwrapped = unwrap_gck(&suite, &transport_key, nonce_part, ciphertext_part, 9, 128)
                .expect("unwrap");
            assert_eq!(unwrapped, gck);
        }
        #[test]
        fn gck_wrap_rejects_invalid_plaintext_length() {
            let suite = sample_suite();
            let transport_key = sample_hash(45);
            let nonce = vec![0x11; nonce_len_for_suite(&suite)];
            let short_gck = [0x22u8; 31];
            let err = wrap_gck(&suite, &transport_key, &nonce, &short_gck, 10, 129)
                .expect_err("short gck rejected before wrapping");
            assert!(matches!(
                err,
                CryptoError::InvalidGroupContentKeyLength {
                    expected: 32,
                    found: 31
                }
            ));
        }
        #[test]
        fn gck_unwrap_rejects_invalid_plaintext_length() {
            let transport_key = sample_hash(46);
            let short_gck = [0x33u8; 31];
            for suite in [sample_suite(), sample_suite_xchacha()] {
                let nonce = vec![0x44; nonce_len_for_suite(&suite)];
                let ciphertext = encrypt_gck_without_length_check(
                    &suite,
                    &transport_key,
                    &nonce,
                    &short_gck,
                    11,
                    130,
                );
                let err = unwrap_gck(&suite, &transport_key, &nonce, &ciphertext, 11, 130)
                    .expect_err("short decrypted gck rejected");
                assert!(matches!(
                    err,
                    CryptoError::InvalidGroupContentKeyLength {
                        expected: 32,
                        found: 31
                    }
                ));
            }
        }
    }
}
pub mod chunk {
    use super::{AudioCodecError, Hash, MerkleProof, saturating_usize_to_u32};
    use crate::streaming::codec::{
        Chroma420Frame, EncodedSegment, FRAME_HEADER_LEN, FrameDimensions, FrameType, SegmentError,
        decode_block_rle, dequantize_coeffs, inverse_dct, predictor_block, verify_segment,
        write_reconstructed_block,
    };
    use thiserror::Error;
    const LEAF_DOMAIN: &[u8] = b"nsc_ct_leaf";
    const NODE_DOMAIN: &[u8] = b"nsc_ct_node";
    const STORAGE_DOMAIN: &[u8] = b"nsc_storage";
    const DA_DOMAIN: &[u8] = b"nsc_da";
    /// Bounds violation details returned by [`ChunkError::IndexOutOfBounds`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub struct ChunkIndexBounds {
        pub index: u32,
        pub len: u32,
    }
    /// Errors emitted by chunk hashing and Merkle utilities.
    #[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub enum ChunkError {
        #[error("merkle tree requires at least one leaf")]
        EmptyTree,
        #[error(
            "chunk index {index} out of bounds for {len} leaves",
            index = .0.index,
            len = .0.len
        )]
        IndexOutOfBounds(ChunkIndexBounds),
        #[error("chunk id list must be strictly ascending")]
        UnsortedChunkIds,
    }
    /// Compute the leaf hash for a chunk ciphertext.
    pub fn chunk_leaf_hash(segment_number: u64, chunk_id: u16, ciphertext: &[u8]) -> Hash {
        let mut hasher = domain_hasher(LEAF_DOMAIN);
        hasher.update(&segment_number.to_le_bytes());
        hasher.update(&chunk_id.to_le_bytes());
        hasher.update(ciphertext);
        finalize_hash(hasher)
    }
    /// Compute chunk commitments for a slice of chunk payloads.
    pub fn chunk_commitments(segment_number: u64, chunks: &[(u16, &[u8])]) -> Vec<Hash> {
        chunks
            .iter()
            .map(|(id, payload)| chunk_leaf_hash(segment_number, *id, payload))
            .collect()
    }
    /// Compute the Merkle root for a set of chunk commitments.
    pub fn merkle_root(leaves: &[Hash]) -> Result<Hash, ChunkError> {
        if leaves.is_empty() {
            return Err(ChunkError::EmptyTree);
        }
        if leaves.len() == 1 {
            return Ok(leaves[0]);
        }
        let mut level: Vec<Hash> = leaves.to_vec();
        while level.len() > 1 {
            level = next_parent_level(&level);
        }
        Ok(level[0])
    }
    /// Build a Merkle proof for a given leaf index.
    pub fn merkle_proof(
        leaves: &[Hash],
        index: usize,
        chunk_id: u16,
    ) -> Result<MerkleProof, ChunkError> {
        if leaves.is_empty() {
            return Err(ChunkError::EmptyTree);
        }
        if index >= leaves.len() {
            return Err(ChunkError::IndexOutOfBounds(ChunkIndexBounds {
                index: saturating_usize_to_u32(index),
                len: saturating_usize_to_u32(leaves.len()),
            }));
        }
        let mut current = leaves.to_vec();
        let mut siblings = Vec::new();
        let mut directions = Vec::new();
        let mut idx = index;
        while current.len() > 1 {
            let is_right = idx % 2 == 1;
            let sibling_idx = if is_right {
                idx - 1
            } else if idx + 1 < current.len() {
                idx + 1
            } else {
                idx
            };
            siblings.push(current[sibling_idx]);
            directions.push(is_right);
            current = next_parent_level(&current);
            idx /= 2;
        }
        Ok(MerkleProof {
            chunk_id,
            sibling_hashes: siblings,
            directions,
        })
    }
    /// Verify a Merkle proof against an expected root.
    pub fn verify_merkle_proof(leaf: &Hash, proof: &MerkleProof, expected_root: &Hash) -> bool {
        if proof.sibling_hashes.len() != proof.directions.len() {
            return false;
        }
        let mut node = *leaf;
        for (sibling, is_left) in proof.sibling_hashes.iter().zip(proof.directions.iter()) {
            node = if *is_left {
                parent_hash(sibling, &node)
            } else {
                parent_hash(&node, sibling)
            };
        }
        node == *expected_root
    }
    /// Compute the data-availability storage commitment.
    pub fn storage_commitment(
        segment_number: u64,
        content_key_id: u64,
        chunk_root: &Hash,
        chunk_ids: &[u16],
    ) -> Result<Hash, ChunkError> {
        if !is_strictly_ascending(chunk_ids) {
            return Err(ChunkError::UnsortedChunkIds);
        }
        let mut hasher = domain_hasher(STORAGE_DOMAIN);
        hasher.update(&segment_number.to_le_bytes());
        hasher.update(&content_key_id.to_le_bytes());
        hasher.update(chunk_root);
        for id in chunk_ids {
            hasher.update(&id.to_le_bytes());
        }
        Ok(finalize_hash(hasher))
    }
    /// Compute the data availability proof root helper per spec (`nsc_da`).
    pub fn data_availability_root(
        segment_number: u64,
        content_key_id: u64,
        chunk_root: &Hash,
        chunk_ids: &[u16],
    ) -> Result<Hash, ChunkError> {
        if !is_strictly_ascending(chunk_ids) {
            return Err(ChunkError::UnsortedChunkIds);
        }
        let mut hasher = domain_hasher(DA_DOMAIN);
        hasher.update(&segment_number.to_le_bytes());
        hasher.update(&content_key_id.to_le_bytes());
        hasher.update(chunk_root);
        for id in chunk_ids {
            hasher.update(&id.to_le_bytes());
        }
        Ok(finalize_hash(hasher))
    }
    fn next_parent_level(level: &[Hash]) -> Vec<Hash> {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            next.push(parent_hash(&left, &right));
        }
        next
    }
    fn parent_hash(left: &Hash, right: &Hash) -> Hash {
        let mut hasher = domain_hasher(NODE_DOMAIN);
        hasher.update(left);
        hasher.update(right);
        finalize_hash(hasher)
    }
    fn finalize_hash(hasher: blake3::Hasher) -> Hash {
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_bytes());
        out
    }
    fn domain_hasher(domain: &[u8]) -> blake3::Hasher {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher
    }
    fn is_strictly_ascending(ids: &[u16]) -> bool {
        ids.windows(2).all(|w| w[0] < w[1])
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub struct FrameLengthMismatch {
        pub expected: u32,
        pub actual: u32,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub struct FrameIndexMismatchInfo {
        pub expected: u32,
        pub found: u32,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub struct FramePtsMismatchInfo {
        pub index: u32,
        pub expected: u64,
        pub found: u64,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub struct UnalignedDimensionsInfo {
        pub width: u16,
        pub height: u16,
        pub block_size: u8,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub struct BlockCountMismatchInfo {
        pub expected: u32,
        pub found: u32,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub struct FrameCountOverflowInfo {
        pub max: u32,
        pub found: u32,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub struct AudioSampleCountMismatchInfo {
        pub expected: u64,
        pub found: u64,
    }
    /// Error raised when the encoded chroma payload is shorter than advertised.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub struct ChromaPayloadTruncatedInfo;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub struct ChromaDimensionsNotEvenInfo {
        pub width: u16,
        pub height: u16,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub struct AudioFrameCadenceMismatchInfo {
        pub expected: u16,
        pub found: u16,
        pub sample_rate: u32,
        pub frame_duration_ns: u32,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub struct AudioFrameCadenceOverflowInfo {
        pub expected: u64,
        pub sample_rate: u32,
        pub frame_duration_ns: u32,
    }
    #[derive(Debug, Error)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub enum CodecError {
        #[error(transparent)]
        Segment(#[from] SegmentError),
        #[error(transparent)]
        Audio(#[from] AudioCodecError),
        #[error(
            "frame payload has wrong length: expected {expected}, got {actual}",
            expected = .0.expected,
            actual = .0.actual
        )]
        InvalidFrameLength(FrameLengthMismatch),
        #[error("chunk payload truncated")]
        ChunkTooShort,
        #[error(
            "frame index mismatch: expected {expected}, found {found}",
            expected = .0.expected,
            found = .0.found
        )]
        FrameIndexMismatch(FrameIndexMismatchInfo),
        #[error(
            "frame pts mismatch at index {index}: expected {expected}, found {found}",
            index = .0.index,
            expected = .0.expected,
            found = .0.found
        )]
        FramePtsMismatch(FramePtsMismatchInfo),
        #[error("frame pts computation overflow at index {0}")]
        FramePtsOverflow(u32),
        #[error(
            "frame dimensions ({width}x{height}) are not divisible by {block_size} pixels",
            width = .0.width,
            height = .0.height,
            block_size = .0.block_size
        )]
        UnalignedDimensions(UnalignedDimensionsInfo),
        #[error(
            "encoded block count mismatch: expected {expected}, found {found}",
            expected = .0.expected,
            found = .0.found
        )]
        BlockCountMismatch(BlockCountMismatchInfo),
        #[error(
            "frame count exceeds u16 range: expected <= {max}, found {found}",
            max = .0.max,
            found = .0.found
        )]
        FrameCountOverflow(FrameCountOverflowInfo),
        #[error("run-length stream overflow while decoding block {0}")]
        RleOverflow(u32),
        #[error("run-length stream truncated while decoding block {0}")]
        TruncatedBlock(u32),
        #[error("unknown frame type id {0}")]
        UnknownFrameType(u8),
        #[error("missing end-of-block marker while decoding block {0}")]
        MissingEndOfBlock(u32),
        #[error("audio track configured but samples missing")]
        AudioTrackMissing,
        #[error("audio track provided but encoder audio is disabled")]
        AudioTrackUnexpected,
        #[error(
            "audio frame cadence mismatch: expected {expected} samples for {sample_rate} Hz/{frame_duration_ns} ns, found {found}",
            expected = .0.expected,
            found = .0.found,
            sample_rate = .0.sample_rate,
            frame_duration_ns = .0.frame_duration_ns
        )]
        AudioFrameCadenceMismatch(AudioFrameCadenceMismatchInfo),
        #[error(
            "audio frame cadence overflow for {sample_rate} Hz/{frame_duration_ns} ns (expected {expected} samples)",
            expected = .0.expected,
            sample_rate = .0.sample_rate,
            frame_duration_ns = .0.frame_duration_ns
        )]
        AudioFrameCadenceOverflow(AudioFrameCadenceOverflowInfo),
        #[error(
            "audio sample count mismatch: expected {expected}, found {found}",
            expected = .0.expected,
            found = .0.found
        )]
        AudioSampleCountMismatch(AudioSampleCountMismatchInfo),
        #[error("chroma payload truncated")]
        ChromaPayloadTruncated(ChromaPayloadTruncatedInfo),
        #[error(
            "chroma 4:2:0 requires even dimensions, got {width}x{height}",
            width = .0.width,
            height = .0.height
        )]
        ChromaDimensionsNotEven(ChromaDimensionsNotEvenInfo),
        #[error("audio sample count overflow during validation")]
        AudioSampleCountOverflow,
        #[error("audio frame count exceeds u16 range")]
        AudioFrameCountOverflow,
        #[error("audio sequence counter overflow")]
        AudioSequenceOverflow,
        #[error("audio timestamp overflow at index {0}")]
        AudioTimestampOverflow(u32),
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BaselineDecoder {
        dimensions: FrameDimensions,
        frame_duration_ns: u32,
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    pub struct DecodedFrame {
        pub index: u32,
        pub pts_ns: u64,
        pub luma: Vec<u8>,
        pub chroma: Option<Chroma420Frame>,
    }
    impl BaselineDecoder {
        pub fn new(dimensions: FrameDimensions, frame_duration_ns: u32) -> Self {
            Self {
                dimensions,
                frame_duration_ns,
            }
        }
        pub fn decode_segment(
            &self,
            segment: &EncodedSegment,
        ) -> Result<Vec<DecodedFrame>, CodecError> {
            verify_segment(
                &segment.header,
                &segment.descriptors,
                &segment.chunks,
                segment.audio.as_ref(),
            )?;
            let mut frames = Vec::with_capacity(segment.chunks.len());
            let frame_step = u64::from(self.frame_duration_ns);
            let dims = self.dimensions;
            let aligned_dims = dims.align_to_block();
            let expected_blocks = aligned_dims.block_count();
            let mut previous_frame: Option<Vec<u8>> = None;
            let chroma_dims = FrameDimensions::new(dims.width / 2, dims.height / 2);
            let mut previous_chroma_u: Option<Vec<u8>> = None;
            let mut previous_chroma_v: Option<Vec<u8>> = None;
            for (idx, chunk) in segment.chunks.iter().enumerate() {
                if chunk.len() < FRAME_HEADER_LEN {
                    return Err(CodecError::ChunkTooShort);
                }
                let frame_index = read_frame_header_u32_le(chunk, 0)?;
                if frame_index != idx as u32 {
                    return Err(CodecError::FrameIndexMismatch(
                        super::chunk::FrameIndexMismatchInfo {
                            expected: idx as u32,
                            found: frame_index,
                        },
                    ));
                }
                let pts_ns = read_frame_header_u64_le(chunk, 4)?;
                let delta = frame_step
                    .checked_mul(idx as u64)
                    .ok_or(CodecError::FramePtsOverflow(saturating_usize_to_u32(idx)))?;
                let expected_pts = segment
                    .header
                    .timeline_start_ns
                    .checked_add(delta)
                    .ok_or(CodecError::FramePtsOverflow(saturating_usize_to_u32(idx)))?;
                if pts_ns != expected_pts {
                    return Err(CodecError::FramePtsMismatch(
                        super::chunk::FramePtsMismatchInfo {
                            index: saturating_usize_to_u32(idx),
                            expected: expected_pts,
                            found: pts_ns,
                        },
                    ));
                }
                let frame_type = FrameType::from_byte(chunk[12])?;
                let quantizer = chunk[13];
                let block_count = read_frame_header_u16_le(chunk, 14)?;
                if block_count as usize != expected_blocks {
                    return Err(CodecError::BlockCountMismatch(BlockCountMismatchInfo {
                        expected: saturating_usize_to_u32(expected_blocks),
                        found: block_count as u32,
                    }));
                }
                let mut offset = FRAME_HEADER_LEN;
                let mut reconstructed = vec![0u8; aligned_dims.pixel_count()];
                let mut prev_dc = 0i16;
                if frame_type.reset_dc() {
                    prev_dc = 0;
                }
                for block_idx in 0..expected_blocks {
                    let coeffs =
                        decode_block_rle(chunk, &mut offset, &mut prev_dc, block_idx as u32)?;
                    let dequant = dequantize_coeffs(&coeffs, quantizer);
                    let spatial = inverse_dct(&dequant);
                    let predictor = predictor_block(
                        previous_frame.as_deref(),
                        aligned_dims,
                        block_idx,
                        frame_type,
                    );
                    write_reconstructed_block(
                        &mut reconstructed,
                        &spatial,
                        &predictor,
                        aligned_dims,
                        block_idx,
                    );
                }
                #[cfg(feature = "streaming-neural-filter")]
                super::codec::apply_neural_filter(&mut reconstructed, aligned_dims);
                let cropped =
                    crate::streaming::codec::crop_frame_luma(&reconstructed, dims, aligned_dims);
                let chroma = if chunk.len() > offset {
                    crate::streaming::codec::ensure_chroma_even_dimensions(dims)?;
                    if chunk.len().saturating_sub(offset) < 8 {
                        return Err(CodecError::ChromaPayloadTruncated(
                            ChromaPayloadTruncatedInfo,
                        ));
                    }
                    let u_len = read_chroma_len(chunk, offset)?;
                    let v_len_offset =
                        offset
                            .checked_add(4)
                            .ok_or(CodecError::ChromaPayloadTruncated(
                                ChromaPayloadTruncatedInfo,
                            ))?;
                    let v_len = read_chroma_len(chunk, v_len_offset)?;
                    let chroma_start =
                        offset
                            .checked_add(8)
                            .ok_or(CodecError::ChromaPayloadTruncated(
                                ChromaPayloadTruncatedInfo,
                            ))?;
                    let u_end = chroma_start.checked_add(u_len).ok_or(
                        CodecError::ChromaPayloadTruncated(ChromaPayloadTruncatedInfo),
                    )?;
                    let v_end =
                        u_end
                            .checked_add(v_len)
                            .ok_or(CodecError::ChromaPayloadTruncated(
                                ChromaPayloadTruncatedInfo,
                            ))?;
                    if v_end > chunk.len() {
                        return Err(CodecError::ChromaPayloadTruncated(
                            ChromaPayloadTruncatedInfo,
                        ));
                    }
                    let (u_plane, reconstructed_u) = decode_chroma_plane(
                        &chunk[chroma_start..u_end],
                        frame_type,
                        quantizer,
                        chroma_dims,
                        previous_chroma_u.as_deref(),
                    )?;
                    let (v_plane, reconstructed_v) = decode_chroma_plane(
                        &chunk[u_end..v_end],
                        frame_type,
                        quantizer,
                        chroma_dims,
                        previous_chroma_v.as_deref(),
                    )?;
                    previous_chroma_u = Some(reconstructed_u);
                    previous_chroma_v = Some(reconstructed_v);
                    Some(Chroma420Frame::new(dims, u_plane, v_plane)?)
                } else {
                    previous_chroma_u = None;
                    previous_chroma_v = None;
                    None
                };
                frames.push(DecodedFrame {
                    index: frame_index,
                    pts_ns,
                    luma: cropped,
                    chroma,
                });
                previous_frame = Some(reconstructed);
            }
            Ok(frames)
        }
    }
    pub(crate) fn read_frame_header_field<const N: usize>(
        chunk: &[u8],
        offset: usize,
    ) -> Result<[u8; N], CodecError> {
        let end = offset.checked_add(N).ok_or(CodecError::ChunkTooShort)?;
        let slice = chunk.get(offset..end).ok_or(CodecError::ChunkTooShort)?;
        let mut raw = [0u8; N];
        raw.copy_from_slice(slice);
        Ok(raw)
    }
    pub(crate) fn read_frame_header_u16_le(chunk: &[u8], offset: usize) -> Result<u16, CodecError> {
        Ok(u16::from_le_bytes(read_frame_header_field(chunk, offset)?))
    }
    pub(crate) fn read_frame_header_u32_le(chunk: &[u8], offset: usize) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(read_frame_header_field(chunk, offset)?))
    }
    pub(crate) fn read_frame_header_u64_le(chunk: &[u8], offset: usize) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(read_frame_header_field(chunk, offset)?))
    }
    pub(crate) fn read_chroma_len(chunk: &[u8], offset: usize) -> Result<usize, CodecError> {
        let end = offset
            .checked_add(4)
            .ok_or(CodecError::ChromaPayloadTruncated(
                ChromaPayloadTruncatedInfo,
            ))?;
        let slice = chunk
            .get(offset..end)
            .ok_or(CodecError::ChromaPayloadTruncated(
                ChromaPayloadTruncatedInfo,
            ))?;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(slice);
        Ok(u32::from_le_bytes(raw) as usize)
    }
    fn decode_chroma_plane(
        payload: &[u8],
        frame_type: FrameType,
        quantizer: u8,
        dimensions: FrameDimensions,
        previous: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), CodecError> {
        let aligned = dimensions.align_to_block();
        let expected_blocks = aligned.block_count();
        let mut offset = 0usize;
        let mut reconstructed = vec![0u8; aligned.pixel_count()];
        let mut prev_dc = 0i16;
        if frame_type.reset_dc() {
            prev_dc = 0;
        }
        for block_idx in 0..expected_blocks {
            let coeffs = decode_block_rle(payload, &mut offset, &mut prev_dc, block_idx as u32)?;
            let dequant = dequantize_coeffs(&coeffs, quantizer);
            let spatial = inverse_dct(&dequant);
            let predictor = predictor_block(previous, aligned, block_idx, frame_type);
            write_reconstructed_block(&mut reconstructed, &spatial, &predictor, aligned, block_idx);
        }
        let cropped = crate::streaming::codec::crop_frame_luma(&reconstructed, dimensions, aligned);
        Ok((cropped, reconstructed))
    }
    pub(crate) fn derive_nonce_salt(
        segment_number: u64,
        frame_count: usize,
        chunks: &[Vec<u8>],
    ) -> Hash {
        let mut hasher = domain_hasher(b"nsc_nonce");
        hasher.update(&segment_number.to_le_bytes());
        hasher.update(&(frame_count as u32).to_le_bytes());
        for chunk in chunks {
            hasher.update(&(chunk.len() as u32).to_le_bytes());
            hasher.update(chunk);
        }
        finalize_hash(hasher)
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        fn sample_payload(byte: u8, len: usize) -> Vec<u8> {
            vec![byte; len]
        }
        #[test]
        fn merkle_root_single_leaf_is_leaf() {
            let payload = sample_payload(0xAA, 8);
            let leaf = chunk_leaf_hash(1, 0, &payload);
            let root = merkle_root(&[leaf]).expect("root");
            assert_eq!(root, leaf);
        }
        #[test]
        fn merkle_proof_verifies_for_even_leaves() {
            let ciphertexts = [
                (0u16, sample_payload(0x01, 4)),
                (1u16, sample_payload(0x02, 4)),
                (2u16, sample_payload(0x03, 4)),
                (3u16, sample_payload(0x04, 4)),
            ];
            let payload_refs: Vec<(u16, &[u8])> = ciphertexts
                .iter()
                .map(|(id, data)| (*id, data.as_slice()))
                .collect();
            let leaves = chunk_commitments(7, &payload_refs);
            let root = merkle_root(&leaves).expect("root");
            let proof = merkle_proof(&leaves, 2, 2).expect("proof");
            let leaf = leaves[2];
            assert!(verify_merkle_proof(&leaf, &proof, &root));
        }
        #[test]
        fn merkle_proof_verifies_for_odd_leaves() {
            let ciphertexts = [
                (0u16, sample_payload(0x10, 3)),
                (1u16, sample_payload(0x11, 3)),
                (2u16, sample_payload(0x12, 3)),
            ];
            let payload_refs: Vec<(u16, &[u8])> = ciphertexts
                .iter()
                .map(|(id, data)| (*id, data.as_slice()))
                .collect();
            let leaves = chunk_commitments(9, &payload_refs);
            let root = merkle_root(&leaves).expect("root");
            let proof = merkle_proof(&leaves, 2, 2).expect("proof");
            let leaf = leaves[2];
            assert!(verify_merkle_proof(&leaf, &proof, &root));
        }
        #[test]
        fn merkle_proof_detects_bad_root() {
            let leaves = vec![
                chunk_leaf_hash(1, 0, &sample_payload(1, 2)),
                chunk_leaf_hash(1, 1, &sample_payload(2, 2)),
            ];
            let root = merkle_root(&leaves).expect("root");
            let proof = merkle_proof(&leaves, 0, 0).expect("proof");
            let mut tampered_root = root;
            tampered_root[0] ^= 0xFF;
            assert!(!verify_merkle_proof(&leaves[0], &proof, &tampered_root));
        }
        #[test]
        fn storage_commitment_requires_sorted_ids() {
            let chunk_root = chunk_leaf_hash(5, 0, &sample_payload(0xAA, 1));
            let err = storage_commitment(5, 1, &chunk_root, &[2, 1]).unwrap_err();
            assert!(matches!(err, ChunkError::UnsortedChunkIds));
        }
        #[test]
        fn storage_commitment_matches_spec() {
            let chunk_root = chunk_leaf_hash(5, 0, &sample_payload(0xAA, 4));
            let commitment =
                storage_commitment(5, 12, &chunk_root, &[0, 3, 7]).expect("commitment");
            let proof_root = data_availability_root(5, 12, &chunk_root, &[0, 3, 7]).expect("da");
            assert_ne!(commitment, [0u8; 32]);
            assert_ne!(proof_root, [0u8; 32]);
        }
        #[test]
        fn derive_nonce_salt_varies_with_chunk_payloads() {
            let chunks = vec![sample_payload(0x01, 4), sample_payload(0x02, 8)];
            let salt_a = derive_nonce_salt(9, chunks.len(), &chunks);
            let salt_b = derive_nonce_salt(9, chunks.len(), &chunks);
            assert_eq!(salt_a, salt_b, "nonce salt must be deterministic");
            let mut altered = chunks.clone();
            altered[1][3] ^= 0xFF;
            let salt_c = derive_nonce_salt(9, altered.len(), &altered);
            assert_ne!(salt_a, salt_c, "nonce salt must reflect chunk contents");
            let salt_d = derive_nonce_salt(10, chunks.len(), &chunks);
            assert_ne!(salt_a, salt_d, "nonce salt must capture segment number");
        }
    }
}
pub mod codec;
pub use codec::{
    BundleAnsTables, BundleTableError, default_bundle_tables, load_bundle_tables_from_toml,
    parse_bundle_tables_from_toml,
};
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        deserialize_from, json,
        streaming::codec::{
            BaselineEncoder, BaselineEncoderConfig, BaselineManifestParams, FrameDimensions,
            RawFrame,
        },
        to_bytes,
    };
    use sha2::{Digest, Sha256};
    include!("streaming/shared_hash_tests.rs");
    #[test]
    fn decode_from_slice_rejects_short_payloads() {
        let err = <SoranetRoute as crate::core::DecodeFromSlice>::decode_from_slice(&[])
            .expect_err("short soranet route");
        assert!(matches!(err, crate::core::Error::LengthMismatch));
        let err = <FeedbackHint as crate::core::DecodeFromSlice>::decode_from_slice(&[])
            .expect_err("short feedback hint");
        assert!(matches!(err, crate::core::Error::LengthMismatch));
    }
    #[test]
    fn decode_bundle_stream_simd_rejects_length_mismatch() {
        let tables = codec::default_bundle_tables();
        let mut stream = Vec::new();
        stream.extend_from_slice(b"BR4\x01");
        stream.extend_from_slice(&1u32.to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes());
        let bundles: Vec<codec::BundleRecord> = Vec::new();
        let err =
            codec::decode_bundle_stream(&stream, &bundles, tables.as_ref()).expect_err("bad len");
        assert!(matches!(err, codec::BundleDecodeError::LengthMismatch));
    }
    #[test]
    fn decode_bundle_stream_rejects_zero_bit_length_before_rle_shift() {
        let tables = codec::default_bundle_tables();
        let bundles = [codec::BundleRecord {
            bundle_type: codec::BundleType::SignificanceRle,
            context: codec::BundleContextId::new(0),
            bits: u8::MAX,
            bit_len: 0,
            flush: codec::BundleFlushReason::EndOfBlock,
        }];
        let err = codec::decode_bundle_stream(&[], &bundles, tables.as_ref())
            .expect_err("zero-width records must fail before shifting");
        assert_eq!(
            err,
            codec::BundleDecodeError::InvalidBitLength {
                index: 0,
                bit_len: 0,
                max: tables.max_width(),
            }
        );
    }
    #[test]
    fn decode_bundle_stream_rejects_width_above_authenticated_tables() {
        let tables = codec::default_bundle_tables();
        let invalid_width = tables.max_width().checked_add(1).expect("bounded width");
        let bundles = [codec::BundleRecord {
            bundle_type: codec::BundleType::SignificanceRle,
            context: codec::BundleContextId::new(0),
            bits: u8::MAX,
            bit_len: invalid_width,
            flush: codec::BundleFlushReason::EndOfBlock,
        }];
        let err = codec::decode_bundle_stream(&[], &bundles, tables.as_ref())
            .expect_err("out-of-domain widths must fail before shifting");
        assert_eq!(
            err,
            codec::BundleDecodeError::InvalidBitLength {
                index: 0,
                bit_len: invalid_width,
                max: tables.max_width(),
            }
        );
    }
    #[test]
    fn transparent_wrappers_roundtrip_individually() {
        fn roundtrip<T>(value: T) -> T
        where
            T: NoritoSerialize
                + for<'de> NoritoDeserialize<'de>
                + Copy
                + PartialEq
                + std::fmt::Debug,
        {
            let encoded = to_bytes(&value).expect("serialize wrapper");
            deserialize_from(encoded.as_slice()).expect("deserialize wrapper")
        }
        let profile = ProfileId::UHD_AI;
        assert_eq!(roundtrip(profile), profile);
        let capability_flags = CapabilityFlags::from_bits(
            CapabilityFlags::FEATURE_FEEDBACK_HINTS | CapabilityFlags::FEATURE_SM_TRANSACTIONS,
        );
        assert_eq!(roundtrip(capability_flags), capability_flags);
        let privacy = PrivacyCapabilities::from_bits(0b1010);
        assert_eq!(roundtrip(privacy), privacy);
        let suites = HpkeSuiteMask::KYBER1024;
        assert_eq!(roundtrip(suites), suites);
        let channel = SoranetChannelId::new(demo_hash(0x90));
        assert_eq!(roundtrip(channel), channel);
        let ticket_caps =
            TicketCapabilities::from_bits(TicketCapabilities::LIVE | TicketCapabilities::HDR);
        assert_eq!(roundtrip(ticket_caps), ticket_caps);
    }
    #[test]
    fn manifest_roundtrip() {
        let chunk = ChunkDescriptor {
            chunk_id: 0,
            offset: 0,
            length: 1024,
            commitment: demo_hash(3),
            parity: false,
        };
        let manifest = ManifestV1 {
            stream_id: demo_hash(1),
            protocol_version: 1,
            segment_number: 42,
            published_at: 1_694_000_000,
            profile: ProfileId::BASELINE,
            entropy_mode: crate::streaming::EntropyMode::RansBundled,
            entropy_tables_checksum: None,
            da_endpoint: "/ip4/127.0.0.1/udp/9000/quic".into(),
            chunk_root: demo_hash(2),
            content_key_id: 7,
            nonce_salt: demo_hash(4),
            chunk_descriptors: vec![chunk],
            audio_summary: None,
            transport_capabilities_hash: demo_hash(11),
            encryption_suite: EncryptionSuite::X25519ChaCha20Poly1305(demo_hash(5)),
            fec_suite: FecScheme::Rs12_10,
            privacy_routes: vec![PrivacyRoute {
                route_id: demo_hash(6),
                entry: PrivacyRelay {
                    relay_id: demo_hash(7),
                    endpoint: "/dns/entry.example/quic".into(),
                    key_fingerprint: demo_hash(8),
                    capabilities: PrivacyCapabilities::from_bits(0b001),
                },
                exit: PrivacyRelay {
                    relay_id: demo_hash(9),
                    endpoint: "/dns/exit.example/quic".into(),
                    key_fingerprint: demo_hash(10),
                    capabilities: PrivacyCapabilities::from_bits(0b010),
                },
                ticket_entry: vec![1, 2, 3],
                ticket_exit: vec![4, 5, 6],
                expiry_segment: 100,
                soranet: None,
            }],
            neural_bundle: Some(NeuralBundle {
                bundle_id: "bundle-v1".into(),
                weights_sha256: demo_hash(11),
                activation_scale: vec![123, 234],
                bias: vec![1000, -42],
                metadata_signature: demo_signature(12),
                metal_shader_sha256: Some(demo_hash(13)),
                cuda_ptx_sha256: None,
            }),
            public_metadata: StreamMetadata {
                title: "Test Stream".into(),
                description: Some("Demo manifest".into()),
                access_policy_id: Some(demo_hash(14)),
                tags: vec!["demo".into(), "nsc".into()],
            },
            capabilities: CapabilityFlags::from_bits(0b1_0101),
            signature: demo_signature(15),
        };
        let encoded = to_bytes(&manifest).expect("serialize");
        let decoded: ManifestV1 = deserialize_from(encoded.as_slice()).expect("deserialize");
        assert_eq!(decoded, manifest);
    }
    #[test]
    fn privacy_route_with_soranet_metadata_roundtrip() {
        let route = PrivacyRoute {
            route_id: demo_hash(0x21),
            entry: PrivacyRelay {
                relay_id: demo_hash(0x22),
                endpoint: "/dns/soranet.entry/quic".into(),
                key_fingerprint: demo_hash(0x23),
                capabilities: PrivacyCapabilities::from_bits(0b001),
            },
            exit: PrivacyRelay {
                relay_id: demo_hash(0x24),
                endpoint: "/dns/soranet.exit/quic".into(),
                key_fingerprint: demo_hash(0x25),
                capabilities: PrivacyCapabilities::from_bits(0b010),
            },
            ticket_entry: vec![0x10, 0x11, 0x12],
            ticket_exit: vec![0x20, 0x21, 0x22],
            expiry_segment: 256,
            soranet: Some(SoranetRoute {
                channel_id: SoranetChannelId::new(demo_hash(0x26)),
                exit_multiaddr: "/dns/torii.exit.example/tcp/8080".into(),
                padding_budget_ms: Some(12),
                access_kind: SoranetAccessKind::Authenticated,
                stream_tag: SoranetStreamTag::NoritoStream,
            }),
        };
        let encoded = to_bytes(&route).expect("serialize privacy route");
        let decoded: PrivacyRoute =
            deserialize_from(encoded.as_slice()).expect("deserialize privacy route");
        assert_eq!(decoded, route);
        let soranet = decoded.soranet.expect("soranet metadata present");
        assert_eq!(
            soranet.channel_id.as_bytes(),
            &demo_hash(0x26),
            "channel id must roundtrip"
        );
    }
    #[test]
    fn privacy_route_debug_redacts_bearer_tokens() {
        let relay = PrivacyRelay {
            relay_id: demo_hash(0x41),
            endpoint: "/dns/relay.example/quic".into(),
            key_fingerprint: demo_hash(0x42),
            capabilities: PrivacyCapabilities::from_bits(1),
        };
        let route = PrivacyRoute {
            route_id: demo_hash(0x43),
            entry: relay.clone(),
            exit: relay,
            ticket_entry: vec![0xDE, 0xAD, 0xBE, 0xEF],
            ticket_exit: vec![0xCA, 0xFE, 0xBA, 0xBE],
            expiry_segment: 9,
            soranet: None,
        };
        let rendered = format!("{route:?}");
        assert!(rendered.contains("ticket_entry: <redacted:4 bytes>"));
        assert!(rendered.contains("ticket_exit: <redacted:4 bytes>"));
        assert!(!rendered.contains("222, 173, 190, 239"));
        assert!(!rendered.contains("202, 254, 186, 190"));

        let update = PrivacyRouteUpdate {
            route_id: demo_hash(0x44),
            stream_id: demo_hash(0x45),
            content_key_id: 1,
            valid_from_segment: 0,
            valid_until_segment: u64::MAX,
            exit_token: vec![0xBA, 0xAD, 0xF0, 0x0D],
            soranet: None,
        };
        let rendered = format!("{update:?}");
        assert!(rendered.contains("exit_token: <redacted:4 bytes>"));
        assert!(!rendered.contains("186, 173, 240, 13"));
    }
    #[test]
    fn soranet_stream_tag_default_is_norito() {
        assert_eq!(SoranetStreamTag::default(), SoranetStreamTag::NoritoStream);
    }
    #[test]
    fn receiver_report_with_sync_diagnostics_roundtrip() {
        let diagnostics = SyncDiagnostics {
            window_ms: 500,
            samples: 96,
            avg_audio_jitter_ms: 4,
            max_audio_jitter_ms: 9,
            avg_av_drift_ms: -3,
            max_av_drift_ms: 11,
            ewma_av_drift_ms: -2,
            violation_count: 1,
        };
        let report = ReceiverReport {
            stream_id: demo_hash(0xA0),
            latest_segment: 128,
            layer_mask: 0b101,
            measured_throughput_kbps: 2_400,
            rtt_ms: 37,
            loss_percent_x100: 250,
            decoder_buffer_ms: 180,
            active_resolution: Resolution::R1080p,
            hdr_active: true,
            ecn_ce_count: 4,
            jitter_ms: 7,
            delivered_sequence: 9_001,
            parity_applied: 2,
            fec_budget: 3,
            sync_diagnostics: Some(diagnostics),
        };
        let encoded = to_bytes(&report).expect("serialize receiver report");
        let decoded: ReceiverReport =
            deserialize_from(encoded.as_slice()).expect("deserialize receiver report");
        assert_eq!(decoded, report);
    }
    #[test]
    fn streaming_ticket_roundtrip() {
        let capabilities = TicketCapabilities::from_bits(
            TicketCapabilities::LIVE | TicketCapabilities::HDR | TicketCapabilities::SPATIAL_AUDIO,
        );
        let policy = TicketPolicy {
            max_relays: 4,
            allowed_regions: vec!["us".into(), "jp".into()],
            max_bandwidth_kbps: Some(15_000),
        };
        let ticket = StreamingTicket {
            ticket_id: demo_hash(0x44),
            owner: "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE".to_owned(),
            dsid: 7,
            lane_id: 5,
            settlement_bucket: 2_048,
            start_slot: 21_000,
            expire_slot: 24_000,
            prepaid_teu: 120_000,
            chunk_teu: 64,
            fanout_quota: 12,
            key_commitment: demo_hash(0x55),
            nonce: 42,
            contract_sig: demo_signature(0x66),
            commitment: demo_hash(0x77),
            nullifier: demo_hash(0x88),
            proof_id: demo_hash(0x99),
            issued_at: 1_701_234_567,
            expires_at: 1_701_834_567,
            policy: Some(policy),
            capabilities,
        };
        let encoded = to_bytes(&ticket).expect("serialize ticket");
        let decoded: StreamingTicket =
            deserialize_from(encoded.as_slice()).expect("deserialize ticket");
        assert_eq!(decoded, ticket);
        assert!(decoded.capabilities.contains(TicketCapabilities::HDR));
        assert!(!decoded.capabilities.contains(TicketCapabilities::VOD));
    }
    #[test]
    fn ticket_revocation_roundtrip() {
        let revocation = TicketRevocation {
            ticket_id: demo_hash(0xAA),
            nullifier: demo_hash(0xBB),
            reason_code: 17,
            revocation_signature: demo_signature(0xCC),
        };
        let encoded = to_bytes(&revocation).expect("serialize ticket revocation");
        let decoded: TicketRevocation =
            deserialize_from(encoded.as_slice()).expect("deserialize ticket revocation");
        assert_eq!(decoded, revocation);
    }
    #[test]
    fn control_frame_roundtrip() {
        let frame = ControlFrame::KeyUpdate(KeyUpdate {
            session_id: demo_hash(20),
            suite: EncryptionSuite::Kyber768XChaCha20Poly1305(demo_hash(21)),
            protocol_version: 1,
            pub_ephemeral: vec![0u8; 32],
            key_counter: 5,
            signature: demo_signature(22),
        });
        let encoded = to_bytes(&frame).expect("serialize");
        let decoded: ControlFrame = deserialize_from(encoded.as_slice()).expect("deserialize");
        assert_eq!(decoded, frame);
    }
    #[test]
    fn telemetry_roundtrip() {
        let event = TelemetryEvent::Security(TelemetrySecurityStats {
            suite: EncryptionSuite::X25519ChaCha20Poly1305(demo_hash(30)),
            rekeys: 3,
            gck_rotations: 1,
            last_content_key_id: Some(42),
            last_content_key_valid_from: Some(1_700_123_456),
        });
        let encoded = to_bytes(&event).expect("serialize");
        let decoded: TelemetryEvent = deserialize_from(encoded.as_slice()).expect("deserialize");
        assert_eq!(decoded, event);
    }
    #[test]
    fn segment_header_roundtrip() {
        let header = SegmentHeader {
            segment_number: 77,
            profile: ProfileId::UHD_MAIN,
            entropy_mode: crate::streaming::EntropyMode::RansBundled,
            entropy_tables_checksum: None,
            encryption_suite: EncryptionSuite::X25519ChaCha20Poly1305(demo_hash(40)),
            layer_bitmap: 0b11,
            chunk_merkle_root: demo_hash(41),
            chunk_count: 12,
            timeline_start_ns: 1000,
            duration_ns: 250_000_000,
            feedback_hint: FeedbackHint {
                layer_hints: vec![LayerFeedback {
                    layer_id: 0,
                    min_target_kbps: 1200,
                    max_target_kbps: 2400,
                    storage_hint: Some(StorageClass::Permanent),
                }],
                report_interval_ms: Some(750),
                fec: Some(FecParameters {
                    scheme: FecScheme::Rs18_14,
                    window_step: Some(5),
                    parity_symbols: Some(4),
                }),
            },
            content_key_id: 11,
            nonce_salt: demo_hash(42),
            storage_class: StorageClass::Ephemeral,
            audio_summary: None,
            bundle_acceleration: BundleAcceleration::None,
        };
        let encoded = to_bytes(&header).expect("serialize");
        let decoded: SegmentHeader = deserialize_from(encoded.as_slice()).expect("deserialize");
        assert_eq!(decoded, header);
    }
    #[test]
    fn feedback_hint_frame_roundtrip() {
        let frame = FeedbackHintFrame {
            stream_id: demo_hash(50),
            loss_ewma_q16: 0x0001_8000,
            latency_gradient_q16: -0x0000_4000,
            observed_rtt_ms: 42,
            report_interval_ms: 250,
            parity_chunks: 3,
        };
        let encoded = to_bytes(&frame).expect("serialize");
        let decoded: FeedbackHintFrame = deserialize_from(encoded.as_slice()).expect("deserialize");
        assert_eq!(decoded, frame);
    }
    include!("streaming/baseline_and_bundle_tests.rs");
    include!("streaming/repo_fixture_test.rs");
}

#[cfg(test)]
#[path = "streaming/wire_identity_tests.rs"]
mod wire_identity_tests;
