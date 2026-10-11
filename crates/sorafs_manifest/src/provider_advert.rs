//! Norito-encoded provider advertisements for the SoraFS node ↔ client protocol.
//!
//! The complete advertisement envelope is signed by governed providers and propagated through the
//! discovery mesh. TTLs are capped at 24 hours with clients refreshing half-way through the
//! validity window to avoid stale routes.
use crate::{chunker_registry, deal::XorQuantity};
use core::time::Duration;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use iroha_crypto::{Algorithm, PublicKey};
use norito::{
    core::{DecodeFromSlice, decode_field_canonical},
    derive::{JsonSerialize, NoritoDeserialize, NoritoSerialize},
    json::{FastJsonWrite, JsonSerialize as NoritoJsonSerialize},
};
use soranet_pq::MlDsaSuite;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
/// Explicit governed registered-account download capability.
pub mod account_read;
/// Advertisement schema version.
pub const PROVIDER_ADVERT_VERSION_V1: u8 = 1;
/// Domain separator prepended to canonical provider-advert signature payloads.
pub const PROVIDER_ADVERT_SIGNATURE_DOMAIN_V1: &[u8] = b"sorafs.provider-advert.v1\0";
/// Maximum advertisement time-to-live (seconds).
pub const MAX_ADVERT_TTL_SECS: u64 = 24 * 60 * 60;
/// Recommended refresh interval (seconds) == 12 hours.
pub const REFRESH_RECOMMENDATION_SECS: u64 = 12 * 60 * 60;
/// Maximum exact canonical size of one V1 provider advertisement.
pub const PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1: usize = 1024 * 1024;
/// Maximum UTF-8 byte length of a chunker profile handle or alias.
pub const PROVIDER_ADVERT_PROFILE_HANDLE_MAX_BYTES_V1: usize = 128;
/// Maximum chunker profile aliases in one V1 advertisement.
pub const PROVIDER_ADVERT_PROFILE_ALIASES_MAX_V1: usize = 16;
/// Maximum capability TLVs in one V1 advertisement.
pub const PROVIDER_ADVERT_CAPABILITIES_MAX_V1: usize = 32;
/// Maximum raw bytes in one capability TLV.
pub const PROVIDER_ADVERT_CAPABILITY_PAYLOAD_MAX_BYTES_V1: usize = 64 * 1024;
/// Maximum aggregate raw capability bytes in one advertisement.
pub const PROVIDER_ADVERT_CAPABILITY_PAYLOAD_TOTAL_MAX_BYTES_V1: usize = 256 * 1024;
/// Maximum service endpoints in one V1 advertisement.
pub const PROVIDER_ADVERT_ENDPOINTS_MAX_V1: usize = 32;
/// Maximum UTF-8 byte length of one endpoint host pattern.
pub const PROVIDER_ADVERT_ENDPOINT_HOST_MAX_BYTES_V1: usize = 512;
/// Maximum metadata rows attached to one endpoint.
pub const PROVIDER_ADVERT_ENDPOINT_METADATA_MAX_V1: usize = 16;
/// Maximum raw bytes in one endpoint metadata value.
pub const PROVIDER_ADVERT_ENDPOINT_METADATA_VALUE_MAX_BYTES_V1: usize = 4 * 1024;
/// Maximum aggregate endpoint metadata bytes in one advertisement.
pub const PROVIDER_ADVERT_ENDPOINT_METADATA_TOTAL_MAX_BYTES_V1: usize = 64 * 1024;
/// Maximum rendezvous topics in one V1 advertisement.
pub const PROVIDER_ADVERT_RENDEZVOUS_TOPICS_MAX_V1: usize = 32;
/// Maximum UTF-8 byte length of one rendezvous topic.
pub const PROVIDER_ADVERT_RENDEZVOUS_TOPIC_MAX_BYTES_V1: usize = 256;
/// Maximum UTF-8 byte length of one rendezvous region.
pub const PROVIDER_ADVERT_RENDEZVOUS_REGION_MAX_BYTES_V1: usize = 32;
/// Maximum UTF-8 byte length of operator notes.
pub const PROVIDER_ADVERT_NOTES_MAX_BYTES_V1: usize = 4 * 1024;
/// Maximum transport hints, equal to the V1 protocol enum cardinality.
pub const PROVIDER_ADVERT_TRANSPORT_HINTS_MAX_V1: usize = 4;
/// Norito payload advertised by storage providers.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::ProviderAdvertV1")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct ProviderAdvertV1 {
    /// Version identifier; must equal [`PROVIDER_ADVERT_VERSION_V1`].
    pub version: u8,
    /// Exact genesis block-header hash identifying the network for this signed advert.
    pub network_id: [u8; 32],
    /// Unix timestamp (seconds) when the advert was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when the advert expires.
    pub expires_at: u64,
    /// Body included in the signed advertisement envelope.
    pub body: ProviderAdvertBodyV1,
    /// Provider signature covering the domain-separated canonical envelope.
    pub signature: AdvertSignature,
    /// Signed verification policy; production Torii ingestion requires `true`.
    pub signature_strict: bool,
    /// Allow consumers to ignore unknown capability TLVs (GREASE-friendly).
    #[norito(default)]
    pub allow_unknown_capabilities: bool,
}
/// Canonical provider-advert fields covered by an envelope signature.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::ProviderAdvertSignaturePayloadV1")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct ProviderAdvertSignaturePayloadV1 {
    /// Provider-advert schema version.
    pub version: u8,
    /// Exact genesis block-header hash covered by the provider signature.
    pub network_id: [u8; 32],
    /// Unix timestamp at which the advert was issued.
    pub issued_at: u64,
    /// Unix timestamp at which the advert expires.
    pub expires_at: u64,
    /// Advert body covered by the signature.
    pub body: ProviderAdvertBodyV1,
    /// Signature algorithm selected for the advert.
    pub signature_algorithm: SignatureAlgorithm,
    /// Public key whose corresponding private key signs the payload.
    pub signature_public_key: Vec<u8>,
    /// Whether consumers are required to verify the signature.
    pub signature_strict: bool,
    /// Whether consumers may ignore unknown capability identifiers.
    pub allow_unknown_capabilities: bool,
}
mod borrowed_norito {
    use norito::core::SerializePayload;
    /// Borrowed value that delegates canonical Norito serialization.
    pub(super) struct Value<'a, T>(pub(super) &'a T);
    impl<T: SerializePayload> SerializePayload for Value<'_, T> {
        fn serialize(
            &self,
            writer: &mut norito::core::Encoder<'_>,
        ) -> Result<(), norito::core::Error> {
            self.0.serialize(writer)
        }
        fn encoded_len_hint(&self) -> Option<usize> {
            self.0.encoded_len_hint()
        }
        fn encoded_len_exact(&self) -> Option<usize> {
            self.0.encoded_len_exact()
        }
    }
    /// Borrowed vector that preserves the owned `Vec<T>` wire representation.
    pub(super) struct Vec<'a, T>(pub(super) &'a std::vec::Vec<T>);
    impl<T: SerializePayload> SerializePayload for Vec<'_, T> {
        fn serialize(
            &self,
            writer: &mut norito::core::Encoder<'_>,
        ) -> Result<(), norito::core::Error> {
            self.0.serialize(writer)
        }
        fn encoded_len_hint(&self) -> Option<usize> {
            self.0.encoded_len_hint()
        }
        fn encoded_len_exact(&self) -> Option<usize> {
            self.0.encoded_len_exact()
        }
    }
}
#[derive(norito::derive::SerializePayload)]
struct ProviderAdvertSignaturePayloadViewWireV1<'a> {
    version: u8,
    network_id: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    body: borrowed_norito::Value<'a, ProviderAdvertBodyV1>,
    signature_algorithm: SignatureAlgorithm,
    signature_public_key: borrowed_norito::Vec<'a, u8>,
    signature_strict: bool,
    allow_unknown_capabilities: bool,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_manifest::provider_advert::ProviderAdvertSignaturePayloadViewV1",
    frame = "sorafs_manifest::provider_advert::ProviderAdvertSignaturePayloadV1"
)]
struct ProviderAdvertSignaturePayloadViewV1<'a>(ProviderAdvertSignaturePayloadViewWireV1<'a>);
impl<'a> From<&'a ProviderAdvertV1> for ProviderAdvertSignaturePayloadViewV1<'a> {
    fn from(advert: &'a ProviderAdvertV1) -> Self {
        Self(ProviderAdvertSignaturePayloadViewWireV1 {
            version: advert.version,
            network_id: advert.network_id,
            issued_at: advert.issued_at,
            expires_at: advert.expires_at,
            body: borrowed_norito::Value(&advert.body),
            signature_algorithm: advert.signature.algorithm,
            signature_public_key: borrowed_norito::Vec(&advert.signature.public_key),
            signature_strict: advert.signature_strict,
            allow_unknown_capabilities: advert.allow_unknown_capabilities,
        })
    }
}

impl norito::core::SerializePayload for ProviderAdvertSignaturePayloadViewV1<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}
impl ProviderAdvertV1 {
    /// Returns the advert TTL in seconds.
    #[must_use]
    pub fn ttl(&self) -> u64 {
        self.expires_at.saturating_sub(self.issued_at)
    }
    /// Returns the recommended refresh deadline (`issued_at + min(ceil(TTL/2), 12h)`).
    #[must_use]
    pub fn refresh_deadline(&self) -> u64 {
        let ttl = self.ttl();
        let half_ttl = ttl.div_ceil(2);
        let refresh_offset = half_ttl.min(REFRESH_RECOMMENDATION_SECS);
        self.issued_at.saturating_add(refresh_offset)
    }
    /// Validates timestamps, TTL, and required body fields.
    pub fn validate(&self, now: u64) -> Result<(), AdvertValidationError> {
        preflight_provider_advert_len(self, PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1)?;
        if self.version != PROVIDER_ADVERT_VERSION_V1 {
            return Err(AdvertValidationError::UnsupportedVersion(self.version));
        }
        if self.network_id == [0; 32] {
            return Err(AdvertValidationError::InvalidNetworkId);
        }
        if self.signature.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(AdvertValidationError::UnsupportedSignatureAlgorithm {
                algorithm: self.signature.algorithm,
            });
        }
        if self.signature.public_key.len() != PUBLIC_KEY_LENGTH {
            return Err(AdvertValidationError::InvalidSignaturePublicKeyLength {
                found: self.signature.public_key.len(),
                expected: PUBLIC_KEY_LENGTH,
            });
        }
        if self.signature.signature.len() != SIGNATURE_LENGTH {
            return Err(AdvertValidationError::InvalidSignatureLength {
                found: self.signature.signature.len(),
                expected: SIGNATURE_LENGTH,
            });
        }
        if crate::inert_bytes(&self.signature.public_key)
            || crate::inert_bytes(&self.signature.signature)
        {
            return Err(AdvertValidationError::InvalidSignatureMaterial);
        }
        if self.expires_at <= self.issued_at {
            return Err(AdvertValidationError::InvalidTimestamps);
        }
        if self.issued_at > now {
            return Err(AdvertValidationError::IssuedInFuture {
                now,
                issued_at: self.issued_at,
            });
        }
        let ttl = self.ttl();
        if ttl == 0 || ttl > MAX_ADVERT_TTL_SECS {
            return Err(AdvertValidationError::TtlOutOfRange {
                ttl,
                max: MAX_ADVERT_TTL_SECS,
            });
        }
        if now > self.expires_at {
            return Err(AdvertValidationError::Expired {
                now,
                expires_at: self.expires_at,
            });
        }
        if self.body.endpoints.is_empty() {
            return Err(AdvertValidationError::MissingEndpoints);
        }
        if self.body.rendezvous_topics.is_empty() {
            return Err(AdvertValidationError::MissingRendezvousTopics);
        }
        if self.body.capabilities.is_empty() {
            return Err(AdvertValidationError::MissingCapabilities);
        }
        if self.body.path_policy.min_guard_weight == 0 {
            return Err(AdvertValidationError::InvalidPathPolicy);
        }
        Ok(())
    }
}
/// Provider advertisement body included in the provider-signed envelope.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::ProviderAdvertBodyV1")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct ProviderAdvertBodyV1 {
    /// Governance-controlled provider identifier (32-byte digest).
    pub provider_id: [u8; 32],
    /// SoraFS chunking profile advertised by the provider.
    pub profile_id: String,
    /// Additional handles recognised when negotiating chunkers.
    #[norito(default)]
    pub profile_aliases: Option<Vec<String>>,
    /// Stake pointer used for admission and weight calculations.
    pub stake: StakePointer,
    /// Quality-of-service hints for routing decisions.
    pub qos: QosHints,
    /// Capability TLVs advertised by the provider.
    pub capabilities: Vec<CapabilityTlv>,
    /// Service endpoints (gateway or direct gRPC hosts).
    pub endpoints: Vec<AdvertEndpoint>,
    /// Rendezvous topics published via the discovery mesh.
    pub rendezvous_topics: Vec<RendezvousTopic>,
    /// Path diversity constraints to mitigate eclipse attacks.
    pub path_policy: PathDiversityPolicy,
    /// Optional notes for operators or diagnostics.
    pub notes: Option<String>,
    /// Optional stream budget advertised by the provider.
    #[norito(default)]
    pub stream_budget: Option<StreamBudgetV1>,
    /// Optional transport hints indicating supported protocols.
    #[norito(default)]
    pub transport_hints: Option<Vec<TransportHintV1>>,
}
/// Stake pointer encoded in the advertisement.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::StakePointer")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct StakePointer {
    /// Identifier of the staking pool.
    pub pool_id: [u8; 32],
    /// Exact XOR-denominated amount staked in the pool.
    pub stake_amount: XorQuantity,
}
impl StakePointer {
    /// Returns true if the stake is non-zero.
    #[must_use]
    pub fn is_positive(&self) -> bool {
        !self.stake_amount.is_zero()
    }
}
/// QoS hints used by clients to pick storage providers.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::QosHints")]
#[derive(Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct QosHints {
    /// Availability class advertised by the provider.
    pub availability: AvailabilityTier,
    /// Maximum retrieval latency target (milliseconds).
    pub max_retrieval_latency_ms: u32,
    /// Maximum concurrent streams guaranteed.
    pub max_concurrent_streams: u16,
}
impl QosHints {
    /// Ensures the QoS configuration is internally consistent.
    pub fn validate(&self) -> Result<(), AdvertValidationError> {
        if self.max_retrieval_latency_ms == 0 {
            return Err(AdvertValidationError::InvalidQos);
        }
        if self.max_concurrent_streams == 0 {
            return Err(AdvertValidationError::InvalidQos);
        }
        Ok(())
    }
}
/// Availability tier definitions.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::AvailabilityTier")]
#[derive(Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum AvailabilityTier {
    /// Hot availability — sub-second retrieval targets.
    Hot = 1,
    /// Warm availability — under one minute cold-start.
    Warm = 2,
    /// Cold availability — archival with relaxed SLA.
    Cold = 3,
}
/// Capability TLV advertised by a provider.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::CapabilityTlv")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct CapabilityTlv {
    /// Capability type identifier.
    pub cap_type: CapabilityType,
    /// Capability payload, encoded as raw bytes.
    pub payload: Vec<u8>,
}
/// Enumerates high-level capability families.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::CapabilityType")]
#[derive(
    Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[repr(u16)]
pub enum CapabilityType {
    /// Provider supports SoraFS chunk retrieval over Torii.
    ToriiGateway = 0x0001,
    /// Provider exposes QUIC retrieval with Noise handshake.
    QuicNoise = 0x0002,
    /// Provider supports ranged chunk requests for multi-source fetch.
    ChunkRangeFetch = 0x0004,
    /// Provider advertises hybrid SoraNet PQ support (stage flags).
    SoraNetHybridPq = 0x0005,
    /// Provider advertises the council-governed ML-DSA-65 key used for PoTR receipts.
    PotrMlDsa = 0x0006,
    /// Admitted policy permitting registered accounts to read immutable provider objects.
    RegisteredAccountRead = 0x0007,
    /// Custom capability encoded via payload.
    VendorReserved = 0xFF00,
}
/// Errors raised while validating a governed PoTR ML-DSA capability.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PotrMldsaCapabilityError {
    /// The key does not have the exact ML-DSA-65 public-key length.
    #[error("PoTR ML-DSA capability has invalid public-key length {found}; expected {expected}")]
    InvalidLength {
        /// Observed public-key length.
        found: usize,
        /// Required ML-DSA-65 public-key length.
        expected: usize,
    },
    /// The capability contains inert all-zero key material.
    #[error("PoTR ML-DSA capability public key must not be all zero")]
    InertKey,
    /// The bytes do not parse as a canonical ML-DSA-65 public key.
    #[error("PoTR ML-DSA capability public key is invalid")]
    InvalidKey,
}
/// Validate the raw ML-DSA-65 public key carried by a governed PoTR capability.
pub fn validate_potr_mldsa_capability(public_key: &[u8]) -> Result<(), PotrMldsaCapabilityError> {
    let expected = MlDsaSuite::MlDsa65.public_key_len();
    if public_key.len() != expected {
        return Err(PotrMldsaCapabilityError::InvalidLength {
            found: public_key.len(),
            expected,
        });
    }
    if crate::inert_bytes(public_key) {
        return Err(PotrMldsaCapabilityError::InertKey);
    }
    PublicKey::from_bytes(Algorithm::MlDsa, public_key)
        .map_err(|_| PotrMldsaCapabilityError::InvalidKey)?;
    Ok(())
}
/// Payload describing range-fetch capability metadata.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::ProviderCapabilityRangeV1")]
#[derive(Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct ProviderCapabilityRangeV1 {
    /// Maximum contiguous chunk span that may be served per request.
    pub max_chunk_span: u32,
    /// Minimum granularity (bytes) supported when seeking within a chunk.
    pub min_granularity: u32,
    /// Whether sparse (non-contiguous) offsets are supported.
    pub supports_sparse_offsets: bool,
    /// Whether requests must align to `min_granularity`.
    pub requires_alignment: bool,
    /// Whether Merkle proofs can accompany ranged responses.
    pub supports_merkle_proof: bool,
}
impl Default for ProviderCapabilityRangeV1 {
    fn default() -> Self {
        Self {
            max_chunk_span: 1,
            min_granularity: 1,
            supports_sparse_offsets: false,
            requires_alignment: false,
            supports_merkle_proof: false,
        }
    }
}
const PQ_FLAG_GUARD: u8 = 0x01;
const PQ_FLAG_MAJORITY: u8 = 0x02;
const PQ_FLAG_STRICT: u8 = 0x04;
/// Errors raised when validating SoraNet PQ capability payloads.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PqCapabilityError {
    #[error("soranet_pq capability payload must be exactly 1 byte, found {0}")]
    InvalidLength(usize),
    #[error("soranet_pq capability must advertise guard-level support")]
    MissingGuardSupport,
    #[error("soranet_pq capability marked strict support without majority support")]
    StrictWithoutMajority,
}
/// Bitflag payload describing SoraNet PQ support levels.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::ProviderCapabilitySoranetPqV1")]
#[derive(Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct ProviderCapabilitySoranetPqV1 {
    pub supports_guard: bool,
    pub supports_majority: bool,
    pub supports_strict: bool,
}
impl ProviderCapabilitySoranetPqV1 {
    /// Validate invariants for the payload.
    pub fn validate(&self) -> Result<(), PqCapabilityError> {
        if !self.supports_guard {
            return Err(PqCapabilityError::MissingGuardSupport);
        }
        if self.supports_strict && !self.supports_majority {
            return Err(PqCapabilityError::StrictWithoutMajority);
        }
        Ok(())
    }
    /// Encode the payload into the compact bitflag representation.
    pub fn to_bytes(self) -> Result<Vec<u8>, PqCapabilityError> {
        self.validate()?;
        let mut mask = 0u8;
        if self.supports_guard {
            mask |= PQ_FLAG_GUARD;
        }
        if self.supports_majority {
            mask |= PQ_FLAG_MAJORITY;
        }
        if self.supports_strict {
            mask |= PQ_FLAG_STRICT;
        }
        Ok(vec![mask])
    }
    /// Decode the payload from the bitflag representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqCapabilityError> {
        if bytes.len() != 1 {
            return Err(PqCapabilityError::InvalidLength(bytes.len()));
        }
        let mask = bytes[0];
        let supports_guard = (mask & PQ_FLAG_GUARD) != 0;
        let supports_majority = (mask & PQ_FLAG_MAJORITY) != 0;
        let supports_strict = (mask & PQ_FLAG_STRICT) != 0;
        let payload = Self {
            supports_guard,
            supports_majority,
            supports_strict,
        };
        payload.validate()?;
        Ok(payload)
    }
}
impl ProviderCapabilityRangeV1 {
    /// Validates the capability metadata.
    pub fn validate(&self) -> Result<(), RangeCapabilityError> {
        if self.max_chunk_span == 0 {
            return Err(RangeCapabilityError::InvalidMaxChunkSpan);
        }
        if self.min_granularity == 0 {
            return Err(RangeCapabilityError::InvalidMinGranularity);
        }
        if self.min_granularity > self.max_chunk_span {
            return Err(RangeCapabilityError::GranularityExceedsSpan {
                granularity: self.min_granularity,
                span: self.max_chunk_span,
            });
        }
        Ok(())
    }
    /// Encodes the capability metadata to the compact 9-byte TLV payload.
    pub fn to_bytes(self) -> Result<Vec<u8>, RangeCapabilityError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(9);
        bytes.extend_from_slice(&self.max_chunk_span.to_le_bytes());
        bytes.extend_from_slice(&self.min_granularity.to_le_bytes());
        let mut flags = 0u8;
        if self.supports_sparse_offsets {
            flags |= 0x01;
        }
        if self.requires_alignment {
            flags |= 0x02;
        }
        if self.supports_merkle_proof {
            flags |= 0x04;
        }
        bytes.push(flags);
        Ok(bytes)
    }
    /// Decodes metadata from the compact TLV payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RangeCapabilityError> {
        if bytes.len() != 9 {
            return Err(RangeCapabilityError::Decode(format!(
                "expected 9 bytes, got {}",
                bytes.len()
            )));
        }
        let max_chunk_span = u32::from_le_bytes(bytes[0..4].try_into().expect("length checked"));
        let min_granularity = u32::from_le_bytes(bytes[4..8].try_into().expect("length checked"));
        let flags = bytes[8];
        let value = Self {
            max_chunk_span,
            min_granularity,
            supports_sparse_offsets: flags & 0x01 != 0,
            requires_alignment: flags & 0x02 != 0,
            supports_merkle_proof: flags & 0x04 != 0,
        };
        value.validate()?;
        Ok(value)
    }
}
/// Advertised stream budget for ranged fetches.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::StreamBudgetV1")]
#[derive(Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct StreamBudgetV1 {
    /// Maximum concurrent ranged fetches the provider will serve.
    pub max_in_flight: u16,
    /// Sustained byte rate (bytes per second) reserved for ranged traffic.
    pub max_bytes_per_sec: u64,
    /// Optional burst allowance (bytes).
    #[norito(default)]
    pub burst_bytes: Option<u64>,
}
impl<'a> DecodeFromSlice<'a> for StreamBudgetV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        decode_field_canonical::<Self>(bytes)
    }
}
impl StreamBudgetV1 {
    /// Validates the stream budget configuration.
    pub fn validate(&self) -> Result<(), StreamBudgetError> {
        if self.max_in_flight == 0 {
            return Err(StreamBudgetError::InvalidMaxInFlight);
        }
        if self.max_bytes_per_sec == 0 {
            return Err(StreamBudgetError::InvalidMaxBytesPerSec);
        }
        if let Some(burst) = self.burst_bytes {
            if burst == 0 {
                return Err(StreamBudgetError::InvalidBurstBytes);
            }
            if burst > self.max_bytes_per_sec {
                return Err(StreamBudgetError::BurstExceedsRate {
                    burst,
                    rate: self.max_bytes_per_sec,
                });
            }
        }
        Ok(())
    }
}
/// Hint describing a supported ranged-fetch transport.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::TransportHintV1")]
#[derive(Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
#[norito(decode_from_slice)]
pub struct TransportHintV1 {
    /// Transport protocol identifier.
    pub protocol: TransportProtocol,
    /// Preference ordering (lower values are preferred).
    pub priority: u8,
}
impl TransportHintV1 {
    /// Ensures the transport hint is internally consistent.
    pub fn validate(&self) -> Result<(), TransportHintError> {
        if self.priority > 15 {
            return Err(TransportHintError::InvalidPriority);
        }
        Ok(())
    }
}
/// Transport protocols supported by providers.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::TransportProtocol")]
#[derive(Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TransportProtocol {
    /// HTTP range requests served via Torii.
    ToriiHttpRange = 1,
    /// QUIC stream delivery.
    QuicStream = 2,
    /// SoraNet relay transport.
    SoraNetRelay = 3,
    /// Vendor-reserved protocol identifier.
    VendorReserved = 255,
}
/// Errors raised when validating range capability metadata.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RangeCapabilityError {
    #[error("max_chunk_span must be positive")]
    InvalidMaxChunkSpan,
    #[error("min_granularity must be positive")]
    InvalidMinGranularity,
    #[error("min_granularity {granularity} exceeds max_chunk_span {span}")]
    GranularityExceedsSpan { granularity: u32, span: u32 },
    #[error("failed to encode capability payload: {0}")]
    Encode(String),
    #[error("failed to decode capability payload: {0}")]
    Decode(String),
}
/// Errors raised when validating stream budgets.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum StreamBudgetError {
    #[error("max_in_flight must be at least 1")]
    InvalidMaxInFlight,
    #[error("max_bytes_per_sec must be positive")]
    InvalidMaxBytesPerSec,
    #[error("burst_bytes must be positive")]
    InvalidBurstBytes,
    #[error("burst_bytes {burst} must be <= max_bytes_per_sec {rate}")]
    BurstExceedsRate { burst: u64, rate: u64 },
}
/// Errors raised when validating transport hints.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TransportHintError {
    #[error("transport hint priority is out of range")]
    InvalidPriority,
}
/// Service endpoint exposed by the provider.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::AdvertEndpoint")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct AdvertEndpoint {
    /// Logical endpoint type.
    pub kind: EndpointKind,
    /// Host pattern (FQDN or CIDR notation) the endpoint serves.
    pub host_pattern: String,
    /// Optional TLS fingerprint / ALPN hints.
    pub metadata: Vec<EndpointMetadata>,
}
/// Endpoint metadata TLV fields.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::EndpointMetadata")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct EndpointMetadata {
    /// Metadata field identifier.
    pub key: EndpointMetadataKey,
    /// Raw value bytes.
    pub value: Vec<u8>,
}
/// Metadata keys for endpoint hints.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::EndpointMetadataKey")]
#[derive(Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
#[repr(u16)]
pub enum EndpointMetadataKey {
    /// TLS certificate fingerprint (SHA-256).
    TlsFingerprint = 0x0001,
    /// Supported ALPN identifier.
    Alpn = 0x0002,
    /// Region tag for routing hints.
    Region = 0x0003,
}
/// Endpoint kind enumeration.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::EndpointKind")]
#[derive(Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum EndpointKind {
    /// Torii HTTP/2 gateway.
    Torii = 1,
    /// Direct QUIC retrieval.
    Quic = 2,
    /// Norito-RPC streaming endpoint.
    NoritoRpc = 3,
}
/// Rendezvous topic advertised for discovery.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::RendezvousTopic")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct RendezvousTopic {
    /// Topic identifier (e.g., `sorafs.sf1.primary`).
    pub topic: String,
    /// Region or locale code (ISO-3166 alpha-2 or `global`).
    pub region: String,
}
/// Path diversity policy to mitigate eclipse attacks.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::PathDiversityPolicy")]
#[derive(Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
pub struct PathDiversityPolicy {
    /// Minimum guard weight (stake percentile) allowed per path.
    pub min_guard_weight: u16,
    /// Maximum providers from the same ASN allowed in a circuit.
    pub max_same_asn_per_path: u8,
    /// Maximum entries from the same staking pool.
    pub max_same_pool_per_path: u8,
}
/// Signature covering the domain-separated canonical advertisement envelope.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::AdvertSignature")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, JsonSerialize, PartialEq, Eq)]
#[norito(decode_from_slice)]
pub struct AdvertSignature {
    /// Signature algorithm identifier.
    pub algorithm: SignatureAlgorithm,
    /// Public key bytes.
    pub public_key: Vec<u8>,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}
/// Supported advertisement signature algorithms.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::provider_advert::SignatureAlgorithm")]
#[derive(Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    /// Ed25519 signature (preferred).
    Ed25519 = 1,
    /// Multi-signature aggregated via Norito (reserved).
    MultiSig = 2,
}
impl FastJsonWrite for SignatureAlgorithm {
    fn write_json(&self, out: &mut String) {
        let label = match self {
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::MultiSig => "multi-sig",
        };
        NoritoJsonSerialize::json_serialize(&label, out);
    }
}
impl norito::json::JsonDeserialize for SignatureAlgorithm {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let label = <String as norito::json::JsonDeserialize>::json_deserialize(parser)?;
        match label.as_str() {
            "ed25519" => Ok(Self::Ed25519),
            "multi-sig" => Ok(Self::MultiSig),
            other => Err(norito::json::Error::Message(format!(
                "unknown signature algorithm `{other}`"
            ))),
        }
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        match value.as_str() {
            Some("ed25519") => Ok(Self::Ed25519),
            Some("multi-sig") => Ok(Self::MultiSig),
            Some(other) => Err(norito::json::Error::Message(format!(
                "unknown signature algorithm `{other}`"
            ))),
            None => Err(norito::json::Error::Message(
                "expected string signature algorithm".to_owned(),
            )),
        }
    }
}
/// Builder for constructing provider advertisements.
#[derive(Debug, Default)]
pub struct ProviderAdvertBuilder {
    network_id: Option<[u8; 32]>,
    profile_id: Option<String>,
    profile_aliases: Option<Vec<String>>,
    provider_id: Option<[u8; 32]>,
    stake_pool_id: Option<[u8; 32]>,
    stake_amount: Option<XorQuantity>,
    availability: Option<AvailabilityTier>,
    max_latency_ms: Option<u32>,
    max_streams: Option<u16>,
    capabilities: Vec<CapabilityTlv>,
    endpoints: Vec<AdvertEndpoint>,
    topics: Vec<RendezvousTopic>,
    min_guard_weight: Option<u16>,
    max_same_asn: Option<u8>,
    max_same_pool: Option<u8>,
    notes: Option<String>,
    stream_budget: Option<StreamBudgetV1>,
    transport_hints: Vec<TransportHintV1>,
    issued_at: Option<u64>,
    ttl_secs: Option<u64>,
    signature_alg: Option<SignatureAlgorithm>,
    public_key: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
    allow_unknown_capabilities: bool,
}
/// Errors raised while building provider adverts.
#[derive(Debug, Error)]
pub enum ProviderAdvertBuildError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("provider advert validation failed: {0}")]
    Validation(AdvertValidationError),
}
impl ProviderAdvertBuilder {
    /// Creates a new, empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Bind the advert to the exact genesis block-header hash of its network.
    #[must_use]
    pub fn network_id(&mut self, network_id: [u8; 32]) -> &mut Self {
        self.network_id = Some(network_id);
        self
    }
    #[must_use]
    pub fn profile_id(&mut self, profile_id: impl Into<String>) -> &mut Self {
        self.profile_id = Some(profile_id.into());
        self
    }
    #[must_use]
    pub fn profile_aliases(&mut self, aliases: Vec<String>) -> &mut Self {
        self.profile_aliases = Some(aliases);
        self
    }
    #[must_use]
    pub fn provider_id(&mut self, provider_id: [u8; 32]) -> &mut Self {
        self.provider_id = Some(provider_id);
        self
    }
    #[must_use]
    pub fn stake_pool_id(&mut self, stake_pool_id: [u8; 32]) -> &mut Self {
        self.stake_pool_id = Some(stake_pool_id);
        self
    }
    #[must_use]
    pub fn stake_amount(&mut self, stake_amount: XorQuantity) -> &mut Self {
        self.stake_amount = Some(stake_amount);
        self
    }
    #[must_use]
    pub fn availability(&mut self, availability: AvailabilityTier) -> &mut Self {
        self.availability = Some(availability);
        self
    }
    #[must_use]
    pub fn max_retrieval_latency_ms(&mut self, latency: u32) -> &mut Self {
        self.max_latency_ms = Some(latency);
        self
    }
    #[must_use]
    pub fn max_concurrent_streams(&mut self, streams: u16) -> &mut Self {
        self.max_streams = Some(streams);
        self
    }
    #[must_use]
    pub fn add_capability(&mut self, capability: CapabilityTlv) -> &mut Self {
        self.capabilities.push(capability);
        self
    }
    pub fn add_range_capability(
        &mut self,
        capability: ProviderCapabilityRangeV1,
    ) -> Result<&mut Self, RangeCapabilityError> {
        let payload = capability.to_bytes()?;
        self.capabilities
            .retain(|cap| cap.cap_type != CapabilityType::ChunkRangeFetch);
        self.capabilities.push(CapabilityTlv {
            cap_type: CapabilityType::ChunkRangeFetch,
            payload,
        });
        Ok(self)
    }
    #[must_use]
    pub fn add_endpoint(&mut self, endpoint: AdvertEndpoint) -> &mut Self {
        self.endpoints.push(endpoint);
        self
    }
    #[must_use]
    pub fn add_topic(&mut self, topic: RendezvousTopic) -> &mut Self {
        self.topics.push(topic);
        self
    }
    #[must_use]
    pub fn allow_unknown_capabilities(&mut self, allow: bool) -> &mut Self {
        self.allow_unknown_capabilities = allow;
        self
    }
    #[must_use]
    pub fn path_policy_min_guard_weight(&mut self, weight: u16) -> &mut Self {
        self.min_guard_weight = Some(weight);
        self
    }
    #[must_use]
    pub fn path_policy_max_same_asn_per_path(&mut self, limit: u8) -> &mut Self {
        self.max_same_asn = Some(limit);
        self
    }
    #[must_use]
    pub fn path_policy_max_same_pool_per_path(&mut self, limit: u8) -> &mut Self {
        self.max_same_pool = Some(limit);
        self
    }
    #[must_use]
    pub fn notes(&mut self, notes: impl Into<String>) -> &mut Self {
        self.notes = Some(notes.into());
        self
    }
    #[must_use]
    pub fn stream_budget(&mut self, budget: StreamBudgetV1) -> &mut Self {
        self.stream_budget = Some(budget);
        self
    }
    #[must_use]
    pub fn clear_stream_budget(&mut self) -> &mut Self {
        self.stream_budget = None;
        self
    }
    #[must_use]
    pub fn transport_hints(&mut self, hints: Vec<TransportHintV1>) -> &mut Self {
        self.transport_hints = hints;
        self
    }
    #[must_use]
    pub fn add_transport_hint(&mut self, hint: TransportHintV1) -> &mut Self {
        self.transport_hints.push(hint);
        self
    }
    #[must_use]
    pub fn issued_at(&mut self, issued_at: u64) -> &mut Self {
        self.issued_at = Some(issued_at);
        self
    }
    #[must_use]
    pub fn ttl_secs(&mut self, ttl: u64) -> &mut Self {
        self.ttl_secs = Some(ttl);
        self
    }
    #[must_use]
    pub fn signature(
        &mut self,
        algorithm: SignatureAlgorithm,
        public_key: Vec<u8>,
        signature: Vec<u8>,
    ) -> &mut Self {
        self.signature_alg = Some(algorithm);
        self.public_key = Some(public_key);
        self.signature = Some(signature);
        self
    }
    /// Consumes the builder and returns a fully validated advert.
    pub fn build(self) -> Result<ProviderAdvertV1, ProviderAdvertBuildError> {
        let network_id = self
            .network_id
            .ok_or(ProviderAdvertBuildError::MissingField("network_id"))?;
        let requested_profile = self
            .profile_id
            .ok_or(ProviderAdvertBuildError::MissingField("profile_id"))?;
        let descriptor = chunker_registry::lookup_by_handle(&requested_profile).ok_or(
            ProviderAdvertBuildError::Validation(AdvertValidationError::UnknownProfileHandle {
                handle: requested_profile.clone(),
            }),
        )?;
        let canonical_profile = format!(
            "{}.{}@{}",
            descriptor.namespace, descriptor.name, descriptor.semver
        );
        let profile_id = canonical_profile.clone();
        let provider_id = self
            .provider_id
            .ok_or(ProviderAdvertBuildError::MissingField("provider_id"))?;
        let stake_pool_id = self
            .stake_pool_id
            .ok_or(ProviderAdvertBuildError::MissingField("stake_pool_id"))?;
        let stake_amount = self
            .stake_amount
            .ok_or(ProviderAdvertBuildError::MissingField("stake_amount"))?;
        let availability = self
            .availability
            .ok_or(ProviderAdvertBuildError::MissingField("availability"))?;
        let max_latency_ms = self
            .max_latency_ms
            .ok_or(ProviderAdvertBuildError::MissingField(
                "max_retrieval_latency_ms",
            ))?;
        let max_streams = self
            .max_streams
            .ok_or(ProviderAdvertBuildError::MissingField(
                "max_concurrent_streams",
            ))?;
        if self.capabilities.is_empty() {
            return Err(ProviderAdvertBuildError::MissingField("capabilities"));
        }
        if self.endpoints.is_empty() {
            return Err(ProviderAdvertBuildError::MissingField("endpoints"));
        }
        if self.topics.is_empty() {
            return Err(ProviderAdvertBuildError::MissingField("rendezvous_topics"));
        }
        let signature_alg = self.signature_alg.unwrap_or(SignatureAlgorithm::Ed25519);
        let public_key = self
            .public_key
            .ok_or(ProviderAdvertBuildError::MissingField("public_key"))?;
        let signature = self
            .signature
            .ok_or(ProviderAdvertBuildError::MissingField("signature"))?;
        let issued_at = self
            .issued_at
            .unwrap_or_else(|| unix_time_now().unwrap_or(0));
        let ttl = self
            .ttl_secs
            .unwrap_or(REFRESH_RECOMMENDATION_SECS * 2)
            .min(MAX_ADVERT_TTL_SECS);
        let expires_at = issued_at
            .checked_add(ttl)
            .ok_or(ProviderAdvertBuildError::Validation(
                AdvertValidationError::InvalidTimestamps,
            ))?;
        if ttl == 0 {
            return Err(ProviderAdvertBuildError::Validation(
                AdvertValidationError::InvalidTimestamps,
            ));
        }
        let profile_aliases = self.profile_aliases.map(|mut aliases| {
            if !aliases.iter().any(|alias| alias == &profile_id) {
                aliases.insert(0, profile_id.clone());
            } else if !aliases
                .first()
                .map(|alias| alias == &profile_id)
                .unwrap_or(false)
            {
                aliases.retain(|alias| alias != &profile_id);
                aliases.insert(0, profile_id.clone());
            }
            aliases
        });
        let stream_budget = self.stream_budget;
        let transport_hints = if self.transport_hints.is_empty() {
            None
        } else {
            Some(self.transport_hints.clone())
        };
        let body = ProviderAdvertBodyV1 {
            provider_id,
            profile_id,
            profile_aliases,
            stake: StakePointer {
                pool_id: stake_pool_id,
                stake_amount,
            },
            qos: QosHints {
                availability,
                max_retrieval_latency_ms: max_latency_ms,
                max_concurrent_streams: max_streams,
            },
            capabilities: self.capabilities,
            endpoints: self.endpoints,
            rendezvous_topics: self.topics,
            path_policy: PathDiversityPolicy {
                min_guard_weight: self.min_guard_weight.unwrap_or(10),
                max_same_asn_per_path: self.max_same_asn.unwrap_or(1),
                max_same_pool_per_path: self.max_same_pool.unwrap_or(1),
            },
            notes: self.notes,
            stream_budget,
            transport_hints,
        };
        body.validate()
            .map_err(ProviderAdvertBuildError::Validation)?;
        let advert = ProviderAdvertV1 {
            version: PROVIDER_ADVERT_VERSION_V1,
            network_id,
            issued_at,
            expires_at,
            body,
            signature: AdvertSignature {
                algorithm: signature_alg,
                public_key,
                signature,
            },
            signature_strict: true,
            allow_unknown_capabilities: self.allow_unknown_capabilities,
        };
        advert
            .validate_with_body(issued_at)
            .map_err(ProviderAdvertBuildError::Validation)?;
        Ok(advert)
    }
}
impl ProviderAdvertV1 {
    /// Returns a builder for the advert.
    #[must_use]
    pub fn builder() -> ProviderAdvertBuilder {
        ProviderAdvertBuilder::new()
    }
}
/// Errors raised while validating a provider advert.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdvertValidationError {
    #[error("provider advert does not expose an exact canonical encoded length")]
    CanonicalLengthUnavailable,
    #[error("provider advert has {found} canonical bytes; maximum is {maximum}")]
    AdvertTooLarge { found: usize, maximum: usize },
    #[error("unsupported provider advert version: {0}")]
    UnsupportedVersion(u8),
    #[error("provider advert network id must be the nonzero genesis block-header hash")]
    InvalidNetworkId,
    #[error("unsupported first-release provider advert signature algorithm: {algorithm:?}")]
    UnsupportedSignatureAlgorithm { algorithm: SignatureAlgorithm },
    #[error("provider advert public key has {found} bytes; expected {expected}")]
    InvalidSignaturePublicKeyLength { found: usize, expected: usize },
    #[error("provider advert signature has {found} bytes; expected {expected}")]
    InvalidSignatureLength { found: usize, expected: usize },
    #[error("provider advert signature material must not be inert")]
    InvalidSignatureMaterial,
    #[error("expires_at must be greater than issued_at")]
    InvalidTimestamps,
    #[error("advert issued in the future (now={now}, issued_at={issued_at})")]
    IssuedInFuture { now: u64, issued_at: u64 },
    #[error("advert TTL {ttl} exceeds maximum {max}")]
    TtlOutOfRange { ttl: u64, max: u64 },
    #[error("advert expired (now={now}, expires_at={expires_at})")]
    Expired { now: u64, expires_at: u64 },
    #[error("provider advert must advertise at least one endpoint")]
    MissingEndpoints,
    #[error("provider advert must include at least one rendezvous topic")]
    MissingRendezvousTopics,
    #[error("provider advert must advertise at least one capability")]
    MissingCapabilities,
    #[error("path diversity policy must require a positive guard weight")]
    InvalidPathPolicy,
    #[error("invalid QoS configuration")]
    InvalidQos,
    #[error("profile_aliases must include the advertised chunker handle and canonical aliases")]
    MissingProfileAliases,
    #[error("profile_aliases may not contain empty or whitespace-only entries")]
    InvalidProfileAlias,
    #[error("chunker profile handle has {found} bytes; maximum is {maximum}")]
    ProfileHandleTooLong { found: usize, maximum: usize },
    #[error("profile alias #{index} has {found} bytes; maximum is {maximum}")]
    ProfileAliasTooLong {
        index: usize,
        found: usize,
        maximum: usize,
    },
    #[error("profile_aliases has {found} rows; maximum is {maximum}")]
    TooManyProfileAliases { found: usize, maximum: usize },
    #[error("profile_aliases must include required alias {alias}")]
    MissingRequiredAlias { alias: String },
    #[error("unknown chunker profile handle advertised: {handle}")]
    UnknownProfileHandle { handle: String },
    #[error("duplicate profile alias detected: {alias}")]
    DuplicateProfileAlias { alias: String },
    #[error("range capability payload missing or malformed")]
    InvalidRangeCapabilityPayload,
    #[error("range capability payload invalid: {0}")]
    InvalidRangeCapability(RangeCapabilityError),
    #[error("duplicate range capability TLV detected")]
    DuplicateRangeCapability,
    #[error("duplicate PoTR ML-DSA capability TLV detected")]
    DuplicatePotrMldsaCapability,
    #[error("registered-account read capability is duplicate or invalid")]
    InvalidAccountReadCapability,
    #[error("advert has {found} capability TLVs; maximum is {maximum}")]
    TooManyCapabilities { found: usize, maximum: usize },
    #[error("capability #{index} has {found} payload bytes; maximum is {maximum}")]
    CapabilityPayloadTooLarge {
        index: usize,
        found: usize,
        maximum: usize,
    },
    #[error("capability payloads have {found} aggregate bytes; maximum is {maximum}")]
    CapabilityPayloadAggregateTooLarge { found: usize, maximum: usize },
    #[error("capability payload aggregate length overflow")]
    CapabilityPayloadLengthOverflow,
    #[error("PoTR ML-DSA capability invalid: {0}")]
    InvalidPotrMldsaCapability(#[source] PotrMldsaCapabilityError),
    #[error("stream budget or transport hints require chunk_range_fetch capability")]
    RangeMetadataWithoutCapability,
    #[error("stream budget invalid: {0}")]
    InvalidStreamBudget(StreamBudgetError),
    #[error("transport hints must not be empty when provided")]
    EmptyTransportHints,
    #[error("advert has {found} transport hints; maximum is {maximum}")]
    TooManyTransportHints { found: usize, maximum: usize },
    #[error("transport hints must have unique protocols")]
    DuplicateTransportProtocol,
    #[error("transport hint invalid: {0}")]
    InvalidTransportHint(TransportHintError),
    #[error("soranet transport hints require a soranet capability")]
    SoranetTransportWithoutCapability,
    #[error("advert has {found} endpoints; maximum is {maximum}")]
    TooManyEndpoints { found: usize, maximum: usize },
    #[error("endpoint #{index} host pattern is noncanonical or exceeds {maximum} bytes")]
    InvalidEndpointHost { index: usize, maximum: usize },
    #[error("endpoint #{index} has {found} metadata rows; maximum is {maximum}")]
    TooManyEndpointMetadata {
        index: usize,
        found: usize,
        maximum: usize,
    },
    #[error(
        "endpoint #{endpoint_index} metadata #{metadata_index} has {found} bytes; maximum is {maximum}"
    )]
    EndpointMetadataValueTooLarge {
        endpoint_index: usize,
        metadata_index: usize,
        found: usize,
        maximum: usize,
    },
    #[error("endpoint metadata has {found} aggregate bytes; maximum is {maximum}")]
    EndpointMetadataAggregateTooLarge { found: usize, maximum: usize },
    #[error("endpoint metadata aggregate length overflow")]
    EndpointMetadataLengthOverflow,
    #[error("advert has {found} rendezvous topics; maximum is {maximum}")]
    TooManyRendezvousTopics { found: usize, maximum: usize },
    #[error("rendezvous topic #{index} is noncanonical or exceeds {maximum} bytes")]
    InvalidRendezvousTopic { index: usize, maximum: usize },
    #[error("rendezvous region #{index} is noncanonical or exceeds {maximum} bytes")]
    InvalidRendezvousRegion { index: usize, maximum: usize },
    #[error("operator notes are noncanonical or exceed {maximum} bytes")]
    InvalidNotes { maximum: usize },
}
fn preflight_provider_advert_len(
    advert: &ProviderAdvertV1,
    maximum: usize,
) -> Result<usize, AdvertValidationError> {
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    if let Some(found) = norito::core::SerializePayload::encoded_len_exact(advert)
        && found > maximum
    {
        return Err(AdvertValidationError::AdvertTooLarge { found, maximum });
    }
    let found = norito::core::encoded_payload_len(advert)
        .map_err(|_| AdvertValidationError::CanonicalLengthUnavailable)?;
    if found > maximum {
        return Err(AdvertValidationError::AdvertTooLarge { found, maximum });
    }
    Ok(found)
}
/// Decode one bounded, canonically encoded V1 provider advertisement.
///
/// Structural and signature-policy validation remains the caller's
/// responsibility because it requires an admission timestamp.
///
/// # Errors
///
/// Returns a Norito error for oversized, malformed, or noncanonical bytes.
pub fn decode_provider_advert_v1(bytes: &[u8]) -> Result<ProviderAdvertV1, norito::core::Error> {
    if bytes.len() > PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1 {
        return Err(norito::core::Error::Message(format!(
            "provider advert has {} canonical bytes; maximum is {PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1}",
            bytes.len()
        )));
    }
    let advert: ProviderAdvertV1 = norito::decode_canonical_with_limits(
        bytes,
        norito::DecodeLimits::new(
            PROVIDER_ADVERT_CAPABILITY_PAYLOAD_MAX_BYTES_V1,
            // Field budgets include the whole nested body, not just its leaf buffers.
            // Per-capability sequence limits and body leaf/aggregate validation are separate.
            PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1,
            400_000,
            PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1 * 4,
            64,
        ),
    )?;
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let exact = norito::core::encoded_payload_len(&advert)?;
    if exact > PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1 {
        return Err(norito::core::Error::Message(format!(
            "provider advert has {exact} canonical bytes; maximum is {PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1}"
        )));
    }
    Ok(advert)
}
impl ProviderAdvertBodyV1 {
    /// Validates the body independently of outer metadata.
    pub fn validate(&self) -> Result<(), AdvertValidationError> {
        if !self.stake.is_positive() {
            return Err(AdvertValidationError::InvalidQos);
        }
        self.qos.validate()?;
        if self.profile_id.len() > PROVIDER_ADVERT_PROFILE_HANDLE_MAX_BYTES_V1 {
            return Err(AdvertValidationError::ProfileHandleTooLong {
                found: self.profile_id.len(),
                maximum: PROVIDER_ADVERT_PROFILE_HANDLE_MAX_BYTES_V1,
            });
        }
        let descriptor = chunker_registry::lookup_by_handle(&self.profile_id).ok_or_else(|| {
            AdvertValidationError::UnknownProfileHandle {
                handle: self.profile_id.clone(),
            }
        })?;
        let aliases = self
            .profile_aliases
            .as_ref()
            .ok_or(AdvertValidationError::MissingProfileAliases)?;
        if aliases.is_empty() {
            return Err(AdvertValidationError::MissingProfileAliases);
        }
        if aliases.len() > PROVIDER_ADVERT_PROFILE_ALIASES_MAX_V1 {
            return Err(AdvertValidationError::TooManyProfileAliases {
                found: aliases.len(),
                maximum: PROVIDER_ADVERT_PROFILE_ALIASES_MAX_V1,
            });
        }
        let mut seen = std::collections::HashSet::new();
        for (index, alias) in aliases.iter().enumerate() {
            if alias.len() > PROVIDER_ADVERT_PROFILE_HANDLE_MAX_BYTES_V1 {
                return Err(AdvertValidationError::ProfileAliasTooLong {
                    index,
                    found: alias.len(),
                    maximum: PROVIDER_ADVERT_PROFILE_HANDLE_MAX_BYTES_V1,
                });
            }
            let trimmed = alias.trim();
            if trimmed.is_empty() || trimmed != alias || alias.chars().any(char::is_control) {
                return Err(AdvertValidationError::InvalidProfileAlias);
            }
            if !seen.insert(trimmed) {
                return Err(AdvertValidationError::DuplicateProfileAlias {
                    alias: trimmed.to_owned(),
                });
            }
        }
        for required in descriptor.aliases {
            if !seen.contains(*required) {
                return Err(AdvertValidationError::MissingRequiredAlias {
                    alias: (*required).to_owned(),
                });
            }
        }
        if self.capabilities.len() > PROVIDER_ADVERT_CAPABILITIES_MAX_V1 {
            return Err(AdvertValidationError::TooManyCapabilities {
                found: self.capabilities.len(),
                maximum: PROVIDER_ADVERT_CAPABILITIES_MAX_V1,
            });
        }
        let mut capability_payload_bytes = 0_usize;
        for (index, capability) in self.capabilities.iter().enumerate() {
            if capability.payload.len() > PROVIDER_ADVERT_CAPABILITY_PAYLOAD_MAX_BYTES_V1 {
                return Err(AdvertValidationError::CapabilityPayloadTooLarge {
                    index,
                    found: capability.payload.len(),
                    maximum: PROVIDER_ADVERT_CAPABILITY_PAYLOAD_MAX_BYTES_V1,
                });
            }
            capability_payload_bytes = capability_payload_bytes
                .checked_add(capability.payload.len())
                .ok_or(AdvertValidationError::CapabilityPayloadLengthOverflow)?;
            if capability_payload_bytes > PROVIDER_ADVERT_CAPABILITY_PAYLOAD_TOTAL_MAX_BYTES_V1 {
                return Err(AdvertValidationError::CapabilityPayloadAggregateTooLarge {
                    found: capability_payload_bytes,
                    maximum: PROVIDER_ADVERT_CAPABILITY_PAYLOAD_TOTAL_MAX_BYTES_V1,
                });
            }
        }
        let mut seen_range_capability = false;
        account_read::RegisteredAccountReadV1::from_capabilities(&self.capabilities)
            .map_err(|_| AdvertValidationError::InvalidAccountReadCapability)?;
        let mut seen_potr_mldsa_capability = false;
        for capability in &self.capabilities {
            if capability.cap_type == CapabilityType::ChunkRangeFetch {
                if seen_range_capability {
                    return Err(AdvertValidationError::DuplicateRangeCapability);
                }
                let range_cap = ProviderCapabilityRangeV1::from_bytes(&capability.payload)
                    .map_err(|_| AdvertValidationError::InvalidRangeCapabilityPayload)?;
                range_cap
                    .validate()
                    .map_err(AdvertValidationError::InvalidRangeCapability)?;
                seen_range_capability = true;
                continue;
            }
            if capability.cap_type == CapabilityType::PotrMlDsa {
                if seen_potr_mldsa_capability {
                    return Err(AdvertValidationError::DuplicatePotrMldsaCapability);
                }
                validate_potr_mldsa_capability(&capability.payload)
                    .map_err(AdvertValidationError::InvalidPotrMldsaCapability)?;
                seen_potr_mldsa_capability = true;
            }
        }
        if self.endpoints.len() > PROVIDER_ADVERT_ENDPOINTS_MAX_V1 {
            return Err(AdvertValidationError::TooManyEndpoints {
                found: self.endpoints.len(),
                maximum: PROVIDER_ADVERT_ENDPOINTS_MAX_V1,
            });
        }
        let mut endpoint_metadata_bytes = 0_usize;
        for (endpoint_index, endpoint) in self.endpoints.iter().enumerate() {
            if !is_canonical_bounded_text(
                &endpoint.host_pattern,
                PROVIDER_ADVERT_ENDPOINT_HOST_MAX_BYTES_V1,
            ) {
                return Err(AdvertValidationError::InvalidEndpointHost {
                    index: endpoint_index,
                    maximum: PROVIDER_ADVERT_ENDPOINT_HOST_MAX_BYTES_V1,
                });
            }
            if endpoint.metadata.len() > PROVIDER_ADVERT_ENDPOINT_METADATA_MAX_V1 {
                return Err(AdvertValidationError::TooManyEndpointMetadata {
                    index: endpoint_index,
                    found: endpoint.metadata.len(),
                    maximum: PROVIDER_ADVERT_ENDPOINT_METADATA_MAX_V1,
                });
            }
            for (metadata_index, metadata) in endpoint.metadata.iter().enumerate() {
                if metadata.value.len() > PROVIDER_ADVERT_ENDPOINT_METADATA_VALUE_MAX_BYTES_V1 {
                    return Err(AdvertValidationError::EndpointMetadataValueTooLarge {
                        endpoint_index,
                        metadata_index,
                        found: metadata.value.len(),
                        maximum: PROVIDER_ADVERT_ENDPOINT_METADATA_VALUE_MAX_BYTES_V1,
                    });
                }
                endpoint_metadata_bytes = endpoint_metadata_bytes
                    .checked_add(metadata.value.len())
                    .ok_or(AdvertValidationError::EndpointMetadataLengthOverflow)?;
                if endpoint_metadata_bytes > PROVIDER_ADVERT_ENDPOINT_METADATA_TOTAL_MAX_BYTES_V1 {
                    return Err(AdvertValidationError::EndpointMetadataAggregateTooLarge {
                        found: endpoint_metadata_bytes,
                        maximum: PROVIDER_ADVERT_ENDPOINT_METADATA_TOTAL_MAX_BYTES_V1,
                    });
                }
            }
        }
        if self.rendezvous_topics.len() > PROVIDER_ADVERT_RENDEZVOUS_TOPICS_MAX_V1 {
            return Err(AdvertValidationError::TooManyRendezvousTopics {
                found: self.rendezvous_topics.len(),
                maximum: PROVIDER_ADVERT_RENDEZVOUS_TOPICS_MAX_V1,
            });
        }
        for (index, rendezvous) in self.rendezvous_topics.iter().enumerate() {
            if !is_canonical_bounded_text(
                &rendezvous.topic,
                PROVIDER_ADVERT_RENDEZVOUS_TOPIC_MAX_BYTES_V1,
            ) {
                return Err(AdvertValidationError::InvalidRendezvousTopic {
                    index,
                    maximum: PROVIDER_ADVERT_RENDEZVOUS_TOPIC_MAX_BYTES_V1,
                });
            }
            if !is_canonical_bounded_text(
                &rendezvous.region,
                PROVIDER_ADVERT_RENDEZVOUS_REGION_MAX_BYTES_V1,
            ) {
                return Err(AdvertValidationError::InvalidRendezvousRegion {
                    index,
                    maximum: PROVIDER_ADVERT_RENDEZVOUS_REGION_MAX_BYTES_V1,
                });
            }
        }
        if self.notes.as_ref().is_some_and(|notes| {
            !is_canonical_bounded_text(notes, PROVIDER_ADVERT_NOTES_MAX_BYTES_V1)
        }) {
            return Err(AdvertValidationError::InvalidNotes {
                maximum: PROVIDER_ADVERT_NOTES_MAX_BYTES_V1,
            });
        }
        let mut has_stream_budget = false;
        if let Some(budget) = &self.stream_budget {
            has_stream_budget = true;
            budget
                .validate()
                .map_err(AdvertValidationError::InvalidStreamBudget)?;
        }
        let mut has_transport_hints = false;
        if let Some(hints) = &self.transport_hints {
            if hints.is_empty() {
                return Err(AdvertValidationError::EmptyTransportHints);
            }
            if hints.len() > PROVIDER_ADVERT_TRANSPORT_HINTS_MAX_V1 {
                return Err(AdvertValidationError::TooManyTransportHints {
                    found: hints.len(),
                    maximum: PROVIDER_ADVERT_TRANSPORT_HINTS_MAX_V1,
                });
            }
            has_transport_hints = true;
            let mut seen_protocols = std::collections::HashSet::new();
            for hint in hints {
                hint.validate()
                    .map_err(AdvertValidationError::InvalidTransportHint)?;
                if !seen_protocols.insert(hint.protocol) {
                    return Err(AdvertValidationError::DuplicateTransportProtocol);
                }
            }
            let has_soranet_hint = hints
                .iter()
                .any(|hint| hint.protocol == TransportProtocol::SoraNetRelay);
            if has_soranet_hint
                && !self
                    .capabilities
                    .iter()
                    .any(|cap| cap.cap_type == CapabilityType::SoraNetHybridPq)
            {
                return Err(AdvertValidationError::SoranetTransportWithoutCapability);
            }
        }
        if (has_stream_budget || has_transport_hints) && !seen_range_capability {
            return Err(AdvertValidationError::RangeMetadataWithoutCapability);
        }
        Ok(())
    }
}
fn is_canonical_bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
impl ProviderAdvertV1 {
    /// Combined validation helper for outer advert and inner body.
    pub fn validate_with_body(&self, now: u64) -> Result<(), AdvertValidationError> {
        self.validate(now)?;
        self.body.validate()?;
        Ok(())
    }
    /// Returns the canonical envelope fields covered by the signature.
    #[must_use]
    pub fn signature_payload(&self) -> ProviderAdvertSignaturePayloadV1 {
        ProviderAdvertSignaturePayloadV1 {
            version: self.version,
            network_id: self.network_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            body: self.body.clone(),
            signature_algorithm: self.signature.algorithm,
            signature_public_key: self.signature.public_key.clone(),
            signature_strict: self.signature_strict,
            allow_unknown_capabilities: self.allow_unknown_capabilities,
        }
    }
    /// Returns the domain-separated canonical bytes covered by the signature.
    ///
    /// The signed envelope binds the schema version, timestamps, body,
    /// signature algorithm and public key, strict-verification policy, and
    /// unknown-capability policy. Signature bytes themselves are excluded.
    pub fn signature_payload_bytes(&self) -> Result<Vec<u8>, AdvertSignatureError> {
        let _canonical_flags =
            norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        preflight_provider_advert_len(self, PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1)
            .map_err(|error| AdvertSignatureError::EnvelopeEncoding(error.to_string()))?;
        let envelope = ProviderAdvertSignaturePayloadViewV1::from(self);
        let exact = norito::core::encoded_payload_len(&envelope)
            .map_err(|_| AdvertSignatureError::CanonicalLengthUnavailable)?;
        if exact > PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1 {
            return Err(AdvertSignatureError::EnvelopeTooLarge {
                found: exact,
                maximum: PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1,
            });
        }
        let envelope_bytes = norito::encode_canonical(&envelope)
            .map_err(|err| AdvertSignatureError::EnvelopeEncoding(err.to_string()))?;
        let mut payload =
            Vec::with_capacity(PROVIDER_ADVERT_SIGNATURE_DOMAIN_V1.len() + envelope_bytes.len());
        payload.extend_from_slice(PROVIDER_ADVERT_SIGNATURE_DOMAIN_V1);
        payload.extend_from_slice(&envelope_bytes);
        Ok(payload)
    }
    /// Verifies the provider signature over the canonical advert envelope.
    pub fn verify_signature(&self) -> Result<(), AdvertSignatureError> {
        match self.signature.algorithm {
            SignatureAlgorithm::Ed25519 => {}
            other => return Err(AdvertSignatureError::UnsupportedAlgorithm(other)),
        }
        if self.signature.public_key.len() != PUBLIC_KEY_LENGTH {
            return Err(AdvertSignatureError::InvalidPublicKeyLength {
                length: self.signature.public_key.len(),
            });
        }
        if self.signature.signature.len() != SIGNATURE_LENGTH {
            return Err(AdvertSignatureError::InvalidSignatureLength {
                length: self.signature.signature.len(),
            });
        }
        let mut public_key = [0u8; PUBLIC_KEY_LENGTH];
        public_key.copy_from_slice(&self.signature.public_key);
        let verifying_key = crate::checked_ed25519_verifying_key_from_bytes(&public_key)
            .map_err(AdvertSignatureError::InvalidPublicKey)?;
        let mut signature = [0u8; SIGNATURE_LENGTH];
        signature.copy_from_slice(&self.signature.signature);
        let signature = crate::checked_ed25519_signature_from_bytes(&signature)
            .map_err(AdvertSignatureError::Verification)?;
        let payload = self.signature_payload_bytes()?;
        verifying_key
            .verify_strict(&payload, &signature)
            .map_err(|err| AdvertSignatureError::Verification(err.to_string()))
    }
}
/// Human-friendly accessors useful for monitoring dashboards.
impl ProviderAdvertV1 {
    /// Returns the TTL as a [`Duration`].
    #[must_use]
    pub fn ttl_duration(&self) -> Duration {
        Duration::from_secs(self.ttl())
    }
    /// Returns the refresh deadline as a [`Duration`] since epoch.
    #[must_use]
    pub fn refresh_deadline_duration(&self) -> Duration {
        Duration::from_secs(self.refresh_deadline())
    }
}
/// Errors raised while verifying a provider advert signature.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdvertSignatureError {
    /// Signature algorithm is not supported by this validator.
    #[error("unsupported provider advert signature algorithm: {0:?}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    /// Ed25519 public key length is invalid.
    #[error("ed25519 public key must be 32 bytes, got {length}")]
    InvalidPublicKeyLength {
        /// Observed public key byte length.
        length: usize,
    },
    /// Ed25519 signature length is invalid.
    #[error("ed25519 signature must be 64 bytes, got {length}")]
    InvalidSignatureLength {
        /// Observed signature byte length.
        length: usize,
    },
    /// Public key bytes could not be parsed.
    #[error("invalid ed25519 public key: {0}")]
    InvalidPublicKey(String),
    /// Canonical signature-envelope length cannot be preflighted exactly.
    #[error("provider advert signature envelope has no exact canonical encoded length")]
    CanonicalLengthUnavailable,
    /// Canonical signature envelope exceeds the V1 provider-advert ceiling.
    #[error("provider advert signature envelope has {found} bytes; maximum is {maximum}")]
    EnvelopeTooLarge {
        /// Exact canonical signature-envelope bytes.
        found: usize,
        /// Maximum accepted signature-envelope bytes.
        maximum: usize,
    },
    /// Advert envelope could not be encoded into canonical signature bytes.
    #[error("failed to encode provider advert envelope for signature verification: {0}")]
    EnvelopeEncoding(String),
    /// Signature verification failed.
    #[error("provider advert signature verification failed: {0}")]
    Verification(String),
}
fn unix_time_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use iroha_crypto::{Algorithm, KeyPair};
    use norito::{SerializePayload as _, decode_from_bytes, to_bytes};
    fn encode_bare_with_flags<T: norito::core::NoritoSerialize>(value: &T, flags: u8) -> Vec<u8> {
        let _guard = norito::core::DecodeFlagsGuard::enter(flags);
        let mut bytes = Vec::new();
        norito::core::serialize_to_buffer(value, &mut bytes).expect("serialize explicit layout");
        bytes
    }
    fn encode_frame_with_flags<T: norito::core::NoritoSerialize>(value: &T, flags: u8) -> Vec<u8> {
        let _guard = norito::core::DecodeFlagsGuard::enter(flags);
        norito::to_bytes(value).expect("serialize explicit canonical frame")
    }
    fn supported_layouts() -> [u8; 2] {
        [0, norito::core::header_flags::COMPACT_LEN]
    }
    include!("provider_advert/canonical_tests.rs");

    #[test]
    fn transport_hint_slice_decoder_preserves_mandatory_record_fields() {
        use norito::core::{DecodeFlagsGuard, DecodeFromSlice};

        for flags in supported_layouts() {
            let _flags = DecodeFlagsGuard::enter(flags);
            let frame = |body: &[u8]| {
                let mut bytes = Vec::new();
                norito::core::write_len_to_vec_with_flags(&mut bytes, body.len() as u64, flags);
                bytes.extend_from_slice(body);
                bytes
            };
            for (protocol, tag) in [
                (TransportProtocol::ToriiHttpRange, 1_u32),
                (TransportProtocol::QuicStream, 2),
                (TransportProtocol::SoraNetRelay, 3),
                (TransportProtocol::VendorReserved, 255),
            ] {
                let hint = TransportHintV1 {
                    protocol,
                    priority: 7,
                };
                let wire = encode_bare_with_flags(&hint, flags);
                let mut expected = frame(&tag.to_le_bytes());
                expected.extend_from_slice(&frame(&[7]));
                assert_eq!(wire, expected);
                assert_eq!(
                    TransportHintV1::decode_from_slice(&wire).unwrap(),
                    (hint, wire.len())
                );
                for end in 0..wire.len() {
                    assert!(TransportHintV1::decode_from_slice(&wire[..end]).is_err());
                }
                let mut trailing = wire.clone();
                trailing.push(9);
                assert_eq!(
                    TransportHintV1::decode_from_slice(&trailing).unwrap(),
                    (hint, wire.len())
                );
                assert!(
                    norito::core::decode_field_canonical::<TransportHintV1>(&trailing).is_err()
                );
                for protocol_body in [vec![1, 0, 0], vec![1, 0, 0, 0, 0], vec![254, 0, 0, 0]] {
                    let mut malformed = frame(&protocol_body);
                    malformed.extend_from_slice(&frame(&[7]));
                    assert!(TransportHintV1::decode_from_slice(&malformed).is_err());
                }
                for priority_body in [Vec::new(), vec![7, 9]] {
                    let mut malformed = frame(&tag.to_le_bytes());
                    malformed.extend_from_slice(&frame(&priority_body));
                    assert!(TransportHintV1::decode_from_slice(&malformed).is_err());
                }
            }
        }
    }
    fn sample_advert(now: u64) -> ProviderAdvertV1 {
        let issued_at = now;
        let expires_at = now + REFRESH_RECOMMENDATION_SECS * 2;
        ProviderAdvertV1 {
            version: PROVIDER_ADVERT_VERSION_V1,
            network_id: [0xA1; 32],
            issued_at,
            expires_at,
            body: ProviderAdvertBodyV1 {
                provider_id: [0u8; 32],
                profile_id: "sorafs.sf1@1.0.0".to_owned(),
                profile_aliases: Some(vec!["sorafs.sf1@1.0.0".to_owned(), "sorafs-sf1".to_owned()]),
                stake: StakePointer {
                    pool_id: [1u8; 32],
                    stake_amount: XorQuantity::try_from_micro(1_000_000)
                        .expect("fixture stake is representable"),
                },
                qos: QosHints {
                    availability: AvailabilityTier::Hot,
                    max_retrieval_latency_ms: 1_500,
                    max_concurrent_streams: 32,
                },
                capabilities: vec![
                    CapabilityTlv {
                        cap_type: CapabilityType::ToriiGateway,
                        payload: Vec::new(),
                    },
                    CapabilityTlv {
                        cap_type: CapabilityType::ChunkRangeFetch,
                        payload: ProviderCapabilityRangeV1 {
                            max_chunk_span: 32,
                            min_granularity: 8,
                            supports_sparse_offsets: true,
                            requires_alignment: false,
                            supports_merkle_proof: true,
                        }
                        .to_bytes()
                        .expect("encode range capability"),
                    },
                ],
                endpoints: vec![AdvertEndpoint {
                    kind: EndpointKind::Torii,
                    host_pattern: "storage.example.com".to_owned(),
                    metadata: vec![EndpointMetadata {
                        key: EndpointMetadataKey::Region,
                        value: b"global".to_vec(),
                    }],
                }],
                rendezvous_topics: vec![RendezvousTopic {
                    topic: "sorafs.sf1.primary".to_owned(),
                    region: "global".to_owned(),
                }],
                path_policy: PathDiversityPolicy {
                    min_guard_weight: 10,
                    max_same_asn_per_path: 1,
                    max_same_pool_per_path: 1,
                },
                notes: None,
                stream_budget: Some(StreamBudgetV1 {
                    max_in_flight: 8,
                    max_bytes_per_sec: 10_000_000,
                    burst_bytes: Some(5_000_000),
                }),
                transport_hints: Some(vec![TransportHintV1 {
                    protocol: TransportProtocol::ToriiHttpRange,
                    priority: 0,
                }]),
            },
            signature: AdvertSignature {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: vec![7u8; 32],
                signature: vec![9u8; 64],
            },
            signature_strict: true,
            allow_unknown_capabilities: false,
        }
    }
    pub(super) fn signed_sample_advert(now: u64) -> ProviderAdvertV1 {
        let mut advert = sample_advert(now);
        let signing_key = SigningKey::from_bytes(&[0xA5; 32]);
        advert.signature = AdvertSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
            signature: vec![0; SIGNATURE_LENGTH],
        };
        let payload = advert
            .signature_payload_bytes()
            .expect("encode advert signature envelope");
        advert.signature.signature = signing_key.sign(&payload).to_bytes().to_vec();
        advert
    }
    #[test]
    fn advert_roundtrip() {
        let advert = sample_advert(1_700_000_000);
        advert.body.validate().unwrap();
        advert.validate_with_body(1_700_000_000).unwrap();
        let bytes = norito::to_bytes(&advert).expect("serialize advert");
        let decoded = decode_provider_advert_v1(&bytes).expect("decode bounded canonical advert");
        assert_eq!(decoded, advert);
        let compressed = crate::canonical_test_support::with_compression_tag(&advert);
        assert!(decode_provider_advert_v1(&compressed).is_err());
        assert!(
            decode_provider_advert_v1(&vec![0; PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1 + 1])
                .is_err()
        );
    }
    #[test]
    fn advert_size_and_signature_preflight_accept_boundaries_and_reject_one_over() {
        let now = 1_700_000_000;
        let advert = sample_advert(now);
        let exact = norito::core::encoded_payload_len(&advert)
            .expect("provider advert canonical length must be countable");
        assert_eq!(preflight_provider_advert_len(&advert, exact), Ok(exact));
        assert_eq!(
            preflight_provider_advert_len(&advert, exact.saturating_sub(1)),
            Err(AdvertValidationError::AdvertTooLarge {
                found: exact,
                maximum: exact.saturating_sub(1),
            })
        );
        let mut unsupported = advert.clone();
        unsupported.signature.algorithm = SignatureAlgorithm::MultiSig;
        assert_eq!(
            unsupported.validate(now),
            Err(AdvertValidationError::UnsupportedSignatureAlgorithm {
                algorithm: SignatureAlgorithm::MultiSig,
            })
        );
        let mut bad_key = advert.clone();
        bad_key.signature.public_key.push(7);
        assert_eq!(
            bad_key.validate(now),
            Err(AdvertValidationError::InvalidSignaturePublicKeyLength {
                found: PUBLIC_KEY_LENGTH + 1,
                expected: PUBLIC_KEY_LENGTH,
            })
        );
        let mut oversized = advert;
        oversized.body.notes = Some("x".repeat(PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1));
        assert!(matches!(
            oversized.validate(now),
            Err(AdvertValidationError::AdvertTooLarge {
                maximum: PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1,
                ..
            })
        ));
        assert!(matches!(
            oversized.signature_payload_bytes(),
            Err(AdvertSignatureError::EnvelopeEncoding(reason))
                if reason.contains("maximum")
        ));
    }
    #[test]
    fn borrowed_advert_signature_view_is_byte_exact_for_every_layout() {
        let advert = sample_advert(1_700_000_000);
        let owned = advert.signature_payload();
        let borrowed = ProviderAdvertSignaturePayloadViewV1::from(&advert);
        assert_eq!(
            norito::schema::identity::frame_hash::<ProviderAdvertSignaturePayloadViewV1<'_>>(),
            norito::schema::identity::frame_hash::<ProviderAdvertSignaturePayloadV1>()
        );
        let owned_frame =
            norito::encode_canonical(&owned).expect("encode owned signature envelope");
        assert_eq!(
            norito::to_bytes(&borrowed).expect("encode borrowed signature envelope"),
            owned_frame
        );
        let mut expected_domain_separated = PROVIDER_ADVERT_SIGNATURE_DOMAIN_V1.to_vec();
        expected_domain_separated.extend_from_slice(&owned_frame);
        assert_eq!(
            advert
                .signature_payload_bytes()
                .expect("encode domain-separated borrowed signature envelope"),
            expected_domain_separated
        );
        for flags in supported_layouts() {
            let owned_bytes = encode_bare_with_flags(&owned, flags);
            let borrowed_bytes = encode_bare_with_flags(&borrowed, flags);
            assert_eq!(
                borrowed_bytes, owned_bytes,
                "borrowed provider-advert signing bytes changed for flags 0x{flags:02x}"
            );
            let _guard = norito::core::DecodeFlagsGuard::enter(flags);
            assert_eq!(
                borrowed.encoded_len_exact(),
                owned.encoded_len_exact(),
                "borrowed provider-advert signing size changed for flags 0x{flags:02x}"
            );
            assert_eq!(
                norito::core::encoded_payload_len(&borrowed)
                    .expect("borrowed provider advert length must be countable"),
                borrowed_bytes.len()
            );
            let owned_frame = encode_frame_with_flags(&owned, flags);
            assert_eq!(
                encode_frame_with_flags(&borrowed, flags),
                owned_frame,
                "borrowed provider-advert canonical frame or layout flags changed for flags 0x{flags:02x}"
            );
            assert_eq!(
                advert
                    .signature_payload_bytes()
                    .expect("encode borrowed provider-advert signing payload"),
                expected_domain_separated,
                "provider-advert signature payload changed for flags 0x{flags:02x}"
            );
        }
    }
    #[test]
    fn advert_body_collection_boundaries_are_deterministic() {
        let mut body = sample_advert(1_700_000_000).body;
        let aliases = body.profile_aliases.as_mut().expect("sample aliases");
        for index in aliases.len()..PROVIDER_ADVERT_PROFILE_ALIASES_MAX_V1 {
            aliases.push(format!("alias-{index:02}"));
        }
        while body.capabilities.len() < PROVIDER_ADVERT_CAPABILITIES_MAX_V1 {
            body.capabilities.push(CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            });
        }
        let endpoint = body.endpoints[0].clone();
        body.endpoints = vec![endpoint; PROVIDER_ADVERT_ENDPOINTS_MAX_V1];
        body.rendezvous_topics = (0..PROVIDER_ADVERT_RENDEZVOUS_TOPICS_MAX_V1)
            .map(|index| RendezvousTopic {
                topic: format!("sorafs.boundary.{index:02}"),
                region: "global".to_owned(),
            })
            .collect();
        body.notes = Some("x".repeat(PROVIDER_ADVERT_NOTES_MAX_BYTES_V1));
        assert!(body.validate().is_ok());
        let mut too_many_aliases = body.clone();
        too_many_aliases
            .profile_aliases
            .as_mut()
            .expect("aliases")
            .push("overflow".to_owned());
        assert_eq!(
            too_many_aliases.validate(),
            Err(AdvertValidationError::TooManyProfileAliases {
                found: PROVIDER_ADVERT_PROFILE_ALIASES_MAX_V1 + 1,
                maximum: PROVIDER_ADVERT_PROFILE_ALIASES_MAX_V1,
            })
        );
        let mut too_many_capabilities = body.clone();
        too_many_capabilities.capabilities.push(CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        });
        assert_eq!(
            too_many_capabilities.validate(),
            Err(AdvertValidationError::TooManyCapabilities {
                found: PROVIDER_ADVERT_CAPABILITIES_MAX_V1 + 1,
                maximum: PROVIDER_ADVERT_CAPABILITIES_MAX_V1,
            })
        );
        let mut too_many_endpoints = body.clone();
        too_many_endpoints
            .endpoints
            .push(too_many_endpoints.endpoints[0].clone());
        assert_eq!(
            too_many_endpoints.validate(),
            Err(AdvertValidationError::TooManyEndpoints {
                found: PROVIDER_ADVERT_ENDPOINTS_MAX_V1 + 1,
                maximum: PROVIDER_ADVERT_ENDPOINTS_MAX_V1,
            })
        );
        let mut too_many_topics = body;
        too_many_topics.rendezvous_topics.push(RendezvousTopic {
            topic: "overflow".to_owned(),
            region: "global".to_owned(),
        });
        assert_eq!(
            too_many_topics.validate(),
            Err(AdvertValidationError::TooManyRendezvousTopics {
                found: PROVIDER_ADVERT_RENDEZVOUS_TOPICS_MAX_V1 + 1,
                maximum: PROVIDER_ADVERT_RENDEZVOUS_TOPICS_MAX_V1,
            })
        );
    }
    #[test]
    fn advert_body_byte_aggregates_accept_boundaries_and_reject_one_over() {
        let mut body = sample_advert(1_700_000_000).body;
        let mut capability_boundary = body.clone();
        capability_boundary.stream_budget = None;
        capability_boundary.transport_hints = None;
        capability_boundary.capabilities = (0..4)
            .map(|_| CapabilityTlv {
                cap_type: CapabilityType::VendorReserved,
                payload: vec![1; PROVIDER_ADVERT_CAPABILITY_PAYLOAD_MAX_BYTES_V1],
            })
            .collect();
        assert_eq!(
            capability_boundary
                .capabilities
                .iter()
                .map(|capability| capability.payload.len())
                .sum::<usize>(),
            PROVIDER_ADVERT_CAPABILITY_PAYLOAD_TOTAL_MAX_BYTES_V1
        );
        capability_boundary
            .validate()
            .expect("exact capability aggregate boundary validates");
        let mut capability_advert = sample_advert(1_700_000_000);
        capability_advert.body = capability_boundary.clone();
        let capability_bytes = norito::encode_canonical(&capability_advert).unwrap();
        let decoded = decode_provider_advert_v1(&capability_bytes).unwrap();
        assert_eq!(decoded, capability_advert);
        decoded
            .body
            .validate()
            .expect("maximum aggregate survives bounded decode");
        capability_boundary.capabilities.push(CapabilityTlv {
            cap_type: CapabilityType::VendorReserved,
            payload: vec![1],
        });
        assert_eq!(
            capability_boundary.validate(),
            Err(AdvertValidationError::CapabilityPayloadAggregateTooLarge {
                found: PROVIDER_ADVERT_CAPABILITY_PAYLOAD_TOTAL_MAX_BYTES_V1 + 1,
                maximum: PROVIDER_ADVERT_CAPABILITY_PAYLOAD_TOTAL_MAX_BYTES_V1,
            })
        );
        capability_advert.body = capability_boundary;
        let decoded =
            decode_provider_advert_v1(&norito::encode_canonical(&capability_advert).unwrap())
                .unwrap();
        assert_eq!(
            decoded.body.validate(),
            Err(AdvertValidationError::CapabilityPayloadAggregateTooLarge {
                found: PROVIDER_ADVERT_CAPABILITY_PAYLOAD_TOTAL_MAX_BYTES_V1 + 1,
                maximum: PROVIDER_ADVERT_CAPABILITY_PAYLOAD_TOTAL_MAX_BYTES_V1,
            })
        );
        body.capabilities.push(CapabilityTlv {
            cap_type: CapabilityType::VendorReserved,
            payload: vec![1; PROVIDER_ADVERT_CAPABILITY_PAYLOAD_MAX_BYTES_V1],
        });
        body.endpoints[0].host_pattern = "h".repeat(PROVIDER_ADVERT_ENDPOINT_HOST_MAX_BYTES_V1);
        body.endpoints[0].metadata = vec![
            EndpointMetadata {
                key: EndpointMetadataKey::Region,
                value: vec![1; PROVIDER_ADVERT_ENDPOINT_METADATA_VALUE_MAX_BYTES_V1],
            };
            PROVIDER_ADVERT_ENDPOINT_METADATA_MAX_V1
        ];
        body.rendezvous_topics[0].topic = "t".repeat(PROVIDER_ADVERT_RENDEZVOUS_TOPIC_MAX_BYTES_V1);
        body.rendezvous_topics[0].region =
            "r".repeat(PROVIDER_ADVERT_RENDEZVOUS_REGION_MAX_BYTES_V1);
        assert!(body.validate().is_ok());
        let mut boundary_advert = sample_advert(1_700_000_000);
        boundary_advert.body = body.clone();
        let boundary_bytes = to_bytes(&boundary_advert).expect("encode field-boundary advert");
        assert_eq!(
            decode_provider_advert_v1(&boundary_bytes)
                .expect("bounded decoder accepts the maximum capability field"),
            boundary_advert
        );
        let mut oversized_capability = body.clone();
        oversized_capability
            .capabilities
            .last_mut()
            .expect("vendor capability")
            .payload
            .push(1);
        assert!(matches!(
            oversized_capability.validate(),
            Err(AdvertValidationError::CapabilityPayloadTooLarge {
                maximum: PROVIDER_ADVERT_CAPABILITY_PAYLOAD_MAX_BYTES_V1,
                ..
            })
        ));
        boundary_advert.body = oversized_capability;
        assert!(matches!(
            decode_provider_advert_v1(&norito::encode_canonical(&boundary_advert).unwrap()),
            Err(norito::core::Error::SequenceLengthExceeded { length, limit })
                if length == (PROVIDER_ADVERT_CAPABILITY_PAYLOAD_MAX_BYTES_V1 + 1) as u64
                    && limit == PROVIDER_ADVERT_CAPABILITY_PAYLOAD_MAX_BYTES_V1 as u64
        ));
        let mut oversized_host = body.clone();
        oversized_host.endpoints[0].host_pattern.push('h');
        assert_eq!(
            oversized_host.validate(),
            Err(AdvertValidationError::InvalidEndpointHost {
                index: 0,
                maximum: PROVIDER_ADVERT_ENDPOINT_HOST_MAX_BYTES_V1,
            })
        );
        let mut aggregate_overflow = body.clone();
        aggregate_overflow.endpoints.push(AdvertEndpoint {
            kind: EndpointKind::Torii,
            host_pattern: "extra.example".to_owned(),
            metadata: vec![EndpointMetadata {
                key: EndpointMetadataKey::Region,
                value: vec![1],
            }],
        });
        assert_eq!(
            aggregate_overflow.validate(),
            Err(AdvertValidationError::EndpointMetadataAggregateTooLarge {
                found: PROVIDER_ADVERT_ENDPOINT_METADATA_TOTAL_MAX_BYTES_V1 + 1,
                maximum: PROVIDER_ADVERT_ENDPOINT_METADATA_TOTAL_MAX_BYTES_V1,
            })
        );
        boundary_advert.body = aggregate_overflow;
        let decoded =
            decode_provider_advert_v1(&norito::encode_canonical(&boundary_advert).unwrap())
                .unwrap();
        assert_eq!(
            decoded.body.validate(),
            Err(AdvertValidationError::EndpointMetadataAggregateTooLarge {
                found: PROVIDER_ADVERT_ENDPOINT_METADATA_TOTAL_MAX_BYTES_V1 + 1,
                maximum: PROVIDER_ADVERT_ENDPOINT_METADATA_TOTAL_MAX_BYTES_V1,
            })
        );
        let mut oversized_topic = body.clone();
        oversized_topic.rendezvous_topics[0].topic.push('t');
        assert_eq!(
            oversized_topic.validate(),
            Err(AdvertValidationError::InvalidRendezvousTopic {
                index: 0,
                maximum: PROVIDER_ADVERT_RENDEZVOUS_TOPIC_MAX_BYTES_V1,
            })
        );
        let mut oversized_notes = body;
        oversized_notes.notes = Some("n".repeat(PROVIDER_ADVERT_NOTES_MAX_BYTES_V1 + 1));
        assert_eq!(
            oversized_notes.validate(),
            Err(AdvertValidationError::InvalidNotes {
                maximum: PROVIDER_ADVERT_NOTES_MAX_BYTES_V1,
            })
        );
    }
    #[test]
    fn advert_transport_hint_enum_boundary_is_enforced() {
        let mut body = sample_advert(1_700_000_000).body;
        body.capabilities.push(CapabilityTlv {
            cap_type: CapabilityType::SoraNetHybridPq,
            payload: Vec::new(),
        });
        body.transport_hints = Some(vec![
            TransportHintV1 {
                protocol: TransportProtocol::ToriiHttpRange,
                priority: 0,
            },
            TransportHintV1 {
                protocol: TransportProtocol::QuicStream,
                priority: 1,
            },
            TransportHintV1 {
                protocol: TransportProtocol::SoraNetRelay,
                priority: 2,
            },
            TransportHintV1 {
                protocol: TransportProtocol::VendorReserved,
                priority: 3,
            },
        ]);
        assert!(body.validate().is_ok());
        body.transport_hints
            .as_mut()
            .expect("transport hints")
            .push(TransportHintV1 {
                protocol: TransportProtocol::ToriiHttpRange,
                priority: 4,
            });
        assert_eq!(
            body.validate(),
            Err(AdvertValidationError::TooManyTransportHints {
                found: PROVIDER_ADVERT_TRANSPORT_HINTS_MAX_V1 + 1,
                maximum: PROVIDER_ADVERT_TRANSPORT_HINTS_MAX_V1,
            })
        );
    }
    #[test]
    fn verify_signature_accepts_signed_advert_envelope() {
        let advert = signed_sample_advert(1_700_000_000);
        advert
            .verify_signature()
            .expect("signature should verify over canonical envelope bytes");
    }
    #[test]
    fn verify_signature_rejects_every_tampered_envelope_field() {
        let advert = signed_sample_advert(1_700_000_000);
        let tampered = [
            ("version", {
                let mut value = advert.clone();
                value.version += 1;
                value
            }),
            ("issued_at", {
                let mut value = advert.clone();
                value.issued_at += 1;
                value
            }),
            ("expires_at", {
                let mut value = advert.clone();
                value.expires_at += 1;
                value
            }),
            ("body", {
                let mut value = advert.clone();
                value.body.qos.max_retrieval_latency_ms += 1;
                value
            }),
            ("signature algorithm", {
                let mut value = advert.clone();
                value.signature.algorithm = SignatureAlgorithm::MultiSig;
                value
            }),
            ("signature public key", {
                let mut value = advert.clone();
                value.signature.public_key[0] ^= 1;
                value
            }),
            ("signature bytes", {
                let mut value = advert.clone();
                value.signature.signature[0] ^= 1;
                value
            }),
            ("signature policy", {
                let mut value = advert.clone();
                value.signature_strict = false;
                value
            }),
            ("unknown-capability policy", {
                let mut value = advert.clone();
                value.allow_unknown_capabilities = true;
                value
            }),
        ];
        for (field, value) in tampered {
            assert!(
                value.verify_signature().is_err(),
                "tampering with {field} must invalidate the signature"
            );
        }
    }
    #[test]
    fn verify_signature_rejects_legacy_body_only_signature() {
        let mut advert = sample_advert(1_700_000_000);
        let signing_key = SigningKey::from_bytes(&[0xA5; 32]);
        let body_bytes = norito::to_bytes(&advert.body).expect("encode advert body");
        advert.signature = AdvertSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
            signature: signing_key.sign(&body_bytes).to_bytes().to_vec(),
        };
        assert!(matches!(
            advert.verify_signature(),
            Err(AdvertSignatureError::Verification(_))
        ));
    }
    #[test]
    fn verify_signature_rejects_undomained_envelope_signature() {
        let mut advert = sample_advert(1_700_000_000);
        let signing_key = SigningKey::from_bytes(&[0xA5; 32]);
        advert.signature = AdvertSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
            signature: vec![0; SIGNATURE_LENGTH],
        };
        let envelope_bytes = norito::to_bytes(&advert.signature_payload())
            .expect("encode undomained advert envelope");
        advert.signature.signature = signing_key.sign(&envelope_bytes).to_bytes().to_vec();
        assert!(matches!(
            advert.verify_signature(),
            Err(AdvertSignatureError::Verification(_))
        ));
    }
    #[test]
    fn verify_signature_rejects_all_zero_signature_material() {
        let mut advert = signed_sample_advert(1_700_000_000);
        advert.signature.signature.fill(0);
        let err = advert
            .verify_signature()
            .expect_err("all-zero provider advert signature must be rejected");
        assert!(matches!(
            err,
            AdvertSignatureError::Verification(reason) if reason.contains("all zero")
        ));
    }
    #[test]
    fn verify_signature_rejects_malformed_signature_r() {
        const SMALL_ORDER_R: [u8; PUBLIC_KEY_LENGTH] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const NONCANONICAL_R: [u8; PUBLIC_KEY_LENGTH] = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        for (label, replacement_r, expected) in [
            ("small-order", SMALL_ORDER_R, "small-order"),
            ("noncanonical", NONCANONICAL_R, "not a canonical"),
        ] {
            let mut advert = signed_sample_advert(1_700_000_000);
            advert.signature.signature[..PUBLIC_KEY_LENGTH].copy_from_slice(&replacement_r);
            let err = advert
                .verify_signature()
                .expect_err("malformed provider advert signature R must be rejected");
            assert!(
                matches!(&err, AdvertSignatureError::Verification(reason) if reason.contains(expected)),
                "{label} signature R produced unexpected error: {err}"
            );
        }
    }
    #[test]
    fn verify_signature_rejects_all_zero_public_key_material() {
        let mut advert = signed_sample_advert(1_700_000_000);
        advert.signature.public_key = vec![0; PUBLIC_KEY_LENGTH];
        let err = advert
            .verify_signature()
            .expect_err("all-zero provider advert public key must be rejected");
        assert!(matches!(
            err,
            AdvertSignatureError::InvalidPublicKey(reason) if reason.contains("all zero")
        ));
    }
    #[test]
    fn ttl_enforced() {
        let mut advert = sample_advert(1_700_000_000);
        advert.expires_at = advert.issued_at + MAX_ADVERT_TTL_SECS + 1;
        let err = advert.validate(1_700_000_000).unwrap_err();
        assert!(matches!(
            err,
            AdvertValidationError::TtlOutOfRange { ttl, max } if ttl == MAX_ADVERT_TTL_SECS + 1 && max == MAX_ADVERT_TTL_SECS
        ));
    }
    #[test]
    fn future_issued_advert_is_rejected() {
        let now = 1_700_000_000;
        let advert = sample_advert(now + 1);
        assert_eq!(
            advert.validate(now),
            Err(AdvertValidationError::IssuedInFuture {
                now,
                issued_at: now + 1,
            })
        );
    }
    #[test]
    fn refresh_deadline_tracks_half_ttl() {
        let mut advert = sample_advert(1_700_000_000);
        advert.expires_at = advert.issued_at + 2 * 60 * 60;
        assert_eq!(advert.refresh_deadline(), advert.issued_at + 60 * 60);
        advert.expires_at = advert.issued_at + 3;
        assert_eq!(advert.refresh_deadline(), advert.issued_at + 2);
    }
    #[test]
    fn detects_missing_endpoints() {
        let mut advert = sample_advert(1_700_000_000);
        advert.body.endpoints.clear();
        let err = advert.validate_with_body(1_700_000_000).unwrap_err();
        assert_eq!(err, AdvertValidationError::MissingEndpoints);
    }
    #[test]
    fn qos_validation() {
        let mut advert = sample_advert(1_700_000_000);
        advert.body.qos.max_concurrent_streams = 0;
        let err = advert.body.validate().unwrap_err();
        assert_eq!(err, AdvertValidationError::InvalidQos);
    }
    #[test]
    fn stream_budget_option_roundtrip() {
        let budget = StreamBudgetV1 {
            max_in_flight: 4,
            max_bytes_per_sec: 2_000_000,
            burst_bytes: Some(1_000_000),
        };
        let bytes = to_bytes(&Some(budget)).expect("encode option");
        let decoded: Option<StreamBudgetV1> = decode_from_bytes(&bytes).expect("decode option");
        assert_eq!(decoded, Some(budget));
    }
    #[test]
    fn builder_constructs_advert() {
        let mut builder = ProviderAdvertV1::builder();
        let _ = builder
            .network_id([0xA1; 32])
            .profile_id("sorafs.sf1@1.0.0")
            .profile_aliases(vec!["sorafs.sf1@1.0.0".to_owned(), "sorafs-sf1".to_owned()])
            .provider_id([0u8; 32])
            .stake_pool_id([1u8; 32])
            .stake_amount(
                XorQuantity::try_from_micro(1_000_000).expect("fixture stake is representable"),
            )
            .availability(AvailabilityTier::Hot)
            .max_retrieval_latency_ms(1_500)
            .max_concurrent_streams(32)
            .path_policy_min_guard_weight(5)
            .path_policy_max_same_asn_per_path(2)
            .path_policy_max_same_pool_per_path(2)
            .notes("primary-provider");
        let _ = builder.add_capability(CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        });
        let range_capability = ProviderCapabilityRangeV1 {
            max_chunk_span: 24,
            min_granularity: 8,
            supports_sparse_offsets: true,
            requires_alignment: false,
            supports_merkle_proof: true,
        };
        builder
            .add_range_capability(range_capability)
            .expect("encode range capability");
        let _ = builder.stream_budget(StreamBudgetV1 {
            max_in_flight: 4,
            max_bytes_per_sec: 6_000_000,
            burst_bytes: Some(3_000_000),
        });
        let _ = builder.add_transport_hint(TransportHintV1 {
            protocol: TransportProtocol::ToriiHttpRange,
            priority: 0,
        });
        let _ = builder.add_endpoint(AdvertEndpoint {
            kind: EndpointKind::Torii,
            host_pattern: "storage.example.com".into(),
            metadata: vec![EndpointMetadata {
                key: EndpointMetadataKey::Region,
                value: b"global".to_vec(),
            }],
        });
        let _ = builder.add_topic(RendezvousTopic {
            topic: "sorafs.sf1.primary".into(),
            region: "global".into(),
        });
        let _ = builder
            .signature(SignatureAlgorithm::Ed25519, vec![7u8; 32], vec![9u8; 64])
            .ttl_secs(3600)
            .issued_at(1_700_000_000)
            .allow_unknown_capabilities(true);
        let advert = builder.build().expect("builder constructs advert");
        advert
            .validate_with_body(1_700_000_100)
            .expect("advert validates");
        assert_eq!(advert.body.capabilities.len(), 2);
        let range_payload = advert
            .body
            .capabilities
            .iter()
            .find(|cap| cap.cap_type == CapabilityType::ChunkRangeFetch)
            .expect("range capability present");
        assert_eq!(
            ProviderCapabilityRangeV1::from_bytes(&range_payload.payload).unwrap(),
            range_capability
        );
        assert_eq!(advert.body.endpoints.len(), 1);
        assert_eq!(advert.body.rendezvous_topics.len(), 1);
        assert!(advert.allow_unknown_capabilities);
        assert!(advert.body.stream_budget.is_some());
        assert_eq!(
            advert
                .body
                .transport_hints
                .as_ref()
                .map(|hints| hints.len()),
            Some(1)
        );
    }
    #[test]
    fn stream_budget_validation() {
        let err = StreamBudgetV1 {
            max_in_flight: 0,
            max_bytes_per_sec: 1,
            burst_bytes: None,
        }
        .validate()
        .unwrap_err();
        assert_eq!(err, StreamBudgetError::InvalidMaxInFlight);
        let err = StreamBudgetV1 {
            max_in_flight: 1,
            max_bytes_per_sec: 0,
            burst_bytes: None,
        }
        .validate()
        .unwrap_err();
        assert_eq!(err, StreamBudgetError::InvalidMaxBytesPerSec);
        let err = StreamBudgetV1 {
            max_in_flight: 1,
            max_bytes_per_sec: 32,
            burst_bytes: Some(0),
        }
        .validate()
        .unwrap_err();
        assert_eq!(err, StreamBudgetError::InvalidBurstBytes);
        let err = StreamBudgetV1 {
            max_in_flight: 1,
            max_bytes_per_sec: 32,
            burst_bytes: Some(64),
        }
        .validate()
        .unwrap_err();
        assert_eq!(
            err,
            StreamBudgetError::BurstExceedsRate {
                burst: 64,
                rate: 32
            }
        );
    }
    #[test]
    fn transport_hint_priority_validation() {
        let hint = TransportHintV1 {
            protocol: TransportProtocol::ToriiHttpRange,
            priority: 42,
        };
        let err = hint.validate().unwrap_err();
        assert_eq!(err, TransportHintError::InvalidPriority);
    }
    #[test]
    fn signature_algorithm_json_deserializes_stable_labels() {
        let ed25519: SignatureAlgorithm =
            norito::json::from_slice(br#""ed25519""#).expect("parse ed25519");
        assert_eq!(ed25519, SignatureAlgorithm::Ed25519);
        let multisig: SignatureAlgorithm =
            norito::json::from_slice(br#""multi-sig""#).expect("parse multi-sig");
        assert_eq!(multisig, SignatureAlgorithm::MultiSig);
    }
    #[test]
    fn duplicate_transport_protocol_rejected() {
        let mut advert = sample_advert(1_700_000_000);
        advert.body.transport_hints = Some(vec![
            TransportHintV1 {
                protocol: TransportProtocol::ToriiHttpRange,
                priority: 0,
            },
            TransportHintV1 {
                protocol: TransportProtocol::ToriiHttpRange,
                priority: 1,
            },
        ]);
        let err = advert.body.validate().unwrap_err();
        assert_eq!(err, AdvertValidationError::DuplicateTransportProtocol);
    }
    #[test]
    fn soranet_transport_requires_capability() {
        let mut advert = sample_advert(1_700_000_000);
        advert.body.transport_hints = Some(vec![TransportHintV1 {
            protocol: TransportProtocol::SoraNetRelay,
            priority: 0,
        }]);
        let err = advert.body.validate().unwrap_err();
        assert_eq!(
            err,
            AdvertValidationError::SoranetTransportWithoutCapability
        );
    }
    #[test]
    fn soranet_transport_accepts_matching_capability() {
        let mut advert = sample_advert(1_700_000_000);
        advert.body.transport_hints = Some(vec![TransportHintV1 {
            protocol: TransportProtocol::SoraNetRelay,
            priority: 0,
        }]);
        let pq_payload = ProviderCapabilitySoranetPqV1 {
            supports_guard: true,
            supports_majority: false,
            supports_strict: false,
        }
        .to_bytes()
        .expect("encode soranet_pq");
        advert.body.capabilities.push(CapabilityTlv {
            cap_type: CapabilityType::SoraNetHybridPq,
            payload: pq_payload,
        });
        advert.body.validate().unwrap();
    }
    #[test]
    fn invalid_range_capability_rejected() {
        let mut advert = sample_advert(1_700_000_000);
        let mut payload = Vec::with_capacity(9);
        payload.extend_from_slice(&8u32.to_le_bytes());
        payload.extend_from_slice(&16u32.to_le_bytes());
        payload.push(0);
        advert.body.capabilities = vec![CapabilityTlv {
            cap_type: CapabilityType::ChunkRangeFetch,
            payload,
        }];
        let err = advert.body.validate().unwrap_err();
        assert!(matches!(
            err,
            AdvertValidationError::InvalidRangeCapability(
                RangeCapabilityError::GranularityExceedsSpan { .. }
            ) | AdvertValidationError::InvalidRangeCapabilityPayload
        ));
    }
    #[test]
    fn soranet_pq_payload_roundtrip() {
        let pq = ProviderCapabilitySoranetPqV1 {
            supports_guard: true,
            supports_majority: true,
            supports_strict: true,
        };
        let bytes = pq.to_bytes().expect("encode soranet_pq");
        let decoded = ProviderCapabilitySoranetPqV1::from_bytes(&bytes).expect("decode soranet_pq");
        assert_eq!(decoded, pq);
    }
    #[test]
    fn soranet_pq_requires_guard_and_majority() {
        let invalid_guard = ProviderCapabilitySoranetPqV1 {
            supports_guard: false,
            supports_majority: true,
            supports_strict: false,
        };
        let err = invalid_guard.to_bytes().unwrap_err();
        assert_eq!(err, PqCapabilityError::MissingGuardSupport);
        let invalid_strict = ProviderCapabilitySoranetPqV1 {
            supports_guard: true,
            supports_majority: false,
            supports_strict: true,
        };
        let err = invalid_strict.to_bytes().unwrap_err();
        assert_eq!(err, PqCapabilityError::StrictWithoutMajority);
    }
    #[test]
    fn potr_mldsa_capability_requires_a_canonical_mldsa65_key() {
        assert!(matches!(
            validate_potr_mldsa_capability(&[1; 32]),
            Err(PotrMldsaCapabilityError::InvalidLength { .. })
        ));
        let key_len = MlDsaSuite::MlDsa65.public_key_len();
        assert_eq!(
            validate_potr_mldsa_capability(&vec![0; key_len]),
            Err(PotrMldsaCapabilityError::InertKey)
        );
        let key_pair = KeyPair::try_from_seed(vec![0x5A; 32], Algorithm::MlDsa)
            .expect("derive deterministic ML-DSA-65 capability key");
        let (algorithm, public_key) = key_pair
            .public_key()
            .try_to_bytes()
            .expect("encode ML-DSA-65 capability key");
        assert_eq!(algorithm, Algorithm::MlDsa);
        validate_potr_mldsa_capability(public_key).expect("canonical ML-DSA-65 capability key");
    }
    #[test]
    fn stream_budget_without_range_capability_rejected() {
        let mut advert = sample_advert(1_700_000_000);
        advert
            .body
            .capabilities
            .retain(|cap| cap.cap_type != CapabilityType::ChunkRangeFetch);
        let err = advert.body.validate().unwrap_err();
        assert_eq!(err, AdvertValidationError::RangeMetadataWithoutCapability);
    }
    #[test]
    fn transport_hints_without_range_capability_rejected() {
        let mut advert = sample_advert(1_700_000_000);
        advert.body.stream_budget = None;
        advert
            .body
            .capabilities
            .retain(|cap| cap.cap_type != CapabilityType::ChunkRangeFetch);
        let err = advert.body.validate().unwrap_err();
        assert_eq!(err, AdvertValidationError::RangeMetadataWithoutCapability);
    }
    #[test]
    fn empty_transport_hints_rejected() {
        let mut advert = sample_advert(1_700_000_000);
        advert.body.transport_hints = Some(vec![]);
        let err = advert.body.validate().unwrap_err();
        assert_eq!(err, AdvertValidationError::EmptyTransportHints);
    }
}

#[cfg(test)]
include!("provider_advert/captured_owner_identity_tests.rs");

#[cfg(test)]
#[path = "provider_advert/borrowed_payload_tests.rs"]
mod borrowed_payload_tests;

#[cfg(test)]
#[path = "provider_advert/signing_identity_tests.rs"]
pub(crate) mod signing_identity_tests;
