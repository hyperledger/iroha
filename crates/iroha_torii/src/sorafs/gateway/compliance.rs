//! Governed SoraFS gateway-compliance catalog admission and durable promotion.
//!
//! The controller deliberately owns no credentials and performs no ambient DNS or HTTP access. Feed
//! transport and catalog signatures cross explicit runtime boundaries so production embeddings can
//! keep authentication material inside a qualified deployment-owned provider and pin the exact
//! addresses used for each connection. Enabled feed transports attest a stable V1
//! handle, revision, and canonical
//! hostname/SPKI policy digest before checkpoint state is opened and again before and after every
//! feed operation.
use super::provider::{GatewayProviderBindingErrorV1, GatewayProviderBindingV1};
use crate::secure_file_metadata::{self, SecureMetadata};
use blake3::Hasher;
use flate2::read::GzDecoder;
use norito::derive::{JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize};
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
#[cfg(test)]
use sorafs_manifest::gateway_compliance::{
    GATEWAY_COMPLIANCE_ACK_VERSION_V1, GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
    GATEWAY_COMPLIANCE_ROLLBACK_VERSION_V1, GatewayComplianceAcknowledgementPayloadV1,
    GatewayComplianceAppealOverrideV1, GatewayComplianceBaselineRuleV1,
    GatewayComplianceCatalogApprovalV1, GatewayComplianceLegalSafetyHoldV1,
    GatewayComplianceRollbackPayloadV1, GatewayComplianceTrustedSignerV1,
};
#[cfg(any(test, feature = "test-fixtures"))]
use sorafs_manifest::gateway_compliance::{
    GATEWAY_COMPLIANCE_CATALOG_VERSION_V1, GatewayComplianceSourceAnchorV1,
};
use sorafs_manifest::gateway_compliance::{
    GatewayComplianceAcknowledgementV1, GatewayComplianceCatalogPayloadV1,
    GatewayComplianceCatalogV1, GatewayComplianceFeedDocumentV1, GatewayComplianceProtocolError,
    GatewayComplianceRollbackV1, GatewayComplianceSubjectKindV1, GatewayComplianceToggleV1,
    GatewayComplianceTrustPolicyV1, MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1,
    MAX_GATEWAY_COMPLIANCE_ENTRIES_V1, MAX_GATEWAY_COMPLIANCE_SIGNERS_V1, encode_bounded,
    gateway_compliance_feed_transport_policy_digest, normalize_scope, normalize_subject,
    validate_catalog_freshness, validate_catalog_transition, validate_dns_hostname, validate_token,
    verify_rollback,
};
use std::{
    collections::BTreeSet,
    fmt::Debug,
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read, Write as _},
    net::IpAddr,
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering as AtomicOrdering},
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use url::{Host, Url};
/// V1 schema version for durable controller checkpoints.
pub const GATEWAY_COMPLIANCE_CHECKPOINT_VERSION_V1: u8 = 1;
/// Maximum retained gateway acknowledgements for one candidate.
pub const MAX_GATEWAY_COMPLIANCE_ACKS_V1: usize = 128;
/// Maximum durable checkpoint bytes.
pub const MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1: usize = 64 * 1024 * 1024;
/// Maximum bounded controller history records.
pub const MAX_GATEWAY_COMPLIANCE_HISTORY_V1: usize = 4_096;
/// Maximum durable mutation-idempotency records.
pub const MAX_GATEWAY_COMPLIANCE_IDEMPOTENCY_RECORDS_V1: usize = 4_096;
const CHECKPOINT_STORE_GENERATION_DOMAIN_V1: &[u8] =
    b"sorafs-gateway-compliance-checkpoint-store-generation-v1";
#[cfg(test)]
use iroha_config::parameters::defaults::sorafs::gateway::compliance::{
    GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1, GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
};
/// One allowlisted HTTPS host and pinned TLS identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayComplianceFeedHostPolicy {
    /// Canonical lowercase DNS hostname.
    pub hostname: String,
    /// Non-empty set of accepted SHA-256 SPKI digests.
    pub accepted_spki_sha256: BTreeSet<[u8; 32]>,
}
/// Config-derived feed endpoint policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayComplianceFeedPolicy {
    /// Stable feed identity.
    pub feed_id: String,
    /// Exact canonical initial HTTPS URL.
    pub url: String,
    /// Whether catalog construction requires this feed.
    pub required: bool,
    /// Exact redirect host allowlist, including the initial host.
    pub hosts: Vec<GatewayComplianceFeedHostPolicy>,
}
/// Bounded feed-fetch policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayComplianceFetchLimits {
    /// Maximum encoded response bytes.
    pub max_encoded_bytes: usize,
    /// Maximum decoded response bytes.
    ///
    /// The Zstandard history window is capped at the greatest power of two no larger
    /// than this limit, with a 1 KiB minimum window. The exact decoded-byte limit
    /// still applies even when it is below that minimum window.
    pub max_decoded_bytes: usize,
    /// Maximum redirect count.
    pub max_redirects: u8,
    /// Maximum distinct DNS answers.
    pub max_dns_addresses: usize,
    /// Connect timeout given to the injected transport.
    pub connect_timeout: Duration,
    /// Total operation deadline given to the injected transport.
    pub total_timeout: Duration,
}
impl Default for GatewayComplianceFetchLimits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: 4 * 1024 * 1024,
            max_decoded_bytes: 16 * 1024 * 1024,
            max_redirects: 3,
            max_dns_addresses: 8,
            connect_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(20),
        }
    }
}
/// Content encodings admitted from compliance feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayComplianceContentEncoding {
    /// Uncompressed bytes.
    Identity,
    /// Gzip-compressed bytes.
    Gzip,
    /// Zstandard-compressed bytes.
    Zstd,
}
/// Address-pinned request handed to a runtime transport.
#[derive(Debug, Clone)]
pub struct GatewayComplianceFetchRequest {
    /// Exact validated HTTPS URL.
    pub url: Url,
    /// Validated DNS answers the transport must exclusively use.
    pub pinned_addresses: Vec<IpAddr>,
    /// Per-connection timeout.
    pub connect_timeout: Duration,
    /// Overall timeout.
    pub total_timeout: Duration,
    /// Maximum response bytes the transport may buffer.
    pub max_encoded_bytes: usize,
}
/// Address- and trust-bound response returned by a runtime transport.
#[derive(Clone)]
pub struct GatewayComplianceFetchResponse {
    /// HTTP status.
    pub status: u16,
    /// Redirect location for 3xx responses.
    pub redirect_location: Option<String>,
    /// Exact connected peer address.
    pub connected_address: IpAddr,
    /// SHA-256 digest of the authenticated peer SPKI.
    pub peer_spki_sha256: [u8; 32],
    /// Declared content encoding.
    pub content_encoding: GatewayComplianceContentEncoding,
    /// Encoded response bytes.
    pub body: Vec<u8>,
    /// Transport-observed elapsed time.
    pub elapsed: Duration,
}
impl Debug for GatewayComplianceFetchResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayComplianceFetchResponse")
            .field("status", &self.status)
            .field(
                "redirect_location_bytes",
                &self.redirect_location.as_ref().map(String::len),
            )
            .field("connected_address", &self.connected_address)
            .field("peer_spki_sha256", &self.peer_spki_sha256)
            .field("content_encoding", &self.content_encoding)
            .field("body_bytes", &self.body.len())
            .field("elapsed", &self.elapsed)
            .finish()
    }
}
/// Runtime-owned authenticated DNS and HTTPS transport.
pub trait GatewayComplianceFeedTransport: Send + Sync {
    /// Return the provider identity currently serving this runtime boundary.
    ///
    /// Implementations must obtain this identity from the same provider
    /// instance that performs [`Self::resolve`] and [`Self::fetch`]. Provider
    /// diagnostics must remain behind this boundary; callers intentionally see
    /// only the payload-free [`GatewayComplianceFeedTransportProbeError`].
    fn qualification(
        &self,
    ) -> Result<GatewayComplianceFeedTransportIdentityV1, GatewayComplianceFeedTransportProbeError>;
    /// Resolve a DNS hostname using the runtime's pinned resolver.
    fn resolve(
        &self,
        hostname: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>, GatewayComplianceError>;
    /// Fetch through only the supplied pinned addresses, without automatic
    /// redirects or transparent decompression.
    fn fetch(
        &self,
        request: &GatewayComplianceFetchRequest,
    ) -> Result<GatewayComplianceFetchResponse, GatewayComplianceError>;
}
/// Payload-free identity reported by one authenticated feed transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayComplianceFeedTransportIdentityV1 {
    /// Stable adapter contract handle. This is never a credential or URL.
    pub provider_handle: String,
    /// Monotonic deployed adapter revision.
    pub revision: u64,
    /// Domain-separated digest of the exact hostname/SPKI trust inventory.
    pub policy_digest: [u8; 32],
    /// Explicit marker set by test, mock, development, or placeholder adapters.
    pub test_marked: bool,
}
/// Redacted failure returned when a runtime provider cannot attest its identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("gateway compliance feed transport qualification failed")]
pub struct GatewayComplianceFeedTransportProbeError;
/// Controller configuration assembled exclusively from resolved `iroha_config`.
#[derive(Debug, Clone)]
pub struct GatewayComplianceControllerConfig {
    /// Threshold signature and acknowledgement policy.
    pub trust_policy: GatewayComplianceTrustPolicyV1,
    /// Exact regional serving scope for this independently administered gateway.
    pub region_scope: String,
    /// Exact gateway serving scope bound to one active gateway signer identity.
    pub gateway_scope: String,
    /// Configured external feeds in strict feed-id order.
    pub feeds: Vec<GatewayComplianceFeedPolicy>,
    /// Exact independently configured runtime feed-transport provider.
    ///
    /// Production launchers must provide this binding. `None` is reserved for
    /// the test-only controller core, which cannot perform external feed I/O.
    pub feed_transport_provider: Option<GatewayProviderBindingV1>,
    /// Fetch and decompression limits.
    pub fetch_limits: GatewayComplianceFetchLimits,
    /// Maximum accepted future timestamp skew.
    pub max_clock_skew_secs: u64,
    /// Maximum age of any source feed at catalog generation.
    pub max_feed_age_secs: u64,
    /// Maximum catalog validity interval.
    pub max_catalog_validity_secs: u64,
    /// Maximum durable history length.
    pub max_history_entries: usize,
}
impl GatewayComplianceControllerConfig {
    /// Validate bounds, ordering, HTTPS allowlists, and pins.
    pub fn validate(&self) -> Result<(), GatewayComplianceError> {
        self.trust_policy.validate()?;
        if normalize_scope(&self.region_scope).ok().as_deref() != Some(self.region_scope.as_str())
            || !self.region_scope.starts_with("region:")
        {
            return Err(GatewayComplianceError::InvalidPolicy(
                "region_scope must be one canonical region:<id> scope".into(),
            ));
        }
        if normalize_scope(&self.gateway_scope).ok().as_deref() != Some(self.gateway_scope.as_str())
        {
            return Err(GatewayComplianceError::InvalidPolicy(
                "gateway_scope must be one canonical gateway:<id> scope".into(),
            ));
        }
        let gateway_id = self.gateway_scope.strip_prefix("gateway:").ok_or_else(|| {
            GatewayComplianceError::InvalidPolicy(
                "gateway_scope must be one canonical gateway:<id> scope".into(),
            )
        })?;
        if self
            .trust_policy
            .gateway_signers
            .binary_search_by(|signer| signer.signer_id.as_str().cmp(gateway_id))
            .is_err()
            || self
                .trust_policy
                .revoked_gateway_signer_ids
                .binary_search_by(|signer_id| signer_id.as_str().cmp(gateway_id))
                .is_ok()
        {
            return Err(GatewayComplianceError::InvalidPolicy(
                "gateway_scope must name one active configured gateway signer".into(),
            ));
        }
        if self.feeds.len() > MAX_GATEWAY_COMPLIANCE_SIGNERS_V1 {
            return Err(GatewayComplianceError::ResourceLimit {
                resource: "configured feeds",
                found: self.feeds.len(),
                maximum: MAX_GATEWAY_COMPLIANCE_SIGNERS_V1,
            });
        }
        if self.fetch_limits.max_encoded_bytes == 0
            || self.fetch_limits.max_decoded_bytes == 0
            || self.fetch_limits.max_encoded_bytes > MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1
            || self.fetch_limits.max_decoded_bytes > MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1
            || self.fetch_limits.max_redirects > 8
            || self.fetch_limits.max_dns_addresses == 0
            || self.fetch_limits.max_dns_addresses > 32
            || self.fetch_limits.connect_timeout.is_zero()
            || self.fetch_limits.connect_timeout > Duration::from_secs(30)
            || self.fetch_limits.total_timeout < self.fetch_limits.connect_timeout
            || self.fetch_limits.total_timeout > Duration::from_secs(120)
        {
            return Err(GatewayComplianceError::InvalidPolicy(
                "invalid compliance fetch limits".into(),
            ));
        }
        if self.max_history_entries == 0
            || self.max_history_entries > MAX_GATEWAY_COMPLIANCE_HISTORY_V1
            || self.max_clock_skew_secs > 3_600
            || self.max_feed_age_secs == 0
            || self.max_feed_age_secs > 30 * 24 * 60 * 60
            || self.max_catalog_validity_secs == 0
            || self.max_catalog_validity_secs > 30 * 24 * 60 * 60
        {
            return Err(GatewayComplianceError::InvalidPolicy(
                "invalid compliance controller bounds".into(),
            ));
        }
        let mut previous: Option<&str> = None;
        for feed in &self.feeds {
            validate_token(&feed.feed_id, "feed_id")?;
            if previous.is_some_and(|value| value >= feed.feed_id.as_str()) {
                return Err(GatewayComplianceError::NonCanonical(
                    "configured feed order".into(),
                ));
            }
            if feed.hosts.is_empty() {
                return Err(GatewayComplianceError::InvalidPolicy(format!(
                    "feed `{}` has no HTTPS host allowlist",
                    feed.feed_id
                )));
            }
            let mut previous_host: Option<&str> = None;
            for host in &feed.hosts {
                validate_dns_hostname(&host.hostname)?;
                if previous_host.is_some_and(|value| value >= host.hostname.as_str()) {
                    return Err(GatewayComplianceError::NonCanonical(format!(
                        "feed `{}` host allowlist",
                        feed.feed_id
                    )));
                }
                if host.accepted_spki_sha256.is_empty()
                    || host
                        .accepted_spki_sha256
                        .iter()
                        .any(|digest| digest.iter().all(|byte| *byte == 0))
                {
                    return Err(GatewayComplianceError::InvalidPolicy(format!(
                        "feed `{}` host `{}` has no valid trust pin",
                        feed.feed_id, host.hostname
                    )));
                }
                previous_host = Some(&host.hostname);
            }
            validate_feed_url(feed, &feed.url)?;
            previous = Some(&feed.feed_id);
        }
        if let Some(binding) = self.feed_transport_provider.as_ref()
            && binding.policy_digest() != self.feed_transport_policy_digest()?
        {
            return Err(GatewayComplianceError::InvalidPolicy(
                "feed transport provider policy digest does not bind the exact configured hostname/SPKI inventory"
                    .into(),
            ));
        }
        Ok(())
    }
    fn feed(&self, feed_id: &str) -> Option<&GatewayComplianceFeedPolicy> {
        self.feeds
            .binary_search_by(|feed| feed.feed_id.as_str().cmp(feed_id))
            .ok()
            .map(|index| &self.feeds[index])
    }
    fn expected_feed_transport_identity(
        &self,
    ) -> Result<GatewayComplianceFeedTransportIdentityV1, GatewayComplianceError> {
        let binding = self.feed_transport_provider.as_ref().ok_or_else(|| {
            GatewayComplianceError::InvalidPolicy(
                "feed transport provider binding is required for external feed access".into(),
            )
        })?;
        if binding.policy_digest() != self.feed_transport_policy_digest()? {
            return Err(GatewayComplianceError::InvalidPolicy(
                "feed transport provider policy digest does not bind the exact configured hostname/SPKI inventory"
                    .into(),
            ));
        }
        Ok(GatewayComplianceFeedTransportIdentityV1 {
            provider_handle: binding.provider_handle().to_owned(),
            revision: binding.revision(),
            policy_digest: binding.policy_digest(),
            test_marked: false,
        })
    }
    fn feed_transport_policy_digest(&self) -> Result<[u8; 32], GatewayComplianceError> {
        let mut pins_by_hostname = std::collections::BTreeMap::new();
        for feed in &self.feeds {
            for host in &feed.hosts {
                if let Some(existing) = pins_by_hostname
                    .insert(host.hostname.clone(), host.accepted_spki_sha256.clone())
                    && existing != host.accepted_spki_sha256
                {
                    return Err(GatewayComplianceError::InvalidPolicy(
                        "one compliance hostname has conflicting trust inventories".into(),
                    ));
                }
            }
        }
        gateway_compliance_feed_transport_policy_digest(&pins_by_hostname).map_err(Into::into)
    }
}
/// Effective request disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayComplianceDisposition {
    /// Serve unless another gateway policy rejects.
    Allow,
    /// Reject under the selected compliance rule.
    Deny,
}
/// Policy tier that produced an effective decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayComplianceDecisionSource {
    /// No catalog entry matched.
    NoMatch,
    /// Baseline deny rule matched.
    Baseline,
    /// Finalized accepted appeal overrode a baseline deny.
    AcceptedAppeal,
    /// Legal or safety hold took absolute precedence.
    LegalSafetyHold,
}
/// Payload-free deterministic evaluation output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayComplianceDecision {
    /// Effective disposition.
    pub disposition: GatewayComplianceDisposition,
    /// Winning precedence tier.
    pub source: GatewayComplianceDecisionSource,
    /// Winning rule/appeal/hold identity.
    pub reference_id: Option<String>,
    /// Serving catalog digest, when a catalog is active.
    pub catalog_digest: Option<[u8; 32]>,
    /// Monotonic serving-catalog sequence.
    pub catalog_sequence: u64,
    /// Exclusive serving-catalog expiry as a Unix second.
    pub catalog_valid_until_unix: u64,
}
/// Durable promotion or rollback record.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii::sorafs::gateway::compliance::GatewayComplianceHistoryRecordV1"
)]
#[derive(
    Debug, Clone, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize, PartialEq, Eq,
)]
pub struct GatewayComplianceHistoryRecordV1 {
    /// Replay-resistant operation identity.
    pub operation_id: [u8; 32],
    /// Serving catalog before the action, when present.
    pub previous_serving_digest: Option<[u8; 32]>,
    /// Serving catalog after the action.
    pub serving_digest: [u8; 32],
    /// Action Unix second.
    pub recorded_at_unix: u64,
    /// `promotion` or `rollback`.
    pub action: String,
    /// Payload-free reason code.
    pub reason_code: String,
}
/// Exact durable gateway-compliance mutation kind.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::gateway::compliance::GatewayComplianceMutationKindV1")]
#[derive(
    Debug,
    Clone,
    Copy,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[norito(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum GatewayComplianceMutationKindV1 {
    /// Stage a threshold-signed candidate catalog.
    Stage,
    /// Record a signed regional-gateway acknowledgement.
    Acknowledge,
    /// Promote the staged catalog.
    Promote,
    /// Roll back to the last-known-good catalog.
    Rollback,
}
impl GatewayComplianceMutationKindV1 {
    fn history_action(self) -> Option<&'static str> {
        match self {
            Self::Stage | Self::Acknowledge => None,
            Self::Promote => Some("promotion"),
            Self::Rollback => Some("rollback"),
        }
    }
}
/// Cryptographic idempotency binding supplied by the authenticated API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayComplianceMutationBindingV1 {
    /// Digest-form operation key. Raw caller-provided keys are never persisted.
    pub key_digest: [u8; 32],
    /// Digest of the exact canonical method, target, and request bytes.
    pub request_digest: [u8; 32],
}
/// Stable response returned for an initial mutation and every exact replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayComplianceMutationResultV1 {
    /// Catalog affected by the committed mutation.
    pub catalog_digest: [u8; 32],
    /// Unix second at which the initial mutation committed.
    pub recorded_at_unix: u64,
}
/// Durable replay binding for one successful mutation.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii::sorafs::gateway::compliance::GatewayComplianceIdempotencyRecordV1"
)]
#[derive(
    Debug,
    Clone,
    Copy,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    PartialEq,
    Eq,
)]
pub struct GatewayComplianceIdempotencyRecordV1 {
    /// Digest-form operation key.
    pub key_digest: [u8; 32],
    /// Digest of the exact canonical request.
    pub request_digest: [u8; 32],
    /// Mutation performed by the request.
    pub operation: GatewayComplianceMutationKindV1,
    /// Catalog affected by the mutation.
    pub catalog_digest: [u8; 32],
    /// Unix second at which the initial mutation committed.
    pub recorded_at_unix: u64,
}
/// Durable controller state.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::gateway::compliance::GatewayComplianceCheckpointV1")]
#[derive(
    Debug, Clone, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize, PartialEq, Eq,
)]

pub struct GatewayComplianceCheckpointV1 {
    /// Schema version.
    pub version: u8,
    /// Monotonic durable mutation revision. Exact idempotency replays do not advance it.
    pub revision: u64,
    /// Bound trust-policy digest.
    pub policy_digest: [u8; 32],
    /// Most recently promoted predecessor-chain head.
    pub chain_head: Option<GatewayComplianceCatalogV1>,
    /// Catalog currently served by this gateway.
    pub serving: Option<GatewayComplianceCatalogV1>,
    /// Last-known-good catalog available for rollback.
    pub previous_serving: Option<GatewayComplianceCatalogV1>,
    /// Staged candidate awaiting gateway acknowledgements.
    pub candidate: Option<GatewayComplianceCatalogV1>,
    /// Signed acknowledgements for the staged candidate.
    pub acknowledgements: Vec<GatewayComplianceAcknowledgementV1>,
    /// Bounded immutable promotion/rollback history.
    pub history: Vec<GatewayComplianceHistoryRecordV1>,
    /// Bounded immutable exact-request replay registry.
    pub idempotency_records: Vec<GatewayComplianceIdempotencyRecordV1>,
}
impl GatewayComplianceCheckpointV1 {
    fn empty(policy_digest: [u8; 32]) -> Self {
        Self {
            version: GATEWAY_COMPLIANCE_CHECKPOINT_VERSION_V1,
            revision: 0,
            policy_digest,
            chain_head: None,
            serving: None,
            previous_serving: None,
            candidate: None,
            acknowledgements: Vec::new(),
            history: Vec::new(),
            idempotency_records: Vec::new(),
        }
    }
}
/// Opaque generation of the exact durable checkpoint bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayComplianceStoreGeneration {
    /// No checkpoint exists.
    Absent,
    /// Domain-separated digest of the exact checkpoint bytes.
    Present([u8; 32]),
}
/// One exact snapshot loaded under an active checkpoint-store lease.
#[derive(Debug)]
pub struct GatewayComplianceStoreSnapshot {
    /// Opaque exact-byte generation.
    pub generation: GatewayComplianceStoreGeneration,
    /// Exact checkpoint bytes, or `None` when the checkpoint is absent.
    pub bytes: Option<Vec<u8>>,
}
/// Process-lifetime exclusive lease over one durable checkpoint backend.
pub trait GatewayComplianceStoreLease: Debug + Send + Sync {
    /// Load the exact current checkpoint snapshot.
    fn load(&self) -> Result<GatewayComplianceStoreSnapshot, GatewayComplianceError>;
    /// Atomically replace the checkpoint only when its exact generation matches.
    fn compare_and_store(
        &self,
        expected: GatewayComplianceStoreGeneration,
        bytes: &[u8],
    ) -> Result<GatewayComplianceStoreGeneration, GatewayComplianceError>;
}
/// Durable checkpoint backend. A controller must hold its exclusive lease for
/// its complete lifetime.
pub trait GatewayComplianceStore: Debug + Send + Sync {
    /// Acquire the one active process-lifetime lease.
    fn try_acquire(&self) -> Result<Box<dyn GatewayComplianceStoreLease>, GatewayComplianceError>;
}
#[cfg(test)]
#[derive(Debug, Default)]
struct TestGatewayComplianceStore {
    state: Arc<std::sync::Mutex<TestGatewayComplianceStoreState>>,
}
#[cfg(test)]
#[derive(Debug, Default)]
struct TestGatewayComplianceStoreState {
    bytes: Option<Vec<u8>>,
    leased: bool,
}
#[cfg(test)]
#[derive(Debug)]
struct TestGatewayComplianceStoreLease {
    state: Arc<std::sync::Mutex<TestGatewayComplianceStoreState>>,
}
#[cfg(test)]
impl Drop for TestGatewayComplianceStoreLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.leased = false;
        }
    }
}
#[cfg(test)]
impl GatewayComplianceStore for TestGatewayComplianceStore {
    fn try_acquire(&self) -> Result<Box<dyn GatewayComplianceStoreLease>, GatewayComplianceError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayComplianceError::StatePoisoned)?;
        if state.leased {
            return Err(GatewayComplianceError::LeaseHeld);
        }
        state.leased = true;
        drop(state);
        Ok(Box::new(TestGatewayComplianceStoreLease {
            state: Arc::clone(&self.state),
        }))
    }
}
#[cfg(test)]
impl GatewayComplianceStoreLease for TestGatewayComplianceStoreLease {
    fn load(&self) -> Result<GatewayComplianceStoreSnapshot, GatewayComplianceError> {
        let state = self
            .state
            .lock()
            .map_err(|_| GatewayComplianceError::StatePoisoned)?;
        Ok(checkpoint_store_snapshot(state.bytes.clone()))
    }
    fn compare_and_store(
        &self,
        expected: GatewayComplianceStoreGeneration,
        bytes: &[u8],
    ) -> Result<GatewayComplianceStoreGeneration, GatewayComplianceError> {
        if bytes.len() > MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1 {
            return Err(GatewayComplianceError::ResourceLimit {
                resource: "compliance checkpoint bytes",
                found: bytes.len(),
                maximum: MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1,
            });
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayComplianceError::StatePoisoned)?;
        if checkpoint_store_generation(state.bytes.as_deref()) != expected {
            return Err(GatewayComplianceError::CheckpointConflict);
        }
        state.bytes = Some(bytes.to_vec());
        Ok(checkpoint_store_generation(Some(bytes)))
    }
}
/// Filesystem store with an exclusive stable-file lease, exact-byte CAS,
/// no-follow temp creation, fsync, and atomic replacement.
#[derive(Debug, Clone)]
pub struct FileGatewayComplianceStore {
    path: PathBuf,
    max_bytes: usize,
    #[cfg(test)]
    test_hook: Arc<FileGatewayComplianceStoreTestHook>,
}
#[cfg(test)]
#[derive(Debug, Default)]
struct FileGatewayComplianceStoreTestHook {
    before_persist_replacement: std::sync::Mutex<Option<Vec<u8>>>,
}
impl FileGatewayComplianceStore {
    /// Construct an absolute-path store. The parent directory must be provisioned ahead of startup,
    /// must not traverse symlinks, and must not be group- or world-writable.
    pub fn new(path: PathBuf) -> Result<Self, GatewayComplianceError> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(GatewayComplianceError::Persistence(
                "compliance checkpoint path must be an absolute file path".into(),
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            GatewayComplianceError::Persistence("compliance checkpoint path has no parent".into())
        })?;
        validate_checkpoint_parent(parent)?;
        Ok(Self {
            path,
            max_bytes: MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1,
            #[cfg(test)]
            test_hook: Arc::new(FileGatewayComplianceStoreTestHook::default()),
        })
    }
    #[cfg(test)]
    fn replace_before_next_persist(&self, bytes: Vec<u8>) {
        *self
            .test_hook
            .before_persist_replacement
            .lock()
            .expect("file checkpoint test hook lock") = Some(bytes);
    }
}
#[derive(Debug)]
struct FileGatewayComplianceStoreLease {
    path: PathBuf,
    max_bytes: usize,
    _lock_file: File,
    #[cfg(test)]
    test_hook: Arc<FileGatewayComplianceStoreTestHook>,
}
impl GatewayComplianceStore for FileGatewayComplianceStore {
    fn try_acquire(&self) -> Result<Box<dyn GatewayComplianceStoreLease>, GatewayComplianceError> {
        let parent = self.path.parent().ok_or_else(|| {
            GatewayComplianceError::Persistence("compliance checkpoint path has no parent".into())
        })?;
        validate_checkpoint_parent(parent)?;
        let lock_path = checkpoint_lock_path(&self.path)?;
        let before_open = validate_output_file(&lock_path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        set_no_follow(&mut options);
        set_lock_share_mode(&mut options);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o640);
        }
        let lock_file = options
            .open(&lock_path)
            .map_err(|error| persistence_io("open checkpoint lease file", error))?;
        let (opened_before_lock, named_before_lock) = validate_opened_file(
            &lock_path,
            &lock_file,
            "checkpoint lease file changed while opening",
        )?;
        if before_open
            .as_ref()
            .is_some_and(|metadata| !secure_file_metadata::same_file(metadata, &opened_before_lock))
        {
            return Err(GatewayComplianceError::Persistence(
                "checkpoint lease file changed between inspection and open".into(),
            ));
        }
        match lock_file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(GatewayComplianceError::LeaseHeld);
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(persistence_io("lock checkpoint lease file", error));
            }
        }
        let (opened_after_lock, named_after_lock) = validate_opened_file(
            &lock_path,
            &lock_file,
            "checkpoint lease file changed after locking",
        )?;
        if !secure_file_metadata::same_file(&opened_before_lock, &opened_after_lock)
            || !secure_file_metadata::same_file(&named_before_lock, &named_after_lock)
            || !secure_file_metadata::same_file(&opened_after_lock, &named_after_lock)
        {
            return Err(GatewayComplianceError::Persistence(
                "checkpoint lease ownership changed while locking".into(),
            ));
        }
        Ok(Box::new(FileGatewayComplianceStoreLease {
            path: self.path.clone(),
            max_bytes: self.max_bytes,
            _lock_file: lock_file,
            #[cfg(test)]
            test_hook: Arc::clone(&self.test_hook),
        }))
    }
}
impl GatewayComplianceStoreLease for FileGatewayComplianceStoreLease {
    fn load(&self) -> Result<GatewayComplianceStoreSnapshot, GatewayComplianceError> {
        read_checkpoint_snapshot(&self.path, self.max_bytes)
    }
    fn compare_and_store(
        &self,
        expected: GatewayComplianceStoreGeneration,
        bytes: &[u8],
    ) -> Result<GatewayComplianceStoreGeneration, GatewayComplianceError> {
        if bytes.len() > self.max_bytes {
            return Err(GatewayComplianceError::ResourceLimit {
                resource: "compliance checkpoint bytes",
                found: bytes.len(),
                maximum: self.max_bytes,
            });
        }
        let parent = self.path.parent().ok_or_else(|| {
            GatewayComplianceError::Persistence("compliance checkpoint path has no parent".into())
        })?;
        let current_generation = read_checkpoint_snapshot(&self.path, self.max_bytes)?.generation;
        if current_generation != expected {
            return Err(GatewayComplianceError::CheckpointConflict);
        }
        validate_checkpoint_parent(parent)?;
        let _output_before_prepare = validate_output_file(&self.path)?;
        let filename = self.path.file_name().ok_or_else(|| {
            GatewayComplianceError::Persistence("compliance checkpoint path has no filename".into())
        })?;
        let mut prefix = std::ffi::OsString::from(".");
        prefix.push(filename);
        prefix.push(".tmp-");
        let mut temporary_builder = tempfile::Builder::new();
        temporary_builder.prefix(&prefix);
        let mut temporary = temporary_builder
            .make_in(parent, |temporary_path| {
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                set_no_follow(&mut options);
                set_checkpoint_temp_share_mode(&mut options);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.mode(0o640);
                }
                options.open(temporary_path)
            })
            .map_err(|error| persistence_io("create checkpoint temp file", error))?;
        let temporary_metadata = secure_file_metadata::from_file(temporary.as_file())
            .map_err(|error| persistence_io("inspect checkpoint temp file", error))?;
        let named_temporary_metadata = secure_file_metadata::from_path(temporary.path())
            .map_err(|error| persistence_io("inspect checkpoint temp path", error))?;
        validate_checkpoint_file_metadata(&temporary_metadata)?;
        validate_checkpoint_file_metadata(&named_temporary_metadata)?;
        if !secure_file_metadata::same_file(&temporary_metadata, &named_temporary_metadata) {
            return Err(GatewayComplianceError::Persistence(
                "compliance checkpoint temp changed identity while opening".into(),
            ));
        }
        temporary
            .write_all(bytes)
            .map_err(|error| persistence_io("write checkpoint temp file", error))?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| persistence_io("fsync checkpoint temp file", error))?;
        let written_temporary_metadata = secure_file_metadata::from_file(temporary.as_file())
            .map_err(|error| persistence_io("re-inspect checkpoint temp file", error))?;
        let named_written_temporary_metadata = secure_file_metadata::from_path(temporary.path())
            .map_err(|error| persistence_io("re-inspect checkpoint temp path", error))?;
        validate_checkpoint_file_metadata(&written_temporary_metadata)?;
        validate_checkpoint_file_metadata(&named_written_temporary_metadata)?;
        let expected_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if !secure_file_metadata::same_file(&temporary_metadata, &written_temporary_metadata)
            || !secure_file_metadata::same_file(
                &written_temporary_metadata,
                &named_written_temporary_metadata,
            )
            || written_temporary_metadata.len() != expected_length
            || named_written_temporary_metadata.len() != expected_length
        {
            return Err(GatewayComplianceError::Persistence(
                "compliance checkpoint temp changed while writing".into(),
            ));
        }
        validate_checkpoint_parent(parent)?;
        let _output_before_compare = validate_output_file(&self.path)?;
        #[cfg(test)]
        if let Some(replacement) = self
            .test_hook
            .before_persist_replacement
            .lock()
            .map_err(|_| GatewayComplianceError::StatePoisoned)?
            .take()
        {
            fs::write(&self.path, replacement)
                .map_err(|error| persistence_io("run checkpoint test hook", error))?;
        }
        let current_generation = read_checkpoint_snapshot(&self.path, self.max_bytes)?.generation;
        if current_generation != expected {
            return Err(GatewayComplianceError::CheckpointConflict);
        }
        // The stable lease serializes compliant writers. Standard filesystem
        // APIs do not provide an atomic compare-bytes-and-rename operation, so
        // a non-cooperating same-user writer can still race this final check
        // and be overwritten. Post-replacement exact-byte verification catches
        // interference that changes the final durable result, but cannot
        // observe an intervening value overwritten by the rename.
        let persisted = temporary
            .persist(&self.path)
            .map_err(|error| persistence_io("replace checkpoint", error.error))?;
        let persisted_metadata = secure_file_metadata::from_file(&persisted)
            .map_err(|_| GatewayComplianceError::CheckpointConflict)?;
        let path_metadata = secure_file_metadata::from_path(&self.path)
            .map_err(|_| GatewayComplianceError::CheckpointConflict)?;
        if validate_checkpoint_file_metadata(&persisted_metadata).is_err()
            || validate_checkpoint_file_metadata(&path_metadata).is_err()
            || !secure_file_metadata::same_file(&persisted_metadata, &path_metadata)
            || persisted_metadata.len() != expected_length
            || path_metadata.len() != expected_length
        {
            return Err(GatewayComplianceError::CheckpointConflict);
        }
        crate::durable_fs::sync_direct_directory(parent)
            .map_err(|_| GatewayComplianceError::CheckpointConflict)?;
        let durable_path_metadata = secure_file_metadata::from_path(&self.path)
            .map_err(|_| GatewayComplianceError::CheckpointConflict)?;
        if validate_checkpoint_file_metadata(&durable_path_metadata).is_err()
            || !secure_file_metadata::unchanged(&path_metadata, &durable_path_metadata)
            || durable_path_metadata.len() != expected_length
        {
            return Err(GatewayComplianceError::CheckpointConflict);
        }
        // Release every write-capable clone before reopening the durable file. On Windows the
        // stable reader deliberately denies write sharing, so it must not overlap this writer.
        drop(persisted_metadata);
        drop(persisted);
        drop(written_temporary_metadata);
        drop(temporary_metadata);
        let generation = checkpoint_store_generation(Some(bytes));
        let durable = read_checkpoint_snapshot(&self.path, self.max_bytes)
            .map_err(|_| GatewayComplianceError::CheckpointConflict)?;
        if durable.generation != generation || durable.bytes.as_deref() != Some(bytes) {
            return Err(GatewayComplianceError::CheckpointConflict);
        }
        Ok(generation)
    }
}
#[derive(Debug, Clone)]
struct GatewayComplianceControllerState {
    checkpoint: GatewayComplianceCheckpointV1,
    generation: GatewayComplianceStoreGeneration,
}
impl std::ops::Deref for GatewayComplianceControllerState {
    type Target = GatewayComplianceCheckpointV1;
    fn deref(&self) -> &Self::Target {
        &self.checkpoint
    }
}
impl std::ops::DerefMut for GatewayComplianceControllerState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.checkpoint
    }
}
/// Thread-safe governed compliance controller.
#[derive(Debug)]
pub struct GatewayComplianceController {
    config: GatewayComplianceControllerConfig,
    expected_feed_transport_identity: Option<GatewayComplianceFeedTransportIdentityV1>,
    lease: Box<dyn GatewayComplianceStoreLease>,
    state: RwLock<GatewayComplianceControllerState>,
    fenced: AtomicBool,
}
impl GatewayComplianceController {
    /// Load or initialize a controller without enabling external feed access.
    ///
    /// Production launchers must use [`Self::new_with_feed_transport`]. This private constructor
    /// exists for controller-core tests and for the test-only allow-all policy;
    /// [`Self::fetch_feed`] fails closed when no transport identity was bound at construction.
    #[cfg(test)]
    fn new(
        config: GatewayComplianceControllerConfig,
        store: Arc<dyn GatewayComplianceStore>,
    ) -> Result<Self, GatewayComplianceError> {
        Self::new_inner(config, store, None)
    }
    /// Qualify an authenticated feed transport before opening durable state,
    /// then load or initialize the controller.
    ///
    /// # Errors
    ///
    /// Returns an error when controller policy is invalid, provider identity
    /// does not exactly match it, the provider is unavailable or test-marked,
    /// or the durable checkpoint cannot be acquired and validated.
    pub fn new_with_feed_transport(
        config: GatewayComplianceControllerConfig,
        store: Arc<dyn GatewayComplianceStore>,
        transport: &dyn GatewayComplianceFeedTransport,
    ) -> Result<Self, GatewayComplianceError> {
        config.validate()?;
        let expected_feed_transport_identity = config.expected_feed_transport_identity()?;
        qualify_feed_transport(&expected_feed_transport_identity, transport)?;
        Self::new_inner(config, store, Some(expected_feed_transport_identity))
    }
    fn new_inner(
        config: GatewayComplianceControllerConfig,
        store: Arc<dyn GatewayComplianceStore>,
        expected_feed_transport_identity: Option<GatewayComplianceFeedTransportIdentityV1>,
    ) -> Result<Self, GatewayComplianceError> {
        config.validate()?;
        let policy_digest = config.trust_policy.canonical_digest()?;
        let lease = store.try_acquire()?;
        let snapshot = lease.load()?;
        let checkpoint = match snapshot.bytes {
            Some(bytes) => decode_checkpoint(&bytes)?,
            None => GatewayComplianceCheckpointV1::empty(policy_digest),
        };
        validate_checkpoint(&checkpoint, &config, 1)?;
        Ok(Self {
            config,
            expected_feed_transport_identity,
            lease,
            state: RwLock::new(GatewayComplianceControllerState {
                checkpoint,
                generation: snapshot.generation,
            }),
            fenced: AtomicBool::new(false),
        })
    }
    /// Fetch, pin, decompress, decode, and normalize one configured feed.
    pub fn fetch_feed(
        &self,
        feed_id: &str,
        transport: &dyn GatewayComplianceFeedTransport,
    ) -> Result<GatewayComplianceFeedDocumentV1, GatewayComplianceError> {
        let expected = self
            .expected_feed_transport_identity
            .as_ref()
            .ok_or(GatewayComplianceError::FeedTransportNotQualified)?;
        qualify_feed_transport(expected, transport)?;
        let feed = self
            .config
            .feed(feed_id)
            .ok_or_else(|| GatewayComplianceError::UnknownFeed(feed_id.to_owned()))?;
        let bytes = fetch_feed_bytes(feed, self.config.fetch_limits, expected, transport)?;
        // Discard even fully bounded/authenticated response bytes if the
        // runtime provider rotated or was substituted during network I/O.
        qualify_feed_transport(expected, transport)?;
        let document: GatewayComplianceFeedDocumentV1 =
            norito::json::from_slice(&bytes).map_err(|error| {
                GatewayComplianceError::InvalidFeed(format!("invalid canonical feed JSON: {error}"))
            })?;
        if document.feed_id != feed.feed_id {
            return Err(GatewayComplianceError::InvalidFeed(
                "feed identity does not match configured endpoint".into(),
            ));
        }
        document.normalize().map_err(Into::into)
    }
    /// Deterministically merge normalized feeds into an unsigned catalog.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn build_catalog_payload(
        &self,
        sequence: u64,
        predecessor_digest: Option<[u8; 32]>,
        generated_at_unix: u64,
        valid_until_unix: u64,
        feeds: &[GatewayComplianceFeedDocumentV1],
    ) -> Result<GatewayComplianceCatalogPayloadV1, GatewayComplianceError> {
        let mut seen = BTreeSet::new();
        let mut anchors = Vec::with_capacity(feeds.len());
        let mut baseline_rules = Vec::new();
        let mut appeal_overrides = Vec::new();
        let mut legal_safety_holds = Vec::new();
        let mut toggles = Vec::new();
        for feed in feeds {
            let normalized = feed.clone().normalize()?;
            if normalized != *feed {
                return Err(GatewayComplianceError::NonCanonical(format!(
                    "feed `{}`",
                    feed.feed_id
                )));
            }
            if self.config.feed(&feed.feed_id).is_none() {
                return Err(GatewayComplianceError::UnknownFeed(feed.feed_id.clone()));
            }
            if !seen.insert(feed.feed_id.clone()) {
                return Err(GatewayComplianceError::InvalidFeed(format!(
                    "duplicate feed `{}`",
                    feed.feed_id
                )));
            }
            anchors.push(GatewayComplianceSourceAnchorV1 {
                feed_id: feed.feed_id.clone(),
                feed_digest: feed.canonical_digest()?,
                generated_at_unix: feed.generated_at_unix,
            });
            baseline_rules.extend(feed.baseline_rules.clone());
            appeal_overrides.extend(feed.appeal_overrides.clone());
            legal_safety_holds.extend(feed.legal_safety_holds.clone());
            toggles.extend(feed.toggles.clone());
        }
        for configured in &self.config.feeds {
            if configured.required && !seen.contains(&configured.feed_id) {
                return Err(GatewayComplianceError::MissingRequiredFeed(
                    configured.feed_id.clone(),
                ));
            }
        }
        let payload = GatewayComplianceCatalogPayloadV1 {
            version: GATEWAY_COMPLIANCE_CATALOG_VERSION_V1,
            sequence,
            predecessor_digest,
            policy_digest: self.config.trust_policy.canonical_digest()?,
            generated_at_unix,
            valid_until_unix,
            source_anchors: anchors,
            baseline_rules,
            appeal_overrides,
            legal_safety_holds,
            toggles,
        }
        .normalize()?;
        validate_catalog_against_config(&payload, &self.config)?;
        Ok(payload)
    }
    /// Durably stage a threshold-signed candidate under an exact request binding. Exact replays
    /// return the original durable result even after a later promotion; same-key substitution and
    /// same-sequence equivocation are rejected.
    pub fn stage_catalog(
        &self,
        catalog: GatewayComplianceCatalogV1,
        observed_at_unix: u64,
        binding: GatewayComplianceMutationBindingV1,
    ) -> Result<GatewayComplianceMutationResultV1, GatewayComplianceError> {
        let mut guard = self.write_state()?;
        if let Some(result) =
            replay_mutation(&guard, GatewayComplianceMutationKindV1::Stage, binding)?
        {
            return Ok(result);
        }
        validate_new_mutation(&guard, binding, observed_at_unix)?;
        let digest = catalog.verify(
            &self.config.trust_policy,
            observed_at_unix,
            self.config.max_clock_skew_secs,
        )?;
        validate_catalog_against_config(&catalog.payload, &self.config)?;
        validate_catalog_transition(guard.chain_head.as_ref(), &catalog)?;
        let mut replace_candidate = true;
        if let Some(candidate) = guard.candidate.as_ref() {
            let existing = candidate.payload.catalog_digest()?;
            if existing == digest {
                replace_candidate = false;
            }
            if existing != digest && candidate.payload.sequence == catalog.payload.sequence {
                return Err(GatewayComplianceError::CatalogEquivocation {
                    sequence: catalog.payload.sequence,
                });
            }
        }
        let mut next = guard.clone();
        if replace_candidate {
            next.candidate = Some(catalog);
            next.acknowledgements.clear();
        }
        append_mutation_record(
            &mut next,
            GatewayComplianceMutationKindV1::Stage,
            binding,
            digest,
            observed_at_unix,
        );
        self.commit(&mut guard, next)?;
        Ok(GatewayComplianceMutationResultV1 {
            catalog_digest: digest,
            recorded_at_unix: observed_at_unix,
        })
    }
    /// Durably record one signed gateway acknowledgement under an exact request binding.
    ///
    /// A freshly signed observation may replace the same gateway's retained acknowledgement only
    /// when its vote and catalog are unchanged and its signed timestamp strictly increases. This
    /// retains one vote per gateway; promotion still verifies the original catalog lifetime and
    /// current acknowledgement quorum. Exact request replays never replace a newer observation.
    pub fn acknowledge(
        &self,
        acknowledgement: GatewayComplianceAcknowledgementV1,
        observed_at_unix: u64,
        binding: GatewayComplianceMutationBindingV1,
    ) -> Result<GatewayComplianceMutationResultV1, GatewayComplianceError> {
        let mut guard = self.write_state()?;
        if let Some(result) = replay_mutation(
            &guard,
            GatewayComplianceMutationKindV1::Acknowledge,
            binding,
        )? {
            return Ok(result);
        }
        validate_new_mutation(&guard, binding, observed_at_unix)?;
        let candidate = guard
            .candidate
            .as_ref()
            .ok_or(GatewayComplianceError::NoStagedCatalog)?;
        let digest = candidate.payload.catalog_digest()?;
        acknowledgement.verify(
            &self.config.trust_policy,
            digest,
            observed_at_unix,
            self.config.max_clock_skew_secs,
        )?;
        let existing_index = guard
            .acknowledgements
            .iter()
            .position(|entry| entry.payload.gateway_id == acknowledgement.payload.gateway_id);
        if let Some(index) = existing_index {
            let existing = &guard.acknowledgements[index];
            if existing != &acknowledgement {
                let original = &existing.payload;
                let incoming = &acknowledgement.payload;
                // The normal verifier above authenticates this new observation, including current
                // trust, revocation and freshness. A reload refresh cannot change the prior vote.
                if incoming.version != original.version
                    || incoming.gateway_id != original.gateway_id
                    || incoming.catalog_digest != original.catalog_digest
                    || incoming.accepted != original.accepted
                    || incoming.rejection_code != original.rejection_code
                    || incoming.observed_at_unix <= original.observed_at_unix
                {
                    return Err(GatewayComplianceError::GatewayEquivocation(
                        incoming.gateway_id.clone(),
                    ));
                }
            }
        } else if guard.acknowledgements.len() >= MAX_GATEWAY_COMPLIANCE_ACKS_V1 {
            return Err(GatewayComplianceError::ResourceLimit {
                resource: "gateway acknowledgements",
                found: guard.acknowledgements.len().saturating_add(1),
                maximum: MAX_GATEWAY_COMPLIANCE_ACKS_V1,
            });
        }
        let mut next = guard.clone();
        if let Some(index) = existing_index {
            next.acknowledgements[index] = acknowledgement;
        } else {
            next.acknowledgements.push(acknowledgement);
            next.acknowledgements
                .sort_by(|left, right| left.payload.gateway_id.cmp(&right.payload.gateway_id));
        }
        append_mutation_record(
            &mut next,
            GatewayComplianceMutationKindV1::Acknowledge,
            binding,
            digest,
            observed_at_unix,
        );
        self.commit(&mut guard, next)?;
        Ok(GatewayComplianceMutationResultV1 {
            catalog_digest: digest,
            recorded_at_unix: observed_at_unix,
        })
    }
    /// Promote the exact expected staged catalog after the configured regional-gateway quorum.
    pub fn promote(
        &self,
        expected_catalog_digest: [u8; 32],
        expected_sequence: u64,
        observed_at_unix: u64,
        binding: GatewayComplianceMutationBindingV1,
    ) -> Result<GatewayComplianceMutationResultV1, GatewayComplianceError> {
        let mut guard = self.write_state()?;
        if let Some(result) =
            replay_mutation(&guard, GatewayComplianceMutationKindV1::Promote, binding)?
        {
            return Ok(result);
        }
        validate_new_mutation(&guard, binding, observed_at_unix)?;
        let candidate = guard
            .candidate
            .as_ref()
            .ok_or(GatewayComplianceError::NoStagedCatalog)?;
        let digest = candidate.verify(
            &self.config.trust_policy,
            observed_at_unix,
            self.config.max_clock_skew_secs,
        )?;
        validate_catalog_against_config(&candidate.payload, &self.config)?;
        validate_catalog_transition(guard.chain_head.as_ref(), candidate)?;
        if digest != expected_catalog_digest || candidate.payload.sequence != expected_sequence {
            return Err(GatewayComplianceError::PromotionTargetMismatch);
        }
        let mut accepted = 0;
        for acknowledgement in &guard.acknowledgements {
            if !acknowledgement.payload.accepted {
                continue;
            }
            acknowledgement.verify(
                &self.config.trust_policy,
                digest,
                observed_at_unix,
                self.config.max_clock_skew_secs,
            )?;
            accepted += 1;
        }
        if accepted < usize::from(self.config.trust_policy.gateway_ack_threshold) {
            return Err(GatewayComplianceError::GatewayQuorumNotMet {
                found: accepted,
                required: self.config.trust_policy.gateway_ack_threshold,
            });
        }
        if guard.history.len() >= self.config.max_history_entries {
            return Err(GatewayComplianceError::HistoryFull);
        }
        let previous_digest = guard
            .serving
            .as_ref()
            .map(|catalog| catalog.payload.catalog_digest())
            .transpose()?;
        let mut next = guard.clone();
        let promoted = next
            .candidate
            .take()
            .ok_or(GatewayComplianceError::NoStagedCatalog)?;
        next.previous_serving = next.serving.take();
        next.serving = Some(promoted.clone());
        next.chain_head = Some(promoted);
        next.acknowledgements.clear();
        next.history.push(GatewayComplianceHistoryRecordV1 {
            operation_id: binding.key_digest,
            previous_serving_digest: previous_digest,
            serving_digest: digest,
            recorded_at_unix: observed_at_unix,
            action: "promotion".into(),
            reason_code: "gateway-quorum".into(),
        });
        append_mutation_record(
            &mut next,
            GatewayComplianceMutationKindV1::Promote,
            binding,
            digest,
            observed_at_unix,
        );
        self.commit(&mut guard, next)?;
        Ok(GatewayComplianceMutationResultV1 {
            catalog_digest: digest,
            recorded_at_unix: observed_at_unix,
        })
    }
    /// Roll the serving pointer back to the last-known-good catalog while
    /// preserving the promoted predecessor-chain head.
    pub fn rollback(
        &self,
        authorization: &GatewayComplianceRollbackV1,
        observed_at_unix: u64,
        binding: GatewayComplianceMutationBindingV1,
    ) -> Result<GatewayComplianceMutationResultV1, GatewayComplianceError> {
        if binding.key_digest != authorization.payload.operation_id {
            return Err(GatewayComplianceError::IdempotencyConflict);
        }
        let mut guard = self.write_state()?;
        if let Some(result) =
            replay_mutation(&guard, GatewayComplianceMutationKindV1::Rollback, binding)?
        {
            return Ok(result);
        }
        validate_new_mutation(&guard, binding, observed_at_unix)?;
        verify_rollback(
            authorization,
            &self.config.trust_policy,
            observed_at_unix,
            self.config.max_clock_skew_secs,
        )?;
        let current = guard
            .serving
            .as_ref()
            .ok_or(GatewayComplianceError::NoServingCatalog)?;
        let previous = guard
            .previous_serving
            .as_ref()
            .ok_or(GatewayComplianceError::NoLastKnownGood)?;
        let current_digest = current.payload.catalog_digest()?;
        let previous_digest = previous.payload.catalog_digest()?;
        if authorization.payload.from_catalog_digest != current_digest
            || authorization.payload.to_catalog_digest != previous_digest
        {
            return Err(GatewayComplianceError::RollbackTargetMismatch);
        }
        previous.verify(
            &self.config.trust_policy,
            observed_at_unix,
            self.config.max_clock_skew_secs,
        )?;
        validate_catalog_against_config(&previous.payload, &self.config)?;
        if guard.history.len() >= self.config.max_history_entries {
            return Err(GatewayComplianceError::HistoryFull);
        }
        let mut next = guard.clone();
        let old_serving = next
            .serving
            .take()
            .ok_or(GatewayComplianceError::NoServingCatalog)?;
        let restored = next
            .previous_serving
            .take()
            .ok_or(GatewayComplianceError::NoLastKnownGood)?;
        next.serving = Some(restored);
        next.previous_serving = Some(old_serving);
        next.history.push(GatewayComplianceHistoryRecordV1 {
            operation_id: authorization.payload.operation_id,
            previous_serving_digest: Some(current_digest),
            serving_digest: previous_digest,
            recorded_at_unix: observed_at_unix,
            action: "rollback".into(),
            reason_code: authorization.payload.reason_code.clone(),
        });
        append_mutation_record(
            &mut next,
            GatewayComplianceMutationKindV1::Rollback,
            binding,
            previous_digest,
            observed_at_unix,
        );
        self.commit(&mut guard, next)?;
        Ok(GatewayComplianceMutationResultV1 {
            catalog_digest: previous_digest,
            recorded_at_unix: observed_at_unix,
        })
    }
    /// Evaluate the active catalog with mandatory precedence:
    /// legal/safety hold, accepted appeal, then baseline policy.
    pub fn evaluate(
        &self,
        scope: &str,
        subject_kind: GatewayComplianceSubjectKindV1,
        subject: &str,
        observed_at_unix: u64,
    ) -> Result<GatewayComplianceDecision, GatewayComplianceError> {
        let scope = normalize_scope(scope)?;
        self.evaluate_scopes(&[scope.as_str()], subject_kind, subject, observed_at_unix)
    }
    /// Evaluate the complete serving scope for this gateway while preserving
    /// precedence across global, regional, and gateway-specific records.
    pub fn evaluate_serving(
        &self,
        subject_kind: GatewayComplianceSubjectKindV1,
        subject: &str,
        observed_at_unix: u64,
    ) -> Result<GatewayComplianceDecision, GatewayComplianceError> {
        self.evaluate_scopes(
            &[
                self.config.region_scope.as_str(),
                self.config.gateway_scope.as_str(),
            ],
            subject_kind,
            subject,
            observed_at_unix,
        )
    }
    fn evaluate_scopes(
        &self,
        scopes: &[&str],
        subject_kind: GatewayComplianceSubjectKindV1,
        subject: &str,
        observed_at_unix: u64,
    ) -> Result<GatewayComplianceDecision, GatewayComplianceError> {
        let subject = normalize_subject(subject_kind, subject)?;
        let guard = self.read_state()?;
        let catalog = guard
            .serving
            .as_ref()
            .ok_or(GatewayComplianceError::NoServingCatalog)?;
        let catalog_digest = catalog.payload.catalog_digest()?;
        validate_catalog_freshness(
            &catalog.payload,
            observed_at_unix,
            self.config.max_clock_skew_secs,
        )?;
        if let Some(hold) = catalog.payload.legal_safety_holds.iter().find(|hold| {
            scopes_match(&hold.scope, scopes)
                && hold.subject_kind == subject_kind
                && hold.subject == subject
                && active_interval(
                    hold.effective_from_unix,
                    hold.expires_at_unix,
                    observed_at_unix,
                )
        }) {
            return Ok(GatewayComplianceDecision {
                disposition: GatewayComplianceDisposition::Deny,
                source: GatewayComplianceDecisionSource::LegalSafetyHold,
                reference_id: Some(hold.hold_id.clone()),
                catalog_digest: Some(catalog_digest),
                catalog_sequence: catalog.payload.sequence,
                catalog_valid_until_unix: catalog.payload.valid_until_unix,
            });
        }
        if let Some(appeal) = catalog.payload.appeal_overrides.iter().find(|appeal| {
            scopes_match(&appeal.scope, scopes)
                && appeal.subject_kind == subject_kind
                && appeal.subject == subject
                && active_interval(
                    appeal.effective_from_unix,
                    Some(appeal.expires_at_unix),
                    observed_at_unix,
                )
        }) {
            return Ok(GatewayComplianceDecision {
                disposition: GatewayComplianceDisposition::Allow,
                source: GatewayComplianceDecisionSource::AcceptedAppeal,
                reference_id: Some(appeal.appeal_id.clone()),
                catalog_digest: Some(catalog_digest),
                catalog_sequence: catalog.payload.sequence,
                catalog_valid_until_unix: catalog.payload.valid_until_unix,
            });
        }
        if let Some(rule) = catalog.payload.baseline_rules.iter().find(|rule| {
            scopes_match(&rule.scope, scopes)
                && rule.subject_kind == subject_kind
                && rule.subject == subject
                && active_interval(
                    rule.effective_from_unix,
                    rule.expires_at_unix,
                    observed_at_unix,
                )
                && rule.toggle_id.as_ref().is_none_or(|toggle_id| {
                    toggle_enabled(
                        &catalog.payload.toggles,
                        toggle_id,
                        &rule.scope,
                        observed_at_unix,
                    )
                })
        }) {
            return Ok(GatewayComplianceDecision {
                disposition: GatewayComplianceDisposition::Deny,
                source: GatewayComplianceDecisionSource::Baseline,
                reference_id: Some(rule.rule_id.clone()),
                catalog_digest: Some(catalog_digest),
                catalog_sequence: catalog.payload.sequence,
                catalog_valid_until_unix: catalog.payload.valid_until_unix,
            });
        }
        Ok(GatewayComplianceDecision {
            disposition: GatewayComplianceDisposition::Allow,
            source: GatewayComplianceDecisionSource::NoMatch,
            reference_id: None,
            catalog_digest: Some(catalog_digest),
            catalog_sequence: catalog.payload.sequence,
            catalog_valid_until_unix: catalog.payload.valid_until_unix,
        })
    }
    /// Return a payload-safe state snapshot for authenticated control/read APIs.
    pub fn checkpoint(&self) -> Result<GatewayComplianceCheckpointV1, GatewayComplianceError> {
        Ok(self.read_state()?.checkpoint.clone())
    }
    fn read_state(
        &self,
    ) -> Result<RwLockReadGuard<'_, GatewayComplianceControllerState>, GatewayComplianceError> {
        if self.fenced.load(AtomicOrdering::Acquire) {
            return Err(GatewayComplianceError::CheckpointConflict);
        }
        let guard = self.state.read();
        if self.fenced.load(AtomicOrdering::Acquire) {
            return Err(GatewayComplianceError::CheckpointConflict);
        }
        Ok(guard)
    }
    fn write_state(
        &self,
    ) -> Result<RwLockWriteGuard<'_, GatewayComplianceControllerState>, GatewayComplianceError>
    {
        if self.fenced.load(AtomicOrdering::Acquire) {
            return Err(GatewayComplianceError::CheckpointConflict);
        }
        let guard = self.state.write();
        if self.fenced.load(AtomicOrdering::Acquire) {
            return Err(GatewayComplianceError::CheckpointConflict);
        }
        Ok(guard)
    }
    fn commit(
        &self,
        guard: &mut RwLockWriteGuard<'_, GatewayComplianceControllerState>,
        mut next: GatewayComplianceControllerState,
    ) -> Result<(), GatewayComplianceError> {
        next.checkpoint.revision = guard.checkpoint.revision.checked_add(1).ok_or_else(|| {
            GatewayComplianceError::InvalidCheckpoint("checkpoint revision overflow".into())
        })?;
        validate_checkpoint(&next.checkpoint, &self.config, 1)?;
        let bytes = encode_bounded(&next.checkpoint, MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1)?;
        next.generation = match self.lease.compare_and_store(guard.generation, &bytes) {
            Ok(generation) => generation,
            Err(GatewayComplianceError::CheckpointConflict) => {
                self.fenced.store(true, AtomicOrdering::Release);
                return Err(GatewayComplianceError::CheckpointConflict);
            }
            Err(error) => return Err(error),
        };
        **guard = next;
        Ok(())
    }
}
fn validate_mutation_binding(
    binding: GatewayComplianceMutationBindingV1,
) -> Result<(), GatewayComplianceError> {
    if binding.key_digest.iter().all(|byte| *byte == 0)
        || binding.request_digest.iter().all(|byte| *byte == 0)
    {
        return Err(GatewayComplianceError::IdempotencyConflict);
    }
    Ok(())
}
fn replay_mutation(
    checkpoint: &GatewayComplianceCheckpointV1,
    operation: GatewayComplianceMutationKindV1,
    binding: GatewayComplianceMutationBindingV1,
) -> Result<Option<GatewayComplianceMutationResultV1>, GatewayComplianceError> {
    validate_mutation_binding(binding)?;
    let Some(record) = checkpoint
        .idempotency_records
        .iter()
        .find(|record| record.key_digest == binding.key_digest)
    else {
        return Ok(None);
    };
    if record.operation != operation || record.request_digest != binding.request_digest {
        return Err(GatewayComplianceError::IdempotencyConflict);
    }
    Ok(Some(GatewayComplianceMutationResultV1 {
        catalog_digest: record.catalog_digest,
        recorded_at_unix: record.recorded_at_unix,
    }))
}
fn validate_new_mutation(
    checkpoint: &GatewayComplianceCheckpointV1,
    binding: GatewayComplianceMutationBindingV1,
    observed_at_unix: u64,
) -> Result<(), GatewayComplianceError> {
    validate_mutation_binding(binding)?;
    if checkpoint.idempotency_records.len() >= MAX_GATEWAY_COMPLIANCE_IDEMPOTENCY_RECORDS_V1 {
        return Err(GatewayComplianceError::IdempotencyRegistryFull);
    }
    if observed_at_unix == 0
        || checkpoint
            .idempotency_records
            .last()
            .is_some_and(|record| observed_at_unix < record.recorded_at_unix)
    {
        return Err(GatewayComplianceError::MutationTimeInvalid);
    }
    Ok(())
}
fn append_mutation_record(
    checkpoint: &mut GatewayComplianceCheckpointV1,
    operation: GatewayComplianceMutationKindV1,
    binding: GatewayComplianceMutationBindingV1,
    catalog_digest: [u8; 32],
    recorded_at_unix: u64,
) {
    checkpoint
        .idempotency_records
        .push(GatewayComplianceIdempotencyRecordV1 {
            key_digest: binding.key_digest,
            request_digest: binding.request_digest,
            operation,
            catalog_digest,
            recorded_at_unix,
        });
}
/// Build a fresh governed empty catalog for Torii request tests.
#[cfg(test)]
pub(crate) fn allow_all_gateway_compliance_controller_for_tests() -> Arc<GatewayComplianceController>
{
    use ed25519_dalek::{Signer as _, SigningKey};
    let catalog_key = SigningKey::from_bytes(&[0xC1; 32]);
    let gateway_key = SigningKey::from_bytes(&[0xD2; 32]);
    let trust_policy = GatewayComplianceTrustPolicyV1 {
        policy_id: [0xE3; 32],
        catalog_threshold: 1,
        catalog_signers: vec![GatewayComplianceTrustedSignerV1 {
            signer_id: "catalog-test".into(),
            public_key: catalog_key.verifying_key().to_bytes(),
        }],
        revoked_catalog_signer_ids: Vec::new(),
        gateway_ack_threshold: 1,
        gateway_signers: vec![GatewayComplianceTrustedSignerV1 {
            signer_id: "gateway-test".into(),
            public_key: gateway_key.verifying_key().to_bytes(),
        }],
        revoked_gateway_signer_ids: Vec::new(),
    };
    let config = GatewayComplianceControllerConfig {
        trust_policy: trust_policy.clone(),
        region_scope: "region:test".into(),
        gateway_scope: "gateway:gateway-test".into(),
        feeds: Vec::new(),
        feed_transport_provider: None,
        fetch_limits: GatewayComplianceFetchLimits::default(),
        max_clock_skew_secs: 300,
        max_feed_age_secs: 3_600,
        max_catalog_validity_secs: 86_400,
        max_history_entries: 16,
    };
    let observed_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock must follow the Unix epoch")
        .as_secs()
        .max(1);
    let payload = GatewayComplianceCatalogPayloadV1 {
        version: GATEWAY_COMPLIANCE_CATALOG_VERSION_V1,
        sequence: 1,
        predecessor_digest: None,
        policy_digest: trust_policy
            .canonical_digest()
            .expect("test trust policy must be canonical"),
        generated_at_unix: observed_at_unix,
        valid_until_unix: observed_at_unix.saturating_add(86_400),
        source_anchors: Vec::new(),
        baseline_rules: Vec::new(),
        appeal_overrides: Vec::new(),
        legal_safety_holds: Vec::new(),
        toggles: Vec::new(),
    };
    let signing_digest = payload
        .signing_digest()
        .expect("test catalog must be canonical");
    let catalog = GatewayComplianceCatalogV1 {
        payload,
        approvals: vec![GatewayComplianceCatalogApprovalV1 {
            version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
            signer_id: "catalog-test".into(),
            signature: catalog_key.sign(&signing_digest).to_bytes(),
        }],
    };
    let controller = Arc::new(
        GatewayComplianceController::new(config, Arc::new(TestGatewayComplianceStore::default()))
            .expect("test compliance controller must initialize"),
    );
    let catalog_digest = controller
        .stage_catalog(
            catalog,
            observed_at_unix,
            GatewayComplianceMutationBindingV1 {
                key_digest: [0x01; 32],
                request_digest: [0x81; 32],
            },
        )
        .expect("test catalog must stage")
        .catalog_digest;
    let acknowledgement_payload = GatewayComplianceAcknowledgementPayloadV1 {
        version: GATEWAY_COMPLIANCE_ACK_VERSION_V1,
        gateway_id: "gateway-test".into(),
        catalog_digest,
        observed_at_unix,
        accepted: true,
        rejection_code: None,
    };
    let acknowledgement_digest = acknowledgement_payload
        .signing_digest()
        .expect("test acknowledgement must encode");
    controller
        .acknowledge(
            GatewayComplianceAcknowledgementV1 {
                payload: acknowledgement_payload,
                signature: gateway_key.sign(&acknowledgement_digest).to_bytes(),
            },
            observed_at_unix,
            GatewayComplianceMutationBindingV1 {
                key_digest: [0x02; 32],
                request_digest: [0x82; 32],
            },
        )
        .expect("test acknowledgement must commit");
    controller
        .promote(
            catalog_digest,
            1,
            observed_at_unix,
            GatewayComplianceMutationBindingV1 {
                key_digest: [0x03; 32],
                request_digest: [0x83; 32],
            },
        )
        .expect("test catalog must promote");
    controller
}
fn validate_catalog_against_config(
    payload: &GatewayComplianceCatalogPayloadV1,
    config: &GatewayComplianceControllerConfig,
) -> Result<(), GatewayComplianceError> {
    let maximum_valid_until = payload
        .generated_at_unix
        .checked_add(config.max_catalog_validity_secs)
        .ok_or(GatewayComplianceError::TimeOverflow)?;
    if payload.valid_until_unix > maximum_valid_until {
        return Err(GatewayComplianceError::InvalidCatalog(
            "catalog validity exceeds the configured maximum".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    for anchor in &payload.source_anchors {
        if config.feed(&anchor.feed_id).is_none() {
            return Err(GatewayComplianceError::UnknownFeed(anchor.feed_id.clone()));
        }
        if !seen.insert(anchor.feed_id.clone()) {
            return Err(GatewayComplianceError::InvalidCatalog(format!(
                "duplicate source feed `{}`",
                anchor.feed_id
            )));
        }
        if anchor.generated_at_unix
            > payload
                .generated_at_unix
                .saturating_add(config.max_clock_skew_secs)
            || anchor
                .generated_at_unix
                .saturating_add(config.max_feed_age_secs)
                < payload.generated_at_unix
        {
            return Err(GatewayComplianceError::InvalidCatalog(format!(
                "source feed `{}` is stale or future-dated",
                anchor.feed_id
            )));
        }
    }
    for feed in &config.feeds {
        if feed.required && !seen.contains(&feed.feed_id) {
            return Err(GatewayComplianceError::MissingRequiredFeed(
                feed.feed_id.clone(),
            ));
        }
    }
    Ok(())
}
fn validate_checkpoint(
    checkpoint: &GatewayComplianceCheckpointV1,
    config: &GatewayComplianceControllerConfig,
    observed_at_unix: u64,
) -> Result<(), GatewayComplianceError> {
    if checkpoint.version != GATEWAY_COMPLIANCE_CHECKPOINT_VERSION_V1 {
        return Err(GatewayComplianceError::InvalidCheckpoint(
            "unsupported checkpoint version".into(),
        ));
    }
    let durable_mutation_count =
        u64::try_from(checkpoint.idempotency_records.len()).map_err(|_| {
            GatewayComplianceError::InvalidCheckpoint(
                "checkpoint mutation inventory length overflow".into(),
            )
        })?;
    if checkpoint.revision != durable_mutation_count {
        return Err(GatewayComplianceError::InvalidCheckpoint(
            "checkpoint revision must equal its durable mutation inventory length".into(),
        ));
    }
    if checkpoint.policy_digest != config.trust_policy.canonical_digest()? {
        return Err(GatewayComplianceError::PolicyDigestMismatch);
    }
    if checkpoint.history.len() > config.max_history_entries
        || checkpoint.acknowledgements.len() > MAX_GATEWAY_COMPLIANCE_ACKS_V1
        || checkpoint.idempotency_records.len() > MAX_GATEWAY_COMPLIANCE_IDEMPOTENCY_RECORDS_V1
    {
        return Err(GatewayComplianceError::InvalidCheckpoint(
            "checkpoint inventory exceeds configured bounds".into(),
        ));
    }
    for catalog in [
        checkpoint.chain_head.as_ref(),
        checkpoint.serving.as_ref(),
        checkpoint.previous_serving.as_ref(),
        checkpoint.candidate.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        catalog.verify(
            &config.trust_policy,
            catalog.payload.generated_at_unix,
            config.max_clock_skew_secs,
        )?;
        if catalog.payload.policy_digest != checkpoint.policy_digest {
            return Err(GatewayComplianceError::PolicyDigestMismatch);
        }
        validate_catalog_against_config(&catalog.payload, config)?;
    }
    let chain_head_digest = checkpoint
        .chain_head
        .as_ref()
        .map(|catalog| catalog.payload.catalog_digest())
        .transpose()?;
    let serving_digest = checkpoint
        .serving
        .as_ref()
        .map(|catalog| catalog.payload.catalog_digest())
        .transpose()?;
    let previous_serving_digest = checkpoint
        .previous_serving
        .as_ref()
        .map(|catalog| catalog.payload.catalog_digest())
        .transpose()?;
    match (
        checkpoint.chain_head.as_ref(),
        checkpoint.serving.as_ref(),
        checkpoint.previous_serving.as_ref(),
    ) {
        (None, None, None) => {}
        (Some(_), Some(_), previous) => {
            if ![serving_digest, previous_serving_digest]
                .into_iter()
                .flatten()
                .any(|digest| Some(digest) == chain_head_digest)
            {
                return Err(GatewayComplianceError::InvalidCheckpoint(
                    "chain head is not one of the retained serving catalogs".into(),
                ));
            }
            if let Some(previous) = previous {
                let serving = checkpoint.serving.as_ref().expect("matched Some serving");
                if serving_digest == previous_serving_digest {
                    return Err(GatewayComplianceError::InvalidCheckpoint(
                        "serving and previous_serving catalogs must be distinct".into(),
                    ));
                }
                let (older, newer) = if serving.payload.sequence < previous.payload.sequence {
                    (serving, previous)
                } else {
                    (previous, serving)
                };
                if older.payload.sequence.checked_add(1) == Some(newer.payload.sequence) {
                    validate_catalog_transition(Some(older), newer).map_err(|_| {
                        GatewayComplianceError::InvalidCheckpoint(
                            "adjacent retained catalogs break predecessor lineage".into(),
                        )
                    })?;
                } else if chain_head_digest != serving_digest
                    || older.payload.sequence >= newer.payload.sequence
                {
                    return Err(GatewayComplianceError::InvalidCheckpoint(
                        "non-adjacent retained catalogs are inconsistent with a promotion after rollback"
                            .into(),
                    ));
                }
            }
        }
        _ => {
            return Err(GatewayComplianceError::InvalidCheckpoint(
                "chain_head, serving, and previous_serving topology is inconsistent".into(),
            ));
        }
    }
    if let Some(candidate) = checkpoint.candidate.as_ref() {
        validate_catalog_transition(checkpoint.chain_head.as_ref(), candidate)?;
        let digest = candidate.payload.catalog_digest()?;
        let mut previous_gateway: Option<&str> = None;
        for ack in &checkpoint.acknowledgements {
            if previous_gateway.is_some_and(|value| value >= ack.payload.gateway_id.as_str()) {
                return Err(GatewayComplianceError::InvalidCheckpoint(
                    "acknowledgements are not strictly ordered".into(),
                ));
            }
            ack.verify(
                &config.trust_policy,
                digest,
                observed_at_unix.max(ack.payload.observed_at_unix),
                config.max_clock_skew_secs,
            )?;
            previous_gateway = Some(&ack.payload.gateway_id);
        }
    } else if !checkpoint.acknowledgements.is_empty() {
        return Err(GatewayComplianceError::InvalidCheckpoint(
            "acknowledgements exist without a candidate".into(),
        ));
    }
    let mut operation_ids = BTreeSet::new();
    let mut active_history_digest = None;
    let mut last_promotion_digest = None;
    let mut previous_recorded_at = 0;
    for record in &checkpoint.history {
        if record.operation_id.iter().all(|byte| *byte == 0)
            || record.serving_digest.iter().all(|byte| *byte == 0)
            || !operation_ids.insert(record.operation_id)
        {
            return Err(GatewayComplianceError::InvalidCheckpoint(
                "history contains zero digests or duplicate operation ids".into(),
            ));
        }
        validate_token(&record.action, "history action")?;
        validate_token(&record.reason_code, "history reason_code")?;
        if record.recorded_at_unix == 0 || record.recorded_at_unix < previous_recorded_at {
            return Err(GatewayComplianceError::InvalidCheckpoint(
                "history timestamps must be non-zero and monotonic".into(),
            ));
        }
        if record.previous_serving_digest != active_history_digest {
            return Err(GatewayComplianceError::InvalidCheckpoint(
                "history serving lineage is discontinuous".into(),
            ));
        }
        match record.action.as_str() {
            "promotion" => last_promotion_digest = Some(record.serving_digest),
            "rollback" if record.previous_serving_digest.is_some() => {}
            "rollback" => {
                return Err(GatewayComplianceError::InvalidCheckpoint(
                    "rollback history requires a previous serving digest".into(),
                ));
            }
            _ => {
                return Err(GatewayComplianceError::InvalidCheckpoint(
                    "history action must be promotion or rollback".into(),
                ));
            }
        }
        active_history_digest = Some(record.serving_digest);
        previous_recorded_at = record.recorded_at_unix;
    }
    if checkpoint.history.is_empty() {
        if chain_head_digest.is_some()
            || serving_digest.is_some()
            || previous_serving_digest.is_some()
        {
            return Err(GatewayComplianceError::InvalidCheckpoint(
                "serving catalogs require promotion history".into(),
            ));
        }
    } else {
        let last = checkpoint.history.last().expect("history is non-empty");
        if active_history_digest != serving_digest
            || last_promotion_digest != chain_head_digest
            || last.previous_serving_digest != previous_serving_digest
        {
            return Err(GatewayComplianceError::InvalidCheckpoint(
                "checkpoint pointers do not match durable history lineage".into(),
            ));
        }
    }
    let mut known_catalog_digests = BTreeSet::new();
    for catalog in [
        checkpoint.chain_head.as_ref(),
        checkpoint.serving.as_ref(),
        checkpoint.previous_serving.as_ref(),
        checkpoint.candidate.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        known_catalog_digests.insert(catalog.payload.catalog_digest()?);
    }
    for record in &checkpoint.history {
        known_catalog_digests.insert(record.serving_digest);
        if let Some(digest) = record.previous_serving_digest {
            known_catalog_digests.insert(digest);
        }
    }
    let mut idempotency_keys = BTreeSet::new();
    let mut previous_idempotency_timestamp = 0;
    for record in &checkpoint.idempotency_records {
        if record.key_digest.iter().all(|byte| *byte == 0)
            || record.request_digest.iter().all(|byte| *byte == 0)
            || record.catalog_digest.iter().all(|byte| *byte == 0)
            || !idempotency_keys.insert(record.key_digest)
        {
            return Err(GatewayComplianceError::InvalidCheckpoint(
                "idempotency records contain zero digests or duplicate keys".into(),
            ));
        }
        if record.recorded_at_unix == 0 || record.recorded_at_unix < previous_idempotency_timestamp
        {
            return Err(GatewayComplianceError::InvalidCheckpoint(
                "idempotency record timestamps must be non-zero and monotonic".into(),
            ));
        }
        if !known_catalog_digests.contains(&record.catalog_digest) {
            return Err(GatewayComplianceError::InvalidCheckpoint(
                "idempotency record references an unknown catalog".into(),
            ));
        }
        if let Some(action) = record.operation.history_action() {
            let Some(history) = checkpoint
                .history
                .iter()
                .find(|history| history.operation_id == record.key_digest)
            else {
                return Err(GatewayComplianceError::InvalidCheckpoint(
                    "terminal mutation idempotency record has no matching history".into(),
                ));
            };
            if history.action != action
                || history.serving_digest != record.catalog_digest
                || history.recorded_at_unix != record.recorded_at_unix
            {
                return Err(GatewayComplianceError::InvalidCheckpoint(
                    "terminal mutation idempotency record disagrees with history".into(),
                ));
            }
        }
        previous_idempotency_timestamp = record.recorded_at_unix;
    }
    for history in &checkpoint.history {
        let expected_operation = match history.action.as_str() {
            "promotion" => GatewayComplianceMutationKindV1::Promote,
            "rollback" => GatewayComplianceMutationKindV1::Rollback,
            _ => unreachable!("history actions were validated above"),
        };
        let Some(record) = checkpoint
            .idempotency_records
            .iter()
            .find(|record| record.key_digest == history.operation_id)
        else {
            return Err(GatewayComplianceError::InvalidCheckpoint(
                "history has no matching idempotency record".into(),
            ));
        };
        if record.operation != expected_operation
            || record.catalog_digest != history.serving_digest
            || record.recorded_at_unix != history.recorded_at_unix
        {
            return Err(GatewayComplianceError::InvalidCheckpoint(
                "history disagrees with its idempotency record".into(),
            ));
        }
    }
    encode_bounded(checkpoint, MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1)?;
    Ok(())
}
fn decode_checkpoint(
    bytes: &[u8],
) -> Result<GatewayComplianceCheckpointV1, GatewayComplianceError> {
    if bytes.len() > MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1 {
        return Err(GatewayComplianceError::ResourceLimit {
            resource: "compliance checkpoint bytes",
            found: bytes.len(),
            maximum: MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1,
        });
    }
    let checkpoint: GatewayComplianceCheckpointV1 = norito::decode_from_bytes_with_limits(
        bytes,
        norito::DecodeLimits::new(
            MAX_GATEWAY_COMPLIANCE_ENTRIES_V1,
            MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1,
            4_000_000,
            MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1 * 4,
            128,
        ),
    )
    .map_err(|error| GatewayComplianceError::InvalidCheckpoint(error.to_string()))?;
    let canonical = encode_bounded(&checkpoint, MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1)?;
    if canonical != bytes {
        return Err(GatewayComplianceError::NonCanonical(
            "compliance checkpoint encoding".into(),
        ));
    }
    Ok(checkpoint)
}
fn fetch_feed_bytes(
    feed: &GatewayComplianceFeedPolicy,
    limits: GatewayComplianceFetchLimits,
    expected_transport: &GatewayComplianceFeedTransportIdentityV1,
    transport: &dyn GatewayComplianceFeedTransport,
) -> Result<Vec<u8>, GatewayComplianceError> {
    let started = Instant::now();
    let mut current = validate_feed_url(feed, &feed.url)?;
    for redirect_count in 0..=limits.max_redirects {
        let host = current
            .host_str()
            .ok_or_else(|| GatewayComplianceError::UnsafeUrl("missing host".into()))?;
        let remaining = remaining_fetch_time(started, limits.total_timeout)?;
        let mut addresses = qualified_feed_transport_resolve(
            expected_transport,
            transport,
            host,
            limits.connect_timeout.min(remaining),
        )?;
        let remaining = remaining_fetch_time(started, limits.total_timeout)?;
        normalize_resolved_addresses(&mut addresses, limits.max_dns_addresses)?;
        let response = qualified_feed_transport_fetch(
            expected_transport,
            transport,
            &GatewayComplianceFetchRequest {
                url: current.clone(),
                pinned_addresses: addresses.clone(),
                connect_timeout: limits.connect_timeout.min(remaining),
                total_timeout: remaining,
                max_encoded_bytes: limits.max_encoded_bytes,
            },
        )?;
        if response.elapsed > remaining {
            return Err(GatewayComplianceError::FetchTimeout);
        }
        remaining_fetch_time(started, limits.total_timeout)?;
        if !addresses.contains(&response.connected_address) {
            return Err(GatewayComplianceError::DnsRebinding);
        }
        let host_policy = host_policy(feed, host)?;
        if !host_policy
            .accepted_spki_sha256
            .contains(&response.peer_spki_sha256)
        {
            return Err(GatewayComplianceError::TrustPinMismatch);
        }
        if response.body.len() > limits.max_encoded_bytes {
            return Err(GatewayComplianceError::ResourceLimit {
                resource: "encoded feed bytes",
                found: response.body.len(),
                maximum: limits.max_encoded_bytes,
            });
        }
        let remaining = remaining_fetch_time(started, limits.total_timeout)?;
        let mut revalidated = qualified_feed_transport_resolve(
            expected_transport,
            transport,
            host,
            limits.connect_timeout.min(remaining),
        )?;
        remaining_fetch_time(started, limits.total_timeout)?;
        normalize_resolved_addresses(&mut revalidated, limits.max_dns_addresses)?;
        if revalidated != addresses {
            return Err(GatewayComplianceError::DnsRebinding);
        }
        if (300..400).contains(&response.status) {
            if redirect_count == limits.max_redirects {
                return Err(GatewayComplianceError::TooManyRedirects);
            }
            let location = response.redirect_location.ok_or_else(|| {
                GatewayComplianceError::InvalidFeed("redirect lacks Location".into())
            })?;
            let redirected = current.join(&location).map_err(|error| {
                GatewayComplianceError::UnsafeUrl(format!("invalid redirect: {error}"))
            })?;
            current = validate_feed_url(feed, redirected.as_str())?;
            continue;
        }
        if response.status != 200 || response.redirect_location.is_some() {
            return Err(GatewayComplianceError::InvalidFeed(format!(
                "feed returned HTTP {}",
                response.status
            )));
        }
        remaining_fetch_time(started, limits.total_timeout)?;
        let decoded = decompress_bounded(
            &response.body,
            response.content_encoding,
            limits.max_decoded_bytes,
        )?;
        remaining_fetch_time(started, limits.total_timeout)?;
        return Ok(decoded);
    }
    Err(GatewayComplianceError::TooManyRedirects)
}
fn qualified_feed_transport_resolve(
    expected: &GatewayComplianceFeedTransportIdentityV1,
    transport: &dyn GatewayComplianceFeedTransport,
    hostname: &str,
    timeout: Duration,
) -> Result<Vec<IpAddr>, GatewayComplianceError> {
    qualify_feed_transport(expected, transport)?;
    let result = transport.resolve(hostname, timeout);
    qualify_feed_transport(expected, transport)?;
    result.map_err(redact_feed_transport_operation_error)
}
fn qualified_feed_transport_fetch(
    expected: &GatewayComplianceFeedTransportIdentityV1,
    transport: &dyn GatewayComplianceFeedTransport,
    request: &GatewayComplianceFetchRequest,
) -> Result<GatewayComplianceFetchResponse, GatewayComplianceError> {
    qualify_feed_transport(expected, transport)?;
    let result = transport.fetch(request);
    qualify_feed_transport(expected, transport)?;
    result.map_err(redact_feed_transport_operation_error)
}
fn redact_feed_transport_operation_error(error: GatewayComplianceError) -> GatewayComplianceError {
    match error {
        GatewayComplianceError::FetchTimeout => GatewayComplianceError::FetchTimeout,
        GatewayComplianceError::DnsRebinding => GatewayComplianceError::DnsRebinding,
        GatewayComplianceError::NonPublicAddress => GatewayComplianceError::NonPublicAddress,
        GatewayComplianceError::UnsafeAddressSet { found, maximum } => {
            GatewayComplianceError::UnsafeAddressSet { found, maximum }
        }
        GatewayComplianceError::TrustPinMismatch => GatewayComplianceError::TrustPinMismatch,
        GatewayComplianceError::ResourceLimit {
            resource,
            found,
            maximum,
        } => GatewayComplianceError::ResourceLimit {
            resource,
            found,
            maximum,
        },
        _ => GatewayComplianceError::FeedTransportOperationFailed,
    }
}
fn remaining_fetch_time(
    started: Instant,
    total_timeout: Duration,
) -> Result<Duration, GatewayComplianceError> {
    total_timeout
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(GatewayComplianceError::FetchTimeout)
}
fn qualify_feed_transport(
    expected: &GatewayComplianceFeedTransportIdentityV1,
    transport: &dyn GatewayComplianceFeedTransport,
) -> Result<(), GatewayComplianceError> {
    let observed = transport
        .qualification()
        .map_err(|_| GatewayComplianceError::FeedTransportUnavailable)?;
    if observed.test_marked {
        return Err(GatewayComplianceError::FeedTransportTestMarked);
    }
    let observed_binding = GatewayProviderBindingV1::try_new(
        observed.provider_handle,
        observed.revision,
        observed.policy_digest,
    )
    .map_err(|error| match error {
        GatewayProviderBindingErrorV1::TestMarkedHandle => {
            GatewayComplianceError::FeedTransportTestMarked
        }
        GatewayProviderBindingErrorV1::ZeroRevision => GatewayComplianceError::FeedTransportStale,
        GatewayProviderBindingErrorV1::InvalidHandle
        | GatewayProviderBindingErrorV1::ZeroPolicyDigest => {
            GatewayComplianceError::FeedTransportUnqualified
        }
    })?;
    if observed_binding.provider_handle() != expected.provider_handle {
        return Err(GatewayComplianceError::FeedTransportSubstituted);
    }
    if observed_binding.revision() != expected.revision {
        return Err(GatewayComplianceError::FeedTransportStale);
    }
    if observed_binding.policy_digest() != expected.policy_digest {
        return Err(GatewayComplianceError::FeedTransportSubstituted);
    }
    Ok(())
}
fn validate_feed_url(
    feed: &GatewayComplianceFeedPolicy,
    raw: &str,
) -> Result<Url, GatewayComplianceError> {
    if raw.len() > 2_048 {
        return Err(GatewayComplianceError::UnsafeUrl(
            "URL exceeds 2048 bytes".into(),
        ));
    }
    let parsed =
        Url::parse(raw).map_err(|error| GatewayComplianceError::UnsafeUrl(error.to_string()))?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.port().is_some_and(|port| port != 443)
    {
        return Err(GatewayComplianceError::UnsafeUrl(
            "feed URL must be credential-free HTTPS without query or fragment".into(),
        ));
    }
    let host = match parsed.host() {
        Some(Host::Domain(host)) => host,
        _ => {
            return Err(GatewayComplianceError::UnsafeUrl(
                "feed URL must use an allowlisted DNS hostname".into(),
            ));
        }
    };
    validate_dns_hostname(host)?;
    host_policy(feed, host)?;
    if parsed.path().contains("//")
        || raw.contains("%2f")
        || raw.contains("%2F")
        || raw.contains("%5c")
        || raw.contains("%5C")
        || raw.contains("/../")
        || raw.ends_with("/..")
    {
        return Err(GatewayComplianceError::UnsafeUrl(
            "feed URL contains ambiguous path separators or traversal".into(),
        ));
    }
    if parsed.as_str() != raw {
        return Err(GatewayComplianceError::UnsafeUrl(
            "feed URL is not in canonical URL spelling".into(),
        ));
    }
    Ok(parsed)
}
fn host_policy<'a>(
    feed: &'a GatewayComplianceFeedPolicy,
    host: &str,
) -> Result<&'a GatewayComplianceFeedHostPolicy, GatewayComplianceError> {
    feed.hosts
        .binary_search_by(|entry| entry.hostname.as_str().cmp(host))
        .ok()
        .map(|index| &feed.hosts[index])
        .ok_or_else(|| GatewayComplianceError::UnsafeUrl("host is not allowlisted".into()))
}
fn normalize_resolved_addresses(
    addresses: &mut Vec<IpAddr>,
    maximum: usize,
) -> Result<(), GatewayComplianceError> {
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() || addresses.len() > maximum {
        return Err(GatewayComplianceError::UnsafeAddressSet {
            found: addresses.len(),
            maximum,
        });
    }
    if addresses
        .iter()
        .any(|address| !crate::utils::is_public_ip(*address))
    {
        return Err(GatewayComplianceError::NonPublicAddress);
    }
    Ok(())
}
fn decompress_bounded(
    bytes: &[u8],
    encoding: GatewayComplianceContentEncoding,
    maximum: usize,
) -> Result<Vec<u8>, GatewayComplianceError> {
    match encoding {
        GatewayComplianceContentEncoding::Identity => {
            if bytes.len() > maximum {
                return Err(GatewayComplianceError::ResourceLimit {
                    resource: "decoded feed bytes",
                    found: bytes.len(),
                    maximum,
                });
            }
            Ok(bytes.to_vec())
        }
        GatewayComplianceContentEncoding::Gzip => {
            read_bounded(GzDecoder::new(Cursor::new(bytes)), maximum, "gzip")
        }
        GatewayComplianceContentEncoding::Zstd => {
            let mut decoder =
                zstd::stream::read::Decoder::new(Cursor::new(bytes)).map_err(|error| {
                    GatewayComplianceError::Decompression(format!("zstd header: {error}"))
                })?;
            // Bound frame-requested history before the decoder can allocate its window.
            // Zstandard requires at least 1 KiB; emitted bytes keep the exact limit below.
            decoder
                .window_log_max(maximum.max(1024).ilog2())
                .map_err(|error| {
                    GatewayComplianceError::Decompression(format!("zstd window bound: {error}"))
                })?;
            read_bounded(decoder, maximum, "zstd")
        }
    }
}
fn read_bounded<R: Read>(
    reader: R,
    maximum: usize,
    algorithm: &'static str,
) -> Result<Vec<u8>, GatewayComplianceError> {
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    let mut output = Vec::with_capacity(maximum.min(64 * 1024));
    reader
        .take(limit)
        .read_to_end(&mut output)
        .map_err(|error| GatewayComplianceError::Decompression(format!("{algorithm}: {error}")))?;
    if output.len() > maximum {
        return Err(GatewayComplianceError::ResourceLimit {
            resource: "decoded feed bytes",
            found: output.len(),
            maximum,
        });
    }
    Ok(output)
}
fn active_interval(start: u64, end: Option<u64>, observed: u64) -> bool {
    start <= observed && end.is_none_or(|end| observed < end)
}
fn scopes_match(rule_scope: &str, request_scopes: &[&str]) -> bool {
    rule_scope == "global" || request_scopes.contains(&rule_scope)
}
fn toggle_enabled(
    toggles: &[GatewayComplianceToggleV1],
    toggle_id: &str,
    scope: &str,
    observed_at_unix: u64,
) -> bool {
    toggles
        .iter()
        .find(|toggle| {
            toggle.toggle_id == toggle_id
                && toggle.scope == scope
                && active_interval(
                    toggle.effective_from_unix,
                    Some(toggle.expires_at_unix),
                    observed_at_unix,
                )
        })
        .or_else(|| {
            toggles.iter().find(|toggle| {
                toggle.toggle_id == toggle_id
                    && toggle.scope == "global"
                    && active_interval(
                        toggle.effective_from_unix,
                        Some(toggle.expires_at_unix),
                        observed_at_unix,
                    )
            })
        })
        .is_none_or(|toggle| toggle.enabled)
}
fn checkpoint_store_generation(bytes: Option<&[u8]>) -> GatewayComplianceStoreGeneration {
    let Some(bytes) = bytes else {
        return GatewayComplianceStoreGeneration::Absent;
    };
    let mut hasher = Hasher::new();
    hasher.update(CHECKPOINT_STORE_GENERATION_DOMAIN_V1);
    hasher.update(
        &u64::try_from(bytes.len())
            .expect("bounded checkpoint length fits u64")
            .to_le_bytes(),
    );
    hasher.update(bytes);
    GatewayComplianceStoreGeneration::Present(*hasher.finalize().as_bytes())
}
fn checkpoint_store_snapshot(bytes: Option<Vec<u8>>) -> GatewayComplianceStoreSnapshot {
    GatewayComplianceStoreSnapshot {
        generation: checkpoint_store_generation(bytes.as_deref()),
        bytes,
    }
}
fn checkpoint_lock_path(path: &Path) -> Result<PathBuf, GatewayComplianceError> {
    let parent = path.parent().ok_or_else(|| {
        GatewayComplianceError::Persistence("compliance checkpoint path has no parent".into())
    })?;
    let filename = path.file_name().ok_or_else(|| {
        GatewayComplianceError::Persistence("compliance checkpoint path has no filename".into())
    })?;
    let mut lock_name = std::ffi::OsString::from(".");
    lock_name.push(filename);
    lock_name.push(".lock");
    Ok(parent.join(lock_name))
}
fn read_checkpoint_snapshot(
    path: &Path,
    max_bytes: usize,
) -> Result<GatewayComplianceStoreSnapshot, GatewayComplianceError> {
    let parent = path.parent().ok_or_else(|| {
        GatewayComplianceError::Persistence("compliance checkpoint path has no parent".into())
    })?;
    validate_checkpoint_parent(parent)?;
    let named_before = match secure_file_metadata::from_path(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(checkpoint_store_snapshot(None));
        }
        Err(error) => return Err(persistence_io("inspect checkpoint", error)),
    };
    validate_checkpoint_file_metadata(&named_before)?;
    let length = usize::try_from(named_before.len()).unwrap_or(usize::MAX);
    if length > max_bytes {
        return Err(GatewayComplianceError::ResourceLimit {
            resource: "compliance checkpoint bytes",
            found: length,
            maximum: max_bytes,
        });
    }
    let mut options = OpenOptions::new();
    options.read(true);
    set_no_follow(&mut options);
    set_stable_read_share_mode(&mut options);
    let mut file = options
        .open(path)
        .map_err(|error| persistence_io("open checkpoint", error))?;
    let (opened_before, named_after_open) =
        validate_opened_file(path, &file, "compliance checkpoint changed while opening")?;
    if !secure_file_metadata::unchanged(&named_before, &opened_before)
        || !secure_file_metadata::unchanged(&opened_before, &named_after_open)
    {
        return Err(GatewayComplianceError::Persistence(
            "compliance checkpoint changed between inspection and open".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(length);
    Read::by_ref(&mut file)
        .take(
            u64::try_from(max_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|error| persistence_io("read checkpoint", error))?;
    if bytes.len() > max_bytes {
        return Err(GatewayComplianceError::ResourceLimit {
            resource: "compliance checkpoint bytes",
            found: bytes.len(),
            maximum: max_bytes,
        });
    }
    let (opened_after, named_after) =
        validate_opened_file(path, &file, "compliance checkpoint changed while reading")?;
    if !secure_file_metadata::unchanged(&opened_before, &opened_after)
        || !secure_file_metadata::unchanged(&opened_after, &named_after)
        || opened_after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(GatewayComplianceError::Persistence(
            "compliance checkpoint changed while reading".into(),
        ));
    }
    Ok(checkpoint_store_snapshot(Some(bytes)))
}
fn validate_checkpoint_parent(path: &Path) -> Result<(), GatewayComplianceError> {
    validate_existing_directory_chain(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = secure_file_metadata::from_path(path)
            .map_err(|error| persistence_io("inspect checkpoint parent", error))?;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(GatewayComplianceError::Persistence(
                "checkpoint parent must not be group- or world-writable".into(),
            ));
        }
    }
    Ok(())
}
fn validate_existing_directory_chain(path: &Path) -> Result<(), GatewayComplianceError> {
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir => {
                return Err(GatewayComplianceError::Persistence(
                    "checkpoint path contains traversal".into(),
                ));
            }
        }
    }
    let mut ancestors = path
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .collect::<Vec<_>>();
    ancestors.reverse();
    for current in ancestors {
        let metadata = secure_file_metadata::from_path(current)
            .map_err(|error| persistence_io("inspect checkpoint directory", error))?;
        if !secure_file_metadata::is_direct_directory(&metadata) {
            return Err(GatewayComplianceError::Persistence(format!(
                "checkpoint directory `{}` is not a regular directory",
                current.display()
            )));
        }
    }
    Ok(())
}
fn validate_checkpoint_file_metadata(
    metadata: &SecureMetadata,
) -> Result<(), GatewayComplianceError> {
    if !secure_file_metadata::is_direct_file(metadata)
        || secure_file_metadata::number_of_links(metadata) != Some(1)
    {
        return Err(GatewayComplianceError::Persistence(
            "compliance checkpoint must be a single-link direct regular file".into(),
        ));
    }
    validate_file_permissions(metadata, "compliance checkpoint")
}
fn validate_output_file(path: &Path) -> Result<Option<SecureMetadata>, GatewayComplianceError> {
    match secure_file_metadata::from_path(path) {
        Ok(metadata) => {
            if !secure_file_metadata::is_direct_file(&metadata)
                || secure_file_metadata::number_of_links(&metadata) != Some(1)
            {
                return Err(GatewayComplianceError::Persistence(
                    "checkpoint output must be absent or a single-link direct regular file".into(),
                ));
            }
            validate_file_permissions(&metadata, "checkpoint output")?;
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(persistence_io("inspect checkpoint output", error)),
    }
}
fn validate_opened_file(
    path: &Path,
    file: &File,
    changed_message: &'static str,
) -> Result<(SecureMetadata, SecureMetadata), GatewayComplianceError> {
    let opened_metadata = secure_file_metadata::from_file(file)
        .map_err(|error| persistence_io("inspect opened file", error))?;
    let path_metadata = secure_file_metadata::from_path(path)
        .map_err(|error| persistence_io("inspect opened file path", error))?;
    if !secure_file_metadata::is_direct_file(&path_metadata)
        || !secure_file_metadata::is_direct_file(&opened_metadata)
        || secure_file_metadata::number_of_links(&path_metadata) != Some(1)
        || secure_file_metadata::number_of_links(&opened_metadata) != Some(1)
        || !secure_file_metadata::same_file(&path_metadata, &opened_metadata)
    {
        return Err(GatewayComplianceError::Persistence(changed_message.into()));
    }
    validate_file_permissions(&path_metadata, "opened checkpoint file")?;
    validate_file_permissions(&opened_metadata, "opened checkpoint file")?;
    Ok((opened_metadata, path_metadata))
}
#[cfg(unix)]
fn validate_file_permissions(
    metadata: &fs::Metadata,
    label: &'static str,
) -> Result<(), GatewayComplianceError> {
    use std::os::unix::fs::PermissionsExt as _;
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(GatewayComplianceError::Persistence(format!(
            "{label} must not be group- or world-writable"
        )));
    }
    Ok(())
}
#[cfg(not(unix))]
fn validate_file_permissions(
    _metadata: &fs::Metadata,
    _label: &'static str,
) -> Result<(), GatewayComplianceError> {
    Ok(())
}
#[cfg(unix)]
fn set_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.custom_flags(libc::O_NOFOLLOW);
}
#[cfg(windows)]
fn set_no_follow(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}
#[cfg(not(any(unix, windows)))]
fn set_no_follow(_options: &mut OpenOptions) {}
#[cfg(windows)]
fn set_lock_share_mode(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
}
#[cfg(not(windows))]
fn set_lock_share_mode(_options: &mut OpenOptions) {}
#[cfg(windows)]
fn set_stable_read_share_mode(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE);
}
#[cfg(not(windows))]
fn set_stable_read_share_mode(_options: &mut OpenOptions) {}
#[cfg(windows)]
fn set_checkpoint_temp_share_mode(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE);
}
#[cfg(not(windows))]
fn set_checkpoint_temp_share_mode(_options: &mut OpenOptions) {}
fn persistence_io(action: &'static str, error: io::Error) -> GatewayComplianceError {
    GatewayComplianceError::Persistence(format!("{action}: {error}"))
}
/// Fail-closed compliance controller errors.
#[derive(Debug, Error)]
pub enum GatewayComplianceError {
    /// Trust or controller policy is malformed.
    #[error("invalid gateway compliance policy: {0}")]
    InvalidPolicy(String),
    /// Catalog shape or semantics are malformed.
    #[error("invalid gateway compliance catalog: {0}")]
    InvalidCatalog(String),
    /// Feed shape or response is malformed.
    #[error("invalid gateway compliance feed: {0}")]
    InvalidFeed(String),
    /// Durable checkpoint is invalid.
    #[error("invalid gateway compliance checkpoint: {0}")]
    InvalidCheckpoint(String),
    /// A canonical inventory or string was not normalized.
    #[error("non-canonical gateway compliance value: {0}")]
    NonCanonical(String),
    /// A bounded resource exceeded policy.
    #[error("{resource} count/size {found} exceeds maximum {maximum}")]
    ResourceLimit {
        /// Bounded resource.
        resource: &'static str,
        /// Observed count/size.
        found: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// Norito encoding failed.
    #[error("gateway compliance encoding failed: {0}")]
    Encoding(String),
    /// Catalog policy digest differs from resolved config.
    #[error("gateway compliance policy digest mismatch")]
    PolicyDigestMismatch,
    /// Feed access was attempted on a controller without a startup-qualified transport.
    #[error("gateway compliance feed transport was not qualified at startup")]
    FeedTransportNotQualified,
    /// The runtime feed transport could not attest its identity.
    #[error("gateway compliance feed transport is unavailable")]
    FeedTransportUnavailable,
    /// The runtime feed transport returned an invalid public qualification.
    #[error("gateway compliance feed transport is unqualified")]
    FeedTransportUnqualified,
    /// The runtime feed transport failed without exposing provider diagnostics.
    #[error("gateway compliance feed transport operation failed")]
    FeedTransportOperationFailed,
    /// The runtime feed transport does not match the configured trust inventory.
    #[error("gateway compliance feed transport was substituted")]
    FeedTransportSubstituted,
    /// The runtime feed transport revision differs from the V1 contract.
    #[error("gateway compliance feed transport revision is stale")]
    FeedTransportStale,
    /// Test, mock, development, and placeholder providers are forbidden.
    #[error("gateway compliance feed transport is test-marked")]
    FeedTransportTestMarked,
    /// Catalog timestamp is stale or too far in the future.
    #[error("gateway compliance catalog is stale or future-dated")]
    CatalogNotFresh,
    /// Catalog approval quorum is incomplete.
    #[error("gateway compliance quorum not met: found {found}, required {required}")]
    QuorumNotMet {
        /// Valid approval count.
        found: usize,
        /// Required approval count.
        required: u16,
    },
    /// Regional gateway acknowledgement quorum is incomplete.
    #[error("gateway acknowledgement quorum not met: found {found}, required {required}")]
    GatewayQuorumNotMet {
        /// Positive acknowledgement count.
        found: usize,
        /// Required acknowledgement count.
        required: u16,
    },
    /// Signature identity is repeated.
    #[error("duplicate compliance signer `{0}`")]
    DuplicateSigner(String),
    /// Signer is not in the resolved trust policy.
    #[error("untrusted compliance signer `{0}`")]
    UntrustedSigner(String),
    /// Signer is explicitly revoked.
    #[error("revoked compliance signer `{0}`")]
    RevokedSigner(String),
    /// Signature verification failed.
    #[error("invalid compliance signature from `{signer_id}`: {reason}")]
    InvalidSignature {
        /// Signer identity.
        signer_id: String,
        /// Verification failure.
        reason: String,
    },
    /// Initial or successor linkage is invalid.
    #[error("gateway compliance catalog predecessor or sequence is invalid")]
    InvalidPredecessor,
    /// Sequence arithmetic overflowed.
    #[error("gateway compliance catalog sequence overflow")]
    SequenceOverflow,
    /// Timestamp arithmetic overflowed.
    #[error("gateway compliance timestamp overflow")]
    TimeOverflow,
    /// A same-sequence alternative candidate was staged.
    #[error("gateway compliance catalog equivocation at sequence {sequence}")]
    CatalogEquivocation {
        /// Conflicting sequence.
        sequence: u64,
    },
    /// Promotion expectation does not identify the staged catalog exactly.
    #[error("gateway compliance promotion target mismatch")]
    PromotionTargetMismatch,
    /// No candidate is staged.
    #[error("no gateway compliance catalog is staged")]
    NoStagedCatalog,
    /// Gateway acknowledgement is malformed.
    #[error("invalid gateway compliance acknowledgement: {0}")]
    InvalidAcknowledgement(String),
    /// Gateway submitted conflicting acknowledgements.
    #[error("gateway `{0}` submitted conflicting acknowledgements")]
    GatewayEquivocation(String),
    /// No serving catalog exists.
    #[error("no gateway compliance catalog is serving")]
    NoServingCatalog,
    /// No prior last-known-good catalog exists.
    #[error("no last-known-good gateway compliance catalog exists")]
    NoLastKnownGood,
    /// Rollback authorization is malformed.
    #[error("invalid gateway compliance rollback: {0}")]
    InvalidRollback(String),
    /// Rollback targets do not match serving/LKG state.
    #[error("gateway compliance rollback target mismatch")]
    RollbackTargetMismatch,
    /// An idempotency key is already bound to another request or action.
    #[error("gateway compliance idempotency binding conflict")]
    IdempotencyConflict,
    /// Durable replay protection is full and must be archived by an operator.
    #[error("gateway compliance idempotency registry reached its V1 bound")]
    IdempotencyRegistryFull,
    /// Mutation time is zero or regresses behind the last durable operation.
    #[error("gateway compliance mutation time is zero or regressed")]
    MutationTimeInvalid,
    /// Durable history must be archived before additional actions.
    #[error("gateway compliance history reached its configured bound")]
    HistoryFull,
    /// Configured feed does not exist.
    #[error("unknown gateway compliance feed `{0}`")]
    UnknownFeed(String),
    /// Required feed was omitted from catalog construction.
    #[error("required gateway compliance feed `{0}` is missing")]
    MissingRequiredFeed(String),
    /// URL violates HTTPS/allowlist rules.
    #[error("unsafe gateway compliance URL: {0}")]
    UnsafeUrl(String),
    /// DNS answer count is empty or excessive.
    #[error("gateway compliance DNS answer count {found} is outside 1..={maximum}")]
    UnsafeAddressSet {
        /// Observed count.
        found: usize,
        /// Maximum count.
        maximum: usize,
    },
    /// DNS resolved to non-public space.
    #[error("gateway compliance endpoint resolved to a non-public address")]
    NonPublicAddress,
    /// Connected address or revalidation does not match the pinned DNS set.
    #[error("gateway compliance DNS rebinding/address-set change detected")]
    DnsRebinding,
    /// Authenticated peer did not match configured pins.
    #[error("gateway compliance TLS trust pin mismatch")]
    TrustPinMismatch,
    /// Redirect limit was exceeded.
    #[error("gateway compliance redirect limit exceeded")]
    TooManyRedirects,
    /// Fetch exceeded configured time.
    #[error("gateway compliance fetch exceeded its deadline")]
    FetchTimeout,
    /// Bounded decompression failed.
    #[error("gateway compliance decompression failed: {0}")]
    Decompression(String),
    /// Durable storage failed.
    #[error("gateway compliance persistence failed: {0}")]
    Persistence(String),
    /// Another controller already owns the process-lifetime checkpoint lease.
    #[error("gateway compliance checkpoint lease is already held")]
    LeaseHeld,
    /// Exact checkpoint bytes changed or a durable replacement became indeterminate.
    #[error("gateway compliance checkpoint generation conflict")]
    CheckpointConflict,
    /// In-process state lock was poisoned.
    #[error("gateway compliance state lock poisoned")]
    StatePoisoned,
}
impl From<GatewayComplianceProtocolError> for GatewayComplianceError {
    fn from(error: GatewayComplianceProtocolError) -> Self {
        match error {
            GatewayComplianceProtocolError::CatalogNotFresh => Self::CatalogNotFresh,
            GatewayComplianceProtocolError::DuplicateSigner(value) => Self::DuplicateSigner(value),
            GatewayComplianceProtocolError::Encoding(value) => Self::Encoding(value),
            GatewayComplianceProtocolError::InvalidAcknowledgement(value) => {
                Self::InvalidAcknowledgement(value)
            }
            GatewayComplianceProtocolError::InvalidCatalog(value) => Self::InvalidCatalog(value),
            GatewayComplianceProtocolError::InvalidFeed(value) => Self::InvalidFeed(value),
            GatewayComplianceProtocolError::InvalidPolicy(value) => Self::InvalidPolicy(value),
            GatewayComplianceProtocolError::InvalidPredecessor => Self::InvalidPredecessor,
            GatewayComplianceProtocolError::InvalidRollback(value) => Self::InvalidRollback(value),
            GatewayComplianceProtocolError::InvalidSignature { signer_id, reason } => {
                Self::InvalidSignature { signer_id, reason }
            }
            GatewayComplianceProtocolError::NonCanonical(value) => Self::NonCanonical(value),
            GatewayComplianceProtocolError::PolicyDigestMismatch => Self::PolicyDigestMismatch,
            GatewayComplianceProtocolError::QuorumNotMet { found, required } => {
                Self::QuorumNotMet { found, required }
            }
            GatewayComplianceProtocolError::ResourceLimit {
                resource,
                found,
                maximum,
            } => Self::ResourceLimit {
                resource,
                found,
                maximum,
            },
            GatewayComplianceProtocolError::RevokedSigner(value) => Self::RevokedSigner(value),
            GatewayComplianceProtocolError::SequenceOverflow => Self::SequenceOverflow,
            GatewayComplianceProtocolError::UnsafeUrl(value) => Self::UnsafeUrl(value),
            GatewayComplianceProtocolError::UntrustedSigner(value) => Self::UntrustedSigner(value),
        }
    }
}

#[cfg(test)]
mod tests;
