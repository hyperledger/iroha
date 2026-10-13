//! Gateway policy orchestration for GAR enforcement and rate limiting.
use super::rate_limit::{
    ClientFingerprint, GatewayRateLimitConfig, GatewayRateLimiter, RateLimitError,
};
use crate::sorafs::AdmissionRegistry;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};
use hex::ToHex;
use iroha_data_model::{
    events::data::sorafs::{SorafsGarPolicy, SorafsGarPolicyDetail, SorafsGarViolation},
    sorafs::{capacity::ProviderId, pin_registry::ManifestDigest},
};
use iroha_logger::debug;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
/// Canonical, bounded HTTP authority host admitted to GAR event metadata.
///
/// The inner string is private so [`RequestContext`] cannot retain raw request
/// header bytes by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalHost(String);
impl CanonicalHost {
    /// Parse and canonicalize an HTTP authority or `Host` header value.
    pub(crate) fn parse_authority(raw: &str) -> Option<Self> {
        crate::sorafs::site::normalize_host_header(raw).map(Self)
    }
    fn as_str(&self) -> &str {
        &self.0
    }
}
/// Validated two-letter region code supplied by a trusted gateway boundary.
///
/// Construction is crate-private; the HTTP adapter additionally proves that
/// the immediate peer is a configured trusted proxy before creating one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionCode(String);
impl RegionCode {
    /// Validate and canonicalize one trusted-proxy region header value.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        (trimmed.len() == 2 && trimmed.bytes().all(|byte| byte.is_ascii_alphabetic()))
            .then(|| Self(trimmed.to_ascii_uppercase()))
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}
/// Policy configuration controlling the enforcement surface.
#[derive(Clone, Copy, Debug)]
pub struct GatewayPolicyConfig {
    /// Require manifests to ship the governance envelope before serving data.
    pub require_manifest_envelope: bool,
    /// Enforce that providers appear in the admission registry.
    pub enforce_admission: bool,
    /// Rate limiting configuration applied to gateway clients.
    pub rate_limit: GatewayRateLimitConfig,
}
impl Default for GatewayPolicyConfig {
    fn default() -> Self {
        Self {
            require_manifest_envelope: true,
            enforce_admission: true,
            rate_limit: GatewayRateLimitConfig::default(),
        }
    }
}
/// Result returned after evaluating policy rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Request is permitted to proceed.
    Allow,
    /// Request is denied because a rule triggered.
    Deny(PolicyViolation),
}
/// Detailed classification for policy denials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyViolation {
    /// Manifest envelope was required but missing.
    ManifestEnvelopeMissing,
    /// Provider identifier was expected but absent.
    MissingProviderId,
    /// Admission registry is unavailable while enforcement is enabled.
    AdmissionUnavailable,
    /// Provider is not admitted according to the governance registry.
    ProviderNotAdmitted {
        /// Identifier of the provider that failed the check.
        provider_id: [u8; 32],
    },
    /// Rate limiting rejected the client.
    RateLimited(RateLimitError),
}
/// Context supplied to the policy evaluator for each request.
#[derive(Debug)]
pub struct RequestContext<'a> {
    provider_id: Option<&'a [u8; 32]>,
    manifest_digest: Option<&'a [u8; 32]>,
    content_cid: Option<&'a [u8]>,
    manifest_envelope_present: bool,
    client: &'a ClientFingerprint,
    wall_time: SystemTime,
    monotonic_now: Instant,
    remote_addr: Option<SocketAddr>,
    canonical_host: Option<CanonicalHost>,
    region: Option<RegionCode>,
    cache_ttl_secs: Option<u64>,
}
impl<'a> RequestContext<'a> {
    /// Construct a new context with mandatory metadata.
    #[must_use]
    pub fn new(
        client: &'a ClientFingerprint,
        wall_time: SystemTime,
        monotonic_now: Instant,
    ) -> Self {
        Self {
            provider_id: None,
            manifest_digest: None,
            content_cid: None,
            manifest_envelope_present: false,
            client,
            wall_time,
            monotonic_now,
            remote_addr: None,
            canonical_host: None,
            region: None,
            cache_ttl_secs: None,
        }
    }
    /// Attach the provider identifier used for GAR enforcement.
    #[must_use]
    pub fn with_provider_id(mut self, provider_id: &'a [u8; 32]) -> Self {
        self.provider_id = Some(provider_id);
        self
    }
    /// Attach the manifest digest to the GAR event context.
    #[must_use]
    pub fn with_manifest_digest(mut self, digest: &'a [u8; 32]) -> Self {
        self.manifest_digest = Some(digest);
        self
    }
    /// Attach the content identifier (CID) to the GAR event context.
    #[must_use]
    pub fn with_content_cid(mut self, cid: &'a [u8]) -> Self {
        self.content_cid = Some(cid);
        self
    }
    /// Marks that the manifest envelope was supplied for this request.
    #[must_use]
    pub fn with_manifest_envelope(mut self, present: bool) -> Self {
        self.manifest_envelope_present = present;
        self
    }
    /// Provider identifier associated with the request, if known.
    #[must_use]
    pub fn provider_id(&self) -> Option<&'a [u8; 32]> {
        self.provider_id
    }
    /// Manifest digest associated with the request (BLAKE3-256), if supplied.
    #[must_use]
    pub fn manifest_digest(&self) -> Option<&'a [u8; 32]> {
        self.manifest_digest
    }
    /// Content identifier (CID) referenced by the request, if any.
    #[must_use]
    pub fn content_cid(&self) -> Option<&'a [u8]> {
        self.content_cid
    }
    /// Whether a manifest envelope was supplied alongside the request.
    #[must_use]
    pub fn manifest_envelope_present(&self) -> bool {
        self.manifest_envelope_present
    }
    /// Fingerprint representing the client issuing the request.
    #[must_use]
    pub fn client(&self) -> &'a ClientFingerprint {
        self.client
    }
    /// Attach the remote socket address associated with the request.
    #[must_use]
    pub fn with_remote_addr(mut self, remote: SocketAddr) -> Self {
        self.remote_addr = Some(remote);
        self
    }
    /// Attach the validated canonical host associated with the request.
    #[must_use]
    pub(crate) fn with_canonical_host(mut self, host: CanonicalHost) -> Self {
        self.canonical_host = Some(host);
        self
    }
    /// Attach the validated region associated with the request.
    #[must_use]
    pub(crate) fn with_region(mut self, region: RegionCode) -> Self {
        self.region = Some(region);
        self
    }
    /// Attach the cache TTL observed on the request (seconds).
    #[must_use]
    pub fn with_cache_ttl_secs(mut self, ttl: u64) -> Self {
        self.cache_ttl_secs = Some(ttl);
        self
    }
    /// Remote socket address for the request, when available.
    #[must_use]
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }
    /// Current wall-clock time associated with the request.
    #[must_use]
    pub fn wall_time(&self) -> SystemTime {
        self.wall_time
    }
    /// Monotonic instant used for rate-limiter accounting.
    #[must_use]
    pub fn monotonic_now(&self) -> Instant {
        self.monotonic_now
    }
    /// Canonical host for the request, if supplied.
    #[must_use]
    pub fn canonical_host(&self) -> Option<&str> {
        self.canonical_host.as_ref().map(CanonicalHost::as_str)
    }
    /// Optional region label associated with the request.
    #[must_use]
    pub fn region(&self) -> Option<&str> {
        self.region.as_ref().map(RegionCode::as_str)
    }
    /// Optional cache TTL observed for the request (seconds).
    #[must_use]
    pub fn cache_ttl_secs(&self) -> Option<u64> {
        self.cache_ttl_secs
    }
}
impl PolicyViolation {
    /// Convert the violation into telemetry-friendly reason/detail labels.
    #[must_use]
    pub fn telemetry_labels(&self) -> (&'static str, &'static str) {
        match self {
            Self::ManifestEnvelopeMissing => ("manifest_envelope", "missing"),
            Self::MissingProviderId => ("provider", "missing_id"),
            Self::AdmissionUnavailable => ("admission", "unavailable"),
            Self::ProviderNotAdmitted { .. } => ("admission", "not_admitted"),
            Self::RateLimited(error) => match error {
                RateLimitError::Limited { .. } => ("rate_limit", "limited"),
                RateLimitError::Banned { .. } => ("rate_limit", "banned"),
            },
        }
    }
}
/// Policy orchestrator performing GAR and rate limiting checks.
#[derive(Debug)]
pub struct GatewayPolicy {
    config: GatewayPolicyConfig,
    admission: Option<Arc<AdmissionRegistry>>,
    rate_limiter: GatewayRateLimiter,
}
impl GatewayPolicy {
    /// Construct a policy instance.
    #[must_use]
    pub fn new(
        config: GatewayPolicyConfig,
        admission: Option<Arc<AdmissionRegistry>>,
        rate_limiter: GatewayRateLimiter,
    ) -> Self {
        Self {
            config,
            admission,
            rate_limiter,
        }
    }
    /// Construct a policy using default configuration.
    #[must_use]
    pub fn new_default(admission: Option<Arc<AdmissionRegistry>>) -> Self {
        let config = GatewayPolicyConfig::default();
        let rate_limiter = GatewayRateLimiter::new(config.rate_limit);
        Self::new(config, admission, rate_limiter)
    }
    /// Evaluate the supplied request context and return the policy decision.
    #[must_use]
    pub fn evaluate(&self, ctx: &RequestContext<'_>) -> PolicyDecision {
        if self.config.require_manifest_envelope && !ctx.manifest_envelope_present() {
            return PolicyDecision::Deny(PolicyViolation::ManifestEnvelopeMissing);
        }
        if self.config.enforce_admission {
            match (self.admission.as_ref(), ctx.provider_id()) {
                (Some(registry), Some(provider_id)) => {
                    if registry.entry(provider_id).is_none() {
                        debug!(
                            "GAR enforcement: provider {provider_id:02x?} missing from registry",
                            provider_id = provider_id
                        );
                        return PolicyDecision::Deny(PolicyViolation::ProviderNotAdmitted {
                            provider_id: *provider_id,
                        });
                    }
                }
                (Some(_), None) => {
                    return PolicyDecision::Deny(PolicyViolation::MissingProviderId);
                }
                (None, _) => {
                    return PolicyDecision::Deny(PolicyViolation::AdmissionUnavailable);
                }
            }
        }
        self.evaluate_rate_only(ctx)
    }
    /// Evaluate only the client rate limit for a source that has no provider or manifest envelope.
    #[must_use]
    pub fn evaluate_rate_only(&self, ctx: &RequestContext<'_>) -> PolicyDecision {
        if let Err(err) = self.rate_limiter.check(ctx.client(), ctx.monotonic_now()) {
            return PolicyDecision::Deny(PolicyViolation::RateLimited(err));
        }
        PolicyDecision::Allow
    }
    /// Returns a reference to the rate limiter (primarily for tests).
    #[must_use]
    pub fn rate_limiter(&self) -> &GatewayRateLimiter {
        &self.rate_limiter
    }
}
/// Build a [`SorafsGarViolation`] payload describing the provided policy failure.
pub fn build_gar_violation_event(
    ctx: &RequestContext<'_>,
    violation: &PolicyViolation,
) -> SorafsGarViolation {
    let mut provider_id = ctx.provider_id().map(|id| ProviderId::new(*id));
    let manifest_digest = ctx
        .manifest_digest()
        .map(|digest| ManifestDigest::new(*digest));
    let manifest_cid_b64 = ctx.content_cid().map(|cid| BASE64_STD.encode(cid));
    let mut retry_after_seconds: Option<u64> = None;
    let region = ctx.region().map(ToOwned::to_owned);
    let host = ctx.canonical_host().map(ToOwned::to_owned);
    let mut policy_labels: Vec<String> = Vec::new();
    let observed_ttl_seconds = ctx.cache_ttl_secs();
    let rate_ceiling_rps: Option<u64> = None;
    let (policy, detail) = match violation {
        PolicyViolation::ManifestEnvelopeMissing => (
            SorafsGarPolicy::ManifestEnvelope,
            SorafsGarPolicyDetail::ManifestEnvelopeMissing,
        ),
        PolicyViolation::MissingProviderId => (
            SorafsGarPolicy::Provider,
            SorafsGarPolicyDetail::ProviderIdMissing,
        ),
        PolicyViolation::AdmissionUnavailable => (
            SorafsGarPolicy::Admission,
            SorafsGarPolicyDetail::AdmissionUnavailable,
        ),
        PolicyViolation::ProviderNotAdmitted { provider_id: pid } => {
            provider_id = Some(ProviderId::new(*pid));
            (
                SorafsGarPolicy::Admission,
                SorafsGarPolicyDetail::ProviderNotAdmitted,
            )
        }
        PolicyViolation::RateLimited(error) => {
            let detail = match error {
                RateLimitError::Limited { retry_after } => {
                    retry_after_seconds = Some(retry_after.as_secs());
                    SorafsGarPolicyDetail::RateLimitExceeded
                }
                RateLimitError::Banned { retry_after } => {
                    retry_after_seconds = retry_after.map(|duration| duration.as_secs());
                    SorafsGarPolicyDetail::RateLimitBanned
                }
            };
            (SorafsGarPolicy::RateLimit, detail)
        }
    };
    let (reason_label, detail_label) = violation.telemetry_labels();
    policy_labels.insert(0, detail_label.to_string());
    policy_labels.insert(0, reason_label.to_string());
    let client_fingerprint_hex = ctx.client().as_bytes().encode_hex::<String>();
    let remote_addr = ctx.remote_addr().map(|addr| addr.to_string());
    let occurred_at_unix = ctx
        .wall_time()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs();
    SorafsGarViolation {
        policy,
        detail,
        provider_id,
        manifest_digest,
        manifest_cid_b64,
        client_fingerprint_hex,
        remote_addr,
        region,
        host,
        policy_labels,
        observed_ttl_seconds,
        rate_ceiling_rps,
        retry_after_seconds,
        occurred_at_unix,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};
    fn sample_provider_id() -> [u8; 32] {
        [0x42; 32]
    }
    #[test]
    fn policy_denies_missing_manifest_envelope() {
        let admission = Some(Arc::new(AdmissionRegistry::empty([0xA1; 32])));
        let policy = GatewayPolicy::new_default(admission);
        let client = ClientFingerprint::from_identifier("client");
        let provider = sample_provider_id();
        let ctx = RequestContext::new(&client, SystemTime::now(), Instant::now())
            .with_provider_id(&provider)
            .with_manifest_envelope(false);
        let decision = policy.evaluate(&ctx);
        assert!(matches!(
            decision,
            PolicyDecision::Deny(PolicyViolation::ManifestEnvelopeMissing)
        ));
    }
    #[test]
    fn policy_denies_unknown_provider() {
        let admission = Some(Arc::new(AdmissionRegistry::empty([0xA1; 32])));
        let policy = GatewayPolicy::new_default(admission);
        let client = ClientFingerprint::from_identifier("client");
        let other_provider = [0x55; 32];
        let ctx = RequestContext::new(&client, SystemTime::now(), Instant::now())
            .with_provider_id(&other_provider)
            .with_manifest_envelope(true);
        let decision = policy.evaluate(&ctx);
        assert!(matches!(
            decision,
            PolicyDecision::Deny(PolicyViolation::ProviderNotAdmitted { .. })
        ));
    }
    #[test]
    fn policy_denies_when_admission_registry_is_unavailable() {
        let policy = GatewayPolicy::new_default(None);
        let client = ClientFingerprint::from_identifier("client");
        let provider = sample_provider_id();
        let ctx = RequestContext::new(&client, SystemTime::now(), Instant::now())
            .with_provider_id(&provider)
            .with_manifest_envelope(true);
        let decision = policy.evaluate(&ctx);
        assert!(matches!(
            decision,
            PolicyDecision::Deny(PolicyViolation::AdmissionUnavailable)
        ));
    }
    #[test]
    fn policy_does_not_fail_open_without_registry_or_provider_id() {
        let policy = GatewayPolicy::new_default(None);
        let client = ClientFingerprint::from_identifier("client");
        let ctx = RequestContext::new(&client, SystemTime::now(), Instant::now())
            .with_manifest_envelope(true);
        assert!(matches!(
            policy.evaluate(&ctx),
            PolicyDecision::Deny(PolicyViolation::AdmissionUnavailable)
        ));
    }
    #[test]
    fn policy_denies_rate_limited_client() {
        let admission = None;
        let rate_limit = GatewayRateLimitConfig {
            max_requests: Some(1),
            window: Duration::from_mins(1),
            ..GatewayRateLimitConfig::default()
        };
        let config = GatewayPolicyConfig {
            enforce_admission: false,
            rate_limit,
            ..GatewayPolicyConfig::default()
        };
        let policy = GatewayPolicy::new(
            config,
            admission,
            GatewayRateLimiter::new(config.rate_limit),
        );
        let client = ClientFingerprint::from_identifier("client");
        let base = Instant::now();
        let provider = sample_provider_id();
        let ctx = RequestContext::new(&client, SystemTime::now(), base)
            .with_provider_id(&provider)
            .with_manifest_envelope(true);
        assert!(matches!(policy.evaluate(&ctx), PolicyDecision::Allow));
        let denied = policy.evaluate(
            &RequestContext::new(&client, SystemTime::now(), base + Duration::from_millis(5))
                .with_provider_id(&provider)
                .with_manifest_envelope(true),
        );
        assert!(matches!(
            denied,
            PolicyDecision::Deny(PolicyViolation::RateLimited(_))
        ));
    }
    #[test]
    fn rate_only_policy_skips_manifest_and_provider_requirements() {
        let rate_limit = GatewayRateLimitConfig {
            max_requests: Some(1),
            window: Duration::from_mins(1),
            ..GatewayRateLimitConfig::default()
        };
        let config = GatewayPolicyConfig {
            enforce_admission: true,
            require_manifest_envelope: true,
            rate_limit,
        };
        let policy = GatewayPolicy::new(
            config,
            Some(Arc::new(AdmissionRegistry::empty([0xA1; 32]))),
            GatewayRateLimiter::new(config.rate_limit),
        );
        let client = ClientFingerprint::from_identifier("authoritative-wsv-client");
        let base = Instant::now();
        let first = RequestContext::new(&client, SystemTime::now(), base);
        assert!(matches!(
            policy.evaluate_rate_only(&first),
            PolicyDecision::Allow
        ));

        let second =
            RequestContext::new(&client, SystemTime::now(), base + Duration::from_millis(5));
        assert!(matches!(
            policy.evaluate_rate_only(&second),
            PolicyDecision::Deny(PolicyViolation::RateLimited(_))
        ));
    }
    #[test]
    fn gar_violation_event_for_provider_not_admitted() {
        let client = ClientFingerprint::from_identifier("client");
        let provider = sample_provider_id();
        let ctx = RequestContext::new(&client, SystemTime::now(), Instant::now())
            .with_provider_id(&provider)
            .with_manifest_envelope(true)
            .with_remote_addr(SocketAddr::from(([127, 0, 0, 1], 8080)));
        let violation = PolicyViolation::ProviderNotAdmitted {
            provider_id: provider,
        };
        let event = build_gar_violation_event(&ctx, &violation);
        assert_eq!(event.policy, SorafsGarPolicy::Admission);
        assert_eq!(event.detail, SorafsGarPolicyDetail::ProviderNotAdmitted);
        assert_eq!(event.provider_id.unwrap().as_bytes(), &provider);
        assert_eq!(event.remote_addr.as_deref(), Some("127.0.0.1:8080"));
    }
    #[test]
    fn gar_violation_event_for_rate_limit_violation() {
        let client = ClientFingerprint::from_identifier("client");
        let ctx = RequestContext::new(&client, SystemTime::now(), Instant::now())
            .with_manifest_envelope(true);
        let violation = PolicyViolation::RateLimited(RateLimitError::Limited {
            retry_after: Duration::from_secs(42),
        });
        let event = build_gar_violation_event(&ctx, &violation);
        assert_eq!(event.policy, SorafsGarPolicy::RateLimit);
        assert_eq!(event.detail, SorafsGarPolicyDetail::RateLimitExceeded);
        assert_eq!(event.retry_after_seconds, Some(42));
        assert_eq!(
            event.policy_labels,
            vec!["rate_limit".to_string(), "limited".to_string()]
        );
    }
    #[test]
    fn gar_violation_event_for_missing_envelope_maps_labels() {
        let client = ClientFingerprint::from_identifier("client");
        let ctx = RequestContext::new(&client, SystemTime::now(), Instant::now());
        let violation = PolicyViolation::ManifestEnvelopeMissing;
        let event = build_gar_violation_event(&ctx, &violation);
        assert_eq!(event.policy, SorafsGarPolicy::ManifestEnvelope);
        assert_eq!(event.detail, SorafsGarPolicyDetail::ManifestEnvelopeMissing);
        assert_eq!(
            event.policy_labels,
            vec!["manifest_envelope".to_string(), "missing".to_string()]
        );
    }
    fn base_context(client: &ClientFingerprint) -> RequestContext<'_> {
        RequestContext::new(client, SystemTime::now(), Instant::now()).with_manifest_envelope(true)
    }
    #[test]
    fn request_context_host_and_region_are_canonical_by_construction() {
        let client = ClientFingerprint::from_identifier("client");
        let host = CanonicalHost::parse_authority(" CDN.Example.:443 ").expect("canonical host");
        let region = RegionCode::parse(" us ").expect("region");
        let ctx = base_context(&client)
            .with_canonical_host(host)
            .with_region(region);
        assert_eq!(ctx.canonical_host(), Some("cdn.example"));
        assert_eq!(ctx.region(), Some("US"));
        assert!(CanonicalHost::parse_authority("").is_none());
        assert!(CanonicalHost::parse_authority(&format!("{}.example", "a".repeat(254))).is_none());
        assert!(RegionCode::parse("USA").is_none());
        assert!(RegionCode::parse("U1").is_none());
    }
}
