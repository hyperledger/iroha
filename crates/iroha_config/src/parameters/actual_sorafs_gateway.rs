// Gateway and control-plane quota configuration in the actual parameter scope.
/// Per-action quota configuration for `SoraFS` control-plane endpoints.
#[derive(Debug, Clone, Copy)]
pub struct SorafsQuotaWindow {
    /// Maximum events permitted within the rolling window. `None` disables the quota.
    pub max_events: Option<NonZeroU32>,
    /// Rolling window duration.
    pub window: Duration,
}
impl_default!(SorafsQuotaWindow => {
        Self {
            max_events: None,
            window: Duration::from_secs(1),
        }
});
/// Consolidated quota configuration for `SoraFS` control-plane endpoints.
#[derive(Debug, Clone, Copy)]
pub struct SorafsQuota {
    /// Quota applied to capacity declaration submissions.
    pub capacity_declaration: SorafsQuotaWindow,
    /// Quota applied to capacity telemetry reports.
    pub capacity_telemetry: SorafsQuotaWindow,
    /// Quota applied to capacity disputes raised against providers.
    pub capacity_dispute: SorafsQuotaWindow,
    /// Quota applied to proof-of-retrievability submissions.
    pub por_submission: SorafsQuotaWindow,
}
impl_default!(SorafsQuota => {
        Self {
            capacity_declaration: SorafsQuotaWindow {
                max_events: defaults::torii::SORAFS_QUOTA_DECLARATION_MAX_EVENTS
                    .and_then(NonZeroU32::new),
                window: Duration::from_secs(defaults::torii::SORAFS_QUOTA_DECLARATION_WINDOW_SECS),
            },
            capacity_telemetry: SorafsQuotaWindow {
                max_events: defaults::torii::SORAFS_QUOTA_TELEMETRY_MAX_EVENTS
                    .and_then(NonZeroU32::new),
                window: Duration::from_secs(defaults::torii::SORAFS_QUOTA_TELEMETRY_WINDOW_SECS),
            },
            capacity_dispute: SorafsQuotaWindow {
                max_events: defaults::torii::SORAFS_QUOTA_DISPUTE_MAX_EVENTS
                    .and_then(NonZeroU32::new),
                window: Duration::from_secs(defaults::torii::SORAFS_QUOTA_DISPUTE_WINDOW_SECS),
            },
            por_submission: SorafsQuotaWindow {
                max_events: defaults::torii::SORAFS_QUOTA_POR_MAX_EVENTS.and_then(NonZeroU32::new),
                window: Duration::from_secs(defaults::torii::SORAFS_QUOTA_POR_WINDOW_SECS),
            },
        }
});
/// Alias cache policy shared by Torii gateways and client helpers.
#[derive(Debug, Clone, Copy)]
pub struct SorafsAliasCachePolicy {
    /// Positive TTL for cached alias proofs.
    pub positive_ttl: Duration,
    /// Refresh window applied before the positive TTL elapses.
    pub refresh_window: Duration,
    /// Hard expiry after which stale proofs are rejected.
    pub hard_expiry: Duration,
    /// Negative cache TTL for missing aliases.
    pub negative_ttl: Duration,
    /// TTL for revoked aliases (responses returning `410 Gone`).
    pub revocation_ttl: Duration,
    /// Maximum tolerated age for alias proof bundles before rotation is required.
    pub rotation_max_age: Duration,
    /// Grace period applied after an approved successor before predecessor proofs are refused.
    pub successor_grace: Duration,
    /// Grace period applied to governance rotation events.
    pub governance_grace: Duration,
}
impl_default!(SorafsAliasCachePolicy => {
        Self {
            positive_ttl: Duration::from_secs(iroha_service_model::sorafs::DEFAULT_ALIAS_POSITIVE_TTL_SECS),
            refresh_window: Duration::from_secs(iroha_service_model::sorafs::DEFAULT_ALIAS_REFRESH_WINDOW_SECS),
            hard_expiry: Duration::from_secs(iroha_service_model::sorafs::DEFAULT_ALIAS_HARD_EXPIRY_SECS),
            negative_ttl: Duration::from_secs(iroha_service_model::sorafs::DEFAULT_ALIAS_NEGATIVE_TTL_SECS),
            revocation_ttl: Duration::from_secs(iroha_service_model::sorafs::DEFAULT_ALIAS_REVOCATION_TTL_SECS),
            rotation_max_age: Duration::from_secs(
                iroha_service_model::sorafs::DEFAULT_ALIAS_ROTATION_MAX_AGE_SECS,
            ),
            successor_grace: Duration::from_secs(
                iroha_service_model::sorafs::DEFAULT_ALIAS_SUCCESSOR_GRACE_SECS,
            ),
            governance_grace: Duration::from_secs(
                iroha_service_model::sorafs::DEFAULT_ALIAS_GOVERNANCE_GRACE_SECS,
            ),
        }
});
use iroha_service_model::soranet::{AnonymityPolicy, RolloutPhase};
/// Gateway policy configuration for `SoraFS` delivery.
#[derive(Debug, Clone)]
pub struct SorafsGateway {
    /// Require clients to attach the manifest envelope.
    pub require_manifest_envelope: bool,
    /// Enforce admission registry membership for providers.
    pub enforce_admission: bool,
    /// Enforce advertised capabilities (e.g., chunk-range fetch) before serving data.
    pub enforce_capabilities: bool,
    /// Directory containing `SoraNet` salt announcements (Norito JSON).
    pub salt_schedule_dir: Option<PathBuf>,
    /// Named static-site bindings loaded and cached when Torii starts.
    pub site_bindings: SorafsGatewaySiteBindings,
    /// Client-facing rate limit configuration.
    pub rate_limit: SorafsGatewayRateLimit,
    /// High-level rollout phase controlling default anonymity policy.
    pub rollout_phase: RolloutPhase,
    /// Optional staged anonymity policy override.
    pub anonymity_policy: Option<AnonymityPolicy>,
    /// Per-CID untrusted-host routing configuration.
    pub untrusted_hosting: SorafsGatewayUntrustedHosting,
    /// ACME automation configuration.
    pub acme: SorafsGatewayAcme,
    /// Governed signed compliance controller configuration.
    pub compliance: Option<SorafsGatewayCompliance>,
    /// Optional direct-mode override configuration.
    pub direct_mode: Option<SorafsGatewayDirectMode>,
}
impl_default!(SorafsGateway => {
        Self {
            require_manifest_envelope: defaults::sorafs::gateway::REQUIRE_MANIFEST_ENVELOPE,
            enforce_admission: defaults::sorafs::gateway::ENFORCE_ADMISSION,
            enforce_capabilities: defaults::sorafs::gateway::ENFORCE_CAPABILITIES,
            salt_schedule_dir: None,
            site_bindings: SorafsGatewaySiteBindings::default(),
            rate_limit: SorafsGatewayRateLimit::default(),
            rollout_phase: RolloutPhase::default(),
            anonymity_policy: Some(
                AnonymityPolicy::parse(defaults::sorafs::gateway::DEFAULT_ANONYMITY_POLICY)
                    .unwrap_or_else(|| RolloutPhase::default().default_anonymity_policy()),
            ),
            untrusted_hosting: SorafsGatewayUntrustedHosting::default(),
            acme: SorafsGatewayAcme::default(),
            compliance: None,
            direct_mode: None,
        }
});
impl SorafsGateway {
    /// Returns the effective anonymity policy, falling back to the rollout phase when unset.
    #[cfg(test)]
    #[must_use]
    pub fn effective_anonymity_policy(&self) -> AnonymityPolicy {
        self.anonymity_policy
            .unwrap_or_else(|| self.rollout_phase.default_anonymity_policy())
    }
}
/// Startup-only static-site binding source and resource bounds.
#[derive(Debug, Clone)]
pub struct SorafsGatewaySiteBindings {
    /// Optional absolute or traversal-free relative path to the versioned JSON document.
    pub path: Option<PathBuf>,
    /// Maximum encoded bytes read from the document.
    pub max_bytes: Bytes,
    /// Maximum number of host entries accepted from the document.
    pub max_sites: NonZeroUsize,
}
impl_default!(SorafsGatewaySiteBindings => {
        Self {
            path: defaults::sorafs::gateway::site_bindings::path(),
            max_bytes: defaults::sorafs::gateway::site_bindings::MAX_BYTES,
            max_sites: defaults::sorafs::gateway::site_bindings::MAX_SITES,
        }
});
/// Canonical CID-host suffixes for untrusted browser app delivery.
#[derive(Debug, Clone)]
pub struct SorafsGatewayCidHostSuffixes {
    /// Live-network CID-host suffix.
    pub live: String,
    /// Taira-network CID-host suffix.
    pub taira: String,
}
impl_default!(SorafsGatewayCidHostSuffixes => {
        Self {
            live: defaults::sorafs::gateway::untrusted_hosting::live_cid_host_suffix(),
            taira: defaults::sorafs::gateway::untrusted_hosting::taira_cid_host_suffix(),
        }
});
/// Configuration for serving untrusted apps on CID-derived origins.
#[derive(Debug, Clone)]
pub struct SorafsGatewayUntrustedHosting {
    /// Enable per-CID host routing.
    pub enabled: bool,
    /// Canonical live/test host suffixes used for browser delivery.
    pub cid_host_suffixes: SorafsGatewayCidHostSuffixes,
    /// Redirect path-gateway requests to the canonical CID host.
    pub path_gateway_redirect: bool,
    /// Restrict canonical redirects to browser HTML navigations.
    pub redirect_html_only: bool,
}
impl_default!(SorafsGatewayUntrustedHosting => {
        Self {
            enabled: defaults::sorafs::gateway::UNTRUSTED_HOSTING_ENABLED,
            cid_host_suffixes: SorafsGatewayCidHostSuffixes::default(),
            path_gateway_redirect: defaults::sorafs::gateway::PATH_GATEWAY_REDIRECT,
            redirect_html_only: defaults::sorafs::gateway::REDIRECT_HTML_ONLY,
        }
});
/// Constant-memory token budget applied to gateway clients.
#[derive(Debug, Clone, Copy)]
pub struct SorafsGatewayRateLimit {
    /// Maximum burst and tokens replenished per window.
    pub max_requests: Option<NonZeroU32>,
    /// Time required to replenish the complete token budget.
    pub window: Duration,
    /// Optional temporary ban duration.
    pub ban: Option<Duration>,
}
impl_default!(SorafsGatewayRateLimit => {
        Self {
            max_requests: defaults::sorafs::gateway::rate_limit::MAX_REQUESTS
                .and_then(NonZeroU32::new),
            window: defaults::sorafs::gateway::rate_limit::WINDOW,
            ban: defaults::sorafs::gateway::rate_limit::BAN,
        }
});
/// Challenge toggles for ACME automation.
#[derive(Debug, Clone, Copy)]
pub struct SorafsGatewayAcmeChallenges {
    /// Whether DNS-01 challenges should be solved.
    pub dns01: bool,
    /// Whether TLS-ALPN-01 challenges should be solved.
    pub tls_alpn_01: bool,
}
impl_default!(SorafsGatewayAcmeChallenges => {
        Self {
            dns01: defaults::sorafs::gateway::acme::DNS01,
            tls_alpn_01: defaults::sorafs::gateway::acme::TLS_ALPN_01,
        }
});
/// Exact non-secret identity expected from one injected gateway runtime provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsGatewayRuntimeProviderBinding {
    /// Stable production provider handle.
    pub provider_handle: String,
    /// Non-zero deployed adapter and public-policy revision.
    pub revision: u64,
    /// Non-zero digest of the exact public provider policy.
    pub policy_digest: [u8; 32],
}
/// ACME automation settings for TLS/ECH management.
#[derive(Debug, Clone)]
pub struct SorafsGatewayAcme {
    /// Enable ACME automation.
    pub enabled: bool,
    /// Exact runtime ACME provider identity required when automation is enabled.
    pub provider: Option<SorafsGatewayRuntimeProviderBinding>,
    /// Account email registered with the ACME provider.
    pub account_email: Option<String>,
    /// ACME directory URL.
    pub directory_url: String,
    /// Hostnames covered by certificate orders.
    pub hostnames: Vec<String>,
    /// Identifier of the DNS provider used for DNS-01 challenges.
    pub dns_provider_id: Option<String>,
    /// Renewal window applied before certificate expiry.
    pub renewal_window: Duration,
    /// Base backoff applied after failures.
    pub retry_backoff: Duration,
    /// Maximum jitter applied to retry scheduling.
    pub retry_jitter: Duration,
    /// Challenge toggles to exercise.
    pub challenges: SorafsGatewayAcmeChallenges,
    /// Initial ECH enabled state exposed via telemetry.
    pub ech_enabled: bool,
}
impl_default!(SorafsGatewayAcme => {
        Self {
            enabled: defaults::sorafs::gateway::acme::ENABLED,
            provider: None,
            account_email: defaults::sorafs::gateway::acme::account_email(),
            directory_url: defaults::sorafs::gateway::acme::directory_url(),
            hostnames: defaults::sorafs::gateway::acme::hostnames(),
            dns_provider_id: defaults::sorafs::gateway::acme::dns_provider_id(),
            renewal_window: defaults::sorafs::gateway::acme::RENEWAL_WINDOW,
            retry_backoff: defaults::sorafs::gateway::acme::RETRY_BACKOFF,
            retry_jitter: defaults::sorafs::gateway::acme::RETRY_JITTER,
            challenges: SorafsGatewayAcmeChallenges::default(),
            ech_enabled: defaults::sorafs::gateway::acme::ECH_ENABLED,
        }
});
/// One governed Ed25519 identity in the gateway compliance policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsGatewayComplianceSigner {
    /// Stable payload-free signer identifier.
    pub signer_id: String,
    /// Raw Ed25519 verifying key.
    pub public_key: [u8; 32],
}
/// One exact HTTPS host and its accepted TLS SPKI identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsGatewayComplianceFeedHost {
    /// Canonical lowercase DNS hostname.
    pub hostname: String,
    /// Accepted SHA-256 SPKI digests in canonical order.
    pub accepted_spki_sha256: Vec<[u8; 32]>,
}
/// One authenticated external compliance feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsGatewayComplianceFeed {
    /// Stable feed identifier.
    pub feed_id: String,
    /// Exact credential-free HTTPS URL.
    pub url: String,
    /// Whether every promoted catalog must bind this feed.
    pub required: bool,
    /// Exact initial/redirect host allowlist.
    pub hosts: Vec<SorafsGatewayComplianceFeedHost>,
}
/// Non-secret production policy for the governed gateway compliance controller.
#[derive(Debug, Clone)]
pub struct SorafsGatewayCompliance {
    /// Absolute durable checkpoint file path.
    pub checkpoint_path: PathBuf,
    /// Exact authenticated feed-transport identity required at runtime.
    pub feed_transport_provider: SorafsGatewayRuntimeProviderBinding,
    /// Non-zero governance policy identity.
    pub policy_id: [u8; 32],
    /// Canonical region identity for this gateway.
    pub region_id: String,
    /// Canonical gateway identity bound to one active gateway signer.
    pub gateway_id: String,
    /// Required distinct catalog approvals.
    pub catalog_threshold: u16,
    /// Canonically ordered catalog signers.
    pub catalog_signers: Vec<SorafsGatewayComplianceSigner>,
    /// Canonically ordered revoked catalog signer identifiers.
    pub revoked_catalog_signer_ids: Vec<String>,
    /// Required distinct regional-gateway acknowledgements.
    pub gateway_ack_threshold: u16,
    /// Canonically ordered regional-gateway signers.
    pub gateway_signers: Vec<SorafsGatewayComplianceSigner>,
    /// Canonically ordered revoked gateway signer identifiers.
    pub revoked_gateway_signer_ids: Vec<String>,
    /// Canonically ordered authenticated feeds.
    pub feeds: Vec<SorafsGatewayComplianceFeed>,
    /// Maximum encoded feed response bytes.
    pub max_encoded_bytes: Bytes,
    /// Maximum normalized/decompressed feed response bytes.
    pub max_decoded_bytes: Bytes,
    /// Maximum redirect count.
    pub max_redirects: u8,
    /// Maximum distinct public DNS answers.
    pub max_dns_addresses: usize,
    /// Per-connection timeout.
    pub connect_timeout: Duration,
    /// Total feed operation timeout.
    pub total_timeout: Duration,
    /// Maximum timestamp skew.
    pub max_clock_skew: Duration,
    /// Maximum age of a source feed at catalog construction.
    pub max_feed_age: Duration,
    /// Maximum signed catalog validity interval.
    pub max_catalog_validity: Duration,
    /// Maximum durable promotion/rollback history.
    pub max_history_entries: usize,
}
/// Optional direct-mode override details for gateway configuration.
#[derive(Debug, Clone)]
pub struct SorafsGatewayDirectMode {
    /// Provider identifier associated with the direct-mode override (hex).
    pub provider_id_hex: String,
    /// Chain id associated with the override.
    pub chain_id: String,
    /// Canonical hostname derived from governance inputs.
    pub canonical_host: String,
    /// Vanity hostname exposed for direct-mode tooling.
    pub vanity_host: String,
    /// Direct-CAR endpoint bound to the canonical host.
    pub direct_car_canonical: String,
    /// Direct-CAR endpoint bound to the vanity host.
    pub direct_car_vanity: String,
    /// Manifest digest tied to the override.
    pub manifest_digest_hex: String,
}
