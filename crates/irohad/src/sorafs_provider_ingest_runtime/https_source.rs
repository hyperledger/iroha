//! Concrete provider HTTPS byte acquisition with an explicitly injected governed grant resolver.
//!
//! The finalized ingest authorization contains no network/admission/grant credential. The resolver
//! below supplies that required authority boundary; this module never substitutes a local config
//! assertion for finalized governance. No production resolver or credential loader is installed here.
use super::VerifiedProviderIngestPayloadV1;
use iroha_config::parameters::is_production_runtime_handle;
use iroha_data_model::NetworkId;
use sorafs_car::gateway::{
    GatewayFetchConfig, GatewayFetchContext, GatewayProviderInput, GatewaySourceErrorV1,
    GatewaySourceLimitsV1,
};
use sorafs_manifest::{ManifestV1, PinPolicyConstraints, validate_manifest};
use sorafs_node::provider_ingest_runtime::{
    ProviderIngestAuthenticatedProviderSourceV1, ProviderIngestAuthenticatedSourceBindingV1,
    ProviderIngestSourceQualificationV1,
};
use sorafs_node::{
    FinalizedProviderIngestAuthorizationV1, ProviderIngestFutureV1,
    ProviderIngestMusubiArchiveFetchBindingV1, ProviderIngestSourceFetchErrorV1,
};
use std::{
    fmt,
    io::{self, Read},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Public deployment policy, passed explicitly by the existing runtime broker launcher.
#[derive(Debug, Clone)]
pub struct ProviderIngestHttpsSourceConfigV1 {
    /// Exact genesis-derived network identity.
    pub network_id: NetworkId,
    /// Independently pinned source identity and public policy revision.
    pub binding: ProviderIngestAuthenticatedSourceBindingV1,
    /// Complete metadata and temporary-payload disk resource bounds.
    pub limits: GatewaySourceLimitsV1,
    /// Nonzero connection timeout, no longer than the request timeout.
    pub connect_timeout: Duration,
    /// Nonzero HTTP deadline, no longer than the source operation deadline.
    pub request_timeout: Duration,
    /// Absolute complete operation/reader lifetime, at most 120 seconds.
    pub operation_timeout: Duration,
    /// Maximum concurrent temporary payload spools and DNS workers; between one and four.
    pub max_in_flight: usize,
}
impl ProviderIngestHttpsSourceConfigV1 {
    /// Validate bounds without network access or credential resolution.
    ///
    /// # Errors
    /// Rejects an invalid network, source binding, resource limit, timeout or concurrency bound.
    pub fn validate(&self) -> Result<(), ProviderIngestSourceFetchErrorV1> {
        if self.network_id.as_bytes()[31] & 1 != 1
            || self.binding.provider_id == [0; 32]
            || !is_production_runtime_handle(&self.binding.runtime_handle)
            || self.binding.qualification().validate().is_err()
            || self.limits.validate().is_err()
            || self.connect_timeout.is_zero()
            || self.connect_timeout > self.request_timeout
            || self.request_timeout > self.operation_timeout
            || self.operation_timeout > Duration::from_secs(120)
            || self.max_in_flight == 0
            || self.max_in_flight > 4
        {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        Ok(())
    }
}
/// Exact payload-free request presented to independently authenticated governance/grant resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestHttpsGrantRequestV1 {
    /// Configured network; never inferred from the gateway URL.
    pub network_id: NetworkId,
    /// Source provider, distinct from the destination ingest provider.
    pub source_provider_id: [u8; 32],
    /// Pinned source policy qualification.
    pub qualification: ProviderIngestSourceQualificationV1,
    /// Exact order, destination, manifest and finalized admission cursor.
    pub authorization: FinalizedProviderIngestAuthorizationV1,
    /// Exact optional informational archive binding, checked against authorization.
    pub musubi_archive: Option<ProviderIngestMusubiArchiveFetchBindingV1>,
}
/// Payload-free lease retained until native ingest consumes authenticated EOF.
#[derive(Debug, Clone)]
pub struct ProviderIngestHttpsSourceLeaseV1 {
    /// Exact independently authorized request.
    pub request: ProviderIngestHttpsGrantRequestV1,
    /// Complete canonical manifest obtained from authenticated finalized state.
    pub manifest: ManifestV1,
    /// Opaque nonzero grant identity checked by the resolver on every use and EOF.
    pub grant_id: [u8; 32],
    /// Current governance-admitted signed advert digest, checked against resolver state.
    pub advert_digest: [u8; 32],
    /// Exact nonzero assignment revision observed by the finalized resolver.
    pub assignment_revision: u64,
    /// Fixed Unix expiry; never extended by successful byte delivery.
    pub expires_at_unix_ms: u64,
}
/// Runtime-only grant; secrets and source locations are excluded from `Debug` and durable state.
pub struct ProviderIngestHttpsGrantV1 {
    /// Public exact authorization lease.
    pub lease: ProviderIngestHttpsSourceLeaseV1,
    /// Current advertised endpoint, provider signing-key pin and signed bounded stream token.
    pub provider: GatewayProviderInput,
    /// Independently pinned source TLS roots in DER; replaces platform roots, with no fallback.
    pub tls_roots_der: Vec<Vec<u8>>,
}
impl fmt::Debug for ProviderIngestHttpsGrantV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIngestHttpsGrantV1")
            .field("lease", &self.lease)
            .field("transport", &"<runtime-only>")
            .finish_non_exhaustive()
    }
}
/// Required independently authenticated source-governance and stream-grant service.
///
/// Production resolution must read the exact network's finalized assignment and current admitted
/// signed advert, verify source membership, owner/key rotation, revocation, endpoint/TLS roots,
/// signing-key pin and token grant. A caller-provided manifest, advert or config assertion is not
/// sufficient evidence. This contract supplies authority absent from the ingest authorization.
/// Implementations must never log endpoints, credentials or token material.
pub trait ProviderIngestGovernedHttpsGrantResolverV1: Send + Sync + 'static {
    /// Nonblocking authenticated current source-policy qualification.
    ///
    /// # Errors
    /// Refuses an unqualified source or unavailable authenticated policy snapshot.
    fn qualification(
        &self,
        network: &NetworkId,
        provider: [u8; 32],
    ) -> Result<ProviderIngestSourceQualificationV1, ProviderIngestSourceFetchErrorV1>;
    /// Non-mutating authenticated readiness; no grant issuance or storage mutation.
    ///
    /// # Errors
    /// Refuses unavailable source readiness or a network/provider binding mismatch.
    fn check_readiness(
        &self,
        network: &NetworkId,
        provider: [u8; 32],
    ) -> Result<(), ProviderIngestSourceFetchErrorV1>;
    /// Resolve the exact finalized request to an authenticated bounded transport grant.
    fn resolve(
        &self,
        request: ProviderIngestHttpsGrantRequestV1,
    ) -> ProviderIngestFutureV1<
        '_,
        Result<ProviderIngestHttpsGrantV1, ProviderIngestSourceFetchErrorV1>,
    >;
    /// Nonblocking check against current independently authenticated snapshots.
    ///
    /// Recheck network/order membership, lease/admission/advert/owner/key revocation and expiry.
    /// The snapshot must be authenticated and sufficiently fresh for the configured policy;
    /// unavailable or stale snapshots must fail closed. Called before fetch, after fetch and EOF.
    ///
    /// # Errors
    /// Refuses expired, revoked or changed lease evidence and unavailable current snapshots.
    fn ensure_current(
        &self,
        lease: &ProviderIngestHttpsSourceLeaseV1,
    ) -> Result<(), ProviderIngestSourceFetchErrorV1>;
}
/// Concrete HTTPS leaf for the existing `ProviderIngestAuthenticatedSourcePoolV1`.
///
/// No implicit endpoint, signer, credential loader, trust root or resolver is installed.
pub struct ProviderIngestHttpsSourceV1 {
    config: ProviderIngestHttpsSourceConfigV1,
    resolver: Arc<dyn ProviderIngestGovernedHttpsGrantResolverV1>,
    admissions: Arc<Semaphore>,
}
impl fmt::Debug for ProviderIngestHttpsSourceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIngestHttpsSourceV1")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}
impl ProviderIngestHttpsSourceV1 {
    /// Build the concrete leaf from independently configured policy and an injected resolver.
    ///
    /// This performs public-policy qualification only; pool readiness still requires the real
    /// resolver's non-mutating authenticated probe. Construction never issues a grant.
    ///
    /// # Errors
    /// Refuses invalid configured bounds, an unavailable resolver or a mismatched qualification.
    pub fn new(
        config: ProviderIngestHttpsSourceConfigV1,
        resolver: Arc<dyn ProviderIngestGovernedHttpsGrantResolverV1>,
    ) -> Result<Self, ProviderIngestSourceFetchErrorV1> {
        config.validate()?;
        let admissions = Arc::new(Semaphore::new(config.max_in_flight));
        Self::new_with_admissions(config, resolver, admissions)
    }
    /// Compose multiple leaves under one catalog-bound retained-payload budget.
    pub(super) fn new_with_admissions(
        config: ProviderIngestHttpsSourceConfigV1,
        resolver: Arc<dyn ProviderIngestGovernedHttpsGrantResolverV1>,
        admissions: Arc<Semaphore>,
    ) -> Result<Self, ProviderIngestSourceFetchErrorV1> {
        config.validate()?;
        if resolver.qualification(&config.network_id, config.binding.provider_id)?
            != config.binding.qualification()
        {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        Ok(Self {
            config,
            resolver,
            admissions,
        })
    }
    async fn acquire(
        &self,
        request: ProviderIngestHttpsGrantRequestV1,
        deadline: Instant,
        permit: OwnedSemaphorePermit,
    ) -> Result<VerifiedProviderIngestPayloadV1, ProviderIngestSourceFetchErrorV1> {
        let grant = self.resolver.resolve(request.clone()).await?;
        validate_grant(&self.config, &request, &grant)?;
        ensure_current(&self.config, self.resolver.as_ref(), &grant.lease, deadline)?;
        let config = GatewayFetchConfig {
            manifest_id_hex: hex::encode(request.authorization.manifest_digest()),
            chunker_handle: request.authorization.chunker_handle().to_owned(),
            manifest_envelope_b64: None,
            client_id: None,
            expected_manifest_cid_hex: Some(hex::encode(request.authorization.manifest_cid())),
            blinded_cid_b64: None,
            salt_epoch: None,
            expected_cache_version: None,
        };
        let connect_timeout = self.config.connect_timeout;
        let request_timeout = self.config.request_timeout;
        let lease = grant.lease;
        // DNS uses the system resolver. Keep its retained admission inside the blocking worker;
        // timing out this future cannot create unbounded detached resolver jobs.
        let (context, permit) = build_gateway_context_recoverably(move || {
            let context = GatewayFetchContext::new_with_pinned_tls_roots(
                config,
                [grant.provider],
                connect_timeout,
                request_timeout,
                &grant.tls_roots_der,
            )
            .map_err(|_| ProviderIngestSourceFetchErrorV1::Rejected);
            (context, permit)
        })
        .await?;
        let context = context?;
        ensure_current(&self.config, self.resolver.as_ref(), &lease, deadline)?;
        let verified = context
            .fetch_verified_payload_v1(&lease.manifest, self.config.limits)
            .await
            .map_err(|error| match error {
                GatewaySourceErrorV1::Unavailable => ProviderIngestSourceFetchErrorV1::Unavailable,
                GatewaySourceErrorV1::Bounds | GatewaySourceErrorV1::ContentRejected => {
                    ProviderIngestSourceFetchErrorV1::ContentRejected
                }
            })?;
        ensure_current(&self.config, self.resolver.as_ref(), &lease, deadline)?;
        let (manifest, plan, payload) = verified.into_parts();
        let reader = LeaseCheckedReader {
            reader: Box::new(payload),
            config: self.config.clone(),
            resolver: Arc::clone(&self.resolver),
            lease,
            deadline,
            _permit: permit,
            failed: false,
        };
        Ok(VerifiedProviderIngestPayloadV1::new(
            manifest,
            plan,
            Box::new(reader),
        ))
    }
}
impl ProviderIngestAuthenticatedProviderSourceV1 for ProviderIngestHttpsSourceV1 {
    type Fetched = VerifiedProviderIngestPayloadV1;
    fn provider_id(&self) -> [u8; 32] {
        self.config.binding.provider_id
    }
    fn runtime_handle(&self) -> &str {
        &self.config.binding.runtime_handle
    }
    fn qualification(
        &self,
    ) -> Result<ProviderIngestSourceQualificationV1, ProviderIngestSourceFetchErrorV1> {
        let actual = self
            .resolver
            .qualification(&self.config.network_id, self.provider_id())?;
        if actual != self.config.binding.qualification() {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        Ok(actual)
    }
    fn check_readiness(&self) -> Result<(), ProviderIngestSourceFetchErrorV1> {
        self.qualification()?;
        self.resolver
            .check_readiness(&self.config.network_id, self.provider_id())?;
        self.qualification().map(|_| ())
    }
    fn fetch_provider(
        &self,
        authorization: FinalizedProviderIngestAuthorizationV1,
        musubi_archive: Option<ProviderIngestMusubiArchiveFetchBindingV1>,
    ) -> ProviderIngestFutureV1<'_, Result<Self::Fetched, ProviderIngestSourceFetchErrorV1>> {
        Box::pin(async move {
            authorization
                .validate()
                .map_err(|_| ProviderIngestSourceFetchErrorV1::Rejected)?;
            if authorization.provider_id() == self.provider_id()
                || authorization.content_length() > self.config.limits.max_payload_bytes
                || match (authorization.musubi_context(), musubi_archive.as_ref()) {
                    (None, None) => false,
                    (Some(_), Some(binding)) => {
                        !binding.matches_authorization(&authorization)
                            || binding.network_id() != &self.config.network_id
                    }
                    _ => true,
                }
            {
                return Err(ProviderIngestSourceFetchErrorV1::Rejected);
            }
            self.qualification()?;
            let request = ProviderIngestHttpsGrantRequestV1 {
                network_id: self.config.network_id,
                source_provider_id: self.provider_id(),
                qualification: self.config.binding.qualification(),
                authorization,
                musubi_archive,
            };
            let permit = Arc::clone(&self.admissions)
                .try_acquire_owned()
                .map_err(|_| ProviderIngestSourceFetchErrorV1::Unavailable)?;
            let deadline = Instant::now()
                .checked_add(self.config.operation_timeout)
                .ok_or(ProviderIngestSourceFetchErrorV1::Rejected)?;
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.acquire(request, deadline, permit),
            )
            .await
            .map_err(|_| ProviderIngestSourceFetchErrorV1::Unavailable)?
        })
    }
}
/// Reusable exact request/manifest binding check for governed evidence composition.
pub(super) fn validate_grant(
    config: &ProviderIngestHttpsSourceConfigV1,
    request: &ProviderIngestHttpsGrantRequestV1,
    grant: &ProviderIngestHttpsGrantV1,
) -> Result<(), ProviderIngestSourceFetchErrorV1> {
    let authorization = &request.authorization;
    let manifest = &grant.lease.manifest;
    if grant.lease.request != *request
        || request.network_id != config.network_id
        || request.source_provider_id != config.binding.provider_id
        || request.qualification != config.binding.qualification()
        || grant.lease.grant_id == [0; 32]
        || grant.lease.advert_digest == [0; 32]
        || grant.lease.assignment_revision == 0
        || grant.provider.provider_id_hex != hex::encode(config.binding.provider_id)
        || grant.provider.privacy_events_url.is_some()
        || validate_manifest(manifest, &PinPolicyConstraints::default()).is_err()
        || manifest
            .digest()
            .map(|digest| digest.as_bytes() != &authorization.manifest_digest())
            .unwrap_or(true)
        || manifest.root_cid != authorization.manifest_cid()
        || manifest.content_length != authorization.content_length()
        || manifest.content_length > config.limits.max_payload_bytes
        || manifest.chunk_digest_sha3_256 != authorization.chunk_digest_sha3_256()
        || manifest.por_root != authorization.por_root()
        || format!(
            "{}.{}@{}",
            manifest.chunking.namespace, manifest.chunking.name, manifest.chunking.semver
        ) != authorization.chunker_handle()
        || grant.tls_roots_der.is_empty()
        || grant.tls_roots_der.len() > 4
        || grant
            .tls_roots_der
            .iter()
            .any(|root| root.is_empty() || root.len() > 16 * 1024)
    {
        return Err(ProviderIngestSourceFetchErrorV1::Rejected);
    }
    Ok(())
}
fn ensure_current(
    config: &ProviderIngestHttpsSourceConfigV1,
    resolver: &dyn ProviderIngestGovernedHttpsGrantResolverV1,
    lease: &ProviderIngestHttpsSourceLeaseV1,
    deadline: Instant,
) -> Result<(), ProviderIngestSourceFetchErrorV1> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProviderIngestSourceFetchErrorV1::Unavailable)?;
    if Instant::now() >= deadline
        || now.as_millis() >= u128::from(lease.expires_at_unix_ms)
        || resolver.qualification(&config.network_id, config.binding.provider_id)?
            != config.binding.qualification()
    {
        return Err(ProviderIngestSourceFetchErrorV1::Rejected);
    }
    resolver.ensure_current(lease)
}
struct LeaseCheckedReader {
    reader: Box<dyn Read + Send>,
    config: ProviderIngestHttpsSourceConfigV1,
    resolver: Arc<dyn ProviderIngestGovernedHttpsGrantResolverV1>,
    lease: ProviderIngestHttpsSourceLeaseV1,
    deadline: Instant,
    _permit: OwnedSemaphorePermit,
    failed: bool,
}
impl Read for LeaseCheckedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.failed
            || ensure_current(
                &self.config,
                self.resolver.as_ref(),
                &self.lease,
                self.deadline,
            )
            .is_err()
        {
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "provider source lease is no longer current",
            ));
        }
        self.reader.read(output)
    }
}
async fn build_gateway_context_recoverably<F, T>(
    operation: F,
) -> Result<T, ProviderIngestSourceFetchErrorV1>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    crate::panic_recovery::join_recoverable(crate::panic_recovery::spawn_blocking_recoverable(
        operation,
    ))
    .await
    .map_err(|_| ProviderIngestSourceFetchErrorV1::Unavailable)
}

#[cfg(test)]
mod tests;
