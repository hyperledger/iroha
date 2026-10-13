//! Reusable checks over independently authenticated source evidence and already-issued grants.
//!
//! This adapter is not a grant resolver or a finality verifier. It composes existing native
//! request, council admission and current cached-advert types. Callers must obtain the request,
//! assignment revision, fresh snapshots and transport pins from their authoritative services.
use super::https_source::{
    ProviderIngestHttpsGrantRequestV1, ProviderIngestHttpsGrantV1,
    ProviderIngestHttpsSourceConfigV1, validate_grant,
};
use crate::sorafs_provider_ingest_finalized_query::ArchivedProviderIngestFinalizedLedgerV1;
use iroha_data_model::NetworkId;
use iroha_torii::sorafs::{AdmissionRegistry, discovery::ProviderAdvertCache};
use sorafs_manifest::{CapabilityType, EndpointKind, verify_advert_against_record};
use sorafs_node::{
    ProviderIngestSourceFetchErrorV1, provider_ingest_runtime::ProviderIngestSourceRequestV1,
};
use std::fmt;

/// Independently governed runtime transport pins, never inferred from a candidate grant.
///
/// Admission advert keys authenticate adverts; they do not automatically authorize stream-token
/// signing. Advert TLS fingerprint hints identify leaf certificates; they are not DER trust roots.
/// The exact source origin, token issuer key and root set require their own governed binding.
pub struct ProviderIngestHttpsTransportPinsV1 {
    /// Exact network under which the authority authenticated these pins.
    pub network_id: NetworkId,
    /// Exact source provider whose authority owns this transport.
    pub provider_id: [u8; 32],
    /// Current council-verified admission envelope digest.
    pub admission_envelope_digest: [u8; 32],
    /// Current complete signed-advert fingerprint from the replay-protected cache.
    pub advert_digest: [u8; 32],
    /// Exact root HTTPS origin, with no path prefix, credentials, query or fragment.
    pub origin: String,
    /// Independently approved stream-token verification key; distinct from the advert key role.
    pub stream_token_public_key: [u8; 32],
    /// Exact ordered DER roots authorized for this origin, replacing platform roots.
    pub tls_roots_der: Vec<Vec<u8>>,
}
impl fmt::Debug for ProviderIngestHttpsTransportPinsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIngestHttpsTransportPinsV1")
            .field("network_id", &self.network_id)
            .field("provider_id", &self.provider_id)
            .field("transport", &"<runtime-only>")
            .finish_non_exhaustive()
    }
}

/// Borrowed evidence selected atomically by an independently authenticated resolver boundary.
///
/// These values are evidence inputs, not an authentication capability. Native source requests
/// have canonical fields but do not carry their own finality proof or grant authority. The
/// resolver must authenticate snapshots and recheck current revocation for every lease use.
#[derive(Clone, Copy)]
pub struct ProviderIngestHttpsEvidenceV1<'a> {
    /// Exact fresh finalized request, including the canonical permitted source inventory.
    pub source_request: &'a ProviderIngestSourceRequestV1,
    /// Current exact assignment revision obtained alongside that finalized request.
    pub assignment_revision: u64,
    /// Nonzero identity of the already-issued grant authorized for this request.
    pub grant_id: [u8; 32],
    /// Inclusive start of this authenticated snapshot's validity, in Unix milliseconds.
    pub observed_at_unix_ms: u64,
    /// Exclusive end of this authenticated snapshot's fixed validity window.
    pub valid_until_unix_ms: u64,
    /// Current registry, including renewals and revocations; stale cached admission is insufficient.
    pub admission: &'a AdmissionRegistry,
    /// Current admitted signed-advert cache, with externally qualified replay persistence.
    pub adverts: &'a ProviderAdvertCache,
    /// Independently authenticated transport pins for this exact network/source/advert.
    pub transport: &'a ProviderIngestHttpsTransportPinsV1,
}
impl fmt::Debug for ProviderIngestHttpsEvidenceV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIngestHttpsEvidenceV1")
            .field("assignment_revision", &self.assignment_revision)
            .field("observed_at_unix_ms", &self.observed_at_unix_ms)
            .field("valid_until_unix_ms", &self.valid_until_unix_ms)
            .field("authority_inputs", &"<runtime-only>")
            .finish()
    }
}

/// Check already-issued grant evidence against the live State/Kura-qualified assignment twice.
///
/// This is a non-authorizing local validation step. The admission registry, advert cache, pins,
/// grant, and clock must still come from separately authenticated, revocation-fresh services;
/// this check does not make those inputs final or issue a grant. A production resolver must
/// authenticate the immutable admission cursor's historical ancestry and current revocation, then
/// independently repeat its full currentness check before fetch, after fetch, and at reader EOF.
/// The two assignment reads reject a finalized-head or revision change during this observation.
///
/// # Errors
///
/// Fails closed when the current assignment cannot be read, differs from the request or grant,
/// changes during the observation, or the independently supplied evidence fails validation.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "awaits independently governed HTTPS grant resolver"
    )
)]
pub(crate) fn validate_provider_ingest_current_https_evidence_v1(
    finalized: &ArchivedProviderIngestFinalizedLedgerV1,
    config: &ProviderIngestHttpsSourceConfigV1,
    evidence: &ProviderIngestHttpsEvidenceV1<'_>,
    grant: &ProviderIngestHttpsGrantV1,
    now_unix_ms: u64,
) -> Result<(), ProviderIngestSourceFetchErrorV1> {
    finalized.validate_with_current_source_request(
        config.network_id,
        config.binding.provider_id,
        evidence.source_request,
        evidence.assignment_revision,
        || validate_provider_ingest_https_evidence_v1(config, evidence, grant, now_unix_ms),
    )
}

/// Validate native source/admission/advert/transport bindings before accepting an issued grant.
///
/// This performs no network access, grant issuance, signing or mutation. It does not authenticate
/// the caller's snapshots, establish finality or assert readiness. The HTTPS leaf subsequently
/// performs canonical token decoding/signature/budget checks and TLS/public-DNS enforcement.
///
/// # Errors
///
/// Rejects substituted network, source inventory, assignment, grant, manifest, cached advert,
/// expired/revoked council admission, unsupported endpoint, issuer key or trust roots. Snapshot
/// and grant lifetimes cannot exceed the explicitly configured operation deadline.
pub fn validate_provider_ingest_https_evidence_v1(
    config: &ProviderIngestHttpsSourceConfigV1,
    evidence: &ProviderIngestHttpsEvidenceV1<'_>,
    grant: &ProviderIngestHttpsGrantV1,
    now_unix_ms: u64,
) -> Result<(), ProviderIngestSourceFetchErrorV1> {
    let rejected = ProviderIngestSourceFetchErrorV1::Rejected;
    config.validate()?;
    let pins = evidence.transport;
    let request = evidence.source_request;
    let source = config.binding.provider_id;
    if pins.network_id != config.network_id
        || pins.provider_id != source
        || request
            .source_provider_ids()
            .binary_search(&source)
            .is_err()
        || evidence.assignment_revision == 0
        || evidence.assignment_revision != grant.lease.assignment_revision
        || evidence.grant_id == [0; 32]
        || evidence.grant_id != grant.lease.grant_id
        || evidence.observed_at_unix_ms > now_unix_ms
        || evidence.valid_until_unix_ms <= now_unix_ms
        || u128::from(
            evidence
                .valid_until_unix_ms
                .saturating_sub(evidence.observed_at_unix_ms),
        ) > config.operation_timeout.as_millis()
        || grant.lease.expires_at_unix_ms <= now_unix_ms
        || grant.lease.expires_at_unix_ms > evidence.valid_until_unix_ms
        || pins.stream_token_public_key == [0; 32]
        || grant.provider.gateway_public_key_hex != hex::encode(pins.stream_token_public_key)
        || grant.provider.base_url != pins.origin
        || grant.tls_roots_der != pins.tls_roots_der
    {
        return Err(rejected);
    }
    validate_grant(
        config,
        &ProviderIngestHttpsGrantRequestV1 {
            network_id: config.network_id,
            source_provider_id: source,
            qualification: config.binding.qualification(),
            authorization: request.authorization().clone(),
            musubi_archive: request.musubi_archive().cloned(),
        },
        grant,
    )?;
    let admission = evidence.admission.entry(&source).ok_or(rejected)?;
    let cached = evidence
        .adverts
        .record_by_provider(&source)
        .ok_or(rejected)?;
    let advert = cached.advert();
    let now_seconds = now_unix_ms / 1000;
    if !(admission.is_council_verified() || admission.is_genesis_material())
        || admission.envelope_digest() != &pins.admission_envelope_digest
        || cached.fingerprint() != &pins.advert_digest
        || grant.lease.advert_digest != pins.advert_digest
        || now_seconds < admission.envelope().issued_at
        || now_seconds >= admission.envelope().retention_epoch
        || now_seconds >= advert.expires_at
        || u128::from(grant.lease.expires_at_unix_ms) > u128::from(advert.expires_at) * 1000
        || !advert.signature_strict
        || advert.validate_with_body(now_seconds).is_err()
        || advert.verify_signature().is_err()
        || verify_advert_against_record(advert, &admission).is_err()
        || advert.body.profile_id != request.authorization().chunker_handle()
        || !cached
            .known_capabilities()
            .contains(&CapabilityType::ToriiGateway)
        || !cached
            .known_capabilities()
            .contains(&CapabilityType::ChunkRangeFetch)
    {
        return Err(rejected);
    }
    let origin = reqwest::Url::parse(&pins.origin).map_err(|_| rejected)?;
    if origin.as_str() != pins.origin
        || origin.scheme() != "https"
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.path() != "/"
        || origin.host_str().is_none()
        // The gateway transport accepts only HTTPS on its canonical port. Evidence must not
        // approve an origin that its own fetcher will reject after grant resolution.
        || origin.port_or_known_default() != Some(443)
    {
        return Err(rejected);
    }
    let authority = match origin.port() {
        Some(port) => format!("{}:{port}", origin.host_str().ok_or(rejected)?),
        None => origin.host_str().ok_or(rejected)?.to_owned(),
    };
    // An exact advertised authority is required. Wildcards, URL rewrites and alternate port
    // spellings cannot silently broaden admission; public-address/TLS checks remain in the leaf.
    if !advert
        .body
        .endpoints
        .iter()
        .any(|endpoint| endpoint.kind == EndpointKind::Torii && endpoint.host_pattern == authority)
    {
        return Err(rejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
