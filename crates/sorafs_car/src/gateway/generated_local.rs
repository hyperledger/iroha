//! Exact owner-selected local intent joined to the existing native provider verifier.
//!
//! Bare certificate pins are not admission authority. Only `authenticate_current` can produce
//! the transport consumed by HTTP clients; the environment still owns finality freshness.

use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use iroha_data_model::{
    NetworkId,
    account::AccountId,
    sorafs::{
        capacity::ProviderId,
        provider_admission::discovery::account_read::VerifiedAccountReadProviderV1,
    },
};
use sorafs_manifest::{
    provider_admission::{EndpointAttestationKind, ProviderAdmissionGenesisMaterialV1},
    provider_advert::{EndpointKind, account_read::RegisteredAccountReadV1},
};

use super::{GatewayBuildError, GatewayProviderInput, Url};

const MATERIAL_MAX: usize = 64 * 1024;
const CERT_MAX: usize = 16 * 1024;
const MATERIAL_LIMITS: norito::DecodeLimits = norito::DecodeLimits::new(
    MATERIAL_MAX,
    MATERIAL_MAX,
    MATERIAL_MAX * 2,
    2 * 1024 * 1024,
    48,
);

/// Owner-selected original generated-local transport intent, without native authority.
///
/// The managed caller authenticates retained signed genesis before selecting this value. A
/// caller cannot obtain transport authority merely by providing matching-looking fields.
#[derive(Clone)]
pub struct GeneratedLocalProviderTransportV1(Arc<Original>);

struct Original {
    network: NetworkId,
    chain: String,
    provider: ProviderId,
    owner: AccountId,
    material: ProviderAdmissionGenesisMaterialV1,
    url: Url,
    socket: SocketAddr,
}

impl fmt::Debug for GeneratedLocalProviderTransportV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedLocalProviderTransportV1")
            .finish_non_exhaustive()
    }
}

/// Exact original local transport joined to an opaque current native account-read proof.
///
/// This contains no signer and grants no service activation or transaction authority. The
/// caller must repeat the current join for each new token/session, after fresh finality.
#[derive(Clone, Debug)]
pub struct AuthenticatedGeneratedLocalProviderTransportV1(GeneratedLocalProviderTransportV1);

/// Closed, redacted refusal of generated-local transport intent or native binding.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error(
    "generated local provider transport does not match its selected original and current native authority"
)]
pub struct GeneratedLocalProviderTransportErrorV1;

impl GeneratedLocalProviderTransportV1 {
    /// Select bounded original intent, without reading files, resolving DNS or sending requests.
    ///
    /// Only the fixed provider-hash `.localhost` name and its explicit original port are admitted.
    /// The sole destination is IPv4 loopback; arbitrary IP addresses and trust stores are absent.
    /// # Errors
    /// Refuses noncanonical scope, excessive material or a different generated endpoint shape.
    pub fn select(
        network_id: NetworkId,
        chain_id: &str,
        provider: ProviderId,
        owner: &AccountId,
        material: &ProviderAdmissionGenesisMaterialV1,
    ) -> Result<Self, GeneratedLocalProviderTransportErrorV1> {
        norito::core::with_decode_limits_scope(MATERIAL_LIMITS, || {
            let fail = || GeneratedLocalProviderTransportErrorV1;
            if chain_id.is_empty()
                || chain_id.len() > 256
                || chain_id.trim() != chain_id
                || chain_id.chars().any(char::is_control)
                || provider.as_bytes() == &[0; 32]
                || material.proposal.provider_id != *provider.as_bytes()
                || material.proposal.endpoints.len() != 1
                || material.retention_epoch == u64::MAX
            {
                return Err(fail());
            }
            // Bound the complete graph before the native validator or any retained graph copy.
            let _flags =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            if norito::core::encoded_frame_len(owner).map_err(|_| fail())? > 4096 {
                return Err(fail());
            }
            let length = norito::core::encoded_frame_len(material).map_err(|_| fail())?;
            if length > MATERIAL_MAX {
                return Err(fail());
            }
            material.validate().map_err(|_| fail())?;
            let endpoint = &material.proposal.endpoints[0];
            let tls = &endpoint.attestation;
            let hex = hex::encode(provider.as_bytes());
            let hostname = format!("{}.{}.localhost", &hex[..32], &hex[32..]);
            let policy =
                RegisteredAccountReadV1::from_capabilities(&material.proposal.capabilities)
                    .map_err(|_| fail())?
                    .ok_or_else(fail)?;
            let origin = policy.https_origin().map_err(|_| fail())?;
            let url = Url::parse(&format!("{origin}/")).map_err(|_| fail())?;
            let port = url
                .port_or_known_default()
                .filter(|p| *p != 0)
                .ok_or_else(fail)?;
            if endpoint.endpoint.kind != EndpointKind::Torii
                || endpoint.endpoint.host_pattern != hostname
                || tls.kind != EndpointAttestationKind::Tls
                || tls.attested_at != material.issued_at
                || tls.expires_at != material.retention_epoch
                || tls.leaf_certificate.is_empty()
                || tls.leaf_certificate.len() > CERT_MAX
                || tls.intermediate_certificates.len() != 1
                || tls.intermediate_certificates[0].is_empty()
                || tls.intermediate_certificates[0].len() > CERT_MAX
                || tls.alpn_ids != ["http/1.1"]
                || !tls.report.is_empty()
                || url.host_str() != Some(hostname.as_str())
                || url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
                || url.as_str() != format!("{origin}/")
            {
                return Err(fail());
            }
            // The shared encoder charges its exact frame once; the retained decoded graph
            // is separately charged to the same unchanged aggregate scope.
            let bytes = norito::core::to_bytes_bounded(material, length).map_err(|_| fail())?;
            let material = norito::decode_canonical_with_limits(&bytes, MATERIAL_LIMITS)
                .map_err(|_| fail())?;
            Ok(Self(Arc::new(Original {
                network: network_id,
                chain: chain_id.to_owned(),
                provider,
                owner: owner.clone(),
                material,
                url,
                socket: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            })))
        })
    }

    /// Original network choice; this accessor is not authenticated current state.
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        self.0.network
    }
    /// Original chain label; this accessor is not authenticated current state.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.0.chain
    }
    /// Exact original provider choice.
    #[must_use]
    pub fn provider_id(&self) -> ProviderId {
        self.0.provider
    }

    /// Join the exact retained original with the existing native provider proof owner.
    /// # Errors
    /// Refuses changed network, chain, owner, origin, endpoint material or admission lineage.
    pub fn authenticate_current(
        &self,
        current: &VerifiedAccountReadProviderV1,
    ) -> Result<
        AuthenticatedGeneratedLocalProviderTransportV1,
        GeneratedLocalProviderTransportErrorV1,
    > {
        let discovery = current.discovery();
        let admission = discovery.admission();
        let envelope = admission.envelope();
        let original = &self.0;
        if discovery.network_id() != original.network
            || current.chain_id() != original.chain
            || discovery.owner() != &original.owner
            || discovery.advert().body.provider_id != *original.provider.as_bytes()
            || !admission.is_genesis_material()
            || envelope.proposal != original.material.proposal
            || envelope.advert_body != original.material.advert_body
            || envelope.issued_at != original.material.issued_at
            || envelope.retention_epoch != original.material.retention_epoch
            || current.policy().https_origin().ok().as_deref()
                != Some(original.url.as_str().trim_end_matches('/'))
        {
            return Err(GeneratedLocalProviderTransportErrorV1);
        }
        Ok(AuthenticatedGeneratedLocalProviderTransportV1(self.clone()))
    }
}

impl AuthenticatedGeneratedLocalProviderTransportV1 {
    /// Exact original HTTPS root URL, including its selected nonzero port.
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.0.0.url
    }
    /// Sole original local socket; the original DNS hostname remains the TLS server name.
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        self.0.0.socket
    }
    /// Exact original CA replacing platform roots. Ordinary TLS name/time checks still apply.
    #[must_use]
    pub fn ca_certificate_der(&self) -> &[u8] {
        &self.0.0.material.proposal.endpoints[0]
            .attestation
            .intermediate_certificates[0]
    }
    /// Construct the bounded blocking control client using this exact native-joined selection.
    ///
    /// The account adapter supplies paths beneath `base_url`; no unrelated default headers,
    /// proxy, platform roots, redirect, automatic retry or DNS fallback are installed.
    /// # Errors
    /// Refuses invalid timeout or certificate material and HTTP client construction failure.
    pub fn blocking_http_client(
        &self,
        connect_timeout: std::time::Duration,
        request_timeout: std::time::Duration,
    ) -> Result<reqwest::blocking::Client, GatewayBuildError> {
        self.tls_identity().blocking_http_client(
            self.base_url(),
            self.socket_addr(),
            connect_timeout,
            request_timeout,
        )
    }
    pub(super) fn async_http_client(
        &self,
        connect_timeout: std::time::Duration,
        request_timeout: std::time::Duration,
    ) -> Result<reqwest::Client, GatewayBuildError> {
        self.tls_identity().async_http_client(
            self.base_url(),
            self.socket_addr(),
            connect_timeout,
            request_timeout,
        )
    }
    fn tls_identity(&self) -> super::generated_tls::OriginalTlsIdentity {
        super::generated_tls::OriginalTlsIdentity::new(
            self.ca_certificate_der(),
            &self.0.0.material.proposal.endpoints[0]
                .attestation
                .leaf_certificate,
        )
    }
    pub(super) fn validate_input(
        &self,
        input: &GatewayProviderInput,
    ) -> Result<Url, GatewayBuildError> {
        if input.provider_id_hex != hex::encode(self.0.0.provider.as_bytes())
            || input.base_url != self.base_url().as_str()
            || input.privacy_events_url.is_some()
        {
            return Err(GatewayBuildError::InvalidGeneratedLocalTransport);
        }
        Ok(self.base_url().clone())
    }
}

mod publication;
pub use publication::{
    GeneratedLocalPublicationHttpClientV1, GeneratedLocalPublicationTransportErrorV1,
    GeneratedLocalPublicationTransportV1,
};

#[cfg(test)]
mod tests;
