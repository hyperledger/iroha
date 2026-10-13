//! A separate, purpose-bound publication transport; TLS intent is never native authority.

use super::*;
use std::time::Duration;

/// Original generated private-publication transport intent, without native service authority.
///
/// The caller authenticates the retained generated plan before selection. The original provider
/// certificate identity is shared, but this listener has its own explicit port. Account-read
/// capability is used only to exclude its port, never to authorize publication or provider tokens.
#[derive(Clone)]
pub struct GeneratedLocalPublicationTransportV1 {
    original: GeneratedLocalProviderTransportV1,
    url: Url,
    socket: SocketAddr,
}

impl fmt::Debug for GeneratedLocalPublicationTransportV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedLocalPublicationTransportV1")
            .finish_non_exhaustive()
    }
}

/// Closed refusal of private-publication transport selection, destination or TLS exchange.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("generated private publication transport refused its selection or exchange")]
pub struct GeneratedLocalPublicationTransportErrorV1;

impl GeneratedLocalPublicationTransportV1 {
    /// Select an original publication listener without I/O or a native authority claim.
    ///
    /// # Errors
    /// Refuses malformed original material, a zero port or reuse of the provider data port.
    pub fn select(
        network: NetworkId,
        chain: &str,
        provider: ProviderId,
        owner: &AccountId,
        material: &ProviderAdmissionGenesisMaterialV1,
        publication_port: u16,
    ) -> Result<Self, GeneratedLocalPublicationTransportErrorV1> {
        // This is the shared bounded original-intent parser, not authenticate_current. No
        // account-read proof or token client is created or widened by this selection.
        let original =
            GeneratedLocalProviderTransportV1::select(network, chain, provider, owner, material)
                .map_err(|_| GeneratedLocalPublicationTransportErrorV1)?;
        if publication_port == 0 || publication_port == original.0.socket.port() {
            return Err(GeneratedLocalPublicationTransportErrorV1);
        }
        let mut url = original.0.url.clone();
        url.set_port(Some(publication_port))
            .map_err(|_| GeneratedLocalPublicationTransportErrorV1)?;
        Ok(Self {
            original,
            url,
            socket: SocketAddr::from((Ipv4Addr::LOCALHOST, publication_port)),
        })
    }

    /// Original network identity, without a current-state claim.
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        self.original.network_id()
    }
    /// Original business chain label.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        self.original.chain_id()
    }
    /// Original provider supplying this listener's TLS identity.
    #[must_use]
    pub fn provider_id(&self) -> ProviderId {
        self.original.provider_id()
    }
    /// Original provider owner selected independently from the publication signer.
    /// This identity is intent only; current native ownership remains separately verified.
    #[must_use]
    pub fn provider_owner(&self) -> &AccountId {
        &self.original.0.owner
    }
    /// Exact publication HTTPS root, including the separately selected listener port.
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.url
    }
    /// Require the exact original root before any application authorization is signed.
    /// # Errors
    /// Refuses other origins, base paths, credentials, query strings or fragments.
    pub fn validate_base_url(
        &self,
        base: &Url,
    ) -> Result<(), GeneratedLocalPublicationTransportErrorV1> {
        if base != &self.url {
            return Err(GeneratedLocalPublicationTransportErrorV1);
        }
        Ok(())
    }
    /// Require an endpoint under the original private-publication root.
    ///
    /// The service client separately owns its fixed route inventory and native authorization.
    /// # Errors
    /// Refuses another origin, credentials, query/fragment or a non-publication path.
    pub fn validate_endpoint(
        &self,
        endpoint: &Url,
    ) -> Result<(), GeneratedLocalPublicationTransportErrorV1> {
        if endpoint.origin() != self.url.origin()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !endpoint.path().starts_with("/v1/musubi/publication/")
            || endpoint.path() == "/v1/musubi/publication/"
        {
            return Err(GeneratedLocalPublicationTransportErrorV1);
        }
        Ok(())
    }
    /// Consume this selection into a guarded client with fixed loopback resolution and the
    /// sole original TLS verifier.
    ///
    /// No raw HTTP client, request builder, alternate resolver or custom root API is exposed.
    /// # Errors
    /// Refuses zero timeout, invalid original TLS material or client construction failure.
    pub fn blocking_client(
        self,
        timeout: Duration,
    ) -> Result<GeneratedLocalPublicationHttpClientV1, GeneratedLocalPublicationTransportErrorV1>
    {
        let tls = &self.original.0.material.proposal.endpoints[0].attestation;
        let identity = super::super::generated_tls::OriginalTlsIdentity::new(
            &tls.intermediate_certificates[0],
            &tls.leaf_certificate,
        );
        let http = identity
            .blocking_http_client(&self.url, self.socket, timeout, timeout)
            .map_err(|_| GeneratedLocalPublicationTransportErrorV1)?;
        Ok(GeneratedLocalPublicationHttpClientV1 {
            selection: self,
            http,
            timeout,
        })
    }
}

/// A publication HTTP owner which cannot send outside its selected private origin.
#[derive(Clone)]
pub struct GeneratedLocalPublicationHttpClientV1 {
    selection: GeneratedLocalPublicationTransportV1,
    http: reqwest::blocking::Client,
    timeout: Duration,
}
impl fmt::Debug for GeneratedLocalPublicationHttpClientV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedLocalPublicationHttpClientV1")
            .finish_non_exhaustive()
    }
}
impl GeneratedLocalPublicationHttpClientV1 {
    /// Borrow the immutable original transport intent.
    #[must_use]
    pub fn selection(&self) -> &GeneratedLocalPublicationTransportV1 {
        &self.selection
    }

    /// Send once after checking the exact selected destination immediately before execution.
    ///
    /// The original finite timeout replaces caller request overrides. Native authorization and
    /// response bounds remain owned by the publication service client.
    /// # Errors
    /// Refuses a foreign endpoint, non-POST method, caller-supplied Host header or TLS/HTTP error.
    pub fn execute(
        &self,
        mut request: reqwest::blocking::Request,
    ) -> Result<reqwest::blocking::Response, GeneratedLocalPublicationTransportErrorV1> {
        self.selection.validate_endpoint(request.url())?;
        if request.method() != reqwest::Method::POST
            || request.headers().contains_key(reqwest::header::HOST)
        {
            return Err(GeneratedLocalPublicationTransportErrorV1);
        }
        // A public Request cannot weaken the original finite client budget.
        *request.timeout_mut() = Some(self.timeout);
        self.http
            .execute(request)
            .map_err(|_| GeneratedLocalPublicationTransportErrorV1)
    }
}
