//! Validated construction and inspection of immutable client contexts.

use super::*;

/// Mutable configuration used only before constructing an immutable [`Client`].
///
/// `build` validates authority and endpoint binding and creates a fresh
/// compatibility cache. A builder contains runtime credentials; its Debug
/// representation excludes headers and private key material.
#[derive(Clone)]
pub struct ClientBuilder {
    /// The business chain label.
    pub chain: ChainId,
    /// The genesis-lineage identity.
    pub network_id: NetworkId,
    /// The validated Torii endpoint.
    pub torii_url: Url,
    /// The address-formatting discriminant.
    pub account_chain_discriminant: u16,
    /// The configured account signing key.
    pub key_pair: KeyPair,
    /// The default transaction lifetime.
    pub transaction_ttl: Option<Duration>,
    /// The transaction finality deadline.
    pub transaction_status_timeout: Duration,
    /// The HTTP request deadline.
    pub torii_request_timeout: Duration,
    /// The configured account authority.
    pub account: AccountId,
    /// The configured HTTP headers.
    pub headers: HashMap<String, String>,
    /// The configured operator signing key.
    pub operator_key_pair: Option<KeyPair>,
    /// The transaction nonce policy.
    pub add_transaction_nonce: bool,
    /// The alias proof cache policy.
    pub alias_cache_policy: sorafs_manifest::alias_cache::AliasCachePolicy,
    /// The gateway anonymity policy.
    pub default_anonymity_policy: AnonymityPolicy,
    /// The gateway rollout phase.
    pub rollout_phase: RolloutPhase,
    /// The response wire-format preference.
    pub wire_format_preference: WireFormatPreference,
    pub(super) http_transport: Option<DefaultHttpTransport>,
    pub(super) stream_transport: Option<Arc<dyn crate::stream::StreamTransport>>,
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field(
                "torii_origin",
                &self.torii_url.origin().ascii_serialization(),
            )
            .field("network_id", &self.network_id)
            .field("account", &self.account)
            .field("headers", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ClientBuilder {
    pub(super) fn from_config(configuration: Config) -> Self {
        let Config {
            chain,
            network_id,
            account,
            account_chain_discriminant,
            torii_api_url,
            torii_request_timeout,
            key_pair,
            basic_auth,
            api_token,
            transaction_add_nonce,
            transaction_ttl,
            transaction_status_timeout,
            sorafs_alias_cache,
            sorafs_anonymity_policy,
            sorafs_rollout_phase,
        } = configuration;
        let mut headers = HashMap::new();
        if let Some(api_token) = api_token {
            headers.insert(
                String::from("X-API-Token"),
                api_token.expose_secret().to_owned(),
            );
        }
        if let Some(basic_auth) = basic_auth {
            let credentials = format!(
                "{}:{}",
                basic_auth.web_login,
                basic_auth.password.expose_secret()
            );
            let encoded =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, credentials);
            headers.insert(String::from("Authorization"), format!("Basic {encoded}"));
        }
        Self {
            chain,
            network_id,
            account,
            account_chain_discriminant,
            key_pair,
            torii_url: torii_api_url,
            torii_request_timeout,
            transaction_ttl: Some(transaction_ttl),
            transaction_status_timeout,
            add_transaction_nonce: transaction_add_nonce,
            alias_cache_policy: sorafs_alias_cache,
            default_anonymity_policy: sorafs_anonymity_policy,
            rollout_phase: sorafs_rollout_phase,
            headers,
            operator_key_pair: None,
            wire_format_preference: WireFormatPreference::default(),
            http_transport: None,
            stream_transport: None,
        }
    }

    pub(super) fn from_client(client: &Client) -> Self {
        Self {
            chain: client.chain.clone(),
            network_id: client.network_id,
            torii_url: client.torii_url.clone(),
            account_chain_discriminant: client.account_chain_discriminant,
            key_pair: client.key_pair.clone(),
            transaction_ttl: client.transaction_ttl,
            transaction_status_timeout: client.transaction_status_timeout,
            torii_request_timeout: client.torii_request_timeout,
            account: client.account.clone(),
            headers: client.headers.clone(),
            operator_key_pair: client.operator_key_pair.clone(),
            add_transaction_nonce: client.add_transaction_nonce,
            alias_cache_policy: client.alias_cache_policy,
            default_anonymity_policy: client.default_anonymity_policy,
            rollout_phase: client.rollout_phase,
            wire_format_preference: client.wire_format_preference,
            http_transport: Some(client.http_transport.clone()),
            stream_transport: Some(Arc::clone(&client.stream_transport)),
        }
    }

    /// Add default headers, retaining explicitly configured authentication.
    #[must_use]
    pub fn headers(mut self, mut headers: HashMap<String, String>) -> Self {
        // HTTP names are case-insensitive. A supplied Authorization spelling
        // must not create a second credential beside configured Basic auth.
        for name in self.headers.keys() {
            headers.retain(|candidate, _| !candidate.eq_ignore_ascii_case(name));
        }
        headers.extend(self.headers);
        self.headers = headers;
        self
    }

    /// Select the transport used by this context and all of its authority views.
    #[must_use]
    pub fn http_transport(mut self, transport: Arc<dyn crate::http::HttpTransport>) -> Self {
        self.http_transport = Some(DefaultHttpTransport::from_shared(transport));
        self
    }

    /// Select the client-owned event and block stream transport.
    #[must_use]
    pub fn stream_transport(mut self, transport: Arc<dyn crate::stream::StreamTransport>) -> Self {
        self.stream_transport = Some(transport);
        self
    }

    /// Validate the configuration and create one immutable client context.
    ///
    /// # Errors
    /// Returns a structured context error for an invalid endpoint or an account
    /// signing key that cannot represent the configured authority.
    pub fn build(mut self) -> crate::Result<Client> {
        self.torii_url = crate::config::normalize_torii_api_url(self.torii_url);
        validate_endpoint(&self.torii_url)?;
        validate_authority(&self.account, &self.key_pair)?;
        if self.account_chain_discriminant == 0 {
            return Err(AuthorityContextError::InvalidAddressDiscriminant.into());
        }
        let mut headers = HashMap::with_capacity(self.headers.len());
        for (name, value) in self.headers {
            let name = http::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| AuthorityContextError::InvalidHeaderName)?;
            http::header::HeaderValue::from_str(&value).map_err(|_| {
                AuthorityContextError::InvalidHeaderValue {
                    name: name.to_string(),
                }
            })?;
            let name = name.to_string();
            if headers.insert(name.clone(), value).is_some() {
                return Err(AuthorityContextError::DuplicateHeader { name }.into());
            }
        }
        self.headers = headers;
        let client = Client {
            chain: self.chain,
            network_id: self.network_id,
            torii_url: self.torii_url,
            account_chain_discriminant: self.account_chain_discriminant,
            key_pair: self.key_pair,
            transaction_ttl: self.transaction_ttl,
            transaction_status_timeout: self.transaction_status_timeout,
            torii_request_timeout: self.torii_request_timeout,
            account: self.account,
            headers: self.headers,
            operator_key_pair: self.operator_key_pair,
            add_transaction_nonce: self.add_transaction_nonce,
            alias_cache_policy: self.alias_cache_policy,
            default_anonymity_policy: self.default_anonymity_policy,
            rollout_phase: self.rollout_phase,
            wire_format_preference: self.wire_format_preference,
            http_transport: self.http_transport.unwrap_or_default(),
            stream_transport: self
                .stream_transport
                .unwrap_or_else(|| Arc::new(crate::stream::DefaultStreamTransport)),
            data_model_compatibility: Arc::new(Mutex::new(DataModelCompatibility::Unchecked)),
            compatibility_probe: Arc::new(CompatibilityProbeCoordinator::new()),
        };
        Ok(client)
    }
}

impl Client {
    /// Return the business chain label fixed at construction.
    #[must_use]
    pub fn chain(&self) -> &ChainId {
        &self.chain
    }

    /// Return the genesis-lineage identity fixed at construction.
    #[must_use]
    pub fn network_id(&self) -> &NetworkId {
        &self.network_id
    }

    /// Return the validated Torii endpoint fixed at construction.
    #[must_use]
    pub fn endpoint(&self) -> &Url {
        &self.torii_url
    }

    /// Return the address-formatting discriminant fixed at construction.
    #[must_use]
    pub fn account_chain_discriminant(&self) -> u16 {
        self.account_chain_discriminant
    }

    /// Return the configured account signing key fixed at construction.
    #[must_use]
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }

    /// Return the default transaction lifetime fixed at construction.
    #[must_use]
    pub fn transaction_ttl(&self) -> Option<Duration> {
        self.transaction_ttl
    }

    /// Return the transaction finality deadline fixed at construction.
    #[must_use]
    pub fn transaction_status_timeout(&self) -> Duration {
        self.transaction_status_timeout
    }

    /// Return the HTTP request deadline fixed at construction.
    #[must_use]
    pub fn torii_request_timeout(&self) -> Duration {
        self.torii_request_timeout
    }

    /// Return the configured account authority fixed at construction.
    #[must_use]
    pub fn account(&self) -> &AccountId {
        &self.account
    }

    /// Return the configured HTTP headers fixed at construction.
    #[must_use]
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Return the configured operator signing key fixed at construction.
    #[must_use]
    pub fn operator_key_pair(&self) -> Option<&KeyPair> {
        self.operator_key_pair.as_ref()
    }

    /// Return the transaction nonce policy fixed at construction.
    #[must_use]
    pub fn add_transaction_nonce(&self) -> bool {
        self.add_transaction_nonce
    }

    /// Return the alias proof cache policy fixed at construction.
    #[must_use]
    pub fn alias_cache_policy(&self) -> &sorafs_manifest::alias_cache::AliasCachePolicy {
        &self.alias_cache_policy
    }

    /// Return the gateway anonymity policy fixed at construction.
    #[must_use]
    pub fn default_anonymity_policy(&self) -> AnonymityPolicy {
        self.default_anonymity_policy
    }

    /// Return the gateway rollout phase fixed at construction.
    #[must_use]
    pub fn rollout_phase(&self) -> RolloutPhase {
        self.rollout_phase
    }

    /// Return the response wire-format preference fixed at construction.
    #[must_use]
    pub fn wire_format_preference(&self) -> WireFormatPreference {
        self.wire_format_preference
    }
}

pub(super) fn validate_endpoint(endpoint: &Url) -> core::result::Result<(), AuthorityContextError> {
    if !matches!(endpoint.scheme(), "http" | "https") {
        return Err(AuthorityContextError::UnsupportedEndpointScheme {
            scheme: endpoint.scheme().to_owned(),
        });
    }
    if endpoint.host().is_none() {
        return Err(AuthorityContextError::MissingEndpointHost);
    }
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err(AuthorityContextError::EmbeddedEndpointCredentials);
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        return Err(AuthorityContextError::EndpointHasQueryOrFragment);
    }
    Ok(())
}

pub(super) fn validate_authority(
    account: &AccountId,
    key_pair: &KeyPair,
) -> core::result::Result<AccountSigningCapability, AuthorityContextError> {
    match account.controller() {
        AccountController::Single(account_key) => {
            if account_key != key_pair.public_key() {
                return Err(AuthorityContextError::AccountSigningKeyMismatch);
            }
            Ok(AccountSigningCapability::Direct)
        }
        AccountController::Multisig(policy) => {
            if !policy
                .members()
                .iter()
                .any(|member| member.public_key() == key_pair.public_key())
            {
                return Err(AuthorityContextError::AccountSigningKeyNotMultisigMember);
            }
            Ok(AccountSigningCapability::MultisigMember)
        }
    }
}
