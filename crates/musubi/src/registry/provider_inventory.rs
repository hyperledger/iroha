//! Account-signed provider inventory requests using the publisher's exact selected authority.
use super::*;
use iroha_data_model::musubi::MusubiProviderBundleVerificationAttestationV1;
use std::time::Instant;

impl RegistrySigningClientV1 {
    #[cfg(test)]
    pub(crate) fn with_unrelated_listener_headers_for_test(&mut self) {
        let mut builder = self.client.client().to_builder();
        builder
            .headers
            .insert("Authorization".into(), "Basic unrelated".into());
        builder
            .headers
            .insert("X-API-Token".into(), "unrelated-token".into());
        self.client = Client::from_client(builder.build().unwrap()).unwrap();
    }

    /// Read one original provider inventory under the caller's unchanged finite deadline.
    /// Origin selection comes only from validated configuration; Torii credentials and custom
    /// transports are excluded when constructing the separate management client.
    pub(crate) fn provider_attestation_at(
        &self,
        endpoint: &Url,
        key: MusubiProviderBundleAttestationKeyV1,
        deadline: Instant,
    ) -> Result<Option<MusubiProviderBundleVerificationAttestationV1>, RegistryErrorV1> {
        let invalid = || {
            RegistryErrorV1::new(
                RegistryFailureClassV1::Permanent,
                "MUSUBI_PROVIDER_ATTESTATION_SELECTION_INVALID",
            )
        };
        let pending = || {
            RegistryErrorV1::new(
                RegistryFailureClassV1::Retryable,
                "MUSUBI_PROVIDER_ATTESTATION_INVENTORY_UNAVAILABLE",
            )
        };
        crate::publication_runtime::provider_inventory::parse_attestation_origin(endpoint.as_str())
            .map_err(|_| invalid())?;
        key.validate().map_err(|_| invalid())?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || remaining > Duration::from_secs(60) {
            return Err(pending());
        }
        let original = self.client.client().to_builder();
        // Construct a new ordinary SDK context instead of retaining unrelated listener headers,
        // operator keys, custom transport state or compatibility caches from another origin.
        let selected = Config {
            chain: original.chain,
            network_id: original.network_id,
            account: original.account,
            account_chain_discriminant: original.account_chain_discriminant,
            key_pair: original.key_pair,
            basic_auth: None,
            api_token: None,
            http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
            torii_api_url: endpoint.clone(),
            torii_request_timeout: remaining,
            transaction_ttl: original.transaction_ttl.unwrap_or(Duration::from_secs(60)),
            transaction_status_timeout: original.transaction_status_timeout,
            transaction_add_nonce: original.add_transaction_nonce,
            sorafs_alias_cache: original.alias_cache_policy,
            sorafs_anonymity_policy: original.default_anonymity_policy,
            sorafs_rollout_phase: original.rollout_phase,
        };
        let client = AsyncClient::builder(selected)
            .build()
            .map_err(|_| invalid())?;
        client
            .with_request_deadline(deadline)
            .get_sorafs_provider_attestation(key)
            .map_err(|_| pending())
    }
}
