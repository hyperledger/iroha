//! Lazy account read adapter over the canonical authenticated archive transport.
//!
//! The environment owns fresh finality and the qualified native schema. Only its portable
//! verified provider result can select an origin or token key. Every token mint reobserves
//! that authority through the same callback; planning retains no stale token verification key.
//! Parent listener tokens, basic
//! authentication, and unrelated default headers are never forwarded to provider origins.
use super::*;
use iroha_data_model::{
    account::AccountId,
    sorafs::provider_admission::discovery::account_read::VerifiedAccountReadProviderV1,
};

/// Closed failure classes from the environment's independently bound provider discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MusubiArchiveDiscoveryErrorV1 {
    /// Current authenticated state or its approved endpoint is temporarily unavailable.
    Unavailable,
    /// Returned state or policy failed exact native authentication.
    Rejected,
    /// The caller's finite overall deadline expired.
    Deadline,
}
/// Caller-owned fresh finality and native provider discovery, evaluated for each origin resolution,
/// plan selection, and token mint. A cached transport never replaces current native authority.
pub type MusubiArchiveProviderDiscoveryV1 = dyn Fn(ProviderId) -> Result<VerifiedAccountReadProviderV1, MusubiArchiveDiscoveryErrorV1>
    + Send
    + Sync;

#[derive(Clone)]
pub(super) struct AccountRegistryV1 {
    pub(super) account: AccountId,
    pub(super) key_pair: KeyPair,
    pub(super) chain_id: String,
    pub(super) local_transports: Option<[GeneratedLocalProviderTransportV1; 3]>,
    // Drop selections before the callback and any original allocation custody it retains.
    pub(super) discovery: Arc<MusubiArchiveProviderDiscoveryV1>,
}
#[derive(Clone)]
pub(super) enum ProviderCredentialV1 {
    Operator(KeyPair),
    Account {
        account: AccountId,
        key_pair: KeyPair,
        chain_id: String,
        discovery: Arc<MusubiArchiveProviderDiscoveryV1>,
    },
}

impl PreparedMusubiArchiveFetchConfigV1 {
    /// Borrow the original ordinary account signer only for the exact three-provider local selection.
    /// This reads retained intent only, performs no discovery and grants no current authority.
    #[must_use]
    pub fn generated_local_registry_identity(&self) -> Option<(&str, &AccountId)> {
        let registry = self.account_registry.as_ref()?;
        registry.local_transports.as_ref()?;
        Some((&registry.chain_id, &registry.account))
    }

    /// Bind account reads to a separately resolved registry signer and authenticated discovery.
    ///
    /// This opens no keys, resolves no DNS and sends no requests. The callback must use an
    /// independently installed network/schema and freshly authenticated finality decision.
    /// A private child must explicitly pass its parent's registry context; none is inferred.
    /// # Errors
    /// Rejects zero/overlong timeout or a signer that is not this single-key account controller.
    pub fn from_account_registry(
        config: iroha::config::Config,
        discovery: Arc<MusubiArchiveProviderDiscoveryV1>,
        request_timeout: Duration,
    ) -> Result<Self, MusubiArchiveRuntimeErrorV1> {
        Self::prepare_account_registry(
            config.network_id,
            config.chain.to_string(),
            config.account,
            config.key_pair,
            discovery,
            None,
            request_timeout,
        )
    }

    /// Prepare account reads for exactly three original generated-local provider transports.
    ///
    /// The original selection is caller-owned intent, never native authority. Every provider
    /// access and token mint joins it to fresh native discovery before loopback I/O is possible.
    /// This retains no management-listener token or default authentication headers.
    /// # Errors
    /// Refuses duplicate providers, a different network/chain, invalid signer or unbounded timeout without I/O.
    pub fn from_generated_local_account_registry(
        config: iroha::config::Config,
        discovery: Arc<MusubiArchiveProviderDiscoveryV1>,
        originals: [GeneratedLocalProviderTransportV1; 3],
        request_timeout: Duration,
    ) -> Result<Self, MusubiArchiveRuntimeErrorV1> {
        Self::from_generated_local_account_signer(
            config.network_id,
            config.chain.as_str(),
            config.account,
            config.key_pair,
            discovery,
            originals,
            request_timeout,
        )
    }

    /// Prepare cold generated-local reads with the exact ordinary account signer.
    ///
    /// This performs no I/O and retains no management client configuration. Original TLS
    /// selection grants transport intent only; every access still requires fresh native
    /// discovery and an ordinary account-read token from the selected provider.
    /// # Errors
    /// Refuses duplicate or foreign original providers, a mismatched account key, or an
    /// unbounded timeout. No arbitrary HTTP client or verified proof can be injected.
    pub fn from_generated_local_account_signer(
        network: NetworkId,
        chain: &str,
        account: AccountId,
        key_pair: KeyPair,
        discovery: Arc<MusubiArchiveProviderDiscoveryV1>,
        originals: [GeneratedLocalProviderTransportV1; 3],
        request_timeout: Duration,
    ) -> Result<Self, MusubiArchiveRuntimeErrorV1> {
        if originals
            .iter()
            .any(|original| original.network_id() != network || original.chain_id() != chain)
            || originals.iter().enumerate().any(|(index, original)| {
                originals[..index]
                    .iter()
                    .any(|other| other.provider_id() == original.provider_id())
            })
        {
            return Err(permanent("MUSUBI_ARCHIVE_LOCAL_TRANSPORT_MISMATCH"));
        }
        Self::prepare_account_registry(
            network,
            chain.to_owned(),
            account,
            key_pair,
            discovery,
            Some(originals),
            request_timeout,
        )
    }

    fn prepare_account_registry(
        network_id: NetworkId,
        chain_id: String,
        account: AccountId,
        key_pair: KeyPair,
        discovery: Arc<MusubiArchiveProviderDiscoveryV1>,
        local_transports: Option<[GeneratedLocalProviderTransportV1; 3]>,
        request_timeout: Duration,
    ) -> Result<Self, MusubiArchiveRuntimeErrorV1> {
        if request_timeout.is_zero()
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
            || account != AccountId::new(key_pair.public_key().clone())
        {
            return Err(permanent("MUSUBI_ARCHIVE_REGISTRY_ACCOUNT_INVALID"));
        }
        Ok(Self {
            providers: Vec::new(),
            network_id,
            client_id: "musubi-v1".into(),
            request_timeout,
            account_registry: Some(Arc::new(AccountRegistryV1 {
                account,
                key_pair,
                chain_id,
                local_transports,
                discovery,
            })),
        })
    }
}

pub(super) struct ResolvedAccountProviderV1 {
    authority: VerifiedAccountReadProviderV1,
    pub(super) base_url: Url,
    original: Option<GeneratedLocalProviderTransportV1>,
    local_transport: Option<AuthenticatedGeneratedLocalProviderTransportV1>,
}

impl AccountRegistryV1 {
    // Shared cold/current origin selection. This performs no DNS, HTTP-client construction,
    // token issuance or provider-data request; only the independently owned discovery callback.
    pub(super) fn resolve_provider(
        &self,
        network: NetworkId,
        provider: ProviderId,
    ) -> Result<ResolvedAccountProviderV1, MusubiArchiveRuntimeErrorV1> {
        // No callback or network work may precede exact original-provider selection.
        let original = match &self.local_transports {
            Some(originals) => Some(
                originals
                    .iter()
                    .find(|original| original.provider_id() == provider)
                    .ok_or_else(|| control_integrity("MUSUBI_ARCHIVE_LOCAL_TRANSPORT_MISMATCH"))?,
            ),
            None => None,
        };
        let authority = discover_authority(self.discovery.as_ref(), provider)?;
        if authority.discovery().network_id() != network
            || authority.discovery().advert().body.provider_id != *provider.as_bytes()
            || authority.chain_id() != self.chain_id.as_str()
        {
            return Err(control_integrity(
                "MUSUBI_ARCHIVE_PROVIDER_DISCOVERY_SCOPE_MISMATCH",
            ));
        }
        let local_transport = original
            .map(|original| original.authenticate_current(&authority))
            .transpose()
            .map_err(|_| control_integrity("MUSUBI_ARCHIVE_LOCAL_TRANSPORT_MISMATCH"))?;
        let base_url = if let Some(selected) = &local_transport {
            selected.base_url().clone()
        } else {
            let origin = authority
                .policy()
                .https_origin()
                .map_err(|_| control_integrity("MUSUBI_ARCHIVE_PROVIDER_ORIGIN_INVALID"))?;
            parse_gateway_base_url(&format!("{origin}/"))?
        };
        Ok(ResolvedAccountProviderV1 {
            authority,
            base_url,
            original: original.cloned(),
            local_transport,
        })
    }
}

impl AuthenticatedMusubiArchiveFetchClientV1 {
    pub(super) fn discover_account_provider(
        &mut self,
        provider: ProviderId,
    ) -> Result<(), MusubiArchiveRuntimeErrorV1> {
        let Some(registry) = &self.account_registry else {
            return Ok(());
        };
        let selected = registry.resolve_provider(self.network_id, provider)?;
        let http = match &selected.local_transport {
            Some(local) => pinned_generated_local_http_client(local, self.request_timeout)?,
            None => pinned_http_client(&selected.base_url, self.request_timeout)?,
        };
        if self.providers.len() >= MAX_CONFIGURED_PROVIDERS
            && !self.providers.contains_key(&provider)
        {
            self.providers.pop_first();
        }
        self.providers.insert(
            provider,
            ProviderRuntimeV1 {
                provider,
                base_url: selected.base_url,
                http,
                local_transport: selected.original,
                credential: ProviderCredentialV1::Account {
                    account: registry.account.clone(),
                    key_pair: registry.key_pair.clone(),
                    chain_id: selected.authority.chain_id().to_owned(),
                    discovery: registry.discovery.clone(),
                },
            },
        );
        Ok(())
    }
}

fn discover_authority(
    discovery: &MusubiArchiveProviderDiscoveryV1,
    provider: ProviderId,
) -> Result<VerifiedAccountReadProviderV1, MusubiArchiveRuntimeErrorV1> {
    discovery(provider).map_err(|e| match e {
        MusubiArchiveDiscoveryErrorV1::Unavailable => {
            unavailable("MUSUBI_ARCHIVE_PROVIDER_DISCOVERY_UNAVAILABLE")
        }
        MusubiArchiveDiscoveryErrorV1::Rejected => {
            control_integrity("MUSUBI_ARCHIVE_PROVIDER_DISCOVERY_INVALID")
        }
        MusubiArchiveDiscoveryErrorV1::Deadline => {
            retryable("MUSUBI_ARCHIVE_PROVIDER_DISCOVERY_DEADLINE")
        }
    })
}

pub(super) fn refresh_account_authority(
    runtime: &ProviderRuntimeV1,
    network: NetworkId,
) -> Result<Option<VerifiedAccountReadProviderV1>, MusubiArchiveRuntimeErrorV1> {
    let ProviderCredentialV1::Account {
        chain_id,
        discovery,
        ..
    } = &runtime.credential
    else {
        return Ok(None);
    };
    // Every mint, including a replacement session, needs the same independently bound fresh
    // finality callback. A cached key is never an alternative after revocation or rotation.
    let authority = discover_authority(discovery.as_ref(), runtime.provider)?;
    let origin = authority
        .policy()
        .https_origin()
        .map_err(|_| control_integrity("MUSUBI_ARCHIVE_PROVIDER_ORIGIN_INVALID"))?;
    let current_url = match &runtime.local_transport {
        Some(original) => original
            .authenticate_current(&authority)
            .map_err(|_| control_integrity("MUSUBI_ARCHIVE_LOCAL_TRANSPORT_MISMATCH"))?
            .base_url()
            .clone(),
        None => parse_gateway_base_url(&format!("{origin}/"))?,
    };
    if authority.discovery().network_id() != network
        || authority.discovery().advert().body.provider_id != *runtime.provider.as_bytes()
        || authority.chain_id() != chain_id
        || gateway_origin(&current_url) != gateway_origin(&runtime.base_url)
    {
        return Err(control_integrity(
            "MUSUBI_ARCHIVE_PROVIDER_DISCOVERY_SCOPE_MISMATCH",
        ));
    }
    Ok(Some(authority))
}

pub(super) fn verify_current_account_token(
    token: &StreamTokenV1,
    header_key_hex: &str,
    provider: ProviderId,
    key: &PublicKey,
    key_revision: u32,
    policy: &sorafs_manifest::provider_advert::account_read::RegisteredAccountReadV1,
) -> Result<(), MusubiArchiveRuntimeErrorV1> {
    let failed = || control_integrity("MUSUBI_ARCHIVE_TOKEN_AUTHORITY_MISMATCH");
    let (algorithm, bytes) = key.to_bytes();
    if algorithm != iroha_crypto::Algorithm::Ed25519
        || header_key_hex != hex::encode(bytes)
        || token.body.token_pk_version != key_revision
        || token.body.provider_id != *provider.as_bytes()
        || token.body.max_streams > policy.max_streams
        || token.body.rate_limit_bytes > policy.rate_limit_bytes
        || token.body.requests_per_minute > policy.requests_per_minute
        || token
            .body
            .ttl_epoch
            .checked_sub(token.body.issued_at)
            .is_none_or(|ttl| ttl > policy.ttl_secs)
    {
        return Err(failed());
    }
    token.verify_public_key(key).map_err(|_| failed())
}

pub(super) fn account_request_headers(
    account: &AccountId,
    key_pair: &KeyPair,
    network: &NetworkId,
    url: &Url,
    body: &[u8],
) -> Result<HeaderMap, MusubiArchiveRuntimeErrorV1> {
    let failed = || permanent("MUSUBI_ARCHIVE_ACCOUNT_SIGNING_FAILED");
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| failed())?
        .as_millis()
        .try_into()
        .map_err(|_| failed())?;
    let nonce = random_nonce()?;
    let payload = iroha::client::canonical_network_request_signature_message(
        network,
        &iroha::http::Method::POST,
        url,
        body,
        timestamp_ms,
        &nonce,
    )
    .map_err(|_| failed())?;
    let signature = Signature::try_new(key_pair.private_key(), &payload).map_err(|_| failed())?;
    let values = [
        (
            "x-iroha-account",
            iroha::client::canonical_request_account_header_value(account).map_err(|_| failed())?,
        ),
        (
            "x-iroha-timestamp-ms",
            iroha::client::canonical_request_timestamp_header_value(timestamp_ms)
                .map_err(|_| failed())?,
        ),
        ("x-iroha-nonce", nonce),
        (
            "x-iroha-signature",
            iroha::client::canonical_request_signature_header_value(&signature)
                .map_err(|_| failed())?,
        ),
    ];
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        headers.insert(name, value.parse().map_err(|_| failed())?);
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_intent(config: &iroha::config::Config, slot: u8) -> GeneratedLocalProviderTransportV1 {
        use sorafs_manifest::{
            provider_admission::{ProviderAdmissionEnvelopeV1, ProviderAdmissionGenesisMaterialV1},
            provider_advert::{
                CapabilityType, EndpointKind, account_read::RegisteredAccountReadV1,
            },
        };
        // Native producer bytes provide structurally valid keys. This deliberately constructs
        // only caller-selected intent, never an opaque proof or authenticated genesis profile.
        let bytes = include_bytes!(
            "../../../../fixtures/sorafs_manifest/provider_admission/envelope_v1.to"
        );
        assert!(bytes.len() < 128 * 1024);
        let mut envelope: ProviderAdmissionEnvelopeV1 = norito::decode_canonical_with_limits(
            bytes,
            norito::DecodeLimits::new(128 * 1024, 128 * 1024, 256 * 1024, 2 * 1024 * 1024, 48),
        )
        .unwrap();
        envelope.proposal.provider_id[0] ^= slot;
        envelope.advert_body.provider_id = envelope.proposal.provider_id;
        let provider = ProviderId::new(envelope.proposal.provider_id);
        let hex = hex::encode(provider.as_bytes());
        let host = format!("{}.{}.localhost", &hex[..32], &hex[32..]);
        envelope
            .proposal
            .capabilities
            .retain(|cap| cap.cap_type != CapabilityType::RegisteredAccountRead);
        envelope.proposal.capabilities.push(
            RegisteredAccountReadV1 {
                https_host: host.clone(),
                https_port: 8443,
                ttl_secs: 60,
                max_streams: 1,
                rate_limit_bytes: 1024,
                requests_per_minute: 60,
            }
            .to_capability()
            .unwrap(),
        );
        envelope.proposal.endpoints.truncate(1);
        let endpoint = &mut envelope.proposal.endpoints[0];
        endpoint.endpoint.kind = EndpointKind::Torii;
        endpoint.endpoint.host_pattern = host;
        endpoint.attestation.kind =
            sorafs_manifest::provider_admission::EndpointAttestationKind::Tls;
        endpoint.attestation.attested_at = envelope.issued_at;
        endpoint.attestation.expires_at = envelope.retention_epoch;
        endpoint.attestation.alpn_ids = vec!["http/1.1".into()];
        endpoint.attestation.report.clear();
        endpoint.attestation.leaf_certificate = vec![1];
        endpoint.attestation.intermediate_certificates = vec![vec![2]];
        envelope.advert_body.capabilities = envelope.proposal.capabilities.clone();
        envelope.advert_body.endpoints = vec![endpoint.endpoint.clone()];
        let material = ProviderAdmissionGenesisMaterialV1 {
            proposal: envelope.proposal,
            advert_body: envelope.advert_body,
            issued_at: envelope.issued_at,
            retention_epoch: envelope.retention_epoch,
        };
        GeneratedLocalProviderTransportV1::select(
            config.network_id,
            config.chain.as_str(),
            provider,
            &config.account,
            &material,
        )
        .unwrap()
    }

    #[test]
    fn direct_generated_account_signer_stays_cold_and_rejects_foreign_keys_without_discovery() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let config = config();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let discovery: Arc<MusubiArchiveProviderDiscoveryV1> = Arc::new(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
            Err(MusubiArchiveDiscoveryErrorV1::Unavailable)
        });
        let select = |account, timeout| {
            PreparedMusubiArchiveFetchConfigV1::from_generated_local_account_signer(
                config.network_id,
                config.chain.as_str(),
                account,
                config.key_pair.clone(),
                discovery.clone(),
                std::array::from_fn(|slot| {
                    local_intent(
                        &config,
                        u8::try_from(slot).expect("three provider slots fit u8"),
                    )
                }),
                timeout,
            )
        };
        let foreign = KeyPair::from_seed(vec![0xB3; 32], iroha_crypto::Algorithm::Ed25519);
        assert!(
            select(
                AccountId::new(foreign.public_key().clone()),
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(select(config.account.clone(), Duration::ZERO).is_err());
        assert!(
            select(
                config.account.clone(),
                Duration::from_millis(MAX_REQUEST_TIMEOUT_MS + 1)
            )
            .is_err()
        );
        let selected = select(config.account.clone(), Duration::from_secs(1)).unwrap();
        assert_eq!(
            selected.generated_local_registry_identity(),
            Some((config.chain.as_str(), &config.account))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let client = selected.build_client().unwrap();
        assert!(client.providers.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            client
                .resolve_provider_gateway_origin(ProviderId::new([0; 32]))
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        for slot in 0..3 {
            let provider = local_intent(&config, slot).provider_id();
            assert_eq!(
                client
                    .resolve_provider_gateway_origin(provider)
                    .unwrap_err()
                    .code(),
                "MUSUBI_ARCHIVE_PROVIDER_DISCOVERY_UNAVAILABLE"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(client.providers.is_empty());
    }

    #[test]
    fn generated_local_preparation_is_lazy_and_scope_mismatch_never_discovers() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let config = config();
        let original = local_intent(&config, 0);
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let discovery: Arc<MusubiArchiveProviderDiscoveryV1> = Arc::new(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
            Err(MusubiArchiveDiscoveryErrorV1::Rejected)
        });
        let mut wrong = config.clone();
        wrong.chain = "different-chain".parse().unwrap();
        assert!(
            PreparedMusubiArchiveFetchConfigV1::from_generated_local_account_registry(
                wrong,
                discovery.clone(),
                std::array::from_fn(|slot| local_intent(
                    &config,
                    u8::try_from(slot).expect("three provider slots fit u8")
                )),
                Duration::from_secs(1)
            )
            .is_err()
        );
        let mut wrong = config.clone();
        wrong.network_id =
            NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"other original"),
            ));
        assert_ne!(wrong.network_id, config.network_id);
        assert!(
            PreparedMusubiArchiveFetchConfigV1::from_generated_local_account_registry(
                wrong,
                discovery.clone(),
                std::array::from_fn(|slot| local_intent(
                    &config,
                    u8::try_from(slot).expect("three provider slots fit u8")
                )),
                Duration::from_secs(1)
            )
            .is_err()
        );
        let prepared = PreparedMusubiArchiveFetchConfigV1::from_generated_local_account_registry(
            config.clone(),
            discovery,
            std::array::from_fn(|slot| {
                local_intent(
                    &config,
                    u8::try_from(slot).expect("three provider slots fit u8"),
                )
            }),
            Duration::from_secs(1),
        )
        .unwrap();
        let mut client = prepared.build_client().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            client
                .resolve_provider_gateway_origin(ProviderId::new([0; 32]))
                .unwrap_err()
                .code(),
            "MUSUBI_ARCHIVE_LOCAL_TRANSPORT_MISMATCH"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            client
                .discover_account_provider(ProviderId::new([0; 32]))
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            client
                .discover_account_provider(original.provider_id())
                .unwrap_err()
                .code(),
            "MUSUBI_ARCHIVE_PROVIDER_DISCOVERY_INVALID"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        for slot in 1..3 {
            assert_eq!(
                client
                    .discover_account_provider(local_intent(&config, slot).provider_id())
                    .unwrap_err()
                    .code(),
                "MUSUBI_ARCHIVE_PROVIDER_DISCOVERY_INVALID"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(
            client
                .resolve_provider_gateway_origin(original.provider_id())
                .unwrap_err()
                .code(),
            "MUSUBI_ARCHIVE_PROVIDER_DISCOVERY_INVALID"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert!(client.providers.is_empty());
    }

    #[test]
    fn generated_local_duplicate_or_mixed_scope_set_is_refused_without_discovery() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let config = config();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let discovery: Arc<MusubiArchiveProviderDiscoveryV1> = Arc::new(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
            Err(MusubiArchiveDiscoveryErrorV1::Rejected)
        });
        for duplicate in 0..3 {
            let mut originals = std::array::from_fn(|slot| {
                local_intent(
                    &config,
                    u8::try_from(slot).expect("three provider slots fit u8"),
                )
            });
            originals[(duplicate + 1) % 3] = originals[duplicate].clone();
            assert!(
                PreparedMusubiArchiveFetchConfigV1::from_generated_local_account_registry(
                    config.clone(),
                    discovery.clone(),
                    originals,
                    Duration::from_secs(1)
                )
                .is_err()
            );
        }
        for slot in 0..3 {
            for change_network in [false, true] {
                let mut selected = config.clone();
                if change_network {
                    selected.network_id =
                        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                            iroha_crypto::Hash::new(b"different original transport network"),
                        ));
                    assert_ne!(selected.network_id, config.network_id);
                } else {
                    selected.chain = "different-original-transport-chain".parse().unwrap();
                }
                let mut originals = std::array::from_fn(|index| {
                    local_intent(
                        &config,
                        u8::try_from(index).expect("three provider slots fit u8"),
                    )
                });
                originals[slot] = local_intent(
                    &selected,
                    u8::try_from(slot).expect("three provider slots fit u8"),
                );
                assert!(
                    PreparedMusubiArchiveFetchConfigV1::from_generated_local_account_registry(
                        config.clone(),
                        discovery.clone(),
                        originals,
                        Duration::from_secs(1),
                    )
                    .is_err()
                );
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn generated_local_initial_and_replacement_mints_require_fresh_native_authority() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let config = config();
        let original = local_intent(&config, 0);
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let hex = hex::encode(original.provider_id().as_bytes());
        let runtime = ProviderRuntimeV1 {
            provider: original.provider_id(),
            base_url: Url::parse(&format!(
                "https://{}.{}.localhost:8443/",
                &hex[..32],
                &hex[32..]
            ))
            .unwrap(),
            http: HttpClient::builder()
                .timeout(Duration::from_millis(1))
                .build()
                .unwrap(),
            local_transport: Some(original),
            credential: ProviderCredentialV1::Account {
                account: config.account,
                key_pair: config.key_pair,
                chain_id: config.chain.to_string(),
                discovery: Arc::new(move |_| {
                    counted.fetch_add(1, Ordering::SeqCst);
                    Err(MusubiArchiveDiscoveryErrorV1::Rejected)
                }),
            },
        };
        for _ in 0..2 {
            let error = mint_stream_token(
                &runtime,
                &config.network_id,
                &ManifestDigest::new([1; 32]),
                "component",
                1,
            )
            .err()
            .unwrap();
            assert_eq!(error.code(), "MUSUBI_ARCHIVE_PROVIDER_DISCOVERY_INVALID");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn revoked_current_custody_prevents_initial_and_replacement_mint_before_http() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let selected = config();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        // Planning retains only the authenticated origin/scope. No old signer key or token
        // policy is kept in these credentials as an alternative to a current callback.
        let runtime = ProviderRuntimeV1 {
            local_transport: None,
            provider: ProviderId::new([1; 32]),
            base_url: Url::parse("https://storage.example.com/").unwrap(),
            http: HttpClient::builder()
                .https_only(true)
                .timeout(Duration::from_millis(1))
                .build()
                .unwrap(),
            credential: ProviderCredentialV1::Account {
                account: selected.account,
                key_pair: selected.key_pair,
                chain_id: selected.chain.to_string(),
                discovery: Arc::new(move |_| {
                    counted.fetch_add(1, Ordering::SeqCst);
                    Err(MusubiArchiveDiscoveryErrorV1::Rejected)
                }),
            },
        };
        for _ in 0..2 {
            assert_eq!(
                mint_stream_token(
                    &runtime,
                    &selected.network_id,
                    &ManifestDigest::new([1; 32]),
                    "test",
                    1
                )
                .err()
                .expect("current custody must refuse the mint")
                .code(),
                "MUSUBI_ARCHIVE_PROVIDER_DISCOVERY_INVALID"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_response_signed_by_the_retired_key_cannot_refresh_a_rotated_session() {
        let old = KeyPair::try_from_seed(vec![0x81; 32], iroha_crypto::Algorithm::Ed25519).unwrap();
        let current =
            KeyPair::try_from_seed(vec![0x82; 32], iroha_crypto::Algorithm::Ed25519).unwrap();
        let provider = ProviderId::new([1; 32]);
        let policy = sorafs_manifest::provider_advert::account_read::RegisteredAccountReadV1 {
            https_host: "storage.example.com".into(),
            https_port: 443,
            ttl_secs: 60,
            max_streams: 1,
            rate_limit_bytes: 1024,
            requests_per_minute: 10,
        };
        let mut token = StreamTokenV1 {
            body: sorafs_manifest::StreamTokenBodyV1 {
                token_id: "01J3E4ZCMQ3GP2H3R5PSNF6Z7X".into(),
                manifest_cid: vec![1, 0x55, 1],
                provider_id: *provider.as_bytes(),
                profile_handle: "sorafs.sf1@1.0.0".into(),
                max_streams: 1,
                ttl_epoch: 61,
                rate_limit_bytes: 1024,
                issued_at: 1,
                requests_per_minute: 10,
                token_pk_version: 1,
            },
            signature: vec![],
        };
        let sign = |token: &mut StreamTokenV1, key: &KeyPair| {
            token.signature = Signature::new(
                key.private_key(),
                &token.body.signing_payload_bytes().unwrap(),
            )
            .payload()
            .to_vec();
        };
        let old_header = hex::encode(old.public_key().to_bytes().1);
        let current_header = hex::encode(current.public_key().to_bytes().1);
        sign(&mut token, &old);
        verify_current_account_token(&token, &old_header, provider, old.public_key(), 1, &policy)
            .unwrap();
        assert!(
            verify_current_account_token(
                &token,
                &old_header,
                provider,
                current.public_key(),
                2,
                &policy
            )
            .is_err()
        );
        token.body.token_pk_version = 2;
        sign(&mut token, &old);
        assert!(
            verify_current_account_token(
                &token,
                &current_header,
                provider,
                current.public_key(),
                2,
                &policy
            )
            .is_err()
        );
        sign(&mut token, &current);
        verify_current_account_token(
            &token,
            &current_header,
            provider,
            current.public_key(),
            2,
            &policy,
        )
        .unwrap();
        let mut narrower = policy;
        narrower.rate_limit_bytes = 512;
        assert!(
            verify_current_account_token(
                &token,
                &current_header,
                provider,
                current.public_key(),
                2,
                &narrower
            )
            .is_err()
        );
    }

    fn config() -> iroha::config::Config {
        let key_pair =
            KeyPair::try_from_seed(vec![0x77; 32], iroha_crypto::Algorithm::Ed25519).unwrap();
        iroha::config::Config {
            chain: "build-registry".parse().unwrap(),
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"registry genesis"),
            )),
            account: AccountId::new(key_pair.public_key().clone()),
            account_chain_discriminant: 753,
            key_pair,
            basic_auth: None,
            api_token: None,
            torii_api_url: Url::parse("https://registry.example.com/").unwrap(),
            torii_request_timeout: Duration::from_secs(1),
            transaction_ttl: Duration::from_secs(1),
            transaction_status_timeout: Duration::from_secs(1),
            transaction_add_nonce: false,
            sorafs_alias_cache: sorafs_manifest::alias_cache::AliasCachePolicy::new(
                Duration::from_secs(60),
                Duration::from_secs(10),
                Duration::from_secs(120),
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_secs(60),
                Duration::from_secs(10),
                Duration::from_secs(10),
            ),
            sorafs_anonymity_policy: iroha_service_model::soranet::AnonymityPolicy::default(),
            sorafs_rollout_phase: iroha_service_model::soranet::RolloutPhase::default(),
        }
    }
    #[test]
    fn preparing_and_materializing_account_context_does_not_discover_or_resolve_dns() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let captured = calls.clone();
        let prepared = PreparedMusubiArchiveFetchConfigV1::from_account_registry(
            config(),
            Arc::new(move |_| {
                captured.fetch_add(1, Ordering::SeqCst);
                Err(MusubiArchiveDiscoveryErrorV1::Unavailable)
            }),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(prepared.network_id(), config().network_id);
        assert!(prepared.generated_local_registry_identity().is_none());
        let mut client = prepared.build_client().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            client
                .discover_account_provider(ProviderId::new([1; 32]))
                .unwrap_err()
                .code(),
            "MUSUBI_ARCHIVE_PROVIDER_DISCOVERY_UNAVAILABLE"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(client.providers.is_empty());
        let mut foreign = config();
        foreign.account = AccountId::new(KeyPair::try_random().unwrap().public_key().clone());
        assert!(
            PreparedMusubiArchiveFetchConfigV1::from_account_registry(
                foreign,
                Arc::new(|_| Err(MusubiArchiveDiscoveryErrorV1::Rejected)),
                Duration::from_secs(1)
            )
            .is_err()
        );
    }
    #[test]
    fn account_headers_bind_exact_network_path_body_and_freshness_without_other_credentials() {
        let config = config();
        let url =
            Url::parse("https://storage.example.com/v1/sorafs/storage/token/account").unwrap();
        let body = br#"{"provider_id_hex":"11"}"#;
        let headers = account_request_headers(
            &config.account,
            &config.key_pair,
            &config.network_id,
            &url,
            body,
        )
        .unwrap();
        assert_eq!(headers.len(), 4);
        assert!(!headers.contains_key("x-api-token"));
        assert!(!headers.contains_key("authorization"));
        assert!(!headers.contains_key(OPERATOR_PUBLIC_KEY_HEADER));
        let timestamp = headers["x-iroha-timestamp-ms"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let nonce = headers["x-iroha-nonce"].to_str().unwrap();
        let sig = Signature::from_bytes(
            &STANDARD
                .decode(headers["x-iroha-signature"].as_bytes())
                .unwrap(),
        );
        let message = iroha::client::canonical_network_request_signature_message(
            &config.network_id,
            &iroha::http::Method::POST,
            &url,
            body,
            timestamp,
            nonce,
        )
        .unwrap();
        sig.verify(config.key_pair.public_key(), &message).unwrap();
        let changed = iroha::client::canonical_network_request_signature_message(
            &config.network_id,
            &iroha::http::Method::POST,
            &url,
            b"changed",
            timestamp,
            nonce,
        )
        .unwrap();
        assert!(sig.verify(config.key_pair.public_key(), &changed).is_err());
        let fresh = account_request_headers(
            &config.account,
            &config.key_pair,
            &config.network_id,
            &url,
            body,
        )
        .unwrap();
        assert_ne!(headers["x-iroha-nonce"], fresh["x-iroha-nonce"]);
    }
}
