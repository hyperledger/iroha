//! Complete provider-specific Musubi readback through the authenticated `SoraFS` fetch transport.
//!
//! This backend never treats a provider's claimed digest as readback. It obtains the exact plan
//! and CAR through the authenticated provider client, consumes the complete bounded stream, and
//! parses the canonical bundle again before issuing a service response. The daemon checks the
//! finalized registration, current State target, and admitted endpoint on both sides of the fetch.
// TODO: Qualify independent replica readbacks and live council-admission refresh before private
// ingress participates in production publication.
use super::{
    MusubiPublicationFinalizedArchiveRegistrationQueryV1,
    MusubiPublicationFinalizedArchiveRegistrationReadErrorV1,
    MusubiPublicationFinalizedArchiveRegistrationReaderV1,
    MusubiPublicationPrivateServiceContextV1,
};
use iroha_data_model::{
    NetworkId,
    musubi::{MUSUBI_MAX_CAR_BYTES_V1, MusubiArchiveCommitmentV1},
    sorafs::{capacity::ProviderId, pin_registry::ManifestDigest},
};
use iroha_musubi_service::{
    MusubiProviderReadbackBackendV1, MusubiProviderReadbackRequestV1,
    MusubiProviderReadbackResponseV1, MusubiPublicationServiceBackendErrorV1,
};
use iroha_storage_client::musubi_archive_fetch::{
    AuthenticatedMusubiArchiveFetchClientV1, MusubiArchiveRuntimeErrorV1,
    MusubiArchiveRuntimeFailureClassV1,
};
use sorafs_car::{CarBuildPlan, musubi::MusubiBundleVerifierV1};
use sorafs_manifest::provider_advert::{
    AdvertEndpoint, CapabilityTlv, CapabilityType, EndpointKind,
    account_read::RegisteredAccountReadV1,
};
use std::{
    io::Read as _,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

type SharedProviderAdvertsV1 = Arc<tokio::sync::RwLock<iroha_torii::sorafs::ProviderAdvertCache>>;

trait AuthenticatedReadbackSourceV1: Send {
    fn network_id(&self) -> NetworkId;
    fn storage_plan(
        &mut self,
        pin_manifest: &ManifestDigest,
        provider: ProviderId,
        commitment: &MusubiArchiveCommitmentV1,
    ) -> Result<CarBuildPlan, MusubiArchiveRuntimeErrorV1>;
    fn open_authenticated_car(
        &mut self,
        pin_manifest: &ManifestDigest,
        provider: ProviderId,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &CarBuildPlan,
    ) -> Result<Box<dyn std::io::Read + Send + 'static>, MusubiArchiveRuntimeErrorV1>;
    fn take_stream_failure(&mut self) -> Option<MusubiArchiveRuntimeErrorV1>;
}
impl AuthenticatedReadbackSourceV1 for AuthenticatedMusubiArchiveFetchClientV1 {
    fn network_id(&self) -> NetworkId {
        AuthenticatedMusubiArchiveFetchClientV1::network_id(self)
    }
    fn storage_plan(
        &mut self,
        pin_manifest: &ManifestDigest,
        provider: ProviderId,
        commitment: &MusubiArchiveCommitmentV1,
    ) -> Result<CarBuildPlan, MusubiArchiveRuntimeErrorV1> {
        AuthenticatedMusubiArchiveFetchClientV1::storage_plan(
            self,
            pin_manifest,
            provider,
            commitment,
        )
    }
    fn open_authenticated_car(
        &mut self,
        pin_manifest: &ManifestDigest,
        provider: ProviderId,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &CarBuildPlan,
    ) -> Result<Box<dyn std::io::Read + Send + 'static>, MusubiArchiveRuntimeErrorV1> {
        AuthenticatedMusubiArchiveFetchClientV1::open_authenticated_car(
            self,
            pin_manifest,
            provider,
            commitment,
            plan,
        )
    }
    fn take_stream_failure(&mut self) -> Option<MusubiArchiveRuntimeErrorV1> {
        AuthenticatedMusubiArchiveFetchClientV1::take_stream_failure(self)
    }
}

struct ReadbackCoreV1<S> {
    network_id: NetworkId,
    source: S,
}
impl<S: AuthenticatedReadbackSourceV1> ReadbackCoreV1<S> {
    fn new(
        network_id: NetworkId,
        source: S,
    ) -> Result<Self, MusubiPublicationServiceBackendErrorV1> {
        if source.network_id() != network_id {
            return Err(MusubiPublicationServiceBackendErrorV1::Permanent);
        }
        Ok(Self { network_id, source })
    }
    fn readback(
        &mut self,
        request: &MusubiProviderReadbackRequestV1,
    ) -> Result<MusubiProviderReadbackResponseV1, MusubiPublicationServiceBackendErrorV1> {
        if request.network_id != self.network_id || request.validate().is_err() {
            return Err(MusubiPublicationServiceBackendErrorV1::Permanent);
        }
        let manifest = &request.location.pin_manifest;
        let plan = self
            .source
            .storage_plan(manifest, request.provider, &request.commitment)
            .map_err(backend_error)?;
        let car = read_complete_car(&mut self.source, request, &plan)?;
        verify_complete_readback(request, &plan, &car)
    }
}

/// Daemon-owned service backend using the actual authenticated `SoraFS` archive fetch client.
///
/// The constructor binds the transport's genesis-derived network to the daemon context. The
/// private publication factory must retain this backend as the service's readback dependency;
/// stock startup does not create or activate that factory.
pub struct MusubiPublicationAuthenticatedProviderReadbackV1 {
    core: ReadbackCoreV1<AuthenticatedMusubiArchiveFetchClientV1>,
    finalized_reader: MusubiPublicationFinalizedArchiveRegistrationReaderV1,
    adverts: SharedProviderAdvertsV1,
}
impl std::fmt::Debug for MusubiPublicationAuthenticatedProviderReadbackV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MusubiPublicationAuthenticatedProviderReadbackV1")
            .field("network_id", &self.core.network_id)
            .finish_non_exhaustive()
    }
}
impl MusubiPublicationAuthenticatedProviderReadbackV1 {
    /// Bind an authenticated provider client to the daemon's exact network.
    ///
    /// # Errors
    /// Refuses a client configured for another genesis-derived network.
    pub fn new(
        context: &MusubiPublicationPrivateServiceContextV1,
        client: AuthenticatedMusubiArchiveFetchClientV1,
        adverts: SharedProviderAdvertsV1,
    ) -> Result<Self, MusubiPublicationServiceBackendErrorV1> {
        Ok(Self {
            core: ReadbackCoreV1::new(context.network_id(), client)?,
            finalized_reader: context.finalized_archive_registration_reader(),
            adverts,
        })
    }
    fn validate_target(
        &self,
        request: &MusubiProviderReadbackRequestV1,
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        let evidence = &request.finalized_registration;
        let query = MusubiPublicationFinalizedArchiveRegistrationQueryV1 {
            version: 1,
            network_id: evidence.network_id,
            transaction_hash: evidence.transaction_hash,
            snapshot: evidence.snapshot,
            registration: evidence.registration.clone(),
            expected_policy_revision: request.expected_policy_revision,
        };
        self.finalized_reader
            .validate_current_readback_target(&query, &request.location, request.provider)
            .map_err(|error| match error {
                MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::LocallyAhead
                | MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Deferred(_) => {
                    MusubiPublicationServiceBackendErrorV1::Retryable
                }
                MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Invalid => {
                    MusubiPublicationServiceBackendErrorV1::Permanent
                }
            })?;
        // Discovery can perform registry I/O. Never hold the advert cache guard across it.
        let origin = self
            .core
            .source
            .resolve_provider_gateway_origin(request.provider)
            .map_err(backend_error)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MusubiPublicationServiceBackendErrorV1::Retryable)?
            .as_secs();
        let adverts = self
            .adverts
            .try_read()
            .map_err(|_| MusubiPublicationServiceBackendErrorV1::Retryable)?;
        let record = adverts
            .admitted_record_by_provider(request.provider.as_bytes(), now)
            .ok_or(MusubiPublicationServiceBackendErrorV1::Retryable)?;
        if !admitted_torii_gateway_matches(record, &origin) {
            return Err(MusubiPublicationServiceBackendErrorV1::Permanent);
        }
        Ok(())
    }
}
impl MusubiProviderReadbackBackendV1 for MusubiPublicationAuthenticatedProviderReadbackV1 {
    fn verify_current_target(
        &self,
        request: &MusubiProviderReadbackRequestV1,
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        if request.network_id != self.core.network_id || request.validate().is_err() {
            return Err(MusubiPublicationServiceBackendErrorV1::Permanent);
        }
        self.validate_target(request)
    }
    fn readback_provider(
        &mut self,
        request: &MusubiProviderReadbackRequestV1,
    ) -> Result<MusubiProviderReadbackResponseV1, MusubiPublicationServiceBackendErrorV1> {
        self.verify_current_target(request)?;
        let response = self.core.readback(request)?;
        self.verify_current_target(request)?;
        Ok(response)
    }
}

fn admitted_torii_gateway_matches(
    record: &iroha_torii::sorafs::discovery::AdvertRecord,
    origin: &str,
) -> bool {
    torii_gateway_origin_matches(
        &record.advert().body.capabilities,
        &record.advert().body.endpoints,
        origin,
    )
}
fn torii_gateway_origin_matches(
    capabilities: &[CapabilityTlv],
    endpoints: &[AdvertEndpoint],
    origin: &str,
) -> bool {
    if origin.is_empty() || origin.len() > 2_048 {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(origin) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    if url.as_str() != origin
        || url.scheme() != "https"
        || url.port_or_known_default().is_none_or(|port| port == 0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return false;
    }
    let Ok(account_policy) = RegisteredAccountReadV1::from_capabilities(capabilities) else {
        return false;
    };
    // Absent account capability leaves the existing operator-configured transport contract
    // intact; it does not itself authorize an origin or any network access.
    if account_policy.is_some_and(|policy| {
        policy.https_host != host || Some(policy.https_port) != url.port_or_known_default()
    }) {
        return false;
    }
    capabilities
        .iter()
        .any(|cap| cap.cap_type == CapabilityType::ToriiGateway)
        && capabilities
            .iter()
            .any(|cap| cap.cap_type == CapabilityType::ChunkRangeFetch)
        && endpoints.iter().any(|endpoint| {
            endpoint.kind == EndpointKind::Torii && endpoint.host_pattern.eq_ignore_ascii_case(host)
        })
}

fn read_complete_car<S: AuthenticatedReadbackSourceV1>(
    source: &mut S,
    request: &MusubiProviderReadbackRequestV1,
    plan: &CarBuildPlan,
) -> Result<Vec<u8>, MusubiPublicationServiceBackendErrorV1> {
    let size = usize::try_from(request.commitment.car_size)
        .map_err(|_| MusubiPublicationServiceBackendErrorV1::Permanent)?;
    if size == 0 || request.commitment.car_size > MUSUBI_MAX_CAR_BYTES_V1 {
        return Err(MusubiPublicationServiceBackendErrorV1::Permanent);
    }
    let mut car = Vec::new();
    car.try_reserve_exact(size)
        .map_err(|_| MusubiPublicationServiceBackendErrorV1::Retryable)?;
    car.resize(size, 0);
    let mut reader = source
        .open_authenticated_car(
            &request.location.pin_manifest,
            request.provider,
            &request.commitment,
            plan,
        )
        .map_err(backend_error)?;
    if reader.read_exact(&mut car).is_err() {
        drop(reader);
        // A closed stream without a classified transport result may be a network interruption.
        // It cannot become a permanent provider-content verdict from partial bytes alone.
        return Err(source.take_stream_failure().map_or_else(
            || MusubiPublicationServiceBackendErrorV1::Retryable,
            backend_error,
        ));
    }
    let mut tail = [0u8; 1];
    let extra = reader.read(&mut tail);
    drop(reader);
    if let Some(error) = source.take_stream_failure() {
        return Err(backend_error(error));
    }
    match extra {
        Ok(0) => Ok(car),
        Ok(_) => Err(MusubiPublicationServiceBackendErrorV1::Permanent),
        Err(_) => Err(MusubiPublicationServiceBackendErrorV1::Retryable),
    }
}

fn verify_complete_readback(
    request: &MusubiProviderReadbackRequestV1,
    plan: &CarBuildPlan,
    car: &[u8],
) -> Result<MusubiProviderReadbackResponseV1, MusubiPublicationServiceBackendErrorV1> {
    let verified = MusubiBundleVerifierV1::verify(plan, car, &request.commitment)
        .map_err(|_| MusubiPublicationServiceBackendErrorV1::Permanent)?;
    if verified.semantic_release().semantic_digest() != request.semantic_release_digest
        || verified.verification_lock().digest() != request.verification_lock_digest
    {
        return Err(MusubiPublicationServiceBackendErrorV1::Permanent);
    }
    let response = MusubiProviderReadbackResponseV1 {
        version: 1,
        provider: request.provider,
        location_id: request.location.location_id,
        replication_order: request.location.replication_order,
        commitment: request.commitment.clone(),
        semantic_release_digest: verified.semantic_release().semantic_digest(),
        verification_lock_digest: verified.verification_lock().digest(),
    };
    response
        .validate_for(request)
        .map_err(|_| MusubiPublicationServiceBackendErrorV1::Permanent)?;
    Ok(response)
}

fn backend_error(error: MusubiArchiveRuntimeErrorV1) -> MusubiPublicationServiceBackendErrorV1 {
    match error.class() {
        MusubiArchiveRuntimeFailureClassV1::Retryable
        | MusubiArchiveRuntimeFailureClassV1::Unavailable => {
            MusubiPublicationServiceBackendErrorV1::Retryable
        }
        MusubiArchiveRuntimeFailureClassV1::Integrity
        | MusubiArchiveRuntimeFailureClassV1::Permanent => {
            MusubiPublicationServiceBackendErrorV1::Permanent
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair, SignatureOf};
    use iroha_data_model::{
        musubi::{
            MusubiArchiveLocationIdV1, MusubiArchiveLocationStateV1, MusubiArchiveLocationV1,
            MusubiArchiveRegistrationProjectionV1, MusubiProviderBundleAttestationSetDigestV1,
            MusubiRegistrySnapshotV1, MusubiSeedIngressReceiptApprovalV1,
            MusubiSeedIngressReceiptPayloadV1, MusubiSeedIngressReceiptV1,
        },
        sorafs::pin_registry::ReplicationOrderId,
    };
    use iroha_musubi_service::MusubiFinalizedArchiveRegistrationEvidenceV1;
    use iroha_musubi_service::seed_test_support::fixture;
    use std::io::Cursor;

    struct FixtureSourceV1 {
        network_id: NetworkId,
        expected_manifest: ManifestDigest,
        expected_provider: ProviderId,
        expected_commitment: MusubiArchiveCommitmentV1,
        plan: CarBuildPlan,
        car: Vec<u8>,
        plan_calls: usize,
        car_calls: usize,
    }
    impl AuthenticatedReadbackSourceV1 for FixtureSourceV1 {
        fn network_id(&self) -> NetworkId {
            self.network_id
        }
        fn storage_plan(
            &mut self,
            pin_manifest: &ManifestDigest,
            provider: ProviderId,
            commitment: &MusubiArchiveCommitmentV1,
        ) -> Result<CarBuildPlan, MusubiArchiveRuntimeErrorV1> {
            assert_eq!(*pin_manifest, self.expected_manifest);
            assert_eq!(provider, self.expected_provider);
            assert_eq!(*commitment, self.expected_commitment);
            self.plan_calls += 1;
            Ok(self.plan.clone())
        }
        fn open_authenticated_car(
            &mut self,
            pin_manifest: &ManifestDigest,
            provider: ProviderId,
            commitment: &MusubiArchiveCommitmentV1,
            plan: &CarBuildPlan,
        ) -> Result<Box<dyn std::io::Read + Send + 'static>, MusubiArchiveRuntimeErrorV1> {
            assert_eq!(*pin_manifest, self.expected_manifest);
            assert_eq!(provider, self.expected_provider);
            assert_eq!(*commitment, self.expected_commitment);
            assert_eq!(*plan, self.plan);
            self.car_calls += 1;
            Ok(Box::new(Cursor::new(self.car.clone())))
        }
        fn take_stream_failure(&mut self) -> Option<MusubiArchiveRuntimeErrorV1> {
            None
        }
    }
    fn fixture_request() -> (MusubiProviderReadbackRequestV1, FixtureSourceV1) {
        let (binding, commitment, plan, car) = fixture();
        let verified = MusubiBundleVerifierV1::verify(&plan, &car, &commitment)
            .expect("canonical bundle fixture");
        let provider = binding.seed_provider;
        let broker_key =
            KeyPair::try_from_seed(vec![0x32; 32], Algorithm::Ed25519).expect("broker key");
        let receipt_payload = MusubiSeedIngressReceiptPayloadV1 {
            version: 1,
            binding: binding.clone(),
            issued_at_ms: 1,
            expires_at_ms: 1_000,
        };
        let receipt = MusubiSeedIngressReceiptV1 {
            approvals: vec![MusubiSeedIngressReceiptApprovalV1 {
                public_key: broker_key.public_key().clone(),
                signature: SignatureOf::try_from_hash(
                    broker_key.private_key(),
                    receipt_payload.signing_hash(),
                )
                .expect("receipt signature"),
            }],
            payload: receipt_payload,
        };
        let registration = MusubiArchiveRegistrationProjectionV1 {
            archive_id: commitment.archive_id(),
            commitment: commitment.clone(),
            staging_receipt: receipt,
            registered_by: binding.publisher.clone(),
            registered_at_height: 1,
        };
        let request = MusubiProviderReadbackRequestV1 {
            version: 1,
            operation_id: [0x41; 32],
            network_id: binding.network_id,
            publisher: binding.publisher.clone(),
            expected_policy_revision: 1,
            finalized_registration: MusubiFinalizedArchiveRegistrationEvidenceV1 {
                version: 1,
                network_id: binding.network_id,
                transaction_hash: [0x41; 32],
                snapshot: MusubiRegistrySnapshotV1 {
                    finalized_height: 1,
                    finalized_block_hash: [0x42; 32],
                    index_revision: 1,
                },
                registration,
            },
            location: MusubiArchiveLocationV1 {
                location_id: MusubiArchiveLocationIdV1::new([0x31; 32]),
                archive_id: commitment.archive_id(),
                pin_manifest: ManifestDigest::new([0x32; 32]),
                replication_order: ReplicationOrderId::new([0x33; 32]),
                providers: vec![provider],
                provider_attestation_set_digest: MusubiProviderBundleAttestationSetDigestV1::new(
                    [0x34; 32],
                ),
                renew_after_epoch: 1,
                expires_at_epoch: 2,
                finalized_height: 1,
                revision: 1,
                state: MusubiArchiveLocationStateV1::Healthy,
            },
            provider,
            commitment,
            semantic_release_digest: binding.semantic_release_manifest_digest,
            verification_lock_digest: verified.verification_lock().digest(),
        };
        let source = FixtureSourceV1 {
            network_id: request.network_id,
            expected_manifest: request.location.pin_manifest,
            expected_provider: request.provider,
            expected_commitment: request.commitment.clone(),
            plan,
            car,
            plan_calls: 0,
            car_calls: 0,
        };
        (request, source)
    }

    #[test]
    fn readback_consumes_and_verifies_complete_provider_car() {
        let (request, source) = fixture_request();
        let mut backend = ReadbackCoreV1::new(request.network_id, source).expect("same network");
        let response = backend
            .readback(&request)
            .expect("complete verified readback");
        response.validate_for(&request).expect("exact response");
        assert_eq!(backend.source.plan_calls, 1);
        assert_eq!(backend.source.car_calls, 1);
    }

    #[test]
    fn readback_rejects_foreign_network_and_incomplete_or_substituted_car() {
        let (request, source) = fixture_request();
        let mut foreign_source = source;
        foreign_source.network_id =
            iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                iroha_crypto::Hash::new([0x17; 32])
            ));
        let foreign_network_id = foreign_source.network_id;
        assert!(matches!(
            ReadbackCoreV1::new(request.network_id, foreign_source),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent)
        ));

        let (mut request, source) = fixture_request();
        let mut backend = ReadbackCoreV1::new(request.network_id, source).expect("same network");
        request.network_id = foreign_network_id;
        assert_eq!(
            backend.readback(&request),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent)
        );
        assert_eq!(backend.source.plan_calls, 0);

        let (mut request, source) = fixture_request();
        let mut backend = ReadbackCoreV1::new(request.network_id, source).expect("same network");
        request.semantic_release_digest =
            iroha_data_model::musubi::MusubiSemanticReleaseDigestV1::new([0x81; 32]);
        assert_eq!(
            backend.readback(&request),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent)
        );
        assert_eq!(backend.source.plan_calls, 0);
        assert_eq!(backend.source.car_calls, 0);

        let (request, mut source) = fixture_request();
        source.car.pop();
        let mut backend = ReadbackCoreV1::new(request.network_id, source).expect("same network");
        assert_eq!(
            backend.readback(&request),
            Err(MusubiPublicationServiceBackendErrorV1::Retryable)
        );

        let (request, mut source) = fixture_request();
        source.car.push(0);
        let mut backend = ReadbackCoreV1::new(request.network_id, source).expect("same network");
        assert_eq!(
            backend.readback(&request),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent)
        );

        let (request, mut source) = fixture_request();
        source.car[0] ^= 1;
        let mut backend = ReadbackCoreV1::new(request.network_id, source).expect("same network");
        assert_eq!(
            backend.readback(&request),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent)
        );

        let (request, mut source) = fixture_request();
        source.plan.chunks[0].digest[0] ^= 1;
        let mut backend = ReadbackCoreV1::new(request.network_id, source).expect("same network");
        assert_eq!(
            backend.readback(&request),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent)
        );
    }

    #[test]
    fn readback_gateway_must_match_admitted_torii_endpoint_and_capabilities() {
        let capabilities = [
            CapabilityType::ToriiGateway,
            CapabilityType::ChunkRangeFetch,
        ]
        .map(|cap_type| CapabilityTlv {
            cap_type,
            payload: Vec::new(),
        });
        let endpoint = AdvertEndpoint {
            kind: EndpointKind::Torii,
            host_pattern: "provider.example".to_owned(),
            metadata: Vec::new(),
        };
        assert!(torii_gateway_origin_matches(
            &capabilities,
            std::slice::from_ref(&endpoint),
            "https://provider.example/",
        ));
        assert!(!torii_gateway_origin_matches(
            &capabilities,
            std::slice::from_ref(&endpoint),
            "https://other.example/",
        ));
        assert!(!torii_gateway_origin_matches(
            &capabilities[..1],
            std::slice::from_ref(&endpoint),
            "https://provider.example/",
        ));
        // Without account capability, the previously configured operator transport owns its
        // exact port. Matching an advert alone never constructs or authorizes that transport.
        assert!(torii_gateway_origin_matches(
            &capabilities,
            std::slice::from_ref(&endpoint),
            "https://provider.example:444/",
        ));
        let changed_kind = AdvertEndpoint {
            kind: EndpointKind::Quic,
            ..endpoint
        };
        assert!(!torii_gateway_origin_matches(
            &capabilities,
            &[changed_kind],
            "https://provider.example/",
        ));
    }

    #[test]
    fn readback_account_origin_requires_exact_admitted_port_and_canonical_root() {
        let endpoint = AdvertEndpoint {
            kind: EndpointKind::Torii,
            host_pattern: "provider.example".into(),
            metadata: Vec::new(),
        };
        let mut policy = RegisteredAccountReadV1 {
            https_host: "provider.example".into(),
            https_port: 8443,
            ttl_secs: 60,
            max_streams: 1,
            rate_limit_bytes: 1024,
            requests_per_minute: 60,
        };
        let mut capabilities = vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            CapabilityTlv {
                cap_type: CapabilityType::ChunkRangeFetch,
                payload: Vec::new(),
            },
            policy.to_capability().unwrap(),
        ];
        let matches = |caps: &[CapabilityTlv], origin: &str| {
            torii_gateway_origin_matches(caps, std::slice::from_ref(&endpoint), origin)
        };
        assert!(matches(&capabilities, "https://provider.example:8443/"));
        for origin in [
            "https://provider.example/",
            "https://provider.example:8444/",
            "https://other.example:8443/",
            "http://provider.example:8443/",
            "https://provider.example:8443",
            "https://PROVIDER.example:8443/",
            "https://provider.example:08443/",
            "https://provider.example:0/",
            "https://user@provider.example:8443/",
            "https://user:secret@provider.example:8443/",
            "https://provider.example:8443/?query",
            "https://provider.example:8443/?",
            "https://provider.example:8443/#fragment",
            "https://provider.example:8443/#",
            "https://provider.example:8443/path",
            "https://provider.example:8443/a/../",
            " https://provider.example:8443/",
            "https://provider.example:8443/\n",
        ] {
            assert!(!matches(&capabilities, origin), "{origin:?}");
        }
        let valid = capabilities[2].clone();
        capabilities.push(valid.clone());
        assert!(!matches(&capabilities, "https://provider.example:8443/"));
        capabilities.pop();
        for payload in [
            vec![],
            vec![0],
            valid.payload.iter().copied().chain([0]).collect(),
        ] {
            capabilities[2].payload = payload;
            assert!(!matches(&capabilities, "https://provider.example:8443/"));
        }
        policy.https_port = 443;
        capabilities[2] = policy.to_capability().unwrap();
        assert!(matches(&capabilities, "https://provider.example/"));
        assert!(!matches(&capabilities, "https://provider.example:443/"));
    }
}
