//! Explicit fixture-authority tests; do not qualify finalized governance or production readiness.
use super::*;
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::block::BlockHeader;
use sorafs_car::{
    CarBuildPlan, CarStreamingWriter, compute_chunk_plan_digest_sha3, compute_por_root,
};
use sorafs_manifest::{ChunkingProfileV1, DagCodecId, ManifestBuilder, PinPolicy};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
fn network(seed: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        [seed; 32],
    )))
}
fn config() -> ProviderIngestHttpsSourceConfigV1 {
    ProviderIngestHttpsSourceConfigV1 {
        network_id: network(1),
        binding: ProviderIngestAuthenticatedSourceBindingV1 {
            provider_id: [0x12; 32],
            runtime_handle: "governed-source-alpha".into(),
            revision: 1,
            policy_digest: [0x14; 32],
        },
        limits: GatewaySourceLimitsV1 {
            max_payload_bytes: 4 * 1024 * 1024,
            max_files: 16,
            max_chunks: 16,
            max_page_bytes: 64 * 1024,
            max_pages: 8,
            page_entries: 2,
        },
        connect_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(2),
        operation_timeout: Duration::from_secs(10),
        max_in_flight: 1,
    }
}
fn fixture() -> ProviderIngestHttpsGrantV1 {
    let config = config();
    let payload = b"SORA CARS source bytes";
    let plan = CarBuildPlan::single_file(payload).unwrap();
    let stats = CarStreamingWriter::new(&plan)
        .write_from_reader(&mut payload.as_slice(), &mut io::sink())
        .unwrap();
    let manifest = ManifestBuilder::new()
        .root_cid(stats.root_cids[0].clone())
        .dag_codec(DagCodecId(stats.dag_codec))
        .chunking_profile(ChunkingProfileV1::from_descriptor(
            sorafs_manifest::chunker_registry::lookup_by_handle("sorafs.sf1@1.0.0").unwrap(),
        ))
        .chunk_digest_sha3_256(compute_chunk_plan_digest_sha3(&plan.chunks))
        .por_root(compute_por_root(payload, &plan).unwrap())
        .content_length(plan.content_length)
        .car_digest(*stats.car_archive_digest.as_bytes())
        .car_size(stats.car_size)
        .pin_policy(PinPolicy {
            retention_epoch: 100,
            ..PinPolicy::default()
        })
        .build()
        .unwrap();
    let authorization = FinalizedProviderIngestAuthorizationV1::from_finalized_state(
        10,
        [0x22; 32],
        [0x23; 32],
        [0x24; 32],
        *manifest.digest().unwrap().as_bytes(),
        manifest.root_cid.clone(),
        "sorafs.sf1@1.0.0".into(),
        manifest.chunk_digest_sha3_256,
        manifest.por_root,
        manifest.content_length,
    )
    .unwrap();
    let request = ProviderIngestHttpsGrantRequestV1 {
        network_id: config.network_id,
        source_provider_id: config.binding.provider_id,
        qualification: config.binding.qualification(),
        authorization,
        musubi_archive: None,
    };
    let expires_at_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
        + 60_000;
    ProviderIngestHttpsGrantV1 {
        lease: ProviderIngestHttpsSourceLeaseV1 {
            request,
            manifest,
            grant_id: [0x25; 32],
            advert_digest: [0x26; 32],
            assignment_revision: 1,
            expires_at_unix_ms,
        },
        provider: GatewayProviderInput {
            name: "source".into(),
            provider_id_hex: hex::encode(config.binding.provider_id),
            gateway_public_key_hex: hex::encode([0x27; 32]),
            base_url: "https://provider.example/".into(),
            stream_token_b64: "SECRET-FIXTURE-TOKEN".into(),
            privacy_events_url: None,
        },
        tls_roots_der: vec![vec![1]],
    }
}
struct FixtureResolver {
    current: AtomicBool,
    resolves: AtomicUsize,
    pending: bool,
}
impl FixtureResolver {
    fn new() -> Self {
        Self {
            current: AtomicBool::new(true),
            resolves: AtomicUsize::new(0),
            pending: false,
        }
    }
}
impl ProviderIngestGovernedHttpsGrantResolverV1 for FixtureResolver {
    fn qualification(
        &self,
        network: &NetworkId,
        provider: [u8; 32],
    ) -> Result<ProviderIngestSourceQualificationV1, ProviderIngestSourceFetchErrorV1> {
        let config = config();
        if network != &config.network_id || provider != config.binding.provider_id {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        Ok(config.binding.qualification())
    }
    fn check_readiness(
        &self,
        _: &NetworkId,
        _: [u8; 32],
    ) -> Result<(), ProviderIngestSourceFetchErrorV1> {
        Err(ProviderIngestSourceFetchErrorV1::Unavailable)
    }
    fn resolve(
        &self,
        _: ProviderIngestHttpsGrantRequestV1,
    ) -> ProviderIngestFutureV1<
        '_,
        Result<ProviderIngestHttpsGrantV1, ProviderIngestSourceFetchErrorV1>,
    > {
        self.resolves.fetch_add(1, Ordering::SeqCst);
        if self.pending {
            return Box::pin(std::future::pending());
        }
        Box::pin(async { Err(ProviderIngestSourceFetchErrorV1::Rejected) })
    }
    fn ensure_current(
        &self,
        _: &ProviderIngestHttpsSourceLeaseV1,
    ) -> Result<(), ProviderIngestSourceFetchErrorV1> {
        if self.current.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ProviderIngestSourceFetchErrorV1::Rejected)
        }
    }
}
#[tokio::test]
async fn shared_pool_admission_bounds_distinct_leaf_instances_and_releases_on_cancellation() {
    let resolver = Arc::new(FixtureResolver {
        pending: true,
        ..FixtureResolver::new()
    });
    let admissions = Arc::new(Semaphore::new(1));
    let first = ProviderIngestHttpsSourceV1::new_with_admissions(
        config(),
        resolver.clone(),
        Arc::clone(&admissions),
    )
    .unwrap();
    let second = ProviderIngestHttpsSourceV1::new_with_admissions(
        config(),
        resolver.clone(),
        Arc::clone(&admissions),
    )
    .unwrap();
    let authorization = fixture().lease.request.authorization;
    let mut pending = first.fetch_provider(authorization.clone(), None);
    // Poll the real acquisition until it enters the deliberately pending authority.
    tokio::select! {
        result = &mut pending => panic!("pending authority unexpectedly returned: {}", result.is_ok()),
        () = tokio::task::yield_now() => {}
    }
    assert_eq!(resolver.resolves.load(Ordering::SeqCst), 1);
    assert!(matches!(
        second.fetch_provider(authorization, None).await,
        Err(ProviderIngestSourceFetchErrorV1::Unavailable)
    ));
    assert_eq!(
        resolver.resolves.load(Ordering::SeqCst),
        1,
        "second leaf must not issue a second grant"
    );
    drop(pending);
    assert_eq!(
        admissions.available_permits(),
        1,
        "cancelling acquisition releases the shared budget"
    );
}
#[tokio::test]
async fn gateway_context_worker_panic_is_unavailable() {
    let result: Result<(), _> = build_gateway_context_recoverably(|| {
        assert!(iroha_panic_hook::is_suppressed());
        panic!("injected gateway context worker failure");
    })
    .await;
    assert_eq!(result, Err(ProviderIngestSourceFetchErrorV1::Unavailable));
}

#[test]
fn grant_binds_network_provider_revision_manifest_and_exact_finalized_request() {
    let original = fixture();
    let request = original.lease.request.clone();
    validate_grant(&config(), &request, &original).unwrap();
    let mut changed = fixture();
    changed.lease.request.network_id = network(2);
    assert!(validate_grant(&config(), &request, &changed).is_err());
    let mut changed = fixture();
    changed.lease.request.source_provider_id[0] ^= 1;
    assert!(validate_grant(&config(), &request, &changed).is_err());
    let mut changed = fixture();
    changed.lease.assignment_revision = 0;
    assert!(validate_grant(&config(), &request, &changed).is_err());
    let mut changed = fixture();
    changed.lease.manifest.por_root[0] ^= 1;
    assert!(validate_grant(&config(), &request, &changed).is_err());
    let mut changed = fixture();
    changed.provider.provider_id_hex = hex::encode([0x99; 32]);
    assert!(validate_grant(&config(), &request, &changed).is_err());
    let mut changed = fixture();
    changed.tls_roots_der.clear();
    assert!(validate_grant(&config(), &request, &changed).is_err());
    let mut changed = fixture();
    changed.lease.grant_id = [0; 32];
    assert!(validate_grant(&config(), &request, &changed).is_err());
    let debug = format!("{original:?}");
    assert!(!debug.contains("SECRET-FIXTURE"));
    assert!(!debug.contains("provider.example"));
}
#[tokio::test]
async fn injected_resolver_refusal_never_becomes_fake_readiness_or_network_fetch() {
    let resolver = Arc::new(FixtureResolver::new());
    let source = ProviderIngestHttpsSourceV1::new(config(), resolver.clone()).unwrap();
    assert!(source.check_readiness().is_err());
    assert_eq!(resolver.resolves.load(Ordering::SeqCst), 0);
    let authorization = fixture().lease.request.authorization;
    assert!(matches!(
        source.fetch_provider(authorization, None).await,
        Err(ProviderIngestSourceFetchErrorV1::Rejected)
    ));
    assert_eq!(resolver.resolves.load(Ordering::SeqCst), 1);
}
#[test]
fn retained_reader_rechecks_revocation_at_exact_eof_and_keeps_admission_bounded() {
    let config = config();
    let resolver = Arc::new(FixtureResolver::new());
    let admissions = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&admissions).try_acquire_owned().unwrap();
    let mut reader = LeaseCheckedReader {
        reader: Box::new(std::io::Cursor::new(vec![1, 2])),
        config,
        resolver: resolver.clone(),
        lease: fixture().lease,
        deadline: Instant::now() + Duration::from_secs(10),
        _permit: permit,
        failed: false,
    };
    let mut bytes = [0; 2];
    assert_eq!(reader.read(&mut bytes).unwrap(), 2);
    assert!(Arc::clone(&admissions).try_acquire_owned().is_err());
    resolver.current.store(false, Ordering::SeqCst);
    assert!(
        reader.read(&mut bytes).is_err(),
        "revoked EOF must fail native ingestion"
    );
    resolver.current.store(true, Ordering::SeqCst);
    assert!(
        reader.read(&mut bytes).is_err(),
        "failed reader cannot recover"
    );
    drop(reader);
    assert!(Arc::clone(&admissions).try_acquire_owned().is_ok());
}
#[test]
fn source_policy_and_lease_expiry_fail_closed() {
    let mut invalid = config();
    invalid.operation_timeout = Duration::from_secs(121);
    assert!(invalid.validate().is_err());
    let mut invalid = config();
    invalid.max_in_flight = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = config();
    invalid.connect_timeout = Duration::from_secs(20);
    assert!(invalid.validate().is_err());
    let resolver = FixtureResolver::new();
    let mut grant = fixture();
    grant.lease.expires_at_unix_ms = 1;
    assert!(
        ensure_current(
            &config(),
            &resolver,
            &grant.lease,
            Instant::now() + Duration::from_secs(10)
        )
        .is_err()
    );
    assert!(ensure_current(&config(), &resolver, &fixture().lease, Instant::now()).is_err());
}
