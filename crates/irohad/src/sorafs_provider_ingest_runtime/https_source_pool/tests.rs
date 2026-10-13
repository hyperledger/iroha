//! Native catalog/pool/launcher composition with explicit refusing fixture authorities.
use super::*;
use crate::{
    RuntimeProviderBrokerBackendRegistryV1, RuntimeProviderBrokerBackendsV1,
    RuntimeProviderBrokerDeploymentV1,
    runtime_provider_registry::{
        IrohaRuntimeProviderRegistryErrorV1, ProviderIngestSourceLimitsV1,
        runtime_provider_test_network_id,
    },
};
use sorafs_car::gateway::GatewaySourceLimitsV1;
use sorafs_node::provider_ingest_runtime::{
    ProviderIngestAuthenticatedSourceBindingV1, ProviderIngestSourceQualificationV1,
};
use sorafs_node::{ProviderIngestFutureV1, ProviderIngestSourceFetchErrorV1};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct Calls {
    qualifications: AtomicUsize,
    readiness: AtomicUsize,
    grants: AtomicUsize,
}
struct RefusingAuthority {
    config: ProviderIngestHttpsSourceConfigV1,
    calls: Arc<Calls>,
}
impl ProviderIngestGovernedHttpsGrantResolverV1 for RefusingAuthority {
    fn qualification(
        &self,
        network: &iroha_data_model::NetworkId,
        provider: [u8; 32],
    ) -> Result<ProviderIngestSourceQualificationV1, ProviderIngestSourceFetchErrorV1> {
        self.calls.qualifications.fetch_add(1, Ordering::SeqCst);
        if network != &self.config.network_id || provider != self.config.binding.provider_id {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        Ok(self.config.binding.qualification())
    }
    fn check_readiness(
        &self,
        _: &iroha_data_model::NetworkId,
        _: [u8; 32],
    ) -> Result<(), ProviderIngestSourceFetchErrorV1> {
        self.calls.readiness.fetch_add(1, Ordering::SeqCst);
        Err(ProviderIngestSourceFetchErrorV1::Unavailable)
    }
    fn resolve(
        &self,
        _: ProviderIngestHttpsGrantRequestV1,
    ) -> ProviderIngestFutureV1<
        '_,
        Result<ProviderIngestHttpsGrantV1, ProviderIngestSourceFetchErrorV1>,
    > {
        self.calls.grants.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(ProviderIngestSourceFetchErrorV1::Rejected) })
    }
    fn ensure_current(
        &self,
        _: &ProviderIngestHttpsSourceLeaseV1,
    ) -> Result<(), ProviderIngestSourceFetchErrorV1> {
        Err(ProviderIngestSourceFetchErrorV1::Unavailable)
    }
}
fn limits() -> ProviderIngestSourceLimitsV1 {
    ProviderIngestSourceLimitsV1 {
        operation_timeout_ms: 10_000,
        max_content_bytes: 256 * 1024 * 1024,
        max_source_providers: 3,
        max_concurrent_streams: 1,
    }
}
fn catalog(limits: ProviderIngestSourceLimitsV1) -> IrohaRuntimeProviderBindingsV1 {
    IrohaRuntimeProviderBindingsV1::qualified_provider_ingest_source_for_test(
        "sorafs-source-network",
        "governed-https-pool",
        2,
        [0x31; 32],
        limits,
    )
}
fn sources(calls: &Arc<Calls>) -> Vec<ProviderIngestHttpsSourceRegistrationV1> {
    [0x13, 0x12]
        .map(|provider| {
            let config = ProviderIngestHttpsSourceConfigV1 {
                network_id: runtime_provider_test_network_id(),
                binding: ProviderIngestAuthenticatedSourceBindingV1 {
                    provider_id: [provider; 32],
                    runtime_handle: format!("governed-source-{provider}"),
                    revision: 1,
                    policy_digest: [provider + 1; 32],
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
            };
            ProviderIngestHttpsSourceRegistrationV1 {
                resolver: Arc::new(RefusingAuthority {
                    config: config.clone(),
                    calls: Arc::clone(calls),
                }),
                config,
            }
        })
        .to_vec()
}
#[test]
fn exact_catalog_native_pool_preserves_sorted_inventory_and_refused_readiness() {
    let calls = Arc::new(Calls::default());
    let pool = compose_provider_ingest_https_pool_v1(&catalog(limits()), sources(&calls)).unwrap();
    assert_eq!(pool.runtime_handle(), "governed-https-pool");
    assert_eq!(
        pool.qualification(),
        ProviderIngestRuntimeProviderQualificationV1::new(2, [0x31; 32])
    );
    assert_eq!(pool.source_provider_ids(), &[[0x12; 32], [0x13; 32]]);
    assert_eq!(pool.max_sources_per_fetch(), 3);
    assert_eq!(calls.readiness.load(Ordering::SeqCst), 0);
    assert_eq!(calls.grants.load(Ordering::SeqCst), 0);
    assert!(matches!(
        pool.check_readiness(),
        Err(ProviderIngestSourceFetchErrorV1::Unavailable)
    ));
    assert!(calls.readiness.load(Ordering::SeqCst) > 0);
    assert_eq!(calls.grants.load(Ordering::SeqCst), 0);
}
#[test]
fn invalid_public_inventory_is_rejected_before_consulting_any_resolver() {
    let calls = Arc::new(Calls::default());
    let catalog = catalog(limits());
    let original = sources(&calls);
    let mutations: [fn(&mut Vec<ProviderIngestHttpsSourceRegistrationV1>); 8] = [
        |sources| {
            sources.pop();
        },
        |sources| {
            sources.push(sources[0].clone());
        },
        |sources| {
            sources[1].config.binding.runtime_handle =
                sources[0].config.binding.runtime_handle.clone();
        },
        |sources| {
            sources[1].config.binding.runtime_handle = "governed-https-pool".into();
        },
        |sources| {
            sources[1].config.binding.revision = 0;
        },
        |sources| {
            sources[1].config.max_in_flight = 2;
        },
        |sources| {
            sources[1].config.operation_timeout = Duration::from_secs(11);
        },
        |sources| {
            use iroha_crypto::{Hash, HashOf};
            sources[1].config.network_id =
                iroha_data_model::NetworkId::from_genesis_hash(HashOf::<
                    iroha_data_model::block::BlockHeader,
                >::from_untyped_unchecked(
                    Hash::new(b"different-network")
                ));
        },
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert!(matches!(
            compose_provider_ingest_https_pool_v1(&catalog, changed),
            Err(ProviderIngestHttpsCompositionErrorV1::InvalidSources)
        ));
        assert_eq!(calls.qualifications.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn missing_role_and_exceeded_catalog_bounds_fail_before_resolver_access() {
    let calls = Arc::new(Calls::default());
    assert!(matches!(
        compose_provider_ingest_https_pool_v1(
            &IrohaRuntimeProviderBindingsV1::empty_for_test("source-network"),
            sources(&calls),
        ),
        Err(ProviderIngestHttpsCompositionErrorV1::CatalogMismatch)
    ));
    let mut smaller = limits();
    smaller.max_content_bytes = 1024;
    assert!(matches!(
        compose_provider_ingest_https_pool_v1(&catalog(smaller), sources(&calls)),
        Err(ProviderIngestHttpsCompositionErrorV1::InvalidSources)
    ));
    let mut source_limit = limits();
    source_limit.max_source_providers = 1;
    assert!(matches!(
        compose_provider_ingest_https_pool_v1(&catalog(source_limit), sources(&calls)),
        Err(ProviderIngestHttpsCompositionErrorV1::InvalidSources)
    ));
    let mut concurrent = sources(&calls);
    for source in &mut concurrent {
        source.config.max_in_flight = 2;
    }
    assert!(matches!(
        compose_provider_ingest_https_pool_v1(&catalog(limits()), concurrent),
        Err(ProviderIngestHttpsCompositionErrorV1::InvalidSources)
    ));
    assert_eq!(calls.qualifications.load(Ordering::SeqCst), 0);
}
#[test]
fn mismatched_live_source_qualification_cannot_be_installed() {
    let calls = Arc::new(Calls::default());
    let mut changed = sources(&calls);
    changed[1].config.binding.policy_digest = [0x99; 32];
    assert!(matches!(
        compose_provider_ingest_https_pool_v1(&catalog(limits()), changed),
        Err(ProviderIngestHttpsCompositionErrorV1::SourceUnavailable)
    ));
    assert_eq!(calls.readiness.load(Ordering::SeqCst), 0);
    assert_eq!(calls.grants.load(Ordering::SeqCst), 0);
}
#[test]
fn backend_injection_rejects_silent_replacement() {
    let calls = Arc::new(Calls::default());
    let catalog = catalog(limits());
    let backends = RuntimeProviderBrokerBackendsV1::default()
        .with_provider_ingest_https_sources(&catalog, sources(&calls))
        .unwrap();
    let prior = calls.qualifications.load(Ordering::SeqCst);
    assert!(matches!(
        backends.with_provider_ingest_https_sources(&catalog, sources(&calls)),
        Err(ProviderIngestHttpsCompositionErrorV1::AlreadyInstalled)
    ));
    assert_eq!(calls.qualifications.load(Ordering::SeqCst), prior);
}
#[test]
fn actual_deployment_constructor_uses_catalog_bound_injection_without_claiming_readiness() {
    struct Registry(Arc<Calls>);
    impl RuntimeProviderBrokerBackendRegistryV1 for Registry {
        fn resolve(
            &self,
            bindings: &IrohaRuntimeProviderBindingsV1,
        ) -> Result<RuntimeProviderBrokerBackendsV1, IrohaRuntimeProviderRegistryErrorV1> {
            RuntimeProviderBrokerBackendsV1::default()
                .with_provider_ingest_https_sources(bindings, sources(&self.0))
                .map_err(|_| {
                    IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                        IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource,
                    )
                })
        }
    }
    let calls = Arc::new(Calls::default());
    let deployment = RuntimeProviderBrokerDeploymentV1::try_new(
        catalog(limits()),
        iroha_config::parameters::actual::RuntimeProviderBroker::from_toml_source(
            iroha_config_base::toml::TomlSource::inline("".parse().expect("empty broker policy")),
        )
        .expect("validated default broker policy"),
        &Registry(Arc::clone(&calls)),
    )
    .unwrap();
    assert_eq!(deployment.binding_count(), 1);
    assert!(calls.qualifications.load(Ordering::SeqCst) > 0);
    assert_eq!(calls.readiness.load(Ordering::SeqCst), 0);
    assert_eq!(calls.grants.load(Ordering::SeqCst), 0);
}
