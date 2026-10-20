//! Signed HTTP reads of genuine native Set/Register cuts before local service activation.

use super::{handler, operator};
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderValue, Method, Request, StatusCode, Uri, header},
};
use iroha_core::{
    state::{State as CoreState, World, WorldReadOnly as _},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    asset::{Asset, AssetBalancePolicy, AssetDefinition, AssetDefinitionId},
    domain::Domain,
    isi::{
        Log,
        sorafs::{RegisterSorafsReserveAccount, SetSorafsReservePolicy, UpsertProviderCredit},
    },
    sorafs::reserve::{
        RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveAuthorityPolicyV1, ReserveDuration,
        ReservePolicyV1, ReserveProviderTermsV1, ReserveTier,
        account_proof::{
            MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1, ReserveAccountProofExpectedV1,
            ReserveAccountProofV1,
        },
        history::reserve_policy_permission,
    },
    sorafs::{capacity::ProviderId, pricing::ProviderCreditRecord},
    sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier, VerifiedSumeragiBlock},
};
use iroha_model_base::domain::DomainId;
use iroha_torii_shared::route_catalog::{self, EnabledFeatures, RouteCatalog};
use mv::storage::StorageReadOnly as _;
use sorafs_manifest::deal::XorQuantity;
use std::{collections::BTreeSet, sync::Arc};
use tower::ServiceExt as _;

use crate::{
    AxResponse, ByteWeightedMemoryPool, SharedAppState, attach_matched_route_metadata,
    enforce_catalog_private_no_store,
    router::builder::{HandlerAuthentication, RouterBuilder, catalog_get},
    tests_runtime_handlers::{
        app_auth_test_guard, mk_app_state_for_tests, signed_network_app_headers,
    },
};

const WORKING_BYTES: usize = 64 * 1024 * 1024;

struct Fixture {
    chain: CertifiedTestChain,
    manager_key: KeyPair,
    manager: AccountId,
    outsider_key: KeyPair,
    outsider: AccountId,
    policy: ReserveAuthorityPolicyV1,
    provider: ProviderId,
}

impl Fixture {
    fn new() -> Self {
        Self::new_with_owner_funds(false)
    }

    fn new_with_owner_funds(funded: bool) -> Self {
        Self::new_with_source_padding(funded, 0)
    }

    fn new_with_source_padding(funded: bool, source_padding: usize) -> Self {
        let key = |seed| KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
        let manager_key = key(0xc1);
        let manager = AccountId::new(manager_key.public_key().clone());
        let outsider_key = key(0xc2);
        let outsider = AccountId::new(outsider_key.public_key().clone());
        let custody = AccountId::new(key(0xc3).public_key().clone());
        let treasury = AccountId::new(key(0xc4).public_key().clone());
        let provider = ProviderId::new([0xd4; 32]);
        let domain = DomainId::parse_fully_qualified("app.reserve-http-test").unwrap();
        let asset =
            AssetDefinitionId::derive_from_components(domain.clone(), "reserve".parse().unwrap());
        let mut definition = AssetDefinition::numeric(
            asset.clone(),
            "Reserve HTTP test asset",
            AssetBalancePolicy::Global,
            Some(domain.clone()),
        )
        .build(&manager);
        let assets = if funded {
            definition.total_quantity = 100_u32.into();
            vec![Asset::new(
                iroha_data_model::asset::AssetId::new(asset.clone(), outsider.clone()),
                100_u32,
            )]
        } else {
            Vec::new()
        };
        let mut world = World::with_assets(
            [Domain::new(domain.clone()).build(&manager)],
            [&manager, &outsider, &custody, &treasury]
                .map(|account| Account::new(account.clone()).build(&manager)),
            [definition],
            assets,
            [],
        );
        // This input is retained by genuine signed genesis; no post-genesis World is injected.
        world.account_permissions_mut_for_testing().insert(
            manager.clone(),
            BTreeSet::from([
                reserve_policy_permission(),
                iroha_data_model::permission::Permission::from(
                    iroha_executor_data_model::permission::sorafs::CanUpsertSorafsProviderCredit,
                ),
            ]),
        );
        let policy = ReserveAuthorityPolicyV1 {
            version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            economics: ReservePolicyV1::default(),
            asset_definition: asset,
            custody_account: custody,
            treasury_account: treasury,
            operations_authority: manager.clone(),
            decision_authority: manager.clone(),
            grace_period_days: 7,
            default_after_days: 30,
            max_provider_debt: XorQuantity::try_from_micro(1_000_000_000).unwrap(),
            max_pending_movements_per_provider: 4,
            max_open_appeals_per_provider: 2,
        };
        let mut configuration = TestChainConfig::new(world, 1_000);
        // Genuine signed source bytes make the block corridor narrower than
        // its frame while still funding the complete authentication owner.
        // Each inert log stays below the genesis manifest's string ceiling.
        let mut remaining = source_padding;
        while remaining != 0 {
            let bytes = remaining.min(512 * 1024);
            configuration
                .genesis_instructions
                .push(Log::new(iroha_logger::Level::TRACE, "x".repeat(bytes)).into());
            remaining -= bytes;
        }
        let mut governance = iroha_config::parameters::actual::Governance::default();
        governance
            .sorafs_provider_owners
            .insert(provider, outsider.clone());
        configuration.governance = Some(governance);
        let mut chain = CertifiedTestChain::start(configuration).unwrap();
        let signed = chain.sign(
            &manager_key,
            [Log::new(iroha_logger::Level::INFO, "reserve HTTP source".into()).into()],
            2_000,
        );
        assert!(chain.commit(vec![signed])[0]);
        Self {
            chain,
            manager_key,
            manager,
            outsider_key,
            outsider,
            policy,
            provider,
        }
    }

    fn app(&self, working_bytes: usize) -> SharedAppState {
        let mut app = mk_app_state_for_tests();
        let inner = Arc::get_mut(&mut app).unwrap();
        inner.chain_id = Arc::new(self.chain.state().chain_id_ref().clone());
        inner.state = Arc::clone(self.chain.state());
        inner.kura = Arc::clone(self.chain.kura());
        inner.query_fanout_working_set_bytes = working_bytes;
        inner.query_fanout_inflight = ByteWeightedMemoryPool::new(working_bytes).unwrap();
        inner.torii_proxy_max_response_bytes = MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1;
        assert!(!inner.sorafs_node.is_enabled());
        assert!(inner.sorafs_reserve_transaction_signer.is_none());
        let view = inner.state.view();
        assert_eq!(
            view.world().account_permissions().get(&self.manager),
            Some(&BTreeSet::from([
                reserve_policy_permission(),
                iroha_data_model::permission::Permission::from(
                    iroha_executor_data_model::permission::sorafs::CanUpsertSorafsProviderCredit,
                ),
            ])),
            "the manager has no broad ledger-read permission",
        );
        assert!(view.world().accounts().get(&self.outsider).is_some());
        assert_eq!(
            view.world().account_permissions().get(&self.outsider),
            Some(&BTreeSet::from([
                iroha_data_model::permission::Permission::from(
                    iroha_executor_data_model::permission::sorafs::CanOperateSorafsRepair {
                        provider_id: self.provider,
                    },
                ),
            ])),
            "the provider owner has only its scoped repair permission, without ledger-read or reserve-policy authority",
        );
        drop(view);
        app
    }

    fn publish_policy(&mut self) {
        let signed = self.chain.sign(
            &self.manager_key,
            [SetSorafsReservePolicy::new(self.policy.clone()).into()],
            3_000,
        );
        assert!(self.chain.commit(vec![signed])[0]);
    }

    fn register(&mut self) {
        let signed = self.chain.sign(
            &self.manager_key,
            [RegisterSorafsReserveAccount::new(
                ReserveProviderTermsV1 {
                    provider_id: self.provider,
                    provider_account: self.outsider.clone(),
                    tier: ReserveTier::TierA,
                    storage_class: iroha_data_model::sorafs::pin_registry::StorageClass::Hot,
                    duration: ReserveDuration::Monthly,
                    capacity_gib: 10,
                },
                self.policy.digest().unwrap(),
            )
            .into()],
            4_000,
        );
        assert_eq!(self.chain.commit(vec![signed]), vec![true]);
    }

    fn install_credit(&mut self) -> ProviderCreditRecord {
        let mut record = ProviderCreditRecord::new(
            self.provider,
            17_u32.into(),
            0_u32.into(),
            19_u32.into(),
            23_u32.into(),
            1_000_000,
            999_999,
            iroha_model_base::metadata::Metadata::default(),
        );
        record.metadata.insert(
            "source".parse().unwrap(),
            iroha_primitives::json::Json::new("native-http-original"),
        );
        let signed = self.chain.sign(
            &self.manager_key,
            [UpsertProviderCredit::new(None, record.clone()).into()],
            5_000,
        );
        assert_eq!(self.chain.commit(vec![signed]), vec![true]);
        record
    }

    fn expected(&self) -> ReserveAccountProofExpectedV1<'_> {
        ReserveAccountProofExpectedV1 {
            chain: self.chain.state().chain_id_ref().as_str(),
            network_id: self.chain.network_id(),
            operator: &self.manager,
            provider_id: self.provider,
            owner: &self.outsider,
            policy: &self.policy,
            schema: CoreState::native_world_schema_hash_v1().unwrap(),
        }
    }

    fn path(&self, height: u64) -> String {
        format!(
            "/v1/sorafs/reserve/providers/{}/proof/{height}",
            hex::encode(self.provider.as_bytes())
        )
    }

    fn verified_tip(&self) -> VerifiedSumeragiBlock {
        let validators = self
            .chain
            .validators()
            .iter()
            .map(|(peer, pop)| FinalityValidator {
                public_key: peer.public_key().clone(),
                proof_of_possession: pop.clone(),
            })
            .collect();
        let mut verifier = SumeragiFinalityVerifier::new(
            self.chain.genesis(),
            self.chain.state().chain_id_ref().as_str(),
            validators,
        )
        .unwrap();
        let view = self.chain.state().view();
        let mut authenticated = None;
        // This finite fixture uses only submitted native work. Production acquisition uses the native tip continuation.
        for height in 1..=self.chain.height() {
            authenticated = Some(
                verifier
                    .verify(&iroha_core::sumeragi::finality::build_proof(&view, height).unwrap())
                    .unwrap(),
            );
        }
        authenticated.unwrap()
    }

    fn request(&self, path: &str, signer: Option<(&AccountId, &KeyPair)>) -> Request<Body> {
        let uri: Uri = path.parse().unwrap();
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(uri.clone())
            .header(header::ACCEPT, "application/x-norito")
            .body(Body::empty())
            .unwrap();
        if let Some((account, key)) = signer {
            request.headers_mut().extend(signed_network_app_headers(
                &self.chain.network_id(),
                account,
                key,
                &Method::GET,
                &uri,
                &[],
            ));
        }
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:14521".parse::<std::net::SocketAddr>().unwrap(),
        ));
        request
    }

    fn manager_request(&self, height: u64) -> Request<Body> {
        self.request(&self.path(height), Some((&self.manager, &self.manager_key)))
    }
}

fn router(app: SharedAppState) -> Router {
    let descriptor =
        &route_catalog::contracts_and_verification_keys::SORAFS_RESERVE_ACCOUNT_PROOF_GET;
    let mut builder = RouterBuilder::new(
        app.clone(),
        RouteCatalog::new(&[
            route_catalog::contracts_and_verification_keys::SORAFS_RESERVE_ACCOUNT_PROOF_GET,
            route_catalog::runtime_governance::NODE_CAPABILITIES,
        ]),
        EnabledFeatures::new(&["app_api"]),
    )
    .unwrap();
    builder.route(
        descriptor,
        catalog_get(handler)
            .authenticated_in_handler(HandlerAuthentication::CanonicalAccountSignature),
    );
    // The real metadata owner supplies compatibility version/schema facts only. It creates
    // no reserve or finality evidence and observes the same original fixture State.
    builder.route(
        &route_catalog::runtime_governance::NODE_CAPABILITIES,
        catalog_get(crate::handler_node_capabilities).unauthenticated(),
    );
    let (router, manifest) = builder.finish().unwrap();
    router
        .layer(axum::middleware::from_fn_with_state(
            manifest.route_index(),
            attach_matched_route_metadata,
        ))
        .layer(axum::middleware::from_fn(enforce_catalog_private_no_store))
        .with_state(app)
}

fn assert_private(response: &AxResponse) {
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("private, no-store"))
    );
}

async fn success_proof(response: AxResponse) -> ReserveAccountProofV1 {
    assert_eq!(response.status(), StatusCode::OK);
    assert_private(&response);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/x-norito"
    );
    let bytes = axum::body::to_bytes(response.into_body(), MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1)
        .await
        .unwrap();
    let proof = ReserveAccountProofV1::decode_frame(&bytes).unwrap();
    assert_eq!(
        norito::encode_canonical(&proof).unwrap().as_slice(),
        bytes.as_ref()
    );
    proof
}

async fn assert_failure_is_not_absence(response: AxResponse, expected_status: StatusCode) {
    assert_eq!(response.status(), expected_status);
    let bytes = axum::body::to_bytes(response.into_body(), MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1)
        .await
        .unwrap();
    assert!(
        ReserveAccountProofV1::decode_frame(&bytes).is_err(),
        "HTTP failure cannot authenticate provider partition absence"
    );
}

#[tokio::test]
async fn signed_reserve_account_http_reads_real_absence_and_registered_partition_before_services() {
    let _auth = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let mut f = Fixture::new();
    let app = f.app(WORKING_BYTES);
    let router = router(app.clone());
    // A missing policy is a refusal. It cannot be repackaged as provider absence.
    assert_failure_is_not_absence(
        router.clone().oneshot(f.manager_request(2)).await.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    f.publish_policy();
    let absent = success_proof(router.clone().oneshot(f.manager_request(3)).await.unwrap()).await;
    let absent_tip = f.verified_tip();
    let verified = absent.verify(&f.expected(), &absent_tip).unwrap();
    assert!(verified.current().is_none());
    assert!(verified.capacity().is_none());
    assert_eq!(
        verified.pricing(),
        &iroha_data_model::sorafs::pricing::PricingScheduleRecord::launch_default()
    );
    assert_eq!(verified.owner(), &f.outsider);
    assert_eq!(verified.operator(), &f.manager);
    f.register();
    let present = success_proof(router.clone().oneshot(f.manager_request(4)).await.unwrap()).await;
    let native = f.verified_tip();
    let verified = present.verify(&f.expected(), &native).unwrap();
    assert_eq!(
        verified.current().unwrap().terms.provider_account,
        f.outsider
    );
    assert_eq!(verified.current().unwrap().revision, 1);
    assert!(verified.capacity().is_none());
    assert_eq!(
        verified.pricing(),
        &iroha_data_model::sorafs::pricing::PricingScheduleRecord::launch_default()
    );
    assert!(verified.current().unwrap().reserve_balance.is_zero());
    assert_eq!(verified.height(), 4);
    assert!(!app.sorafs_node.is_enabled());
    assert!(app.sorafs_reserve_transaction_signer.is_none());
    assert!(absent.verify(&f.expected(), &native).is_err());
    assert_failure_is_not_absence(
        router.oneshot(f.manager_request(3)).await.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
}

#[tokio::test]
async fn signed_reserve_account_http_requires_operations_signer_and_errors_never_prove_absence() {
    let _auth = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let mut f = Fixture::new();
    f.publish_policy();
    let app = f.app(WORKING_BYTES);
    let router = router(app.clone());
    let auth_probe = f.request(&f.path(3), Some((&f.outsider, &f.outsider_key)));
    assert_eq!(
        operator(
            &app,
            auth_probe.headers(),
            auth_probe.method(),
            auth_probe.uri()
        )
        .unwrap(),
        f.outsider
    );
    // Registry ownership alone does not impersonate the active operations account.
    // The probe consumed its nonce; this independently signed request reaches policy checks.
    let owner = f.request(&f.path(3), Some((&f.outsider, &f.outsider_key)));
    assert_failure_is_not_absence(
        router.clone().oneshot(owner).await.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_failure_is_not_absence(
        router
            .clone()
            .oneshot(f.request(&f.path(3), None))
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let missing = f.request(
        "/v1/sorafs/reserve/missing-proof",
        Some((&f.manager, &f.manager_key)),
    );
    assert_failure_is_not_absence(
        router.oneshot(missing).await.unwrap(),
        StatusCode::NOT_FOUND,
    )
    .await;
}

#[tokio::test]
async fn signed_reserve_account_http_source_refusal_preserves_the_same_native_retry() {
    let _auth = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let mut f = Fixture::new_with_source_padding(false, 2 * 1024 * 1024);
    f.publish_policy();
    let native = f.verified_tip();
    // Admit the original signer before refusing a native source frame, so
    // authentication capacity cannot stand in for the source-refusal assertion.
    let genesis_bytes = f.chain.committed(1).block().encode_wire().unwrap().len();
    assert!(genesis_bytes > 2 * 1024 * 1024);
    assert!(genesis_bytes <= iroha_data_model::sumeragi::finality::NATIVE_FINALITY_MAX_BLOCK_BYTES);
    let working_bytes = genesis_bytes
        .checked_sub(1)
        .unwrap()
        .checked_mul(8)
        .unwrap();
    assert_eq!(working_bytes / 8 + 1, genesis_bytes);
    let narrow_app = f.app(working_bytes);
    let probe = f.manager_request(3);
    assert_eq!(
        operator(&narrow_app, probe.headers(), probe.method(), probe.uri()).unwrap(),
        f.manager,
    );
    let refused = router(narrow_app)
        .oneshot(f.manager_request(3))
        .await
        .unwrap();
    assert_failure_is_not_absence(refused, StatusCode::TOO_MANY_REQUESTS).await;
    let proof = success_proof(
        router(f.app(WORKING_BYTES))
            .oneshot(f.manager_request(3))
            .await
            .unwrap(),
    )
    .await;
    let verified = proof.verify(&f.expected(), &native).unwrap();
    assert!(verified.current().is_none());
    assert_eq!(verified.context_id(), native.context_id());
}

struct LoopbackServer {
    address: std::net::SocketAddr,
    runtime: tokio::runtime::Runtime,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl LoopbackServer {
    fn start(app: SharedAppState) -> Self {
        // Ordinary worker stacks: the blocking SDK stays on this synchronous test thread,
        // outside a Tokio runtime, while the real listener serves the canonical handlers.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let task = runtime.spawn(async move {
            axum::serve(
                listener,
                router(app).into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
        });
        Self {
            address,
            runtime,
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        self.runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .map_err(|_| {
                    "reserve SDK fixture did not shut down within its deadline".to_owned()
                })?
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())
        })
    }
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        // Unwinding assertions still close the listener; explicit stop below asserts completion.
        let _ = self.stop();
    }
}

#[test]
fn signed_reserve_account_sdk_loopback_verifies_native_absence_then_registration() {
    use std::time::{Duration, Instant};

    let _auth = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let mut f = Fixture::new();
    f.publish_policy();
    let app = f.app(WORKING_BYTES);
    let mut server = LoopbackServer::start(app.clone());
    let client = iroha::client::Client::builder(iroha::config::Config {
        chain: f.chain.state().chain_id_ref().clone(),
        network_id: f.chain.network_id(),
        account: f.manager.clone(),
        account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
        key_pair: f.manager_key.clone(),
        basic_auth: None,
        api_token: None,
        http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
        torii_api_url: format!("http://{}/", server.address).parse().unwrap(),
        torii_request_timeout: Duration::from_secs(10),
        transaction_ttl: Duration::from_secs(30),
        transaction_status_timeout: Duration::from_secs(30),
        transaction_add_nonce: true,
        sorafs_alias_cache: iroha::config::AliasCache::default().into_policy(),
        sorafs_anonymity_policy: Default::default(),
        sorafs_rollout_phase: Default::default(),
    })
    .build()
    .unwrap();
    let schema = CoreState::native_world_schema_hash_v1().unwrap();
    let absent_tip = f.verified_tip();
    let absent = client
        .with_request_deadline(Instant::now() + Duration::from_secs(30))
        .get_reserve_account_state(
            &f.manager,
            f.provider,
            &f.outsider,
            &f.policy,
            schema,
            &absent_tip,
        )
        .unwrap();
    assert!(absent.current().is_none());
    assert!(absent.credit().is_none());
    assert_eq!(absent.operator(), &f.manager);
    assert_eq!(absent.owner(), &f.outsider);
    assert_eq!(absent.context_id(), absent_tip.context_id());
    assert_eq!(absent.policy().policy, f.policy);

    // Execute the real original registration on the State already served by this listener.
    // Neither the HTTP server nor the SDK injects a successful result or manufactured World.
    f.register();
    let present_tip = f.verified_tip();
    let present = client
        .with_request_deadline(Instant::now() + Duration::from_secs(30))
        .get_reserve_account_state(
            &f.manager,
            f.provider,
            &f.outsider,
            &f.policy,
            schema,
            &present_tip,
        )
        .unwrap();
    assert!(present.credit().is_none());
    let partition = present.current().unwrap();
    assert_eq!(present.height(), 4);
    assert_eq!(present.context_id(), present_tip.context_id());
    assert_eq!(partition.terms.provider_id, f.provider);
    assert_eq!(partition.terms.provider_account, f.outsider);
    assert_eq!(partition.revision, 1);
    assert!(partition.reserve_balance.is_zero());
    assert!(partition.debt_principal.is_zero());
    assert!(!app.sorafs_node.is_enabled());
    assert!(app.sorafs_reserve_transaction_signer.is_none());
    // Install the real permissioned native credit row on the same State and existing listener.
    // The manager pays fees; this zero-bond projection grants no collateral or service status.
    let credit = f.install_credit();
    let credited_tip = f.verified_tip();
    let credited = client
        .with_request_deadline(Instant::now() + Duration::from_secs(30))
        .get_reserve_account_state(
            &f.manager,
            f.provider,
            &f.outsider,
            &f.policy,
            schema,
            &credited_tip,
        )
        .unwrap();
    assert_eq!(credited.height(), 5);
    assert_eq!(credited.context_id(), credited_tip.context_id());
    assert_eq!(credited.current(), present.current());
    assert_eq!(credited.credit(), Some(&credit));
    assert!(
        present.credit().is_none(),
        "an earlier verified cut never changes in place"
    );
    // The old request's exact certified cut cannot be fulfilled by the new current state.
    assert!(
        client
            .with_request_deadline(Instant::now() + Duration::from_secs(30))
            .get_reserve_account_state(
                &f.manager,
                f.provider,
                &f.outsider,
                &f.policy,
                schema,
                &absent_tip,
            )
            .is_err()
    );
    drop(client);
    server.stop().unwrap();
}

#[path = "capacity_pricing_http_tests.rs"]
mod capacity_pricing_http_tests;
