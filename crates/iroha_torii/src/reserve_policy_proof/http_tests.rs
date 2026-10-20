//! Signed HTTP reads of actual native reserve cuts before local service activation.

use super::{handler, manager};
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
    isi::{Log, sorafs::SetSorafsReservePolicy},
    sorafs::reserve::{
        RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveAuthorityPolicyV1, ReservePolicyV1,
        history::reserve_policy_permission,
        proof::{MAX_RESERVE_POLICY_PROOF_BYTES_V1, ReservePolicyProofV1},
    },
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
}

impl Fixture {
    fn new() -> Self {
        Self::new_with_source_padding(0)
    }

    fn new_with_source_padding(source_padding: usize) -> Self {
        let key = |seed| KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
        let manager_key = key(0xc1);
        let manager = AccountId::new(manager_key.public_key().clone());
        let outsider_key = key(0xc2);
        let outsider = AccountId::new(outsider_key.public_key().clone());
        let custody = AccountId::new(key(0xc3).public_key().clone());
        let treasury = AccountId::new(key(0xc4).public_key().clone());
        let domain = DomainId::parse_fully_qualified("app.reserve-http-test").unwrap();
        let asset =
            AssetDefinitionId::derive_from_components(domain.clone(), "reserve".parse().unwrap());
        let mut world = World::with_assets(
            [Domain::new(domain.clone()).build(&manager)],
            [&manager, &outsider, &custody, &treasury]
                .map(|account| Account::new(account.clone()).build(&manager)),
            [AssetDefinition::numeric(
                asset.clone(),
                "Reserve HTTP test asset",
                AssetBalancePolicy::Global,
                Some(domain),
            )
            .build(&manager)],
            std::iter::empty::<Asset>(),
            [],
        );
        // This input is retained by genuine signed genesis; no post-genesis World is injected.
        world.account_permissions_mut_for_testing().insert(
            manager.clone(),
            BTreeSet::from([reserve_policy_permission()]),
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
        let mut config = TestChainConfig::new(world, 1_000);
        // Keep each field below the public genesis string bound while making the
        // genuine signed source larger than authentication's fixed working set.
        for offset in (0..source_padding).step_by(512 * 1024) {
            let bytes = (source_padding - offset).min(512 * 1024);
            config
                .genesis_instructions
                .push(Log::new(iroha_logger::Level::TRACE, "p".repeat(bytes)).into());
        }
        let mut chain = CertifiedTestChain::start(config).unwrap();
        let signed = chain.sign(
            &manager_key,
            [Log::new(iroha_logger::Level::INFO, "reserve HTTP source".into()).into()],
            2_000,
        );
        assert!(chain.commit_at(2_000, vec![signed])[0]);
        Self {
            chain,
            manager_key,
            manager,
            outsider_key,
            outsider,
            policy,
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
        inner.torii_proxy_max_response_bytes = MAX_RESERVE_POLICY_PROOF_BYTES_V1;
        assert!(!inner.sorafs_node.is_enabled());
        assert!(inner.sorafs_reserve_transaction_signer.is_none());
        let view = inner.state.view();
        assert_eq!(
            view.world().account_permissions().get(&self.manager),
            Some(&BTreeSet::from([reserve_policy_permission()])),
            "the manager has no broad ledger-read permission",
        );
        assert!(view.world().accounts().get(&self.outsider).is_some());
        assert!(
            view.world()
                .account_permissions()
                .get(&self.outsider)
                .is_none()
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
        assert!(self.chain.commit_at(3_000, vec![signed])[0]);
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
        // The finite fixture has only H1–H3. Production acquisition uses the native tip continuation.
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
        self.request(
            &format!("/v1/sorafs/reserve/policy/{height}"),
            Some((&self.manager, &self.manager_key)),
        )
    }
}

fn router(app: SharedAppState) -> Router {
    let descriptor =
        &route_catalog::contracts_and_verification_keys::SORAFS_RESERVE_POLICY_PROOF_GET;
    let mut builder = RouterBuilder::new(
        app.clone(),
        RouteCatalog::new(&[
            route_catalog::contracts_and_verification_keys::SORAFS_RESERVE_POLICY_PROOF_GET,
        ]),
        EnabledFeatures::new(&["app_api"]),
    )
    .unwrap();
    builder.route(
        descriptor,
        catalog_get(handler)
            .authenticated_in_handler(HandlerAuthentication::CanonicalAccountSignature),
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

async fn success_proof(response: AxResponse) -> ReservePolicyProofV1 {
    assert_eq!(response.status(), StatusCode::OK);
    assert_private(&response);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/x-norito"
    );
    let bytes = axum::body::to_bytes(response.into_body(), MAX_RESERVE_POLICY_PROOF_BYTES_V1)
        .await
        .unwrap();
    let proof = ReservePolicyProofV1::decode_frame(&bytes).unwrap();
    assert_eq!(
        norito::encode_canonical(&proof).unwrap().as_slice(),
        bytes.as_ref()
    );
    proof
}

async fn assert_failure_is_not_absence(response: AxResponse, expected_status: StatusCode) {
    assert_eq!(response.status(), expected_status);
    let bytes = axum::body::to_bytes(response.into_body(), MAX_RESERVE_POLICY_PROOF_BYTES_V1)
        .await
        .unwrap();
    assert!(
        ReservePolicyProofV1::decode_frame(&bytes).is_err(),
        "HTTP failure cannot authenticate singleton absence"
    );
}

#[tokio::test]
async fn signed_reserve_http_reads_native_absence_and_presence_before_service_activation() {
    let _auth = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let mut f = Fixture::new();
    let app = f.app(WORKING_BYTES);
    let router = router(app.clone());
    let absent = success_proof(router.clone().oneshot(f.manager_request(2)).await.unwrap()).await;
    let absent_tip = f.verified_tip();
    let schema = CoreState::native_world_schema_hash_v1().unwrap();
    let verified = absent
        .verify(
            f.chain.state().chain_id_ref().as_str(),
            f.chain.network_id(),
            &f.manager,
            &f.policy,
            schema,
            &absent_tip,
        )
        .unwrap();
    assert!(verified.current().is_none());
    assert_eq!(verified.height(), 2);
    assert_eq!(verified.context_id(), absent_tip.context_id());

    f.publish_policy();
    assert!(!app.sorafs_node.is_enabled());
    let present = success_proof(router.clone().oneshot(f.manager_request(3)).await.unwrap()).await;
    let present_tip = f.verified_tip();
    let verified = present
        .verify(
            f.chain.state().chain_id_ref().as_str(),
            f.chain.network_id(),
            &f.manager,
            &f.policy,
            schema,
            &present_tip,
        )
        .unwrap();
    let current = verified.current().unwrap();
    assert_eq!(current.policy, f.policy);
    assert_eq!(current.activated_by, f.manager);
    assert_eq!(current.activated_at_unix, 3);
    assert_eq!(verified.height(), 3);
    assert_eq!(verified.context_id(), present_tip.context_id());
    assert!(
        absent
            .verify(
                f.chain.state().chain_id_ref().as_str(),
                f.chain.network_id(),
                &f.manager,
                &f.policy,
                schema,
                &present_tip
            )
            .is_err()
    );
    assert_failure_is_not_absence(
        router.oneshot(f.manager_request(2)).await.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
}

#[tokio::test]
async fn signed_reserve_http_refuses_unprivileged_signer_missing_auth_and_route_absence() {
    let _auth = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let f = Fixture::new();
    let app = f.app(WORKING_BYTES);
    let router = router(app.clone());
    // Show the outsider is a valid registered HTTP signer before testing its missing direct grant.
    let probe = f.request(
        "/v1/sorafs/reserve/policy/2",
        Some((&f.outsider, &f.outsider_key)),
    );
    assert_eq!(
        manager(&app, probe.headers(), probe.method(), probe.uri()).unwrap(),
        f.outsider
    );
    let denied = router
        .clone()
        .oneshot(f.request(
            "/v1/sorafs/reserve/policy/2",
            Some((&f.outsider, &f.outsider_key)),
        ))
        .await
        .unwrap();
    assert_private(&denied);
    assert_failure_is_not_absence(denied, StatusCode::SERVICE_UNAVAILABLE).await;
    let unsigned = router
        .clone()
        .oneshot(f.request("/v1/sorafs/reserve/policy/2", None))
        .await
        .unwrap();
    assert_private(&unsigned);
    assert_failure_is_not_absence(unsigned, StatusCode::UNAUTHORIZED).await;
    assert_failure_is_not_absence(
        router
            .clone()
            .oneshot(f.request("/v1/sorafs/reserve/policy/2/unknown", None))
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
    )
    .await;
    assert!(
        success_proof(router.oneshot(f.manager_request(2)).await.unwrap())
            .await
            .current
            .is_none()
    );
}

#[tokio::test]
async fn signed_reserve_http_source_quota_refusal_does_not_become_absence_or_poison_retry() {
    let _auth = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let f = Fixture::new_with_source_padding(2 * 1024 * 1024);
    // Fund authentication, but leave the native block corridor one byte short
    // of the original genesis frame. This exercises source refusal after auth.
    let genesis_bytes = f.chain.committed(1).block().encode_wire().unwrap().len();
    assert!(genesis_bytes > 2 * 1024 * 1024);
    assert!(genesis_bytes < super::NATIVE_FINALITY_MAX_BLOCK_BYTES);
    let narrow_app = f.app(
        genesis_bytes
            .checked_sub(1)
            .unwrap()
            .checked_mul(8)
            .unwrap(),
    );
    let probe = f.manager_request(2);
    assert_eq!(
        super::manager(&narrow_app, probe.headers(), probe.method(), probe.uri()).unwrap(),
        f.manager,
    );
    let narrow = router(narrow_app);
    let unsigned = narrow
        .clone()
        .oneshot(f.request("/v1/sorafs/reserve/policy/2", None))
        .await
        .unwrap();
    assert_failure_is_not_absence(unsigned, StatusCode::UNAUTHORIZED).await;
    let refused = narrow.oneshot(f.manager_request(2)).await.unwrap();
    assert_private(&refused);
    assert_failure_is_not_absence(refused, StatusCode::TOO_MANY_REQUESTS).await;
    let proof = success_proof(
        router(f.app(WORKING_BYTES))
            .oneshot(f.manager_request(2))
            .await
            .unwrap(),
    )
    .await;
    let verified = proof
        .verify(
            f.chain.state().chain_id_ref().as_str(),
            f.chain.network_id(),
            &f.manager,
            &f.policy,
            CoreState::native_world_schema_hash_v1().unwrap(),
            &f.verified_tip(),
        )
        .unwrap();
    assert!(verified.current().is_none());
    assert_eq!(verified.height(), 2);
    assert_eq!(f.chain.height(), 2);
}
