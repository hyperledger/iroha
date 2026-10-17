// Exact public-HTTP admission regressions for all application routed reads.
mod app_routed_read_http_admission_tests {
    use super::*;
    use axum::{
        Router,
        body::{Body, Bytes},
        http::{HeaderMap, HeaderValue, Request, StatusCode, header},
        middleware::{Next, from_fn, from_fn_with_state},
        response::Response,
        routing::any,
    };
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Poll,
    };
    fn pending_body(polls: &Arc<AtomicUsize>) -> Body {
        let polls = Arc::clone(polls);
        Body::from_stream(futures::stream::poll_fn(move |_| {
            polls.fetch_add(1, Ordering::SeqCst);
            Poll::<Option<Result<Bytes, Infallible>>>::Pending
        }))
    }
    fn occupy_fanout_pool(app: &SharedAppState) -> tokio::sync::OwnedSemaphorePermit {
        app.query_fanout_inflight
            .try_acquire_parts([app.query_fanout_inflight.capacity_bytes()])
            .expect("fixture occupies the whole query pool")
    }
    async fn insert_test_route_metadata(
        descriptor: iroha_torii_shared::route_catalog::RouteDescriptor,
        mut request: Request<Body>,
        next: Next,
    ) -> Response {
        request
            .extensions_mut()
            .insert(MatchedRouteMetadata::from_descriptor(descriptor));
        next.run(request).await
    }
    async fn test_auth_gate(request: Request<Body>, next: Next) -> Response {
        if request.headers().get("x-test-auth").is_none() {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        next.run(request).await
    }
    fn admission_router(
        app: SharedAppState,
        descriptor: iroha_torii_shared::route_catalog::RouteDescriptor,
        authenticate_first: bool,
    ) -> Router {
        let path = descriptor.path();
        let mut router = Router::new()
            .route(path, any(|| async { StatusCode::NO_CONTENT }))
            .layer(from_fn_with_state(
                app,
                enforce_app_routed_read_http_admission,
            ))
            .layer(from_fn(move |request, next| {
                insert_test_route_metadata(descriptor, request, next)
            }));
        if authenticate_first {
            router = router.layer(from_fn(test_auth_gate));
        }
        router
    }
    fn json_request(path: &str, body: Body) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .expect("valid test request")
    }
    macro_rules! define_endpoint_inventory {
        ($($endpoint:ident),+ $(,)?) => {
            const ENDPOINT_INVENTORY: &[ToriiReadEndpointV1] = &[
                $(ToriiReadEndpointV1::$endpoint),+
            ];
            fn endpoint_inventory_is_exhaustive(endpoint: ToriiReadEndpointV1) -> bool {
                match endpoint {
                    $(ToriiReadEndpointV1::$endpoint => true),+
                }
            }
        };
    }
    define_endpoint_inventory!(
        AccountGet,
        ExplorerAccountDetail,
        AccountAssetsGet,
        AccountAssetsQuery,
        AccountPermissionsGet,
        AccountTransactionsGet,
        AccountTransactionsQuery,
        TransactionsQuery,
        PipelineTransactionStatusGet,
        ProofRecordGet,
        AccountsList,
        AccountsQuery,
        AccountsPortfolio,
        AssetDefinitionsList,
        AssetDefinitionGet,
        AssetDefinitionsQuery,
        AssetHoldersGet,
        AssetHoldersQuery,
        DomainsList,
        DomainsQuery,
        NftsList,
        NftsQuery,
        NexusPublicLaneValidators,
        NexusPublicLaneStake,
        NexusPublicLaneRewards,
        NexusDataspacesAccountSummary,
        SpaceDirectoryBindingsGet,
        SpaceDirectoryManifestsGet,
        RwasList,
        RwasQuery,
        AliasResolve,
        AliasResolveIndex,
        AliasLookupByAccount,
        ExplorerAssetDefinitionDetail,
        ExplorerAssetDefinitionEconometrics,
        ExplorerAssetDefinitionSnapshot,
        ContractAliasResolve,
        ContractStateGet,
        ContractViewPost,
        ContractViewBatchPost,
        AccountHistoryGet,
        InternalAccountGet,
        InternalAccountTransactionGet,
        InternalAccountAssetGet,
        ContractDeploymentState,
        AccountOnboardingCurrentState,
        AccountPermissionsQuery,
        UaidManifestsQuery,
        AccountHistoryQuery,
    );
    #[test]
    fn all_49_endpoint_and_stable_route_id_mappings_are_exact_and_unique() {
        let expected = ENDPOINT_INVENTORY;
        assert_eq!(APP_ROUTED_READ_HTTP_ENDPOINTS_V1.len(), expected.len());
        for &endpoint in expected {
            assert!(endpoint_inventory_is_exhaustive(endpoint));
            assert_eq!(
                APP_ROUTED_READ_HTTP_ENDPOINTS_V1
                    .iter()
                    .filter(|entry| entry.endpoint == endpoint)
                    .count(),
                1,
                "endpoint {endpoint:?} must have exactly one public HTTP admission entry"
            );
        }
        let mut route_ids = std::collections::BTreeSet::new();
        for entry in APP_ROUTED_READ_HTTP_ENDPOINTS_V1 {
            assert!(route_ids.insert(entry.route.stable_route_id()));
            assert_eq!(
                app_routed_read_http_endpoint(entry.route.stable_route_id())
                    .expect("catalog route must resolve")
                    .endpoint,
                AppReadHttpIdentity::Routed(entry.endpoint)
            );
            match entry.decoder {
                AppRoutedReadHttpDecoder::None
                | AppRoutedReadHttpDecoder::ExactInternalAssetScope => {
                    assert!(entry.decoder.typed_request_name().is_none());
                }
                AppRoutedReadHttpDecoder::Query(name)
                | AppRoutedReadHttpDecoder::StringQuery(name)
                | AppRoutedReadHttpDecoder::JsonOrNorito(name)
                | AppRoutedReadHttpDecoder::Json(name) => {
                    assert!(!name.is_empty());
                    assert_eq!(entry.decoder.typed_request_name(), Some(name));
                }
            }
        }
        assert_eq!(route_ids.len(), expected.len());
    }
    #[test]
    fn every_direct_collection_get_and_post_has_the_same_closed_owner_path() {
        let mut ids = std::collections::BTreeSet::new();
        for entry in APP_LOCAL_COLLECTION_HTTP_ROUTES_V1 {
            assert!(ids.insert(entry.route.stable_route_id()));
            let resolved = app_routed_read_http_endpoint(entry.route.stable_route_id()).unwrap();
            assert_eq!(resolved.endpoint, entry.endpoint);
            assert_eq!(resolved.decoder, entry.decoder);
            assert!(matches!(
                entry.decoder,
                AppRoutedReadHttpDecoder::None
                    | AppRoutedReadHttpDecoder::Query("ListQuery")
                    | AppRoutedReadHttpDecoder::Json("ListQuery")
                    | AppRoutedReadHttpDecoder::Json("AccountInspectionRequest")
            ));
            assert!(
                APP_ROUTED_READ_HTTP_ENDPOINTS_V1
                    .iter()
                    .all(|routed| routed.route.stable_route_id() != entry.route.stable_route_id())
            );
        }
        let collections: Vec<_> = APP_LOCAL_COLLECTION_HTTP_ROUTES_V1
            .iter()
            .filter(|entry| {
                matches!(
                    entry.decoder,
                    AppRoutedReadHttpDecoder::Query("ListQuery")
                        | AppRoutedReadHttpDecoder::Json("ListQuery")
                )
            })
            .collect();
        assert_eq!(collections.len(), 32);
        for pair in collections.chunks_exact(2) {
            assert_eq!(pair[0].endpoint, pair[1].endpoint);
            assert_eq!(
                pair[0].decoder,
                AppRoutedReadHttpDecoder::Query("ListQuery")
            );
            assert_eq!(pair[1].decoder, AppRoutedReadHttpDecoder::Json("ListQuery"));
        }
        let details: Vec<_> = APP_LOCAL_COLLECTION_HTTP_ROUTES_V1
            .iter()
            .filter(|entry| entry.decoder == AppRoutedReadHttpDecoder::None)
            .map(|entry| entry.route.stable_route_id())
            .collect();
        assert_eq!(details, [
            route_catalog::application_api::EXPLORER_BLOCKS_BY_IDENTIFIER_GET.stable_route_id(),
            route_catalog::application_api::EXPLORER_TRANSACTIONS_BY_HASH_GET.stable_route_id(),
            route_catalog::application_api::EXPLORER_TRANSACTIONS_BY_HASH_PROOF_GET.stable_route_id(),
            route_catalog::application_api::EXPLORER_INSTRUCTIONS_BY_HASH_BY_INDEX_GET.stable_route_id(),
            route_catalog::application_api::EXPLORER_INSTRUCTIONS_BY_HASH_BY_INDEX_CONTRACT_VIEW_GET.stable_route_id(),
            route_catalog::application_api::EXPLORER_HEALTH_GET.stable_route_id(),
            route_catalog::application_api::EXPLORER_DOMAINS_BY_DOMAIN_ID_GET.stable_route_id(),
            route_catalog::application_api::EXPLORER_ASSETS_BY_ASSET_ID_GET.stable_route_id(),
            route_catalog::application_api::EXPLORER_NFTS_BY_NFT_ID_GET.stable_route_id(),
            route_catalog::application_api::EXPLORER_RWAS_BY_RWA_ID_GET.stable_route_id(),
        ]);
        let inspection = app_routed_read_http_endpoint(
            route_catalog::application_api::ACCOUNTS_INSPECT_POST.stable_route_id(),
        )
        .unwrap();
        assert_eq!(
            inspection.endpoint,
            AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::AccountInspection,)
        );
        assert_eq!(
            inspection.decoder,
            AppRoutedReadHttpDecoder::Json("AccountInspectionRequest")
        );
        assert_eq!(ids.len(), 43);
    }

    async fn native_read_owner_probe(
        State(app): State<SharedAppState>,
        headers: HeaderMap,
    ) -> Response {
        let limit = if headers.contains_key("x-test-overflow") {
            1
        } else {
            128
        };
        let admission = acquire_query_admission(&app, true).await.unwrap();
        match routing::run_admitted_blocking(admission, "native read owner probe", move || {
            let owner = crate::history_producer::HistoryProducerOwner::current()?;
            owner.json_with_limit("native-owner", limit)
        })
        .await
        {
            Ok(response) => response,
            Err(error) => error.into_response(),
        }
    }

    fn native_read_owner_router(
        app: SharedAppState,
        descriptor: iroha_torii_shared::route_catalog::RouteDescriptor,
    ) -> Router {
        Router::new()
            .route(descriptor.path(), any(native_read_owner_probe))
            .with_state(app.clone())
            .layer(from_fn_with_state(
                app,
                enforce_app_routed_read_http_admission,
            ))
            .layer(from_fn(move |request, next| {
                insert_test_route_metadata(descriptor, request, next)
            }))
    }

    #[tokio::test]
    async fn native_read_admission_preserves_worker_owner_and_response_cap() {
        for descriptor in [
            route_catalog::application_api::ACCOUNTS_INSPECT_POST,
            route_catalog::application_api::EXPLORER_TRANSACTIONS_BY_HASH_PROOF_GET,
        ] {
            let app = mk_app_state_for_tests();
            let before = app.query_fanout_inflight.available_bytes();
            for overflow in [false, true] {
                let path = descriptor.path().replace("{hash}", &"ab".repeat(32));
                let mut request =
                    if descriptor == route_catalog::application_api::ACCOUNTS_INSPECT_POST {
                        json_request(&path, Body::from("{}"))
                    } else {
                        Request::builder().uri(path).body(Body::empty()).unwrap()
                    };
                if overflow {
                    request
                        .headers_mut()
                        .insert("x-test-overflow", HeaderValue::from_static("1"));
                }
                let response = native_read_owner_router(app.clone(), descriptor)
                    .oneshot(request)
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    if overflow {
                        StatusCode::TOO_MANY_REQUESTS
                    } else {
                        StatusCode::OK
                    },
                    "{}",
                    descriptor.stable_route_id()
                );
                assert!(app.query_fanout_inflight.available_bytes() < before);
                let bytes = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                if !overflow {
                    assert_eq!(bytes.as_ref(), br#""native-owner""#);
                }
                assert!(app.query_fanout_inflight.available_bytes() < before);
                drop(bytes);
                assert_eq!(app.query_fanout_inflight.available_bytes(), before);
            }
        }
    }

    #[tokio::test]
    async fn account_inspection_real_handler_inherits_outer_http_owner() {
        let app = mk_app_state_for_tests();
        let before = app.query_fanout_inflight.available_bytes();
        let descriptor = route_catalog::application_api::ACCOUNTS_INSPECT_POST;
        let account = AccountId::new(
            iroha_crypto::KeyPair::try_from_seed(vec![0xc6; 32], iroha_crypto::Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
        );
        let body = norito::json::to_vec(&norito::json!({
            "version": 1,
            "network_id": app.state.network_id_ref().to_string(),
            "request_id": "8a70f738-e08d-4d2c-bb07-f3eec382f441",
            "nonce": "a1".repeat(32),
            "account_id": account.to_string(),
        }))
        .unwrap();
        let router = Router::new()
            .route(
                descriptor.path(),
                axum::routing::post(account_inspection::handler),
            )
            .with_state(app.clone())
            .layer(axum::Extension(crate::loopback_connect_info()))
            .layer(from_fn_with_state(
                app.clone(),
                enforce_app_routed_read_http_admission,
            ))
            .layer(from_fn(move |request, next| {
                insert_test_route_metadata(descriptor, request, next)
            }));
        let response = router
            .oneshot(json_request(descriptor.path(), Body::from(body)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert!(app.query_fanout_inflight.available_bytes() < before);
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let value: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
        assert_eq!(
            value["account_id"].as_str(),
            Some(account.to_string().as_str())
        );
        assert!(app.query_fanout_inflight.available_bytes() < before);
        drop(bytes);
        assert_eq!(app.query_fanout_inflight.available_bytes(), before);
    }

    #[tokio::test]
    async fn account_inspection_outer_body_cap_rejects_before_excess_retention() {
        let app = mk_app_state_for_tests();
        let descriptor = route_catalog::application_api::ACCOUNTS_INSPECT_POST;
        let before = app.query_fanout_inflight.available_bytes();
        let polls = Arc::new(AtomicUsize::new(0));
        let mut declared = json_request(descriptor.path(), pending_body(&polls));
        declared
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("4097"));
        let response = native_read_owner_router(app.clone(), descriptor)
            .oneshot(declared)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(app.query_fanout_inflight.available_bytes(), before);
        drop(response);

        let stream_polls = Arc::clone(&polls);
        let body = Body::from_stream(futures::stream::poll_fn(move |_| {
            let poll = stream_polls.fetch_add(1, Ordering::SeqCst);
            match poll {
                0 => Poll::Ready(Some(Ok::<Bytes, Infallible>(Bytes::from(vec![b' '; 4096])))),
                1 => Poll::Ready(Some(Ok(Bytes::from_static(b"x")))),
                _ => Poll::Pending,
            }
        }));
        let response = native_read_owner_router(app.clone(), descriptor)
            .oneshot(json_request(descriptor.path(), body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert!(app.query_fanout_inflight.available_bytes() < before);
        drop(response);
        assert_eq!(app.query_fanout_inflight.available_bytes(), before);

        // The other new endpoint remains bodyless at the same outer boundary.
        let proof = route_catalog::application_api::EXPLORER_TRANSACTIONS_BY_HASH_PROOF_GET;
        let path = proof.path().replace("{hash}", &"ab".repeat(32));
        let proof_polls = Arc::new(AtomicUsize::new(0));
        let request = Request::builder()
            .uri(path)
            .header(header::CONTENT_LENGTH, "1")
            .body(pending_body(&proof_polls))
            .unwrap();
        let response = native_read_owner_router(app.clone(), proof)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(proof_polls.load(Ordering::SeqCst), 0);
        assert_eq!(app.query_fanout_inflight.available_bytes(), before);
    }

    #[tokio::test(start_paused = true)]
    async fn account_inspection_outer_deadline_uses_stricter_native_or_configured_bound() {
        for (configured, expected) in [(60, 5), (1, 1)] {
            let mut app = mk_app_state_for_tests();
            Arc::get_mut(&mut app)
                .unwrap()
                .app_api_routed_read_body_read_timeout = Duration::from_secs(configured);
            let descriptor = route_catalog::application_api::ACCOUNTS_INSPECT_POST;
            let before = app.query_fanout_inflight.available_bytes();
            let polls = Arc::new(AtomicUsize::new(0));
            let started = tokio::time::Instant::now();
            let response = native_read_owner_router(app.clone(), descriptor)
                .oneshot(json_request(descriptor.path(), pending_body(&polls)))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
            assert_eq!(started.elapsed(), Duration::from_secs(expected));
            assert!(polls.load(Ordering::SeqCst) > 0);
            assert!(app.query_fanout_inflight.available_bytes() < before);
            drop(response);
            assert_eq!(app.query_fanout_inflight.available_bytes(), before);
        }
    }

    #[tokio::test]
    async fn collection_execution_refuses_configuration_without_an_owner() {
        let app = mk_app_state_for_tests();
        assert!(current_routed_read_memory_envelope(&app).is_err());
        assert!(torii_routed_read_request_decode_plan(&app).is_err());
        assert!(routing::collection_sources::collection_execution_limits(Some(&app)).is_err());
        assert!(torii_routed_read_request_preflight_plan(&app).is_ok());
    }

    #[tokio::test]
    async fn every_direct_collection_rejects_busy_memory_before_body_polling() {
        let mut app = mk_app_state_for_tests();
        Arc::get_mut(&mut app).unwrap().query_queue_timeout = Duration::ZERO;
        let _occupied = occupy_fanout_pool(&app);
        for entry in APP_LOCAL_COLLECTION_HTTP_ROUTES_V1 {
            let polls = Arc::new(AtomicUsize::new(0));
            let request = if entry.decoder.body_type_name().is_some() {
                json_request(entry.route.path(), pending_body(&polls))
            } else {
                Request::builder()
                    .uri(entry.route.path())
                    .body(Body::empty())
                    .unwrap()
            };
            let response = admission_router(Arc::clone(&app), entry.route, false)
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "{}",
                entry.route.stable_route_id()
            );
            assert_eq!(polls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn detached_collection_worker_keeps_its_actual_memory_owner() {
        let app = mk_app_state_for_tests();
        let before = app.query_fanout_inflight.available_bytes();
        let owner = try_acquire_new_query_fanout_memory(&app).unwrap();
        let admission = COLLECTION_READ_MEMORY_RESERVATION
            .scope(owner.clone(), acquire_query_admission(app.as_ref(), true))
            .await
            .unwrap();
        drop(owner);
        assert_eq!(
            app.query_fanout_inflight.available_bytes(),
            before - 48_000_000
        );
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let work = tokio::spawn(routing::run_admitted_blocking(
            admission,
            "test worker",
            move || {
                let _ = started_tx.send(());
                finish_rx.recv().unwrap();
                Ok(())
            },
        ));
        started_rx.await.unwrap();
        work.abort();
        let _ = work.await;
        assert_eq!(
            app.query_fanout_inflight.available_bytes(),
            before - 48_000_000
        );
        finish_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while app.query_fanout_inflight.available_bytes() != before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed worker returns its owner");
    }

    #[tokio::test]
    async fn producer_body_budget_requires_the_actual_query_owner() {
        let app = mk_app_state_for_tests();
        let owner = try_acquire_new_query_fanout_memory(&app).unwrap();
        let expected = owner.admitted_envelope(&app).unwrap().route_body_bytes;
        let mut admission = COLLECTION_READ_MEMORY_RESERVATION
            .scope(owner, acquire_query_admission(app.as_ref(), false))
            .await
            .unwrap();
        assert_eq!(admission.response_body_budget().unwrap(), expected);

        let response_only = tokio::sync::Semaphore::new(1);
        let response_only = Arc::new(response_only).acquire_owned().await.unwrap();
        admission._fanout_memory = Some(QueryFanoutMemoryReservation::new(response_only));
        assert!(matches!(
            admission.response_body_budget(),
            Err(Error::Query(
                iroha_data_model::ValidationFail::InternalError(_)
            ))
        ));
        admission._fanout_memory = None;
        assert!(admission.response_body_budget().is_err());
    }

    #[test]
    fn catalog_bounds_axum_url_parameter_topology() {
        let mut maximum = 0;
        for entry in APP_ROUTED_READ_HTTP_ENDPOINTS_V1 {
            let names: Vec<_> = entry
                .route
                .path()
                .split('/')
                .filter_map(|component| component.strip_prefix('{')?.strip_suffix('}'))
                .collect();
            maximum = maximum.max(names.len());
            assert!(names.len() <= APP_ROUTED_READ_MAX_URL_PARAMETERS_V1);
            assert!(
                names.iter().map(|name| name.len()).sum::<usize>()
                    <= APP_ROUTED_READ_URL_PARAMETER_KEY_BYTES_V1
            );
        }
        assert_eq!(maximum, APP_ROUTED_READ_MAX_URL_PARAMETERS_V1);
        assert_eq!(APP_ROUTED_READ_URL_PARAMETER_VEC_CAPACITY_V1, 4);
    }
    #[test]
    fn content_length_grammar_is_canonical_and_exact() {
        for invalid in ["", "00", "01", "+1", " 1", "1 ", "1,1", "-1"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(invalid).expect("test header value"),
            );
            assert!(preflight_app_routed_read_content_length(&headers, 8).is_err());
        }
        let mut exact = HeaderMap::new();
        exact.insert(header::CONTENT_LENGTH, HeaderValue::from_static("8"));
        assert_eq!(
            preflight_app_routed_read_content_length(&exact, 8).expect("exact length"),
            Some(8)
        );
        assert!(preflight_app_routed_read_content_length(&exact, 7).is_err());
        let mut duplicate = HeaderMap::new();
        duplicate.append(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
        duplicate.append(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert!(preflight_app_routed_read_content_length(&duplicate, 8).is_err());
        let mut ambiguous = exact;
        ambiguous.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        assert!(preflight_app_routed_read_content_length(&ambiguous, 8).is_err());
        assert_eq!(
            preflight_app_routed_read_content_length(&HeaderMap::new(), 8)
                .expect("missing length is admitted as unknown"),
            None
        );
    }
    #[test]
    fn bodyless_routes_allow_only_missing_or_canonical_zero_framing() {
        assert_eq!(
            preflight_bodyless_app_routed_read(&HeaderMap::new()).expect("missing framing"),
            None
        );
        let mut zero = HeaderMap::new();
        zero.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        assert_eq!(
            preflight_bodyless_app_routed_read(&zero).expect("canonical zero length"),
            Some(0)
        );
        zero.insert(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert!(preflight_bodyless_app_routed_read(&zero).is_err());
        let mut chunked = HeaderMap::new();
        chunked.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        assert!(preflight_bodyless_app_routed_read(&chunked).is_err());
    }
    #[tokio::test]
    async fn missing_content_length_keeps_exact_owner_and_body_extraction_is_zero_copy() {
        let admitted = collect_app_routed_read_body(Body::from("abc"), 8, None)
            .await
            .expect("small unknown-length body");
        assert_eq!(admitted.bytes.as_ref(), b"abc");
        assert_eq!(admitted.destination_bytes, 8);
        let pointer = admitted.bytes.as_ptr();
        let mut request = Request::new(Body::from(admitted.bytes.clone()));
        request.extensions_mut().insert(admitted.clone());
        assert!(
            admitted_app_routed_read_body(&request).is_none(),
            "a typed extension alone is not trusted without task-local admission provenance"
        );
        let app = mk_app_state_for_tests();
        let reservation = try_acquire_new_query_fanout_memory(&app).expect("test reservation");
        let admission = AppRoutedReadHttpAdmission {
            reservation: reservation.clone(),
            decode_plan: torii_routed_read_request_preflight_plan(&app).expect("test request plan"),
        };
        let extension = APP_ROUTED_READ_HTTP_ADMISSION
            .scope(admission, async {
                admitted_app_routed_read_body(&request).expect("stored admitted body")
            })
            .await;
        assert_eq!(extension.as_ptr(), pointer);
        let extracted = axum::body::to_bytes(request.into_body(), 8)
            .await
            .expect("one Full<Bytes> frame collects");
        assert_eq!(extracted.as_ptr(), pointer);
    }
    #[tokio::test]
    async fn zero_body_is_drained_before_returning_canonical_empty_bytes() {
        let polls = Arc::new(AtomicUsize::new(0));
        let body_polls = Arc::clone(&polls);
        let body = Body::from_stream(futures::stream::poll_fn(move |_| {
            let poll = body_polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(match poll {
                0 => Some(Ok::<Bytes, Infallible>(Bytes::new())),
                _ => None,
            })
        }));
        let admitted = collect_app_routed_read_body(body, 8, None)
            .await
            .expect("zero-byte body should drain successfully");
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(admitted.destination_bytes, 8);
        assert_eq!(admitted.bytes, Bytes::new());
        assert_eq!(admitted.bytes.as_ptr(), Bytes::new().as_ptr());
    }
    #[tokio::test]
    async fn unknown_and_lying_lengths_reject_exact_plus_one() {
        let unknown = collect_app_routed_read_body(Body::from("123456789"), 8, None)
            .await
            .expect_err("unknown body over cap must fail");
        assert_eq!(unknown.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let short = collect_app_routed_read_body(Body::from("123"), 8, Some(4))
            .await
            .expect_err("short declared body must fail");
        assert_eq!(short.status(), StatusCode::BAD_REQUEST);
        let long = collect_app_routed_read_body(Body::from("12345"), 8, Some(4))
            .await
            .expect_err("long declared body must fail");
        assert_eq!(long.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
    #[tokio::test]
    async fn bodyless_routes_probe_missing_and_zero_length_bodies() {
        let mut app = mk_app_state_for_tests();
        Arc::get_mut(&mut app)
            .expect("unique test state")
            .app_api_routed_read_body_read_timeout = std::time::Duration::from_millis(1);
        let descriptor = route_catalog::pipeline::TRANSACTION_STATUS;
        let before = app.query_fanout_inflight.available_permits();
        for declared_zero in [false, true] {
            let mut request = Request::builder()
                .uri(descriptor.path())
                .body(Body::from("x"))
                .expect("bodyless request with data");
            if declared_zero {
                request
                    .headers_mut()
                    .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
            }
            let response = admission_router(Arc::clone(&app), descriptor, false)
                .oneshot(request)
                .await
                .expect("bodyless data rejection");
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            drop(response);
            assert_eq!(app.query_fanout_inflight.available_permits(), before);
        }
        let polls = Arc::new(AtomicUsize::new(0));
        let response = admission_router(Arc::clone(&app), descriptor, false)
            .oneshot(
                Request::builder()
                    .uri(descriptor.path())
                    .body(pending_body(&polls))
                    .expect("stalled bodyless request"),
            )
            .await
            .expect("bodyless deadline response");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(polls.load(Ordering::SeqCst) > 0);
        assert!(app.query_fanout_inflight.available_permits() < before);
        drop(response);
        assert_eq!(app.query_fanout_inflight.available_permits(), before);
    }
    #[tokio::test]
    async fn bodyless_zero_length_success_holds_admission_until_response_drop() {
        let app = mk_app_state_for_tests();
        let descriptor = route_catalog::pipeline::TRANSACTION_STATUS;
        let before = app.query_fanout_inflight.available_permits();
        let request = Request::builder()
            .uri(descriptor.path())
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .expect("empty bodyless request");
        let response = admission_router(Arc::clone(&app), descriptor, false)
            .oneshot(request)
            .await
            .expect("bodyless success response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(app.query_fanout_inflight.available_permits() < before);
        drop(response);
        assert_eq!(app.query_fanout_inflight.available_permits(), before);
    }
    #[tokio::test]
    async fn one_byte_and_empty_frames_are_bounded_only_by_admitted_bytes() {
        const BYTES: usize = 5_000;
        let frames = futures::stream::iter((0..BYTES * 2).map(|index| {
            let data = if index % 2 == 0 {
                Bytes::from_static(b"x")
            } else {
                Bytes::new()
            };
            Ok::<_, Infallible>(hyper::body::Frame::data(data))
        }));
        let body = Body::new(http_body_util::StreamBody::new(frames));
        let admitted = collect_app_routed_read_body(body, BYTES, Some(BYTES))
            .await
            .expect("more than 4096 one-byte frames remain compatible");
        assert_eq!(admitted.bytes.len(), BYTES);
    }
    #[tokio::test]
    async fn malformed_and_duplicate_media_reject_without_poll_or_permit() {
        let app = mk_app_state_for_tests();
        let before = app.query_fanout_inflight.available_permits();
        let descriptor = route_catalog::application_api::ACCOUNTS_QUERY_POST;
        for duplicate in [false, true] {
            let polls = Arc::new(AtomicUsize::new(0));
            let mut request = Request::builder()
                .method("POST")
                .uri(descriptor.path())
                .body(pending_body(&polls))
                .expect("pending request");
            request
                .headers_mut()
                .append(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            if duplicate {
                request.headers_mut().append(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
            }
            let response = admission_router(Arc::clone(&app), descriptor, false)
                .oneshot(request)
                .await
                .expect("media rejection response");
            assert!(matches!(
                response.status(),
                StatusCode::BAD_REQUEST | StatusCode::UNSUPPORTED_MEDIA_TYPE
            ));
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert_eq!(app.query_fanout_inflight.available_permits(), before);
        }
    }
    #[tokio::test]
    async fn listener_authentication_precedes_admission_and_body_reaches_deadline() {
        let mut app = mk_app_state_for_tests();
        Arc::get_mut(&mut app)
            .expect("unique test state")
            .app_api_routed_read_body_read_timeout = std::time::Duration::from_millis(1);
        let descriptor = route_catalog::application_api::ACCOUNTS_QUERY_POST;
        let before = app.query_fanout_inflight.available_permits();
        let unauthenticated_polls = Arc::new(AtomicUsize::new(0));
        let response = admission_router(Arc::clone(&app), descriptor, true)
            .oneshot(json_request(
                descriptor.path(),
                pending_body(&unauthenticated_polls),
            ))
            .await
            .expect("auth rejection");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(unauthenticated_polls.load(Ordering::SeqCst), 0);
        assert_eq!(app.query_fanout_inflight.available_permits(), before);
        let authenticated_polls = Arc::new(AtomicUsize::new(0));
        let mut request = json_request(descriptor.path(), pending_body(&authenticated_polls));
        request
            .headers_mut()
            .insert("x-test-auth", HeaderValue::from_static("yes"));
        let response = admission_router(Arc::clone(&app), descriptor, true)
            .oneshot(request)
            .await
            .expect("deadline response");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(authenticated_polls.load(Ordering::SeqCst) > 0);
        assert!(app.query_fanout_inflight.available_permits() < before);
        drop(response);
        assert_eq!(app.query_fanout_inflight.available_permits(), before);
    }
    #[tokio::test]
    async fn busy_admission_fails_before_body_poll_and_task_local_clone_does_not_reacquire() {
        let app = mk_app_state_for_tests();
        let reservation = try_acquire_new_query_fanout_memory(&app)
            .expect("fixture occupies complete fanout working set");
        let _other_memory = app
            .query_fanout_inflight
            .try_acquire_parts([app.query_fanout_inflight.available_bytes()])
            .expect("fixture occupies every other complete working set");
        let occupied = app.query_fanout_inflight.available_permits();
        let polls = Arc::new(AtomicUsize::new(0));
        let descriptor = route_catalog::application_api::ACCOUNTS_QUERY_POST;
        let response = admission_router(Arc::clone(&app), descriptor, false)
            .oneshot(json_request(descriptor.path(), pending_body(&polls)))
            .await
            .expect("busy response");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(app.query_fanout_inflight.available_permits(), occupied);
        let plan = torii_routed_read_request_preflight_plan(&app).expect("test request plan");
        let admission = AppRoutedReadHttpAdmission {
            reservation: reservation.clone(),
            decode_plan: plan,
        };
        APP_ROUTED_READ_HTTP_ADMISSION
            .scope(admission, async {
                let cloned = try_acquire_query_fanout_memory(&app)
                    .expect("downstream borrows outer reservation");
                assert_eq!(app.query_fanout_inflight.available_permits(), occupied);
                drop(cloned);
            })
            .await;
        drop(reservation);
    }

    #[tokio::test]
    async fn default_pool_admits_eight_complete_owners_with_independent_ingress_and_body_custody() {
        let app = mk_app_state_for_tests();
        let before = app.query_fanout_inflight.available_bytes();
        let ingress_before = app.query_ingress_inflight.available_permits();
        assert_eq!(before, 384_000_000);
        assert_eq!(app.query_fanout_working_set_bytes, 48_000_000);
        let mut owners = (0..8)
            .map(|_| try_acquire_new_query_fanout_memory(&app).unwrap())
            .collect::<Vec<_>>();
        for owner in &owners {
            let envelope = owner.admitted_envelope(&app).unwrap();
            assert_eq!(envelope.working_set_bytes, 48_000_000);
            assert!(envelope.phases_fit());
            let request = ToriiRoutedReadMemoryBudget::from_envelope(
                envelope,
                app.torii_proxy_max_response_bytes,
            )
            .request_decode_plan()
            .unwrap();
            assert!(request.raw_input_limit_bytes >= 8 * 1024);
        }
        assert_eq!(app.query_fanout_inflight.available_bytes(), 0);
        assert_eq!(
            app.query_ingress_inflight.available_permits(),
            ingress_before
        );
        let ingress = acquire_query_ingress_memory(&app).await.unwrap();
        assert_eq!(
            app.query_ingress_inflight.available_permits(),
            ingress_before - 1
        );
        assert!(try_acquire_new_query_fanout_memory(&app).is_err());
        drop(ingress);
        let response = hold_query_fanout_memory_in_response_body(
            Response::new(Body::from("retained")),
            owners.pop().unwrap(),
        );
        drop(owners);
        assert_eq!(
            app.query_fanout_inflight.available_bytes(),
            before - 48_000_000
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 8).await.unwrap(),
            Bytes::from_static(b"retained")
        );
        assert_eq!(app.query_fanout_inflight.available_bytes(), before);
        assert_eq!(
            app.query_ingress_inflight.available_permits(),
            ingress_before
        );
    }

    #[tokio::test]
    async fn admitted_geometry_reaches_decoder_coordinator_and_collection_source() {
        let mut app = mk_app_state_for_tests();
        Arc::get_mut(&mut app)
            .unwrap()
            .query_fanout_working_set_bytes = 36_000_000;
        let owner = try_acquire_new_query_fanout_memory(&app).unwrap();
        let envelope = owner.admitted_envelope(&app).unwrap();
        Arc::get_mut(&mut app)
            .unwrap()
            .query_fanout_working_set_bytes = 48_000_000;
        let expected = ToriiRoutedReadMemoryBudget::from_envelope(
            envelope,
            app.torii_proxy_max_response_bytes,
        )
        .request_decode_plan()
        .unwrap();
        let admission = AppRoutedReadHttpAdmission {
            reservation: owner.clone(),
            decode_plan: expected,
        };
        APP_ROUTED_READ_HTTP_ADMISSION
            .scope(admission, async {
                assert_eq!(current_routed_read_memory_envelope(&app).unwrap(), envelope);
                let decoder = torii_routed_read_request_decode_plan(&app).unwrap();
                assert_eq!(
                    decoder.raw_input_limit_bytes,
                    expected.raw_input_limit_bytes
                );
                assert_eq!(decoder.typed_limits, expected.typed_limits);
                let source = routing::collection_sources::collection_execution_limits(Some(&app))
                    .unwrap()
                    .bytes;
                assert_eq!(source.row_bytes, envelope.decode_allocated_bytes);
                assert_eq!(source.source_frame_bytes, envelope.route_body_bytes);
                COLLECTION_READ_MEMORY_RESERVATION
                    .scope(owner.clone(), async {
                        assert_eq!(current_routed_read_memory_envelope(&app).unwrap(), envelope);
                    })
                    .await;
            })
            .await;
        let other = mk_app_state_for_tests();
        assert!(!owner.belongs_to(&other));
        assert!(owner.admitted_envelope(&other).is_err());
        let custody = QueryFanoutMemoryReservation::new(
            other.query_fanout_inflight.try_acquire_parts([1]).unwrap(),
        );
        assert!(!custody.belongs_to(&other));
        assert!(custody.admitted_envelope(&other).is_err());
    }
    #[tokio::test]
    async fn bodyless_read_waits_before_polling_and_releases_capacity_on_cancellation() {
        let mut app = mk_app_state_for_tests();
        Arc::get_mut(&mut app).unwrap().query_queue_timeout = Duration::from_secs(1);
        let before = app.query_fanout_inflight.available_permits();
        let waiters = app.app_routed_read_waiters.available_permits();
        let occupied = occupy_fanout_pool(&app);
        let polls = Arc::new(AtomicUsize::new(0));
        let descriptor = route_catalog::application_api::ACCOUNTS_GET;
        let router = admission_router(Arc::clone(&app), descriptor, false);
        let request = Request::builder()
            .uri(descriptor.path())
            .body(pending_body(&polls))
            .unwrap();
        let mut response = Box::pin(router.oneshot(request));
        assert!(futures::poll!(response.as_mut()).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(app.app_routed_read_waiters.available_permits(), waiters - 1);
        drop(response);
        assert_eq!(app.app_routed_read_waiters.available_permits(), waiters);
        drop(occupied);
        assert_eq!(app.query_fanout_inflight.available_permits(), before);
        let permit = acquire_app_routed_read_http_memory(&app, false)
            .await
            .unwrap();
        assert!(app.query_fanout_inflight.available_permits() < before);
        drop(permit);
        assert_eq!(app.query_fanout_inflight.available_permits(), before);
    }

    #[tokio::test]
    async fn solo_bodyless_burst_queues_under_one_unchanged_memory_working_set() {
        let mut app = mk_app_state_for_tests();
        Arc::get_mut(&mut app).unwrap().query_queue_timeout = Duration::from_secs(5);
        let before = app.query_fanout_inflight.available_permits();
        let occupied = occupy_fanout_pool(&app);
        let descriptor = route_catalog::application_api::ACCOUNTS_GET;
        let mut reads = Vec::new();
        for _ in 0..12 {
            let router = admission_router(Arc::clone(&app), descriptor, false);
            let request = Request::builder()
                .uri(format!("{}?limit=100", descriptor.path()))
                .body(Body::empty())
                .unwrap();
            let mut read = Box::pin(async move {
                let response = router.oneshot(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::NO_CONTENT);
                drop(response);
            });
            assert!(futures::poll!(read.as_mut()).is_pending());
            reads.push(read);
        }
        assert_eq!(app.query_fanout_inflight.available_permits(), 0);
        drop(occupied);
        futures::future::join_all(reads).await;
        assert_eq!(app.query_fanout_inflight.available_permits(), before);
        assert_eq!(
            app.app_routed_read_waiters.available_permits(),
            defaults::torii::QUERY_MAX_INFLIGHT.get()
        );
    }

    #[tokio::test]
    async fn bodyless_read_queue_keeps_finite_count_and_deadline() {
        let mut app = mk_app_state_for_tests();
        let state = Arc::get_mut(&mut app).unwrap();
        state.query_queue_timeout = Duration::from_millis(10);
        state.app_routed_read_waiters = Arc::new(tokio::sync::Semaphore::new(1));
        let before = app.query_fanout_inflight.available_permits();
        let occupied = occupy_fanout_pool(&app);
        let mut waiting = Box::pin(acquire_app_routed_read_http_memory(&app, false));
        assert!(futures::poll!(waiting.as_mut()).is_pending());
        let full = acquire_app_routed_read_http_memory(&app, false)
            .await
            .err()
            .unwrap();
        assert_eq!(full.status(), StatusCode::TOO_MANY_REQUESTS);
        let elapsed = waiting.await.err().unwrap();
        assert_eq!(elapsed.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(app.app_routed_read_waiters.available_permits(), 1);
        drop(occupied);
        assert_eq!(app.query_fanout_inflight.available_permits(), before);
    }

    #[test]
    fn dynamic_raw_target_exact_and_plus_one_precede_permit_acquisition() {
        let app = mk_app_state_for_tests();
        let before = app.query_fanout_inflight.available_permits();
        let mut plan = torii_routed_read_request_preflight_plan(&app).expect("test request plan");
        // `http::Uri` itself has a u16-sized textual ceiling. A small synthetic
        // admission cap exercises exact/+1 accounting without hitting that
        // independent parser boundary first.
        plan.raw_input_limit_bytes = 4_096;
        let exact = format!("/{}", "x".repeat(plan.raw_input_limit_bytes - 1));
        let exact_uri: axum::http::Uri = exact.parse().expect("exact URI");
        assert_eq!(
            app_routed_read_raw_target_bytes(&exact_uri),
            plan.raw_input_limit_bytes
        );
        plan.admit_raw_input(app_routed_read_raw_target_bytes(&exact_uri))
            .expect("exact raw target fits");
        let over_uri: axum::http::Uri = format!("{exact}x").parse().expect("over-limit URI");
        assert!(
            plan.admit_raw_input(app_routed_read_raw_target_bytes(&over_uri))
                .is_err()
        );
        let absolute_prefix = "http://torii.example/";
        let suffix_bytes = plan
            .raw_input_limit_bytes
            .checked_sub(absolute_prefix.len())
            .expect("request limit exceeds absolute-form prefix");
        let absolute = format!("{absolute_prefix}{}", "x".repeat(suffix_bytes));
        let absolute_uri: axum::http::Uri = absolute.parse().expect("absolute-form URI");
        assert_eq!(
            app_routed_read_raw_target_bytes(&absolute_uri),
            absolute.len()
        );
        plan.admit_raw_input(app_routed_read_raw_target_bytes(&absolute_uri))
            .expect("exact absolute-form target fits");
        let absolute_over_uri: axum::http::Uri = format!("{absolute}x")
            .parse()
            .expect("over-limit absolute-form URI");
        assert!(
            plan.admit_raw_input(app_routed_read_raw_target_bytes(&absolute_over_uri))
                .is_err()
        );
        let asterisk_uri: axum::http::Uri = "*".parse().expect("asterisk-form URI");
        assert_eq!(app_routed_read_raw_target_bytes(&asterisk_uri), 1);
        let authority_uri: axum::http::Uri =
            "torii.example:8080".parse().expect("authority-form URI");
        assert_eq!(
            app_routed_read_raw_target_bytes(&authority_uri),
            "torii.example:8080".len()
        );
        assert_eq!(app.query_fanout_inflight.available_permits(), before);
        let source = include_str!("../../torii_app_routed_read_http.rs");
        let target = source
            .find("let target_bytes = app_routed_read_raw_target_bytes")
            .expect("target preflight source");
        let permit = source
            .find("let reservation = match acquire_app_routed_read_http_memory")
            .expect("permit source");
        assert!(target < permit);
    }
}
