mod identifier_owner_routes {
    //! Mounted identifier-owner routes retain one exact signature and beneficiary binding.

    use super::*;
    use tower::ServiceExt as _;

    const COMPUTE_ROUTES: &[route_catalog::RouteDescriptor] = &[
        route_catalog::application_api::SPACE_DIRECTORY_MANIFESTS_POST,
        route_catalog::application_api::SPACE_DIRECTORY_MANIFESTS_REVOKE_POST,
        route_catalog::application_api::RAM_LFE_PROGRAMS_BY_PROGRAM_ID_EXECUTE_POST,
        route_catalog::application_api::RAM_LFE_RECEIPTS_VERIFY_POST,
        route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_IDENTIFIERS_CLAIM_RECEIPT_POST,
        route_catalog::application_api::IDENTIFIERS_RESOLVE_POST,
    ];

    fn owner_router(app: SharedAppState, limit: usize) -> axum::Router {
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(COMPUTE_ROUTES),
            compiled_route_features(),
        )
        .expect("compute descriptors");
        add_authenticated_application_compute_routes(&mut builder, app.clone(), limit);
        let (router, _) = builder
            .finish()
            .expect("production authentication policies");
        router
            .with_state(app)
            .layer(axum::Extension(crate::loopback_connect_info()))
    }

    fn seed_beneficiary(
        app: &SharedAppState,
        owner: &AccountId,
        seed: u8,
    ) -> (AccountId, UniversalAccountId) {
        let beneficiary = checked_torii_test_account_id(seed, "existing identifier beneficiary");
        let uaid = UniversalAccountId::from_hash(Hash::new([seed]));
        let (id, value) = iroha_data_model::IntoKeyValue::into_key_value(
            Account::new(beneficiary.clone())
                .with_uaid(Some(uaid))
                .build(owner),
        );
        // Seed only an existing universal account. No identifier claim is admitted.
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block = app.state.block(header);
        let mut tx = block.transaction();
        assert!(
            tx.world_mut_for_testing()
                .insert_account_for_testing(id, value)
                .is_none()
        );
        tx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("beneficiary fixture");
        (beneficiary, uaid)
    }

    fn prepare_request(policy: &IdentifierPolicy) -> routing::IdentifierResolveRequestDto {
        routing::IdentifierResolveRequestDto {
            phase: "prepare".to_owned(),
            policy_id: policy.id.to_string(),
            normalized_input: "alice".to_owned(),
            input_nonce: "a".repeat(64),
            output_opening: None,
            phone_retail_canonicality: None,
        }
    }

    fn owner_headers(
        app: &SharedAppState,
        owner: &AccountId,
        key: &KeyPair,
        uri: &axum::http::Uri,
        body: &[u8],
    ) -> HeaderMap {
        crate::tests_runtime_handlers::signed_network_app_headers(
            app.state.network_id_ref(),
            owner,
            key,
            &Method::POST,
            uri,
            body,
        )
    }

    async fn post(
        router: &axum::Router,
        uri: &axum::http::Uri,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Response {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri.clone())
            .body(Body::from(body))
            .expect("request");
        *request.headers_mut() = headers;
        request.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        router
            .clone()
            .oneshot(request)
            .await
            .expect("route response")
    }

    fn assert_private(response: &Response) {
        assert_eq!(
            response.headers()[axum::http::header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_eq!(
            response.headers()[axum::http::header::VARY],
            crate::content::CANONICAL_CONTENT_AUTH_VARY
        );
    }

    async fn response_bytes(response: Response) -> axum::body::Bytes {
        http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("body")
            .to_bytes()
    }

    #[tokio::test]
    async fn mounted_owner_claim_allows_distinct_beneficiary_and_consumes_each_signature_once() {
        let (app, owner, signer, policy, program) = registered_hkdf_identifier_app(0x68);
        let key = checked_torii_test_ed25519_keypair(0x68, "current owner route key");
        let (beneficiary, uaid) = seed_beneficiary(&app, &owner, 0x6a);
        assert_ne!(owner, beneficiary);
        let uri: axum::http::Uri = format!("/v1/accounts/{beneficiary}/identifiers/claim-receipt")
            .parse()
            .unwrap();
        let router = owner_router(app.clone(), 16_384);
        let prepare = prepare_request(&policy);
        let body = norito::json::to_vec(&prepare).unwrap();
        let headers = owner_headers(&app, &owner, &key, &uri, &body);
        let response = post(&router, &uri, headers.clone(), body.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_private(&response);
        let prepared: routing::IdentifierPrfPrepareResponseDto =
            norito::json::from_slice(&response_bytes(response).await).unwrap();
        prepared
            .output_opening
            .verify_signature(signer.public_key())
            .unwrap();
        assert_eq!(prepared.account_id, beneficiary.to_string());
        assert_eq!(prepared.uaid, uaid.to_string());
        assert!(prepared.phone_retail_canonicality_payload.is_none());
        identifier_resolution::owner_prf::validate_owner_prf_lease(
            prepared.output_opening.payload.opened_at_ms,
            prepared.output_opening.payload.expires_at_ms,
        )
        .unwrap();
        let replay = post(&router, &uri, headers, body).await;
        assert_eq!(replay.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            replay.headers()[axum::http::header::CONTENT_TYPE],
            utils::NORITO_MIME_TYPE
        );
        let replay_error: ErrorEnvelope =
            norito::decode_from_bytes(&response_bytes(replay).await).expect("Norito replay error");
        assert!(
            replay_error
                .message()
                .contains("request nonce already used")
        );

        let claim = routing::IdentifierResolveRequestDto {
            phase: "claim".to_owned(),
            policy_id: prepare.policy_id.clone(),
            normalized_input: prepare.normalized_input.clone(),
            input_nonce: prepare.input_nonce.clone(),
            output_opening: Some(prepared.output_opening.clone()),
            phone_retail_canonicality: None,
        };
        let body = norito::json::to_vec(&claim).unwrap();
        let headers = owner_headers(&app, &owner, &key, &uri, &body);
        let response = post(&router, &uri, headers.clone(), body.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_private(&response);
        let receipt: routing::IdentifierResolveResponseDto =
            norito::json::from_slice(&response_bytes(response).await).unwrap();
        assert_eq!(receipt.payload.account_id, beneficiary.to_string());
        assert_eq!(receipt.payload.uaid, uaid.to_string());
        assert_eq!(
            receipt.payload.execution.program_id,
            program.program_id.to_string()
        );
        assert_eq!(
            receipt.payload.opening.payload.opened_at_ms,
            prepared.output_opening.payload.opened_at_ms
        );
        assert_eq!(
            receipt.payload.opening.payload.expires_at_ms,
            prepared.output_opening.payload.expires_at_ms
        );
        assert_eq!(
            receipt.payload.opening.signature,
            hex::encode(prepared.output_opening.signature.payload())
        );
        assert_eq!(
            post(&router, &uri, headers, body.clone()).await.status(),
            StatusCode::FORBIDDEN
        );

        // Issuing a prospective receipt does not admit the claim. A fresh owner
        // signature reaches that genuine missing-claim result, rather than replay.
        let resolve_uri: axum::http::Uri = "/v1/identifiers/resolve".parse().unwrap();
        let headers = owner_headers(&app, &owner, &key, &resolve_uri, &body);
        let response = post(&router, &resolve_uri, headers.clone(), body.clone()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_private(&response);
        assert_eq!(
            post(&router, &resolve_uri, headers, body).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn mounted_owner_routes_reject_substitution_without_burning_the_exact_request() {
        let (mut app, owner, _, policy, _) = registered_hkdf_identifier_app(0x72);
        let key = checked_torii_test_ed25519_keypair(0x72, "exact owner route key");
        let (beneficiary, _) = seed_beneficiary(&app, &owner, 0x74);
        let beneficiary_key = checked_torii_test_ed25519_keypair(0x74, "beneficiary request key");
        {
            let state = Arc::get_mut(&mut app).expect("unique fixture");
            state.require_api_token = true;
            state.api_token_digests = Arc::new(limits::ApiTokenDigestSet::from_tokens([
                "owner-route-token",
            ]));
        }
        let router = owner_router(app.clone(), 16_384);
        let uri: axum::http::Uri = format!("/v1/accounts/{beneficiary}/identifiers/claim-receipt")
            .parse()
            .unwrap();
        let prepare = prepare_request(&policy);
        let body = norito::json::to_vec(&prepare).unwrap();
        let add_token = |mut headers: HeaderMap| {
            headers.insert(
                HEADER_API_TOKEN,
                HeaderValue::from_static("owner-route-token"),
            );
            headers
        };
        // API-token access and beneficiary ownership cannot replace policy-owner auth.
        assert_eq!(
            post(&router, &uri, add_token(HeaderMap::new()), body.clone())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let headers = add_token(owner_headers(
            &app,
            &beneficiary,
            &beneficiary_key,
            &uri,
            &body,
        ));
        assert_eq!(
            post(&router, &uri, headers, body.clone()).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let headers = owner_headers(&app, &owner, &key, &uri, &body);
        assert_eq!(
            post(&router, &uri, headers.clone(), body.clone())
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(&router, &uri, add_token(headers), body.clone())
                .await
                .status(),
            StatusCode::OK
        );

        let headers = add_token(owner_headers(&app, &owner, &key, &uri, &body));
        let mut changed_body = body.clone();
        changed_body.push(b'\n'); // Same JSON value, different signed raw bytes.
        assert_eq!(
            post(&router, &uri, headers.clone(), changed_body)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let wrong_uri: axum::http::Uri = "/v1/identifiers/resolve".parse().unwrap();
        assert_eq!(
            post(&router, &wrong_uri, headers.clone(), body.clone())
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let get_headers = add_token(crate::tests_runtime_handlers::signed_network_app_headers(
            app.state.network_id_ref(),
            &owner,
            &key,
            &Method::GET,
            &uri,
            &body,
        ));
        assert_eq!(
            post(&router, &uri, get_headers, body.clone())
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let foreign_network = iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(
                [0xff; Hash::LENGTH],
            )),
        );
        assert_ne!(&foreign_network, app.state.network_id_ref());
        let foreign_headers = add_token(crate::tests_runtime_handlers::signed_network_app_headers(
            &foreign_network,
            &owner,
            &key,
            &Method::POST,
            &uri,
            &body,
        ));
        assert_eq!(
            post(&router, &uri, foreign_headers, body.clone())
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let query_uri: axum::http::Uri = format!("{uri}?extra=1").parse().unwrap();
        assert!(
            post(&router, &query_uri, headers.clone(), body.clone())
                .await
                .status()
                .is_client_error()
        );
        let response = post(&router, &uri, headers, body.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_private(&response);

        // A configured transport bound rejects before signature consumption; the
        // unchanged request remains usable on the ordinary admitted body limit.
        let bounded = owner_router(app.clone(), body.len() - 1);
        let headers = add_token(owner_headers(&app, &owner, &key, &uri, &body));
        assert_eq!(
            post(&bounded, &uri, headers.clone(), body.clone())
                .await
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            post(&router, &uri, headers, body).await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn mounted_program_execute_authenticates_the_raw_owner_request_once() {
        let (app, owner, _, _, program) = registered_hkdf_identifier_app(0x78);
        let key = checked_torii_test_ed25519_keypair(0x78, "program owner route key");
        let uri: axum::http::Uri = format!("/v1/ram-lfe/programs/{}/execute", program.program_id)
            .parse()
            .unwrap();
        let router = owner_router(app.clone(), 16_384);
        let request = routing::RamLfeExecuteRequestDto {
            normalized_input: "alice".to_owned(),
            input_nonce: "b".repeat(64),
        };
        let body = norito::json::to_vec(&request).unwrap();
        assert_eq!(
            post(&router, &uri, HeaderMap::new(), body.clone())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let headers = owner_headers(&app, &owner, &key, &uri, &body);
        let response = post(&router, &uri, headers.clone(), body.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_private(&response);
        let execution: routing::RamLfeExecuteResponseDto =
            norito::json::from_slice(&response_bytes(response).await).unwrap();
        assert_eq!(execution.program_id, program.program_id.to_string());
        assert_eq!(
            execution.receipt.payload.program_id,
            program.program_id.to_string()
        );
        assert_eq!(execution.receipt.payload.output_hash, execution.output_hash);
        assert_eq!(
            execution.receipt.payload.associated_data_hash,
            execution.associated_data_hash
        );
        assert_eq!(
            execution.receipt.payload.executed_at_ms,
            execution.executed_at_ms
        );
        assert_eq!(
            execution.receipt.payload.expires_at_ms,
            execution.expires_at_ms
        );
        identifier_resolution::owner_prf::validate_owner_prf_lease(
            execution.executed_at_ms,
            execution.expires_at_ms,
        )
        .unwrap();
        assert_eq!(execution.receipt.attestation.kind, "signed");
        assert!(execution.receipt.attestation.signature.is_some());
        assert!(execution.receipt.attestation.proof_backend.is_none());
        assert!(execution.receipt.attestation.proof_b64.is_none());
        let replay = post(&router, &uri, headers, body).await;
        assert_eq!(replay.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            replay.headers()[axum::http::header::CONTENT_TYPE],
            utils::NORITO_MIME_TYPE
        );
        let replay_error: ErrorEnvelope =
            norito::decode_from_bytes(&response_bytes(replay).await).expect("Norito replay error");
        assert!(
            replay_error
                .message()
                .contains("request nonce already used")
        );
    }
}
