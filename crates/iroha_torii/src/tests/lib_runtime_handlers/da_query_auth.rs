mod da_query_auth {
    //! DA proof authentication through the production router and signed request boundary.

    use super::*;
    use axum::http::{Method, Request, Uri};
    use iroha_data_model::da::{
        commitment::{DaCommitmentBundle, DaCommitmentRecord, DaProofScheme},
        ingest::{
            DaIngestAuthorizationV1, DaIngestSignatureV1, DaPinScopeAuthorizationV1, DaPinScopeV1,
        },
        pin_intent::{DaPinIntent, DaPinIntentBundle},
        types::{BlobDigest, RetentionPolicy, StorageTicketId},
    };
    use iroha_data_model::sorafs::pin_registry::ManifestDigest;
    use iroha_torii_shared::da::{
        DaCommitmentProofRequest, DaCommitmentVerifyResponse, DaPinIntentQueryRequest,
        DaPinIntentVerifyResponse,
    };
    use norito::json;

    fn fixture(account: &AccountId) -> RuntimeApiRouterFixture {
        let kura = Kura::blank_kura_for_testing();
        let state = Arc::new(IrohaState::new_with_chain_and_network_id_for_testing(
            world_with_account(account),
            kura.clone(),
            LiveQueryStore::start_test(),
            ChainId::from("da-query-auth"),
            crate::signed_query_test_network_id(),
        ));
        RuntimeApiRouterFixture::with_runtime(
            "da-query-auth",
            kura,
            state,
            ToriiRuntimeDeps::new(
                crate::build_identity_test_fixture::build_identity(),
                routing::MaybeTelemetry::disabled(),
            ),
        )
    }

    fn request(path: &str, body: &[u8], headers: HeaderMap) -> Request<Body> {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(axum::http::header::ACCEPT, "application/json")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_vec()))
            .expect("DA proof request");
        request.headers_mut().extend(headers);
        request
            .extensions_mut()
            .insert(crate::loopback_connect_info());
        request
    }

    async fn assert_rejected(
        router: &axum::Router,
        request: Request<Body>,
        status: StatusCode,
        code: &str,
        explanation: &str,
    ) {
        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("DA authentication response");
        assert_eq!(response.status(), status);
        let body = torii_body_bytes(response, "DA authentication error").await;
        let error: crate::ErrorEnvelope =
            json::from_slice(&body).expect("typed JSON authentication error");
        assert_eq!(error.code(), code);
        assert!(
            error.message().contains(explanation),
            "unexpected authentication rejection: {}",
            error.message()
        );
    }

    #[expect(
        clippy::future_not_send,
        reason = "current-thread tests retain the global authentication configuration guard across requests"
    )]
    async fn assert_authentication(path: &'static str, body: Vec<u8>) {
        let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
        let signer = checked_torii_test_ed25519_keypair(0xB1, "DA proof request signer");
        let account = AccountId::new(signer.public_key().clone());
        let fixture = fixture(&account);
        let router: &axum::Router = &fixture.router;
        let uri: Uri = path.parse().expect("DA proof URI");
        assert_rejected(
            router,
            request(path, b"{", HeaderMap::new()),
            StatusCode::UNAUTHORIZED,
            "canonical_authentication_required",
            "authentication is required",
        )
        .await;

        let mut partial = signed_app_headers(&account, &signer, &Method::POST, &uri, &body);
        partial.remove(crate::HEADER_NONCE);
        assert_rejected(
            router,
            request(path, b"{", partial),
            StatusCode::FORBIDDEN,
            "query_validation_failed",
            "must be set together",
        )
        .await;

        let foreign_network = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xB2; Hash::LENGTH])),
        );
        let foreign_headers = signed_network_app_headers(
            &foreign_network,
            &account,
            &signer,
            &Method::POST,
            &uri,
            &body,
        );
        assert_rejected(
            router,
            request(path, &body, foreign_headers),
            StatusCode::FORBIDDEN,
            "query_validation_failed",
            "signature failed verification",
        )
        .await;

        let headers = signed_app_headers(&account, &signer, &Method::POST, &uri, &body);
        let mut changed_body = body.clone();
        changed_body.push(b' ');
        assert_rejected(
            router,
            request(path, &changed_body, headers),
            StatusCode::FORBIDDEN,
            "query_validation_failed",
            "signature failed verification",
        )
        .await;

        let unregistered = checked_torii_test_ed25519_keypair(0xB3, "unregistered DA proof signer");
        let unregistered_account = AccountId::new(unregistered.public_key().clone());
        let headers = signed_app_headers(
            &unregistered_account,
            &unregistered,
            &Method::POST,
            &uri,
            &body,
        );
        assert_rejected(
            router,
            request(path, &body, headers),
            StatusCode::FORBIDDEN,
            "query_validation_failed",
            "account is not registered",
        )
        .await;

        let signed_payload = signed_app_headers(&account, &signer, &Method::POST, &uri, &body);
        let response = router
            .clone()
            .oneshot(request(path, &body, signed_payload.clone()))
            .await
            .expect("signed DA handler response");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "registered account reaches {path}"
        );
        let bytes = torii_body_bytes(response, "DA proof handler result").await;
        if path.ends_with("/prove") {
            let value: json::Value = json::from_slice(&bytes).expect("proof absence response");
            assert!(
                value.is_null(),
                "empty committed index has no matching proof"
            );
        } else if path == "/v1/da/commitments/verify" {
            let result: DaCommitmentVerifyResponse =
                json::from_slice(&bytes).expect("commitment verification response");
            assert!(!result.valid);
            assert!(
                result
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains("not available in Kura"))
            );
        } else {
            let result: DaPinIntentVerifyResponse =
                json::from_slice(&bytes).expect("pin-intent verification response");
            assert!(!result.valid);
            assert!(
                result
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains("not available in Kura"))
            );
        }
        assert_rejected(
            router,
            request(path, &body, signed_payload),
            StatusCode::FORBIDDEN,
            "query_validation_failed",
            "nonce already used",
        )
        .await;
        fixture.shutdown().await;
    }

    fn commitment_proof_body() -> Vec<u8> {
        let signer = checked_torii_test_ed25519_keypair(0xB4, "DA commitment proof fixture signer");
        let record = DaCommitmentRecord::new(
            LaneId::new(0),
            1,
            1,
            BlobDigest::new([0xB5; 32]),
            ManifestDigest::new([0xB6; 32]),
            DaProofScheme::MerkleSha256,
            Hash::prehashed([0xB7; 32]),
            None,
            RetentionPolicy::default(),
            StorageTicketId::new([0xB8; 32]),
            Signature::try_new(signer.private_key(), b"DA authentication test commitment")
                .expect("fixture acknowledgement"),
        );
        let proof =
            iroha_core::da::build_da_commitment_proof(&DaCommitmentBundle::new(vec![record]), 1, 0)
                .expect("canonical commitment proof");
        json::to_vec(&proof).expect("commitment proof JSON")
    }

    fn pin_proof_body() -> Vec<u8> {
        let signer = checked_torii_test_ed25519_keypair(0xB9, "DA pin proof fixture signer");
        let mut authorization = DaIngestAuthorizationV1 {
            network_id: crate::signed_query_test_network_id(),
            owner: AccountId::new(signer.public_key().clone()),
            lane_id: LaneId::new(0),
            epoch: 1,
            sequence: 1,
            payload_hash: BlobDigest::new([0xBA; 32]),
            payload_bytes: 1,
            request_content_hash: Hash::prehashed([0xBB; 32]),
            signatures: Vec::new(),
        };
        authorization.signatures.push(DaIngestSignatureV1 {
            signer: signer.public_key().clone(),
            signature: Signature::try_new(signer.private_key(), &authorization.signing_digest())
                .expect("fixture ingest authorization"),
        });
        let scope = DaPinScopeV1::new(
            &authorization,
            StorageTicketId::new([0xBC; 32]),
            ManifestDigest::new([0xBD; 32]),
            None,
        );
        let scope_authorization =
            DaPinScopeAuthorizationV1::try_sign(scope, &signer).expect("fixture pin authorization");
        let bundle =
            DaPinIntentBundle::new(vec![DaPinIntent::new(authorization, scope_authorization)]);
        let proof = iroha_core::da::build_da_pin_intent_proof(&bundle, 1, 0)
            .expect("canonical pin-intent proof");
        json::to_vec(&proof).expect("pin-intent proof JSON")
    }

    #[tokio::test]
    async fn commitment_prove_production_route_requires_exact_signed_account_request() {
        let body = json::to_vec(&DaCommitmentProofRequest {
            lane_id: Some(0),
            epoch: Some(1),
            sequence: Some(1),
            manifest_hash: None,
        })
        .expect("commitment query JSON");
        assert_authentication("/v1/da/commitments/prove", body).await;
    }

    #[tokio::test]
    async fn commitment_verify_production_route_requires_exact_signed_account_request() {
        assert_authentication("/v1/da/commitments/verify", commitment_proof_body()).await;
    }

    #[tokio::test]
    async fn pin_intent_prove_production_route_requires_exact_signed_account_request() {
        let body = json::to_vec(&DaPinIntentQueryRequest {
            lane_id: Some(0),
            epoch: Some(1),
            sequence: Some(1),
            ..DaPinIntentQueryRequest::default()
        })
        .expect("pin-intent query JSON");
        assert_authentication("/v1/da/pin-intents/prove", body).await;
    }

    #[tokio::test]
    async fn pin_intent_verify_production_route_requires_exact_signed_account_request() {
        assert_authentication("/v1/da/pin-intents/verify", pin_proof_body()).await;
    }
}
