// HTTP regressions for the production owner-input route composition.
mod owner_prf_mounted_tests {
    use super::*;
    use crate::tests_runtime_handlers::{app_auth_test_guard, signed_network_app_headers};
    use axum::{Router, body::Body, http::Uri};
    use iroha_torii_shared::route_catalog::{EnabledFeatures, RouteCatalog};
    use tower::ServiceExt as _;

    fn mounted_router(app: SharedAppState, body_limit: usize) -> Router {
        use route_catalog::application_api as routes;
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(&[
                routes::SPACE_DIRECTORY_MANIFESTS_POST,
                routes::SPACE_DIRECTORY_MANIFESTS_REVOKE_POST,
                routes::RAM_LFE_PROGRAMS_BY_PROGRAM_ID_EXECUTE_POST,
                routes::RAM_LFE_RECEIPTS_VERIFY_POST,
                routes::ACCOUNTS_BY_ACCOUNT_ID_IDENTIFIERS_CLAIM_RECEIPT_POST,
                routes::IDENTIFIERS_RESOLVE_POST,
            ]),
            EnabledFeatures::new(&["app_api"]),
        )
        .expect("current application compute route catalog");
        add_authenticated_application_compute_routes(&mut builder, app.clone(), body_limit);
        let (router, _) = builder
            .finish()
            .expect("all compute routes retain declared authentication");
        router.with_state(app)
    }

    async fn send(
        router: &Router,
        method: Method,
        uri: &Uri,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> (StatusCode, Vec<u8>) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri.clone())
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .expect("original HTTP request");
        request.headers_mut().extend(headers);
        request
            .extensions_mut()
            .insert(crate::loopback_connect_info());
        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("mounted route response");
        let status = response.status();
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("complete response body")
            .to_bytes()
            .to_vec();
        (status, body)
    }

    #[tokio::test]
    async fn owner_routes_consume_one_nonce_and_preserve_original_opening_for_distinct_beneficiary()
    {
        let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
        let (app, owner, signer, policy, program) = registered_hkdf_identifier_app(0x52);
        let owner_key = checked_torii_test_ed25519_keypair(0x52, "mounted owner request key");
        let beneficiary = checked_torii_test_account_id(0x54, "distinct claim beneficiary");
        assert_ne!(owner, beneficiary);
        let uaid = UniversalAccountId::from_hash(Hash::new(b"mounted-owner-claim-beneficiary"));
        {
            let mut block = app
                .state
                .block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
            let mut tx = block.transaction();
            iroha_data_model::isi::Register::account(
                Account::new(beneficiary.clone()).with_uaid(Some(uaid)),
            )
            .execute(&owner, &mut tx)
            .expect("seed independent universal beneficiary account and UAID");
            tx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("commit beneficiary fixture");
        }
        let router = mounted_router(app.clone(), 16_384);
        let execute_uri: Uri = format!("/v1/ram-lfe/programs/{}/execute", program.program_id)
            .parse()
            .unwrap();
        // Whitespace is deliberately part of the signed original body.
        let execute_body = format!(
            " \n{{\"normalized_input\":\"alice\",\"input_nonce\":\"{}\"}}\n",
            "a".repeat(64)
        )
        .into_bytes();
        let headers = signed_network_app_headers(
            app.state.network_id_ref(),
            &owner,
            &owner_key,
            &Method::POST,
            &execute_uri,
            &execute_body,
        );
        let (status, body) = send(
            &router,
            Method::POST,
            &execute_uri,
            headers.clone(),
            execute_body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let executed: routing::RamLfeExecuteResponseDto = norito::json::from_slice(&body).unwrap();
        assert_eq!(executed.program_id, program.program_id.to_string());
        let (status, _) = send(&router, Method::POST, &execute_uri, headers, execute_body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the original nonce must still reject replay"
        );

        let claim_uri: Uri = format!("/v1/accounts/{beneficiary}/identifiers/claim-receipt")
            .parse()
            .unwrap();
        let mut request = routing::IdentifierResolveRequestDto {
            phase: "prepare".to_owned(),
            policy_id: policy.id.to_string(),
            normalized_input: "alice".to_owned(),
            input_nonce: "b".repeat(64),
            output_opening: None,
            phone_retail_canonicality: None,
        };
        let body = norito::json::to_vec(&request).unwrap();
        let beneficiary_key = checked_torii_test_ed25519_keypair(0x54, "beneficiary request key");
        let headers = signed_network_app_headers(
            app.state.network_id_ref(),
            &beneficiary,
            &beneficiary_key,
            &Method::POST,
            &claim_uri,
            &body,
        );
        let (status, _) = send(&router, Method::POST, &claim_uri, headers, body.clone()).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the beneficiary cannot substitute for the policy owner"
        );
        let headers = signed_network_app_headers(
            app.state.network_id_ref(),
            &owner,
            &owner_key,
            &Method::POST,
            &claim_uri,
            &body,
        );
        let (status, body) = send(&router, Method::POST, &claim_uri, headers, body).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let prepared: routing::IdentifierPrfPrepareResponseDto =
            norito::json::from_slice(&body).unwrap();
        assert_eq!(prepared.account_id, beneficiary.to_string());
        assert_eq!(prepared.uaid, uaid.to_string());
        prepared
            .output_opening
            .verify_signature(signer.public_key())
            .unwrap();

        request.phase = "claim".to_owned();
        request.output_opening = Some(prepared.output_opening.clone());
        let body = norito::json::to_vec(&request).unwrap();
        let headers = signed_network_app_headers(
            app.state.network_id_ref(),
            &owner,
            &owner_key,
            &Method::POST,
            &claim_uri,
            &body,
        );
        let (status, bytes) = send(&router, Method::POST, &claim_uri, headers, body.clone()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        let receipt: routing::IdentifierResolveResponseDto =
            norito::json::from_slice(&bytes).unwrap();
        assert_eq!(receipt.payload.account_id, beneficiary.to_string());
        assert_eq!(receipt.payload.uaid, uaid.to_string());
        assert_eq!(
            receipt.payload.opening.signature,
            hex::encode(prepared.output_opening.signature.payload())
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
            receipt.payload.opening.payload.input_ciphertext_hash,
            prepared
                .output_opening
                .payload
                .input_ciphertext_hash
                .to_string()
        );

        let resolve_uri: Uri = "/v1/identifiers/resolve".parse().unwrap();
        let headers = signed_network_app_headers(
            app.state.network_id_ref(),
            &owner,
            &owner_key,
            &Method::POST,
            &resolve_uri,
            &body,
        );
        let (status, bytes) = send(&router, Method::POST, &resolve_uri, headers, body).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a prospective receipt has no admitted claim: {}",
            String::from_utf8_lossy(&bytes)
        );
    }

    #[tokio::test]
    async fn owner_routes_reject_unsigned_substituted_and_oversized_requests() {
        let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
        let (app, owner, _, _, program) = registered_hkdf_identifier_app(0x62);
        let owner_key = checked_torii_test_ed25519_keypair(0x62, "mounted bounded owner key");
        let router = mounted_router(app.clone(), 16_384);
        for uri in [
            format!("/v1/ram-lfe/programs/{}/execute", program.program_id),
            format!("/v1/accounts/{owner}/identifiers/claim-receipt"),
            "/v1/identifiers/resolve".to_owned(),
        ] {
            let uri: Uri = uri.parse().unwrap();
            let malformed = b"not-json".to_vec();
            let (status, _) = send(
                &router,
                Method::POST,
                &uri,
                HeaderMap::new(),
                malformed.clone(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "unsigned bytes must be rejected before JSON decoding"
            );
            let headers = signed_network_app_headers(
                app.state.network_id_ref(),
                &owner,
                &owner_key,
                &Method::POST,
                &uri,
                &malformed,
            );
            let (status, _) = send(
                &router,
                Method::POST,
                &uri,
                headers,
                b"changed-body".to_vec(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a body substitution must invalidate its signature"
            );
            let other_uri: Uri = "/v1/not-the-signed-target".parse().unwrap();
            let foreign_network = iroha_data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(
                    [0xed; Hash::LENGTH],
                )),
            );
            assert_ne!(&foreign_network, app.state.network_id_ref());
            for headers in [
                signed_network_app_headers(
                    app.state.network_id_ref(),
                    &owner,
                    &owner_key,
                    &Method::POST,
                    &other_uri,
                    &malformed,
                ),
                signed_network_app_headers(
                    app.state.network_id_ref(),
                    &owner,
                    &owner_key,
                    &Method::GET,
                    &uri,
                    &malformed,
                ),
                signed_network_app_headers(
                    &foreign_network,
                    &owner,
                    &owner_key,
                    &Method::POST,
                    &uri,
                    &malformed,
                ),
            ] {
                let (status, _) =
                    send(&router, Method::POST, &uri, headers, malformed.clone()).await;
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "method, target and network are part of the original signature"
                );
            }
            let (status, _) = send(&router, Method::GET, &uri, HeaderMap::new(), malformed).await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
            let (status, _) = send(
                &router,
                Method::POST,
                &uri,
                HeaderMap::new(),
                vec![b'x'; 16_385],
            )
            .await;
            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
            let smaller = mounted_router(app.clone(), 32);
            let (status, _) = send(
                &smaller,
                Method::POST,
                &uri,
                HeaderMap::new(),
                vec![b'x'; 33],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::PAYLOAD_TOO_LARGE,
                "the configured smaller body limit must survive mounting"
            );
            let larger = mounted_router(app.clone(), 32_768);
            let (status, _) = send(
                &larger,
                Method::POST,
                &uri,
                HeaderMap::new(),
                vec![b'x'; 16_385],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::PAYLOAD_TOO_LARGE,
                "a larger configured limit must not weaken the owner-input bound"
            );
        }
    }
}
