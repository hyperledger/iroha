// Crate-root runtime configuration, dependency and ingress-policy test modules.

#[cfg(all(test, feature = "app_api"))]
mod public_dataspace_upstream_config_tests {
    use super::*;

    fn route(
        dataspace_id: u64,
        base_url: &str,
    ) -> iroha_config::parameters::actual::ToriiPublicDataspaceUpstream {
        iroha_config::parameters::actual::ToriiPublicDataspaceUpstream {
            dataspace_id: DataSpaceId::new(dataspace_id),
            base_url: reqwest::Url::parse(base_url).expect("test upstream URL"),
        }
    }

    #[test]
    fn typed_public_dataspace_upstreams_are_exact_and_unique() {
        let loaded = load_public_dataspace_upstreams(&[
            route(0, "https://universal.example"),
            route(7, "http://127.0.0.1:8080/torii"),
        ])
        .expect("canonical upstreams");
        assert_eq!(
            loaded.get(&DataSpaceId::UNIVERSAL).map(String::as_str),
            Some("https://universal.example")
        );
        assert_eq!(
            loaded.get(&DataSpaceId::new(7)).map(String::as_str),
            Some("http://127.0.0.1:8080/torii")
        );
        assert!(
            load_public_dataspace_upstreams(&[
                route(7, "https://one.example"),
                route(7, "https://two.example"),
            ])
            .is_err()
        );
        assert!(load_public_dataspace_upstreams(&[route(8, "http://public.example")]).is_err());
    }
}

#[cfg(all(test, feature = "app_api"))]
mod account_capabilities_tests {
    use super::*;

    #[tokio::test]
    async fn account_capabilities_need_no_account_and_bind_current_network() {
        let app = mk_app_state_for_tests();
        let network_id = *app.state.network_id_ref();
        let response = handler_accounts_capabilities(
            State(app),
            axum::http::HeaderMap::new(),
            "/v1/accounts/capabilities".parse().expect("URI"),
            axum::extract::ConnectInfo("127.0.0.1:8080".parse().expect("remote")),
            axum::body::Bytes::new(),
        )
        .await
        .expect("public account capabilities");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "application/json"
        );
        assert_eq!(
            response.headers()[axum::http::header::CACHE_CONTROL],
            "no-store"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("bounded body");
        let value: iroha_torii_shared::account_capabilities::AccountCapabilitiesV1 =
            norito::json::from_slice(&bytes).expect("capabilities JSON");
        assert_eq!(value.network_id, network_id);
        assert_eq!(value.default_signing, "ed25519");
        assert!(
            value
                .allowed_signing
                .iter()
                .any(|algorithm| algorithm == "ed25519")
        );
    }

    #[tokio::test]
    async fn account_capabilities_reject_query_and_body_inputs() {
        for (uri, body) in [
            ("/v1/accounts/capabilities?account_id=unregistered", ""),
            ("/v1/accounts/capabilities", "{}"),
        ] {
            assert!(matches!(
                handler_accounts_capabilities(
                    State(mk_app_state_for_tests()),
                    axum::http::HeaderMap::new(),
                    uri.parse().expect("URI"),
                    axum::extract::ConnectInfo("127.0.0.1:8080".parse().expect("remote")),
                    axum::body::Bytes::from(body),
                )
                .await,
                Err(Error::AppQueryValidation { .. })
            ));
        }
    }

    #[tokio::test]
    async fn account_capabilities_empty_body_limit_rejects_payload_before_handler() {
        let router = axum::Router::new()
            .route(
                "/v1/accounts/capabilities",
                axum::routing::get(handler_accounts_capabilities)
                    .layer(axum::extract::DefaultBodyLimit::max(0)),
            )
            .with_state(mk_app_state_for_tests());
        let mut request = axum::http::Request::builder()
            .uri("/v1/accounts/capabilities")
            .body(axum::body::Body::from(vec![b'x'; 4097]))
            .expect("body-bearing bootstrap request");
        request.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:8080"
                .parse::<std::net::SocketAddr>()
                .expect("remote"),
        ));
        let response = router
            .oneshot(request)
            .await
            .expect("bounded route response");
        assert_eq!(response.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    }
}

#[cfg(test)]
mod node_probe_tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn node_probes_report_node_readiness_and_liveness() {
        let fixture = crate::tests_runtime_handlers::ReadinessNode::start();
        let app = Arc::clone(&fixture.app);
        let readiness = handler_readyz(axum::extract::State(app)).await;
        assert_eq!(readiness.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(readiness.into_body(), usize::MAX)
            .await
            .expect("readiness body");
        assert_eq!(&body[..], b"Ready");
        let liveness = axum::response::IntoResponse::into_response(handler_livez().await);
        assert_eq!(liveness.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(liveness.into_body(), usize::MAX)
            .await
            .expect("liveness body");
        assert_eq!(&body[..], b"Alive");
    }
}

#[cfg(all(test, feature = "app_api"))]
mod explorer_asset_definitions_query_tests {
    use iroha_torii_shared::list_query::{ListQuery, field};
    #[test]
    fn explorer_asset_definition_ownership_uses_shared_filter() {
        let query: ListQuery = norito::json::from_str(
            r#"{"filter":"owning_domain = \"treasury.universal\"","limit":7}"#,
        )
        .expect("shared ownership filter");
        assert_eq!(
            query.filter,
            Some(field("owning_domain").eq("treasury.universal"))
        );
        assert_eq!(query.limit, Some(7));
        for retired in [
            r#"{"domain":"treasury.universal"}"#,
            r#"{"owning_domain":"treasury.universal"}"#,
        ] {
            assert!(
                norito::json::from_str::<ListQuery>(retired).is_err(),
                "top-level resource selectors must be rejected"
            );
        }
    }
}

#[cfg(test)]
mod transaction_ingress_decode_tests {
    use super::*;
    use iroha_data_model::{
        isi::Log,
        transaction::{TransactionBuilder, signed::TransactionSignature},
    };
    use iroha_logger::Level;
    fn signed_transaction_for_test() -> SignedTransaction {
        signed_transaction_for_test_with_message("batch decode")
    }
    fn signed_transaction_for_test_with_message(message: &str) -> SignedTransaction {
        let keypair =
            checked_transaction_batch_test_keypair(0xa1, iroha_crypto::Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        TransactionBuilder::new(
            signed_query_test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, message.to_owned())])
        .sign(keypair.private_key())
    }
    fn signed_transaction_for_test_with_keypair(
        network_id: NetworkId,
        keypair: &KeyPair,
        message: &str,
    ) -> SignedTransaction {
        let authority = AccountId::new(keypair.public_key().clone());
        TransactionBuilder::new(
            network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, message.to_owned())])
        .sign(keypair.private_key())
    }
    fn checked_transaction_batch_test_keypair(
        seed: u8,
        algorithm: iroha_crypto::Algorithm,
    ) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], algorithm)
            .expect("derive transaction batch fixture key")
    }
    fn versioned_signed_transaction(tx: &SignedTransaction) -> Vec<u8> {
        <SignedTransaction as iroha_version::codec::EncodeVersioned>::encode_versioned(tx)
    }
    const SMALL_ORDER_ED25519_SIGNATURE_R: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const NONCANONICAL_ED25519_SIGNATURE_R: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    fn transaction_with_invalid_signature(message: &str) -> SignedTransaction {
        let mut tx = signed_transaction_for_test_with_message(message);
        let mut signature = tx.signature().payload().payload().to_vec();
        let last = signature
            .last_mut()
            .expect("test signature payload is non-empty");
        *last ^= 0xff;
        tx.set_signature(TransactionSignature(SignatureOf::from_signature(
            iroha_crypto::Signature::from_bytes(&signature),
        )));
        tx
    }
    fn transaction_with_malformed_signature_r(
        message: &str,
        replacement_r: &[u8; 32],
    ) -> SignedTransaction {
        let mut tx = signed_transaction_for_test_with_message(message);
        let mut signature = tx.signature().payload().payload().to_vec();
        signature[..replacement_r.len()].copy_from_slice(replacement_r);
        tx.set_signature(TransactionSignature(SignatureOf::from_signature(
            iroha_crypto::Signature::from_bytes(&signature),
        )));
        tx
    }
    #[test]
    fn transaction_batch_fixture_keypair_rejects_all_zero_seed_material() {
        assert!(
            KeyPair::try_from_seed(vec![0; 32], iroha_crypto::Algorithm::Ed25519).is_err(),
            "checked transaction batch fixtures must reject invalid Ed25519 seed material"
        );
        assert!(
            KeyPair::try_from_seed(vec![0; 32], iroha_crypto::Algorithm::Secp256k1).is_err(),
            "checked transaction batch fixtures must reject invalid Secp256k1 seed material"
        );
    }
    #[test]
    fn decode_transaction_batch_payloads_prepares_exact_lengths() {
        let signed = signed_transaction_for_test();
        let expected_len = norito::to_bytes(&signed)
            .expect("signed transaction encodes")
            .len();
        let versioned = versioned_signed_transaction(&signed);
        let decoded =
            decode_transaction_batch_payloads(vec![versioned]).expect("batch transaction decodes");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].hash(), signed.hash());
        assert_eq!(decoded[0].hash_as_entrypoint(), signed.hash_as_entrypoint());
        assert_eq!(decoded[0].encoded_len(), expected_len);
    }
    #[test]
    fn decode_transaction_batch_payloads_rejects_trailing_payload() {
        let signed = signed_transaction_for_test();
        let mut versioned = versioned_signed_transaction(&signed);
        versioned.push(0);
        match decode_transaction_batch_payloads(vec![versioned]) {
            Err(Error::AppQueryValidation { code, .. }) => {
                assert_eq!(code, "invalid_transaction_batch_payload");
            }
            other => panic!("expected invalid batch payload, got {other:?}"),
        }
    }
    #[test]
    fn transaction_batch_ed25519_precheck_accepts_valid_single_key_batch() {
        let tx1 = signed_transaction_for_test_with_message("ed25519-precheck-valid-1");
        let tx2 = signed_transaction_for_test_with_message("ed25519-precheck-valid-2");
        let decoded = decode_transaction_batch_payloads(vec![
            versioned_signed_transaction(&tx1),
            versioned_signed_transaction(&tx2),
        ])
        .expect("valid batch decodes");
        let prechecks = precheck_transaction_batch_ed25519(&decoded, 64);
        assert_eq!(prechecks.len(), 2);
        assert!(prechecks.iter().all(|precheck| {
            precheck.single_ed25519_prechecked && precheck.precheck_rejection.is_none()
        }));
    }
    #[test]
    fn transaction_batch_ed25519_precheck_reuses_exact_duplicate_key() {
        let tx = signed_transaction_for_test_with_message("ed25519-precheck-duplicate");
        let decoded = decode_transaction_batch_payloads(vec![
            versioned_signed_transaction(&tx),
            versioned_signed_transaction(&tx),
        ])
        .expect("valid duplicate batch decodes");
        let prechecks = precheck_transaction_batch_ed25519(&decoded, 64);
        assert_eq!(prechecks.len(), 2);
        assert!(prechecks.iter().all(|precheck| {
            precheck.single_ed25519_prechecked && precheck.precheck_rejection.is_none()
        }));
    }
    #[test]
    fn transaction_batch_ed25519_precheck_rejects_exact_duplicate_invalid_signature() {
        let tx = transaction_with_invalid_signature("ed25519-precheck-duplicate-invalid");
        let decoded = decode_transaction_batch_payloads(vec![
            versioned_signed_transaction(&tx),
            versioned_signed_transaction(&tx),
        ])
        .expect("well-formed duplicate invalid-signature batch decodes");
        let prechecks = precheck_transaction_batch_ed25519(&decoded, 64);
        assert_eq!(prechecks.len(), 2);
        assert!(prechecks.iter().all(|precheck| {
            !precheck.single_ed25519_prechecked && precheck.precheck_rejection.is_some()
        }));
    }
    #[test]
    fn transaction_batch_ed25519_precheck_rejects_malformed_signature_r() {
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_ED25519_SIGNATURE_R),
            ("noncanonical", NONCANONICAL_ED25519_SIGNATURE_R),
        ] {
            let tx = transaction_with_malformed_signature_r(
                &format!("ed25519-precheck-malformed-r-{label}"),
                &replacement_r,
            );
            let decoded =
                decode_transaction_batch_payloads(vec![versioned_signed_transaction(&tx)])
                    .expect("well-formed malformed-signature transaction decodes");
            let mut prechecks = precheck_transaction_batch_ed25519(&decoded, 64);
            assert_eq!(prechecks.len(), 1);
            assert!(
                !prechecks[0].single_ed25519_prechecked,
                "{label} signature R must not be marked prechecked"
            );
            let rejection = prechecks[0]
                .precheck_rejection
                .take()
                .expect("malformed signature R should be marked");
            match rejection {
                AcceptTransactionFail::SignatureVerification(fail) => {
                    assert_eq!(
                        fail.code(),
                        SignatureRejectionCode::InvalidSignature,
                        "{label} signature R produced unexpected rejection code"
                    );
                }
                other => panic!("expected invalid signature rejection, got {other:?}"),
            }
        }
    }
    #[test]
    fn transaction_batch_ed25519_precheck_accepts_repeated_authority_batch() {
        let network_id = signed_query_test_network_id();
        let keypair =
            checked_transaction_batch_test_keypair(0xa2, iroha_crypto::Algorithm::Ed25519);
        let tx1 = signed_transaction_for_test_with_keypair(
            network_id,
            &keypair,
            "ed25519-precheck-repeat-1",
        );
        let tx2 = signed_transaction_for_test_with_keypair(
            network_id,
            &keypair,
            "ed25519-precheck-repeat-2",
        );
        let decoded = decode_transaction_batch_payloads(vec![
            versioned_signed_transaction(&tx1),
            versioned_signed_transaction(&tx2),
        ])
        .expect("valid repeated-authority batch decodes");
        let prechecks = precheck_transaction_batch_ed25519(&decoded, 64);
        assert_eq!(prechecks.len(), 2);
        assert!(prechecks.iter().all(|precheck| {
            precheck.single_ed25519_prechecked && precheck.precheck_rejection.is_none()
        }));
    }
    #[test]
    fn transaction_batch_ed25519_precheck_identifies_first_invalid_signature() {
        let valid = signed_transaction_for_test_with_message("ed25519-precheck-valid");
        let invalid = transaction_with_invalid_signature("ed25519-precheck-invalid");
        let decoded = decode_transaction_batch_payloads(vec![
            versioned_signed_transaction(&valid),
            versioned_signed_transaction(&invalid),
        ])
        .expect("well-formed invalid-signature batch decodes");
        let mut prechecks = precheck_transaction_batch_ed25519(&decoded, 64);
        assert_eq!(prechecks.len(), 2);
        assert!(!prechecks[0].single_ed25519_prechecked);
        assert!(prechecks[0].precheck_rejection.is_none());
        let rejection = prechecks[1]
            .precheck_rejection
            .take()
            .expect("invalid signature should be marked");
        match rejection {
            AcceptTransactionFail::SignatureVerification(fail) => {
                assert_eq!(fail.code(), SignatureRejectionCode::InvalidSignature);
            }
            other => panic!("expected invalid signature rejection, got {other:?}"),
        }
    }
    #[test]
    fn transaction_batch_ed25519_precheck_matches_single_signature_verification() {
        let valid = signed_transaction_for_test_with_message("ed25519-precheck-equivalence-valid");
        let invalid = transaction_with_invalid_signature("ed25519-precheck-equivalence-invalid");
        for signed in [valid, invalid] {
            let decoded =
                decode_transaction_batch_payloads(vec![versioned_signed_transaction(&signed)])
                    .expect("singleton transaction decodes");
            let single_ok = decoded[0].signed().verify_signature().is_ok();
            let prechecks = precheck_transaction_batch_ed25519(&decoded, 64);
            let precheck_ok =
                prechecks[0].single_ed25519_prechecked && prechecks[0].precheck_rejection.is_none();
            assert_eq!(precheck_ok, single_ok);
            assert_eq!(prechecks[0].precheck_rejection.is_some(), !single_ok);
        }
    }
    #[test]
    fn transaction_batch_non_ed25519_bypasses_ed25519_precheck() {
        let keypair =
            checked_transaction_batch_test_keypair(0xa3, iroha_crypto::Algorithm::Secp256k1);
        let authority = AccountId::new(keypair.public_key().clone());
        let signed = TransactionBuilder::new(
            signed_query_test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "batch secp".to_owned())])
        .sign(keypair.private_key());
        let decoded =
            decode_transaction_batch_payloads(vec![versioned_signed_transaction(&signed)])
                .expect("non-Ed25519 signed transaction decodes");
        let prechecks = precheck_transaction_batch_ed25519(&decoded, 64);
        assert_eq!(prechecks.len(), 1);
        assert!(!prechecks[0].single_ed25519_prechecked);
        assert!(prechecks[0].precheck_rejection.is_none());
    }
    #[tokio::test]
    async fn transaction_authority_reservation_rejects_same_authority_atomically() {
        let keypair =
            checked_transaction_batch_test_keypair(0xa4, iroha_crypto::Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let network_id = signed_query_test_network_id();
        let decoded = decode_transaction_batch_payloads(
            (0..3)
                .map(|index| {
                    let signed = TransactionBuilder::new(
                        network_id,
                        authority.clone(),
                        iroha_data_model::transaction::FeePaymentIntent::authority(
                            Vec::new(),
                            None,
                        ),
                    )
                    .with_instructions([Log::new(
                        Level::INFO,
                        format!("same-authority-rate-limit-{index}"),
                    )])
                    .sign(keypair.private_key());
                    versioned_signed_transaction(&signed)
                })
                .collect(),
        )
        .expect("same-authority batch decodes");
        let limiter = crate::limits::RateLimiter::new(Some(1), Some(2));
        let verified_authorities = decoded
            .iter()
            .map(|transaction| transaction.authority().clone())
            .collect::<Vec<_>>();
        let authority_key = transaction_verified_authority_key(&authority);
        assert!(
            reserve_verified_transaction_authorities(&limiter, &verified_authorities)
                .await
                .is_err()
        );
        assert!(
            limiter.allow(&authority_key).await,
            "a rejected aggregate must leave the authority's first token available"
        );
        assert!(
            limiter.allow(&authority_key).await,
            "a rejected aggregate must leave the authority's second token available"
        );
        assert!(
            !limiter.allow(&authority_key).await,
            "the unchanged two-token burst must still reject a third charge"
        );
    }
    #[tokio::test]
    async fn transaction_authority_reservation_rolls_back_nonadjacent_authorities() {
        let keypair_a =
            checked_transaction_batch_test_keypair(0xa5, iroha_crypto::Algorithm::Ed25519);
        let keypair_b =
            checked_transaction_batch_test_keypair(0xa6, iroha_crypto::Algorithm::Ed25519);
        let authority_a = AccountId::new(keypair_a.public_key().clone());
        let authority_b = AccountId::new(keypair_b.public_key().clone());
        let network_id = signed_query_test_network_id();
        let signed_a1 = TransactionBuilder::new(
            network_id,
            authority_a.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "authority-a-1".to_owned())])
        .sign(keypair_a.private_key());
        let signed_b = TransactionBuilder::new(
            network_id,
            authority_b.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "authority-b".to_owned())])
        .sign(keypair_b.private_key());
        let signed_a2 = TransactionBuilder::new(
            network_id,
            authority_a.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "authority-a-2".to_owned())])
        .sign(keypair_a.private_key());
        let decoded = decode_transaction_batch_payloads(vec![
            versioned_signed_transaction(&signed_a1),
            versioned_signed_transaction(&signed_b),
            versioned_signed_transaction(&signed_a2),
        ])
        .expect("mixed-authority batch decodes");
        let limiter = crate::limits::RateLimiter::new(Some(1), Some(1));
        let verified_authorities = decoded
            .iter()
            .map(|transaction| transaction.authority().clone())
            .collect::<Vec<_>>();
        assert!(
            reserve_verified_transaction_authorities(&limiter, &verified_authorities)
                .await
                .is_err()
        );
        assert!(
            limiter
                .allow(&transaction_verified_authority_key(&authority_a))
                .await,
            "authority A must remain uncharged when its aggregate rejects the batch"
        );
        assert!(
            limiter
                .allow(&transaction_verified_authority_key(&authority_b))
                .await,
            "authority B must remain uncharged when another authority rejects the batch"
        );
    }
    #[tokio::test]
    async fn transaction_batch_rate_limit_refunds_uncommitted_queue_reservation() {
        let keypair =
            checked_transaction_batch_test_keypair(0xa7, iroha_crypto::Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let limiter = crate::limits::RateLimiter::new(Some(1), Some(1));
        let reservation =
            reserve_verified_transaction_authorities(&limiter, std::slice::from_ref(&authority))
                .await
                .expect("first queue attempt reserves its authority token");

        drop(reservation);

        assert!(
            limiter
                .allow(&transaction_verified_authority_key(&authority))
                .await,
            "a failed queue attempt must refund its provisional authority charge"
        );
    }
}

#[cfg(all(test, feature = "connect"))]
mod connect_token_tests {
    use super::{
        ConnectWsPermitHandoff, connect_remote_ip_from_headers, connect_session_rejection_response,
        parse_connect_ws_query, resolve_connect_ws_token,
    };
    use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
    #[test]
    fn connect_query_rejects_token_param() {
        let err = parse_connect_ws_query(Some("sid=abc&role=app&token=deadbeef"))
            .expect_err("token param should be rejected");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }
    #[test]
    fn connect_query_rejects_invalid_role() {
        let err = parse_connect_ws_query(Some("sid=abc&role=operator"))
            .expect_err("invalid role should be rejected");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }
    #[test]
    fn connect_query_rejects_noncanonical_shapes() {
        for query in [
            "sid=abc&role=Wallet",
            "sid=abc&role=app&role=wallet",
            "sid=abc&role=app&extra=value",
            "sid=abc&role=%61pp",
            "sid=abc&role=app&",
        ] {
            let err = parse_connect_ws_query(Some(query))
                .expect_err("noncanonical query should be rejected");
            assert_eq!(err.status(), StatusCode::BAD_REQUEST, "query: {query}");
        }
    }
    #[test]
    fn resolve_connect_ws_token_requires_headers() {
        let headers = HeaderMap::new();
        let err = resolve_connect_ws_token(&headers).expect_err("missing token should fail");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }
    #[test]
    fn resolve_connect_ws_token_accepts_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer test-token".parse().unwrap());
        let token = resolve_connect_ws_token(&headers).expect("bearer token ok");
        assert_eq!(token.token, "test-token");
        assert!(token.protocol.is_none());
    }
    #[test]
    fn resolve_connect_ws_token_preserves_protocol_and_exact_matching_bearer() {
        let mut headers = HeaderMap::new();
        let protocol = "iroha-connect.token.v1.dGVzdC10b2tlbg";
        headers.insert(header::SEC_WEBSOCKET_PROTOCOL, protocol.parse().unwrap());
        let token = resolve_connect_ws_token(&headers).expect("canonical protocol token");
        assert_eq!(token.token, "test-token");
        assert_eq!(token.protocol.as_deref(), Some(protocol));
        headers.insert(header::AUTHORIZATION, "Bearer test-token".parse().unwrap());
        let token = resolve_connect_ws_token(&headers).expect("matching independent header token");
        assert_eq!(token.token, "test-token");
        assert_eq!(token.protocol.as_deref(), Some(protocol));
    }
    #[test]
    fn resolve_connect_ws_token_rejects_corrupt_protocol_and_substituted_bearer() {
        for encoded in ["%%%", "", "_w"] {
            let mut headers = HeaderMap::new();
            let protocol = format!("iroha-connect.token.v1.{encoded}");
            headers.insert(header::SEC_WEBSOCKET_PROTOCOL, protocol.parse().unwrap());
            let error = resolve_connect_ws_token(&headers)
                .expect_err("corrupt, empty or non-UTF8 protocol token must fail closed");
            assert_eq!(
                error.status(),
                StatusCode::BAD_REQUEST,
                "encoded: {encoded}"
            );
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            "iroha-connect.token.v1.dGVzdC10b2tlbg".parse().unwrap(),
        );
        headers.insert(
            header::AUTHORIZATION,
            "Bearer substituted-token".parse().unwrap(),
        );
        let error = resolve_connect_ws_token(&headers)
            .expect_err("independent authorization must match the original protocol token");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    }
    #[test]
    fn resolve_connect_ws_token_rejects_duplicate_authorization_headers() {
        let mut headers = HeaderMap::new();
        headers.append(header::AUTHORIZATION, "Bearer first-token".parse().unwrap());
        headers.append(
            header::AUTHORIZATION,
            "Bearer second-token".parse().unwrap(),
        );
        let err = resolve_connect_ws_token(&headers)
            .expect_err("ambiguous bearer credentials must fail closed");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }
    #[test]
    fn connect_remote_ip_requires_injected_header() {
        let headers = HeaderMap::new();
        let err = connect_remote_ip_from_headers(&headers).expect_err("missing remote addr");
        assert_eq!(err, "connect: remote addr unavailable");
    }
    #[test]
    fn connect_remote_ip_accepts_valid_injected_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(crate::limits::REMOTE_ADDR_HEADER),
            "203.0.113.7".parse().unwrap(),
        );
        let ip = connect_remote_ip_from_headers(&headers).expect("remote addr");
        assert_eq!(ip.to_string(), "203.0.113.7");
    }
    #[test]
    fn connect_remote_ip_rejects_invalid_injected_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(crate::limits::REMOTE_ADDR_HEADER),
            "not-an-ip".parse().unwrap(),
        );
        let err = connect_remote_ip_from_headers(&headers).expect_err("invalid remote addr");
        assert_eq!(err, "connect: remote addr unavailable");
    }
    #[test]
    fn connect_session_rejections_preserve_capacity_and_conflict_statuses() {
        let rate_limited = connect_session_rejection_response(
            StatusCode::TOO_MANY_REQUESTS,
            "connect_session_capacity",
            "capacity reached",
        );
        assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            rate_limited.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("1"))
        );
        assert_eq!(
            rate_limited.headers().get("x-iroha-reject-code"),
            Some(&HeaderValue::from_static("connect_session_capacity"))
        );

        let conflict = connect_session_rejection_response(
            StatusCode::CONFLICT,
            "connect_session_exists",
            "already exists",
        );
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert!(!conflict.headers().contains_key(header::RETRY_AFTER));
    }
    #[tokio::test]
    async fn connect_ws_permit_handoff_is_single_owner() {
        let bus = crate::connect::Bus::new();
        let permit = bus
            .pre_ws_handshake("192.0.2.91".parse().expect("test IP"))
            .await
            .expect("reserve WebSocket capacity");
        let handoff = ConnectWsPermitHandoff::new(permit);
        let mut permit = handoff.take().expect("first owner takes permit");
        assert!(handoff.take().is_none());
        permit.release().await;
    }
}

#[cfg(all(test, feature = "app_api"))]
mod appeal_finance_runtime_signer_tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use iroha_data_model::transaction::TransactionBuilder;
    use sorafs_node::appeal_finance_transaction_forwarder::{
        APPEAL_FINANCE_CHECKPOINT_AUTHENTICATION_POLICY_VERSION_V1,
        APPEAL_FINANCE_TRANSACTION_MAX_CANONICAL_BYTES_V1,
        AppealFinanceCheckpointAuthenticationPolicyV1, AppealFinanceCheckpointExternalError,
        AppealFinanceCheckpointRuntime, AppealFinanceCheckpointRuntimeIdentityV1,
        AppealFinanceRuntimeProviderQualificationV1, AppealFinanceSealedCheckpointRecordV1,
        AppealFinanceTransactionForwarder, AppealFinanceTransactionForwarderPolicyV1,
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use tempfile::TempDir;
    struct TestSigner {
        handle: String,
        keypair: KeyPair,
        qualification: sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceRuntimeProviderQualificationV1,
    }
    impl SoraFsAppealFinanceTransactionSigner for TestSigner {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn public_key(&self) -> Result<PublicKey, SoraFsAppealFinanceSigningError> {
            Ok(self.keypair.public_key().clone())
        }
        fn qualification(
            &self,
        ) -> Result<
            sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceRuntimeProviderQualificationV1,
            SoraFsAppealFinanceSigningError,
        >{
            Ok(self.qualification)
        }
        fn sign(
            &self,
            payload: TransactionPayload,
        ) -> Result<SignedTransaction, SoraFsAppealFinanceSigningError> {
            TransactionBuilder::from_payload(payload)
                .and_then(|builder| builder.try_sign(self.keypair.private_key()))
                .map_err(|_| SoraFsAppealFinanceSigningError::Refused)
        }
    }
    struct PostSignQualificationDriftingSigner {
        handle: String,
        keypair: KeyPair,
        qualification: Mutex<
            sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceRuntimeProviderQualificationV1,
        >,
    }
    impl SoraFsAppealFinanceTransactionSigner for PostSignQualificationDriftingSigner {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn public_key(&self) -> Result<PublicKey, SoraFsAppealFinanceSigningError> {
            Ok(self.keypair.public_key().clone())
        }
        fn qualification(
            &self,
        ) -> Result<
            sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceRuntimeProviderQualificationV1,
            SoraFsAppealFinanceSigningError,
        >{
            self.qualification
                .lock()
                .map(|qualification| *qualification)
                .map_err(|_| SoraFsAppealFinanceSigningError::Unavailable)
        }
        fn sign(
            &self,
            _payload: TransactionPayload,
        ) -> Result<SignedTransaction, SoraFsAppealFinanceSigningError> {
            *self
                .qualification
                .lock()
                .map_err(|_| SoraFsAppealFinanceSigningError::Unavailable)? =
                sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceRuntimeProviderQualificationV1::new(
                    2, [0xA2; 32],
                );
            Err(SoraFsAppealFinanceSigningError::Refused)
        }
    }
    fn key(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
            .expect("test Ed25519 key")
    }
    fn provider(handle: &str, keypair: KeyPair) -> Arc<dyn SoraFsAppealFinanceTransactionSigner> {
        Arc::new(TestSigner {
            handle: handle.to_owned(),
            keypair,
            qualification:
                sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceRuntimeProviderQualificationV1::new(
                    1, [0xA1; 32],
                ),
        })
    }
    #[derive(Debug, Default)]
    struct UnexpectedCheckpointRuntime {
        identity_called: AtomicBool,
    }
    impl AppealFinanceCheckpointRuntime for UnexpectedCheckpointRuntime {
        fn identity(
            &self,
        ) -> Result<AppealFinanceCheckpointRuntimeIdentityV1, AppealFinanceCheckpointExternalError>
        {
            self.identity_called.store(true, Ordering::SeqCst);
            Err(AppealFinanceCheckpointExternalError::Unavailable)
        }
        fn sign_digest(
            &self,
            _digest: [u8; 32],
        ) -> Result<[u8; 64], AppealFinanceCheckpointExternalError> {
            Err(AppealFinanceCheckpointExternalError::Unavailable)
        }
        fn load_latest(
            &self,
        ) -> Result<
            Option<AppealFinanceSealedCheckpointRecordV1>,
            AppealFinanceCheckpointExternalError,
        > {
            Err(AppealFinanceCheckpointExternalError::Unavailable)
        }
        fn compare_and_swap_latest(
            &self,
            _expected_revision: Option<[u8; 32]>,
            _next: &AppealFinanceSealedCheckpointRecordV1,
        ) -> Result<(), AppealFinanceCheckpointExternalError> {
            Err(AppealFinanceCheckpointExternalError::Unavailable)
        }
    }
    #[derive(Debug)]
    struct IdentityOnlyCheckpointRuntime {
        identity: AppealFinanceCheckpointRuntimeIdentityV1,
    }
    impl AppealFinanceCheckpointRuntime for IdentityOnlyCheckpointRuntime {
        fn identity(
            &self,
        ) -> Result<AppealFinanceCheckpointRuntimeIdentityV1, AppealFinanceCheckpointExternalError>
        {
            Ok(self.identity.clone())
        }
        fn sign_digest(
            &self,
            _digest: [u8; 32],
        ) -> Result<[u8; 64], AppealFinanceCheckpointExternalError> {
            Err(AppealFinanceCheckpointExternalError::Unavailable)
        }
        fn load_latest(
            &self,
        ) -> Result<
            Option<AppealFinanceSealedCheckpointRecordV1>,
            AppealFinanceCheckpointExternalError,
        > {
            Err(AppealFinanceCheckpointExternalError::Unavailable)
        }
        fn compare_and_swap_latest(
            &self,
            _expected_revision: Option<[u8; 32]>,
            _next: &AppealFinanceSealedCheckpointRecordV1,
        ) -> Result<(), AppealFinanceCheckpointExternalError> {
            Err(AppealFinanceCheckpointExternalError::Unavailable)
        }
    }
    #[derive(Debug)]
    struct DurableTestCheckpointRuntime {
        identity: AppealFinanceCheckpointRuntimeIdentityV1,
        signing_key: SigningKey,
        latest: Mutex<Option<AppealFinanceSealedCheckpointRecordV1>>,
    }
    impl DurableTestCheckpointRuntime {
        fn new(seed: u8) -> Self {
            let signing_key = SigningKey::from_bytes(&[seed; 32]);
            Self {
                identity: AppealFinanceCheckpointRuntimeIdentityV1 {
                    provider_handle: "provider:appeal-finance-checkpoint-primary".to_owned(),
                    public_key: signing_key.verifying_key().to_bytes(),
                    qualification: AppealFinanceRuntimeProviderQualificationV1::new(1, [seed; 32]),
                },
                signing_key,
                latest: Mutex::new(None),
            }
        }
        fn authentication_policy(&self) -> AppealFinanceCheckpointAuthenticationPolicyV1 {
            AppealFinanceCheckpointAuthenticationPolicyV1 {
                version: APPEAL_FINANCE_CHECKPOINT_AUTHENTICATION_POLICY_VERSION_V1,
                provider_handle: self.identity.provider_handle.clone(),
                public_key: self.identity.public_key,
                revision: self.identity.qualification.revision,
                policy_digest: self.identity.qualification.policy_digest,
            }
        }
    }
    impl AppealFinanceCheckpointRuntime for DurableTestCheckpointRuntime {
        fn identity(
            &self,
        ) -> Result<AppealFinanceCheckpointRuntimeIdentityV1, AppealFinanceCheckpointExternalError>
        {
            Ok(self.identity.clone())
        }
        fn sign_digest(
            &self,
            digest: [u8; 32],
        ) -> Result<[u8; 64], AppealFinanceCheckpointExternalError> {
            Ok(self.signing_key.sign(&digest).to_bytes())
        }
        fn load_latest(
            &self,
        ) -> Result<
            Option<AppealFinanceSealedCheckpointRecordV1>,
            AppealFinanceCheckpointExternalError,
        > {
            self.latest
                .lock()
                .map(|latest| latest.clone())
                .map_err(|_| AppealFinanceCheckpointExternalError::Unavailable)
        }
        fn compare_and_swap_latest(
            &self,
            expected_revision: Option<[u8; 32]>,
            next: &AppealFinanceSealedCheckpointRecordV1,
        ) -> Result<(), AppealFinanceCheckpointExternalError> {
            let mut latest = self
                .latest
                .lock()
                .map_err(|_| AppealFinanceCheckpointExternalError::Unavailable)?;
            if latest.as_ref().map(|record| record.revision) != expected_revision
                || latest
                    .as_ref()
                    .map_or(1, |record| record.checkpoint_sequence.saturating_add(1))
                    != next.checkpoint_sequence
            {
                return Err(AppealFinanceCheckpointExternalError::Rejected);
            }
            *latest = Some(next.clone());
            Ok(())
        }
    }
    fn durable_test_forwarder(
        policy: AppealFinanceTransactionForwarderPolicyV1,
    ) -> (AppealFinanceTransactionForwarder, TempDir) {
        let state_dir = tempfile::tempdir().expect("appeal-finance forwarder state directory");
        let runtime = Arc::new(DurableTestCheckpointRuntime::new(0xC5));
        let authentication_policy = runtime.authentication_policy();
        let forwarder = AppealFinanceTransactionForwarder::open(
            state_dir.path(),
            policy,
            authentication_policy,
            runtime,
        )
        .expect("durable appeal-finance forwarder");
        (forwarder, state_dir)
    }
    fn submitter(
        bindings: Vec<iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding>,
        providers: Vec<Arc<dyn SoraFsAppealFinanceTransactionSigner>>,
    ) -> (SoraFsAppealSettlementSubmitter, TempDir) {
        let (forwarder, state_dir) =
            durable_test_forwarder(AppealFinanceTransactionForwarderPolicyV1 {
                max_pending: 8,
                max_completed: 8,
                max_dead_letters: 8,
                max_attempts: 2,
                max_transaction_bytes: APPEAL_FINANCE_TRANSACTION_MAX_CANONICAL_BYTES_V1,
                checkpoint_max_bytes: 8 * 1024 * 1024,
            });
        let submitter = SoraFsAppealSettlementSubmitter {
            bindings,
            runtime_signers: Some(Arc::new(
                SoraFsAppealFinanceRuntimeSignersV1::new(providers)
                    .expect("valid runtime signer registry"),
            )),
            forwarder,
            worker_scan_interval: Duration::from_secs(1),
        };
        (submitter, state_dir)
    }
    #[test]
    fn registry_rejects_duplicate_opaque_handles() {
        let result = SoraFsAppealFinanceRuntimeSignersV1::new(vec![
            provider("provider:appeal", key(1)),
            provider("provider:appeal", key(2)),
        ]);
        assert!(matches!(
            result,
            Err(SoraFsAppealFinanceRuntimeSignerRegistryError::DuplicateHandle)
        ));
    }
    #[test]
    fn registry_handles_use_central_production_grammar() {
        SoraFsAppealFinanceRuntimeSignersV1::new(vec![provider(
            "provider://appeal-finance/primary.v1_slot-a",
            key(2),
        )])
        .expect("canonical production runtime handle");
        for handle in [
            "provider:test:appeal",
            "https://operator:secret@appeal-signer",
            "https://appeal-signer/path?credential=secret",
            "https://appeal-signer/path#fragment",
            "provider://appeal-finance/%70rimary",
            "provider:\\appeal-finance\\primary",
        ] {
            let result = SoraFsAppealFinanceRuntimeSignersV1::new(vec![provider(handle, key(2))]);
            assert!(matches!(
                result,
                Err(SoraFsAppealFinanceRuntimeSignerRegistryError::InvalidHandle)
            ));
        }
    }
    #[test]
    fn post_sign_qualification_drift_discards_transaction_bytes() {
        let configured = key(12);
        let authority = AccountId::new(configured.public_key().clone());
        let binding = iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
            handle: "provider:appeal-qualified".to_owned(),
            authority: authority.clone(),
            public_key: configured.public_key().clone(),
            revision: 1,
            policy_digest: [0xA1; 32],
            valid_from_block_height: 1,
            revoked_at_block_height: None,
        };
        let signer: Arc<dyn SoraFsAppealFinanceTransactionSigner> =
            Arc::new(PostSignQualificationDriftingSigner {
                handle: binding.handle.clone(),
                keypair: configured,
                qualification: Mutex::new(
                    sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceRuntimeProviderQualificationV1::new(
                        binding.revision,
                        binding.policy_digest,
                    ),
                ),
            });
        let signer = SoraFsAppealFinanceQualifiedSignerV1::try_new(&binding, signer)
            .expect("initial signer qualification");
        let payload = TransactionBuilder::new(
            signed_query_test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .into_payload()
        .expect("transaction payload");
        assert!(matches!(
            signer.sign(payload),
            Err(SoraFsAppealFinanceSigningError::QualificationChanged)
        ));
    }
    #[test]
    fn startup_qualification_rejects_missing_registry() {
        let configured = key(6);
        let authority = AccountId::new(configured.public_key().clone());
        let bindings = vec![
            iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                handle: "provider:appeal-current".to_owned(),
                authority,
                public_key: configured.public_key().clone(),
                revision: 1,
                policy_digest: [0xA1; 32],
                valid_from_block_height: 1,
                revoked_at_block_height: None,
            },
        ];
        assert!(matches!(
            qualify_appeal_finance_runtime_signer_inventory(&bindings, None, 7),
            Err(SoraFsAppealFinanceRuntimeSignerQualificationError::RegistryMissing)
        ));
    }
    #[test]
    fn construction_rejects_missing_registry_before_checkpoint_or_state_access() {
        let configured = key(6);
        let authority = AccountId::new(configured.public_key().clone());
        let config = iroha_config::parameters::actual::SorafsAppealFinanceSettlement {
            submitter_signers: vec![
                iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                    handle: "provider:appeal-current".to_owned(),
                    authority,
                    public_key: configured.public_key().clone(),
                    revision: 1,
                    policy_digest: [0xA1; 32],
                    valid_from_block_height: 1,
                    revoked_at_block_height: None,
                },
            ],
            ..Default::default()
        };
        let storage_dir = tempfile::tempdir().expect("temporary storage directory");
        let checkpoint_runtime = Arc::new(UnexpectedCheckpointRuntime::default());
        let error = SoraFsAppealSettlementSubmitter::from_config(
            &config,
            storage_dir.path(),
            None,
            1,
            checkpoint_runtime.clone(),
        )
        .err()
        .expect("missing registry must reject construction");
        assert!(matches!(
            error,
            ToriiBuildError::InvalidRuntimeDependency {
                component: "sorafs.appeal_finance.submitter_signers",
                ..
            }
        ));
        assert!(
            !checkpoint_runtime.identity_called.load(Ordering::SeqCst),
            "checkpoint runtime must remain untouched"
        );
        assert!(
            !storage_dir
                .path()
                .join("appeal-finance-transaction-forwarder")
                .exists(),
            "durable state must not be opened before signer qualification"
        );
    }
    #[test]
    fn construction_rejects_substituted_checkpoint_binding_before_state_access() {
        let transaction_key = key(13);
        let checkpoint_key = key(14);
        let authority = AccountId::new(transaction_key.public_key().clone());
        let config = iroha_config::parameters::actual::SorafsAppealFinanceSettlement {
            submitter_signers: vec![
                iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                    handle: "provider:appeal-current".to_owned(),
                    authority,
                    public_key: transaction_key.public_key().clone(),
                    revision: 1,
                    policy_digest: [0xA1; 32],
                    valid_from_block_height: 1,
                    revoked_at_block_height: None,
                },
            ],
            checkpoint_provider: Some(
                iroha_config::parameters::actual::SorafsAppealFinanceCheckpointBinding {
                    handle: "kms:appeal-checkpoint".to_owned(),
                    public_key: checkpoint_key.public_key().clone(),
                    revision: 4,
                    policy_digest: [0xC4; 32],
                },
            ),
            ..Default::default()
        };
        let runtime_signers = Arc::new(
            SoraFsAppealFinanceRuntimeSignersV1::new(vec![provider(
                "provider:appeal-current",
                transaction_key,
            )])
            .expect("qualified transaction signer"),
        );
        let checkpoint_public_key: [u8; 32] = checkpoint_key
            .public_key()
            .try_to_bytes()
            .expect("checkpoint public key bytes")
            .1
            .try_into()
            .expect("Ed25519 public key width");
        let checkpoint_runtime = Arc::new(IdentityOnlyCheckpointRuntime {
            identity: AppealFinanceCheckpointRuntimeIdentityV1 {
                provider_handle: "kms:appeal-checkpoint-substituted".to_owned(),
                public_key: checkpoint_public_key,
                qualification:
                    sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceRuntimeProviderQualificationV1::new(
                        4, [0xC4; 32],
                    ),
            },
        });
        let storage_dir = tempfile::tempdir().expect("temporary storage directory");
        let error = SoraFsAppealSettlementSubmitter::from_config(
            &config,
            storage_dir.path(),
            Some(runtime_signers),
            1,
            checkpoint_runtime,
        )
        .err()
        .expect("substituted checkpoint must fail construction");
        assert!(matches!(
            error,
            ToriiBuildError::InvalidRuntimeDependency {
                component: "sorafs.appeal_finance.checkpoint_provider",
                ..
            }
        ));
        assert!(
            !storage_dir
                .path()
                .join("appeal-finance-transaction-forwarder")
                .exists(),
            "state must not be opened before checkpoint qualification"
        );
    }
    #[test]
    fn startup_qualification_rejects_missing_active_or_future_provider() {
        let configured = key(7);
        let authority = AccountId::new(configured.public_key().clone());
        let bindings = vec![
            iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                handle: "provider:appeal-current".to_owned(),
                authority: authority.clone(),
                public_key: configured.public_key().clone(),
                revision: 1,
                policy_digest: [0xA1; 32],
                valid_from_block_height: 1,
                revoked_at_block_height: Some(10),
            },
            iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                handle: "provider:appeal-future".to_owned(),
                authority,
                public_key: configured.public_key().clone(),
                revision: 1,
                policy_digest: [0xA1; 32],
                valid_from_block_height: 10,
                revoked_at_block_height: None,
            },
        ];
        let only_future = SoraFsAppealFinanceRuntimeSignersV1::new(vec![provider(
            "provider:appeal-future",
            configured.clone(),
        )])
        .expect("valid future-only registry");
        assert!(matches!(
            qualify_appeal_finance_runtime_signer_inventory(
                &bindings,
                Some(&only_future),
                5
            ),
            Err(
                SoraFsAppealFinanceRuntimeSignerQualificationError::ProviderMissing {
                    handle
                }
            ) if handle == "provider:appeal-current"
        ));
        let only_current = SoraFsAppealFinanceRuntimeSignersV1::new(vec![provider(
            "provider:appeal-current",
            configured,
        )])
        .expect("valid current-only registry");
        assert!(matches!(
            qualify_appeal_finance_runtime_signer_inventory(
                &bindings,
                Some(&only_current),
                5
            ),
            Err(
                SoraFsAppealFinanceRuntimeSignerQualificationError::ProviderMissing {
                    handle
                }
            ) if handle == "provider:appeal-future"
        ));
    }
    #[test]
    fn startup_qualification_rejects_key_and_account_substitution() {
        let configured = key(8);
        let substituted = key(9);
        let authority = AccountId::new(configured.public_key().clone());
        let binding = iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
            handle: "provider:appeal-current".to_owned(),
            authority: authority.clone(),
            public_key: configured.public_key().clone(),
            revision: 1,
            policy_digest: [0xA1; 32],
            valid_from_block_height: 1,
            revoked_at_block_height: None,
        };
        let substituted_key_registry = SoraFsAppealFinanceRuntimeSignersV1::new(vec![provider(
            "provider:appeal-current",
            substituted.clone(),
        )])
        .expect("valid substituted-key registry");
        assert!(matches!(
            qualify_appeal_finance_runtime_signer_inventory(
                std::slice::from_ref(&binding),
                Some(&substituted_key_registry),
                1
            ),
            Err(SoraFsAppealFinanceRuntimeSignerQualificationError::PublicKeyMismatch { .. })
        ));
        let substituted_account_binding =
            iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                authority: AccountId::new(substituted.public_key().clone()),
                ..binding
            };
        let configured_registry = SoraFsAppealFinanceRuntimeSignersV1::new(vec![provider(
            "provider:appeal-current",
            configured,
        )])
        .expect("valid configured-key registry");
        assert!(matches!(
            qualify_appeal_finance_runtime_signer_inventory(
                std::slice::from_ref(&substituted_account_binding),
                Some(&configured_registry),
                1
            ),
            Err(SoraFsAppealFinanceRuntimeSignerQualificationError::AccountIdMismatch { .. })
        ));
    }
    #[test]
    fn startup_qualification_allows_omitted_revoked_historical_provider() {
        let configured = key(10);
        let authority = AccountId::new(configured.public_key().clone());
        let bindings = vec![
            iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                handle: "provider:appeal-retired".to_owned(),
                authority: authority.clone(),
                public_key: configured.public_key().clone(),
                revision: 1,
                policy_digest: [0xA1; 32],
                valid_from_block_height: 1,
                revoked_at_block_height: Some(10),
            },
            iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                handle: "provider:appeal-current".to_owned(),
                authority,
                public_key: configured.public_key().clone(),
                revision: 1,
                policy_digest: [0xA1; 32],
                valid_from_block_height: 10,
                revoked_at_block_height: None,
            },
        ];
        let registry = SoraFsAppealFinanceRuntimeSignersV1::new(vec![provider(
            "provider:appeal-current",
            configured,
        )])
        .expect("valid current registry");
        qualify_appeal_finance_runtime_signer_inventory(&bindings, Some(&registry), 10)
            .expect("already-revoked historical providers may be omitted");
    }
    #[test]
    fn startup_qualification_accepts_complete_rotation_inventory() {
        let configured = key(11);
        let authority = AccountId::new(configured.public_key().clone());
        let bindings = vec![
            iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                handle: "provider:appeal-retired".to_owned(),
                authority: authority.clone(),
                public_key: configured.public_key().clone(),
                revision: 1,
                policy_digest: [0xA1; 32],
                valid_from_block_height: 1,
                revoked_at_block_height: Some(10),
            },
            iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                handle: "provider:appeal-current".to_owned(),
                authority: authority.clone(),
                public_key: configured.public_key().clone(),
                revision: 1,
                policy_digest: [0xA1; 32],
                valid_from_block_height: 10,
                revoked_at_block_height: Some(20),
            },
            iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                handle: "provider:appeal-future".to_owned(),
                authority,
                public_key: configured.public_key().clone(),
                revision: 1,
                policy_digest: [0xA1; 32],
                valid_from_block_height: 20,
                revoked_at_block_height: None,
            },
        ];
        let registry = SoraFsAppealFinanceRuntimeSignersV1::new(vec![
            provider("provider:appeal-current", configured.clone()),
            provider("provider:appeal-future", configured),
        ])
        .expect("valid rotation registry");
        qualify_appeal_finance_runtime_signer_inventory(&bindings, Some(&registry), 10)
            .expect("current and future rotation providers qualify at startup");
    }
    #[test]
    fn selection_rejects_provider_key_substitution() {
        let configured = key(3);
        let authority = AccountId::new(configured.public_key().clone());
        let (submitter, _forwarder_state_dir) = submitter(
            vec![
                iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                    handle: "provider:appeal".to_owned(),
                    authority: authority.clone(),
                    public_key: configured.public_key().clone(),
                    revision: 1,
                    policy_digest: [0xA1; 32],
                    valid_from_block_height: 1,
                    revoked_at_block_height: None,
                },
            ],
            vec![provider("provider:appeal", key(4))],
        );
        assert!(matches!(
            submitter.signer_for(&authority, 1),
            Err(SoraFsAppealFinanceSignerSelectionError::IdentityMismatch)
        ));
    }
    #[test]
    fn active_binding_observation_does_not_require_runtime_signer_provider() {
        let configured = key(4);
        let authority = AccountId::new(configured.public_key().clone());
        let (submitter, _forwarder_state_dir) = submitter(
            vec![
                iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                    handle: "provider:appeal-offline".to_owned(),
                    authority: authority.clone(),
                    public_key: configured.public_key().clone(),
                    revision: 1,
                    policy_digest: [0xA1; 32],
                    valid_from_block_height: 1,
                    revoked_at_block_height: None,
                },
            ],
            Vec::new(),
        );
        assert_eq!(
            submitter
                .active_binding_for(&authority, 1)
                .expect("configured binding remains active")
                .handle,
            "provider:appeal-offline"
        );
        assert!(matches!(
            submitter.signer_for(&authority, 1),
            Err(SoraFsAppealFinanceSignerSelectionError::ProviderMissing)
        ));
    }
    #[test]
    fn selection_obeys_rotation_and_revocation_boundaries() {
        let configured = key(5);
        let authority = AccountId::new(configured.public_key().clone());
        let (submitter, _forwarder_state_dir) = submitter(
            vec![
                iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                    handle: "provider:appeal-old".to_owned(),
                    authority: authority.clone(),
                    public_key: configured.public_key().clone(),
                    revision: 1,
                    policy_digest: [0xA1; 32],
                    valid_from_block_height: 1,
                    revoked_at_block_height: Some(10),
                },
                iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                    handle: "provider:appeal-new".to_owned(),
                    authority: authority.clone(),
                    public_key: configured.public_key().clone(),
                    revision: 1,
                    policy_digest: [0xA1; 32],
                    valid_from_block_height: 10,
                    revoked_at_block_height: Some(20),
                },
            ],
            vec![
                provider("provider:appeal-old", configured.clone()),
                provider("provider:appeal-new", configured),
            ],
        );
        assert!(matches!(
            submitter.signer_for(&authority, 0),
            Err(SoraFsAppealFinanceSignerSelectionError::NotYetActive)
        ));
        assert_eq!(
            submitter
                .signer_for(&authority, 9)
                .expect("old signer active")
                .handle,
            "provider:appeal-old"
        );
        assert_eq!(
            submitter
                .signer_for(&authority, 10)
                .expect("new signer active")
                .handle,
            "provider:appeal-new"
        );
        assert!(matches!(
            submitter.signer_for(&authority, 20),
            Err(SoraFsAppealFinanceSignerSelectionError::NoActiveBinding)
        ));
    }
}

#[cfg(all(test, feature = "app_api"))]
mod sorafs_evidence_viewer_startup_tests {
    use super::*;
    #[test]
    fn runtime_dependency_shape_is_fail_closed() {
        for supplied_mask in 0_u16..128 {
            let supplied = |bit| (supplied_mask & (1_u16 << bit)) != 0_u16;
            let enabled_error = sorafs_evidence_viewer_dependency_error(
                true,
                [
                    supplied(0),
                    supplied(1),
                    supplied(2),
                    supplied(3),
                    supplied(4),
                    supplied(5),
                    supplied(6),
                ],
            );
            assert_eq!(
                enabled_error,
                (supplied_mask != 0b111_1111)
                    .then_some(SORAFS_EVIDENCE_VIEWER_MISSING_RUNTIME_DEPENDENCIES)
            );
            let disabled_error = sorafs_evidence_viewer_dependency_error(
                false,
                [
                    supplied(0),
                    supplied(1),
                    supplied(2),
                    supplied(3),
                    supplied(4),
                    supplied(5),
                    supplied(6),
                ],
            );
            assert_eq!(
                disabled_error,
                (supplied_mask != 0)
                    .then_some(SORAFS_EVIDENCE_VIEWER_UNEXPECTED_RUNTIME_DEPENDENCIES)
            );
        }
    }
    #[test]
    fn launcher_uses_only_the_qualified_checkpoint_store_entry_point() {
        let compact_source: String = include_str!("lib.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let qualified_open = [
            "EvidenceViewerServiceV1::",
            "open_with_checkpoint_store(service_config,service_deps,sorafs_node.clone(),",
            "policy.checkpoint_store_handle.clone(),",
        ]
        .concat();
        let revision_pin = ["policy.", "checkpoint_store_revision"].concat();
        let digest_pin = ["policy.", "checkpoint_store_policy_digest"].concat();
        let archive_handle_pin = ["policy.", "compaction_archive_handle"].concat();
        let archive_revision_pin = ["policy.", "compaction_archive_revision"].concat();
        let archive_policy_pin = ["policy.", "compaction_archive_policy_digest"].concat();
        let archive_id_pin = ["policy.", "compaction_archive_id"].concat();
        let archive_key_pin = ["policy.", "compaction_archive_public_key"].concat();
        let publisher_handle_pin = ["policy.", "transparency_publisher_handle"].concat();
        let publisher_revision_pin = ["policy.", "transparency_publisher_revision"].concat();
        let publisher_policy_pin = ["policy.", "transparency_publisher_policy_digest"].concat();
        let publisher_key_pin = ["policy.", "transparency_publisher_public_key"].concat();
        let providerless_open = [
            "EvidenceViewerServiceV1::",
            "open(service_config,service_deps,sorafs_node.clone())",
        ]
        .concat();
        assert!(compact_source.contains(&qualified_open));
        assert!(compact_source.contains(&revision_pin));
        assert!(compact_source.contains(&digest_pin));
        assert!(compact_source.contains(&archive_handle_pin));
        assert!(compact_source.contains(&archive_revision_pin));
        assert!(compact_source.contains(&archive_policy_pin));
        assert!(compact_source.contains(&archive_id_pin));
        assert!(compact_source.contains(&archive_key_pin));
        assert!(compact_source.contains(&publisher_handle_pin));
        assert!(compact_source.contains(&publisher_revision_pin));
        assert!(compact_source.contains(&publisher_policy_pin));
        assert!(compact_source.contains(&publisher_key_pin));
        assert!(compact_source.contains("compaction_archive,"));
        assert!(compact_source.contains(
            "EvidenceViewerTransparencyProducerV1::try_new(producer_config,transparency_publisher)"
        ));
        assert!(compact_source.contains("producer.reconcile().is_ok()"));
        assert!(!compact_source.contains(&providerless_open));
    }
    #[test]
    fn launcher_uses_bounded_archive_compaction_without_a_fallback() {
        let compact_source: String = include_str!("lib.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let mock_archive_constructor = ["MockCompactionArchive", "::new"].concat();
        assert!(
            compact_source
                .contains("self.spawn_evidence_viewer_compaction_worker(shutdown_signal.clone())")
        );
        assert!(compact_source.contains("service.compact_expired_tick(now_unix_ms)"));
        assert!(compact_source.contains(
            "publish_evidence_viewer_transparency_tick(service.as_ref(),transparency_producer.as_ref())"
        ));
        assert!(compact_source.contains("Duration::from_millis(service.compaction_interval_ms())"));
        assert!(!compact_source.contains(&mock_archive_constructor));
    }
    #[test]
    fn transparency_retry_backoff_is_bounded_and_deterministic() {
        assert_eq!(evidence_viewer_transparency_backoff_ticks(0), 0);
        assert_eq!(evidence_viewer_transparency_backoff_ticks(1), 1);
        assert_eq!(evidence_viewer_transparency_backoff_ticks(2), 3);
        assert_eq!(evidence_viewer_transparency_backoff_ticks(3), 7);
        assert_eq!(evidence_viewer_transparency_backoff_ticks(u8::MAX), 7);
        assert_eq!(EVIDENCE_VIEWER_TRANSPARENCY_PAGE_ITEMS_V1, 256);
        assert_eq!(EVIDENCE_VIEWER_TRANSPARENCY_MAX_PAGES_PER_TICK_V1, 16);
    }
    #[tokio::test]
    async fn evidence_viewer_compaction_skips_immediate_tick_after_shutdown() {
        let shutdown = ShutdownSignal::new();
        shutdown.send();
        let mut ticker = tokio::time::interval(Duration::from_millis(1));

        assert!(
            !wait_for_evidence_viewer_compaction_tick(&shutdown, &mut ticker).await,
            "a pre-sent shutdown must win over Tokio interval's immediate first tick"
        );
    }
    #[tokio::test]
    async fn evidence_viewer_compaction_supervision_joins_on_normal_shutdown() {
        let shutdown = ShutdownSignal::new();
        let worker_shutdown = shutdown.clone();
        let worker_joined = Arc::new(AtomicBool::new(false));
        let worker_joined_after_stop = Arc::clone(&worker_joined);
        let worker = EvidenceViewerCompactionWorkerHandle::new(tokio::spawn(async move {
            worker_shutdown.receive().await;
            worker_joined_after_stop.store(true, AtomicOrdering::Release);
        }));
        let server_shutdown = shutdown.clone();
        let server = async move {
            server_shutdown.receive().await;
            Ok::<(), std::io::Error>(())
        };
        let supervised_shutdown = shutdown.clone();
        let supervision = tokio::spawn(async move {
            supervise_evidence_viewer_compaction_worker(supervised_shutdown, Some(worker), server)
                .await
        });
        tokio::task::yield_now().await;
        shutdown.send();
        let server_result = tokio::time::timeout(Duration::from_secs(1), supervision)
            .await
            .expect("normal compaction shutdown must not hang")
            .expect("compaction supervisor task must not panic")
            .expect("normal compaction shutdown must not fail supervision");
        server_result.expect("test Torii server must stop cleanly");
        assert!(worker_joined.load(AtomicOrdering::Acquire));
    }
    #[tokio::test]
    async fn evidence_viewer_compaction_supervision_fails_closed_on_unexpected_exit() {
        let shutdown = ShutdownSignal::new();
        let worker = EvidenceViewerCompactionWorkerHandle::new(tokio::spawn(async move {}));
        let server_shutdown = shutdown.clone();
        let server_observed_shutdown = Arc::new(AtomicBool::new(false));
        let server_observed_shutdown_after_stop = Arc::clone(&server_observed_shutdown);
        let server = async move {
            server_shutdown.receive().await;
            server_observed_shutdown_after_stop.store(true, AtomicOrdering::Release);
            Ok::<(), std::io::Error>(())
        };
        let failure = tokio::time::timeout(
            Duration::from_secs(1),
            supervise_evidence_viewer_compaction_worker(shutdown.clone(), Some(worker), server),
        )
        .await
        .expect("unexpected compaction exit must not hang")
        .expect_err("unexpected compaction exit must fail supervision");
        assert_eq!(
            failure,
            EvidenceViewerCompactionSupervisionFailure::WorkerExitedUnexpectedly
        );
        assert!(shutdown.is_sent());
        assert!(server_observed_shutdown.load(AtomicOrdering::Acquire));
    }
    #[tokio::test]
    async fn evidence_viewer_compaction_supervision_fails_closed_on_panic() {
        let shutdown = ShutdownSignal::new();
        let worker = EvidenceViewerCompactionWorkerHandle::new(tokio::spawn(async move {
            panic!("injected evidence-viewer compaction worker panic");
        }));
        let server_shutdown = shutdown.clone();
        let server = async move {
            server_shutdown.receive().await;
            Ok::<(), std::io::Error>(())
        };
        let failure = tokio::time::timeout(
            Duration::from_secs(1),
            supervise_evidence_viewer_compaction_worker(shutdown.clone(), Some(worker), server),
        )
        .await
        .expect("panicked compaction worker supervision must not hang")
        .expect_err("panicked compaction worker must fail supervision");
        assert_eq!(
            failure,
            EvidenceViewerCompactionSupervisionFailure::WorkerPanicked
        );
        assert!(shutdown.is_sent());
    }
    #[test]
    fn startup_failure_is_typed_and_payload_free() {
        let error = Error::SorafsEvidenceViewerStartup {
            code: SORAFS_EVIDENCE_VIEWER_INITIALIZATION_FAILED,
        };
        assert_eq!(error.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        let envelope = error.into_envelope();
        assert_eq!(envelope.code(), "sorafs_evidence_viewer_startup_error");
        assert_eq!(
            envelope.message(),
            "SoraFS evidence-viewer runtime failed to start"
        );
        assert!(!envelope.message().contains("initialization_failed"));
    }
}

#[cfg(test)]
mod iso_bridge_body_limit_tests {
    use super::iso_bridge_body_limit;
    #[test]
    fn body_limit_is_positive_and_capped_by_transaction_limit() {
        assert_eq!(iso_bridge_body_limit(1024 * 1024, 64_000_000), 1024 * 1024);
        assert_eq!(iso_bridge_body_limit(128_000_000, 64_000_000), 64_000_000);
        assert_eq!(iso_bridge_body_limit(0, 64_000_000), 1);
    }
}

#[cfg(all(test, feature = "app_api"))]
mod musubi_search_initialization_tests {
    use super::select_initial_musubi_search_index;
    use iroha_core::musubi_search::{MusubiSearchError, MusubiSearchIndexV1};
    use iroha_data_model::musubi::{
        MusubiPackageMetadataRecordV1, MusubiPackageRecordV1, MusubiSearchSnapshotV1,
    };
    #[test]
    fn inconsistent_discovery_projection_does_not_disable_registry_routes() {
        let unavailable =
            select_initial_musubi_search_index(Err(MusubiSearchError::InconsistentFinalizedEvent));
        assert!(unavailable.snapshot().is_none());
        let snapshot = MusubiSearchSnapshotV1 {
            finalized_height: 7,
            finalized_block_hash: [0x51; 32],
            projection_revision: 3,
        };
        let rebuilt = MusubiSearchIndexV1::rebuild_records(
            core::iter::empty::<&MusubiPackageRecordV1>(),
            core::iter::empty::<&MusubiPackageMetadataRecordV1>(),
            snapshot,
        )
        .expect("empty finalized search projection");
        let available = select_initial_musubi_search_index(Ok(rebuilt));
        assert_eq!(available.snapshot(), Some(snapshot));
    }
}

#[cfg(test)]
mod semaphore_capacity_validation_tests {
    use super::{ToriiBuildError, validate_semaphore_permits};

    #[test]
    fn accepts_exact_runtime_limit_and_rejects_larger_values() {
        let limit = tokio::sync::Semaphore::MAX_PERMITS;
        assert_eq!(
            validate_semaphore_permits("test", limit).expect("exact limit is valid"),
            limit
        );
        assert!(matches!(
            validate_semaphore_permits("test", limit + 1),
            Err(ToriiBuildError::InvalidConfiguration {
                component: "test",
                ..
            })
        ));
    }
}

#[cfg(test)]
mod test_api_router_runtime_tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_joins_retained_physical_worker_completion() {
        let shutdown_signal = ShutdownSignal::new();
        let worker_shutdown = shutdown_signal.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = tokio::spawn(async move {
            worker_shutdown.receive().await;
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    started_tx
                        .send(())
                        .expect("teardown still waits for worker");
                    release_rx
                        .recv()
                        .expect("test releases retained physical completion");
                }),
            )
            .await
            .expect("retained physical completion joins");
            ToriiCriticalWorkerExit::StoppedByShutdown
        });
        let runtime = TestApiRouterRuntime {
            router: axum::Router::new(),
            shutdown_signal,
            workers: vec![ToriiCriticalWorker {
                name: "physical_test_worker",
                task: worker,
            }],
        };

        let teardown = tokio::spawn(runtime.shutdown());
        started_rx
            .await
            .expect("retained worker begins physical completion");
        assert!(
            !teardown.is_finished(),
            "test runtime teardown must wait for retained physical completion"
        );
        release_tx
            .send(())
            .expect("release retained physical completion");
        tokio::time::timeout(Duration::from_secs(5), teardown)
            .await
            .expect("test runtime teardown completes")
            .expect("test runtime teardown task joins");
    }
}

#[cfg(all(test, feature = "app_api"))]
mod sorafs_native_transaction_signer_startup_tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair, PublicKey};
    use iroha_data_model::{
        account::AccountId,
        transaction::{SignedTransaction, TransactionBuilder, TransactionPayload},
    };
    const QUALIFICATION: SorafsNativeTransactionSignerQualificationV1 =
        SorafsNativeTransactionSignerQualificationV1::new(9, [0x59; 32]);
    #[test]
    fn storage_enabled_requires_native_signers_independently_of_generation_flags() {
        assert!(sorafs_native_signer_role_required(true, false));
        assert!(sorafs_native_signer_role_required(true, true));
        assert!(sorafs_native_signer_role_required(false, true));
        assert!(!sorafs_native_signer_role_required(false, false));
    }
    struct ProofSigner {
        handle: String,
        key_pair: KeyPair,
    }
    impl ProofSigner {
        fn new(handle: impl Into<String>, seed: u8) -> Self {
            Self {
                handle: handle.into(),
                key_pair: KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .expect("derive native signer startup fixture"),
            }
        }
        fn configured_binding(
            &self,
        ) -> iroha_config::parameters::actual::SorafsNativeTransactionSignerBinding {
            let public_key = self.key_pair.public_key().clone();
            iroha_config::parameters::actual::SorafsNativeTransactionSignerBinding {
                software_credential: None,
                handle: self.handle.clone(),
                authority: AccountId::new(public_key.clone()),
                algorithm: Algorithm::Ed25519,
                public_key,
                revision: QUALIFICATION.revision(),
                policy_digest: QUALIFICATION.policy_digest(),
            }
        }
    }
    impl SorafsNativeTransactionSignerProviderV1 for ProofSigner {
        fn role(&self) -> SorafsNativeTransactionSignerRoleV1 {
            SorafsNativeTransactionSignerRoleV1::ProofOutcome
        }
        fn handle(&self) -> &str {
            &self.handle
        }
        fn authority(&self) -> AccountId {
            AccountId::new(self.key_pair.public_key().clone())
        }
        fn public_key(&self) -> Result<PublicKey, SorafsNativeTransactionSignerProbeErrorV1> {
            Ok(self.key_pair.public_key().clone())
        }
        fn qualification(
            &self,
        ) -> Result<
            SorafsNativeTransactionSignerQualificationV1,
            SorafsNativeTransactionSignerProbeErrorV1,
        > {
            Ok(QUALIFICATION)
        }
    }
    impl SoraFsProofOutcomeTransactionSigner for ProofSigner {
        fn sign(
            &self,
            payload: TransactionPayload,
        ) -> Result<SignedTransaction, SoraFsProofOutcomeSigningError> {
            TransactionBuilder::from_payload(payload)
                .and_then(|builder| builder.try_sign(self.key_pair.private_key()))
                .map_err(|_| SoraFsProofOutcomeSigningError::Refused)
        }
    }
    #[test]
    fn required_native_signer_role_rejects_missing_binding_and_provider() {
        let error = qualify_configured_sorafs_native_transaction_signer_for_startup::<
            dyn SoraFsProofOutcomeTransactionSigner,
        >(
            signed_query_test_network_id(),
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            true,
            None,
            None,
            qualify_sorafs_proof_outcome_transaction_signer_v1,
        )
        .err()
        .expect("required role must fail without a configured binding");
        assert!(error.contains("missing its configured binding"));
    }
    #[test]
    fn inactive_native_signer_role_rejects_injected_provider() {
        let provider: Arc<dyn SoraFsProofOutcomeTransactionSigner> = Arc::new(ProofSigner::new(
            "provider://sorafs/proof-outcome/unrequested",
            0x11,
        ));
        let error = qualify_configured_sorafs_native_transaction_signer_for_startup(
            signed_query_test_network_id(),
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            false,
            None,
            Some(provider),
            qualify_sorafs_proof_outcome_transaction_signer_v1,
        )
        .err()
        .expect("inactive role must reject an injected provider");
        assert!(error.contains("rejects an injected runtime provider"));
    }
    #[test]
    fn native_signer_startup_qualifies_exact_configured_provider() {
        let provider = Arc::new(ProofSigner::new(
            "provider://sorafs/proof-outcome/primary",
            0x21,
        ));
        let configured = provider.configured_binding();
        let network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([0x73; 32])),
        );
        assert_ne!(network_id, signed_query_test_network_id());
        let provider: Arc<dyn SoraFsProofOutcomeTransactionSigner> = provider;
        let qualified = qualify_configured_sorafs_native_transaction_signer_for_startup(
            network_id,
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            true,
            Some(&configured),
            Some(provider),
            qualify_sorafs_proof_outcome_transaction_signer_v1,
        )
        .expect("exact configured provider must qualify")
        .expect("enabled role returns its qualified facade");
        assert_eq!(qualified.handle(), configured.handle);
        assert_eq!(qualified.authority(), configured.authority);
        assert_eq!(qualified.public_key(), Ok(configured.public_key));
        assert_eq!(qualified.qualification(), Ok(QUALIFICATION));
        use iroha_data_model::isi::sorafs::{
            SorafsPdpProofOutcomeSubmissionV1, SorafsProofOutcomeSubmissionV1,
            SubmitSorafsProofOutcome,
        };
        // The startup boundary owns the typed envelope; native execution validates its evidence.
        let payload = TransactionBuilder::new(
            network_id,
            configured.authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([SubmitSorafsProofOutcome::new(
            SorafsProofOutcomeSubmissionV1::Pdp(SorafsPdpProofOutcomeSubmissionV1 {
                archive_payload: vec![1],
            }),
        )])
        .into_payload()
        .unwrap();
        let mut foreign = payload.clone();
        foreign.domain = iroha_data_model::transaction::TransactionDomain::Network(
            signed_query_test_network_id(),
        );
        assert_eq!(
            qualified.sign(foreign),
            Err(SoraFsProofOutcomeSigningError::Refused)
        );
        let signed = qualified.sign(payload.clone()).unwrap();
        assert_eq!(signed.payload(), &payload);
        signed.verify_signature().unwrap();
    }
    #[test]
    fn native_signer_startup_rejects_substituted_provider() {
        let expected = ProofSigner::new("provider://sorafs/proof-outcome/primary", 0x31);
        let configured = expected.configured_binding();
        let substituted: Arc<dyn SoraFsProofOutcomeTransactionSigner> = Arc::new(ProofSigner::new(
            "provider://sorafs/proof-outcome/substituted",
            0x32,
        ));
        let error = qualify_configured_sorafs_native_transaction_signer_for_startup(
            signed_query_test_network_id(),
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            true,
            Some(&configured),
            Some(substituted),
            qualify_sorafs_proof_outcome_transaction_signer_v1,
        )
        .err()
        .expect("substituted provider must fail startup qualification");
        assert!(error.contains("substituted"));
    }
}

#[cfg(all(test, feature = "app_api"))]
mod musubi_search_projection_worker_lifecycle_tests {
    use super::{
        MusubiSearchProjectionInput, ShutdownSignal, ToriiCriticalWorkerExit,
        next_musubi_search_projection_input,
    };

    #[tokio::test]
    async fn closed_feed_is_an_unexpected_worker_exit() {
        let (sender, mut events) = tokio::sync::broadcast::channel(1);
        let shutdown = ShutdownSignal::new();
        drop(sender);

        assert!(matches!(
            next_musubi_search_projection_input(&shutdown, &mut events).await,
            MusubiSearchProjectionInput::Exit(ToriiCriticalWorkerExit::UnexpectedExit)
        ));
    }

    #[tokio::test]
    async fn shutdown_wins_when_the_feed_is_also_closed() {
        let (sender, mut events) = tokio::sync::broadcast::channel(1);
        let shutdown = ShutdownSignal::new();
        drop(sender);
        shutdown.send();

        assert!(matches!(
            next_musubi_search_projection_input(&shutdown, &mut events).await,
            MusubiSearchProjectionInput::Exit(ToriiCriticalWorkerExit::StoppedByShutdown)
        ));
    }
}

#[cfg(all(test, feature = "app_api"))]
mod gateway_runtime_config_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    #[derive(Debug)]
    struct TestAcmeClient;
    impl sorafs::gateway::AcmeClient for TestAcmeClient {
        fn qualification(
            &self,
        ) -> Result<sorafs::gateway::AcmeClientIdentityV1, sorafs::gateway::AcmeClientProbeError>
        {
            Ok(sorafs::gateway::AcmeClientIdentityV1 {
                provider_handle: "runtime://sorafs/gateway-acme/primary".into(),
                revision: 17,
                policy_digest: [0x51; 32],
                test_marked: false,
            })
        }
        fn order_certificate(
            &self,
            _order: &sorafs::gateway::CertificateOrder,
        ) -> Result<sorafs::gateway::CertificateBundle, sorafs::gateway::AcmeClientError> {
            Err(sorafs::gateway::AcmeClientError::Rejected)
        }
    }
    #[derive(Debug)]
    /// Qualified local fixture transport; no feed request is permitted.
    pub struct TestComplianceFeedTransport;
    impl sorafs::gateway::GatewayComplianceFeedTransport for TestComplianceFeedTransport {
        fn qualification(
            &self,
        ) -> Result<
            sorafs::gateway::GatewayComplianceFeedTransportIdentityV1,
            sorafs::gateway::GatewayComplianceFeedTransportProbeError,
        > {
            let pins_by_hostname = BTreeMap::from([(
                "feed.example.test".to_owned(),
                BTreeSet::from([[0x71; 32], [0x72; 32]]),
            )]);
            Ok(sorafs::gateway::GatewayComplianceFeedTransportIdentityV1 {
                provider_handle: iroha_config::parameters::defaults::sorafs::gateway::compliance::GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1
                    .to_owned(),
                revision: iroha_config::parameters::defaults::sorafs::gateway::compliance::GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
                policy_digest: sorafs_manifest::gateway_compliance::gateway_compliance_feed_transport_policy_digest(
                    &pins_by_hostname,
                )
                .expect("test feed policy digest"),
                test_marked: false,
            })
        }
        fn resolve(
            &self,
            _hostname: &str,
            _timeout: Duration,
        ) -> Result<Vec<IpAddr>, sorafs::gateway::GatewayComplianceError> {
            Err(sorafs::gateway::GatewayComplianceError::InvalidFeed(
                "test transport must not be invoked".into(),
            ))
        }
        fn fetch(
            &self,
            _request: &sorafs::gateway::GatewayComplianceFetchRequest,
        ) -> Result<
            sorafs::gateway::GatewayComplianceFetchResponse,
            sorafs::gateway::GatewayComplianceError,
        > {
            Err(sorafs::gateway::GatewayComplianceError::InvalidFeed(
                "test transport must not be invoked".into(),
            ))
        }
    }
    fn compliance_signer(
        signer_id: &str,
        signing_key_byte: u8,
    ) -> iroha_config::parameters::actual::SorafsGatewayComplianceSigner {
        let signing_key = SigningKey::from_bytes(&[signing_key_byte; 32]);
        iroha_config::parameters::actual::SorafsGatewayComplianceSigner {
            signer_id: signer_id.into(),
            public_key: signing_key.verifying_key().to_bytes(),
        }
    }
    fn acme_provider_binding()
    -> iroha_config::parameters::actual::SorafsGatewayRuntimeProviderBinding {
        iroha_config::parameters::actual::SorafsGatewayRuntimeProviderBinding {
            provider_handle: "runtime://sorafs/gateway-acme/primary".into(),
            revision: 17,
            policy_digest: [0x51; 32],
        }
    }
    fn compliance_feed_provider_binding()
    -> iroha_config::parameters::actual::SorafsGatewayRuntimeProviderBinding {
        let pins_by_hostname = BTreeMap::from([(
            "feed.example.test".to_owned(),
            BTreeSet::from([[0x71; 32], [0x72; 32]]),
        )]);
        iroha_config::parameters::actual::SorafsGatewayRuntimeProviderBinding {
            provider_handle: iroha_config::parameters::defaults::sorafs::gateway::compliance::GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1.into(),
            revision: iroha_config::parameters::defaults::sorafs::gateway::compliance::GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
            policy_digest: sorafs_manifest::gateway_compliance::gateway_compliance_feed_transport_policy_digest(
                &pins_by_hostname,
            )
            .expect("test feed transport policy digest"),
        }
    }
    /// Governed gateway policy paired with the local fixture transport.
    pub fn compliance_config(
        checkpoint_path: PathBuf,
    ) -> iroha_config::parameters::actual::SorafsGatewayCompliance {
        iroha_config::parameters::actual::SorafsGatewayCompliance {
            checkpoint_path,
            feed_transport_provider: compliance_feed_provider_binding(),
            policy_id: [0xA5; 32],
            region_id: "apac".into(),
            gateway_id: "gateway-apac".into(),
            catalog_threshold: 2,
            catalog_signers: vec![
                compliance_signer("catalog-a", 0x11),
                compliance_signer("catalog-b", 0x22),
                compliance_signer("catalog-c", 0x33),
            ],
            revoked_catalog_signer_ids: vec!["catalog-c".into()],
            gateway_ack_threshold: 2,
            gateway_signers: vec![
                compliance_signer("gateway-apac", 0x44),
                compliance_signer("gateway-emea", 0x55),
                compliance_signer("gateway-na", 0x66),
            ],
            revoked_gateway_signer_ids: vec!["gateway-na".into()],
            feeds: vec![
                iroha_config::parameters::actual::SorafsGatewayComplianceFeed {
                    feed_id: "governed-baseline".into(),
                    url: "https://feed.example.test/catalog".into(),
                    required: true,
                    hosts: vec![
                        iroha_config::parameters::actual::SorafsGatewayComplianceFeedHost {
                            hostname: "feed.example.test".into(),
                            accepted_spki_sha256: vec![[0x71; 32], [0x72; 32]],
                        },
                    ],
                },
            ],
            max_encoded_bytes: iroha_config::base::util::Bytes(4_096),
            max_decoded_bytes: iroha_config::base::util::Bytes(8_192),
            max_redirects: 4,
            max_dns_addresses: 6,
            connect_timeout: Duration::from_secs(7),
            total_timeout: Duration::from_secs(23),
            max_clock_skew: Duration::from_secs(301),
            max_feed_age: Duration::from_secs(3_601),
            max_catalog_validity: Duration::from_secs(7_201),
            max_history_entries: 37,
        }
    }
    #[test]
    fn acme_runtime_mapping_preserves_every_resolved_field() {
        let source = iroha_config::parameters::actual::SorafsGatewayAcme {
            enabled: true,
            provider: Some(acme_provider_binding()),
            account_email: Some("gateway-ops@example.test".into()),
            directory_url: "https://acme.example.test/directory".into(),
            hostnames: vec![
                "gateway-a.example.test".into(),
                "gateway-b.example.test".into(),
            ],
            dns_provider_id: Some("runtime-dns-provider".into()),
            renewal_window: Duration::from_secs(91),
            retry_backoff: Duration::from_secs(92),
            retry_jitter: Duration::from_secs(93),
            challenges: iroha_config::parameters::actual::SorafsGatewayAcmeChallenges {
                dns01: true,
                tls_alpn_01: false,
            },
            ech_enabled: true,
        };
        let mapped = gateway_acme_config(&source);
        assert_eq!(mapped.enabled, source.enabled);
        assert_eq!(mapped.account_email, source.account_email);
        assert_eq!(mapped.directory_url, source.directory_url);
        assert_eq!(mapped.hostnames, source.hostnames);
        assert_eq!(mapped.dns_provider_id, source.dns_provider_id);
        assert_eq!(mapped.renewal_window, source.renewal_window);
        assert_eq!(mapped.retry_backoff, source.retry_backoff);
        assert_eq!(mapped.retry_jitter, source.retry_jitter);
        assert_eq!(mapped.challenge.dns01, source.challenges.dns01);
        assert_eq!(mapped.challenge.tls_alpn_01, source.challenges.tls_alpn_01);
        let source_provider = source
            .provider
            .as_ref()
            .expect("test ACME provider binding");
        let mapped_provider = gateway_runtime_provider_binding(source_provider)
            .expect("valid resolved gateway provider binding");
        assert_eq!(
            mapped_provider.provider_handle(),
            source_provider.provider_handle.as_str()
        );
        assert_eq!(mapped_provider.revision(), source_provider.revision);
        assert_eq!(
            mapped_provider.policy_digest(),
            source_provider.policy_digest
        );
    }
    #[test]
    fn compliance_runtime_mapping_preserves_every_resolved_field() {
        let source = compliance_config(PathBuf::from(
            "/var/lib/iroha/sorafs/compliance-checkpoint.norito",
        ));
        let mapped = gateway_compliance_controller_config(&source)
            .expect("valid resolved gateway compliance configuration");
        assert_eq!(mapped.trust_policy.policy_id, source.policy_id);
        assert_eq!(mapped.region_scope, format!("region:{}", source.region_id));
        assert_eq!(
            mapped.gateway_scope,
            format!("gateway:{}", source.gateway_id)
        );
        assert_eq!(
            mapped.trust_policy.catalog_threshold,
            source.catalog_threshold
        );
        assert_eq!(
            mapped
                .trust_policy
                .catalog_signers
                .iter()
                .map(|signer| (&signer.signer_id, signer.public_key))
                .collect::<Vec<_>>(),
            source
                .catalog_signers
                .iter()
                .map(|signer| (&signer.signer_id, signer.public_key))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            mapped.trust_policy.revoked_catalog_signer_ids,
            source.revoked_catalog_signer_ids
        );
        assert_eq!(
            mapped.trust_policy.gateway_ack_threshold,
            source.gateway_ack_threshold
        );
        assert_eq!(
            mapped
                .trust_policy
                .gateway_signers
                .iter()
                .map(|signer| (&signer.signer_id, signer.public_key))
                .collect::<Vec<_>>(),
            source
                .gateway_signers
                .iter()
                .map(|signer| (&signer.signer_id, signer.public_key))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            mapped.trust_policy.revoked_gateway_signer_ids,
            source.revoked_gateway_signer_ids
        );
        assert_eq!(mapped.feeds.len(), 1);
        assert_eq!(mapped.feeds[0].feed_id, source.feeds[0].feed_id);
        assert_eq!(mapped.feeds[0].url, source.feeds[0].url);
        assert_eq!(mapped.feeds[0].required, source.feeds[0].required);
        assert_eq!(mapped.feeds[0].hosts.len(), 1);
        assert_eq!(
            mapped.feeds[0].hosts[0].hostname,
            source.feeds[0].hosts[0].hostname
        );
        assert_eq!(
            mapped.feeds[0].hosts[0].accepted_spki_sha256,
            source.feeds[0].hosts[0]
                .accepted_spki_sha256
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(
            mapped.fetch_limits.max_encoded_bytes,
            usize::try_from(source.max_encoded_bytes.0).expect("test value fits usize")
        );
        assert_eq!(
            mapped.fetch_limits.max_decoded_bytes,
            usize::try_from(source.max_decoded_bytes.0).expect("test value fits usize")
        );
        assert_eq!(mapped.fetch_limits.max_redirects, source.max_redirects);
        assert_eq!(
            mapped.fetch_limits.max_dns_addresses,
            source.max_dns_addresses
        );
        assert_eq!(mapped.fetch_limits.connect_timeout, source.connect_timeout);
        assert_eq!(mapped.fetch_limits.total_timeout, source.total_timeout);
        assert_eq!(mapped.max_clock_skew_secs, source.max_clock_skew.as_secs());
        assert_eq!(mapped.max_feed_age_secs, source.max_feed_age.as_secs());
        assert_eq!(
            mapped.max_catalog_validity_secs,
            source.max_catalog_validity.as_secs()
        );
        assert_eq!(mapped.max_history_entries, source.max_history_entries);
        let mapped_provider = mapped
            .feed_transport_provider
            .as_ref()
            .expect("mapped feed transport provider");
        assert_eq!(
            mapped_provider.provider_handle(),
            source.feed_transport_provider.provider_handle.as_str()
        );
        assert_eq!(
            mapped_provider.revision(),
            source.feed_transport_provider.revision
        );
        assert_eq!(
            mapped_provider.policy_digest(),
            source.feed_transport_provider.policy_digest
        );
        mapped.validate().expect("mapped policy must remain valid");
    }
    include!("runtime_dependency_tests/stream_token_signer.rs");
    #[test]
    fn gateway_security_builds_only_from_resolved_config_and_runtime_dependencies() {
        let checkpoint_dir = tempfile::tempdir().expect("temporary checkpoint directory");
        let checkpoint_dir = checkpoint_dir
            .path()
            .canonicalize()
            .expect("canonical temporary checkpoint directory");
        let acme_client: Arc<dyn sorafs::gateway::AcmeClient> = Arc::new(TestAcmeClient);
        let compliance_transport: Arc<dyn sorafs::gateway::GatewayComplianceFeedTransport> =
            Arc::new(TestComplianceFeedTransport);
        let mut config = iroha_config::parameters::actual::SorafsGateway::default();
        config.acme.enabled = true;
        config.acme.provider = Some(acme_provider_binding());
        config.acme.ech_enabled = true;
        config.compliance = Some(compliance_config(checkpoint_dir.join("checkpoint.norito")));
        let components = build_sorafs_gateway_security(
            &config,
            None,
            Some(acme_client),
            Some(Arc::clone(&compliance_transport)),
        )
        .expect("valid gateway security runtime");
        assert!(components.tls_automation.is_some());
        assert!(
            components
                .tls_state
                .try_read()
                .expect("TLS state lock")
                .header_value()
                .starts_with("ech-enabled")
        );
        assert!(components.compliance_controller.is_some());
        assert!(Arc::ptr_eq(
            components
                .compliance_feed_transport
                .as_ref()
                .expect("compliance transport retained"),
            &compliance_transport
        ));
    }
    #[test]
    fn acme_enabled_without_runtime_client_fails_closed() {
        let mut config = iroha_config::parameters::actual::SorafsGateway::default();
        config.acme.enabled = true;
        config.acme.provider = Some(acme_provider_binding());
        let error = build_sorafs_gateway_security(&config, None, None, None)
            .err()
            .expect("missing ACME runtime client must reject construction");
        assert!(matches!(
            error,
            ToriiBuildError::InvalidRuntimeDependency {
                component: "sorafs.gateway.acme",
                ..
            }
        ));
    }
    #[test]
    fn acme_enabled_without_configured_provider_binding_fails_closed() {
        let mut config = iroha_config::parameters::actual::SorafsGateway::default();
        config.acme.enabled = true;
        let error =
            build_sorafs_gateway_security(&config, None, Some(Arc::new(TestAcmeClient)), None)
                .err()
                .expect("missing ACME provider binding must reject construction");
        assert!(matches!(
            error,
            ToriiBuildError::InvalidConfiguration {
                component: "sorafs.gateway.acme.provider",
                ..
            }
        ));
    }
    #[test]
    fn stale_acme_runtime_provider_fails_closed_without_provider_details() {
        let mut config = iroha_config::parameters::actual::SorafsGateway::default();
        config.acme.enabled = true;
        let mut provider = acme_provider_binding();
        provider.revision += 1;
        config.acme.provider = Some(provider);
        let error =
            build_sorafs_gateway_security(&config, None, Some(Arc::new(TestAcmeClient)), None)
                .err()
                .expect("stale ACME runtime provider must reject construction");
        assert!(matches!(
            error,
            ToriiBuildError::InvalidRuntimeDependency {
                component: "sorafs.gateway.acme",
                ..
            }
        ));
    }
    #[test]
    fn compliance_enabled_without_runtime_transport_fails_closed() {
        let config = iroha_config::parameters::actual::SorafsGateway {
            compliance: Some(compliance_config(
                std::env::temp_dir().join("unused-compliance-checkpoint.norito"),
            )),
            ..Default::default()
        };
        let error = build_sorafs_gateway_security(&config, None, None, None)
            .err()
            .expect("missing compliance transport must reject construction");
        assert!(matches!(
            error,
            ToriiBuildError::InvalidRuntimeDependency {
                component: "sorafs.gateway.compliance",
                ..
            }
        ));
    }
}

#[cfg(all(test, feature = "app_api"))]
mod por_runtime_readiness_tests {
    use super::{ToriiBuildError, por_runtime_readiness_error, validate_por_runtime_ready};
    fn configured_por() -> iroha_config::parameters::actual::SorafsPor {
        let mut config = iroha_config::parameters::actual::SorafsPor {
            enabled: true,
            ..Default::default()
        };
        iroha_crypto::drand::UNCHAINED_G1_RFC9380_SCHEME.clone_into(&mut config.drand.scheme);
        config.drand.chain_hash =
            hex::decode("52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971")
                .expect("chain hash")
                .try_into()
                .expect("32-byte chain hash");
        config.drand.public_key = hex::decode(concat!(
            "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c",
            "8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb",
            "5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
        ))
        .expect("public key")
        .try_into()
        .expect("96-byte public key");
        config.drand.genesis_time = 1_692_803_367;
        config.drand.period_secs = 3;
        let chain = hex::encode(config.drand.chain_hash);
        config.drand.endpoints = ["api.drand.sh", "api2.drand.sh", "drand.cloudflare.com"]
            .into_iter()
            .map(|host| format!("https://{host}/v2/chains/{chain}"))
            .collect();
        config.drand.quorum = 2;
        config
    }
    #[test]
    fn por_runtime_is_disabled_or_requires_complete_verified_entropy_config() {
        let mut config = iroha_config::parameters::actual::SorafsPor::default();
        assert_eq!(por_runtime_readiness_error(&config), None);
        config.enabled = true;
        assert!(por_runtime_readiness_error(&config).is_some());
        let error = validate_por_runtime_ready(&config)
            .expect_err("enabled incomplete PoR runtime must fail construction");
        assert!(matches!(
            error,
            ToriiBuildError::InvalidConfiguration {
                component: "sorafs.por",
                ..
            }
        ));
        let configured = configured_por();
        assert_eq!(por_runtime_readiness_error(&configured), None);
        validate_por_runtime_ready(&configured).expect("complete PoR configuration");
        let mut missing_key = configured.clone();
        missing_key.drand.public_key = [0; 96];
        assert!(por_runtime_readiness_error(&missing_key).is_some());
        let mut no_quorum = configured.clone();
        no_quorum.drand.quorum = 1;
        assert!(por_runtime_readiness_error(&no_quorum).is_some());
        let mut late_vrf = configured;
        late_vrf.vrf_submission_deadline_secs = late_vrf.epoch_interval_secs;
        assert!(por_runtime_readiness_error(&late_vrf).is_some());
    }
}

#[cfg(test)]
#[test]
fn torii_runtime_deps_keep_vpn_and_proxy_signers_separate() {
    let proxy_signer = KeyPair::try_from_seed(vec![0x91; 32], iroha_crypto::Algorithm::Ed25519)
        .expect("proxy signer fixture");
    let vpn_signer = KeyPair::try_from_seed(vec![0x92; 32], iroha_crypto::Algorithm::Ed25519)
        .expect("VPN signer fixture");
    let proxy_only = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_torii_proxy_bridge_signer(proxy_signer.clone());
    assert!(
        proxy_only.vpn_operator_signer.is_none(),
        "proxy signer must never fill the VPN signer role"
    );
    let deps = proxy_only.with_vpn_operator_signer(vpn_signer.clone());

    assert_eq!(
        deps.torii_proxy_bridge_signer
            .as_ref()
            .map(KeyPair::public_key),
        Some(proxy_signer.public_key())
    );
    assert_eq!(
        deps.vpn_operator_signer.as_ref().map(KeyPair::public_key),
        Some(vpn_signer.public_key())
    );
    assert_ne!(proxy_signer.public_key(), vpn_signer.public_key());
}

#[cfg(test)]
#[test]
fn emergency_fast_runtime_deps_drop_external_services_and_signers() {
    let proxy_signer = KeyPair::try_from_seed(vec![0x93; 32], iroha_crypto::Algorithm::Ed25519)
        .expect("proxy signer fixture");
    let vpn_signer = KeyPair::try_from_seed(vec![0x94; 32], iroha_crypto::Algorithm::Ed25519)
        .expect("VPN signer fixture");
    let deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_torii_proxy_bridge_signer(proxy_signer)
    .with_vpn_operator_signer(vpn_signer)
    .into_emergency_fast();

    assert!(deps.torii_proxy_bridge_signer.is_none());
    assert!(deps.vpn_operator_signer.is_none());
    assert!(deps.soracloud_runtime.is_none());
    assert!(deps.sorafs_node.is_none());
    assert_eq!(
        deps.build_identity,
        crate::build_identity_test_fixture::build_identity(),
        "emergency recovery retains the executable identity"
    );
}
