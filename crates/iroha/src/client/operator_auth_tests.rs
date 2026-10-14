//! Exact operator-authentication client boundary tests.
use super::evidence_http_tests::{
    SnapshotStore, base_url, client_with_base_url, respond_with, with_mock_http,
};
use super::{
    HEADER_OPERATOR_NONCE, HEADER_OPERATOR_PUBLIC_KEY, HEADER_OPERATOR_SIGNATURE,
    HEADER_OPERATOR_TIMESTAMP_MS, IdentityRequestSignerV1, IdentityRequestSigningErrorV1,
    checked_random_keypair,
};
use crate::http::{Method as HttpMethod, Response, StatusCode};
use iroha_crypto::{KeyPair, PublicKey, Signature};
use std::sync::{Arc, Mutex};

struct SubstitutingIdentityRequestSignerV1 {
    advertised: KeyPair,
    actual: KeyPair,
}

impl IdentityRequestSignerV1 for SubstitutingIdentityRequestSignerV1 {
    fn public_key(&self) -> &PublicKey {
        self.advertised.public_key()
    }

    fn sign_identity_request(
        &self,
        message: &[u8],
    ) -> core::result::Result<Signature, IdentityRequestSigningErrorV1> {
        Signature::try_new(self.actual.private_key(), message)
            .map_err(|_| IdentityRequestSigningErrorV1)
    }
}

#[test]
fn identity_request_signer_cannot_substitute_its_advertised_public_key() {
    let signer = SubstitutingIdentityRequestSignerV1 {
        advertised: checked_random_keypair(),
        actual: checked_random_keypair(),
    };
    let error = match client_with_base_url(base_url()).identity_signed_request_with_signer(
        &signer,
        HttpMethod::GET,
        base_url(),
        Vec::new(),
    ) {
        Ok(_) => panic!("substituted signer output must fail before transport"),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), "identity-bound request signing failed");
}

#[test]
fn operator_endpoint_requires_a_signing_key_before_dispatch() {
    let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
    let mut client = client_with_base_url(base_url());
    client.operator_key_pair = None;
    let error = with_mock_http(
        respond_with(
            &snapshots,
            Response::builder()
                .status(StatusCode::OK)
                .body(Vec::new())
                .expect("response build"),
        ),
        |mock_transport| {
            let client = client
                .clone()
                .with_test_http_transport(mock_transport.clone());
            client.operator_signed_request(
                HttpMethod::GET,
                super::join_torii_url(
                    &client.torii_url,
                    iroha_torii_shared::route_catalog::core::CONFIGURATION_GET.path(),
                ),
                Vec::new(),
            )
        },
    )
    .expect_err("operator endpoint must reject a missing local signer");
    assert!(
        error
            .to_string()
            .contains("operator signing key is required before request dispatch")
    );
    assert!(
        snapshots.lock().expect("lock snapshots").is_empty(),
        "missing operator credentials must fail before transport"
    );
}
#[test]
fn operator_context_is_independent_of_account_authority() {
    let mut client = client_with_base_url(base_url());
    client.account =
        iroha_data_model::account::AccountId::new(checked_random_keypair().public_key().clone());
    let operator = client
        .operator_client(checked_random_keypair())
        .expect("operator binding must not depend on account credentials");
    assert_eq!(operator.network_id(), &client.network_id);
}
#[tokio::test]
async fn proof_retention_uses_one_exact_signed_empty_body_get() {
    let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
    let client = client_with_base_url(base_url());
    let operator_key = checked_random_keypair();
    let error = with_mock_http(
        respond_with(
            &snapshots,
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Vec::new())
                .expect("response build"),
        ),
        |mock_transport| async move {
            let client = client
                .clone()
                .with_test_http_transport(mock_transport.clone());
            client
                .operator_client(operator_key)
                .expect("valid operator context")
                .get_proof_retention_status()
                .await
        },
    )
    .await
    .expect_err("mocked unauthorized response must fail");
    assert!(error.to_string().contains("proof retention"));
    let snapshots = snapshots.lock().expect("lock snapshots");
    assert_eq!(snapshots.len(), 1, "operator reads are one-shot");
    let snapshot = &snapshots[0];
    assert_eq!(snapshot.method, HttpMethod::GET);
    assert_eq!(snapshot.url.path(), "/v1/proofs/retention");
    assert!(snapshot.url.query().is_none());
    assert!(snapshot.body.is_empty());
    for header in [
        HEADER_OPERATOR_PUBLIC_KEY,
        HEADER_OPERATOR_TIMESTAMP_MS,
        HEADER_OPERATOR_NONCE,
        HEADER_OPERATOR_SIGNATURE,
    ] {
        assert!(
            snapshot
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(header)),
            "missing {header}"
        );
    }
}

fn configured_listener_builder() -> super::ClientBuilder {
    let seed = client_with_base_url(base_url());
    let configuration = crate::config::Config {
        chain: seed.chain.clone(),
        network_id: seed.network_id,
        key_pair: seed.key_pair.clone(),
        account: seed.account.clone(),
        account_chain_discriminant: seed.account_chain_discriminant,
        torii_api_url: seed.torii_url.clone(),
        torii_request_timeout: seed.torii_request_timeout,
        basic_auth: None,
        api_token: Some(crate::secrecy::SecretString::new(
            "configured-listener-owner-test-token".to_owned(),
        )),
        transaction_add_nonce: seed.add_transaction_nonce,
        transaction_ttl: seed.transaction_ttl.unwrap(),
        transaction_status_timeout: seed.transaction_status_timeout,
        sorafs_alias_cache: seed.alias_cache_policy,
        sorafs_anonymity_policy: seed.default_anonymity_policy,
        http_transport_policy: seed.http_transport_policy(),
        sorafs_rollout_phase: seed.rollout_phase,
    };
    let mut builder = super::Client::builder(configuration);
    builder.operator_key_pair = seed.operator_key_pair.clone();
    builder
}

fn assert_status_listener_and_signature(
    client: super::Client,
    expected_token: Option<&'static str>,
) {
    use base64::Engine as _;
    let network = client.network_id;
    let expected_url = super::join_torii_url(
        &client.torii_url,
        iroha_torii_shared::route_catalog::sumeragi::STATUS.path(),
    );
    let operator = client
        .operator_key_pair
        .as_ref()
        .unwrap()
        .public_key()
        .clone();
    let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&snapshots);
    let expected = super::tests::sample_sumeragi_status();
    let wire = norito::to_bytes(&expected).unwrap();
    let result = with_mock_http(
        move |request| {
            let header = |name: &str| {
                let values = request
                    .headers
                    .iter()
                    .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                    .collect::<Vec<_>>();
                assert_eq!(values.len(), 1, "one fresh {name}");
                values[0].1.as_str()
            };
            assert_eq!(request.method, HttpMethod::GET);
            assert_eq!(request.url, expected_url, "exact rebound origin and target");
            assert_eq!(request.url.path(), "/v1/sumeragi/status");
            assert!(request.url.query().is_none());
            assert!(request.body.is_empty());
            let advertised: PublicKey = header(HEADER_OPERATOR_PUBLIC_KEY).parse().unwrap();
            assert_eq!(advertised, operator);
            let timestamp = header(HEADER_OPERATOR_TIMESTAMP_MS).parse().unwrap();
            let nonce = header(HEADER_OPERATOR_NONCE);
            let raw = base64::engine::general_purpose::STANDARD
                .decode(header(HEADER_OPERATOR_SIGNATURE))
                .unwrap();
            let signature = Signature::from_bytes(&raw);
            let message = super::Client::operator_network_request_message(
                &network,
                &request.method,
                &request.url,
                &request.body,
                timestamp,
                nonce,
            )
            .unwrap();
            signature.verify(&operator, &message).unwrap();
            let mut changed_target = request.url.clone();
            changed_target.set_path("/v1/configuration");
            let changed = super::Client::operator_network_request_message(
                &network,
                &request.method,
                &changed_target,
                &request.body,
                timestamp,
                nonce,
            )
            .unwrap();
            assert!(signature.verify(&operator, &changed).is_err());
            for reserved in [
                "authorization",
                "x-iroha-account",
                "x-iroha-signature",
                "x-iroha-timestamp-ms",
                "x-iroha-nonce",
                "x-iroha-witness",
            ] {
                assert!(
                    request
                        .headers
                        .iter()
                        .all(|(name, _)| !name.eq_ignore_ascii_case(reserved))
                );
            }
            let tokens = request
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("x-api-token"))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>();
            let allowed = expected_token.map_or(tokens.is_empty(), |token| tokens == [token]);
            captured.lock().unwrap().push(request);
            // This models only the already-established listener credential gate; the signature
            // above is independently verified, not inferred from a successful mock response.
            Ok(if allowed {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", super::APPLICATION_NORITO)
                    .body(wire.clone())
                    .unwrap()
            } else {
                Response::builder().status(StatusCode::UNAUTHORIZED).header("content-type", "application/json").body(br#"{"code":"api_token_required","message":"A valid Torii API token is required for this request."}"#.to_vec()).unwrap()
            })
        },
        |transport| {
            client
                .with_test_http_transport(transport)
                .get_sumeragi_status()
        },
    );
    assert_eq!(
        result.expect(
            "typed listener credential and operator signature must both reach status dispatch"
        ),
        expected
    );
    assert_eq!(
        snapshots.lock().unwrap().len(),
        1,
        "one original signed request, no fallback or retries"
    );
}

#[test]
fn operator_status_carries_typed_listener_token_and_exact_signature() {
    let client = configured_listener_builder().build().unwrap();
    assert_status_listener_and_signature(client, Some("configured-listener-owner-test-token"));
}

#[test]
fn operator_listener_token_survives_builder_overrides_and_context_rebuild() {
    let mut builder = configured_listener_builder();
    for (name, value) in [
        ("x-api-token", "caller-substitution"),
        ("X-API-TOKEN", "case-duplicate"),
        ("authorization", "Bearer stale"),
        ("X-Iroha-Operator-Signature", "stale"),
        ("X-Iroha-Account", "stale-account"),
    ] {
        builder.headers.insert(name.to_owned(), value.to_owned());
    }
    assert!(!format!("{builder:?}").contains("configured-listener-owner-test-token"));
    let client = builder
        .build()
        .expect("typed credential replaces every ambient spelling");
    assert!(!format!("{client:?}").contains("configured-listener-owner-test-token"));
    assert_status_listener_and_signature(
        client.clone(),
        Some("configured-listener-owner-test-token"),
    );
    let mut rebuilt = client.to_builder();
    rebuilt
        .headers
        .insert("X-Api-Token".into(), "rebuild-substitution".into());
    assert_status_listener_and_signature(
        rebuilt.build().unwrap(),
        Some("configured-listener-owner-test-token"),
    );
}

#[test]
fn operator_listener_token_provenance_cannot_come_from_ambient_headers() {
    let mut builder = client_with_base_url(base_url()).to_builder();
    builder
        .headers
        .insert("X-Api-Token".into(), "ambient-only".into());
    let client = builder.build().unwrap();
    assert_eq!(
        client.headers.get("x-api-token").map(String::as_str),
        Some("ambient-only"),
        "ordinary configured-header behavior stays unchanged"
    );
    assert_status_listener_and_signature(client.to_builder().build().unwrap(), None);
    let mut missing = configured_listener_builder().build().unwrap();
    missing.headers.remove("x-api-token");
    missing
        .headers
        .insert("X-API-TOKEN".into(), "unproven-case-substitution".into());
    assert_status_listener_and_signature(missing.to_builder().build().unwrap(), None);
}

#[test]
fn configured_listener_token_cannot_replace_missing_operator_signer() {
    let mut builder = configured_listener_builder();
    builder.operator_key_pair = None;
    let client = builder.build().unwrap();
    let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
    let result = with_mock_http(
        respond_with(
            &snapshots,
            Response::builder()
                .status(StatusCode::OK)
                .body(Vec::new())
                .unwrap(),
        ),
        |transport| {
            client
                .with_test_http_transport(transport)
                .get_sumeragi_status()
        },
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("operator signing key is required before request dispatch")
    );
    assert!(snapshots.lock().unwrap().is_empty());
}

fn assert_ordinary_listener_dispatch(client: super::Client, expected_token: Option<&'static str>) {
    let url = super::join_torii_url(&client.torii_url, "/status");
    let expected_url = url.clone();
    let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&snapshots);
    let response = with_mock_http(
        move |request| {
            assert_eq!(request.method, HttpMethod::GET);
            assert_eq!(
                request.url, expected_url,
                "ordinary dispatch binds the rebound origin"
            );
            let tokens = request
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("x-api-token"))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>();
            match expected_token {
                Some(token) => assert_eq!(tokens, [token], "only the chosen listener credential"),
                None => assert!(
                    tokens.is_empty(),
                    "cleared listener credential must not be sent"
                ),
            }
            assert!(
                request
                    .headers
                    .iter()
                    .all(|(name, _)| !name.eq_ignore_ascii_case(HEADER_OPERATOR_SIGNATURE))
            );
            captured.lock().unwrap().push(request);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Vec::new())
                .unwrap())
        },
        |transport| {
            let client = client.with_test_http_transport(transport);
            client.send_builder(client.default_request(HttpMethod::GET, url))
        },
    )
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(snapshots.lock().unwrap().len(), 1);
}

#[test]
fn operator_listener_token_can_be_cleared_for_a_different_origin() {
    let original = configured_listener_builder().build().unwrap();
    let original_url = original.torii_url.clone();
    let mut builder = original.to_builder();
    builder.torii_url = "http://cleared.mock.local/".parse().unwrap();
    builder.headers.clear();
    builder
        .headers
        .insert("X-Api-Token".into(), "ambient-old-token".into());
    builder
        .headers
        .insert("x-API-token".into(), "ambient-duplicate".into());
    let rebound = builder.api_token(None).build().unwrap();
    assert_ne!(rebound.torii_url.origin(), original_url.origin());
    assert!(
        rebound
            .headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("x-api-token"))
    );
    assert_ordinary_listener_dispatch(rebound.clone(), None);
    assert_status_listener_and_signature(rebound.clone(), None);
    assert_status_listener_and_signature(rebound.to_builder().build().unwrap(), None);
    // Changing the new builder does not clear the original immutable context.
    assert_status_listener_and_signature(original, Some("configured-listener-owner-test-token"));
}

#[test]
fn operator_listener_token_can_be_replaced_for_a_different_origin() {
    let original = configured_listener_builder().build().unwrap();
    let original_url = original.torii_url.clone();
    let mut builder = original.to_builder();
    builder.torii_url = "http://replacement.mock.local/".parse().unwrap();
    builder
        .headers
        .insert("X-API-TOKEN".into(), "ambient-old-token".into());
    builder
        .headers
        .insert("x-api-token".into(), "ambient-duplicate".into());
    let rebound = builder
        .api_token(Some(crate::secrecy::SecretString::new(
            "replacement-listener-owner-test-token".into(),
        )))
        .build()
        .unwrap();
    assert_ne!(rebound.torii_url.origin(), original_url.origin());
    assert_eq!(
        rebound.headers.get("x-api-token").map(String::as_str),
        Some("replacement-listener-owner-test-token")
    );
    assert!(!format!("{rebound:?}").contains("replacement-listener-owner-test-token"));
    assert_ordinary_listener_dispatch(
        rebound.clone(),
        Some("replacement-listener-owner-test-token"),
    );
    assert_status_listener_and_signature(
        rebound.clone(),
        Some("replacement-listener-owner-test-token"),
    );
    assert_status_listener_and_signature(
        rebound.to_builder().build().unwrap(),
        Some("replacement-listener-owner-test-token"),
    );
    assert_status_listener_and_signature(original, Some("configured-listener-owner-test-token"));
}

#[test]
fn client_debug_reports_listener_token_provenance_without_secret() {
    let client = client_with_base_url(base_url());
    let absent = format!("{client:?}");
    assert!(absent.contains("has_configured_api_token: false"));
    let client = client
        .to_builder()
        .api_token(Some(crate::secrecy::SecretString::new(
            "sdk-debug-token-sentinel".into(),
        )))
        .build()
        .unwrap();
    let configured = format!("{client:?}");
    assert!(configured.contains("has_configured_api_token: true"));
    assert!(configured.contains("<redacted>"));
    assert!(!configured.contains("sdk-debug-token-sentinel"));
}
