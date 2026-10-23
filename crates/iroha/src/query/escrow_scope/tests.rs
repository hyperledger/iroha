//! Transport and shape tests; these do not establish certified World membership.
use super::*;
use iroha_data_model::nexus::AxtAssetIncarnationV1;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn fixture() -> (
    FindAssetEscrowsByAssetDefinitionV1,
    AssetEscrowScopeOriginalV1,
) {
    let query = FindAssetEscrowsByAssetDefinitionV1 {
        asset_definition_id: "61CtjvNd9T3THAR65GsMVHr82Bjc".parse().unwrap(),
        expected_incarnation: AxtAssetIncarnationV1::try_from_bytes(
            *iroha_crypto::Hash::new(b"escrow SDK scope").as_ref(),
        )
        .unwrap(),
    };
    let scope = AssetEscrowScopeV1 {
        asset_definition_id: query.asset_definition_id.clone(),
        asset_incarnation: query.expected_incarnation,
        revision: 1,
        record_count: 0,
    };
    (
        query,
        AssetEscrowScopeOriginalV1 {
            scope_original: norito::encode_canonical(&scope).unwrap(),
            records: vec![],
        },
    )
}

fn response(
    originals: Vec<AssetEscrowScopeOriginalV1>,
    more: bool,
    cursor: Option<ForwardCursor>,
) -> http::Response<Vec<u8>> {
    let value = QueryResponse::Iterable(QueryOutput::new_bounded(
        QueryOutputBatchBox::AssetEscrowScopeOriginalV1(originals).into(),
        more,
        cursor,
    ));
    http::Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, APPLICATION_NORITO)
        .body(norito::encode_canonical(&value).unwrap())
        .unwrap()
}

#[test]
fn initialized_zero_is_one_observation_and_selector_changes_refuse() {
    let (query, original) = fixture();
    let reply = response(vec![original.clone()], false, None);
    assert_eq!(
        decode_scope_response(&reply, &query, MAX_RESPONSE_BYTES).unwrap(),
        original
    );
    let mut wrong = query;
    wrong.expected_incarnation = AxtAssetIncarnationV1::try_from_bytes(
        *iroha_crypto::Hash::new(b"different incarnation").as_ref(),
    )
    .unwrap();
    assert!(decode_scope_response(&reply, &wrong, MAX_RESPONSE_BYTES).is_err());
}

#[test]
fn absent_duplicate_partial_and_stored_scope_responses_refuse() {
    let (query, original) = fixture();
    for reply in [
        response(vec![], false, None),
        response(vec![original.clone(), original.clone()], false, None),
        response(vec![original.clone()], true, None),
        response(
            vec![original],
            false,
            Some(ForwardCursor {
                query: "a".repeat(64),
                cursor: NonZeroU64::new(1).unwrap(),
                gas_budget: None,
            }),
        ),
    ] {
        assert!(decode_scope_response(&reply, &query, MAX_RESPONSE_BYTES).is_err());
    }
}

#[test]
fn exact_media_size_and_initialized_anchor_are_required() {
    let (query, mut original) = fixture();
    let mut reply = response(vec![original.clone()], false, None);
    assert!(decode_scope_response(&reply, &query, reply.body().len() - 1).is_err());
    reply
        .headers_mut()
        .insert(CONTENT_TYPE, "application/json".parse().unwrap());
    assert!(decode_scope_response(&reply, &query, MAX_RESPONSE_BYTES).is_err());
    original.scope_original.clear();
    assert!(
        decode_scope_response(
            &response(vec![original], false, None),
            &query,
            MAX_RESPONSE_BYTES
        )
        .is_err()
    );
}

#[test]
fn client_signs_one_exact_ephemeral_query_and_never_retries() {
    use iroha_version::codec::DecodeVersioned as _;
    let (query, original) = fixture();
    let expected_query = query.clone();
    let expected_original = original.clone();
    let sent = Arc::new(AtomicUsize::new(0));
    let count = sent.clone();
    let key = KeyPair::try_from_seed(vec![41; 32], iroha_crypto::Algorithm::Ed25519).unwrap();
    let account = AccountId::new(key.public_key().clone());
    let expected_account = account.clone();
    let transport = DefaultHttpTransport::mock(Arc::new(move |snapshot| {
        let ordinal = count.fetch_add(1, Ordering::SeqCst);
        assert_eq!(snapshot.url.path(), torii_routes::pipeline::QUERY.path());
        assert_eq!(
            snapshot.url.query(),
            Some("cursor_mode=ephemeral&count_mode=bounded")
        );
        let signed =
            iroha_data_model::query::SignedQuery::decode_all_versioned(&snapshot.body).unwrap();
        assert_eq!(signed.payload.authority, expected_account);
        assert_ne!(signed.payload.nonce, [0; 32]);
        let QueryRequest::Start(request) = signed.payload.request else {
            panic!("start query");
        };
        assert_eq!(
            request.item,
            iroha_data_model::query::QueryItemKind::AssetEscrowScopeOriginalV1
        );
        assert_eq!(request.query_payload, expected_query.dyn_encode());
        assert_eq!(request.params.fetch_size.fetch_size, NonZeroU64::new(1));
        if ordinal == 0 {
            Ok(response(vec![original.clone()], false, None))
        } else {
            Ok(http::Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(vec![])
                .unwrap())
        }
    }));
    let config = crate::config::Config {
        chain: iroha_model_base::chain::ChainId::from("escrow-sdk-test"),
        network_id: crate::client::test_network_id(),
        account,
        key_pair: key,
        account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
        torii_api_url: Url::parse("http://mock.local/").unwrap(),
        torii_request_timeout: crate::config::DEFAULT_TORII_REQUEST_TIMEOUT,
        basic_auth: None,
        api_token: None,
        transaction_add_nonce: false,
        transaction_ttl: Duration::from_secs(5),
        transaction_status_timeout: Duration::from_secs(10),
        sorafs_alias_cache: crate::client::default_alias_policy(),
        sorafs_anonymity_policy: iroha_service_model::soranet::AnonymityPolicy::GuardPq,
        http_transport_policy: crate::config::HttpTransportPolicy::Ordinary,
        sorafs_rollout_phase: iroha_service_model::soranet::RolloutPhase::Canary,
    };
    let client = Client::builder(config)
        .build()
        .unwrap()
        .with_test_http_transport(transport);
    *client.data_model_compatibility.lock().unwrap() =
        crate::client::DataModelCompatibility::SubmitCompatible;
    assert_eq!(
        client
            .get_asset_escrow_scope_original(query.clone(), MAX_RESPONSE_BYTES)
            .unwrap(),
        expected_original
    );
    assert!(
        client
            .get_asset_escrow_scope_original(query.clone(), MAX_RESPONSE_BYTES)
            .is_err()
    );
    assert_eq!(
        sent.load(Ordering::SeqCst),
        2,
        "one send for each explicitly requested read"
    );
    assert!(client.get_asset_escrow_scope_original(query, 0).is_err());
    assert_eq!(
        sent.load(Ordering::SeqCst),
        2,
        "invalid bounds never dispatch"
    );
}
