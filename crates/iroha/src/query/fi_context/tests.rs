//! Candidate transport tests; these do not authenticate ledger execution.
use super::*;
use iroha_data_model::{
    asset::fi_link::AssetFiLinkV1,
    isi::asset_fi::{SetAssetFiLinkV1, TransferToLinkedFiV1},
    nexus::AxtAssetIncarnationV1,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn fixture(link: bool) -> (FindAssetFiContextV1, AssetFiContextSnapshotV1) {
    let account = |seed| {
        AccountId::new(
            KeyPair::try_from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
        )
    };
    let snapshot = AssetFiContextSnapshotV1 {
        asset_definition_id: "61CtjvNd9T3THAR65GsMVHr82Bjc".parse().unwrap(),
        asset_incarnation: AxtAssetIncarnationV1::try_from_bytes(
            *iroha_crypto::Hash::new(b"FI SDK context").as_ref(),
        )
        .unwrap(),
        account_id: account(41),
        uid: [7; 32],
        fi_account_id: account(42),
        reference_digest: [9; 32],
        binding: None,
        policy: None,
        fi: None,
        attestation: None,
        link: None,
        controller: None,
    };
    let target = if link {
        AssetFiContextTargetV1::LinkApproval(SetAssetFiLinkV1 {
            link: AssetFiLinkV1 {
                asset_definition_id: snapshot.asset_definition_id.clone(),
                account_id: snapshot.account_id.clone(),
                fi_account_id: snapshot.fi_account_id.clone(),
                reference_digest: snapshot.reference_digest,
                fi_revision: 1,
                attestation_revision: 1,
                revision: 1,
                enabled: true,
                controller: None,
                waterfall: false,
                reverse_waterfall: false,
            },
            expected_policy_revision: 1,
        })
    } else {
        AssetFiContextTargetV1::Transfer {
            instruction: TransferToLinkedFiV1 {
                asset_definition_id: snapshot.asset_definition_id.clone(),
                account_id: snapshot.account_id.clone(),
                amount: 5_u32.into(),
                expected_link_revision: 1,
                expected_policy_revision: 1,
            },
            fi_account_id: snapshot.fi_account_id.clone(),
            reference_digest: snapshot.reference_digest,
            expected_fi_revision: 1,
            expected_attestation_revision: 1,
        }
    };
    (
        FindAssetFiContextV1 {
            target,
            expected_incarnation: snapshot.asset_incarnation,
            expected_uid: snapshot.uid,
        },
        snapshot,
    )
}

fn response(
    rows: Vec<AssetFiContextSnapshotV1>,
    more: bool,
    cursor: Option<ForwardCursor>,
) -> http::Response<Vec<u8>> {
    encoded_response(QueryResponse::Iterable(QueryOutput::new_bounded(
        QueryOutputBatchBox::AssetFiContextSnapshotV1(rows).into(),
        more,
        cursor,
    )))
}
fn encoded_response(value: QueryResponse) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, APPLICATION_NORITO)
        .body(norito::encode_canonical(&value).unwrap())
        .unwrap()
}

#[test]
fn both_targets_preserve_explicit_absence_as_one_candidate() {
    for link in [false, true] {
        let (query, snapshot) = fixture(link);
        let reply = response(vec![snapshot.clone()], false, None);
        assert_eq!(
            decode_context_response(&reply, &query, MAX_RESPONSE_BYTES).unwrap(),
            snapshot
        );
    }
}

#[test]
fn each_changed_selector_is_refused_for_both_target_shapes() {
    for link in [false, true] {
        let (query, snapshot) = fixture(link);
        for field in 0..6 {
            let mut changed = snapshot.clone();
            match field {
                0 => {
                    changed.asset_definition_id =
                        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                            iroha_model_base::domain::DomainId::try_new("changed", "universal")
                                .unwrap(),
                            "different".parse().unwrap(),
                        )
                }
                1 => changed.account_id = snapshot.fi_account_id.clone(),
                2 => changed.fi_account_id = snapshot.account_id.clone(),
                3 => changed.reference_digest = [8; 32],
                4 => {
                    changed.asset_incarnation = AxtAssetIncarnationV1::try_from_bytes(
                        *iroha_crypto::Hash::new(b"other incarnation").as_ref(),
                    )
                    .unwrap()
                }
                _ => changed.uid = [8; 32],
            }
            assert!(
                decode_context_response(
                    &response(vec![changed], false, None),
                    &query,
                    MAX_RESPONSE_BYTES
                )
                .is_err(),
                "changed field {field}"
            );
        }
    }
}

#[test]
fn empty_duplicate_partial_cursor_and_wrong_item_are_refused() {
    let (query, snapshot) = fixture(false);
    for reply in [
        response(vec![], false, None),
        response(vec![snapshot.clone(), snapshot.clone()], false, None),
        response(vec![snapshot.clone()], true, None),
        // Preserve the contradictory count using the real typed codec. The
        // convenience constructor would also set has_more and mask this guard.
        encoded_response(QueryResponse::Iterable(QueryOutput {
            batch: QueryOutputBatchBox::AssetFiContextSnapshotV1(vec![snapshot.clone()]).into(),
            remaining_items: Some(1),
            has_more: false,
            continue_cursor: None,
        })),
        response(
            vec![snapshot.clone()],
            false,
            Some(ForwardCursor {
                query: "a".repeat(64),
                cursor: NonZeroU64::new(1).unwrap(),
                gas_budget: None,
            }),
        ),
        encoded_response(QueryResponse::Iterable(QueryOutput::new_bounded(
            QueryOutputBatchBox::AccountId(vec![snapshot.account_id.clone()]).into(),
            false,
            None,
        ))),
    ] {
        assert!(decode_context_response(&reply, &query, MAX_RESPONSE_BYTES).is_err());
    }
}

#[test]
fn byte_cap_media_and_canonical_encoding_are_enforced() {
    let (query, snapshot) = fixture(false);
    let mut reply = response(vec![snapshot.clone()], false, None);
    assert!(decode_context_response(&reply, &query, reply.body().len() - 1).is_err());
    reply
        .headers_mut()
        .insert(CONTENT_TYPE, "application/json".parse().unwrap());
    assert!(decode_context_response(&reply, &query, MAX_RESPONSE_BYTES).is_err());
    let mut reply = response(vec![snapshot], false, None);
    reply.body_mut().push(0);
    assert!(decode_context_response(&reply, &query, MAX_RESPONSE_BYTES).is_err());
}

#[test]
fn client_signs_one_exact_ephemeral_query_and_never_retries() {
    const TEST_RESPONSE_BYTES: usize = 16 * 1024;
    use iroha_version::codec::DecodeVersioned as _;
    let (query, original) = fixture(false);
    let expected_query = query.clone();
    let expected_original = original.clone();
    let sent = Arc::new(AtomicUsize::new(0));
    let count = sent.clone();
    let key = KeyPair::try_from_seed(vec![41; 32], iroha_crypto::Algorithm::Ed25519).unwrap();
    let account = AccountId::new(key.public_key().clone());
    let expected_account = account.clone();
    let transport = DefaultHttpTransport::mock(Arc::new(move |snapshot| {
        let ordinal = count.fetch_add(1, Ordering::SeqCst);
        assert_eq!(snapshot.max_response_bytes, TEST_RESPONSE_BYTES);
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
            iroha_data_model::query::QueryItemKind::AssetFiContextSnapshotV1
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
        chain: iroha_model_base::chain::ChainId::from("fi-context-sdk-test"),
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
            .get_asset_fi_context_snapshot(query.clone(), TEST_RESPONSE_BYTES)
            .unwrap(),
        expected_original
    );
    assert!(
        client
            .get_asset_fi_context_snapshot(query.clone(), TEST_RESPONSE_BYTES)
            .is_err()
    );
    assert_eq!(
        sent.load(Ordering::SeqCst),
        2,
        "one send for each explicitly requested read"
    );
    assert!(client.get_asset_fi_context_snapshot(query, 0).is_err());
    assert_eq!(
        sent.load(Ordering::SeqCst),
        2,
        "invalid bounds never dispatch"
    );
}
