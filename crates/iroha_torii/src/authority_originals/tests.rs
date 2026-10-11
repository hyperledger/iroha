//! Exact signed-body correlation and private response regression fixtures.
use super::*;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{NetworkId, alias_setup::AccountAliasName};
use iroha_executor_data_model::permission::query::CanReadAccountData;
fn request(challenge: u8) -> NativeAuthorityOriginalsRequestV1 {
    NativeAuthorityOriginalsRequestV1 {
        network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"authority request test network",
        ))),
        challenge: [challenge; 32],
        selector: NativeAuthorityOriginalsSelectorV1::AccountAlias(
            "retail@leumi.is2".parse::<AccountAliasName>().unwrap(),
        ),
    }
}
fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(utils::NORITO_MIME_TYPE),
    );
    headers
}
#[test]
fn exact_post_target_rejects_get_query_prefix_duplicate_type_and_oversized_length() {
    let uri: Uri = NATIVE_AUTHORITY_ORIGINALS_ROUTE_V1.parse().unwrap();
    let original = headers();
    assert!(target(&Method::POST, &uri, &original).is_ok());
    for path in [
        "/peer/v1/ledger/authority-originals",
        "/v1/ledger/authority-originals?challenge=a",
        "/v1/ledger/authority-originals/",
    ] {
        assert!(target(&Method::POST, &path.parse().unwrap(), &original).is_err());
    }
    assert!(target(&Method::GET, &uri, &original).is_err());
    let mut changed = original.clone();
    changed.append(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(utils::NORITO_MIME_TYPE),
    );
    assert!(target(&Method::POST, &uri, &changed).is_err());
    let mut changed = original;
    changed.insert(
        axum::http::header::CONTENT_LENGTH,
        HeaderValue::from_static("65537"),
    );
    assert!(target(&Method::POST, &uri, &changed).is_err());
}
#[test]
fn challenge_correlates_full_original_body_selector_network_and_singleton_header() {
    let original = request(7);
    let body = original.canonical_wire().unwrap();
    let mut headers = headers();
    let (_, digest, challenge) = request_original(&body, &original.network_id, &headers).unwrap();
    assert_eq!(
        (digest, challenge),
        native_authority_originals_request_digests_v1(&body).unwrap()
    );
    headers.insert(
        BRIDGE_FINALITY_CHALLENGE_HEADER,
        HeaderValue::from_str(&hex::encode(challenge)).unwrap(),
    );
    assert!(request_original(&body, &original.network_id, &headers).is_ok());
    let changed = request(8).canonical_wire().unwrap();
    assert!(request_original(&changed, &original.network_id, &headers).is_err());
    let mut other = original.clone();
    other.selector =
        NativeAuthorityOriginalsSelectorV1::AccountAlias("other@leumi.is2".parse().unwrap());
    assert!(
        request_original(
            &other.canonical_wire().unwrap(),
            &original.network_id,
            &headers
        )
        .is_err()
    );
    let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"other actual native network",
    )));
    assert!(request_original(&body, &network, &headers).is_err());
    headers.append(
        BRIDGE_FINALITY_CHALLENGE_HEADER,
        HeaderValue::from_str(&hex::encode(challenge)).unwrap(),
    );
    assert!(request_original(&body, &original.network_id, &headers).is_err());
    let mut body = body;
    body.push(0);
    assert!(request_original(&body, &original.network_id, &headers).is_err());
}
#[test]
fn outer_success_and_error_private_no_store_is_not_lost_by_finality_finalizer() {
    for response in [
        finalize(Ok(AxResponse::new(Body::empty()))),
        finalize(Err(unavailable())),
        finalize(Err(conversion_error("invalid request".into()))),
    ] {
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap(),
            "private, no-store"
        );
    }
}
#[test]
fn variable_committee_and_request_intake_cannot_borrow_unfunded_capacity() {
    let key = KeyPair::from_seed(vec![41; 32], Algorithm::BlsNormal);
    let pop = vec![17; 96];
    let count = 1024;
    let bytes = native_committee_original_bytes(
        count,
        std::iter::repeat_n((key.public_key(), pop.as_slice()), count),
    )
    .unwrap();
    assert!(bytes > 16 * 1024);
    let budget = AllocationBudget::new(bytes - 1);
    assert!(budget.try_reserve_bytes(bytes).is_err());
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        native_committee_original_bytes(
            count,
            std::iter::repeat_n((key.public_key(), pop.as_slice()), count - 1)
        )
        .is_err()
    );
    let intake = NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1 * 8;
    assert!(
        AllocationBudget::new(intake - 1)
            .try_reserve_bytes(intake)
            .is_err()
    );
}

fn native_auth_fixture() -> (SharedAppState, AccountId, KeyPair, Vec<u8>, Uri) {
    let key = KeyPair::from_seed(vec![61; 32], Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
        crate::tests_runtime_handlers::world_with_account(&account),
    );
    let mut request = request(8);
    request.network_id = *app.state.network_id_ref();
    let body = request.canonical_wire().unwrap();
    (
        app,
        account,
        key,
        body,
        NATIVE_AUTHORITY_ORIGINALS_ROUTE_V1.parse().unwrap(),
    )
}
fn grant(app: &SharedAppState, account: &AccountId, permission: Permission) {
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    tx.world_mut_for_testing()
        .add_account_permission(account, permission);
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
}
fn signed(
    app: &SharedAppState,
    account: &AccountId,
    key: &KeyPair,
    body: &[u8],
    uri: &Uri,
) -> HeaderMap {
    crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        account,
        key,
        &Method::POST,
        uri,
        body,
    )
}
#[test]
fn actual_signed_post_requires_native_root_not_listener_or_selective_permissions() {
    let (app, account, key, body, uri) = native_auth_fixture();
    let mut token_only = HeaderMap::new();
    token_only.insert(
        "X-API-Token",
        HeaderValue::from_static("synthetic listener only"),
    );
    assert!(authenticate_body(&app, &token_only, &Method::POST, &uri, &body).is_err());
    assert!(
        authenticate_body(
            &app,
            &signed(&app, &account, &key, &body, &uri),
            &Method::POST,
            &uri,
            &body
        )
        .is_err()
    );
    grant(
        &app,
        &account,
        CanReadAccountData {
            account: account.clone(),
        }
        .into(),
    );
    assert!(
        authenticate_body(
            &app,
            &signed(&app, &account, &key, &body, &uri),
            &Method::POST,
            &uri,
            &body
        )
        .is_err()
    );
    grant(
        &app,
        &account,
        CanReadRestrictedDataspace {
            dataspace: iroha_model_base::topology::DataSpaceId::new(77),
        }
        .into(),
    );
    assert!(
        authenticate_body(
            &app,
            &signed(&app, &account, &key, &body, &uri),
            &Method::POST,
            &uri,
            &body
        )
        .is_err()
    );
    grant(&app, &account, CanReadAllLedgerData.into());
    assert_eq!(
        authenticate_body(
            &app,
            &signed(&app, &account, &key, &body, &uri),
            &Method::POST,
            &uri,
            &body
        )
        .unwrap(),
        account
    );
}
#[test]
fn actual_native_post_signature_rejects_body_selector_network_and_nonce_substitution() {
    let (app, account, key, body, uri) = native_auth_fixture();
    grant(&app, &account, CanReadAllLedgerData.into());
    let mut changed = request(9);
    changed.network_id = *app.state.network_id_ref();
    let altered = changed.canonical_wire().unwrap();
    assert!(
        authenticate_body(
            &app,
            &signed(&app, &account, &key, &body, &uri),
            &Method::POST,
            &uri,
            &altered
        )
        .is_err()
    );
    let headers = signed(&app, &account, &key, &body, &uri);
    assert_eq!(
        authenticate_body(&app, &headers, &Method::POST, &uri, &body).unwrap(),
        account
    );
    assert!(
        authenticate_body(&app, &headers, &Method::POST, &uri, &body).is_err(),
        "actual native nonce cannot be replayed"
    );
    let changed_uri: Uri = "/v1/ledger/authority-originals?selector=other"
        .parse()
        .unwrap();
    assert!(
        authenticate_body(
            &app,
            &signed(&app, &account, &key, &body, &uri),
            &Method::POST,
            &changed_uri,
            &body
        )
        .is_err()
    );
    let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign signed native authority network",
    )));
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        &network,
        &account,
        &key,
        &Method::POST,
        &uri,
        &body,
    );
    assert!(authenticate_body(&app, &headers, &Method::POST, &uri, &body).is_err());
}
#[test]
fn existing_read_root_revocation_is_current_at_queued_and_egress_fences() {
    let (app, account, key, body, uri) = native_auth_fixture();
    let permission: Permission = CanReadAllLedgerData.into();
    grant(&app, &account, permission.clone());
    assert_eq!(
        authenticate_body(
            &app,
            &signed(&app, &account, &key, &body, &uri),
            &Method::POST,
            &uri,
            &body
        )
        .unwrap(),
        account
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    assert!(
        tx.world_mut_for_testing()
            .remove_account_permission(&account, &permission)
    );
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
    // Both actual handler fences call this same current permission check, rather
    // than retaining a passing pre-admission scalar or treating a signed old grant as current.
    assert!(require_full_ledger_carrier_permission(&app, &account).is_err());
    assert!(
        authenticate_body(
            &app,
            &signed(&app, &account, &key, &body, &uri),
            &Method::POST,
            &uri,
            &body
        )
        .is_err()
    );
}
#[test]
fn intake_budget_follows_actual_decoded_and_wire_owner_until_drop() {
    let request = request(11);
    let body = Bytes::from(request.canonical_wire().unwrap());
    let bytes = NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1 * 8;
    let budget = AllocationBudget::new(bytes);
    let charge = budget.try_reserve_bytes(bytes).unwrap();
    let owner = RequestOriginalOwner {
        request,
        _body: body,
        _charge: charge,
    };
    assert_eq!(budget.reserved_bytes(), bytes);
    assert!(budget.try_reserve_bytes(1).is_err());
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn identifier_selector_requires_exact_signed_body_and_existing_full_read_root() {
    let (app, account, key, _, uri) = native_auth_fixture();
    let mut selected = request(47);
    selected.network_id = *app.state.network_id_ref();
    selected.selector =
        NativeAuthorityOriginalsSelectorV1::IdentifierPolicy("email#retail".parse().unwrap());
    let body = selected.canonical_wire().unwrap();
    assert!(
        authenticate_body(
            &app,
            &signed(&app, &account, &key, &body, &uri),
            &Method::POST,
            &uri,
            &body
        )
        .is_err()
    );
    grant(
        &app,
        &account,
        CanReadAccountData {
            account: account.clone(),
        }
        .into(),
    );
    assert!(
        authenticate_body(
            &app,
            &signed(&app, &account, &key, &body, &uri),
            &Method::POST,
            &uri,
            &body
        )
        .is_err()
    );
    grant(&app, &account, CanReadAllLedgerData.into());
    let mut other = selected.clone();
    other.selector =
        NativeAuthorityOriginalsSelectorV1::IdentifierPolicy("other#retail".parse().unwrap());
    assert!(
        authenticate_body(
            &app,
            &signed(&app, &account, &key, &body, &uri),
            &Method::POST,
            &uri,
            &other.canonical_wire().unwrap()
        )
        .is_err()
    );
    other = selected.clone();
    other.challenge = [48; 32];
    assert!(
        authenticate_body(
            &app,
            &signed(&app, &account, &key, &body, &uri),
            &Method::POST,
            &uri,
            &other.canonical_wire().unwrap()
        )
        .is_err()
    );
    let headers = signed(&app, &account, &key, &body, &uri);
    assert_eq!(
        authenticate_body(&app, &headers, &Method::POST, &uri, &body).unwrap(),
        account
    );
    assert!(authenticate_body(&app, &headers, &Method::POST, &uri, &body).is_err());
}
