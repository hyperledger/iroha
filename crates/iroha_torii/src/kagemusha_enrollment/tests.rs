//! Exact HTTP account signatures authenticate the whole closed operation, never provider DATA.
use super::*;
use axum::http::{HeaderMap, Method};
use iroha_core::{kura::Kura, query::store::LiveQueryStore, state::World};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
use iroha_data_model::{
    NetworkId, Registrable as _, account::Account, asset::AssetDefinitionId, block::BlockHeader,
    kagemusha::*, nexus::AxtAssetIncarnationV1,
};

fn fixture() -> (Arc<CoreState>, PreKeyDispatchV1, KeyPair) {
    let selected = test_fixture::provider("/private/test-key".into());
    let asset = KagemushaWalletAssetScopeV1::new(
        AssetDefinitionId::from_uuid_bytes([
            0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd,
            0xcd, 0x2f,
        ])
        .unwrap(),
        &AxtAssetIncarnationV1::try_from_bytes(*Hash::new(b"HTTP enrollment DATA asset").as_ref())
            .unwrap(),
        2,
    )
    .unwrap();
    let key = KeyPair::from_seed(vec![67; 32], Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    let policy = selected.enrollment.for_asset(&asset).unwrap();
    let dispatch = PreKeyDispatchV1 {
        version: 1,
        request_id: [21; 32],
        platform: KagemushaEnrollmentPermitPlatformV1::Apple,
        purpose: KagemushaEnrollmentPermitPurposeV1::Fresh,
        client_nonce: [22; 32],
        native_dispatch_nonce: [23; 32],
        manifest_digest: selected.manifest_digest,
        release_digest: selected.release_digest,
        service_origin_digest: selected.service_origin_digest,
        fi_digest: selected.eligibility.authority.scope_digest(),
        actor_digest: [24; 32],
        scheme: selected.scheme,
        app: selected.app,
        policy,
        enrollment_certificate: selected.certificate,
        account: account.clone(),
        asset,
        previous_permit: None,
    };
    dispatch.validate().unwrap();
    let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed(dispatch.scheme.network_id),
    ));
    let state = Arc::new(CoreState::new_with_chain_and_network_id_for_testing(
        World::with([], [Account::new(account.clone()).build(&account)], []),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        "enrollment-http-tests".parse().unwrap(),
        network,
    ));
    (state, dispatch, key)
}
fn signed(
    state: &Arc<CoreState>,
    dispatch: &PreKeyDispatchV1,
    key: &KeyPair,
    action: EnrollmentServiceActionV1,
) -> HttpCall {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let body = EnrollmentServiceRequestV1 {
        version: 1,
        action,
        dispatch_original: dispatch.encode().unwrap(),
        evidence_original: if action == EnrollmentServiceActionV1::Evidence {
            vec![42]
        } else {
            vec![]
        },
    }
    .canonical_wire()
    .unwrap();
    let method = Method::POST;
    let uri = ENROLLMENT_SERVICE_ROUTE_V1.parse().unwrap();
    let now = crate::utils::unix_now_ms();
    let nonce = format!(
        "enrollment-http-{now}-{}",
        SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let message = crate::app_auth::canonical_network_request_signature_message(
        state.network_id_ref(),
        &method,
        &uri,
        &body,
        now,
        &nonce,
    )
    .unwrap();
    let signature = Signature::try_new(key.private_key(), &message).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        crate::app_auth::HEADER_ACCOUNT,
        dispatch
            .account
            .to_canonical_hex()
            .unwrap()
            .parse()
            .unwrap(),
    );
    headers.insert(
        crate::app_auth::HEADER_SIGNATURE,
        crate::app_auth::signature_header_value(&signature)
            .unwrap()
            .parse()
            .unwrap(),
    );
    headers.insert(
        crate::app_auth::HEADER_TIMESTAMP_MS,
        now.to_string().parse().unwrap(),
    );
    headers.insert(crate::app_auth::HEADER_NONCE, nonce.parse().unwrap());
    HttpCall {
        method,
        uri,
        headers,
        body: body.into(),
    }
}

#[test]
fn exact_envelopes_authenticate_once_for_all_actions() {
    let _guard = crate::tests_runtime_handlers::app_auth_test_guard(Default::default());
    let (state, dispatch, key) = fixture();
    for action in [
        EnrollmentServiceActionV1::PreKey,
        EnrollmentServiceActionV1::Evidence,
        EnrollmentServiceActionV1::Issue,
        EnrollmentServiceActionV1::Deliver,
    ] {
        let call = signed(&state, &dispatch, &key, action);
        assert_eq!(
            authenticate_http(&state, &call, &dispatch.encode().unwrap()).unwrap(),
            dispatch.account
        );
        assert!(authenticate_http(&state, &call, &dispatch.encode().unwrap()).is_err());
    }
}
#[test]
fn account_network_target_action_and_exact_original_mutations_reject() {
    let _guard = crate::tests_runtime_handlers::app_auth_test_guard(Default::default());
    let (state, dispatch, key) = fixture();
    for mutation in 0..9 {
        let mut call = signed(&state, &dispatch, &key, EnrollmentServiceActionV1::Evidence);
        let mut expected = dispatch.encode().unwrap();
        match mutation {
            0 => {
                call.headers.remove(crate::app_auth::HEADER_SIGNATURE);
            }
            1 => call.method = Method::GET,
            2 => call.uri = "/v1/kagemusha/enrollment?attempt=other".parse().unwrap(),
            3 => call.uri = "/v1/kagemusha/enrollment/".parse().unwrap(),
            4 | 5 => {
                let mut changed = EnrollmentServiceRequestV1::decode_canonical(&call.body).unwrap();
                if mutation == 4 {
                    changed.action = EnrollmentServiceActionV1::Issue;
                    changed.evidence_original.clear();
                } else {
                    changed.evidence_original[0] ^= 1;
                }
                call.body = changed.canonical_wire().unwrap().into();
            }
            6 => {
                expected[0] ^= 1;
            }
            7 => {
                let foreign = AccountId::new(
                    KeyPair::from_seed(vec![68; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                );
                call.headers.insert(
                    crate::app_auth::HEADER_ACCOUNT,
                    foreign.to_canonical_hex().unwrap().parse().unwrap(),
                );
            }
            _ => {
                let foreign = Arc::new(CoreState::new_for_testing(
                    World::with(
                        [],
                        [Account::new(dispatch.account.clone()).build(&dispatch.account)],
                        [],
                    ),
                    Kura::blank_kura_for_testing(),
                    LiveQueryStore::start_test(),
                ));
                assert!(authenticate_http(&foreign, &call, &expected).is_err());
                continue;
            }
        }
        assert!(
            authenticate_http(&state, &call, &expected).is_err(),
            "mutation {mutation}"
        );
    }
}
