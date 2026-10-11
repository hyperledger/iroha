//! Transport-only signed specimens: no fixture claims native completion or registry inclusion.
use super::*;
use crate::client::evidence_http_tests::{
    base_url, capture_requests, client_with_base_url, empty_response, with_mock_http,
};
use iroha_crypto::{Algorithm, KeyPair, SignatureOf};
use iroha_data_model::{
    musubi::*,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            ProviderIngestCompletionAuthorityV1, ProviderIngestCompletionSignerPolicyV1,
            ProviderIngestFinalizedAnchorV1, ReplicationOrderId,
        },
    },
};

fn signed(client: &Client) -> MusubiProviderBundleVerificationAttestationV1 {
    let owner = AccountId::new(
        KeyPair::from_seed(vec![0x61; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let signer = KeyPair::from_seed(vec![0x62; 32], Algorithm::Ed25519);
    let completed_by = AccountId::new(signer.public_key().clone());
    let payload = MusubiProviderBundleVerificationPayloadV1 {
        version: MUSUBI_REGISTRY_VERSION_V1,
        binding: MusubiProviderBundleVerificationBindingV1 {
            network_id: client.network_id,
            provider_id: ProviderId::new([0x11; 32]),
            completed_by: completed_by.clone(),
            completion_authority: ProviderIngestCompletionAuthorityV1::new(
                owner,
                completed_by,
                ProviderIngestCompletionSignerPolicyV1 {
                    policy_id: [0x12; 32],
                    revision: 1,
                    predecessor_digest: None,
                    policy_digest: [0x13; 32],
                },
            ),
            replication_order: ReplicationOrderId::new([0x14; 32]),
            assignment_revision: 1,
            completion_epoch: 100,
            finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                height: 3,
                block_hash: [0x15; 32],
            },
            archive_id: ArchiveId::new([0x16; 32]),
            bundle_digest: MusubiContentDigestV1::new([0x17; 32]),
            descriptor_digest: MusubiContentDigestV1::new([0x18; 32]),
            semantic_release_manifest_digest: MusubiSemanticReleaseDigestV1::new([0x19; 32]),
            verification_lock_digest: MusubiVerificationLockDigestV1::new([0x20; 32]),
            source_tree_digest: MusubiContentDigestV1::new([0x21; 32]),
        },
    };
    let result = MusubiProviderBundleVerificationAttestationV1 {
        approvals: vec![MusubiProviderBundleVerificationApprovalV1 {
            public_key: signer.public_key().clone(),
            signature: SignatureOf::try_from_hash(signer.private_key(), payload.signing_hash())
                .unwrap(),
        }],
        payload,
    };
    result.verify(&result.payload.binding).unwrap();
    result
}
fn response(bytes: Vec<u8>) -> crate::http::Response<Vec<u8>> {
    crate::http::Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/x-norito")
        .body(bytes)
        .unwrap()
}
#[test]
fn provider_attestation_exact_original_signed_body_single_authenticated_bounded_post() {
    let client = client_with_base_url(base_url());
    let original = signed(&client);
    assert_ne!(
        original.payload.binding.completed_by,
        original.payload.binding.completion_authority.provider_owner
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let (actual, requests) = capture_requests(
        response(norito::encode_canonical(&original).unwrap()),
        |http| {
            client
                .clone()
                .with_test_http_transport(http)
                .with_request_deadline(deadline)
                .get_sorafs_provider_attestation(original.key())
        },
    );
    assert_eq!(actual.unwrap(), Some(original.clone()));
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, HttpMethod::POST);
    assert_eq!(
        request.url.path(),
        iroha_torii_shared::route_catalog::sorafs::PROVIDER_ATTESTATION.path()
    );
    assert_eq!(
        request.body,
        norito::encode_canonical(&original.key()).unwrap()
    );
    assert_eq!(request.max_response_bytes, RESPONSE_MAX);
    assert!(
        request
            .timeout
            .is_some_and(|value| value <= Duration::from_secs(5))
    );
    crate::client::tests::assert_canonical_account_signed_request(&client, request);
}
#[test]
fn provider_attestation_missing_endpoint_is_not_native_absence_and_statuses_do_not_retry() {
    let client = client_with_base_url(base_url());
    let key = signed(&client).key();
    let (read, calls) = capture_requests(empty_response(StatusCode::NO_CONTENT), |http| {
        client
            .clone()
            .with_test_http_transport(http)
            .get_sorafs_provider_attestation(key)
    });
    assert_eq!(read.unwrap(), None);
    assert_eq!(calls.len(), 1);
    for status in [
        StatusCode::NOT_FOUND,
        StatusCode::FORBIDDEN,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let (read, calls) = capture_requests(empty_response(status), |http| {
            client
                .clone()
                .with_test_http_transport(http)
                .get_sorafs_provider_attestation(key)
        });
        assert!(read.is_err());
        assert_eq!(calls.len(), 1);
    }
    let malformed = crate::http::Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(vec![1])
        .unwrap();
    let (read, calls) = capture_requests(malformed, |http| {
        client
            .clone()
            .with_test_http_transport(http)
            .get_sorafs_provider_attestation(key)
    });
    assert!(read.is_err());
    assert_eq!(calls.len(), 1);
}
#[test]
fn provider_attestation_substitution_forgery_and_noncanonical_body_are_refused() {
    let client = client_with_base_url(base_url());
    let original = signed(&client);
    let mut wrong_key = original.key();
    wrong_key.provider_id = ProviderId::new([0x71; 32]);
    let mut altered = original.clone();
    altered.payload.binding.source_tree_digest = MusubiContentDigestV1::new([0x72; 32]);
    let mut tailed = norito::encode_canonical(&original).unwrap();
    tailed.push(0);
    for (key, bytes) in [
        (wrong_key, norito::encode_canonical(&original).unwrap()),
        (original.key(), norito::encode_canonical(&altered).unwrap()),
        (original.key(), tailed),
        (original.key(), vec![0; RESPONSE_MAX + 1]),
    ] {
        let (read, calls) = capture_requests(response(bytes), |http| {
            client
                .clone()
                .with_test_http_transport(http)
                .get_sorafs_provider_attestation(key)
        });
        assert!(read.is_err());
        assert_eq!(calls.len(), 1);
    }
    // Another independently selected network can receive a genuinely signed statement,
    // but that signature does not change the request's selected network.
    let mut foreign = original.clone();
    foreign.payload.binding.network_id =
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"other attestation network"),
        ));
    let signer = KeyPair::from_seed(vec![0x62; 32], Algorithm::Ed25519);
    foreign.approvals[0].signature =
        SignatureOf::try_from_hash(signer.private_key(), foreign.payload.signing_hash()).unwrap();
    foreign.verify(&foreign.payload.binding).unwrap();
    let (read, calls) = capture_requests(
        response(norito::encode_canonical(&foreign).unwrap()),
        |http| {
            client
                .clone()
                .with_test_http_transport(http)
                .get_sorafs_provider_attestation(original.key())
        },
    );
    assert!(read.is_err());
    assert_eq!(calls.len(), 1);
}
#[test]
fn provider_attestation_invalid_expired_and_zero_budget_are_zero_http() {
    let client = client_with_base_url(base_url());
    let mut key = signed(&client).key();
    with_mock_http(
        |_| panic!("refused reads must not dispatch"),
        |http| {
            let client = client.clone().with_test_http_transport(http);
            assert!(
                client
                    .with_request_deadline(std::time::Instant::now())
                    .get_sorafs_provider_attestation(key)
                    .is_err()
            );
            assert!(
                norito::with_decode_limits_scope(
                    norito::DecodeLimits::new(RESPONSE_MAX, RESPONSE_MAX, RESPONSE_MAX, 0, 64),
                    || client.get_sorafs_provider_attestation(key)
                )
                .is_err()
            );
            key.provider_id = ProviderId::new([0; 32]);
            assert!(client.get_sorafs_provider_attestation(key).is_err());
        },
    );
}

#[test]
fn provider_attestation_charges_one_request_frame_and_distinct_response_reservation() {
    let client = client_with_base_url(base_url());
    let key = signed(&client).key();
    let canonical = norito::encode_canonical(&key).unwrap();
    let budget = canonical.len() + RESPONSE_MAX;
    let limits = norito::DecodeLimits::new(RESPONSE_MAX, RESPONSE_MAX, RESPONSE_MAX, budget, 64);
    let (read, calls) = capture_requests(empty_response(StatusCode::NO_CONTENT), |http| {
        let client = client.clone().with_test_http_transport(http);
        norito::with_decode_limits_scope(limits, || {
            let first = client.get_sorafs_provider_attestation(key);
            assert!(
                client.get_sorafs_provider_attestation(key).is_err(),
                "the original request/response allowance cannot renew"
            );
            first
        })
    });
    assert_eq!(read.unwrap(), None);
    assert_eq!(
        calls.len(),
        1,
        "allocation refusal must precede another HTTP dispatch"
    );
    assert_eq!(calls[0].body, canonical);
    assert_eq!(calls[0].max_response_bytes, RESPONSE_MAX);
}
