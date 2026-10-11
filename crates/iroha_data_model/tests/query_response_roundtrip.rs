//! `QueryResponse` Norito/JSON roundtrip coverage to guard client/server decode issues.
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    da::{
        commitment::DaCommitmentLocation,
        ingest::{
            DaIngestAuthorizationV1, DaIngestSignatureV1, DaPinScopeAuthorizationV1, DaPinScopeV1,
        },
        pin_intent::{DaPinIntent, DaPinIntentWithLocation},
        types::BlobDigest,
    },
    parameter::Parameters,
    query::{
        QueryOutput, QueryOutputBatchBox, QueryOutputBatchBoxTuple, QueryResponse,
        SingularQueryOutputBox, parameters::ForwardCursor,
    },
    rwa::{Rwa, RwaControlPolicy, RwaId},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::topology::LaneId;
fn checked_da_authorization(lane_id: LaneId, epoch: u64, sequence: u64) -> DaIngestAuthorizationV1 {
    let key_pair =
        iroha_crypto::KeyPair::try_from_seed(vec![0xE1; 32], iroha_crypto::Algorithm::Ed25519)
            .expect("valid deterministic query-response DA key");
    let mut authorization = DaIngestAuthorizationV1 {
        network_id: NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0xE2; 32]),
            ),
        ),
        owner: AccountId::new(key_pair.public_key().clone()),
        lane_id,
        epoch,
        sequence,
        payload_hash: BlobDigest::new([0xE3; 32]),
        payload_bytes: 1,
        request_content_hash: iroha_crypto::Hash::prehashed([0xE4; 32]),
        signatures: Vec::new(),
    };
    authorization.signatures.push(DaIngestSignatureV1 {
        signer: key_pair.public_key().clone(),
        signature: iroha_crypto::Signature::try_new(
            key_pair.private_key(),
            &authorization.signing_digest(),
        )
        .expect("sign deterministic query-response DA authorization"),
    });
    authorization
}
fn checked_da_pin_intent(
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: iroha_data_model::da::types::StorageTicketId,
    manifest_hash: iroha_data_model::sorafs::pin_registry::ManifestDigest,
) -> DaPinIntent {
    let key_pair =
        iroha_crypto::KeyPair::try_from_seed(vec![0xE1; 32], iroha_crypto::Algorithm::Ed25519)
            .expect("valid deterministic query-response DA key");
    let authorization = checked_da_authorization(lane_id, epoch, sequence);
    let scope = DaPinScopeV1::new(&authorization, storage_ticket, manifest_hash, None);
    let scope_authorization = DaPinScopeAuthorizationV1::try_sign(scope, &key_pair)
        .expect("sign deterministic query-response DA pin scope");
    DaPinIntent::new(authorization, scope_authorization)
}
fn checked_random_account_id() -> iroha_data_model::AccountId {
    iroha_data_model::AccountId::new(
        iroha_crypto::KeyPair::try_random()
            .expect("generate checked query-response account keypair")
            .public_key()
            .clone(),
    )
}
#[test]
fn parameters_query_response_roundtrips_norito() {
    let params = Parameters::default();
    let bytes = norito::to_bytes(&params).expect("encode Parameters");
    let decoded: Parameters =
        norito::decode_from_bytes(&bytes).expect("decode Parameters via Norito");
    assert_eq!(decoded, params, "Norito roundtrip must preserve parameters");
}
#[test]
fn parameters_query_response_roundtrips_json() {
    let params = Parameters::default();
    let resp = QueryResponse::Singular(SingularQueryOutputBox::Parameters(params.clone()));
    let json = norito::json::to_vec(&resp).expect("serialize QueryResponse to JSON");
    let decoded: QueryResponse =
        norito::json::from_slice(&json).expect("decode QueryResponse from JSON");
    assert_eq!(decoded, resp, "JSON roundtrip must preserve parameters");
}
#[test]
fn parameters_query_response_roundtrips_header_framed() {
    let params = Parameters::default();
    let resp = QueryResponse::Singular(SingularQueryOutputBox::Parameters(params.clone()));
    let bytes = norito::to_bytes(&resp).expect("encode QueryResponse with header");
    let decoded: QueryResponse =
        norito::decode_from_bytes(&bytes).expect("decode QueryResponse with header");
    assert_eq!(
        decoded, resp,
        "Header-framed Norito roundtrip must preserve parameters"
    );
}
#[test]
fn parameters_roundtrip_bare_payload() {
    let params = Parameters::default();
    // Use the bare codec path (no header) to ensure adaptive flags are honored.
    let bare = norito::codec::Encode::encode(&params);
    let decoded: Parameters =
        norito::codec::decode_adaptive(&bare).expect("decode Parameters from bare payload");
    assert_eq!(
        decoded, params,
        "Bare payload Norito roundtrip must preserve parameters"
    );
}
#[test]
fn da_pin_intent_singular_roundtrip() {
    let intent = checked_da_pin_intent(
        LaneId::new(3),
        5,
        7,
        iroha_data_model::da::types::StorageTicketId::new([0xAA; 32]),
        iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0xBB; 32]),
    );
    let with_location = DaPinIntentWithLocation {
        intent: intent.clone(),
        location: DaCommitmentLocation {
            block_height: 9,
            index_in_bundle: 2,
        },
    };
    let resp = QueryResponse::Singular(SingularQueryOutputBox::DaPinIntent(with_location.clone()));
    let bytes = norito::to_bytes(&resp).expect("encode DA pin intent response");
    let decoded: QueryResponse =
        norito::decode_from_bytes(&bytes).expect("decode DA pin intent response");
    assert_eq!(
        decoded, resp,
        "Norito roundtrip must preserve DA pin intent"
    );
    let json = norito::json::to_vec(&resp).expect("serialize DA pin intent response to JSON");
    let decoded_json: QueryResponse =
        norito::json::from_slice(&json).expect("decode DA pin intent response JSON");
    assert_eq!(
        decoded_json, resp,
        "JSON roundtrip must preserve DA pin intent"
    );
}
#[test]
fn iterable_query_response_roundtrips_header_and_json() {
    let batch = QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::String(vec![
        "alpha".to_owned(),
        "beta".to_owned(),
    ]));
    let cursor: ForwardCursor = norito::json::from_value(norito::json!({
        "query": "iterable-query",
        "cursor": 2_u64,
        "gas_budget": 5_u64,
    }))
    .expect("decode query cursor fixture");
    let output = QueryOutput::new(batch.clone(), 3, Some(cursor));
    let resp = QueryResponse::Iterable(output.clone());
    let bytes = norito::to_bytes(&resp).expect("encode iterable QueryResponse");
    let decoded: QueryResponse =
        norito::decode_from_bytes(&bytes).expect("decode iterable QueryResponse");
    assert_eq!(
        decoded, resp,
        "Header-framed Norito roundtrip must preserve iterable responses"
    );
    let json = norito::json::to_vec(&resp).expect("serialize iterable QueryResponse to JSON");
    let decoded_json: QueryResponse =
        norito::json::from_slice(&json).expect("decode iterable QueryResponse from JSON");
    assert_eq!(
        decoded_json, resp,
        "JSON roundtrip must preserve iterable responses"
    );
    // Bare payload path for the batch tuple itself.
    let bare_batch = norito::codec::Encode::encode(&output.into_parts().0);
    let decoded_batch: QueryOutputBatchBoxTuple =
        norito::codec::decode_adaptive(&bare_batch).expect("decode batch tuple");
    assert_eq!(decoded_batch, batch, "Bare batch payload must roundtrip");
}
#[test]
fn rwa_iterable_query_response_roundtrips_header_and_json() {
    let rwa = Rwa::new(
        RwaId::generated(
            DomainId::try_new("vault", "universal").expect("domain"),
            iroha_crypto::Hash::prehashed([0x11; iroha_crypto::Hash::LENGTH]),
        ),
        "12.5"
            .parse::<iroha_primitives::numeric::Quantity>()
            .expect("quantity"),
        iroha_primitives::numeric::NumericSpec::fractional(1),
        "https://example.test/rwa/lot-1".to_owned(),
        Some("vaulted".parse().expect("status")),
        iroha_model_base::metadata::Metadata::default(),
        Vec::new(),
        RwaControlPolicy::default(),
        checked_random_account_id(),
    );
    let batch = QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::Rwa(vec![rwa.clone()]));
    let output = QueryOutput::new(batch.clone(), 0, None);
    let resp = QueryResponse::Iterable(output.clone());
    let bytes = norito::to_bytes(&resp).expect("encode RWA QueryResponse");
    let decoded: QueryResponse =
        norito::decode_from_bytes(&bytes).expect("decode RWA QueryResponse");
    assert_eq!(decoded, resp, "Norito roundtrip must preserve RWA batches");
    let json = norito::json::to_vec(&resp).expect("serialize RWA QueryResponse to JSON");
    let decoded_json: QueryResponse =
        norito::json::from_slice(&json).expect("decode RWA QueryResponse from JSON");
    assert_eq!(
        decoded_json, resp,
        "JSON roundtrip must preserve RWA iterable responses"
    );
    let bare_batch = norito::codec::Encode::encode(&output.into_parts().0);
    let decoded_batch: QueryOutputBatchBoxTuple =
        norito::codec::decode_adaptive(&bare_batch).expect("decode RWA batch tuple");
    assert_eq!(
        decoded_batch, batch,
        "Bare RWA batch payload must roundtrip"
    );
}
#[test]
fn query_response_decode_rejects_corrupted_payloads() {
    let resp = QueryResponse::Singular(SingularQueryOutputBox::Parameters(Parameters::default()));
    let bytes = norito::to_bytes(&resp).expect("encode QueryResponse");
    // Truncate tail.
    let truncated = &bytes[..bytes.len().saturating_sub(4)];
    assert!(
        norito::decode_from_bytes::<QueryResponse>(truncated).is_err(),
        "Decoding should fail on truncated payload"
    );
    // Corrupt header checksum by flipping a byte.
    let mut corrupted = bytes.clone();
    if let Some(first) = corrupted.first_mut() {
        *first ^= 0xFF;
    }
    assert!(
        norito::decode_from_bytes::<QueryResponse>(&corrupted).is_err(),
        "Decoding should fail on checksum/header corruption"
    );
}
