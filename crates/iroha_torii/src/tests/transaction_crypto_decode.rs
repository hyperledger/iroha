//! Actual decoder capabilities determine ingress outcomes without package-feature assumptions.

use axum::{
    body::{Body, Bytes},
    extract::{FromRequest, Request},
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use iroha_crypto::{Algorithm, CryptoOperation, PublicKey, UnsupportedImplementation};
use iroha_data_model::{
    Level,
    isi::Log,
    transaction::{
        FeePaymentIntent, MultisigSignature, MultisigSignatures, SignedTransaction,
        TransactionBuilder, TransactionEntrypoint,
    },
};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
use iroha_version::codec::{DecodeVersioned, EncodeVersioned};
use norito::{codec::Encode as _, core as ncore};

use crate::utils::extractors::{JsonOrNoritoVersioned, SupportsVersionedJsonDecode};

const GOST: Algorithm = Algorithm::Gost3410_2012_256ParamSetA;

fn signed_fixture() -> SignedTransaction {
    TransactionBuilder::new(
        "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .unwrap(),
        (*ALICE_ID).clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "parser readiness".to_owned())])
    .sign(ALICE_KEYPAIR.private_key())
}

fn retag_versioned_key(original: &[u8], tag: u8) -> Vec<u8> {
    assert_eq!(original[0], 1, "declared fixed-V1 transaction layout");
    let flags = ncore::default_encode_flags();
    let key = ALICE_KEYPAIR.public_key();
    let encoded_key = key.encode();
    let (_, key_payload) = key.try_to_bytes().unwrap();
    let mut algorithm_offset = None;
    ncore::visit_binary_sequence_with_count(&encoded_key, flags, key_payload.len() + 1, |span| {
        algorithm_offset.get_or_insert(span.start);
        Ok(())
    })
    .unwrap();
    let algorithm_offset = algorithm_offset.unwrap();
    let matches = original[1..]
        .windows(encoded_key.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == encoded_key).then_some(offset))
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "fixture contains the one authority key");
    let mut payload = original[1..].to_vec();
    payload[matches[0] + algorithm_offset] = tag;
    // Version 1 fixes the bare layout; there is no nested frame to guess or
    // checksum to repair. The absent parser is reached before key validation;
    // this fixture does not claim its retagged key or signature is valid.
    let mut wire = vec![original[0]];
    wire.extend(payload);
    wire
}

fn parser_is_missing() -> bool {
    GOST.require_implementation(CryptoOperation::ParsePublicKey)
        .is_err()
}

fn assert_retagged_key_error<T: DecodeVersioned>(wire: &[u8]) {
    let Err(iroha_version::error::Error::NoritoCodec(error)) = T::decode_all_versioned(wire) else {
        panic!("retagged Ed25519 bytes must fail GOST key decoding");
    };
    if parser_is_missing() {
        assert!(
            matches!(error, norito::Error::UnsupportedFeature(name) if name == GOST.as_static_str())
        );
    } else {
        assert!(!matches!(error, norito::Error::UnsupportedFeature(_)));
        assert!(iroha_core::execution_attempt::crypto_public_key_decode_deferred(&error).is_none());
    }
}

async fn extract<T>(body: Vec<u8>, content_type: &'static str) -> Result<T, Response>
where
    T: DecodeVersioned + SupportsVersionedJsonDecode + 'static,
{
    let request = Request::builder()
        .header(CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap();
    JsonOrNoritoVersioned::<T>::from_request(request, &())
        .await
        .map(|extracted| extracted.0)
}

async fn assert_deferred(response: Response) {
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers().get("retry-after").unwrap(), "1");
    for header in [
        "x-iroha-reject-code",
        "x-iroha-transactions-accepted",
        "x-iroha-entrypoint-hash",
        "x-iroha-signed-transaction-hash",
    ] {
        assert!(response.headers().get(header).is_none(), "{header}");
    }
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let envelope: iroha_torii_shared::ErrorEnvelope = norito::decode_from_bytes(&bytes).unwrap();
    assert_eq!(envelope.code(), "transaction_admission_deferred");
    assert!(envelope.message().contains("not queued"));
    assert!(
        envelope
            .message()
            .contains("retry the unchanged signed request")
    );
}

fn assert_original_deferred(error: &crate::Error) {
    let crate::Error::TransactionAdmissionDeferred(original) = error else {
        panic!("expected local parser deferral, got {error:?}");
    };
    assert_eq!(
        original.reason(),
        ivm::error::ExecutionDeferral::CryptoImplementationUnavailable(UnsupportedImplementation {
            algorithm: GOST,
            operation: CryptoOperation::ParsePublicKey,
        })
    );
    assert!(original.decode_refusal().is_none());
    assert!(original.allocation_refusal().is_none());
}

async fn assert_retagged_response(response: Response) {
    if parser_is_missing() {
        assert_deferred(response).await;
    } else {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get("retry-after").is_none());
    }
}

fn assert_actual_retagged_error(error: &crate::Error, expected_code: &str) {
    if parser_is_missing() {
        assert_original_deferred(error);
    } else {
        assert!(
            matches!(error, crate::Error::AppQueryValidation { code, .. } if *code == expected_code)
        );
    }
}

async fn assert_actual_json_outcome<T>(body: Vec<u8>)
where
    T: DecodeVersioned
        + SupportsVersionedJsonDecode
        + norito::json::JsonSerialize
        + std::fmt::Debug
        + 'static,
{
    let expected: norito::json::Value = norito::json::from_slice(&body).unwrap();
    let decoded = extract::<T>(body, "application/json").await;
    if parser_is_missing() {
        assert_deferred(decoded.unwrap_err()).await;
    } else {
        // This checks complete decoded content, not cryptographic authorization:
        // these deliberately altered signed inputs have not passed admission.
        let actual = norito::json::to_value(&decoded.unwrap()).unwrap();
        assert_eq!(&actual, expected.get("content").unwrap());
    }
}

#[tokio::test]
async fn signed_binary_retagged_key_matches_actual_parser_capability() {
    let signed = signed_fixture();
    let original = signed.encode_versioned();
    assert_eq!(
        extract::<SignedTransaction>(original.clone(), crate::utils::NORITO_MIME_TYPE)
            .await
            .unwrap(),
        signed
    );
    let unavailable = retag_versioned_key(&original, GOST as u8);
    assert_retagged_key_error::<SignedTransaction>(&unavailable);
    assert_retagged_response(
        extract::<SignedTransaction>(unavailable, crate::utils::NORITO_MIME_TYPE)
            .await
            .unwrap_err(),
    )
    .await;
}

#[tokio::test]
async fn entrypoint_binary_retagged_key_matches_actual_parser_capability() {
    let entrypoint = TransactionEntrypoint::External(signed_fixture());
    let original = entrypoint.encode_versioned();
    assert_eq!(
        extract::<TransactionEntrypoint>(original.clone(), crate::utils::NORITO_MIME_TYPE)
            .await
            .unwrap(),
        entrypoint
    );
    let unavailable = retag_versioned_key(&original, GOST as u8);
    assert_retagged_key_error::<TransactionEntrypoint>(&unavailable);
    assert_retagged_response(
        extract::<TransactionEntrypoint>(unavailable, crate::utils::NORITO_MIME_TYPE)
            .await
            .unwrap_err(),
    )
    .await;
}

fn signed_json_fixture() -> SignedTransaction {
    let mut signed = signed_fixture();
    signed.set_multisig_signatures(MultisigSignatures::new(vec![MultisigSignature::new(
        ALICE_KEYPAIR.public_key().clone(),
        signed.signature().0.clone(),
    )]));
    signed
}

fn gost_json_key() -> String {
    // Canonical varints: public-key multicodec 0x1200, 64-byte payload.
    let payload = include_str!("../../../../fixtures/account/gost256a_public_key.hex").trim();
    let literal = format!("802440{payload}");
    let encoded = norito::json::to_string(&literal).unwrap();
    let decoded = norito::json::from_str::<PublicKey>(&encoded);
    if parser_is_missing() {
        assert!(
            matches!(decoded, Err(norito::json::Error::UnsupportedFeature(name)) if name == GOST.as_static_str())
        );
    } else {
        let decoded = decoded.unwrap();
        assert_eq!(decoded.algorithm(), GOST);
        assert_eq!(decoded.to_string(), literal);
    }
    literal
}

fn versioned_json_with_signer<T: norito::json::JsonSerialize>(value: &T, signer: &str) -> Vec<u8> {
    let content = norito::json::to_string(value).unwrap();
    let old_key = norito::json::to_string(ALICE_KEYPAIR.public_key()).unwrap();
    let new_key = norito::json::to_string(signer).unwrap();
    assert_eq!(
        content.matches(&old_key).count(),
        1,
        "one multisig signer literal"
    );
    format!(
        "{{\"version\":1,\"content\":{}}}",
        content.replace(&old_key, &new_key)
    )
    .into_bytes()
}

#[tokio::test]
async fn signed_json_known_signer_preserves_actual_parser_outcome() {
    let signed = signed_json_fixture();
    let original = versioned_json_with_signer(&signed, &ALICE_KEYPAIR.public_key().to_string());
    assert_eq!(
        extract::<SignedTransaction>(original, "application/json")
            .await
            .unwrap(),
        signed
    );
    let unavailable = versioned_json_with_signer(&signed, &gost_json_key());
    assert_actual_json_outcome::<SignedTransaction>(unavailable).await;
}

#[tokio::test]
async fn entrypoint_json_known_signer_preserves_actual_parser_outcome() {
    let entrypoint = TransactionEntrypoint::External(signed_json_fixture());
    let original = versioned_json_with_signer(&entrypoint, &ALICE_KEYPAIR.public_key().to_string());
    assert_eq!(
        extract::<TransactionEntrypoint>(original, "application/json")
            .await
            .unwrap(),
        entrypoint
    );
    let unavailable = versioned_json_with_signer(&entrypoint, &gost_json_key());
    assert_actual_json_outcome::<TransactionEntrypoint>(unavailable).await;
}

#[tokio::test]
async fn programmatic_redecode_matches_actual_parser_capability() {
    let signed = signed_fixture();
    let original = signed.encode_versioned();
    assert_eq!(
        super::decode_signed_transaction_for_ingress(&original)
            .unwrap()
            .hash(),
        signed.hash()
    );
    let unavailable = retag_versioned_key(&original, GOST as u8);
    let error = super::decode_signed_transaction_for_ingress(&unavailable).unwrap_err();
    assert_actual_retagged_error(&error, "invalid_transaction_payload");
    assert_retagged_response(error.into_response()).await;
    let malformed = retag_versioned_key(&original, 0xff);
    let error = super::decode_signed_transaction_for_ingress(&malformed).unwrap_err();
    assert!(matches!(
        &error,
        crate::Error::AppQueryValidation {
            code: "invalid_transaction_payload",
            ..
        }
    ));
    assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn batch_decoder_rejects_bad_second_item_without_partial_result() {
    let original = signed_fixture().encode_versioned();
    let batch = norito::to_bytes(&vec![original.clone(), original.clone()]).unwrap();
    assert_eq!(
        super::decode_transaction_batch_request(Bytes::from(batch), 2)
            .unwrap()
            .len(),
        2
    );
    let unavailable = retag_versioned_key(&original, GOST as u8);
    let batch = norito::to_bytes(&vec![original.clone(), unavailable]).unwrap();
    let error = super::decode_transaction_batch_request(Bytes::from(batch), 2).unwrap_err();
    assert_actual_retagged_error(&error, "invalid_transaction_batch_payload");
    if !parser_is_missing() {
        assert!(
            matches!(&error, crate::Error::AppQueryValidation { message, .. } if message.contains("item 1"))
        );
    }
    assert_retagged_response(error.into_response()).await;
    let malformed = retag_versioned_key(&original, 0xff);
    let batch = norito::to_bytes(&vec![original, malformed]).unwrap();
    let error = super::decode_transaction_batch_request(Bytes::from(batch), 2).unwrap_err();
    assert!(
        matches!(&error, crate::Error::AppQueryValidation { code: "invalid_transaction_batch_payload", message } if message.contains("item 1"))
    );
    assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
    let mut corrupt_envelope =
        norito::to_bytes(&vec![signed_fixture().encode_versioned()]).unwrap();
    *corrupt_envelope.last_mut().unwrap() ^= 1;
    let error =
        super::decode_transaction_batch_request(Bytes::from(corrupt_envelope), 2).unwrap_err();
    assert!(matches!(
        &error,
        crate::Error::AppQueryValidation {
            code: "invalid_transaction_batch_envelope",
            ..
        }
    ));
    assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_binary_identity_and_trailing_bytes_remain_bad_request() {
    let signed = signed_fixture();
    let original = signed.encode_versioned();
    let unknown = retag_versioned_key(&original, 0xff);
    let mut corrupt = original.clone();
    corrupt.push(0);
    for wire in [unknown, corrupt] {
        let response = extract::<SignedTransaction>(wire, crate::utils::NORITO_MIME_TYPE)
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get("x-iroha-reject-code").unwrap(),
            "invalid_transaction_payload"
        );
        assert!(response.headers().get("retry-after").is_none());
    }
    let original = TransactionEntrypoint::External(signed).encode_versioned();
    let unknown = retag_versioned_key(&original, 0xff);
    let mut corrupt = original.clone();
    corrupt.push(0);
    for wire in [unknown, corrupt] {
        let response = extract::<TransactionEntrypoint>(wire, crate::utils::NORITO_MIME_TYPE)
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get("retry-after").is_none());
    }
}

#[tokio::test]
async fn malformed_json_key_does_not_become_parser_deferral() {
    let signed = signed_json_fixture();
    for signer in ["invalid public key", "ed0101AA", "ff7f01AA"] {
        let body = versioned_json_with_signer(&signed, signer);
        let response = extract::<SignedTransaction>(body, "application/json")
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get("x-iroha-reject-code").unwrap(),
            "invalid_transaction_payload"
        );
        assert!(response.headers().get("retry-after").is_none());
        let body =
            versioned_json_with_signer(&TransactionEntrypoint::External(signed.clone()), signer);
        let response = extract::<TransactionEntrypoint>(body, "application/json")
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get("retry-after").is_none());
    }
}

#[tokio::test]
async fn request_byte_limit_precedes_known_parser_and_stays_payload_too_large() {
    let original = signed_fixture().encode_versioned();
    let wire = retag_versioned_key(&original, GOST as u8);
    let mut request = Request::builder()
        .header(CONTENT_TYPE, crate::utils::NORITO_MIME_TYPE)
        .body(Body::from(wire))
        .unwrap();
    request
        .extensions_mut()
        .insert(crate::utils::extractors::VersionedIngressLimits {
            max_body_bytes: 1,
            decode_limits: norito::DecodeLimits::new(1, 1, 1, 1, 1),
            json_decode_limits: norito::DecodeLimits::new(1, 1, 1, 1, 1),
        });
    let response = JsonOrNoritoVersioned::<SignedTransaction>::from_request(request, &())
        .await
        .unwrap_err();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(response.headers().get("retry-after").is_none());
}

fn gost_i105_authority() -> String {
    let fixture: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../fixtures/account/multisig_wire_v1.json"
    ))
    .unwrap();
    let literal = fixture
        .get("positive")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| {
            entry.get("name").and_then(norito::json::Value::as_str) == Some(GOST.as_static_str())
        })
        .unwrap()
        .get("i105")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let encoded = norito::json::to_string(&literal).unwrap();
    let decoded = norito::json::from_str::<iroha_data_model::account::AccountId>(&encoded);
    if parser_is_missing() {
        assert!(
            matches!(decoded, Err(norito::json::Error::UnsupportedFeature(name)) if name == GOST.as_static_str())
        );
    } else {
        assert_eq!(decoded.unwrap().to_string(), literal);
    }
    literal
}

fn versioned_json_with_authority<T: norito::json::JsonSerialize>(
    value: &T,
    authority: &str,
) -> Vec<u8> {
    let content = norito::json::to_string(value).unwrap();
    let old_authority = norito::json::to_string(&*ALICE_ID).unwrap();
    let new_authority = norito::json::to_string(authority).unwrap();
    assert_eq!(
        content.matches(&old_authority).count(),
        1,
        "one primary authority"
    );
    format!(
        "{{\"version\":1,\"content\":{}}}",
        content.replace(&old_authority, &new_authority)
    )
    .into_bytes()
}

#[tokio::test]
async fn signed_json_primary_i105_authority_preserves_actual_parser_outcome() {
    let _chain_guard = iroha_data_model::account::address::ChainDiscriminantGuard::enter(753);
    let signed = signed_fixture();
    let body = versioned_json_with_authority(&signed, &gost_i105_authority());
    assert_actual_json_outcome::<SignedTransaction>(body).await;
    let malformed = versioned_json_with_authority(&signed, "invalid I105 authority");
    let response = extract::<SignedTransaction>(malformed, "application/json")
        .await
        .unwrap_err();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get("x-iroha-reject-code").unwrap(),
        "invalid_transaction_payload"
    );
    assert!(response.headers().get("retry-after").is_none());
}

#[tokio::test]
async fn entrypoint_json_primary_i105_authority_preserves_actual_parser_outcome() {
    let _chain_guard = iroha_data_model::account::address::ChainDiscriminantGuard::enter(753);
    let entrypoint = TransactionEntrypoint::External(signed_fixture());
    let body = versioned_json_with_authority(&entrypoint, &gost_i105_authority());
    assert_actual_json_outcome::<TransactionEntrypoint>(body).await;
    let malformed = versioned_json_with_authority(&entrypoint, "invalid I105 authority");
    let response = extract::<TransactionEntrypoint>(malformed, "application/json")
        .await
        .unwrap_err();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get("retry-after").is_none());
}
