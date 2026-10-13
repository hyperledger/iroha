//! Canonical Rust fixture coverage for the N-API attachment-context boundary.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iroha_data_model::account::address::ChainDiscriminantGuard;
use norito::json::Value;

fn fixtures() -> Value {
    norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/zk/signed_attachments_v1/vectors.json"
    )))
    .expect("shared canonical vectors")
}
fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .expect("fixture string")
}
fn payload(value: &Value) -> Vec<u8> {
    hex::decode(text(value, "payload_hex")).expect("fixture hex")
}
fn expected_identity(bytes: &[u8]) -> (Vec<u8>, String) {
    let builder = TransactionBuilder::decode_payload(bytes).expect("accepted fixture payload");
    (
        builder
            .payload()
            .network_id()
            .expect("network payload")
            .as_bytes()
            .to_vec(),
        builder
            .payload()
            .authority
            .to_i105_for_discriminant(369)
            .expect("fixture authority"),
    )
}
fn inspect(bytes: Vec<u8>) -> JsTransactionAttachmentContextV1 {
    let (network, authority) = expected_identity(&bytes);
    inspect_transaction_attachment_context_v1(bytes.into(), network.into(), authority)
        .expect("actual complete native context")
}
fn assert_projection(context: &JsTransactionAttachmentContextV1, row: &Value) {
    assert_eq!(
        hex::encode(context.ordered_intent_digest.as_ref()),
        text(row, "ordered_intent_digest_hex")
    );
    assert_eq!(
        hex::encode(context.ordered_intent_projection.as_ref()),
        text(row, "ordered_intent_projection_hex")
    );
}

#[test]
fn shared_seven_attachment_contexts_match_actual_rust_payload_projection_and_statements() {
    let _guard = ChainDiscriminantGuard::enter(369);
    let all = fixtures();
    let rows = all.get("accepted").and_then(Value::as_array).unwrap();
    assert_eq!(rows.len(), 7);
    for row in rows {
        let bytes = payload(row);
        let context = inspect(bytes.clone());
        assert_projection(&context, row);
        assert_eq!(
            context.payload_hash.as_ref(),
            iroha_crypto::Hash::new(&bytes).as_ref()
        );
        assert_eq!(
            context.attachment_frame.as_ref().unwrap().as_ref(),
            STANDARD
                .decode(text(row, "attachments_frame_base64"))
                .unwrap()
        );
        let expected = row
            .get("statement_digests_hex")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(context.statement_digests.len(), expected.len());
        for (actual, expected) in context.statement_digests.iter().zip(expected) {
            assert_eq!(hex::encode(actual.as_ref()), expected.as_str().unwrap());
        }
    }
}

#[test]
fn shared_twenty_four_privacy_intents_use_the_canonical_per_submission_normalizer() {
    let _guard = ChainDiscriminantGuard::enter(369);
    let all = fixtures();
    let rows = all
        .get("privacy_intents")
        .and_then(Value::as_array)
        .unwrap();
    assert_eq!(rows.len(), 24);
    for row in rows {
        let context = inspect(payload(row));
        assert_projection(&context, row);
    }
}

// The signed invalid fixtures cannot be decoded as SignedTransaction. Extract
// their payload field with the canonical header/length reader only, so the
// actual production decoder under test must reject it; this never repairs it.
fn invalid_payload(row: &Value) -> Vec<u8> {
    let bytes = hex::decode(text(row, "signed_transaction_hex")).unwrap();
    let view = norito::core::from_bytes_view(&bytes).expect("fixture frame checksum");
    assert_eq!(view.flags(), norito::core::default_encode_flags());
    let data = view.as_bytes();
    let (signature_len, prefix) =
        norito::core::read_len_from_slice_with_flags(data, view.flags()).unwrap();
    let remaining = &data[prefix + signature_len..];
    let (payload_len, prefix) =
        norito::core::read_len_from_slice_with_flags(remaining, view.flags()).unwrap();
    remaining[prefix..prefix + payload_len].to_vec()
}

#[test]
fn all_twelve_shared_rejections_reach_the_actual_native_context_boundary() {
    let _guard = ChainDiscriminantGuard::enter(369);
    let all = fixtures();
    let valid = &all.get("accepted").and_then(Value::as_array).unwrap()[0];
    let (network, authority) = expected_identity(&payload(valid));
    let rows = all.get("rejected").and_then(Value::as_array).unwrap();
    assert_eq!(rows.len(), 12);
    for row in rows {
        let error = inspect_transaction_attachment_context_v1(
            invalid_payload(row).into(),
            network.clone().into(),
            authority.clone(),
        )
        .err()
        .expect("actual invalid context rejected");
        assert!(
            error.reason.contains(text(row, "error")),
            "{}: {}",
            text(row, "name"),
            error.reason
        );
    }
}

#[test]
fn context_binds_requested_identity_and_rejects_noncanonical_or_oversized_payloads() {
    let _guard = ChainDiscriminantGuard::enter(369);
    let all = fixtures();
    let row = &all.get("accepted").and_then(Value::as_array).unwrap()[0];
    let bytes = payload(row);
    let (network, authority) = expected_identity(&bytes);
    let mut foreign = network.clone();
    foreign[0] ^= 1;
    assert!(
        inspect_transaction_attachment_context_v1(
            bytes.clone().into(),
            foreign.into(),
            authority.clone()
        )
        .is_err()
    );
    let other = iroha_crypto::KeyPair::random().public_key().clone();
    let other = iroha_data_model::account::AccountId::new(other)
        .to_i105_for_discriminant(369)
        .unwrap();
    assert!(
        inspect_transaction_attachment_context_v1(
            bytes.clone().into(),
            network.clone().into(),
            other
        )
        .is_err()
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(
        inspect_transaction_attachment_context_v1(
            trailing.into(),
            network.clone().into(),
            authority.clone()
        )
        .is_err()
    );
    for malformed in [Vec::new(), vec![0; MAX_INSPECTION_PAYLOAD_BYTES + 1]] {
        let error = inspect_transaction_attachment_context_v1(
            malformed.into(),
            network.clone().into(),
            authority.clone(),
        )
        .err()
        .unwrap();
        assert!(error.reason.contains("1..=10485760"));
    }
}

#[test]
fn attachment_free_context_has_no_descriptor_or_statements() {
    let _guard = ChainDiscriminantGuard::enter(369);
    let all = fixtures();
    let row = all.get("attachment_free").unwrap();
    let bytes = payload(row);
    let context = inspect(bytes.clone());
    assert!(context.attachment_frame.is_none());
    assert!(context.statement_digests.is_empty());
    assert_eq!(
        hex::encode(context.ordered_intent_digest.as_ref()),
        text(row, "ordered_intent_digest_hex")
    );
    assert_eq!(
        context.payload_hash.as_ref(),
        iroha_crypto::Hash::new(&bytes).as_ref()
    );
}
