//! Structural account-envelope admission with real signatures and exact canonical frame boundaries.
use super::*;
use crate::query::final_promotion_account_custody::observation::{
    FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1, FinalPromotionAccountObservationErrorV1,
    validate_final_promotion_account_transaction_envelope_v1,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::{MultisigMember, MultisigPolicy},
    block::BlockHeader,
    proof::{ProofAttachment, ProofBox, VerifyingKeyId},
    transaction::{FeePaymentIntent, TransactionDomain, TransactionPayload},
};
use iroha_primitives::json::Json;
use std::num::NonZeroU32;
use std::num::NonZeroU64;

fn payload(padding: usize) -> TransactionPayload {
    let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::new(b"independent envelope profile network"),
    ));
    let mut builder = TransactionBuilder::new(
        network,
        AccountId::new(key(4).public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(17)),
    )
    .with_instructions(Vec::<InstructionBox>::new());
    builder.set_creation_time(Duration::from_millis(1_234));
    builder.set_ttl(Duration::from_millis(7_654));
    let mut payload = builder.into_payload().unwrap();
    payload.nonce = NonZeroU32::new(19);
    payload.metadata.insert(
        "review_note".parse().unwrap(),
        Json::new("a".repeat(padding)),
    );
    payload
}

fn real_entry(payload: &TransactionPayload) -> TransactionEntrypoint {
    let signed = TransactionBuilder::from_payload(payload.clone())
        .unwrap()
        .try_sign(key(4).private_key())
        .unwrap();
    signed.verify_signature().unwrap();
    TransactionEntrypoint::External(signed)
}

fn entry_len(payload: &TransactionPayload) -> usize {
    norito::canonical_frame_len(&real_entry(payload)).unwrap()
}

fn last_fitting_padding() -> usize {
    let (mut low, mut high) = (0, FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1);
    assert!(entry_len(&payload(low)) < FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1);
    assert!(entry_len(&payload(high)) > FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1);
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if entry_len(&payload(middle)) <= FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1 {
            low = middle;
        } else {
            high = middle;
        }
    }
    low
}

#[test]
fn account_envelope_preflight_matches_real_signed_external_exact_byte_ceiling() {
    let boundary = last_fitting_padding();
    for (padding, delta) in [(boundary - 1, -1isize), (boundary, 0), (boundary + 1, 1)] {
        let payload = payload(padding);
        let original = norito::encode_canonical(&payload).unwrap();
        let expected_length = FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1
            .checked_add_signed(delta)
            .unwrap();
        let entry = real_entry(&payload);
        assert_eq!(
            norito::encode_canonical(&entry).unwrap().len(),
            expected_length
        );
        assert!(
            original.len() < FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1,
            "the envelope, not just its payload, reaches the ceiling"
        );
        for flags in [0, norito::core::header_flags::COMPACT_LEN] {
            let _layout = norito::core::DecodeFlagsGuard::enter(flags);
            let result = validate_final_promotion_account_transaction_envelope_v1(&payload);
            assert_eq!(
                result,
                if delta <= 0 {
                    Ok(())
                } else {
                    Err(FinalPromotionAccountObservationErrorV1::Transaction)
                }
            );
            assert_eq!(result.is_ok(), bounded_entry(&entry).is_ok());
            assert_eq!(norito::encode_canonical(&payload).unwrap(), original);
        }
    }
}

#[test]
fn account_envelope_preflight_preserves_reviewed_payload_and_rejects_oversized_input() {
    let reviewed = payload(13);
    let before = reviewed.clone();
    validate_final_promotion_account_transaction_envelope_v1(&reviewed).unwrap();
    assert_eq!(reviewed, before);
    assert_eq!(
        real_entry(&reviewed).authority_opt(),
        Some(&before.authority)
    );
    // An empty native instruction list is structurally encodable. This size-only function
    // deliberately cannot authorize any action or manufacture a reviewed-request capability.
    assert!(
        matches!(&reviewed.instructions, Executable::Instructions(values) if values.is_empty())
    );
    let oversized = payload(FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1 + 1);
    assert!(
        norito::canonical_frame_len(&oversized).unwrap()
            > FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1
    );
    assert_eq!(
        validate_final_promotion_account_transaction_envelope_v1(&oversized),
        Err(FinalPromotionAccountObservationErrorV1::Transaction)
    );
}

#[test]
fn account_envelope_preflight_rejects_other_authorization_profiles_and_builder_failures() {
    let original = payload(0);
    validate_final_promotion_account_transaction_envelope_v1(&original).unwrap();
    let mut failures = Vec::new();
    let mut altered = original.clone();
    let other = KeyPair::try_from_seed(vec![0x62; 32], Algorithm::Secp256k1).unwrap();
    altered.authority = AccountId::new(other.public_key().clone());
    failures.push(altered);
    let mut altered = original.clone();
    altered.authority = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(key(4).public_key().clone(), 1).unwrap(),
                MultisigMember::new(key(5).public_key().clone(), 1).unwrap(),
            ],
        )
        .unwrap(),
    );
    failures.push(altered);
    let mut altered = original.clone();
    altered
        .set_proof_attachments_v1(&[ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("halo2/ipa", "vk_1"),
        )])
        .unwrap();
    failures.push(altered);
    let mut altered = original.clone();
    altered.domain = TransactionDomain::Genesis;
    failures.push(altered);
    let mut altered = original.clone();
    altered.time_to_live_ms = None;
    failures.push(altered);
    let mut altered = original.clone();
    altered
        .metadata
        .insert("gas_limit".parse().unwrap(), Json::from(100_u64));
    failures.push(altered);
    for altered in failures {
        assert!(
            norito::canonical_frame_len(&altered).unwrap()
                < FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1
        );
        assert_eq!(
            validate_final_promotion_account_transaction_envelope_v1(&altered),
            Err(FinalPromotionAccountObservationErrorV1::Transaction)
        );
    }
    assert_eq!(original, payload(0));
}

#[test]
fn native_signed_envelope_owner_retains_real_check_bytes_and_canonical_replay() {
    use crate::query::final_promotion_account_custody::observation::final_promotion_native_signed_entry_frame_v1;
    let state = state();
    let mut round = NativeCheckRoundV1::start(Duration::from_secs(60)).unwrap();
    let instruction = instruction(&mut round, &state);
    let signed = sign(&state, instruction.into(), 2, 3_000);
    let entry = TransactionEntrypoint::External(signed);
    let exact = norito::encode_canonical(&entry).unwrap();
    assert_eq!(
        final_promotion_native_signed_entry_frame_v1(&entry).unwrap(),
        exact
    );
    let decoded: TransactionEntrypoint = norito::decode_canonical(&exact).unwrap();
    assert_eq!(decoded, entry);
    assert_eq!(
        final_promotion_native_signed_entry_frame_v1(&decoded).unwrap(),
        exact
    );
    let mut trailing = exact;
    trailing.push(0);
    assert!(norito::decode_canonical::<TransactionEntrypoint>(&trailing).is_err());
}

#[test]
fn native_signed_envelope_owner_rejects_sidecars_extras_signatures_and_other_entry_kinds() {
    use crate::query::final_promotion_account_custody::observation::final_promotion_native_signed_entry_frame_v1;
    use iroha_data_model::transaction::signed::{MultisigSignatures, SealedTransactionReveal};
    let original = payload(0);
    let TransactionEntrypoint::External(signed) = real_entry(&original) else {
        unreachable!()
    };
    let mut sidecar = signed.clone();
    sidecar.set_multisig_signatures(MultisigSignatures::new(Vec::new()));
    let invalid_signature = TransactionBuilder::from_payload(original.clone())
        .unwrap()
        .build_with_signature(Signature::from_bytes(&[0; 64]));
    let mut attached_payload = original.clone();
    attached_payload
        .set_proof_attachments_v1(&[ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("halo2/ipa", "vk_1"),
        )])
        .unwrap();
    let attached = TransactionBuilder::from_payload(attached_payload)
        .unwrap()
        .try_sign(key(4).private_key())
        .unwrap();
    let other_key = KeyPair::try_from_seed(vec![92; 32], Algorithm::Secp256k1).unwrap();
    let mut other_payload = original.clone();
    other_payload.authority = AccountId::new(other_key.public_key().clone());
    let other = TransactionBuilder::from_payload(other_payload)
        .unwrap()
        .try_sign(other_key.private_key())
        .unwrap();
    for entry in [
        TransactionEntrypoint::External(sidecar),
        TransactionEntrypoint::External(invalid_signature),
        TransactionEntrypoint::External(attached),
        TransactionEntrypoint::External(other),
        TransactionEntrypoint::SealedReveal(SealedTransactionReveal {
            commitment: Hash::new([1]),
            signed_transaction: signed,
            salt: [1; 32],
        }),
    ] {
        assert!(
            matches!(final_promotion_native_signed_entry_frame_v1(&entry), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
                FinalPromotionAccountObservationErrorV1::Transaction
            ))
        );
    }
    assert_eq!(original, payload(0));
}

#[test]
fn native_signed_envelope_owner_uses_the_same_exact_complete_frame_ceiling() {
    use crate::query::final_promotion_account_custody::observation::final_promotion_native_signed_entry_frame_v1;
    let boundary = last_fitting_padding();
    for delta in [-1isize, 0, 1] {
        let entry = real_entry(&payload(boundary.checked_add_signed(delta).unwrap()));
        let exact = norito::encode_canonical(&entry).unwrap();
        assert_eq!(
            exact.len(),
            FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1
                .checked_add_signed(delta)
                .unwrap()
        );
        let actual = final_promotion_native_signed_entry_frame_v1(&entry);
        if delta <= 0 {
            assert_eq!(actual.expect("fitting native frame"), exact);
        } else {
            assert!(matches!(
                actual,
                Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                    FinalPromotionAccountObservationErrorV1::Transaction
                ))
            ));
        }
    }
}

#[test]
fn native_signed_envelope_rejects_genuinely_signed_genesis_and_missing_lifetime() {
    use crate::query::final_promotion_account_custody::observation::final_promotion_native_signed_entry_frame_v1;
    let original = payload(0);
    let mut genesis = original.clone();
    genesis.domain = TransactionDomain::Genesis;
    let genesis = TransactionBuilder::from_genesis_payload(genesis)
        .unwrap()
        .try_sign(key(4).private_key())
        .unwrap();
    let mut missing_ttl = TransactionBuilder::from_payload(original).unwrap();
    missing_ttl.set_ttl(Duration::ZERO);
    let signature =
        Signature::try_new(key(4).private_key(), &missing_ttl.payload_hash_bytes()).unwrap();
    let missing_ttl = missing_ttl.build_with_signature(signature);
    assert!(genesis.network_id().is_none());
    assert!(missing_ttl.network_id().is_some());
    assert!(missing_ttl.time_to_live().is_none());
    for signed in [genesis, missing_ttl] {
        signed.verify_signature().unwrap();
        assert!(
            matches!(native_signed_transaction_frame_attempt_v1(&signed), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
                Error::Transaction
            ))
        );
        assert!(
            matches!(final_promotion_native_signed_entry_frame_v1(&TransactionEntrypoint::External(signed)), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
                FinalPromotionAccountObservationErrorV1::Transaction
            ))
        );
    }
}

#[test]
fn borrowed_signed_frame_preserves_canonical_bytes_and_original_resource_refusal() {
    use crate::execution_attempt::ExecutionAttemptError;
    let TransactionEntrypoint::External(signed) = real_entry(&payload(0)) else {
        unreachable!()
    };
    let original = signed.clone();
    let expected =
        norito::encode_canonical(&TransactionEntrypoint::External(signed.clone())).unwrap();
    assert_eq!(
        native_signed_transaction_frame_attempt_v1(&signed).unwrap(),
        expected
    );
    assert_eq!(signed, original);
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    assert!(matches!(
        norito::core::with_decode_limits_scope(limits, || {
            native_signed_transaction_frame_attempt_v1(&signed)
        }),
        Err(ExecutionAttemptError::Deferred(_))
    ));
    let signed_frame_len = norito::canonical_frame_len(&signed).unwrap();
    let limits =
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, signed_frame_len, 128);
    assert!(
        matches!(
            norito::core::with_decode_limits_scope(limits, || {
                native_signed_transaction_frame_attempt_v1(&signed)
            }),
            Err(ExecutionAttemptError::Deferred(_))
        ),
        "owned signed-frame decoding retains the encoding scope's cumulative debit"
    );
    assert_eq!(signed, original);
}

#[test]
fn public_native_signed_frame_preserves_original_local_codec_refusal() {
    use crate::execution_attempt::ExecutionAttemptError;
    use crate::query::final_promotion_account_custody::observation::final_promotion_native_signed_entry_frame_v1;
    let entry = real_entry(&payload(0));
    let expected = norito::encode_canonical(&entry).unwrap();
    let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    let error = norito::with_decode_limits_scope(zero, || {
        final_promotion_native_signed_entry_frame_v1(&entry)
    })
    .unwrap_err();
    assert!(
        matches!(error, ExecutionAttemptError::Deferred(_)),
        "public frame helper retains actual codec refusal: {error:?}"
    );
    assert_eq!(
        final_promotion_native_signed_entry_frame_v1(&entry).unwrap(),
        expected
    );
}
