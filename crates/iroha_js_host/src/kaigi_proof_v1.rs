//! Shared native proof framing and public proving material for final Kaigi V1.

use iroha_data_model::{
    proof::{ProofBox, VerifyingKeyBox},
    zk::OpenVerifyEnvelope,
};
use kaigi_zk::authorization_v1::KaigiAuthorizationWitnessV1;
use napi::{
    Env,
    bindgen_prelude::{JsObjectValue as _, Uint8ArraySlice},
};

/// Native verifier backend shared by the fixed Kaigi circuits.
pub const VK_BACKEND: &str = iroha_core_zk::ZK_BACKEND_NATIVE_PIPA_R;

/// Report rejected caller input at the JavaScript boundary.
pub fn invalid(message: impl ToString) -> napi::Error {
    napi::Error::new(napi::Status::InvalidArg, message.to_string())
}
/// Report a native proving or encoding failure.
pub fn failure(message: impl ToString) -> napi::Error {
    napi::Error::new(napi::Status::GenericFailure, message.to_string())
}

/// Consume the canonical blinding scalar and erase the supplied byte slice.
pub fn take_witness(bytes: &mut [u8]) -> napi::Result<KaigiAuthorizationWitnessV1> {
    let mut owned = [0; 32];
    if bytes.len() == owned.len() {
        owned.copy_from_slice(bytes);
    }
    iroha_crypto::zeroize_value_for_confidential_discard(bytes);
    if bytes.len() != owned.len() {
        return Err(invalid(
            "blinding must contain exactly 32 canonical Pasta Fp bytes",
        ));
    }
    KaigiAuthorizationWitnessV1::take_blinding(&mut owned).map_err(invalid)
}

/// Copy the caller's scalar into native custody and erase its JavaScript buffer.
pub fn consume_blinding(
    env: Env,
    blinding: &mut Uint8ArraySlice<'_>,
) -> napi::Result<KaigiAuthorizationWitnessV1> {
    let length =
        u32::try_from(blinding.len()).map_err(|_| invalid("blinding exceeds JS index width"))?;
    let mut owned = [0; 32];
    if length == 32 {
        owned.copy_from_slice(blinding.as_ref());
    }
    let witness = take_witness(&mut owned);
    let zero = env.create_uint32(0)?;
    // Scoped VM writes avoid an aliased mutable Rust slice into JS memory.
    // No JavaScript callback runs; the owned witness is dropped on every error.
    for index in 0..length {
        blinding.set_element(index, zero)?;
    }
    if length != 32 {
        return Err(invalid(
            "blinding must contain exactly 32 canonical Pasta Fp bytes",
        ));
    }
    witness
}

/// Encode only a proof envelope accepted by its exact native verifying key.
pub fn encode_verified_envelope(
    envelope: &OpenVerifyEnvelope,
    key: &VerifyingKeyBox,
) -> napi::Result<Vec<u8>> {
    let encoded = norito::encode_canonical(envelope).map_err(failure)?;
    let proof = ProofBox::new(VK_BACKEND.to_owned(), encoded.clone());
    finish_verified_envelope(
        encoded,
        iroha_core_zk::verify_backend(VK_BACKEND, &proof, Some(key)),
    )
}

// This terminal SDK boundary returns no proof bytes unless the original verifier
// completed successfully. Local refusal remains distinct from a completed false verdict.
fn finish_verified_envelope(
    encoded: Vec<u8>,
    attempt: Result<bool, iroha_core_zk::VerificationRefusal>,
) -> napi::Result<Vec<u8>> {
    match attempt {
        Ok(true) => Ok(encoded),
        Ok(false) => Err(failure(
            "generated Kaigi proof failed canonical native verification",
        )),
        Err(original) => Err(failure(format!(
            "native_verification_unavailable: {original}"
        ))),
    }
}

#[cfg(test)]
mod attempt_tests {
    use super::*;

    #[test]
    fn only_completed_native_success_returns_the_original_encoded_envelope() {
        let bytes = vec![17, 29, 43];
        let pointer = bytes.as_ptr();
        let complete = finish_verified_envelope(bytes, Ok(true)).unwrap();
        assert_eq!(complete, [17, 29, 43]);
        assert_eq!(complete.as_ptr(), pointer);
        let false_verdict = finish_verified_envelope(vec![17, 29, 43], Ok(false)).unwrap_err();
        assert_eq!(false_verdict.status, napi::Status::GenericFailure);
        assert_eq!(
            false_verdict.reason,
            "generated Kaigi proof failed canonical native verification"
        );
    }

    #[test]
    fn actual_decoder_refusal_cannot_become_a_false_verdict_or_return_proof_bytes() {
        let frame = norito::encode_canonical(&vec![1_u8; 32]).unwrap();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let attempt = norito::with_decode_limits_scope(limits, || {
            norito::core::classify_decode_attempt(|| norito::decode_canonical::<Vec<u8>>(&frame))
        })
        .unwrap_err();
        let original = attempt.into_local_refusal().unwrap();
        let refusal = iroha_core_zk::VerificationRefusal::from_decode_refusal(original);
        let error = finish_verified_envelope(vec![17, 29, 43], Err(refusal)).unwrap_err();
        assert_eq!(error.status, napi::Status::GenericFailure);
        assert!(error.reason.starts_with("native_verification_unavailable:"));
        assert!(
            !error
                .reason
                .contains("failed canonical native verification")
        );
        assert_eq!(
            norito::decode_canonical::<Vec<u8>>(&frame).unwrap(),
            vec![1_u8; 32]
        );
    }
}
