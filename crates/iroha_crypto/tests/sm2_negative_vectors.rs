//! Negative SM2 verification vectors modelled after `BouncyCastle` and `GmSSL` suites.
#![cfg(feature = "sm")]
use super::sm2_negative_vector_fixture::{apply_mutation, load_negative_vectors};
use iroha_crypto::{Sm2PrivateKey, Sm2PublicKey, Sm2Signature};
#[test]
fn sm2_negative_vectors_reject() {
    // Deterministic key seeded so that the public key matches across mutations.
    let private =
        Sm2PrivateKey::from_seed(Sm2PublicKey::DEFAULT_DISTID, b"sm2-negative-vectors").unwrap();
    let base_public = private.public_key();
    // Sanity-check deterministic signing still produces a valid signature.
    let signature = private.sign(b"sanity");
    assert!(base_public.verify(b"sanity", &signature).is_ok());
    let vectors = load_negative_vectors();
    for vector in vectors {
        let outcome = apply_mutation(&vector, &private);
        if outcome.public_parse_failed {
            // Invalid public key decode mirrors upstream behaviour (parse failure).
            continue;
        }
        if outcome.expect_signature_parse_error {
            if let Ok(bytes) = outcome.signature_bytes.clone().try_into() {
                assert!(
                    Sm2Signature::from_bytes(&bytes).is_err(),
                    "Negative vector `{}` should reject at parse time",
                    vector.label
                );
            }
            continue;
        }
        let sig_bytes: [u8; Sm2Signature::LENGTH] = outcome
            .signature_bytes
            .clone()
            .try_into()
            .expect("mutation must retain signature length for verification cases");
        let signature = Sm2Signature::from_bytes(&sig_bytes)
            .unwrap_or_else(|_| panic!("mutation {} should parse", vector.label));
        let verify_result = outcome
            .public_key
            .verify(&outcome.verify_message, &signature);
        assert!(
            verify_result.is_err(),
            "Negative vector `{}` unexpectedly verified",
            vector.label
        );
    }
}
