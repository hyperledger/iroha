//! Shared strict X25519 primitives for fixed first-release wallet codecs.
//!
//! RFC 7748 permits implementations to mask and accept non-canonical public
//! encodings. Consensus-facing wallet codecs need one byte representation, so
//! this module first requires the encoded Montgomery `u` coordinate to be
//! strictly smaller than `2^255 - 19`, then rejects the complete low-order set
//! through the mandatory all-zero shared-secret check.
use core::borrow::Borrow;
use curve25519_dalek::{constants::X25519_BASEPOINT, montgomery::MontgomeryPoint};
use thiserror::Error;
use zeroize::Zeroizing;
const FIELD_MODULUS_LITTLE_ENDIAN: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
/// Strict key-agreement failure shared by private wallet codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum X25519WalletErrorV1 {
    /// A wallet secret uses the reserved all-zero encoding.
    #[error("X25519 wallet secret must be non-zero")]
    ZeroSecret,
    /// A public key is not the unique canonical field encoding.
    #[error("X25519 public key is not canonically encoded")]
    NonCanonicalPublicKey,
    /// A public key is in the low-order set.
    #[error("X25519 public key is low order")]
    LowOrderPublicKey,
    /// Key agreement produced the forbidden all-zero shared secret.
    #[error("X25519 key agreement produced an all-zero shared secret")]
    ZeroSharedSecret,
}
fn is_canonical_field_encoding(bytes: [u8; 32]) -> bool {
    // Strict little-endian comparison against p. Equality is non-canonical.
    for index in (0..32).rev() {
        if bytes[index] < FIELD_MODULUS_LITTLE_ENDIAN[index] {
            return true;
        }
        if bytes[index] > FIELD_MODULUS_LITTLE_ENDIAN[index] {
            return false;
        }
    }
    false
}
/// Validate the sole canonical X25519 public-key representation.
pub fn validate_x25519_public_key_v1(public_key: [u8; 32]) -> Result<(), X25519WalletErrorV1> {
    if !is_canonical_field_encoding(public_key) {
        return Err(X25519WalletErrorV1::NonCanonicalPublicKey);
    }
    // A fixed non-zero clamped probe rejects the entire low-order set. This is
    // safe only after the strict encoding check above; otherwise RFC 7748
    // masking could admit byte aliases for the same low-order point.
    let probe = MontgomeryPoint(public_key)
        .mul_clamped([0x42; 32])
        .to_bytes();
    if probe.iter().all(|byte| *byte == 0) {
        return Err(X25519WalletErrorV1::LowOrderPublicKey);
    }
    Ok(())
}
/// Derive and validate an X25519 public key from a non-zero wallet secret.
pub fn x25519_public_key_v1(
    secret_key: impl Borrow<[u8; 32]>,
) -> Result<[u8; 32], X25519WalletErrorV1> {
    let secret_key = secret_key.borrow();
    if secret_key.iter().all(|byte| *byte == 0) {
        return Err(X25519WalletErrorV1::ZeroSecret);
    }
    let clamped_input = Zeroizing::new(*secret_key);
    let public_key = X25519_BASEPOINT.mul_clamped(*clamped_input).to_bytes();
    validate_x25519_public_key_v1(public_key)?;
    Ok(public_key)
}
/// Perform strict X25519 key agreement and retain the secret in zeroizing storage.
pub fn x25519_shared_secret_v1(
    secret_key: impl Borrow<[u8; 32]>,
    peer_public_key: [u8; 32],
) -> Result<Zeroizing<[u8; 32]>, X25519WalletErrorV1> {
    let secret_key = secret_key.borrow();
    if secret_key.iter().all(|byte| *byte == 0) {
        return Err(X25519WalletErrorV1::ZeroSecret);
    }
    validate_x25519_public_key_v1(peer_public_key)?;
    let clamped_input = Zeroizing::new(*secret_key);
    let shared = Zeroizing::new(
        MontgomeryPoint(peer_public_key)
            .mul_clamped(*clamped_input)
            .to_bytes(),
    );
    if shared.iter().all(|byte| *byte == 0) {
        return Err(X25519WalletErrorV1::ZeroSharedSecret);
    }
    Ok(shared)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_public_key_validation_rejects_aliases_and_low_order_points() {
        let public = x25519_public_key_v1([0x42; 32]).expect("canonical public key");
        validate_x25519_public_key_v1(public).expect("generated key is valid");
        assert_eq!(
            validate_x25519_public_key_v1(FIELD_MODULUS_LITTLE_ENDIAN),
            Err(X25519WalletErrorV1::NonCanonicalPublicKey)
        );
        let mut greater_than_modulus = FIELD_MODULUS_LITTLE_ENDIAN;
        greater_than_modulus[0] = 0xee;
        assert_eq!(
            validate_x25519_public_key_v1(greater_than_modulus),
            Err(X25519WalletErrorV1::NonCanonicalPublicKey)
        );
        assert_eq!(
            validate_x25519_public_key_v1([0; 32]),
            Err(X25519WalletErrorV1::LowOrderPublicKey)
        );
        for torsion_point in curve25519_dalek::constants::EIGHT_TORSION {
            let encoding = torsion_point.to_montgomery().to_bytes();
            assert!(
                is_canonical_field_encoding(encoding),
                "dalek emitted a non-canonical torsion encoding"
            );
            assert_eq!(
                validate_x25519_public_key_v1(encoding),
                Err(X25519WalletErrorV1::LowOrderPublicKey),
                "canonical low-order encoding {encoding:02x?} was accepted"
            );
        }
        assert_eq!(
            x25519_public_key_v1([0; 32]),
            Err(X25519WalletErrorV1::ZeroSecret)
        );
    }
    #[test]
    fn strict_key_agreement_is_symmetric() {
        let alice_secret = [0x11; 32];
        let bob_secret = [0x22; 32];
        let alice_public = x25519_public_key_v1(&alice_secret).unwrap();
        let bob_public = x25519_public_key_v1(&bob_secret).unwrap();
        let alice_shared = x25519_shared_secret_v1(&alice_secret, bob_public).unwrap();
        let bob_shared = x25519_shared_secret_v1(&bob_secret, alice_public).unwrap();
        assert_eq!(*alice_shared, *bob_shared);
    }
    #[test]
    fn rfc_7748_key_agreement_vector_is_exact() {
        let alice_secret: [u8; 32] =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let alice_public: [u8; 32] =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap()
                .try_into()
                .unwrap();
        let bob_secret: [u8; 32] =
            hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .unwrap()
                .try_into()
                .unwrap();
        let bob_public: [u8; 32] =
            hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_shared: [u8; 32] =
            hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(x25519_public_key_v1(&alice_secret).unwrap(), alice_public);
        assert_eq!(x25519_public_key_v1(&bob_secret).unwrap(), bob_public);
        assert_eq!(
            *x25519_shared_secret_v1(&alice_secret, bob_public).unwrap(),
            expected_shared
        );
        assert_eq!(
            *x25519_shared_secret_v1(&bob_secret, alice_public).unwrap(),
            expected_shared
        );
    }
}
