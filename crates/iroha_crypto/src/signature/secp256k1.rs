//! Secp256k1 signatures with one canonical public-key parser.

use self::ecdsa_secp256k1::EcdsaSecp256k1Impl;
pub(crate) mod public_key;

use crate::{Error, KeyGenOption, ParseError};
use std::{format, vec::Vec};
/// ECDSA over secp256k1 with SHA-256 hashing (used for interoperability).
#[derive(Clone, Copy)]
pub struct EcdsaSecp256k1Sha256;
/// Compressed/uncompressed secp256k1 public key.
pub type PublicKey = k256::PublicKey;
/// SEC1-encoded secp256k1 secret key.
pub type PrivateKey = k256::SecretKey;
impl EcdsaSecp256k1Sha256 {
    /// Generate a secp256k1 keypair using the provided RNG option.
    pub fn keypair(option: KeyGenOption<PrivateKey>) -> (PublicKey, PrivateKey) {
        EcdsaSecp256k1Impl::keypair(option)
    }
    /// Fallibly generate a secp256k1 keypair using the provided RNG option.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGen`] if OS-backed random generation fails or cannot
    /// produce a valid scalar within the bounded retry window.
    pub fn try_keypair(option: KeyGenOption<PrivateKey>) -> Result<(PublicKey, PrivateKey), Error> {
        EcdsaSecp256k1Impl::try_keypair(option)
    }
    /// Sign a message using the provided secp256k1 private key.
    pub fn sign(message: &[u8], sk: &PrivateKey) -> Vec<u8> {
        EcdsaSecp256k1Impl::sign(message, sk)
    }
    /// Fallibly sign a message using the provided secp256k1 private key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signing`] if the backend rejects the SHA-256 prehash.
    pub fn try_sign(message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, Error> {
        EcdsaSecp256k1Impl::try_sign(message, sk)
    }
    /// Sign a 32-byte prehash using a recoverable secp256k1 signature.
    ///
    /// Returns a 65-byte `r || s || v` payload where `v` is `27` or `28`, matching
    /// the compact signature format expected by EVM `ecrecover`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signing`] if the key material cannot produce a recoverable signature.
    pub fn sign_prehash_recoverable(
        prehash: &[u8; 32],
        sk: &PrivateKey,
    ) -> Result<[u8; 65], Error> {
        EcdsaSecp256k1Impl::sign_prehash_recoverable(prehash, sk)
    }
    /// Recover a secp256k1 public key from a 32-byte prehash and recoverable signature.
    ///
    /// The signature must be encoded as `r || s || v` where `v` is `27` or `28`.
    /// Only canonical low-S signatures are accepted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadSignature`] if recovery fails, the payload is malformed,
    /// or the signature is non-canonical.
    pub fn recover_public_key_from_prehash(
        prehash: &[u8; 32],
        signature: &[u8; 65],
    ) -> Result<PublicKey, Error> {
        EcdsaSecp256k1Impl::recover_public_key_from_prehash(prehash, signature)
    }
    /// Derive the 20-byte EVM address for a secp256k1 public key.
    pub fn evm_address(pk: &PublicKey) -> [u8; 20] {
        EcdsaSecp256k1Impl::evm_address(pk)
    }
    /// Verify a signature using the provided public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadSignature`] if verification fails, the signature is non-canonical
    /// (high-S), or the inputs are malformed.
    pub fn verify(message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<(), Error> {
        EcdsaSecp256k1Impl::verify(message, signature, pk)
    }
    /// Parse a SEC1-encoded public key.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the payload cannot be decoded into a valid key or
    /// when the encoding is non-canonical (must match the canonical SEC1 encoding).
    pub fn parse_public_key(payload: &[u8]) -> Result<PublicKey, ParseError> {
        public_key::parse(payload).map_err(public_key::KeyRejection::into_parse_error)
    }

    /// Validate a SEC1 public key for a decode path without retaining an
    /// encoded copy or consulting process-local state.
    pub(crate) fn validate_public_key_for_decode(
        payload: &[u8],
    ) -> Result<(), public_key::KeyRejection> {
        public_key::parse(payload).map(drop)
    }
    /// Parse a SEC1-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the payload is malformed or uses an unsupported format.
    pub fn parse_private_key(payload: &[u8]) -> Result<PrivateKey, ParseError> {
        EcdsaSecp256k1Impl::parse_private_key(payload)
    }
    /// Deterministic batch verification helper.
    ///
    /// Verifies each (message, signature, `public_key`) triple independently in order.
    /// The `seed32` parameter is reserved for future deterministic MSM batching and is unused.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadSignature`] when the inputs differ in length or any tuple fails
    /// verification, or when the input is empty.
    pub fn verify_batch_deterministic(
        messages: &[&[u8]],
        signatures: &[&[u8]],
        public_keys: &[&[u8]],
        _seed32: [u8; 32],
    ) -> Result<(), Error> {
        if messages.is_empty()
            || !(messages.len() == signatures.len() && signatures.len() == public_keys.len())
        {
            return Err(Error::BadSignature);
        }
        for ((m, s), pk_bytes) in messages
            .iter()
            .zip(signatures.iter())
            .zip(public_keys.iter())
        {
            let pk = match Self::parse_public_key(pk_bytes) {
                Ok(v) => v,
                Err(_) => return Err(Error::BadSignature),
            };
            Self::verify(m, s, &pk)?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verify_batch_deterministic_two_ok() {
        #[cfg(feature = "rand")]
        let (pk1, sk1) = EcdsaSecp256k1Sha256::keypair(KeyGenOption::Random);
        #[cfg(not(feature = "rand"))]
        let (pk1, sk1) = {
            let bytes =
                hex::decode("e4f21b38e005d4f895a29e84948d7cc83eac79041aeb644ee4fab8d9da42f713")
                    .unwrap();
            let sk = EcdsaSecp256k1Sha256::parse_private_key(&bytes).unwrap();
            (sk.public_key(), sk)
        };
        #[cfg(feature = "rand")]
        let (pk2, sk2) = EcdsaSecp256k1Sha256::keypair(KeyGenOption::Random);
        #[cfg(not(feature = "rand"))]
        let (pk2, sk2) = {
            let bytes =
                hex::decode("a7f0b8eff14c2a0ed5f279d22e2f596dccb6b3f8e8f7e6f4161da676b8458cf1")
                    .unwrap();
            let sk = EcdsaSecp256k1Sha256::parse_private_key(&bytes).unwrap();
            (sk.public_key(), sk)
        };
        let m1 = b"m1".as_ref();
        let m2 = b"m2".as_ref();
        let s1 = EcdsaSecp256k1Sha256::sign(m1, &sk1);
        let s2 = EcdsaSecp256k1Sha256::sign(m2, &sk2);
        let msgs: [&[u8]; 2] = [m1, m2];
        let sigs: [&[u8]; 2] = [s1.as_slice(), s2.as_slice()];
        let ep1 = pk1.to_sec1_bytes();
        let ep2 = pk2.to_sec1_bytes();
        let pks_arr: [&[u8]; 2] = [ep1.as_ref(), ep2.as_ref()];
        EcdsaSecp256k1Sha256::verify_batch_deterministic(&msgs, &sigs, &pks_arr, [0u8; 32])
            .expect("ok");
    }
    #[test]
    fn verify_batch_deterministic_rejects_empty() {
        let empty: Vec<&[u8]> = Vec::new();
        assert!(
            EcdsaSecp256k1Sha256::verify_batch_deterministic(&empty, &empty, &empty, [0u8; 32])
                .is_err()
        );
    }
    #[cfg(feature = "rand")]
    #[test]
    fn try_keypair_random_signs_and_verifies() {
        let (pk, sk) =
            EcdsaSecp256k1Sha256::try_keypair(KeyGenOption::Random).expect("checked keypair");
        let message = b"secp256k1 checked random keypair";
        let signature = EcdsaSecp256k1Sha256::sign(message, &sk);
        EcdsaSecp256k1Sha256::verify(message, &signature, &pk).expect("signature verifies");
    }
}
mod ecdsa_secp256k1 {
    use super::{PrivateKey, PublicKey};
    use crate::{Error, KeyGenOption, ParseError, rng::rng_from_seed};
    use elliptic_curve::sec1::ToEncodedPoint as _;
    use k256::ecdsa::{
        RecoveryId, Signature, SigningKey, VerifyingKey,
        signature::hazmat::{PrehashSigner as _, PrehashVerifier as _},
    };
    #[cfg(feature = "rand")]
    use rand::rngs::OsRng;
    #[cfg(feature = "rand")]
    use rand_core::TryCryptoRng;
    use sha2::Digest as _;
    use sha3::Keccak256;
    use std::{format, string::ToString as _, vec::Vec};
    use zeroize::{Zeroize as _, Zeroizing};
    pub struct EcdsaSecp256k1Impl;
    impl EcdsaSecp256k1Impl {
        pub fn keypair(option: KeyGenOption<PrivateKey>) -> (PublicKey, PrivateKey) {
            Self::try_keypair(option).expect("secp256k1 key generation should succeed")
        }
        pub fn try_keypair(
            option: KeyGenOption<PrivateKey>,
        ) -> Result<(PublicKey, PrivateKey), Error> {
            let signing_key = match option {
                #[cfg(feature = "rand")]
                KeyGenOption::Random => Self::random_private_key()?,
                KeyGenOption::UseSeed(mut seed) => {
                    if !seed.is_empty() && seed.iter().all(|&byte| byte == 0) {
                        seed.zeroize();
                        return Err(Error::KeyGen(
                            "secp256k1 seed material must not be all zero".into(),
                        ));
                    }
                    let mut rng = rng_from_seed(seed);
                    PrivateKey::random(&mut rng)
                }
                KeyGenOption::FromPrivateKey(ref s) => s.clone(),
            };
            let public_key = signing_key.public_key();
            Ok((public_key, signing_key))
        }
        #[cfg(feature = "rand")]
        fn random_private_key() -> Result<PrivateKey, Error> {
            Self::random_private_key_from_rng(&mut OsRng)
        }
        #[cfg(feature = "rand")]
        pub(super) fn random_private_key_from_rng<R>(rng: &mut R) -> Result<PrivateKey, Error>
        where
            R: TryCryptoRng,
        {
            const RANDOM_KEYGEN_ATTEMPTS: usize = 16;
            for _ in 0..RANDOM_KEYGEN_ATTEMPTS {
                let mut bytes = Zeroizing::new([0u8; 32]);
                rng.try_fill_bytes(bytes.as_mut())
                    .map_err(|err| Error::KeyGen(format!("secp256k1 OS RNG failed: {err}")))?;
                if bytes.iter().all(|&byte| byte == 0) {
                    return Err(Error::KeyGen(
                        "secp256k1 OS RNG returned all-zero scalar material".to_owned(),
                    ));
                }
                if let Ok(secret) = PrivateKey::from_slice(bytes.as_ref()) {
                    return Ok(secret);
                }
            }
            Err(Error::KeyGen(
                "secp256k1 OS RNG did not produce a valid scalar".to_owned(),
            ))
        }
        pub fn sign(message: &[u8], sk: &PrivateKey) -> Vec<u8> {
            Self::try_sign(message, sk)
                .expect("secp256k1 signing should succeed for a valid private key and message")
        }
        pub fn try_sign(message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, Error> {
            let signing_key = SigningKey::from(sk);
            let digest = sha2::Sha256::digest(message);
            let signature: Signature = signing_key
                .sign_prehash(&digest)
                .map_err(|err| Error::Signing(format!("{err:?}")))?;
            let signature = signature.normalize_s().unwrap_or(signature);
            Ok(signature.to_bytes().to_vec())
        }
        pub fn sign_prehash_recoverable(
            prehash: &[u8; 32],
            sk: &PrivateKey,
        ) -> Result<[u8; 65], Error> {
            let signing_key = SigningKey::from(sk);
            let (mut signature, mut recovery_id) = signing_key
                .sign_prehash_recoverable(prehash)
                .map_err(|err| Error::Signing(format!("{err:?}")))?;
            if let Some(normalized) = signature.normalize_s() {
                signature = normalized;
                recovery_id =
                    RecoveryId::from_byte(recovery_id.to_byte() ^ 1).ok_or_else(|| {
                        Error::Signing(
                            "invalid secp256k1 recovery id after low-S normalization".into(),
                        )
                    })?;
            }
            let mut out = [0u8; 65];
            let signature_bytes = signature.to_bytes();
            out[..64].copy_from_slice(&signature_bytes);
            out[64] = recovery_id.to_byte().saturating_add(27);
            Ok(out)
        }
        pub fn recover_public_key_from_prehash(
            prehash: &[u8; 32],
            signature: &[u8; 65],
        ) -> Result<PublicKey, Error> {
            if signature_payload_is_all_zero(&signature[..64]) {
                return Err(Error::BadSignature);
            }
            if signature_payload_has_zero_scalar(&signature[..64]) {
                return Err(Error::BadSignature);
            }
            let recovery_id =
                RecoveryId::from_byte(signature[64].checked_sub(27).ok_or(Error::BadSignature)?)
                    .ok_or(Error::BadSignature)?;
            let signature =
                Signature::from_slice(&signature[..64]).map_err(|_| Error::BadSignature)?;
            if signature.normalize_s().is_some() {
                return Err(Error::BadSignature);
            }
            VerifyingKey::recover_from_prehash(prehash, &signature, recovery_id)
                .map(Into::into)
                .map_err(|_| Error::BadSignature)
        }
        pub fn evm_address(pk: &PublicKey) -> [u8; 20] {
            let encoded = pk.to_encoded_point(false);
            let mut keccak = Keccak256::new();
            keccak.update(&encoded.as_bytes()[1..]);
            let hash = keccak.finalize();
            let mut out = [0u8; 20];
            out.copy_from_slice(&hash[12..]);
            out
        }
        pub fn verify(message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<(), Error> {
            if signature_payload_is_all_zero(signature) {
                return Err(Error::BadSignature);
            }
            if signature_payload_has_zero_scalar(signature) {
                return Err(Error::BadSignature);
            }
            let signature = Signature::from_slice(signature).map_err(|_| Error::BadSignature)?;
            if signature.normalize_s().is_some() {
                return Err(Error::BadSignature);
            }
            let verifying_key = VerifyingKey::from(pk);
            let digest = sha2::Sha256::digest(message);
            verifying_key
                .verify_prehash(&digest, &signature)
                .map_err(|_| Error::BadSignature)
        }
        pub fn parse_private_key(payload: &[u8]) -> Result<PrivateKey, ParseError> {
            if !payload.is_empty() && payload.iter().all(|&byte| byte == 0) {
                return Err(ParseError::Invalid(
                    "secp256k1 private key material must not be all zero".to_string(),
                ));
            }
            let bytes = Zeroizing::new(payload.to_vec());
            PrivateKey::from_slice(bytes.as_ref())
                .map_err(|err| ParseError::Invalid(err.to_string()))
        }
    }
    fn signature_payload_is_all_zero(signature: &[u8]) -> bool {
        !signature.is_empty() && signature.iter().all(|&byte| byte == 0)
    }
    fn signature_payload_has_zero_scalar(signature: &[u8]) -> bool {
        signature.len() == 64
            && (signature[..32].iter().all(|&byte| byte == 0)
                || signature[32..].iter().all(|&byte| byte == 0))
    }
}
impl From<elliptic_curve::Error> for Error {
    fn from(error: elliptic_curve::Error) -> Error {
        // RustCrypto doesn't expose any kind of error information =(
        Error::Other(format!("{error}"))
    }
}
#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "crypto-parity-tests")]
    use amcl::secp256k1::ecp;
    use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    #[cfg(feature = "crypto-parity-tests")]
    use openssl::{
        bn::{BigNum, BigNumContext},
        ec::{EcGroup, EcKey, EcPoint},
        ecdsa::EcdsaSig,
        nid::Nid,
    };
    #[cfg(feature = "rand")]
    use rand_core::{TryCryptoRng, TryRngCore};
    use sha2::Digest;
    #[cfg(feature = "crypto-parity-tests")]
    const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
    #[cfg(feature = "crypto-parity-tests")]
    const SIGNATURE_1: &str = "0aab347be3530a3fd7d91c354956561101e6f273b8a1ea3d414f82fbd5939db34b99c54c16c45bf4cde8193b58d718e7efa8c055e7add7d9c9cbe8935e849200";
    const PRIVATE_KEY: &str = "e4f21b38e005d4f895a29e84948d7cc83eac79041aeb644ee4fab8d9da42f713";
    const PUBLIC_KEY: &str = "0242c1e1f775237a26da4fd51b8d75ee2709711f6e90303e511169a324ef0789c0";
    fn private_key() -> PrivateKey {
        let payload = hex::decode(PRIVATE_KEY).unwrap();
        EcdsaSecp256k1Sha256::parse_private_key(&payload).unwrap()
    }
    fn public_key() -> PublicKey {
        let payload = hex::decode(PUBLIC_KEY).unwrap();
        EcdsaSecp256k1Sha256::parse_public_key(&payload).unwrap()
    }
    #[cfg(feature = "rand")]
    struct FixedTryRng {
        byte: u8,
    }
    #[cfg(feature = "rand")]
    impl TryRngCore for FixedTryRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from_le_bytes([self.byte; 4]))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from_le_bytes([self.byte; 8]))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            dest.fill(self.byte);
            Ok(())
        }
    }
    #[cfg(feature = "rand")]
    impl TryCryptoRng for FixedTryRng {}
    #[test]
    fn parse_private_key_accepts_valid_scalar_and_signs() {
        let payload = hex::decode(PRIVATE_KEY).unwrap();
        let secret = EcdsaSecp256k1Sha256::parse_private_key(&payload).unwrap();
        let (public, private) = EcdsaSecp256k1Sha256::keypair(KeyGenOption::FromPrivateKey(secret));
        let message = b"secp256k1 parsed private key";
        let signature = EcdsaSecp256k1Sha256::sign(message, &private);
        EcdsaSecp256k1Sha256::verify(message, &signature, &public).expect("signature verifies");
    }
    #[test]
    fn parse_private_key_rejects_all_zero_scalar_material() {
        let err = EcdsaSecp256k1Sha256::parse_private_key(&[0u8; 32])
            .expect_err("all-zero secp256k1 private key material must fail");
        assert!(
            err.to_string().contains("all zero"),
            "unexpected all-zero private-key error: {err:?}"
        );
    }
    #[test]
    fn secp256k1_try_keypair_rejects_all_zero_seed_material() {
        for len in [1, 31, 32, 33] {
            let err = EcdsaSecp256k1Sha256::try_keypair(KeyGenOption::UseSeed(vec![0u8; len]))
                .expect_err("all-zero seed material must fail");
            assert!(
                matches!(err, Error::KeyGen(ref message) if message.contains("all zero")),
                "unexpected all-zero seed error for length {len}: {err:?}"
            );
        }
    }
    #[test]
    fn secp256k1_try_keypair_accepts_empty_seed_material() {
        EcdsaSecp256k1Sha256::try_keypair(KeyGenOption::UseSeed(Vec::new()))
            .expect("empty seed material remains supported");
    }
    #[cfg(feature = "rand")]
    #[test]
    fn secp256k1_random_private_key_rejects_all_zero_rng_material() {
        let mut rng = FixedTryRng { byte: 0 };
        assert!(matches!(
            ecdsa_secp256k1::EcdsaSecp256k1Impl::random_private_key_from_rng(&mut rng),
            Err(Error::KeyGen(message)) if message.contains("all-zero scalar material")
        ));
    }
    #[cfg(feature = "rand")]
    #[test]
    fn secp256k1_random_private_key_accepts_nonzero_rng_material() {
        let mut rng = FixedTryRng { byte: 0x42 };
        let secret = ecdsa_secp256k1::EcdsaSecp256k1Impl::random_private_key_from_rng(&mut rng)
            .expect("nonzero secp256k1 random scalar material must produce a key");
        assert_eq!(secret.to_bytes().as_slice(), &[0x42; 32]);
    }
    #[cfg(feature = "crypto-parity-tests")]
    fn public_key_uncompressed(pk: &PublicKey) -> Vec<u8> {
        const PUBLIC_UNCOMPRESSED_KEY_SIZE: usize = 65;
        let mut uncompressed = [0u8; PUBLIC_UNCOMPRESSED_KEY_SIZE];
        ecp::ECP::frombytes(&pk.to_sec1_bytes()[..]).tobytes(&mut uncompressed, false);
        uncompressed.to_vec()
    }
    #[test]
    fn parse_public_key_rejects_non_canonical_encoding() {
        let pk = public_key();
        let canonical = pk.to_sec1_bytes();
        let compressed = pk.to_encoded_point(true);
        let uncompressed = pk.to_encoded_point(false);
        let non_canonical = if canonical.as_ref() == compressed.as_bytes() {
            uncompressed.as_bytes()
        } else {
            compressed.as_bytes()
        };
        let err = EcdsaSecp256k1Sha256::parse_public_key(non_canonical).unwrap_err();
        assert!(
            err.to_string().contains("non-canonical"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn typed_decode_rejections_preserve_backend_diagnostics_and_precedence() {
        let key = public_key();
        let uncompressed = key.to_encoded_point(false);
        for payload in [
            &[][..],
            &[0; 1][..],
            &[0; 33][..],
            &[0xff; 33][..],
            uncompressed.as_bytes(),
        ] {
            let rejection =
                EcdsaSecp256k1Sha256::validate_public_key_for_decode(payload).unwrap_err();
            assert_eq!(
                rejection.into_parse_error(),
                EcdsaSecp256k1Sha256::parse_public_key(payload).unwrap_err()
            );
        }
        assert!(matches!(
            EcdsaSecp256k1Sha256::validate_public_key_for_decode(&[0]),
            Err(public_key::KeyRejection::AllZero)
        ));
        assert!(matches!(
            EcdsaSecp256k1Sha256::validate_public_key_for_decode(&[]),
            Err(public_key::KeyRejection::Encoding(_))
        ));
        assert!(matches!(
            EcdsaSecp256k1Sha256::validate_public_key_for_decode(uncompressed.as_bytes()),
            Err(public_key::KeyRejection::NonCanonical)
        ));
    }
    #[test]
    fn decode_validator_matches_public_parser_acceptance() {
        let key = public_key();
        let canonical = key.to_encoded_point(true);
        let uncompressed = key.to_encoded_point(false);
        let all_zero = [0_u8; 33];
        for payload in [
            canonical.as_bytes(),
            uncompressed.as_bytes(),
            &[][..],
            all_zero.as_slice(),
        ] {
            assert_eq!(
                EcdsaSecp256k1Sha256::validate_public_key_for_decode(payload).is_ok(),
                EcdsaSecp256k1Sha256::parse_public_key(payload).is_ok(),
                "decode-only and public parsing diverged for {payload:02x?}"
            );
        }
    }

    #[test]
    fn parse_public_key_rejects_all_zero_sec1_material() {
        for len in [33, 65] {
            let payload = vec![0u8; len];
            let err = EcdsaSecp256k1Sha256::parse_public_key(&payload)
                .expect_err("all-zero secp256k1 public key material must fail");
            assert!(
                err.to_string().contains("all zero"),
                "unexpected all-zero public-key error for {len} bytes: {err:?}"
            );
        }
    }
    #[test]
    fn try_sign_matches_compatibility_sign_and_verifies() {
        let secret = private_key();
        let (public, private) = EcdsaSecp256k1Sha256::keypair(KeyGenOption::FromPrivateKey(secret));
        let message = b"secp256k1 checked message signing";
        let checked =
            EcdsaSecp256k1Sha256::try_sign(message, &private).expect("checked secp256k1 signing");
        assert_eq!(checked, EcdsaSecp256k1Sha256::sign(message, &private));
        assert_eq!(checked.len(), 64);
        EcdsaSecp256k1Sha256::verify(message, &checked, &public).expect("signature verifies");
    }
    #[test]
    fn verify_rejects_malformed_signature_as_bad_signature() {
        let public = public_key();
        let err = EcdsaSecp256k1Sha256::verify(b"malformed secp256k1", &[0x01, 0x02], &public);
        assert!(matches!(err, Err(Error::BadSignature)));
    }
    #[test]
    fn verify_rejects_all_zero_signature_before_backend() {
        let public = public_key();
        let signature = [0u8; 64];
        let err = EcdsaSecp256k1Sha256::verify(b"inert secp256k1", &signature, &public);
        assert!(matches!(err, Err(Error::BadSignature)));
    }
    #[test]
    fn verify_rejects_zero_scalar_halves_before_backend() {
        let secret = private_key();
        let public = public_key();
        let message = b"secp256k1 zero scalar half";
        let signature = EcdsaSecp256k1Sha256::sign(message, &secret);
        for (range, label) in [(0..32, "r"), (32..64, "s")] {
            let mut tampered = signature.clone();
            tampered[range].fill(0);
            let err = EcdsaSecp256k1Sha256::verify(message, &tampered, &public);
            assert!(
                matches!(err, Err(Error::BadSignature)),
                "zero {label} scalar must fail as bad signature"
            );
        }
    }
    #[cfg(feature = "crypto-parity-tests")]
    #[test]
    fn secp256k1_compatibility() {
        let secret = private_key();
        let (p, s) = EcdsaSecp256k1Sha256::keypair(KeyGenOption::FromPrivateKey(secret));
        let _sk = secp256k1::SecretKey::from_byte_array(s.to_bytes().into()).unwrap();
        let _pk = secp256k1::PublicKey::from_slice(&p.to_sec1_bytes()).unwrap();
        let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let _openssl_point =
            EcPoint::from_bytes(&openssl_group, &public_key_uncompressed(&p)[..], &mut ctx)
                .unwrap();
    }
    #[cfg(feature = "crypto-parity-tests")]
    #[test]
    fn secp256k1_verify() {
        let p = public_key();
        EcdsaSecp256k1Sha256::verify(MESSAGE_1, hex::decode(SIGNATURE_1).unwrap().as_slice(), &p)
            .unwrap();
        let context = secp256k1::Secp256k1::new();
        let pk =
            secp256k1::PublicKey::from_slice(hex::decode(PUBLIC_KEY).unwrap().as_slice()).unwrap();
        let hash_bytes: [u8; 32] = sha2::Sha256::digest(MESSAGE_1).into();
        let msg = secp256k1::Message::from_digest(hash_bytes);
        // Check if signatures produced here can be verified by secp256k1
        let signature =
            secp256k1::ecdsa::Signature::from_compact(&hex::decode(SIGNATURE_1).unwrap()[..])
                .unwrap();
        context.verify_ecdsa(msg, &signature, &pk).unwrap();
        let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let openssl_point =
            EcPoint::from_bytes(&openssl_group, &pk.serialize_uncompressed(), &mut ctx).unwrap();
        let openssl_pkey = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();
        // Check if the signatures produced here can be verified by openssl
        let (r, s) = SIGNATURE_1.split_at(SIGNATURE_1.len() / 2);
        let openssl_r = BigNum::from_hex_str(r).unwrap();
        let openssl_s = BigNum::from_hex_str(s).unwrap();
        let openssl_sig = EcdsaSig::from_private_components(openssl_r, openssl_s).unwrap();
        let openssl_result = openssl_sig.verify(hash_bytes.as_ref(), &openssl_pkey);
        assert!(openssl_result.unwrap());
    }
    #[cfg(feature = "crypto-parity-tests")]
    #[test]
    fn secp256k1_sign() {
        let secret = private_key();
        let (pk, sk) = EcdsaSecp256k1Sha256::keypair(KeyGenOption::FromPrivateKey(secret));
        let sig = EcdsaSecp256k1Sha256::sign(MESSAGE_1, &sk);
        EcdsaSecp256k1Sha256::verify(MESSAGE_1, &sig, &pk).unwrap();
        assert_eq!(sig.len(), 64);
        // Check if secp256k1 signs the message and this module still can verify it
        // And that private keys can sign with other libraries
        let context = secp256k1::Secp256k1::new();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&hex::decode(PRIVATE_KEY).unwrap());
        let sk = secp256k1::SecretKey::from_byte_array(key_bytes).unwrap();
        let hash_bytes: [u8; 32] = sha2::Sha256::digest(MESSAGE_1).into();
        let msg = secp256k1::Message::from_digest(hash_bytes);
        let sig_1 = context.sign_ecdsa(msg, &sk).serialize_compact();
        EcdsaSecp256k1Sha256::verify(MESSAGE_1, &sig_1, &pk).unwrap();
        let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let openssl_point =
            EcPoint::from_bytes(&openssl_group, &public_key_uncompressed(&pk), &mut ctx).unwrap();
        let openssl_public_key = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();
        let openssl_secret_key = EcKey::from_private_components(
            &openssl_group,
            &BigNum::from_hex_str(PRIVATE_KEY).unwrap(),
            &openssl_point,
        )
        .unwrap();
        let openssl_sig = EcdsaSig::sign(hash_bytes.as_ref(), &openssl_secret_key).unwrap();
        let openssl_result = openssl_sig.verify(hash_bytes.as_ref(), &openssl_public_key);
        assert!(openssl_result.unwrap());
        let openssl_sig = {
            use std::ops::{Shr, Sub};
            // ensure the S value is "low" (see BIP-0062) https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#user-content-Low_S_values_in_signatures
            // this is required for k256 to successfully verify the signature, as it will fail verification of any signature with a High S value
            // Based on https://github.com/bitcoin/bitcoin/blob/v0.9.3/src/key.cpp#L202-L227
            // this is only required for interoperability with OpenSSL
            // if we are only using signatures from iroha_crypto, all of this dance is not necessary
            let mut s = openssl_sig.s().to_owned().unwrap();
            let mut order = BigNum::new().unwrap();
            openssl_group.order(&mut order, &mut ctx).unwrap();
            let half_order = order.shr(1);
            // if the S is "high" (s > half_order), convert it to "low" form (order - s)
            if s.cmp(&half_order) == std::cmp::Ordering::Greater {
                s = order.sub(&s);
            }
            let r = openssl_sig.r();
            // serialize the key
            let mut res = Vec::new();
            // padding because EcdsaSecp256k1Sha256::verify requires a slice of length 64
            res.extend(r.to_vec_padded(32).expect("r fits into 32 bytes"));
            res.extend(s.to_vec_padded(32).expect("s fits into 32 bytes"));
            res
        };
        EcdsaSecp256k1Sha256::verify(MESSAGE_1, openssl_sig.as_slice(), &pk).unwrap();
        let (p, s) = EcdsaSecp256k1Sha256::keypair(KeyGenOption::Random);
        let signed = EcdsaSecp256k1Sha256::sign(MESSAGE_1, &s);
        EcdsaSecp256k1Sha256::verify(MESSAGE_1, &signed, &p).unwrap();
    }
    #[test]
    fn secp256k1_rejects_high_s_signatures() {
        let secret = private_key();
        let (pk, sk) = EcdsaSecp256k1Sha256::keypair(KeyGenOption::FromPrivateKey(secret));
        let message = b"secp256k1 high-s test";
        let sig = EcdsaSecp256k1Sha256::sign(message, &sk);
        let signature = k256::ecdsa::Signature::from_slice(&sig).expect("signature parse");
        assert!(
            signature.normalize_s().is_none(),
            "signatures must be low-S"
        );
        let high_sig = if signature.normalize_s().is_some() {
            signature
        } else {
            let (r, s) = signature.split_scalars();
            k256::ecdsa::Signature::from_scalars(r, -s).expect("high-s signature")
        };
        assert!(high_sig.normalize_s().is_some());
        let digest = sha2::Sha256::digest(message);
        let verifying_key = k256::ecdsa::VerifyingKey::from(&pk);
        let normalized = high_sig
            .normalize_s()
            .expect("high-S signature must normalize to low-S");
        verifying_key
            .verify_prehash(&digest, &normalized)
            .expect("normalized low-S signature should verify");
        let err = EcdsaSecp256k1Sha256::verify(message, high_sig.to_bytes().as_ref(), &pk);
        assert!(matches!(err, Err(Error::BadSignature)));
    }
    #[test]
    fn recoverable_prehash_roundtrip_preserves_key_and_evm_address() {
        let secret = private_key();
        let public = public_key();
        let prehash = sha2::Sha256::digest(b"iroha:evm:transaction-recovery");
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&prehash);
        let signature = EcdsaSecp256k1Sha256::sign_prehash_recoverable(&digest, &secret)
            .expect("recoverable signature");
        let compact =
            k256::ecdsa::Signature::from_slice(&signature[..64]).expect("signature parse");
        assert!(
            compact.normalize_s().is_none(),
            "recoverable signatures produced by iroha_crypto must be low-S"
        );
        let recovered = EcdsaSecp256k1Sha256::recover_public_key_from_prehash(&digest, &signature)
            .expect("recoverable public key");
        assert_eq!(recovered, public);
        assert_eq!(
            EcdsaSecp256k1Sha256::evm_address(&recovered),
            EcdsaSecp256k1Sha256::evm_address(&public)
        );
        assert!(matches!(signature[64], 27 | 28));
    }
    #[test]
    fn recoverable_prehash_rejects_all_zero_signature_payload_before_backend() {
        let prehash = sha2::Sha256::digest(b"iroha:sccp:evm-all-zero-recovery");
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&prehash);
        let mut signature = [0u8; 65];
        signature[64] = 27;
        let err = EcdsaSecp256k1Sha256::recover_public_key_from_prehash(&digest, &signature);
        assert!(matches!(err, Err(Error::BadSignature)));
    }
    #[test]
    fn recoverable_prehash_rejects_zero_scalar_halves_before_backend() {
        let secret = private_key();
        let prehash = sha2::Sha256::digest(b"iroha:sccp:evm-zero-scalar-recovery");
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&prehash);
        let signature = EcdsaSecp256k1Sha256::sign_prehash_recoverable(&digest, &secret)
            .expect("recoverable signature");
        for (range, label) in [(0..32, "r"), (32..64, "s")] {
            let mut tampered = signature;
            tampered[range].fill(0);
            let err = EcdsaSecp256k1Sha256::recover_public_key_from_prehash(&digest, &tampered);
            assert!(
                matches!(err, Err(Error::BadSignature)),
                "zero {label} scalar must fail as bad recoverable signature"
            );
        }
    }
    #[test]
    fn recoverable_prehash_rejects_high_s_malleable_signature() {
        let secret = private_key();
        let prehash = sha2::Sha256::digest(b"iroha:sccp:evm-high-s-recovery");
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&prehash);
        let mut signature = EcdsaSecp256k1Sha256::sign_prehash_recoverable(&digest, &secret)
            .expect("recoverable signature");
        let low = k256::ecdsa::Signature::from_slice(&signature[..64]).expect("signature parse");
        assert!(
            low.normalize_s().is_none(),
            "test vector must start from canonical low-S form"
        );
        let (r, s) = low.split_scalars();
        let high = k256::ecdsa::Signature::from_scalars(r, -s).expect("high-S signature");
        assert!(high.normalize_s().is_some());
        signature[..64].copy_from_slice(high.to_bytes().as_ref());
        signature[64] = match signature[64] {
            27 => 28,
            28 => 27,
            recovery => panic!("unexpected recovery id {recovery}"),
        };
        let err = EcdsaSecp256k1Sha256::recover_public_key_from_prehash(&digest, &signature);
        assert!(matches!(err, Err(Error::BadSignature)));
    }
}
