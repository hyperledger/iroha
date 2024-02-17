use core::{borrow::Borrow as _, convert::TryFrom};

use ed25519_dalek::Signature;
#[cfg(feature = "rand")]
use rand::rngs::OsRng;
use signature::{Signer as _, Verifier as _};

use crate::{Error, KeyGenOption, ParseError};

pub type PublicKey = ed25519_dalek::VerifyingKey;
pub type PrivateKey = ed25519_dalek::SigningKey;

#[cfg(not(feature = "std"))]
use alloc::{string::ToString as _, vec::Vec};

#[derive(Debug, Clone, Copy)]
pub struct Ed25519Sha512;

impl Ed25519Sha512 {
    pub fn keypair(option: KeyGenOption) -> (PublicKey, PrivateKey) {
        let signing_key = match option {
            #[cfg(feature = "rand")]
            KeyGenOption::Random => PrivateKey::generate(&mut OsRng),
            KeyGenOption::UseSeed(seed) => PrivateKey::generate(&mut super::rng_from_seed(seed)),
            KeyGenOption::FromPrivateKey(ref s) => {
                let crate::PrivateKeyInner::Ed25519(s) = s.0.borrow() else {
                    panic!("Wrong private key type, expected `Ed25519`, got {s:?}")
                };
                PrivateKey::clone(s)
            }
        };
        (signing_key.verifying_key(), signing_key)
    }

    pub fn parse_public_key(payload: &[u8]) -> Result<PublicKey, ParseError> {
        PublicKey::from_bytes(arrayref::array_ref!(payload, 0, 32))
            .map_err(|err| ParseError(err.to_string()))
    }

    pub fn parse_private_key(payload: &[u8]) -> Result<PrivateKey, ParseError> {
        <[u8; 64]>::try_from(payload)
            .map_err(|err| err.to_string())
            .and_then(|payload| {
                PrivateKey::from_keypair_bytes(&payload).map_err(|err| err.to_string())
            })
            .map_err(ParseError)
    }

    pub fn sign(message: &[u8], sk: &PrivateKey) -> Vec<u8> {
        sk.sign(message).to_bytes().to_vec()
    }

    pub fn verify(message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<(), Error> {
        let s = Signature::try_from(signature).map_err(|e| ParseError(e.to_string()))?;
        pk.verify(message, &s).map_err(|_| Error::BadSignature)
    }
}

#[cfg(test)]
// unsafe code is needed to check consistency with libsodium, which is a C library
#[allow(unsafe_code)]
mod test {
    use libsodium_sys as ffi;

    use self::Ed25519Sha512;
    use super::*;
    use crate::{Algorithm, KeyGenOption, PrivateKey, PublicKey};

    const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
    const SIGNATURE_1: &str = "451b5b8e8725321541954997781de51f4142e4a56bab68d24f6a6b92615de5eefb74134138315859a32c7cf5fe5a488bc545e2e08e5eedfd1fb10188d532d808";
    const PRIVATE_KEY: &str = "1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";
    const PUBLIC_KEY: &str = "27c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";

    #[test]
    #[ignore]
    fn create_new_keys() {
        let (p, s) = Ed25519Sha512::keypair(KeyGenOption::Random);

        println!("{s:?}");
        println!("{p:?}");
    }

    #[test]
    fn ed25519_load_keys() {
        let secret = PrivateKey::from_hex(Algorithm::Ed25519, PRIVATE_KEY).unwrap();
        let (p1, s1) = Ed25519Sha512::keypair(KeyGenOption::FromPrivateKey(secret));

        assert_eq!(
            PrivateKey(Box::new(crate::PrivateKeyInner::Ed25519(s1))),
            PrivateKey::from_hex(Algorithm::Ed25519, PRIVATE_KEY).unwrap()
        );
        assert_eq!(
            PublicKey(Box::new(crate::PublicKeyInner::Ed25519(p1))),
            PublicKey::from_hex(Algorithm::Ed25519, PUBLIC_KEY).unwrap()
        );
    }

    #[test]
    fn ed25519_verify() {
        let secret = PrivateKey::from_hex(Algorithm::Ed25519, PRIVATE_KEY).unwrap();
        let (p, _) = Ed25519Sha512::keypair(KeyGenOption::FromPrivateKey(secret));

        Ed25519Sha512::verify(MESSAGE_1, hex::decode(SIGNATURE_1).unwrap().as_slice(), &p).unwrap();

        // Check if signatures produced here can be verified by libsodium
        let signature = hex::decode(SIGNATURE_1).unwrap();
        let p_bytes = p.to_bytes();
        let res = unsafe {
            ffi::crypto_sign_ed25519_verify_detached(
                signature.as_slice().as_ptr(),
                MESSAGE_1.as_ptr(),
                MESSAGE_1.len() as u64,
                p_bytes.as_ptr(),
            )
        };
        assert_eq!(res, 0);
    }

    #[test]
    fn ed25519_sign() {
        let secret = PrivateKey::from_hex(Algorithm::Ed25519, PRIVATE_KEY).unwrap();
        let (p, s) = Ed25519Sha512::keypair(KeyGenOption::FromPrivateKey(secret));

        let sig = Ed25519Sha512::sign(MESSAGE_1, &s);
        Ed25519Sha512::verify(MESSAGE_1, &sig, &p).unwrap();

        assert_eq!(sig.len(), ed25519_dalek::SIGNATURE_LENGTH);
        assert_eq!(hex::encode(sig.as_slice()), SIGNATURE_1);

        //Check if libsodium signs the message and this module still can verify it
        //And that private keys can sign with other libraries
        let mut signature = [0u8; ffi::crypto_sign_ed25519_BYTES as usize];
        let s_bytes = s.to_keypair_bytes();
        unsafe {
            ffi::crypto_sign_ed25519_detached(
                signature.as_mut_ptr(),
                std::ptr::null_mut(),
                MESSAGE_1.as_ptr(),
                MESSAGE_1.len() as u64,
                s_bytes.as_ptr(),
            )
        };
        Ed25519Sha512::verify(MESSAGE_1, &signature, &p).unwrap();
    }
}
