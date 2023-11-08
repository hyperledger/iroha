use std::convert::TryFrom;

use arrayref::array_ref;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey as PK};
pub use ed25519_dalek::{
    EXPANDED_SECRET_KEY_LENGTH as PRIVATE_KEY_SIZE, PUBLIC_KEY_LENGTH as PUBLIC_KEY_SIZE,
    SIGNATURE_LENGTH as SIGNATURE_SIZE,
};
use iroha_primitives::const_vec::ConstVec;
use rand::{rngs::OsRng, SeedableRng};
use rand_chacha::ChaChaRng;
use sha2::Digest;
use zeroize::Zeroize;

const ALGORITHM: Algorithm = Algorithm::Ed25519;

use crate::{Algorithm, Error, KeyGenOption, PrivateKey, PublicKey};

fn parse_private_key(sk: &PrivateKey) -> Result<SigningKey, Error> {
    assert_eq!(sk.digest_function, ALGORITHM);
    SigningKey::from_keypair_bytes(
        &<[u8; 64]>::try_from(&sk.payload[..]).map_err(|e| Error::Parse(e.to_string()))?,
    )
    .map_err(|e| Error::Parse(e.to_string()))
}

fn parse_public_key(pk: &PublicKey) -> Result<PK, Error> {
    assert_eq!(pk.digest_function, ALGORITHM);
    PK::try_from(&pk.payload[..]).map_err(|e| Error::Parse(e.to_string()))
}

#[derive(Debug, Clone, Copy)]
pub struct Ed25519Sha512;

impl Ed25519Sha512 {
    pub fn new() -> Self {
        Self
    }
    pub fn keypair(&self, option: Option<KeyGenOption>) -> Result<(PublicKey, PrivateKey), Error> {
        let kp = match option {
            Some(mut o) => match o {
                KeyGenOption::UseSeed(ref mut s) => {
                    let hash = sha2::Sha256::digest(s.as_slice());
                    s.zeroize();
                    let mut rng = ChaChaRng::from_seed(*array_ref!(hash.as_slice(), 0, 32));
                    SigningKey::generate(&mut rng)
                }
                KeyGenOption::FromPrivateKey(ref s) => parse_private_key(s)?,
            },
            None => {
                let mut rng = OsRng::default();
                SigningKey::generate(&mut rng)
            }
        };
        Ok((
            PublicKey {
                digest_function: ALGORITHM,
                payload: ConstVec::new(kp.verifying_key().to_bytes().to_vec()),
            },
            PrivateKey {
                digest_function: ALGORITHM,
                payload: ConstVec::new(kp.to_keypair_bytes().to_vec()),
            },
        ))
    }
    pub fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, Error> {
        let kp = parse_private_key(sk)?;
        Ok(kp.sign(message).to_bytes().to_vec())
    }
    pub fn verify(&self, message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, Error> {
        let p = parse_public_key(pk)?;
        let s = Signature::try_from(signature).map_err(|e| Error::Parse(e.to_string()))?;
        p.verify(message, &s)
            .map_err(|e| Error::Signing(e.to_string()))?;
        Ok(true)
    }
}

#[cfg(test)]
// unsafe code is needed to check consistency with libsodium, which is a C library
#[allow(unsafe_code)]
mod test {
    use libsodium_sys as ffi;

    use self::Ed25519Sha512;
    use super::*;
    use crate::{KeyGenOption, PrivateKey, PublicKey};

    const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
    const SIGNATURE_1: &str = "451b5b8e8725321541954997781de51f4142e4a56bab68d24f6a6b92615de5eefb74134138315859a32c7cf5fe5a488bc545e2e08e5eedfd1fb10188d532d808";
    const PRIVATE_KEY: &str = "1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";
    const PUBLIC_KEY: &str = "27c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";

    #[test]
    #[ignore]
    fn create_new_keys() {
        let scheme = Ed25519Sha512::new();
        let (p, s) = scheme.keypair(None).unwrap();

        println!("{:?}", s);
        println!("{:?}", p);
    }

    #[test]
    fn ed25519_load_keys() {
        let scheme = Ed25519Sha512::new();
        let secret = PrivateKey::from_hex(Algorithm::Ed25519, PRIVATE_KEY).unwrap();
        let sres = scheme.keypair(Some(KeyGenOption::FromPrivateKey(secret)));
        assert!(sres.is_ok());
        let (p1, s1) = sres.unwrap();

        assert_eq!(
            s1,
            PrivateKey::from_hex(Algorithm::Ed25519, PRIVATE_KEY).unwrap()
        );
        assert_eq!(
            p1,
            PublicKey::from_hex(Algorithm::Ed25519, PUBLIC_KEY).unwrap()
        );
    }

    #[test]
    fn ed25519_verify() {
        let scheme = Ed25519Sha512::new();
        let secret = PrivateKey::from_hex(Algorithm::Ed25519, PRIVATE_KEY).unwrap();
        let (p, _) = scheme
            .keypair(Some(KeyGenOption::FromPrivateKey(secret)))
            .unwrap();

        let result = scheme.verify(&MESSAGE_1, hex::decode(SIGNATURE_1).unwrap().as_slice(), &p);
        assert!(result.is_ok());
        assert!(result.unwrap());

        //Check if signatures produced here can be verified by libsodium
        let signature = hex::decode(SIGNATURE_1).unwrap();
        let res = unsafe {
            ffi::crypto_sign_ed25519_verify_detached(
                signature.as_slice().as_ptr(),
                MESSAGE_1.as_ptr(),
                MESSAGE_1.len() as u64,
                p.payload().as_ptr(),
            )
        };
        assert_eq!(res, 0);
    }

    #[test]
    fn ed25519_sign() {
        let scheme = Ed25519Sha512::new();
        let secret = PrivateKey::from_hex(Algorithm::Ed25519, PRIVATE_KEY).unwrap();
        let (p, s) = scheme
            .keypair(Some(KeyGenOption::FromPrivateKey(secret)))
            .unwrap();

        match scheme.sign(&MESSAGE_1, &s) {
            Ok(sig) => {
                let result = scheme.verify(&MESSAGE_1, &sig, &p);
                assert!(result.is_ok());
                assert!(result.unwrap());

                assert_eq!(sig.len(), SIGNATURE_SIZE);
                assert_eq!(hex::encode(sig.as_slice()), SIGNATURE_1);

                //Check if libsodium signs the message and this module still can verify it
                //And that private keys can sign with other libraries
                let mut signature = [0u8; ffi::crypto_sign_ed25519_BYTES as usize];
                unsafe {
                    ffi::crypto_sign_ed25519_detached(
                        signature.as_mut_ptr(),
                        std::ptr::null_mut(),
                        MESSAGE_1.as_ptr(),
                        MESSAGE_1.len() as u64,
                        s.payload().as_ptr(),
                    )
                };
                let result = scheme.verify(&MESSAGE_1, &signature, &p);
                assert!(result.is_ok());
                assert!(result.unwrap());
            }
            Err(e) => assert!(false, "{}", e),
        }
    }
}
