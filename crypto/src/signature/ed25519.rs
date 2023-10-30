// TODO: clean up & remove
#![allow(missing_docs)]

use std::convert::TryFrom;

use arrayref::array_ref;
use ed25519_dalek::{Keypair, PublicKey as PK, Signature, Signer, Verifier};
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
                    Keypair::generate(&mut rng)
                }
                KeyGenOption::FromPrivateKey(ref s) => {
                    assert_eq!(s.digest_function, ALGORITHM);
                    Keypair::from_bytes(&s.payload[..]).map_err(|e| Error::KeyGen(e.to_string()))?
                }
            },
            None => {
                let mut rng = OsRng::default();
                Keypair::generate(&mut rng)
            }
        };
        Ok((
            PublicKey {
                digest_function: ALGORITHM,
                payload: ConstVec::new(kp.public.to_bytes().to_vec()),
            },
            PrivateKey {
                digest_function: ALGORITHM,
                payload: ConstVec::new(kp.to_bytes().to_vec()),
            },
        ))
    }
    pub fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, Error> {
        assert_eq!(sk.digest_function, ALGORITHM);
        let kp = Keypair::from_bytes(&sk.payload).map_err(|e| Error::KeyGen(e.to_string()))?;
        Ok(kp.sign(message).to_bytes().to_vec())
    }
    pub fn verify(&self, message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, Error> {
        assert_eq!(pk.digest_function, ALGORITHM);
        let p = PK::from_bytes(&pk.payload).map_err(|e| Error::Parse(e.to_string()))?;
        let s = Signature::try_from(signature).map_err(|e| Error::Parse(e.to_string()))?;
        p.verify(message, &s)
            .map_err(|e| Error::Signing(e.to_string()))?;
        Ok(true)
    }
    pub const fn signature_size() -> usize {
        SIGNATURE_SIZE
    }
    pub const fn private_key_size() -> usize {
        PRIVATE_KEY_SIZE
    }
    pub const fn public_key_size() -> usize {
        PUBLIC_KEY_SIZE
    }
}

// #[cfg(test)]
// mod test {
//     use keys::{KeyGenOption, PrivateKey, PublicKey};
//     use libsodium_sys_stable as ffi;
//
//     use self::Ed25519Sha512;
//     use super::{
//         super::{SignatureScheme, Signer},
//         *,
//     };
//
//     const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
//     const SIGNATURE_1: &str = "451b5b8e8725321541954997781de51f4142e4a56bab68d24f6a6b92615de5eefb74134138315859a32c7cf5fe5a488bc545e2e08e5eedfd1fb10188d532d808";
//     const PRIVATE_KEY: &str = "1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";
//     const PUBLIC_KEY: &str = "27c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";
//     const PRIVATE_KEY_X25519: &str =
//         "08e7286c232ec71b37918533ea0229bf0c75d3db4731df1c5c03c45bc909475f";
//     const PUBLIC_KEY_X25519: &str =
//         "9b4260484c889158c128796103dc8d8b883977f2ef7efb0facb12b6ca9b2ae3d";
//
//     #[test]
//     #[ignore]
//     fn create_new_keys() {
//         let scheme = Ed25519Sha512::new();
//         let (p, s) = scheme.keypair(None).unwrap();
//
//         println!("{:?}", s);
//         println!("{:?}", p);
//     }
//
//     #[test]
//     fn ed25519_load_keys() {
//         let scheme = Ed25519Sha512::new();
//         let secret = PrivateKey(hex::decode(PRIVATE_KEY).unwrap());
//         let sres = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret)));
//         assert!(sres.is_ok());
//         let (p1, s1) = sres.unwrap();
//         assert_eq!(s1, PrivateKey(hex::decode(PRIVATE_KEY).unwrap()));
//         assert_eq!(p1, PublicKey(hex::decode(PUBLIC_KEY).unwrap()));
//     }
//
//     #[test]
//     fn ed25519_verify() {
//         let scheme = Ed25519Sha512::new();
//         let secret = PrivateKey(hex::decode(PRIVATE_KEY).unwrap());
//         let (p, _) = scheme
//             .keypair(Some(KeyGenOption::FromSecretKey(secret)))
//             .unwrap();
//
//         let result = scheme.verify(&MESSAGE_1, hex::decode(SIGNATURE_1).unwrap().as_slice(), &p);
//         assert!(result.is_ok());
//         assert!(result.unwrap());
//
//         //Check if signatures produced here can be verified by libsodium
//         let signature = hex::decode(SIGNATURE_1).unwrap();
//         let res = unsafe {
//             ffi::crypto_sign_ed25519_verify_detached(
//                 signature.as_slice().as_ptr() as *const u8,
//                 MESSAGE_1.as_ptr() as *const u8,
//                 MESSAGE_1.len() as u64,
//                 p.as_ptr() as *const u8,
//             )
//         };
//         assert_eq!(res, 0);
//     }
//
//     #[test]
//     fn ed25519_sign() {
//         let scheme = Ed25519Sha512::new();
//         let secret = PrivateKey(hex::decode(PRIVATE_KEY).unwrap());
//         let (p, s) = scheme
//             .keypair(Some(KeyGenOption::FromSecretKey(secret)))
//             .unwrap();
//
//         match scheme.sign(&MESSAGE_1, &s) {
//             Ok(sig) => {
//                 let result = scheme.verify(&MESSAGE_1, &sig, &p);
//                 assert!(result.is_ok());
//                 assert!(result.unwrap());
//
//                 assert_eq!(sig.len(), SIGNATURE_SIZE);
//                 assert_eq!(hex::encode(sig.as_slice()), SIGNATURE_1);
//
//                 //Check if libsodium signs the message and this module still can verify it
//                 //And that private keys can sign with other libraries
//                 let mut signature = [0u8; ffi::crypto_sign_ed25519_BYTES as usize];
//                 unsafe {
//                     ffi::crypto_sign_ed25519_detached(
//                         signature.as_mut_ptr() as *mut u8,
//                         0u64 as *mut u64,
//                         MESSAGE_1.as_ptr() as *const u8,
//                         MESSAGE_1.len() as u64,
//                         s.as_ptr() as *const u8,
//                     )
//                 };
//                 let result = scheme.verify(&MESSAGE_1, &signature, &p);
//                 assert!(result.is_ok());
//                 assert!(result.unwrap());
//             }
//             Err(e) => assert!(false, "{}", e),
//         }
//         let signer = Signer::new(&scheme, &s);
//         match signer.sign(&MESSAGE_1) {
//             Ok(signed) => {
//                 let result = scheme.verify(&MESSAGE_1, &signed, &p);
//                 assert!(result.is_ok());
//                 assert!(result.unwrap());
//             }
//             Err(er) => assert!(false, "{}", er),
//         }
//     }
//
//     #[test]
//     fn ed25519_to_x25519_default() {
//         let scheme = Ed25519Sha512::new();
//         let (p, _) = scheme.keypair(None).unwrap();
//
//         let res = Ed25519Sha512::ver_key_to_key_exchange(&p);
//         assert!(res.is_ok());
//     }
//
//     #[test]
//     fn ed25519_to_x25519_verify() {
//         let sk = PrivateKey(hex::decode(PRIVATE_KEY).unwrap());
//         let pk = PublicKey(hex::decode(PUBLIC_KEY).unwrap());
//
//         let x_pk = Ed25519Sha512::ver_key_to_key_exchange(&pk).unwrap();
//         assert_eq!(hex::encode(&x_pk), PUBLIC_KEY_X25519);
//
//         let x_sk = Ed25519Sha512::sign_key_to_key_exchange(&sk).unwrap();
//         assert_eq!(hex::encode(&x_sk), PRIVATE_KEY_X25519);
//     }
//
//     #[test]
//     fn nacl_derive_from_seed() {
//         let seed = b"000000000000000000000000Trustee1";
//         let test_sk = hex::decode("3030303030303030303030303030303030303030303030305472757374656531e33aaf381fffa6109ad591fdc38717945f8fabf7abf02086ae401c63e9913097").unwrap();
//         let test_pk = &test_sk[32..];
//
//         let (pk, sk) = Ed25519Sha512::expand_keypair(seed).unwrap();
//         assert_eq!(pk.0, test_pk);
//         assert_eq!(sk.0, test_sk);
//     }
// }
