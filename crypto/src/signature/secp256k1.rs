#![allow(unused)]

use rand::rngs::OsRng;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use sha2::digest::generic_array::typenum::U32;

use crate::{Algorithm, Error, KeyGenOption, PrivateKey, PublicKey};

pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 33;
pub const PUBLIC_UNCOMPRESSED_KEY_SIZE: usize = 65;
pub const SIGNATURE_POINT_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const ALGORITHM_NAME: &str = "ECDSA_SECP256K1_SHA256";

const ALGORITHM: Algorithm = Algorithm::Secp256k1;

pub struct EcdsaSecp256k1Sha256(ecdsa_secp256k1::EcdsaSecp256k1Impl);

impl EcdsaSecp256k1Sha256 {
    pub fn normalize_s(&self, signature: &mut [u8]) -> Result<(), Error> {
        self.0.normalize_s(signature)
    }
}

impl EcdsaSecp256k1Sha256 {
    fn new() -> Self {
        EcdsaSecp256k1Sha256(ecdsa_secp256k1::EcdsaSecp256k1Impl::new())
    }
    fn keypair(&self, option: Option<KeyGenOption>) -> Result<(PublicKey, PrivateKey), Error> {
        self.0.keypair::<sha2::Sha256>(option)
    }
    fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, Error> {
        self.0.sign::<sha2::Sha256>(message, sk)
    }
    fn verify(&self, message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, Error> {
        self.0.verify::<sha2::Sha256>(message, signature, pk)
    }
    fn signature_size() -> usize {
        SIGNATURE_SIZE
    }
    fn private_key_size() -> usize {
        PRIVATE_KEY_SIZE
    }
    fn public_key_size() -> usize {
        PUBLIC_KEY_SIZE
    }
}

impl EcdsaSecp256k1Sha256 {
    /// Returns the compressed bytes
    fn public_key_compressed(&self, pk: &PublicKey) -> Vec<u8> {
        self.0.public_key_compressed(pk)
    }
    /// Returns the uncompressed bytes
    fn public_key_uncompressed(&self, pk: &PublicKey) -> Vec<u8> {
        self.0.public_key_uncompressed(pk)
    }
    /// Read raw bytes into key struct. Can be either compressed or uncompressed
    fn parse(&self, data: &[u8]) -> Result<PublicKey, Error> {
        self.0.parse(data)
    }
    fn public_key_uncompressed_size() -> usize {
        PUBLIC_UNCOMPRESSED_KEY_SIZE
    }
}

mod ecdsa_secp256k1 {
    use arrayref::array_ref;
    use iroha_primitives::const_vec::ConstVec;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;
    use secp256k1;
    use sha2::Digest;
    use zeroize::Zeroize;

    use super::*;

    pub struct EcdsaSecp256k1Impl(secp256k1::Secp256k1<secp256k1::All>);

    impl EcdsaSecp256k1Impl {
        pub fn public_key_compressed(&self, pk: &PublicKey) -> Vec<u8> {
            assert_eq!(pk.digest_function, ALGORITHM);
            let pk = secp256k1::key::PublicKey::from_slice(&pk.payload[..]).unwrap();
            pk.serialize().to_vec()
        }
        pub fn public_key_uncompressed(&self, pk: &PublicKey) -> Vec<u8> {
            assert_eq!(pk.digest_function, ALGORITHM);
            let pk = secp256k1::key::PublicKey::from_slice(&pk.payload[..]).unwrap();
            pk.serialize_uncompressed().to_vec()
        }
        pub fn parse(&self, data: &[u8]) -> Result<PublicKey, Error> {
            let res = secp256k1::key::PublicKey::from_slice(data)?;
            let pk = PublicKey {
                digest_function: ALGORITHM,
                payload: ConstVec::new(res.serialize().to_vec()),
            };
            Ok(pk)
        }
        pub fn new() -> Self {
            Self(secp256k1::Secp256k1::new())
        }
        pub(crate) fn keypair<D>(
            &self,
            option: Option<KeyGenOption>,
        ) -> Result<(PublicKey, PrivateKey), Error>
        where
            D: Digest<OutputSize = U32>,
        {
            let sk = match option {
                Some(mut o) => match o {
                    KeyGenOption::UseSeed(ref mut seed) => {
                        let mut s = [0u8; PRIVATE_KEY_SIZE];
                        let mut rng = ChaChaRng::from_seed(*array_ref!(seed.as_slice(), 0, 32));
                        seed.zeroize();
                        rng.fill_bytes(&mut s);
                        let k = D::digest(&s);
                        s.zeroize();
                        secp256k1::key::SecretKey::from_slice(k.as_slice())?
                    }
                    KeyGenOption::FromPrivateKey(ref s) => {
                        assert_eq!(s.digest_function, ALGORITHM);
                        secp256k1::key::SecretKey::from_slice(&s.payload[..])?
                    }
                },
                None => {
                    let mut s = [0u8; PRIVATE_KEY_SIZE];
                    OsRng.fill_bytes(&mut s);
                    let k = D::digest(&s);
                    s.zeroize();
                    secp256k1::key::SecretKey::from_slice(k.as_slice())?
                }
            };
            let pk = secp256k1::key::PublicKey::from_secret_key(&self.0, &sk);
            Ok((
                PublicKey {
                    digest_function: ALGORITHM,
                    payload: ConstVec::new(pk.serialize().to_vec()),
                },
                PrivateKey {
                    digest_function: ALGORITHM,
                    payload: ConstVec::new(sk[..].to_vec()),
                },
            ))
        }
        pub fn sign<D>(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, Error>
        where
            D: Digest<OutputSize = U32>,
        {
            assert_eq!(sk.digest_function, ALGORITHM);
            let h = D::digest(message);
            let msg = secp256k1::Message::from_slice(h.as_slice())?;
            let s = secp256k1::key::SecretKey::from_slice(&sk.payload[..])?;
            let sig = self.0.sign(&msg, &s);
            Ok(sig.serialize_compact().to_vec())
        }
        pub fn verify<D>(
            &self,
            message: &[u8],
            signature: &[u8],
            pk: &PublicKey,
        ) -> Result<bool, Error>
        where
            D: Digest<OutputSize = U32>,
        {
            assert_eq!(pk.digest_function, ALGORITHM);
            let h = D::digest(message);
            let msg = secp256k1::Message::from_slice(h.as_slice())?;
            let p = secp256k1::PublicKey::from_slice(&pk.payload[..])?;
            let sig = secp256k1::Signature::from_compact(signature)?;
            let res = self.0.verify(&msg, &sig, &p);
            match res {
                Ok(()) => Ok(true),
                Err(secp256k1::Error::IncorrectSignature) => Ok(false),
                Err(err) => Err(Error::from(err)),
            }
        }
        pub fn normalize_s(&self, signature: &mut [u8]) -> Result<(), Error> {
            let mut sig = secp256k1::Signature::from_compact(signature)?;
            sig.normalize_s();
            let compact = sig.serialize_compact();
            signature.clone_from_slice(&compact[..]);
            Ok(())
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(error: secp256k1::Error) -> Error {
        match error {
            secp256k1::Error::IncorrectSignature => Error::Parse("Incorrect Signature".to_string()),
            secp256k1::Error::InvalidMessage => Error::Parse("Invalid Message".to_string()),
            secp256k1::Error::InvalidPublicKey => Error::Parse("Invalid Public Key".to_string()),
            secp256k1::Error::InvalidSignature => Error::Parse("Invalid Signature".to_string()),
            secp256k1::Error::InvalidSecretKey => Error::Parse("Invalid Secret Key".to_string()),
            secp256k1::Error::InvalidRecoveryId => Error::Parse("Invalid Recovery Id".to_string()),
            secp256k1::Error::InvalidTweak => Error::Parse("Invalid Tweak".to_string()),
            secp256k1::Error::NotEnoughMemory => Error::Parse("Not Enough Memory".to_string()),
        }
    }
}

// #[cfg(test)]
// mod test {
//     use openssl::{
//         bn::{BigNum, BigNumContext},
//         ec::{EcGroup, EcKey, EcPoint},
//         ecdsa::EcdsaSig,
//         nid::Nid,
//     };
//     use secp256k1;
//     use sha2::Digest;
//
//     use super::{EcdsaPublicKeyHandler, *};
//
//     const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
//     const SIGNATURE_1: &str = "ae46d3fec8e2eb95ebeaf95f7f096ec4bf517f5ef898e4379651f8af8e209ed75f3c47156445d6687a5f817fb3e188e2a76df653b330df859ec47579c8c409be";
//     const PRIVATE_KEY: &str = "e4f21b38e005d4f895a29e84948d7cc83eac79041aeb644ee4fab8d9da42f713";
//     const PUBLIC_KEY: &str = "0242c1e1f775237a26da4fd51b8d75ee2709711f6e90303e511169a324ef0789c0";
//
//     #[test]
//     #[ignore]
//     fn create_new_keys() {
//         let scheme = EcdsaSecp256k1Sha256::new();
//         let (s, p) = scheme.keypair(None).unwrap();
//
//         println!("{:?}", s);
//         println!("{:?}", p);
//     }
//
//     #[test]
//     fn secp256k1_load_keys() {
//         let scheme = EcdsaSecp256k1Sha256::new();
//         let secret = PrivateKey(hex::decode(PRIVATE_KEY).unwrap());
//         let sres = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret)));
//         assert!(sres.is_ok());
//         let pres = scheme.parse(hex::decode(PUBLIC_KEY).unwrap().as_slice());
//         assert!(pres.is_ok());
//         let (p1, _) = sres.unwrap();
//         assert_eq!(p1, pres.unwrap());
//     }
//
//     #[test]
//     fn secp256k1_compatibility() {
//         let scheme = EcdsaSecp256k1Sha256::new();
//         let secret = PrivateKey(hex::decode(PRIVATE_KEY).unwrap());
//         let (p, s) = scheme
//             .keypair(Some(KeyGenOption::FromSecretKey(secret)))
//             .unwrap();
//
//         let p_u = scheme.parse(&scheme.public_key_uncompressed(&p));
//         assert!(p_u.is_ok());
//         let p_u = p_u.unwrap();
//         assert_eq!(p_u, p);
//
//         let sk = secp256k1::key::SecretKey::from_slice(&s[..]);
//         assert!(sk.is_ok());
//         let pk = secp256k1::key::PublicKey::from_slice(&p[..]);
//         assert!(pk.is_ok());
//         let pk = secp256k1::key::PublicKey::from_slice(&scheme.public_key_uncompressed(&p)[..]);
//         assert!(pk.is_ok());
//
//         let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
//         let mut ctx = BigNumContext::new().unwrap();
//         let openssl_point = EcPoint::from_bytes(
//             &openssl_group,
//             &scheme.public_key_uncompressed(&p)[..],
//             &mut ctx,
//         );
//         assert!(openssl_point.is_ok());
//     }
//
//     #[test]
//     fn secp256k1_verify() {
//         let scheme = EcdsaSecp256k1Sha256::new();
//         let p = PublicKey(hex::decode(PUBLIC_KEY).unwrap());
//
//         let result = scheme.verify(&MESSAGE_1, hex::decode(SIGNATURE_1).unwrap().as_slice(), &p);
//         assert!(result.is_ok());
//         assert!(result.unwrap());
//
//         let context = secp256k1::Secp256k1::new();
//         let pk = secp256k1::key::PublicKey::from_slice(
//             hex::decode(PUBLIC_KEY).unwrap().as_slice(),
//         )
//         .unwrap();
//
//         let h = sha2::Sha256::digest(&MESSAGE_1);
//         let msg = secp256k1::Message::from_slice(h.as_slice()).unwrap();
//
//         //Check if signatures produced here can be verified by secp256k1
//         let mut signature =
//             secp256k1::Signature::from_compact(&hex::decode(SIGNATURE_1).unwrap()[..])
//                 .unwrap();
//         signature.normalize_s();
//         let result = context.verify(&msg, &signature, &pk);
//         assert!(result.is_ok());
//
//         let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
//         let mut ctx = BigNumContext::new().unwrap();
//         let openssl_point =
//             EcPoint::from_bytes(&openssl_group, &pk.serialize_uncompressed(), &mut ctx).unwrap();
//         let openssl_pkey = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();
//
//         //Check if the signatures produced here can be verified by openssl
//         let (r, s) = SIGNATURE_1.split_at(SIGNATURE_1.len() / 2);
//         let openssl_r = BigNum::from_hex_str(r).unwrap();
//         let openssl_s = BigNum::from_hex_str(s).unwrap();
//         let openssl_sig = EcdsaSig::from_private_components(openssl_r, openssl_s).unwrap();
//         let openssl_result = openssl_sig.verify(h.as_slice(), &openssl_pkey);
//         assert!(openssl_result.is_ok());
//         assert!(openssl_result.unwrap());
//     }
//
//     #[test]
//     fn secp256k1_sign() {
//         let scheme = EcdsaSecp256k1Sha256::new();
//         let secret = PrivateKey(hex::decode(PRIVATE_KEY).unwrap());
//         let (p, s) = scheme
//             .keypair(Some(KeyGenOption::FromSecretKey(secret)))
//             .unwrap();
//
//         match scheme.sign(MESSAGE_1, &s) {
//             Ok(sig) => {
//                 let result = scheme.verify(&MESSAGE_1, &sig, &p);
//                 assert!(result.is_ok());
//                 assert!(result.unwrap());
//
//                 assert_eq!(sig.len(), SIGNATURE_SIZE);
//
//                 //Check if secp256k1 signs the message and this module still can verify it
//                 //And that private keys can sign with other libraries
//                 let context = secp256k1::Secp256k1::new();
//                 let sk = secp256k1::key::SecretKey::from_slice(
//                     hex::decode(PRIVATE_KEY).unwrap().as_slice(),
//                 )
//                 .unwrap();
//
//                 let h = sha2::Sha256::digest(&MESSAGE_1);
//
//                 let msg = secp256k1::Message::from_slice(h.as_slice()).unwrap();
//                 let sig_1 = context.sign(&msg, &sk).serialize_compact();
//
//                 let result = scheme.verify(&MESSAGE_1, &sig_1, &p);
//
//                 assert!(result.is_ok());
//                 assert!(result.unwrap());
//
//                 let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
//                 let mut ctx = BigNumContext::new().unwrap();
//                 let openssl_point = EcPoint::from_bytes(
//                     &openssl_group,
//                     &scheme.public_key_uncompressed(&p)[..],
//                     &mut ctx,
//                 )
//                 .unwrap();
//                 let openssl_pkey = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();
//                 let openssl_skey = EcKey::from_private_components(
//                     &openssl_group,
//                     &BigNum::from_hex_str(PRIVATE_KEY).unwrap(),
//                     &openssl_point,
//                 )
//                 .unwrap();
//
//                 let openssl_sig = EcdsaSig::sign(h.as_slice(), &openssl_skey).unwrap();
//                 let openssl_result = openssl_sig.verify(h.as_slice(), &openssl_pkey);
//                 assert!(openssl_result.is_ok());
//                 assert!(openssl_result.unwrap());
//                 let mut temp_sig = Vec::new();
//                 temp_sig.extend(openssl_sig.r().to_vec());
//                 temp_sig.extend(openssl_sig.s().to_vec());
//
//                 //secp256k1 expects normalized "s"'s.
//                 scheme.normalize_s(temp_sig.as_mut_slice()).unwrap();
//                 let result = scheme.verify(&MESSAGE_1, temp_sig.as_slice(), &p);
//                 assert!(result.is_ok());
//                 assert!(result.unwrap());
//
//                 let (p, s) = scheme.keypair(None).unwrap();
//                 match scheme.sign(&MESSAGE_1, &s) {
//                     Ok(signed) => {
//                         let result = scheme.verify(&MESSAGE_1, &signed, &p);
//                         assert!(result.is_ok());
//                         assert!(result.unwrap());
//                     }
//                     Err(er) => assert!(false, "{}", er),
//                 }
//
//                 let signer = Signer::new(&scheme, &s);
//                 match signer.sign(&MESSAGE_1) {
//                     Ok(signed) => {
//                         let result = scheme.verify(&MESSAGE_1, &signed, &p);
//                         assert!(result.is_ok());
//                         assert!(result.unwrap());
//                     }
//                     Err(er) => assert!(false, "{}", er),
//                 }
//             }
//             Err(e) => assert!(false, "{}", e),
//         }
//     }
//
//     #[test]
//     fn secp256k1_publickey_compression() {
//         let scheme = EcdsaSecp256k1Sha256::new();
//
//         let pk = PublicKey(hex::decode(PUBLIC_KEY).unwrap());
//
//         let res = scheme.public_key_compressed(&pk);
//         assert_eq!(res[..], pk[..]);
//
//         let res = scheme.public_key_uncompressed(&pk);
//         let pk = PublicKey(res);
//
//         let res = scheme.public_key_uncompressed(&pk);
//         assert_eq!(res[..], pk[..]);
//     }
// }
