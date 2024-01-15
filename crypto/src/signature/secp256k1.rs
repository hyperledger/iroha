#[cfg(not(feature = "std"))]
use alloc::{format, vec::Vec};

use self::ecdsa_secp256k1::EcdsaSecp256k1Impl;
use crate::{Error, KeyGenOption, ParseError};

pub const PRIVATE_KEY_SIZE: usize = 32;

pub struct EcdsaSecp256k1Sha256;

pub type PublicKey = k256::PublicKey;
pub type PrivateKey = k256::SecretKey;

impl EcdsaSecp256k1Sha256 {
    pub fn keypair(option: Option<KeyGenOption>) -> (PublicKey, PrivateKey) {
        EcdsaSecp256k1Impl::keypair(option)
    }

    pub fn sign(message: &[u8], sk: &PrivateKey) -> Vec<u8> {
        EcdsaSecp256k1Impl::sign(message, sk)
    }

    pub fn verify(message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<(), Error> {
        EcdsaSecp256k1Impl::verify(message, signature, pk)
    }

    pub fn parse_public_key(payload: &[u8]) -> Result<PublicKey, ParseError> {
        EcdsaSecp256k1Impl::parse_public_key(payload)
    }

    pub fn parse_private_key(payload: &[u8]) -> Result<PrivateKey, ParseError> {
        EcdsaSecp256k1Impl::parse_private_key(payload)
    }
}

mod ecdsa_secp256k1 {
    #[cfg(not(feature = "std"))]
    use alloc::{format, string::ToString as _, vec::Vec};

    use arrayref::array_ref;
    use digest::Digest as _;
    use rand::{rngs::OsRng, RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;
    use signature::{Signer as _, Verifier as _};
    use zeroize::Zeroize;

    use super::{PrivateKey, PublicKey, PRIVATE_KEY_SIZE};
    use crate::{Error, KeyGenOption, ParseError};

    pub struct EcdsaSecp256k1Impl;
    type Digest = sha2::Sha256;

    impl EcdsaSecp256k1Impl {
        pub fn keypair(option: Option<KeyGenOption>) -> (PublicKey, PrivateKey) {
            let signing_key = option.map_or_else(
                || PrivateKey::random(&mut OsRng),
                |mut o| match o {
                    KeyGenOption::UseSeed(ref mut seed) => {
                        let mut s = [0u8; PRIVATE_KEY_SIZE];
                        let mut rng = ChaChaRng::from_seed(*array_ref!(seed.as_slice(), 0, 32));
                        seed.zeroize();
                        rng.fill_bytes(&mut s);
                        let k = Digest::digest(s);
                        s.zeroize();
                        PrivateKey::from_slice(k.as_slice())
                            .expect("Creating private key from seed should always succeed")
                    }
                    KeyGenOption::FromPrivateKey(ref s) => {
                        let crate::PrivateKey::Secp256k1(s) = s else {
                            panic!("Wrong private key type, expected `Secp256k1`, got {s:?}")
                        };
                        s.clone()
                    }
                },
            );

            let public_key = signing_key.public_key();
            (public_key, signing_key)
        }

        pub fn sign(message: &[u8], sk: &PrivateKey) -> Vec<u8> {
            let signing_key = k256::ecdsa::SigningKey::from(sk);

            let signature: k256::ecdsa::Signature = signing_key.sign(message);
            signature.to_bytes().to_vec()
        }

        pub fn verify(message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<(), Error> {
            let signature = k256::ecdsa::Signature::from_slice(signature)
                .map_err(|e| Error::Signing(format!("{e:?}")))?;

            let verifying_key = k256::ecdsa::VerifyingKey::from(pk);

            verifying_key
                .verify(message, &signature)
                .map_err(|_| Error::BadSignature)
        }

        pub fn parse_public_key(payload: &[u8]) -> Result<PublicKey, ParseError> {
            PublicKey::from_sec1_bytes(payload).map_err(|err| ParseError(err.to_string()))
        }

        pub fn parse_private_key(payload: &[u8]) -> Result<PrivateKey, ParseError> {
            PrivateKey::from_slice(payload).map_err(|err| ParseError(err.to_string()))
        }
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
    use amcl::secp256k1::ecp;
    use openssl::{
        bn::{BigNum, BigNumContext},
        ec::{EcGroup, EcKey, EcPoint},
        ecdsa::EcdsaSig,
        nid::Nid,
    };
    use sha2::Digest;

    use super::*;

    const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
    const SIGNATURE_1: &str = "ae46d3fec8e2eb95ebeaf95f7f096ec4bf517f5ef898e4379651f8af8e209ed75f3c47156445d6687a5f817fb3e188e2a76df653b330df859ec47579c8c409be";
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

    fn public_key_uncompressed(pk: &PublicKey) -> Vec<u8> {
        const PUBLIC_UNCOMPRESSED_KEY_SIZE: usize = 65;

        let mut uncompressed = [0u8; PUBLIC_UNCOMPRESSED_KEY_SIZE];
        ecp::ECP::frombytes(&pk.to_sec1_bytes()[..]).tobytes(&mut uncompressed, false);
        uncompressed.to_vec()
    }

    #[test]
    fn secp256k1_compatibility() {
        let secret = private_key();
        let (p, s) = EcdsaSecp256k1Sha256::keypair(Some(KeyGenOption::FromPrivateKey(
            crate::PrivateKey::Secp256k1(secret),
        )));

        let _sk = secp256k1::SecretKey::from_slice(&s.to_bytes()).unwrap();
        let _pk = secp256k1::PublicKey::from_slice(&p.to_sec1_bytes()).unwrap();

        let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let _openssl_point =
            EcPoint::from_bytes(&openssl_group, &public_key_uncompressed(&p)[..], &mut ctx)
                .unwrap();
    }

    #[test]
    fn secp256k1_verify() {
        let p = public_key();

        EcdsaSecp256k1Sha256::verify(MESSAGE_1, hex::decode(SIGNATURE_1).unwrap().as_slice(), &p)
            .unwrap();

        let context = secp256k1::Secp256k1::new();
        let pk =
            secp256k1::PublicKey::from_slice(hex::decode(PUBLIC_KEY).unwrap().as_slice()).unwrap();

        let h = sha2::Sha256::digest(MESSAGE_1);
        let msg = secp256k1::Message::from_digest_slice(h.as_slice()).unwrap();

        // Check if signatures produced here can be verified by secp256k1
        let signature =
            secp256k1::ecdsa::Signature::from_compact(&hex::decode(SIGNATURE_1).unwrap()[..])
                .unwrap();
        context.verify_ecdsa(&msg, &signature, &pk).unwrap();

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
        let openssl_result = openssl_sig.verify(h.as_slice(), &openssl_pkey);
        assert!(openssl_result.unwrap());
    }

    #[test]
    fn secp256k1_sign() {
        let secret = private_key();
        let (pk, sk) = EcdsaSecp256k1Sha256::keypair(Some(KeyGenOption::FromPrivateKey(
            crate::PrivateKey::Secp256k1(secret),
        )));

        let sig = EcdsaSecp256k1Sha256::sign(MESSAGE_1, &sk);
        EcdsaSecp256k1Sha256::verify(MESSAGE_1, &sig, &pk).unwrap();

        assert_eq!(sig.len(), 64);

        // Check if secp256k1 signs the message and this module still can verify it
        // And that private keys can sign with other libraries
        let context = secp256k1::Secp256k1::new();
        let sk =
            secp256k1::SecretKey::from_slice(hex::decode(PRIVATE_KEY).unwrap().as_slice()).unwrap();

        let h = sha2::Sha256::digest(MESSAGE_1);

        let msg = secp256k1::Message::from_digest_slice(h.as_slice()).unwrap();
        let sig_1 = context.sign_ecdsa(&msg, &sk).serialize_compact();

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

        let openssl_sig = EcdsaSig::sign(h.as_slice(), &openssl_secret_key).unwrap();
        let openssl_result = openssl_sig.verify(h.as_slice(), &openssl_public_key);
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
            res.extend(r.to_vec());
            res.extend(s.to_vec());
            res
        };

        EcdsaSecp256k1Sha256::verify(MESSAGE_1, openssl_sig.as_slice(), &pk).unwrap();

        let (p, s) = EcdsaSecp256k1Sha256::keypair(None);
        let signed = EcdsaSecp256k1Sha256::sign(MESSAGE_1, &s);
        EcdsaSecp256k1Sha256::verify(MESSAGE_1, &signed, &p).unwrap();
    }
}
