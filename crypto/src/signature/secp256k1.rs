use self::ecdsa_secp256k1::EcdsaSecp256k1Impl;
use crate::{Algorithm, Error, KeyGenOption, PrivateKey, PublicKey};

pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 33;

const ALGORITHM: Algorithm = Algorithm::Secp256k1;

pub struct EcdsaSecp256k1Sha256;

impl EcdsaSecp256k1Sha256 {
    pub fn keypair(option: Option<KeyGenOption>) -> Result<(PublicKey, PrivateKey), Error> {
        EcdsaSecp256k1Impl::keypair(option)
    }
    pub fn sign(message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, Error> {
        EcdsaSecp256k1Impl::sign(message, sk)
    }
    pub fn verify(message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, Error> {
        EcdsaSecp256k1Impl::verify(message, signature, pk)
    }
}

mod ecdsa_secp256k1 {
    use amcl::secp256k1::ecp;
    use arrayref::array_ref;
    use digest::Digest as _;
    use iroha_primitives::const_vec::ConstVec;
    use rand::{rngs::OsRng, RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;
    use signature::{Signer as _, Verifier as _};
    use zeroize::Zeroize;

    use super::{ALGORITHM, PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE};
    use crate::{Error, KeyGenOption, PrivateKey, PublicKey};

    pub struct EcdsaSecp256k1Impl;
    type Digest = sha2::Sha256;

    impl EcdsaSecp256k1Impl {
        pub fn public_key_compressed(pk: &PublicKey) -> Vec<u8> {
            assert_eq!(pk.digest_function, ALGORITHM);
            let mut compressed = [0u8; PUBLIC_KEY_SIZE];
            ecp::ECP::frombytes(&pk.payload[..]).tobytes(&mut compressed, true);
            compressed.to_vec()
        }

        pub fn keypair(option: Option<KeyGenOption>) -> Result<(PublicKey, PrivateKey), Error> {
            let signing_key = match option {
                Some(mut o) => match o {
                    KeyGenOption::UseSeed(ref mut seed) => {
                        let mut s = [0u8; PRIVATE_KEY_SIZE];
                        let mut rng = ChaChaRng::from_seed(*array_ref!(seed.as_slice(), 0, 32));
                        seed.zeroize();
                        rng.fill_bytes(&mut s);
                        let k = Digest::digest(s);
                        s.zeroize();
                        k256::SecretKey::from_slice(k.as_slice())?
                    }
                    KeyGenOption::FromPrivateKey(ref s) => {
                        assert_eq!(s.digest_function, ALGORITHM);
                        k256::SecretKey::from_slice(&s.payload[..])?
                    }
                },
                None => k256::SecretKey::random(&mut OsRng),
            };

            let public_key = signing_key.public_key();
            let compressed = public_key.to_sec1_bytes(); //serialized as compressed point
            Ok((
                PublicKey {
                    digest_function: ALGORITHM,
                    payload: ConstVec::new(compressed),
                },
                PrivateKey {
                    digest_function: ALGORITHM,
                    payload: ConstVec::new(signing_key.to_bytes().to_vec()),
                },
            ))
        }

        pub fn sign(message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, Error> {
            assert_eq!(sk.digest_function, ALGORITHM);
            let signing_key = k256::SecretKey::from_slice(&sk.payload[..])
                .map_err(|e| Error::Signing(format!("{:?}", e)))?;
            let signing_key = k256::ecdsa::SigningKey::from(signing_key);

            let signature: k256::ecdsa::Signature = signing_key.sign(message);
            Ok(signature.to_bytes().to_vec())
        }

        pub fn verify(message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, Error> {
            let compressed_pk = Self::public_key_compressed(pk);
            let verifying_key = k256::PublicKey::from_sec1_bytes(&compressed_pk)
                .map_err(|e| Error::Signing(format!("{:?}", e)))?;
            let signature = k256::ecdsa::Signature::from_slice(signature)
                .map_err(|e| Error::Signing(format!("{:?}", e)))?;

            let verifying_key = k256::ecdsa::VerifyingKey::from(verifying_key);

            Ok(verifying_key.verify(message, &signature).is_ok())
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

    fn public_key_uncompressed(pk: &PublicKey) -> Vec<u8> {
        const PUBLIC_UNCOMPRESSED_KEY_SIZE: usize = 65;

        assert_eq!(pk.digest_function, ALGORITHM);
        let mut uncompressed = [0u8; PUBLIC_UNCOMPRESSED_KEY_SIZE];
        ecp::ECP::frombytes(&pk.payload[..]).tobytes(&mut uncompressed, false);
        uncompressed.to_vec()
    }

    #[test]
    #[ignore]
    fn create_new_keys() {
        let (s, p) = EcdsaSecp256k1Sha256::keypair(None).unwrap();

        println!("{s:?}");
        println!("{p:?}");
    }

    #[test]
    fn secp256k1_load_keys() {
        let secret = PrivateKey::from_hex(ALGORITHM, PRIVATE_KEY).unwrap();
        let sres = EcdsaSecp256k1Sha256::keypair(Some(KeyGenOption::FromPrivateKey(secret)));
        assert!(sres.is_ok());
    }

    #[test]
    fn secp256k1_compatibility() {
        let secret = PrivateKey::from_hex(ALGORITHM, PRIVATE_KEY).unwrap();
        let (p, s) =
            EcdsaSecp256k1Sha256::keypair(Some(KeyGenOption::FromPrivateKey(secret))).unwrap();

        let sk = secp256k1::SecretKey::from_slice(s.payload());
        assert!(sk.is_ok());
        let pk = secp256k1::PublicKey::from_slice(p.payload());
        assert!(pk.is_ok());

        let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let openssl_point =
            EcPoint::from_bytes(&openssl_group, &public_key_uncompressed(&p)[..], &mut ctx);
        assert!(openssl_point.is_ok());
    }

    #[test]
    fn secp256k1_verify() {
        let p = PublicKey::from_hex(ALGORITHM, PUBLIC_KEY).unwrap();

        let result = EcdsaSecp256k1Sha256::verify(
            MESSAGE_1,
            hex::decode(SIGNATURE_1).unwrap().as_slice(),
            &p,
        );
        assert!(result.is_ok());
        assert!(result.unwrap());

        let context = secp256k1::Secp256k1::new();
        let pk =
            secp256k1::PublicKey::from_slice(hex::decode(PUBLIC_KEY).unwrap().as_slice()).unwrap();

        let h = sha2::Sha256::digest(MESSAGE_1);
        let msg = secp256k1::Message::from_digest_slice(h.as_slice()).unwrap();

        //Check if signatures produced here can be verified by secp256k1
        let mut signature =
            secp256k1::ecdsa::Signature::from_compact(&hex::decode(SIGNATURE_1).unwrap()[..])
                .unwrap();
        signature.normalize_s();
        let result = context.verify_ecdsa(&msg, &signature, &pk);
        assert!(result.is_ok());

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
        assert!(openssl_result.is_ok());
        assert!(openssl_result.unwrap());
    }

    #[test]
    fn secp256k1_sign() {
        let secret = PrivateKey::from_hex(ALGORITHM, PRIVATE_KEY).unwrap();
        let (p, s) =
            EcdsaSecp256k1Sha256::keypair(Some(KeyGenOption::FromPrivateKey(secret))).unwrap();

        let sig = EcdsaSecp256k1Sha256::sign(MESSAGE_1, &s).unwrap();
        let result = EcdsaSecp256k1Sha256::verify(MESSAGE_1, &sig, &p);
        assert!(result.is_ok());
        assert!(result.unwrap());

        assert_eq!(sig.len(), 64);

        // Check if secp256k1 signs the message and this module still can verify it
        // And that private keys can sign with other libraries
        let context = secp256k1::Secp256k1::new();
        let sk =
            secp256k1::SecretKey::from_slice(hex::decode(PRIVATE_KEY).unwrap().as_slice()).unwrap();

        let h = sha2::Sha256::digest(MESSAGE_1);

        let msg = secp256k1::Message::from_digest_slice(h.as_slice()).unwrap();
        let sig_1 = context.sign_ecdsa(&msg, &sk).serialize_compact();

        let result = EcdsaSecp256k1Sha256::verify(MESSAGE_1, &sig_1, &p);

        assert!(result.is_ok());
        assert!(result.unwrap());

        let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let openssl_point =
            EcPoint::from_bytes(&openssl_group, &public_key_uncompressed(&p)[..], &mut ctx)
                .unwrap();
        let openssl_public_key = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();
        let openssl_secret_key = EcKey::from_private_components(
            &openssl_group,
            &BigNum::from_hex_str(PRIVATE_KEY).unwrap(),
            &openssl_point,
        )
        .unwrap();

        let openssl_sig = EcdsaSig::sign(h.as_slice(), &openssl_secret_key).unwrap();
        let openssl_result = openssl_sig.verify(h.as_slice(), &openssl_public_key);
        assert!(openssl_result.is_ok());
        assert!(openssl_result.unwrap());
        let mut temp_sig = Vec::new();
        temp_sig.extend(openssl_sig.r().to_vec());
        temp_sig.extend(openssl_sig.s().to_vec());

        // secp256k1 expects normalized "s"'s.
        // scheme.normalize_s(temp_sig.as_mut_slice()).unwrap();
        // k256 seems to be normalizing always now
        let result = EcdsaSecp256k1Sha256::verify(MESSAGE_1, temp_sig.as_slice(), &p);
        assert!(result.is_ok());
        assert!(result.unwrap());

        let (p, s) = EcdsaSecp256k1Sha256::keypair(None).unwrap();
        let signed = EcdsaSecp256k1Sha256::sign(MESSAGE_1, &s).unwrap();
        let result = EcdsaSecp256k1Sha256::verify(MESSAGE_1, &signed, &p);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
