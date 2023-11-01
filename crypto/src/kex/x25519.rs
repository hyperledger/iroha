use arrayref::array_ref;
use iroha_primitives::const_vec::ConstVec;
use rand::{rngs::OsRng, SeedableRng};
use rand_chacha::ChaChaRng;
use sha2::Digest;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

const ALGORITHM: Algorithm = Algorithm::Ed25519;

use super::KeyExchangeScheme;
use crate::{Algorithm, Error, KeyGenOption, PrivateKey, PublicKey, SessionKey};

#[derive(Copy, Clone)]
pub struct X25519Sha256;

impl KeyExchangeScheme for X25519Sha256 {
    fn new() -> Self {
        Self
    }

    fn keypair(&self, option: Option<KeyGenOption>) -> Result<(PublicKey, PrivateKey), Error> {
        let (pk, sk) = match option {
            Some(mut o) => match o {
                KeyGenOption::UseSeed(ref mut s) => {
                    let hash = sha2::Sha256::digest(s.as_slice());
                    s.zeroize();
                    let mut rng = ChaChaRng::from_seed(*array_ref!(hash.as_slice(), 0, 32));
                    let sk = StaticSecret::random_from_rng(&mut rng);
                    let pk = X25519PublicKey::from(&sk);
                    (pk, sk)
                }
                KeyGenOption::FromPrivateKey(ref s) => {
                    assert_eq!(s.digest_function, ALGORITHM);
                    let sk = StaticSecret::from(*array_ref!(&s.payload, 0, 32));
                    let pk = X25519PublicKey::from(&sk);
                    (pk, sk)
                }
            },
            None => {
                let mut rng = OsRng::default();
                let sk = StaticSecret::random_from_rng(&mut rng);
                let pk = X25519PublicKey::from(&sk);
                (pk, sk)
            }
        };
        Ok((
            PublicKey {
                digest_function: ALGORITHM,
                payload: ConstVec::new(pk.as_bytes().to_vec()),
            },
            PrivateKey {
                digest_function: ALGORITHM,
                payload: ConstVec::new(sk.to_bytes().to_vec()),
            },
        ))
    }

    fn compute_shared_secret(
        &self,
        local_private_key: &PrivateKey,
        remote_public_key: &PublicKey,
    ) -> Result<SessionKey, Error> {
        assert_eq!(local_private_key.digest_function, ALGORITHM);
        assert_eq!(remote_public_key.digest_function, ALGORITHM);
        let sk = StaticSecret::from(*array_ref!(&local_private_key.payload, 0, 32));
        let pk = X25519PublicKey::from(*array_ref!(&remote_public_key.payload, 0, 32));
        let shared_secret = sk.diffie_hellman(&pk);
        let hash = sha2::Sha256::digest(shared_secret.as_bytes());
        Ok(SessionKey(ConstVec::new(hash.as_slice().to_vec())))
    }

    fn public_key_size() -> usize {
        32
    }
    fn private_key_size() -> usize {
        32
    }
    fn shared_secret_size() -> usize {
        32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn convert_from_sig_keys() {
    //     use crate::{Ed25519Sha512, SignatureScheme};
    //     let sig_scheme = Ed25519Sha512::new();
    //     let (pk, sk) = sig_scheme.keypair(None).unwrap();
    //     let res = Ed25519Sha512::ver_key_to_key_exchange(&pk);
    //     assert!(res.is_ok());
    //     let pk1 = res.unwrap();
    //     let kex_scheme = X25519Sha256::new();
    //     let res = kex_scheme.compute_shared_secret(&sk, &pk1);
    //     assert!(res.is_ok());
    // }

    #[test]
    fn key_exchange() {
        let scheme = X25519Sha256::new();
        let res = scheme.keypair(None);
        assert!(res.is_ok());
        let (pk, sk) = res.unwrap();
        let res = scheme.compute_shared_secret(&sk, &pk);
        assert!(res.is_ok());
        let res = scheme.keypair(None);
        assert!(res.is_ok());
        let (pk1, sk1) = res.unwrap();
        let res = scheme.compute_shared_secret(&sk1, &pk);
        assert!(res.is_ok());
        let res = scheme.compute_shared_secret(&sk, &pk1);
        assert!(res.is_ok());

        let res = scheme.keypair(Some(KeyGenOption::FromPrivateKey(sk.clone())));
        assert!(res.is_ok());
        let (pk1, sk1) = res.unwrap();
        assert_eq!(pk1, pk);
        assert_eq!(sk1, sk);
    }
}
