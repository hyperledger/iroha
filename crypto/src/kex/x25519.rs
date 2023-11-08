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

/// Implements the [`KeyExchangeScheme`] using X25519 key exchange and SHA256 hash function.
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

    const SHARED_SECRET_SIZE: usize = 32;
    const PUBLIC_KEY_SIZE: usize = 32;
    const PRIVATE_KEY_SIZE: usize = 32;
}

#[cfg(test)]
mod tests {
    use super::*;

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
