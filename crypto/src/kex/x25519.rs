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

    fn keypair(&self, mut option: Option<KeyGenOption>) -> Result<(PublicKey, PrivateKey), Error> {
        let (pk, sk) = match option {
            Some(KeyGenOption::UseSeed(ref mut s)) => {
                let hash = sha2::Sha256::digest(s.as_slice());
                s.zeroize();
                let rng = ChaChaRng::from_seed(*array_ref!(hash.as_slice(), 0, 32));
                let sk = StaticSecret::random_from_rng(rng);
                let pk = X25519PublicKey::from(&sk);
                (pk, sk)
            }
            Some(KeyGenOption::FromPrivateKey(ref s)) => {
                assert_eq!(s.digest_function, ALGORITHM);
                let sk = StaticSecret::from(*array_ref!(&s.payload, 0, 32));
                let pk = X25519PublicKey::from(&sk);
                (pk, sk)
            }
            None => {
                let rng = OsRng;
                let sk = StaticSecret::random_from_rng(rng);
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
    ) -> SessionKey {
        assert_eq!(local_private_key.digest_function, ALGORITHM);
        assert_eq!(remote_public_key.digest_function, ALGORITHM);
        let sk = StaticSecret::from(*array_ref!(&local_private_key.payload, 0, 32));
        let pk = X25519PublicKey::from(*array_ref!(&remote_public_key.payload, 0, 32));
        let shared_secret = sk.diffie_hellman(&pk);
        let hash = sha2::Sha256::digest(shared_secret.as_bytes());
        SessionKey(ConstVec::new(hash.as_slice().to_vec()))
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
        let (public_key1, secret_key1) = scheme.keypair(None).unwrap();
        let _res = scheme.compute_shared_secret(&secret_key1, &public_key1);
        let res = scheme.keypair(None);
        let (public_key2, secret_key2) = res.unwrap();
        let _res = scheme.compute_shared_secret(&secret_key2, &public_key1);
        let _res = scheme.compute_shared_secret(&secret_key1, &public_key2);

        let (public_key2, secret_key1) = scheme
            .keypair(Some(KeyGenOption::FromPrivateKey(secret_key1)))
            .unwrap();
        assert_eq!(public_key2, public_key1);
        assert_eq!(secret_key1, secret_key1);
    }
}
