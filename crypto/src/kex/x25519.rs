#[cfg(not(feature = "std"))]
use alloc::{format, vec::Vec};

use arrayref::array_ref;
use iroha_primitives::const_vec::ConstVec;
#[cfg(feature = "rand")]
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::Digest;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use super::KeyExchangeScheme;
use crate::{error::ParseError, KeyPairGenOption, SessionKey};

/// Implements the [`KeyExchangeScheme`] using X25519 key exchange and SHA256 hash function.
#[derive(Copy, Clone)]
pub struct X25519Sha256;

impl KeyExchangeScheme for X25519Sha256 {
    type PublicKey = PublicKey;
    type PrivateKey = StaticSecret;

    fn new() -> Self {
        Self
    }

    fn keypair(
        &self,
        mut option: KeyPairGenOption<Self::PrivateKey>,
    ) -> (Self::PublicKey, Self::PrivateKey) {
        match option {
            #[cfg(feature = "rand")]
            KeyPairGenOption::Random => {
                let rng = OsRng;
                let sk = StaticSecret::random_from_rng(rng);
                let pk = PublicKey::from(&sk);
                (pk, sk)
            }
            KeyPairGenOption::UseSeed(ref mut s) => {
                let hash = sha2::Sha256::digest(s.as_slice());
                s.zeroize();
                let rng = ChaChaRng::from_seed(*array_ref!(hash.as_slice(), 0, 32));
                let sk = StaticSecret::random_from_rng(rng);
                let pk = PublicKey::from(&sk);
                (pk, sk)
            }
            KeyPairGenOption::FromPrivateKey(ref sk) => {
                let pk = PublicKey::from(sk);
                (pk, sk.clone())
            }
        }
    }

    fn compute_shared_secret(
        &self,
        local_private_key: &Self::PrivateKey,
        remote_public_key: &Self::PublicKey,
    ) -> SessionKey {
        let sk = StaticSecret::from(*local_private_key.as_bytes());

        let shared_secret = sk.diffie_hellman(remote_public_key);
        let hash = sha2::Sha256::digest(shared_secret.as_bytes());
        SessionKey(ConstVec::new(hash.as_slice().to_vec()))
    }

    fn encode_public_key(pk: &Self::PublicKey) -> &[u8] {
        pk.as_bytes()
    }

    fn decode_public_key(bytes: Vec<u8>) -> Result<Self::PublicKey, ParseError> {
        let bytes = <[u8; Self::PUBLIC_KEY_SIZE]>::try_from(bytes).map_err(|_| {
            ParseError(format!(
                "X25519 public key should be {} size long",
                Self::PUBLIC_KEY_SIZE
            ))
        })?;
        Ok(PublicKey::from(bytes))
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
        let (public_key1, secret_key1) = scheme.keypair(KeyPairGenOption::Random);

        let (public_key2, secret_key2) = scheme.keypair(KeyPairGenOption::Random);
        let shared_secret1 = scheme.compute_shared_secret(&secret_key2, &public_key1);
        let shared_secret2 = scheme.compute_shared_secret(&secret_key1, &public_key2);
        assert_eq!(shared_secret1.payload(), shared_secret2.payload());

        let (public_key2, _secret_key1) =
            scheme.keypair(KeyPairGenOption::FromPrivateKey(secret_key1));
        assert_eq!(public_key2, public_key1);
    }
}
