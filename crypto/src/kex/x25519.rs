#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned as _, boxed::Box};

use arrayref::array_ref;
use iroha_primitives::const_vec::ConstVec;
#[cfg(feature = "rand")]
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::Digest;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use super::KeyExchangeScheme;
use crate::{Error, KeyGenOption, ParseError, PrivateKey, PublicKey, SessionKey};

/// Implements the [`KeyExchangeScheme`] using X25519 key exchange and SHA256 hash function.
#[derive(Copy, Clone)]
pub struct X25519Sha256;

impl KeyExchangeScheme for X25519Sha256 {
    fn new() -> Self {
        Self
    }

    /// # Note about implementation
    ///
    /// We encode the `X25519` public key as an [`Ed25519`](PublicKey::Ed25519) public key which is
    /// a not so good idea, because we have to do extra computations and extra error handling.
    ///
    /// See #4174 for more details.
    fn keypair(&self, mut option: KeyGenOption) -> (PublicKey, PrivateKey) {
        let (pk, sk) = match option {
            #[cfg(feature = "rand")]
            KeyGenOption::Random => {
                let rng = OsRng;
                let sk = StaticSecret::random_from_rng(rng);
                let pk = X25519PublicKey::from(&sk);
                (pk, sk)
            }
            KeyGenOption::UseSeed(ref mut s) => {
                let hash = sha2::Sha256::digest(s.as_slice());
                s.zeroize();
                let rng = ChaChaRng::from_seed(*array_ref!(hash.as_slice(), 0, 32));
                let sk = StaticSecret::random_from_rng(rng);
                let pk = X25519PublicKey::from(&sk);
                (pk, sk)
            }
            KeyGenOption::FromPrivateKey(ref s) => {
                let crate::PrivateKey::Ed25519(s) = s else {
                    panic!("Wrong private key type, expected `Ed25519`, got {s:?}")
                };
                let sk = StaticSecret::from(*array_ref!(s.as_bytes(), 0, 32));
                let pk = X25519PublicKey::from(&sk);
                (pk, sk)
            }
        };

        let montgomery = curve25519_dalek::MontgomeryPoint(pk.to_bytes());
        // 0 here means the positive sign, but it doesn't matter, because in
        // `compute_shared_secret()` we convert it back to Montgomery form losing the sign.
        let edwards = montgomery
            .to_edwards(0)
            .expect("Montgomery to Edwards conversion failed");
        let edwards_compressed = edwards.compress();

        (
            PublicKey::Ed25519(
                crate::ed25519::PublicKey::from_bytes(edwards_compressed.as_bytes()).expect(
                    "Ed25519 public key should be possible to create from X25519 public key",
                ),
            ),
            PrivateKey::Ed25519(Box::new(crate::ed25519::PrivateKey::from_bytes(
                sk.as_bytes(),
            ))),
        )
    }

    fn compute_shared_secret(
        &self,
        local_private_key: &PrivateKey,
        remote_public_key: &PublicKey,
    ) -> Result<SessionKey, Error> {
        let crate::PrivateKey::Ed25519(local_private_key) = local_private_key else {
            panic!("Wrong private key type, expected `Ed25519`, got {local_private_key:?}")
        };
        let crate::PublicKey::Ed25519(remote_public_key) = remote_public_key else {
            panic!("Wrong public key type, expected `Ed25519`, got {remote_public_key:?}")
        };

        let sk = StaticSecret::from(*local_private_key.as_bytes());

        let pk_slice: &[u8; 32] = remote_public_key.as_bytes();
        let edwards_compressed =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(pk_slice)
                .expect("Ed25519 public key has 32 bytes");
        let edwards = edwards_compressed.decompress().ok_or_else(|| {
            ParseError("Invalid public key: failed to decompress edwards point".to_owned())
        })?;
        let montgomery = edwards.to_montgomery();
        let pk = X25519PublicKey::from(montgomery.to_bytes());

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
        let (public_key1, secret_key1) = scheme.keypair(KeyGenOption::Random);

        let (public_key2, secret_key2) = scheme.keypair(KeyGenOption::Random);
        let shared_secret1 = scheme
            .compute_shared_secret(&secret_key2, &public_key1)
            .unwrap();
        let shared_secret2 = scheme
            .compute_shared_secret(&secret_key1, &public_key2)
            .unwrap();
        assert_eq!(shared_secret1.payload(), shared_secret2.payload());

        let (public_key2, _secret_key1) = scheme.keypair(KeyGenOption::FromPrivateKey(secret_key1));
        assert_eq!(public_key2, public_key1);
    }
}
