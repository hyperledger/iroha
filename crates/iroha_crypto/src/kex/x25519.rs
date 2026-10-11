use super::KeyExchangeScheme;
use crate::{Error, KeyGenOption, SessionKey, error::ParseError, rng::rng_from_seed};
use hkdf::Hkdf;
#[cfg(feature = "rand")]
use rand::rngs::OsRng;
#[cfg(feature = "rand")]
use rand_core::TryCryptoRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};
const HKDF_SALT: &[u8] = b"iroha:x25519:hkdf:v1";
const HKDF_INFO: &[u8] = b"iroha:x25519:session-key";
const LOW_ORDER_CHECK_PRIVATE_KEY: [u8; 32] = [1_u8; 32];
/// Implements the [`KeyExchangeScheme`] using X25519 key exchange and HKDF-SHA256 with
/// domain separation to derive the session key.
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
        option: KeyGenOption<Self::PrivateKey>,
    ) -> (Self::PublicKey, Self::PrivateKey) {
        self.try_keypair(option)
            .expect("X25519 key generation should succeed")
    }
    fn try_keypair(
        &self,
        option: KeyGenOption<Self::PrivateKey>,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), Error> {
        match option {
            #[cfg(feature = "rand")]
            KeyGenOption::Random => {
                let sk = Self::random_private_key()?;
                let pk = PublicKey::from(&sk);
                Ok((pk, sk))
            }
            KeyGenOption::UseSeed(mut s) => {
                if s.len() == Self::PRIVATE_KEY_SIZE && s.iter().all(|&byte| byte == 0) {
                    s.zeroize();
                    return Err(Error::KeyGen(
                        "X25519 seed material must not be all zero".into(),
                    ));
                }
                let mut rng = rng_from_seed(s);
                let mut bytes = Zeroizing::new([0u8; 32]);
                rand_core::RngCore::fill_bytes(&mut rng, bytes.as_mut());
                validate_private_key_material_not_all_zero("X25519 derived private key", &bytes)?;
                let sk = StaticSecret::from(*bytes);
                let pk = PublicKey::from(&sk);
                Ok((pk, sk))
            }
            KeyGenOption::FromPrivateKey(ref sk) => {
                validate_private_key_material_not_all_zero("X25519 private key", sk.as_bytes())?;
                let pk = PublicKey::from(sk);
                Ok((pk, sk.clone()))
            }
        }
    }
    fn compute_shared_secret(
        &self,
        local_private_key: &Self::PrivateKey,
        remote_public_key: &Self::PublicKey,
    ) -> Result<SessionKey, Error> {
        let sk = StaticSecret::from(*local_private_key.as_bytes());
        let shared_secret = sk.diffie_hellman(remote_public_key);
        if shared_secret.as_bytes().iter().all(|&byte| byte == 0) {
            return Err(Error::Other(
                "x25519 shared secret is all-zero (invalid public key)".into(),
            ));
        }
        // Derive a 32-byte session key via HKDF-SHA256 with fixed salt/info to
        // avoid direct use of the raw ECDH output.
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret.as_bytes());
        let mut okm = Zeroizing::new(vec![0u8; 32]);
        hkdf.expand(HKDF_INFO, okm.as_mut_slice())
            .map_err(|_| Error::Other("x25519 hkdf expansion failed".into()))?;
        Ok(SessionKey::from_zeroizing_vec(okm))
    }
    fn encode_public_key(pk: &Self::PublicKey) -> Vec<u8> {
        pk.to_bytes().to_vec()
    }
    fn decode_public_key(bytes: &[u8]) -> Result<Self::PublicKey, ParseError> {
        if bytes.len() != Self::PUBLIC_KEY_SIZE {
            return Err(ParseError(format!(
                "expected {} bytes, got {}",
                Self::PUBLIC_KEY_SIZE,
                bytes.len()
            )));
        }
        let mut array = [0u8; Self::PUBLIC_KEY_SIZE];
        array.copy_from_slice(bytes);
        let public_key = PublicKey::from(array);
        if super::is_x25519_low_order_public_key(&public_key) {
            return Err(ParseError("x25519 public key is low-order".into()));
        }
        Ok(public_key)
    }
    const SHARED_SECRET_SIZE: usize = 32;
    const PUBLIC_KEY_SIZE: usize = 32;
    const PRIVATE_KEY_SIZE: usize = 32;
}
impl X25519Sha256 {
    #[cfg(feature = "rand")]
    fn random_private_key() -> Result<StaticSecret, Error> {
        Self::random_private_key_from_rng(&mut OsRng)
    }
    #[cfg(feature = "rand")]
    fn random_private_key_from_rng<R>(rng: &mut R) -> Result<StaticSecret, Error>
    where
        R: TryCryptoRng,
    {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(bytes.as_mut())
            .map_err(|err| Error::KeyGen(format!("X25519 OS RNG failed: {err}")))?;
        validate_private_key_material_not_all_zero("X25519 OS RNG private key", &bytes)?;
        Ok(StaticSecret::from(*bytes))
    }
}
fn validate_private_key_material_not_all_zero(label: &str, bytes: &[u8; 32]) -> Result<(), Error> {
    if bytes.iter().all(|&byte| byte == 0) {
        return Err(Error::KeyGen(format!(
            "{label} material must not be all zero"
        )));
    }
    Ok(())
}
pub(super) fn is_x25519_low_order_public_key(public_key: &PublicKey) -> bool {
    let probe_secret = StaticSecret::from(LOW_ORDER_CHECK_PRIVATE_KEY);
    probe_secret
        .diffie_hellman(public_key)
        .as_bytes()
        .iter()
        .all(|&byte| byte == 0)
}
#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::EIGHT_TORSION;
    #[cfg(feature = "rand")]
    use rand_core::TryRngCore;
    #[cfg(feature = "rand")]
    struct FixedTryRng {
        byte: u8,
    }
    #[cfg(feature = "rand")]
    impl TryRngCore for FixedTryRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from_le_bytes([self.byte; 4]))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from_le_bytes([self.byte; 8]))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            dest.fill(self.byte);
            Ok(())
        }
    }
    #[cfg(feature = "rand")]
    impl TryCryptoRng for FixedTryRng {}
    fn low_order_montgomery_encodings() -> Vec<[u8; 32]> {
        let mut encodings = EIGHT_TORSION
            .iter()
            .map(|point| point.to_montgomery().0)
            .collect::<Vec<_>>();
        encodings.sort_unstable();
        encodings.dedup();
        encodings
    }
    #[test]
    fn key_exchange() {
        let scheme = X25519Sha256::new();
        let (public_key1, secret_key1) = scheme.keypair(KeyGenOption::UseSeed(
            b"iroha:test:x25519:exchange:first".to_vec(),
        ));
        let (public_key2, secret_key2) = scheme.keypair(KeyGenOption::UseSeed(
            b"iroha:test:x25519:exchange:second".to_vec(),
        ));
        let shared_secret1 = scheme
            .compute_shared_secret(&secret_key2, &public_key1)
            .expect("shared secret");
        let shared_secret2 = scheme
            .compute_shared_secret(&secret_key1, &public_key2)
            .expect("shared secret");
        assert_eq!(shared_secret1.payload(), shared_secret2.payload());
        let (public_key2, _secret_key1) = scheme.keypair(KeyGenOption::FromPrivateKey(secret_key1));
        assert_eq!(public_key2, public_key1);
    }
    #[cfg(feature = "rand")]
    #[test]
    fn try_keypair_random_derives_shared_secret() {
        let scheme = X25519Sha256::new();
        let (public_key1, secret_key1) = scheme
            .try_keypair(KeyGenOption::Random)
            .expect("checked random keypair");
        let (public_key2, secret_key2) = scheme
            .try_keypair(KeyGenOption::Random)
            .expect("checked random keypair");
        let shared_secret1 = scheme
            .compute_shared_secret(&secret_key2, &public_key1)
            .expect("shared secret");
        let shared_secret2 = scheme
            .compute_shared_secret(&secret_key1, &public_key2)
            .expect("shared secret");
        assert_eq!(shared_secret1.payload(), shared_secret2.payload());
    }
    #[cfg(feature = "rand")]
    #[test]
    fn random_private_key_from_rng_rejects_all_zero_material() {
        let mut rng = FixedTryRng { byte: 0 };
        assert!(matches!(
            X25519Sha256::random_private_key_from_rng(&mut rng),
            Err(Error::KeyGen(message)) if message.contains("all zero")
        ));
    }
    #[cfg(feature = "rand")]
    #[test]
    fn random_private_key_from_rng_accepts_nonzero_material() {
        let mut rng = FixedTryRng { byte: 0x42 };
        let secret = X25519Sha256::random_private_key_from_rng(&mut rng)
            .expect("nonzero X25519 random material must produce a secret");
        assert_ne!(secret.to_bytes(), [0u8; 32]);
    }
    #[test]
    fn hkdf_derivation_is_domain_separated() {
        let scheme = X25519Sha256::new();
        // Deterministic secrets for reproducibility.
        let sk1 = StaticSecret::from([0x11; 32]);
        let sk2 = StaticSecret::from([0x22; 32]);
        let pk1 = PublicKey::from(&sk1);
        let pk2 = PublicKey::from(&sk2);
        let session1 = scheme
            .compute_shared_secret(&sk1, &pk2)
            .expect("shared secret");
        let session2 = scheme
            .compute_shared_secret(&sk2, &pk1)
            .expect("shared secret");
        assert_eq!(session1.payload(), session2.payload());
        // Raw DH bytes must not match derived key (HKDF applied).
        let raw = sk1.diffie_hellman(&pk2);
        assert_ne!(session1.payload(), raw.as_bytes());
    }
    #[test]
    fn shared_secret_rejects_all_low_order_public_keys() {
        let scheme = X25519Sha256::new();
        let (_pk, sk) = scheme.keypair(KeyGenOption::UseSeed(vec![0x11; 32]));
        let low_order_points = low_order_montgomery_encodings();
        assert!(low_order_points.len() > 1);
        for low_order in low_order_points {
            let low_order = PublicKey::from(low_order);
            match scheme.compute_shared_secret(&sk, &low_order) {
                Err(Error::Other(message)) => assert!(message.contains("all-zero")),
                Err(other) => panic!("unexpected low-order public-key error: {other:?}"),
                Ok(_) => panic!("low-order public key must derive an all-zero secret"),
            }
        }
    }
    #[test]
    fn seeded_keypair_is_deterministic() {
        let scheme = X25519Sha256::new();
        let (public_one, private_one) = scheme
            .try_keypair(KeyGenOption::UseSeed(vec![0x42; 32]))
            .expect("first seeded keypair");
        let (public_two, private_two) = scheme
            .try_keypair(KeyGenOption::UseSeed(vec![0x42; 32]))
            .expect("second seeded keypair");
        assert_eq!(public_one, public_two);
        assert_eq!(private_one.to_bytes(), private_two.to_bytes());
    }
    #[test]
    fn seeded_keypair_rejects_all_zero_seed_material() {
        let scheme = X25519Sha256::new();
        assert!(matches!(
            scheme.try_keypair(KeyGenOption::UseSeed(vec![0u8; 32])),
            Err(Error::KeyGen(message)) if message.contains("all zero")
        ));
    }
    #[test]
    fn imported_private_key_rejects_all_zero_material() {
        let scheme = X25519Sha256::new();
        let zero_secret = StaticSecret::from([0u8; 32]);
        assert!(matches!(
            scheme.try_keypair(KeyGenOption::FromPrivateKey(zero_secret)),
            Err(Error::KeyGen(message)) if message.contains("all zero")
        ));
    }
    #[test]
    fn decode_public_key_rejects_all_low_order_public_keys() {
        let low_order_points = low_order_montgomery_encodings();
        assert!(low_order_points.len() > 1);
        for low_order in low_order_points {
            let err = X25519Sha256::decode_public_key(&low_order)
                .expect_err("low-order public key must be rejected while decoding");
            assert!(err.to_string().contains("low-order"));
        }
    }
}
