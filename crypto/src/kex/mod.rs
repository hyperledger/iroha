//! A suite of Diffie-Hellman key exchange methods.
//!
//! [`X25519Sha256`] is the only key exchange scheme currently supported,
//! as it is the only one used by the iroha p2p transport protocol.

mod x25519;

pub use x25519::X25519Sha256;

use crate::{Error, KeyGenOption, PrivateKey, PublicKey, SessionKey};

/// A Generic trait for key exchange schemes. Each scheme provides a way to generate keys and
/// do a diffie-hellman computation
pub trait KeyExchangeScheme {
    /// Generate a new instance of the scheme
    fn new() -> Self;

    /// Create new keypairs. If
    /// - `options` is [`Random`](KeyGenOption::Random), the keys are generated ephemerally from the [`OsRng`](rand::rngs::OsRng)
    /// - `options` is [`UseSeed`](KeyGenOption::UseSeed), the keys are generated ephemerally from the sha256 hash of the seed which is
    ///     then used to seed the [`ChaChaRng`](rand_chacha::ChaChaRng)
    /// - `options` is [`FromPrivateKey`](KeyGenOption::FromPrivateKey), the corresponding public key is returned. This should be used for
    ///     static Diffie-Hellman and loading a long-term key.
    fn keypair(&self, options: KeyGenOption) -> (PublicKey, PrivateKey);

    /// Compute the diffie-hellman shared secret.
    /// `local_private_key` is the key generated from calling `keypair` while
    /// `remote_public_key` is the key received from a different call to `keypair` from another party.
    ///
    /// # Errors
    ///
    /// Returns an error if the computation fails, i.e. remote key is invalid.
    fn compute_shared_secret(
        &self,
        local_private_key: &PrivateKey,
        remote_public_key: &PublicKey,
    ) -> Result<SessionKey, Error>;

    /// Size of the shared secret in bytes.
    const SHARED_SECRET_SIZE: usize;
    /// Size of the public key in bytes.
    const PUBLIC_KEY_SIZE: usize;
    /// Size of the private key in bytes.
    const PRIVATE_KEY_SIZE: usize;
}
