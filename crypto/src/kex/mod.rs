//! A suite of Diffie-Hellman key exchange methods.
//!
//! [`X25519Sha256`] is the only key exchange scheme currently supported,
//! as it is the only one used by the iroha p2p transport protocol.

mod x25519;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub use x25519::X25519Sha256;

use crate::{error::ParseError, KeyGenOption, SessionKey};

/// A Generic trait for key exchange schemes. Each scheme provides a way to generate keys and
/// do a diffie-hellman computation
pub trait KeyExchangeScheme {
    /// Public key used by the scheme.
    type PublicKey: Send;
    /// Private key used by the scheme.
    type PrivateKey: Send;

    /// Generate a new instance of the scheme.
    fn new() -> Self;

    /// Create new keypairs. If
    /// - `options` is [`Random`](KeyGenOption::Random), the keys are generated ephemerally from the [`OsRng`](rand::rngs::OsRng)
    /// - `options` is [`UseSeed`](KeyGenOption::UseSeed), the keys are generated ephemerally from the sha256 hash of the seed which is
    ///     then used to seed the [`ChaChaRng`](rand_chacha::ChaChaRng)
    /// - `options` is [`FromPrivateKey`](KeyGenOption::FromPrivateKey), the corresponding public key is returned. This should be used for
    ///     static Diffie-Hellman and loading a long-term key.
    fn keypair(
        &self,
        options: KeyGenOption<Self::PrivateKey>,
    ) -> (Self::PublicKey, Self::PrivateKey);

    /// Compute the diffie-hellman shared secret.
    /// `local_private_key` is the key generated from calling `keypair` while
    /// `remote_public_key` is the key received from a different call to `keypair` from another party.
    fn compute_shared_secret(
        &self,
        local_private_key: &Self::PrivateKey,
        remote_public_key: &Self::PublicKey,
    ) -> SessionKey;

    /// Get byte representation of a public key.
    //
    // TODO: Return `[u8; Self::PUBLIC_KEY_SIZE]` after https://github.com/rust-lang/rust/issues/76560
    fn encode_public_key(pk: &Self::PublicKey) -> &[u8];

    /// Decode public key from byte representation.
    ///
    /// # Errors
    ///
    /// Any error during key decoding, e.g. wrong `bytes` length.
    //
    // TODO: Accept `[u8; Self::PUBLIC_KEY_SIZE]` after https://github.com/rust-lang/rust/issues/76560
    fn decode_public_key(bytes: Vec<u8>) -> Result<Self::PublicKey, ParseError>;

    /// Size of the shared secret in bytes.
    const SHARED_SECRET_SIZE: usize;
    /// Size of the public key in bytes.
    const PUBLIC_KEY_SIZE: usize;
    /// Size of the private key in bytes.
    const PRIVATE_KEY_SIZE: usize;
}
