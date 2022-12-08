//! This module provides a network layer for holding of persistent
//! connections between blockchain nodes. Sane defaults for secure
//! Cryptography are chosen in this module, and encapsulated.
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]
use std::{io, net::AddrParseError};

use iroha_crypto::ursa::{
    encryption::symm::prelude::ChaCha20Poly1305, kex::x25519::X25519Sha256, CryptoError,
};
pub use network::{ConnectPeer, DisconnectPeer, NetworkBase, Post};
use parity_scale_codec::{Decode, Encode};
use thiserror::Error;

pub mod handshake;
pub mod network;
pub mod peer;

/// The main type to use for secure communication.
pub type Network<T> = NetworkBase<T, X25519Sha256, ChaCha20Poly1305>;

/// Errors used in [`crate`].
#[derive(Debug, Error, iroha_actor::Message)]
pub enum Error {
    /// Failed to read or write
    #[error("Failed IO operation.")]
    Io(#[source] std::sync::Arc<io::Error>),
    /// Failed to read or write
    #[error("Failed handshake")]
    Handshake(#[from] HandshakeError),
    /// Failed to read or write
    #[error("Message improperly formatted")]
    Format,
    /// Field is not defined for a peer at this stage
    #[error("Field is not defined for a peer at this stage")]
    Field,
    /// Parity Scale codec error
    #[error("Parity Scale codec error")]
    ParityScale(#[from] parity_scale_codec::Error),
    /// Failed to create keys
    #[error("Failed to create session key")]
    Keys(#[source] CryptographicError),
    /// Failed to parse address
    #[error("Failed to parse socket address.")]
    Addr(#[from] AddrParseError),
}

/// Error during handshake process.
#[derive(Debug, Error, Clone)]
pub enum HandshakeError {
    /// Peer was in an incorrect state
    #[error("Peer was in an incorrect state. {0}")]
    State(String),
    /// Handshake Length
    #[error("Handshake Length {0} exceeds maximum: {}", peer::MAX_HANDSHAKE_LENGTH)]
    Length(usize),
}

/// Error in the cryptographic processes.
#[derive(derive_more::From, Debug, Error)]
pub enum CryptographicError {
    /// Decryption failed
    #[error("Decryption failed")]
    #[from(ignore)]
    Decrypt(aead::Error),
    /// Encryption failed
    #[error("Encryption failed")]
    #[from(ignore)]
    Encrypt(aead::Error),
    /// Ursa Cryptography error
    #[error("Ursa Cryptography error")]
    Ursa(CryptoError),
}

impl<T: Into<CryptographicError>> From<T> for Error {
    fn from(err: T) -> Self {
        Self::Keys(err.into())
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(std::sync::Arc::new(e))
    }
}

/// Result shorthand.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Message read from the other peer, serialized into bytes
#[derive(Debug, Clone, Encode, Decode, iroha_actor::Message)]
pub struct Message(pub Vec<u8>);

/// Result of reading from [`peer::Peer`]
#[derive(Debug, iroha_actor::Message)]
pub struct MessageResult(pub Result<Message, Error>);

impl MessageResult {
    /// Constructor for positive result
    pub const fn new_message(message: Message) -> Self {
        Self(Ok(message))
    }

    /// Constructor for negative result
    pub const fn new_error(error: Error) -> Self {
        Self(Err(error))
    }
}
