//! This module provides a network layer for holding of persistent
//! connections between blockchain nodes. Sane defaults for secure
//! Cryptography are chosen in this module, and encapsulated.

use std::{io, net::AddrParseError};

use iroha_crypto::ursa::{
    encryption::symm::prelude::ChaCha20Poly1305, kex::x25519::X25519Sha256, CryptoError,
};
pub use network::{ConnectPeer, DisconnectPeer, NetworkBase, Post};
use parity_scale_codec::{Decode, Encode};
use thiserror::Error;

/// Network is a main p2p start point.
pub mod network;
/// Peer is an endpoint to another node.
pub mod peer;

/// The main type to use for secure communication.
pub type Network<T> = NetworkBase<T, X25519Sha256, ChaCha20Poly1305>;

/// Errors used in [`crate`].
#[derive(Clone, Debug, iroha_macro::FromVariant, Error, iroha_actor::Message)]
pub enum Error {
    /// Failed to read or write
    #[error("Failed IO operation.")]
    Io(#[source] std::sync::Arc<io::Error>),
    /// Failed to read or write
    #[error("{0}: Failed handshake")]
    Handshake(u32),
    /// Failed to read or write
    #[error("Message improperly formatted")]
    Format,
    /// Failed to create keys
    #[error("Failed to create session key")]
    Keys,
    /// Failed to parse address
    #[error("Failed to parse socket address.")]
    Addr(#[source] AddrParseError),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(std::sync::Arc::new(e))
    }
}

impl From<parity_scale_codec::Error> for Error {
    fn from(_: parity_scale_codec::Error) -> Self {
        Self::Keys
    }
}

impl From<CryptoError> for Error {
    fn from(_: CryptoError) -> Self {
        Self::Keys
    }
}

impl From<aead::Error> for Error {
    fn from(_: aead::Error) -> Self {
        Self::Keys
    }
}

/// Result shorthand.
pub type Result<T, E = Error> = std::result::Result<T, E>;

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
