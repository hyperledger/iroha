//! This module provides a network layer for holding of persistent
//! connections between blockchain nodes. Sane defaults for secure
//! Cryptography are chosen in this module, and encapsulated.

use std::{io, net::AddrParseError};

use iroha_crypto::ursa::{encryption::symm::prelude::ChaCha20Poly1305, kex::x25519::X25519Sha256};
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
#[derive(Clone, Debug, Error, iroha_actor::Message)]
pub enum Error {
    /// Failed to read or write
    #[error("Failed IO operation.")]
    Io(#[from] std::sync::Arc<io::Error>),
    /// Failed to read or write
    #[error("Failed handshake")]
    Handshake(#[from] HandshakeError),
    /// Failed to read or write
    #[error("Message improperly formatted")]
    Format,
    /// Failed to create keys.
    #[error("Failed to create session key, or generate new key-pair.")]
    Keys,
    /// Failed to decode
    #[error("Failed to decode object using parity scale codec")]
    Decode(#[from] parity_scale_codec::Error),
    /// Failed to parse address
    #[error("Failed to parse socket address.")]
    Addr(#[from] AddrParseError),
}

/// Error which occurs in the handshake process specifically.
#[derive(Clone, Copy, Debug, Error, iroha_actor::Message)]
pub enum HandshakeError {
    /// Failure when sending client `hello`.
    #[error("Failure when sending client `hello` message")]
    SendHello,
    /// Failure when reading client `hello`.
    #[error("Failure when sending client `hello` message")]
    ReadHello,
    /// Peer has been disconnected
    #[error("Peer disconnected.")]
    Disconnected,
    /// Peer in broken state with Error.
    #[error("Peer is in a broken state.")]
    BrokenPeer,
    /// Peer is not in the correct state, but it should be.
    #[error("Peer is not in the correct state. This should never happen. ")]
    WrongState,
    /// Too much data in read half
    #[error("The read half of the connection has too much data. Expected")]
    TooLong(usize, usize),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(std::sync::Arc::new(e))
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
