//! This module provides a network layer for holding of persistent connections
//! between blockchain nodes. Also, it provides for simple use of encryption
//! to hide the data flowing between nodes.

use std::{io, net::AddrParseError};

use iroha_derive::FromVariant;
use iroha_error::{derive::Error, error};
pub use network::{ConnectPeer, NetworkBase, Post};
use parity_scale_codec::{Decode, Encode};
use ursa::{encryption::symm::prelude::ChaCha20Poly1305, kex::x25519::X25519Sha256};

/// Network is a main p2p start point.
pub mod network;
/// Peer is an endpoint to another node.
pub mod peer;

/// The main type to use for secure communication.
pub type Network<T> = NetworkBase<T, X25519Sha256, ChaCha20Poly1305>;

/// Error types of this crate.
#[derive(Debug, FromVariant, Error, iroha_actor::Message)]
pub enum Error {
    /// Failed to read or write
    #[error("Failed IO operation")]
    Io(#[source] io::Error),
    /// Failed to read or write
    #[error("Failed handshake")]
    Handshake,
    /// Failed to read or write
    #[error("Failed reading message")]
    Format,
    /// Failed to create keys
    #[error("Failed to create session key")]
    Keys,
    /// Failed to parse address
    #[error("Failed to parse socket address")]
    Addr(#[source] AddrParseError),
}

/// Result to use in this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Any message read from other peer, serialized to bytes
#[derive(Debug, Clone, Encode, Decode, iroha_actor::Message)]
pub struct Message(pub Vec<u8>);

/// Read result from any peer
#[derive(Debug, iroha_actor::Message)]
pub struct MessageResult(pub Result<Message, Error>);

impl MessageResult {
    /// Convenience constructor for positive result
    pub const fn new_message(message: Message) -> Self {
        Self(Ok(message))
    }

    /// Convenience constructor for negative result
    pub const fn new_error(error: Error) -> Self {
        Self(Err(error))
    }
}
