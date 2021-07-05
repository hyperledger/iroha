//! This module provides a network layer for holding of persistent connections
//! between blockchain nodes. Also, it provides for simple use of encryption
//! to hide the data flowing between nodes.

use std::{io, net::AddrParseError};

use iroha_derive::FromVariant;
use iroha_error::{derive::Error, error};
pub use network::{Connect, Network, Post, Received};
use parity_scale_codec::{Decode, Encode};

mod network;
mod peer;

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

#[derive(Debug, Clone, Encode, Decode, iroha_actor::Message)]
pub(crate) struct Message(pub Vec<u8>);

#[derive(Debug, iroha_actor::Message)]
pub(crate) struct MessageResult(pub Result<Message, Error>);

impl MessageResult {
    pub const fn new_message(message: Message) -> Self {
        Self(Ok(message))
    }

    pub const fn new_error(error: Error) -> Self {
        Self(Err(error))
    }
}
