//! This module provides a network layer for holding of persistent connections
//! between blockchain nodes. Also, it provides for simple use of encryption
//! to hide the data flowing between nodes.

use std::io;

use iroha_derive::FromVariant;
use iroha_error::{derive::Error, error};
pub use network::{Connect, Network, Post, Received};

mod message;
mod network;
mod peer;

/// Error types of this crate.
#[derive(Debug, FromVariant, Error)]
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
}

/// Result to use in this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;
