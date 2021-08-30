//! This module provides a network layer for holding of persistent connections
//! between blockchain nodes. Also, it provides for simple use of encryption
//! to hide the data flowing between nodes.

use std::{
    collections::HashSet,
    fmt::Debug,
    io::{self, ErrorKind},
    net::AddrParseError,
};

use iroha_crypto::PublicKey;
use iroha_derive::FromVariant;
use iroha_error::{derive::Error, error};
pub use network::NetworkBase;
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
    /// Connection closed
    #[error("Connection closed")]
    Closed(
        #[skip_from]
        #[skip_try_from]
        #[source]
        io::Error,
    ),
    /// Failed to read or write
    #[error("Failed IO operation")]
    Io(
        #[skip_from]
        #[skip_try_from]
        #[source]
        io::Error,
    ),
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

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if e.kind() == ErrorKind::UnexpectedEof {
            Error::Closed(e)
        } else {
            Error::Io(e)
        }
    }
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

/// Peer's identification.
pub type PeerId = iroha_data_model::peer::Id;

/// The message that is sent to [`NetworkBase`] to start connection to some other peer.
#[derive(Clone, Debug, iroha_actor::Message)]
pub struct Connect {
    /// Peer identification
    pub id: PeerId,
}

/// The message that is sent to [`NetworkBase`] to get connected peers' ids.
#[derive(Clone, Copy, Debug, iroha_actor::Message)]
#[message(result = "Connected")]
pub struct GetConnected;

/// The message that is sent from [`NetworkBase`] back as an answer to [`GetConnectedPeers`] message.
#[derive(Clone, Debug, iroha_actor::Message)]
pub struct Connected {
    /// Connected peers' ids
    pub peers: HashSet<PublicKey>,
}

/// The message to stop the network.
#[derive(Clone, Copy, Debug, iroha_actor::Message, Encode)]
pub struct Stop;

/// The message to stop the peer with included connection id.
#[derive(Clone, Debug, iroha_actor::Message, Encode)]
pub struct Disconnect(PeerId);

/// The message received from other peer.
#[derive(Clone, Debug, iroha_actor::Message, Decode)]
pub struct Received<T: Encode + Decode> {
    /// Data received from another peer
    pub data: T,
    /// Peer identification
    pub id: PeerId,
}

/// The message to be sent to some other peer.
#[derive(Clone, Debug, iroha_actor::Message, Encode)]
pub struct Post<T: Encode + Debug> {
    /// Data to send to another peer
    pub data: T,
    /// Peer identification
    pub id: PeerId,
}
