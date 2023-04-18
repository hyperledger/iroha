//! This module provides a network layer for holding of persistent
//! connections between blockchain nodes. Sane defaults for secure
//! Cryptography are chosen in this module, and encapsulated.
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]
use std::{io, net::AddrParseError};

use iroha_crypto::ursa::{
    encryption::symm::prelude::ChaCha20Poly1305, kex::x25519::X25519Sha256, CryptoError,
};
pub use network::message::*;
use parity_scale_codec::{Decode, Encode};
use thiserror::Error;

pub mod network;
pub mod peer;

/// The main type to use for secure communication.
pub type NetworkHandle<T> = network::NetworkBaseHandle<T, X25519Sha256, ChaCha20Poly1305>;

pub mod boilerplate {
    //! Module containing trait shorthands. Remove when trait aliases
    //! are stable <https://github.com/rust-lang/rust/issues/41517>

    use iroha_crypto::ursa::{encryption::symm::Encryptor, kex::KeyExchangeScheme};

    use super::*;

    /// Shorthand for traits required for payload
    pub trait Pload: Encode + Decode + Send + Clone + 'static {}
    impl<T> Pload for T where T: Encode + Decode + Send + Clone + 'static {}

    /// Shorthand for traits required for key exchange
    pub trait Kex: KeyExchangeScheme + Send + 'static {}
    impl<T> Kex for T where T: KeyExchangeScheme + Send + 'static {}

    /// Shorthand for traits required for encryptor
    pub trait Enc: Encryptor + Send + 'static {}
    impl<T> Enc for T where T: Encryptor + Send + 'static {}
}

/// Errors used in [`crate`].
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to read or write
    #[error("Failed IO operation: {0}.")]
    Io(#[source] std::sync::Arc<io::Error>),
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
    /// Connection reset by peer
    #[error("Connection reset by peer in te middle of message transfer.")]
    ConnectionResetByPeer,
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

/// Module for unbounded channel with attached length of the channel.
pub(crate) mod unbounded_with_len {
    use std::sync::{atomic::AtomicUsize, Arc};

    use tokio::sync::mpsc;

    /// Create unbounded channel with attached length.
    pub fn unbounded_channel<T>() -> (Sender<T>, Receiver<T>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let len = Arc::new(AtomicUsize::new(1));
        (
            Sender {
                sender,
                len: Arc::clone(&len),
            },
            Receiver { receiver, len },
        )
    }

    pub struct Receiver<T> {
        receiver: mpsc::UnboundedReceiver<T>,
        len: Arc<AtomicUsize>,
    }

    #[derive(Clone)]
    pub struct Sender<T> {
        sender: mpsc::UnboundedSender<T>,
        len: Arc<AtomicUsize>,
    }

    impl<T> Receiver<T> {
        pub async fn recv(&mut self) -> Option<T>
        where
            T: Send,
        {
            let message = self.receiver.recv().await?;
            self.len.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            Some(message)
        }

        pub fn len(&self) -> usize {
            self.len
                .load(std::sync::atomic::Ordering::SeqCst)
                .saturating_sub(1)
        }
    }

    impl<T> Sender<T> {
        pub fn send(&self, message: T) -> Result<(), mpsc::error::SendError<T>> {
            self.sender.send(message)?;
            self.len.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }
}
