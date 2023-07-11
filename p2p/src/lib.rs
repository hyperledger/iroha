//! This module provides a network layer for holding of persistent
//! connections between blockchain nodes. Sane defaults for secure
//! Cryptography are chosen in this module, and encapsulated.
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]
use std::{io, net::AddrParseError};

use iroha_crypto::ursa::{
    blake2::{
        digest::{Update, VariableOutput},
        VarBlake2b,
    },
    encryption::symm::prelude::ChaCha20Poly1305,
    kex::x25519::X25519Sha256,
    CryptoError,
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
#[derive(Debug, Error, displaydoc::Display)]
pub enum Error {
    /// Failed IO operation
    Io(#[source] std::sync::Arc<io::Error>),
    /// Message improperly formatted
    Format,
    /// Field is not defined for a peer at this stage
    Field,
    /// Parity Scale codec error
    ParityScale(#[from] parity_scale_codec::Error),
    /// Failed to create keys
    Keys(#[source] CryptographicError),
    /// Failed to parse socket address
    Addr(#[from] AddrParseError),
    /// Connection reset by peer in the middle of message transfer
    ConnectionResetByPeer,
}

/// Error in the cryptographic processes.
#[derive(derive_more::From, Debug, Error, displaydoc::Display)]
pub enum CryptographicError {
    /// Decryption failed
    #[from(ignore)]
    Decrypt(aead::Error),
    /// Encryption failed
    #[from(ignore)]
    Encrypt(aead::Error),
    /// Ursa Cryptography error
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

    pub struct Sender<T> {
        sender: mpsc::UnboundedSender<T>,
        len: Arc<AtomicUsize>,
    }

    impl<T> Clone for Sender<T> {
        fn clone(&self) -> Self {
            Self {
                sender: self.sender.clone(),
                len: self.len.clone(),
            }
        }
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

/// Create Blake2b hash as u64 value
pub fn blake2b_hash(slice: impl AsRef<[u8]>) -> u64 {
    const U64_SIZE: usize = core::mem::size_of::<u64>();
    let hash = VarBlake2b::new(U64_SIZE)
        .expect("Failed to create hash with given length")
        .chain(&slice)
        .finalize_boxed();
    let mut bytes = [0; U64_SIZE];
    bytes.copy_from_slice(&hash);
    u64::from_be_bytes(bytes)
}
