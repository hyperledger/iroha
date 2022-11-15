//! P2P communication logic and exchange mechanisms. This is where the
//! handshake process is defined.
#![allow(unsafe_code, clippy::redundant_else)]

use core::marker::PhantomData;
use eyre::WrapErr as _;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs},
    sync::{atomic::Ordering, Arc, Mutex},
    time::Duration,
};

use iroha_crypto::{
    ursa::{
        encryption::symm::{prelude::ChaCha20Poly1305, Encryptor, SymmetricEncryptor},
        kex::{x25519::X25519Sha256, KeyExchangeScheme},
        keys::{PrivateKey as UrsaPrivateKey, PublicKey as UrsaPublicKey},
        CryptoError,
    },
    PublicKey,
};
use iroha_logger::{error, info, trace};
use parity_scale_codec::{Decode, Encode};
use rand::{Rng, RngCore};
use std::time::Instant;
use thiserror::Error;

use crate::{
    handler::ThreadHandler,
    NetworkMessage::{self, *},
    PeerId,
};

/// Errors used in `p2p`.
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to read or write
    #[error("Failed IO operation.")]
    Io(#[source] std::sync::Arc<std::io::Error>),
    /// Failed to read or write
    #[error("Failed handshake")]
    Handshake(#[from] HandshakeError),
    /// Parity Scale codec error
    #[error("Parity Scale codec error")]
    ParityScale(#[from] parity_scale_codec::Error),
    /// Failed to create keys
    #[error("Failed to create session key")]
    Keys(#[source] CryptographicError),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(std::sync::Arc::new(e))
    }
}

/// Error in the cryptographic processes.
#[derive(Debug, Error)]
pub enum CryptographicError {
    /// Decryption failed
    #[error("Decryption failed")]
    Decrypt(aead::Error),
    /// Encryption failed
    #[error("Encryption failed")]
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

/// Error during handshake process.
#[derive(Debug, Error, Clone)]
pub enum HandshakeError {
    /// Peer was in an incorrect state
    #[error("Peer was in an incorrect state. {0}")]
    State(String),
    /// Handshake Length
    #[error("Handshake Length {0} exceeds maximum: {}", MAX_HANDSHAKE_LENGTH)]
    Length(usize),
}

/// Max length of message handshake in bytes.
pub const MAX_HANDSHAKE_LENGTH: usize = 255;
/// Default associated data for AEAD
/// [`Authenticated encryption`](https://en.wikipedia.org/wiki/Authenticated_encryption)
pub const DEFAULT_AAD: &[u8; 10] = b"Iroha2 AAD";

/// The timemout used to judge if the TCP connection is live or not.
pub const P2P_TCP_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1500);

/// A general purpose packet buffer.
pub struct PacketBuffer {
    sumeragi_packet_buffer: Vec<crate::SumeragiPacket>,
    block_sync_message_buffer: Vec<crate::BlockSyncMessage>,
}

/// A catch-all structure to handle context of the Peer-to-peer communication.
pub struct P2PSystem {
    /// The listening address that needs to be resolved
    listen_addr: String,
    /// The public key of this peer.
    public_key: PublicKey,
    /// The peers that need to be connected to,
    connect_peer_target: Mutex<Vec<PeerId>>,
    /// Peers for which the connection has already been established accessible via `PublicKey` → triplet map.
    connected_to_peers: Mutex<HashMap<PublicKey, (TcpStream, Cryptographer, Instant)>>,
    /// The index of the peer that needs to be polled, which controls how `block_sync` works.
    poll_network_index: std::sync::atomic::AtomicU32,
    /// A buffer containing both [`crate::SumeragiPacket`]s and [`crate::BlockSyncMessage`]s.
    packet_buffers: Mutex<PacketBuffer>,
}

impl P2PSystem {
    /// Convenience getter for connected to peers' keys.
    ///
    /// # Panics
    /// On [`Mutex`] poisoning
    #[allow(clippy::expect_used)]
    #[inline]
    pub fn get_connected_to_peer_keys(&self) -> Vec<PublicKey> {
        self.connected_to_peers
            .lock()
            .expect("Mutex poisoned")
            .keys()
            .cloned()
            .collect()
    }

    /// [`Self`] constructor
    #[inline]
    pub fn new(listen_addr: String, public_key: PublicKey) -> Arc<P2PSystem> {
        Arc::new(P2PSystem {
            listen_addr,
            public_key,
            connect_peer_target: Mutex::new(Vec::new()),
            connected_to_peers: Mutex::new(HashMap::new()),
            poll_network_index: std::sync::atomic::AtomicU32::new(0),
            packet_buffers: Mutex::new(PacketBuffer {
                sumeragi_packet_buffer: Vec::new(),
                block_sync_message_buffer: Vec::new(),
            }),
        })
    }

    /// Poll the network for block sync message.
    ///
    /// # Panics
    /// - Mutex poisoning.
    #[allow(
        clippy::expect_used,
        clippy::unwrap_in_result,
        clippy::panic,
        clippy::cognitive_complexity
    )]
    pub fn poll_network_for_block_sync_message(&self) -> Option<crate::BlockSyncMessage> {
        let PacketBuffer {
            ref mut sumeragi_packet_buffer,
            ref mut block_sync_message_buffer,
        } = *self.packet_buffers.lock().expect("Mutex poisoned");

        if !block_sync_message_buffer.is_empty() {
            iroha_logger::debug!("Early return");
            return Some(block_sync_message_buffer.remove(0));
        }

        let mut send_connection_ack_keys = Vec::new();
        let mut received = None;
        {
            let mut connected_to_peers = self.connected_to_peers.lock().expect("Mutex poisoned");
            let mut values: Vec<_> = connected_to_peers.iter_mut().collect();
            let value_len = values.len();

            let mut to_disconnect_keys = Vec::new();

            for _ in 0..value_len {
                let poll_network_index = self.poll_network_index.load(Ordering::SeqCst);
                let (public_key, (stream, crypto, last_connection_check)) =
                    &mut values[poll_network_index as usize % value_len];
                self.poll_network_index
                    .store(poll_network_index.wrapping_add(1), Ordering::SeqCst);

                if last_connection_check.elapsed().as_secs() > 5 {
                    to_disconnect_keys.push(public_key.clone());
                }

                match read_from_socket(stream, crypto) {
                    None | Some(Health) => (),
                    Some(NetworkMessage::SumeragiPacket(packet)) => sumeragi_packet_buffer.push(*packet),
                    Some(NetworkMessage::BlockSync(message)) => {
                        received = Some(*message);
                        break;
                    }
                    Some(ConnectionCheck(_)) => send_connection_ack_keys.push(public_key.clone()),
                    Some(ConnectionCheckAck(_)) => *last_connection_check = Instant::now(),
                }
            }
            self.disconnect_peers(to_disconnect_keys);
        }
        self.post_to_network(&ConnectionCheckAck(42), &send_connection_ack_keys);

        received
    }

    /// TODO: make sure stupid stuff isn't done here.
    #[allow(clippy::cognitive_complexity, clippy::expect_used, clippy::unwrap_in_result)]
    pub fn poll_network_for_sumeragi_packet(&self) -> Option<crate::SumeragiPacket> {
        let PacketBuffer {
            ref mut sumeragi_packet_buffer,
            ref mut block_sync_message_buffer,
        } = *self.packet_buffers.lock().expect("Mutex poisoned");

        if sumeragi_packet_buffer.is_empty() {
            let mut connected_to_peers = self.connected_to_peers.lock().expect("Mutex poisoned");
            let mut values: Vec<_> = connected_to_peers.iter_mut().collect();
            let value_len = values.len();

            let mut send_connection_ack_keys = Vec::new();
            let mut to_disconnect_keys = Vec::new();

            for _ in 0..values.len() {
                let poll_network_index = self.poll_network_index.load(Ordering::SeqCst);

                let (public_key, (stream, crypto, last_connection_check)): &mut (
                    &PublicKey,
                    &mut (TcpStream, Cryptographer, Instant),
                ) = &mut values[poll_network_index as usize % value_len];
                self.poll_network_index
                    .store(poll_network_index.wrapping_add(1), Ordering::SeqCst);

                if last_connection_check.elapsed().as_secs() > 5 {
                    to_disconnect_keys.push(public_key.clone());
                }

                match read_from_socket(stream, crypto) {
                    None | Some(Health) => (),
                    Some(NetworkMessage::SumeragiPacket(_)) => break,
                    Some(NetworkMessage::BlockSync(message)) => {
                        block_sync_message_buffer.push(*message)
                    }
                    Some(ConnectionCheck(_)) => send_connection_ack_keys.push(public_key.clone()),
                    Some(ConnectionCheckAck(_)) => *last_connection_check = Instant::now(),
                }
            }
            self.disconnect_peers(to_disconnect_keys);
            drop(connected_to_peers);
            self.post_to_network(&ConnectionCheckAck(42), &send_connection_ack_keys);
            None
        } else {
            iroha_logger::debug!("Early return. Buffer empty");
            Some(sumeragi_packet_buffer.remove(0))
        }
    }

    ///
    /// # Panics
    /// - Mutex poisoning
    /// - Connected to peers doesn't contain the key to be removed.
    #[allow(clippy::expect_used)]
    pub fn post_to_network(&self, message: &NetworkMessage, recipients: &[PublicKey]) {
        let to_disconnect_keys: Vec<_> = recipients.iter().filter(|public_key| {
            if let Some((ref mut stream, ref crypto, _)) = self.connected_to_peers.lock().expect("Mutex poisoned").get_mut(public_key) {
                let encrypted = crypto
                    .encrypt(message.encode())
                    .expect("We should always be able to encrypt.");
                let write1 = stream.write_all(&(u32::try_from(encrypted.len()).expect("Encrypted len doesn't fit in a `u32`. Violation of this invariant signals a programmer error")).to_le_bytes());
                let write2 = stream.write_all(&encrypted);

                if write1.is_err() || write2.is_err() {
                    error!(
                        "Disconecting, cause: Could not post message to peer {}.",
                        public_key
                    );
                    true
                } else {
                    false
                }
            } else {
                trace!("P2P post failed: Not connected.");
                false
            }
        }).cloned().collect();
        self.disconnect_peers(to_disconnect_keys);
    }

    #[allow(clippy::expect_used)]
    fn disconnect_peers(&self, to_disconnect_keys: Vec<PublicKey>) {
        for key in to_disconnect_keys {
            info!("Disconnecting from: {}", &key);
            if let Err(e) =  self.connected_to_peers
                .lock()
                .expect("Mutex poisoned")
                .remove(&key)
                .expect("The key in `to_disconnect_peers` was not found in `connected_to_peers`. It's unsafe to keep Iroha running. Bailing out. ")
                .0
                .shutdown(Shutdown::Both) {
                    iroha_logger::debug!(%e);
                }
        }
    }

    /// Post the [`sumeragi_packet`] to `self.packet_buffers`
    #[allow(clippy::expect_used)]
    pub fn post_to_own_sumeragi_buffer(&self, sumeragi_packet: crate::SumeragiPacket) {
        self.packet_buffers
            .lock()
            .expect("Mutex poisoned")
            .sumeragi_packet_buffer
            .push(sumeragi_packet);
    }

    // TODO Docs.
    ///
    /// # Panics
    ///
    /// If the `connected_to_peers` was modified externally and a peer
    /// key wasn't found. This should not happen unless you messed up
    /// the code by ignoring the `Mutex`.
    #[allow(clippy::expect_used)]
    pub fn update_peer_target(&self, new_target: &[PeerId]) {
        let mut target = self.connect_peer_target.lock().expect("Mutex poisoned"); // TODO: This Mutex has to go
        *target = new_target
            .iter()
            .filter(|peer_id| peer_id.public_key != self.public_key)
            .cloned()
            .collect();
        // TODO: filter
        let to_disconnect_keys = self
            .connected_to_peers
            .lock()
            .expect("Valid")
            .keys()
            .filter(|public_key| !target.iter().any(|id| id.public_key == **public_key))
            .cloned()
        // The lock gets released marginally later, but the overall process is less work
            .collect();
        // Release lock here
        self.disconnect_peers(to_disconnect_keys);
    }
}

// TODO: Refactor to return result instead.
fn read_from_socket(stream: &mut TcpStream, crypto: &Cryptographer) -> Option<NetworkMessage> {
    let mut packet_size = 0;
    while packet_size == 0 {
        let mut null_byte = 0_u8;
        // TODO: Maybe fixed number of retries
        while let Err(error) = stream.set_nonblocking(true) {
            iroha_logger::warn!(?error, "Unable to set the TCP stream to non-blocking. Retrying. If this persists, please stop the peer manually (with `Ctrl+C`) and investigate the port settings.")
        }
        let byte_count_maybe = stream.peek(std::slice::from_mut(&mut null_byte));
        while let Err(error) = stream.set_nonblocking(false) {
            iroha_logger::warn!(?error, "Unable to set the TCP stream to non-blocking. Retrying. If this persists, please stop the peer manually (with `Ctrl+C`) and investigate the port settings.")
        }
        let byte_count = byte_count_maybe.ok()?;
        (byte_count != 0).then_some(())?;
        let mut packet_size_buf = [0_u8; 4];
        stream.read_exact(&mut packet_size_buf).ok()?;
        packet_size = u32::from_le_bytes(packet_size_buf);
    }

    let mut buf = vec![0_u8; packet_size as usize];
    stream.read_exact(&mut buf).ok()?;
    let data = crypto.decrypt(buf).ok()?;
    let network_message = Decode::decode(&mut data.as_slice()).ok()?;
    Some(network_message)
}

/// Initialise the listening loop of the p2p system.
///
/// # Panics
/// If failed to spawn a thread handler.
#[allow(clippy::expect_used)]
pub fn start_listen_loop(p2p: Arc<P2PSystem>) -> ThreadHandler {
    // Oneshot channel to allow forcefully stopping the thread.
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();

    let thread_handle = std::thread::Builder::new()
        .name("P2P Listen Thread".to_owned())
        .spawn(move || {
            p2p_listen_loop(&p2p, shutdown_receiver);
        })
        .expect("Failed to spawn thread for listen loop. This is a host-specific problem caused by the OS");

    ThreadHandler::new(
        Box::new(move || {
            let _result = shutdown_sender.send(());
        }),
        thread_handle,
    )
}

// nocheckin do maps
#[allow(clippy::unsafe_code, clippy::unwrap_used, clippy::expect_used, clippy::cognitive_complexity)]
fn p2p_listen_loop(p2p: &P2PSystem, mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>) {
    let listener = TcpListener::bind(&p2p.listen_addr).expect("Could not bind p2p tcp listener.");
    listener
        .set_nonblocking(true)
        .expect("P2P subsystem could not enable nonblocking on listening tcp port.");
    let mut instant_last_sent_connection_check = Instant::now();
    loop {
        if shutdown_receiver.try_recv() == Ok(()) {
            break;
        }
        update_last_connection_check_instant(&mut instant_last_sent_connection_check, p2p);
        // SAFETY:
        //
        // This function is generally safe to call once only.
        // consult `[@appetrosyan, @samhsmith, @mversic, @Erigara]`
        let connection = unsafe {
            establish_new_connection(p2p, &listener).map(|strm| perform_handshake(p2p, strm))
        };
        if let Some(Ok((stream, crypto, other_public_key))) = connection {
            if !p2p
                .connect_peer_target
                .lock()
                .expect("Mutex poisoned")
                .iter()
                .any(|peer_id| peer_id.public_key == other_public_key)
            {
                trace!("Dropping because not in target, {}.", other_public_key);
            } else if p2p
                .connected_to_peers
                .lock()
                .expect("Mutex poisoned")
                .keys()
                .any(|key| *key == other_public_key)
            {
                trace!("Dropping because already connected, {}.", other_public_key);
            } else {
                establish_connection(p2p, crypto, stream, other_public_key.clone()).unwrap_or_else(
                    |e| {
                        iroha_logger::debug!(?e, "Error establishing connection");
                        error!(
                            "Connecting to peer failed in final step, {}.",
                            other_public_key
                        );
                    },
                )
            }
        }
    }
    info!("P2P listen thread is being shut down");
}

#[allow(clippy::expect_used)]
fn update_last_connection_check_instant(
    instant_last_sent_connection_check: &mut Instant,
    p2p: &P2PSystem,
) {
    std::thread::sleep(Duration::from_millis((rand::random::<u64>() % 10) + 10));
    // TODO: This isn't an arbitrary time step.
    if instant_last_sent_connection_check.elapsed().as_secs() > 2 {
        p2p.post_to_network(
            &NetworkMessage::ConnectionCheck(42),
            &p2p.connect_peer_target
                .lock()
                .expect("Mutex poisoned")
                .iter()
                .map(|peer_id| peer_id.public_key.clone())
                .collect::<Vec<_>>(),
        );
        *instant_last_sent_connection_check = Instant::now();
    }
}

// TODO: better name
fn establish_connection(
    p2p: &P2PSystem,
    crypto: Cryptographer,
    mut stream: TcpStream,
    other_public_key: PublicKey,
) -> eyre::Result<()> {
    #![allow(clippy::expect_used, clippy::cast_possible_truncation)]
    let encrypted = crypto
        .encrypt(NetworkMessage::ConnectionCheck(42).encode())
        .expect("We should always be able to encrypt.");
    let enc_len: u32 = encrypted
        .len()
        .try_into()
        .wrap_err("Failed to convert ecrypted length to `u32`")?;
    stream
        .write_all(&(enc_len).to_le_bytes())
        .wrap_err("Failed to write `enc_len`")?;
    stream
        .write_all(&encrypted)
        .wrap_err("Failed to write the `encrypted` message")?;

    let mut packet_size_buf = [0_u8; 4];
    stream
        .read_exact(&mut packet_size_buf)
        .wrap_err("Failed to read packet")?;
    let packet_size = u32::from_le_bytes(packet_size_buf);

    let mut buf = vec![0_u8; packet_size as usize];
    stream
        .read_exact(&mut buf)
        .wrap_err("Failed to `read_exact`")?;
    if let Ok(data) = crypto.decrypt(buf) {
        if let Ok(ConnectionCheck(_)) = Decode::decode(&mut data.as_slice()) {
            info!("Established connection to peer {}.", other_public_key);
            p2p.connected_to_peers
                .lock()
                .expect("Mutex poisoned")
                .insert(other_public_key, (stream, crypto, Instant::now()));
            return Ok(());
        }
    }
    Ok(())
}

const ESTABLISH_CONNECTION_TIME_SLICE: Duration = Duration::from_millis(25);

#[allow(clippy::expect_used)]
unsafe fn establish_new_connection(p2p: &P2PSystem, listener: &TcpListener) -> Option<TcpStream> {
    let incoming_connection = {
        let mut maybe_incoming_connection = None;
        #[allow(clippy::integer_division)]
        if rand::random::<u32>() >= (u32::MAX / 8) {
            for _ in 0_i32..20_i32 {
                if let Ok((stream, addr)) = listener.accept() {
                    trace!("Incomming p2p connection from {}", &addr);
                    stream
                        .set_read_timeout(Some(P2P_TCP_TIMEOUT))
                        .expect("Could not set read timeout on socket.");
                    stream
                        .set_write_timeout(Some(P2P_TCP_TIMEOUT))
                        .expect("Could not set write timeout on socket.");
                    maybe_incoming_connection = Some(stream);
                    break;
                } else {
                    std::thread::sleep(ESTABLISH_CONNECTION_TIME_SLICE);
                    if rand::random::<bool>() {
                        std::thread::sleep(ESTABLISH_CONNECTION_TIME_SLICE * 2);
                    }
                }
            }
        }
        maybe_incoming_connection
    };

    match incoming_connection {
        Some(con) => Some(con),
        None => {
            let connected_to_peer_keys = p2p.get_connected_to_peer_keys();

            let target_addrs: Vec<String> = p2p
                .connect_peer_target
                .lock()
                .expect("Mutex poisoned")
                .iter()
                .filter(|peer_id| {
                    !connected_to_peer_keys
                        .iter()
                        .any(|key| key == &peer_id.public_key)
                })
                .map(|peer_id| peer_id.address.clone())
                .collect();

            if target_addrs.is_empty() {
                None
            } else {
                let address = &target_addrs[rand::random::<usize>() % target_addrs.len()];

                // to_socket_addrs is what enables dns lookups.
                let maybe_addr = address
                    .to_socket_addrs()
                    .unwrap_or_else(|_| Vec::new().into_iter())
                    .next();
                if maybe_addr.is_none() {
                    error!("Error can't produce addr from str. str={}", &address);
                }
                maybe_addr
            }
        }
        .and_then(|addr| {
            if let Ok(stream) =
                TcpStream::connect_timeout(&addr, ESTABLISH_CONNECTION_TIME_SLICE * 40)
            {
                info!("Outgoing p2p connection to {}", &addr);
                stream
                    .set_read_timeout(Some(P2P_TCP_TIMEOUT))
                    .expect("Could not set read timeout on socket.");
                stream
                    .set_write_timeout(Some(P2P_TCP_TIMEOUT))
                    .expect("Could not set write timeout on socket.");
                Some(stream)
            } else {
                None
            }
        }),
    }
}

// TODO: Return actual errors
fn perform_handshake(
    p2p: &P2PSystem,
    mut stream: TcpStream,
) -> eyre::Result<(TcpStream, Cryptographer, PublicKey)> {
    let mut crypto = send_hello(&mut stream)?;
    receive_hello(&mut stream, &mut crypto)?;
    // Exchange keys
    send_key(p2p, &crypto, &mut stream)?;
    let other_public_key = receive_public_key(&mut stream, &crypto)?;
    trace!("Completed handshake with {}.", other_public_key);
    Ok((stream, crypto, other_public_key))
}

fn receive_public_key(
    stream: &mut TcpStream,
    crypto: &GenericCryptographer<X25519Sha256, ChaCha20Poly1305>,
) -> eyre::Result<PublicKey> {
    let mut size = 0_u8;
    stream
        .read_exact(std::slice::from_mut(&mut size))
        .wrap_err("Failed to `read_exact` during `receive_public_key`")?;
    if (size as usize) >= MAX_HANDSHAKE_LENGTH {
        eyre::bail!("Size {size} exceeded max handshake length: {MAX_HANDSHAKE_LENGTH}");
    }
    let mut data = vec![0_u8; size as usize];
    stream
        .read_exact(&mut data)
        .wrap_err("Failed to `read_exact` during `receive_public_key`, after nulling")?;
    let data = crypto
        .decrypt(data)
        .wrap_err("Failed to `decrypt` during `receive_public_key`")?;
    let other_public_key =
        Decode::decode(&mut data.as_slice()).wrap_err("Failed to decode other public key")?;
    Ok(other_public_key)
}

fn send_key(
    p2p: &P2PSystem,
    crypto: &GenericCryptographer<X25519Sha256, ChaCha20Poly1305>,
    stream: &mut TcpStream,
) -> eyre::Result<()> {
    let data = p2p.public_key.encode();
    let data = crypto
        .encrypt(data)
        .wrap_err("Failed to encrypt `p2p.public_key`")?;
    let mut buf = Vec::<u8>::with_capacity(data.len() + 1);
    buf.push(
        data.len()
            .try_into()
            .wrap_err("Failed to convert `data.len()` to `u8`")?,
    );
    buf.extend_from_slice(data.as_slice());
    stream
        .write_all(&buf)
        .wrap_err("Failed to `write_all` during `send_key`")?;
    trace!("Sent public key to other peer.");
    Ok(())
}

type Cryptographer = GenericCryptographer<X25519Sha256, ChaCha20Poly1305>;

// TODO: Return actual errors.
fn send_hello(stream: &mut TcpStream) -> eyre::Result<Cryptographer> {
    Garbage::generate()
        .write(stream)
        .wrap_err("Failed to write garbage during `send_hello`")?;
    let crypto = Cryptographer::default();
    let ursa_key_slice = crypto.public_key.0.as_slice();
    stream
        .write_all(ursa_key_slice)
        .wrap_err("Failed to write `ursa_key_slice`.")?;
    trace!("Sent hello.");
    Ok(crypto)
}

// TODO: Return actual errors
#[allow(clippy::expect_used)]
fn receive_hello(stream: &mut TcpStream, crypto: &mut Cryptographer) -> eyre::Result<()> {
    Garbage::read(stream).wrap_err("Failed to read garbage")?;
    let mut key = [0_u8; 32];
    stream
        .read_exact(&mut key)
        .wrap_err("Failed to `read_exact` in `receive_hello`")?;
    let other_ursa_key = UrsaPublicKey(Vec::from(key));
    crypto
        .derive_shared_key(&other_ursa_key)
        .expect("Deriving of the shared key failed");
    trace!("Received hello.");
    Ok(())
}

/// Cryptographic primitive
struct GenericCryptographer<K, E>
where
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Private key
    pub secret_key: UrsaPrivateKey,
    /// Public key
    pub public_key: UrsaPublicKey,
    /// Public key belonging to another peer.
    pub other_public_key: Option<UrsaPublicKey>,
    /// Encryptor created from session key, that we got by Diffie-Hellman scheme
    pub cipher: Option<SymmetricEncryptor<E>>,
    /// Phantom
    pub _key_exchange: PhantomData<K>,
}

impl<K, E> Clone for GenericCryptographer<K, E>
where
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    #[allow(clippy::expect_used)]
    fn clone(&self) -> Self {
        let mut clone = Self {
            secret_key: self.secret_key.clone(),
            public_key: self.public_key.clone(),
            other_public_key: None,
            cipher: None,
            ..Self::default()
        };
        if let Some(other_public_key) = self.other_public_key.as_ref() {
            clone
                .derive_shared_key(other_public_key)
                .expect("Deriving of a shared key failed");
        }
        clone
    }
}

impl<K, E> GenericCryptographer<K, E>
where
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Instantiate [`Self`].
    ///
    /// # Errors
    /// If key exchange fails to produce keypair (extremely rare)
    #[allow(clippy::expect_used)]
    pub fn default() -> Self {
        let key_exchange = K::new();
        let (public_key, secret_key) = key_exchange
            .keypair(None)
            .expect("Cryptographer failed to produce key-pair.");
        Self {
            secret_key,
            public_key,
            other_public_key: None,
            cipher: None,
            _key_exchange: PhantomData::default(),
        }
    }

    /// Decrypt bytes.
    /// With no cipher set, the bytes are returned as is.
    ///
    /// # Errors
    /// Forwards [`SymmetricEncryptor::decrypt_easy`] error
    pub fn decrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        match &self.cipher {
            None => Ok(data),
            Some(cipher) => Ok(cipher
                .decrypt_easy(DEFAULT_AAD.as_ref(), data.as_slice())
                .map_err(CryptographicError::Decrypt)?),
        }
    }

    /// Encrypt bytes. If no cipher is set, the bytes are returned as is.
    ///
    /// # Errors
    /// Forwards [`SymmetricEncryptor::decrypt_easy`] error
    pub fn encrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        match &self.cipher {
            None => Ok(data),
            Some(cipher) => Ok(cipher
                .encrypt_easy(DEFAULT_AAD.as_ref(), data.as_slice())
                .map_err(CryptographicError::Encrypt)?),
        }
    }

    /// Creates a shared key from two public keys (local and external),
    /// then instantiates an encryptor from that key.
    ///
    /// # Errors
    /// `CryptographicError`
    pub fn derive_shared_key(&mut self, public_key: &UrsaPublicKey) -> Result<&Self, Error> {
        let dh = K::new();
        let shared = dh.compute_shared_secret(&self.secret_key, public_key).map_err(CryptographicError::Ursa)?;
        trace!(key = ?shared.0, "Derived shared key");
        let encryptor = {
            let key: &[u8] = shared.0.as_slice();
            SymmetricEncryptor::<E>::new_with_key(key)
        }
        .map_err(CryptographicError::Encrypt)?;
        self.other_public_key = Some(public_key.clone());
        self.cipher = Some(encryptor);
        Ok(self)
    }
}

/// Placeholder that can skip garbage bytes and generate them.
struct Garbage {
    garbage: Vec<u8>,
}

impl Garbage {
    pub fn generate() -> Self {
        let rng = &mut rand::thread_rng();
        let mut garbage = vec![0_u8; rng.gen_range(64..256)];
        rng.fill_bytes(&mut garbage);
        Self { garbage }
    }

    pub fn write(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        #[allow(clippy::cast_possible_truncation)]
        stream.write_all(std::slice::from_ref(&(self.garbage.len() as u8)))?;
        stream.write_all(self.garbage.as_slice())?;
        Ok(())
    }

    pub fn read(stream: &mut TcpStream) -> Result<Self, Error> {
        let mut size: u8 = 0;
        stream.read_exact(std::slice::from_mut(&mut size))?;
        let size = size as usize;
        if size >= MAX_HANDSHAKE_LENGTH {
            Err(HandshakeError::Length(size).into())
        } else {
            // Reading garbage
            trace!(%size, "Reading garbage");
            let mut garbage = vec![0_u8; size];
            stream.read_exact(&mut garbage)?;
            Ok(Self { garbage })
        }
    }
}
