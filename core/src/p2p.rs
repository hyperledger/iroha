//! handshake and connection logic.
#![allow(
    clippy::significant_drop_in_scrutinee,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use core::marker::PhantomData;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs},
    result::Result,
    sync::Arc,
    time::{Duration, Instant},
};

use eyre::WrapErr as _;
use iroha_crypto::{
    ursa::{
        encryption::symm::{prelude::ChaCha20Poly1305, Encryptor, SymmetricEncryptor},
        kex::{x25519::X25519Sha256, KeyExchangeScheme},
        keys::{PrivateKey as UrsaPrivateKey, PublicKey as UrsaPublicKey},
        CryptoError,
    },
    PublicKey,
};
use iroha_logger::{debug, error, info, trace};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use thiserror::Error;

use crate::{handler::ThreadHandler, NetworkMessage, NetworkMessage::*, PeerId};

/// Errors used in [`crate`].
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to read or write
    #[error("Failed IO operation.")]
    Io(#[from] std::io::Error),
    /// Handshake lengths don't match
    #[error("Handshake length mismatch {0}")]
    HandshakeLength(usize),
    /// Parity Scale codec error
    #[error("Parity Scale codec error")]
    ParityScale(#[from] parity_scale_codec::Error),
    /// Failed to create keys
    #[error("Failed to create session key")]
    Keys(#[from] CryptographicError),
    /// Failed to resolve to any socket address
    #[error("Failed to resolve to any socket address")]
    Resolve,
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

/// Max length of message handshake in bytes.
pub const MAX_HANDSHAKE_LENGTH: usize = 255;
/// Default associated data for AEAD
/// [`Authenticated encryption`](https://en.wikipedia.org/wiki/Authenticated_encryption)
pub const DEFAULT_AAD: &[u8; 10] = b"Iroha2 AAD";

/// Timeout after which the `TCP` connection is no longer considered live.
pub const P2P_TCP_TIMEOUT: Duration = Duration::from_millis(1500);

/// The peer-to-peer communication system
pub struct P2PSystem {
    listen_addr: String,
    public_key: PublicKey,
    connect_peer_target: Mutex<Vec<PeerId>>,
    pub(crate) connected_to_peers: Mutex<HashMap<PublicKey, PeerConnection>>,
    pub(crate) read_thread_data: Mutex<ReadThreadData>,
}

pub(crate) struct ReadThreadData {
    poll_network_index: u32,
    pub(crate) packet_cache: Vec<Option<NetworkMessage>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkMessageVariant {
    Sumeragi,
    BlockSync,
}

#[derive(Debug)]
pub(crate) struct PeerConnection {
    stream: TcpStream,
    crypto: Cryptographer,
    last_connection_check: Instant,
}

impl std::fmt::Debug for P2PSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "P2PSystem")
    }
}

#[allow(clippy::expect_used)]
impl P2PSystem {
    #[inline]
    /// Constructor for [`Self`]
    pub fn new(listen_addr: String, public_key: PublicKey) -> P2PSystem {
        P2PSystem {
            listen_addr,
            public_key,
            connect_peer_target: Mutex::new(Vec::new()),
            connected_to_peers: Mutex::new(HashMap::new()),
            read_thread_data: Mutex::new(ReadThreadData {
                poll_network_index: 0_u32,
                packet_cache: Vec::new(),
            }),
        }
    }

    fn try_resolve_address(&self) -> Option<std::net::SocketAddr> {
        let connected_to_peer_keys = {
            let mut keys = Vec::new();
            let mut connected_to_peers = self.connected_to_peers.lock();
            for (public_key, _) in connected_to_peers.iter_mut() {
                keys.push(public_key.clone());
            }
            keys
        };
        let target_addrs: Vec<String> = self
            .connect_peer_target
            .lock()
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
            let address_candidate =
                &target_addrs[rand::random::<usize>().wrapping_rem(target_addrs.len())];
            // to_socket_addrs enables dns look-ups.
            let maybe_addr = address_candidate
                .to_socket_addrs()
                .unwrap_or_else(|error| {
                    debug!(?error, "Socket addr");
                    Vec::new().into_iter()
                })
                .next();
            if maybe_addr.is_none() {
                error!(%address_candidate, "Error can't produce address from str. ");
            }
            maybe_addr
        }
    }

    pub(crate) fn post_to_network(&self, message: &NetworkMessage, recipients: &[PublicKey]) {
        let mut to_disconnect_keys = Vec::new();

        let mut connected_to_peers = self.connected_to_peers.lock();
        for public_key in recipients.iter() {
            if let Some(PeerConnection { stream, crypto, .. }) =
                connected_to_peers.get_mut(public_key)
            {
                let encrypted = crypto
                    .encrypt(message.encode().clone())
                    .expect("We should always be able to encrypt.");
                let write1 = stream.write_all(&(u32::try_from(encrypted.len())).expect("Encrypted length exceeds 32 bits. This will cause issues with Parity Scale codec. Aborting. ").to_le_bytes());
                let write2 = stream.write_all(&encrypted);

                if write1.is_err() || write2.is_err() {
                    error!(
                        "Disconecting, cause: Could not post message to peer {}.",
                        public_key
                    );
                    to_disconnect_keys.push(public_key.clone());
                }
            } else {
                debug!("P2P post failed: Not connected.");
            }
        }
        drop(connected_to_peers);
        self.disconnect_peers(to_disconnect_keys);
    }

    #[allow(
        clippy::redundant_else,
        clippy::arithmetic_side_effects,
        clippy::cognitive_complexity,
        clippy::needless_pass_by_value
    )]
    pub(crate) fn poll_network_for_packet(
        &self,
        variant: NetworkMessageVariant,
    ) -> Option<NetworkMessage> {
        let ReadThreadData {
            ref mut poll_network_index,
            ref mut packet_cache,
        } = *self.read_thread_data.lock();

        let mut insert_index = 0;
        for i in 0..packet_cache.len() {
            if let Some(content) = packet_cache[i].take() {
                match content {
                    SumeragiPacket(internal) => {
                        if variant == NetworkMessageVariant::Sumeragi {
                            iroha_logger::trace!("Early return.");
                            return Some(SumeragiPacket(internal));
                        } else {
                            packet_cache[insert_index] = Some(SumeragiPacket(internal));
                            insert_index += 1;
                        }
                    }
                    BlockSync(internal) => {
                        if variant == NetworkMessageVariant::BlockSync {
                            iroha_logger::trace!("Early return.");
                            return Some(BlockSync(internal));
                        } else {
                            packet_cache[insert_index] = Some(BlockSync(internal));
                            insert_index += 1;
                        }
                    }
                    _ => (),
                }
            }
        }
        packet_cache.truncate(insert_index);

        let mut connected_to_peers = self.connected_to_peers.lock();
        let mut values: Vec<_> = connected_to_peers.iter_mut().collect();
        let value_len = values.len();

        let mut recieved = None;
        let mut send_connection_ack_keys = Vec::new();
        let mut to_disconnect_keys = Vec::new();

        for _ in 0..values.len() {
            let (
                public_key,
                PeerConnection {
                    stream,
                    crypto,
                    last_connection_check,
                },
            ) = &mut values[*poll_network_index as usize % value_len];
            *poll_network_index = poll_network_index.wrapping_add(1);

            if last_connection_check.elapsed().as_secs() > 5 {
                to_disconnect_keys.push(public_key.clone());
            }

            match crypto.read_from_socket(stream) {
                Err(_) | Ok(Health) => (),
                Ok(NetworkMessage::SumeragiPacket(internal)) => {
                    if NetworkMessageVariant::Sumeragi == variant {
                        recieved = Some(SumeragiPacket(internal));
                    } else {
                        packet_cache.push(Some(SumeragiPacket(internal)));
                    }
                    break;
                }
                Ok(NetworkMessage::BlockSync(internal)) => {
                    if variant == NetworkMessageVariant::BlockSync {
                        recieved = Some(BlockSync(internal));
                    } else {
                        packet_cache.push(Some(BlockSync(internal)));
                    }
                }
                Ok(ConnectionCheck(_)) => {
                    send_connection_ack_keys.push(public_key.clone());
                }
                Ok(ConnectionCheckAck(_)) => {
                    *last_connection_check = Instant::now();
                }
            }
        }
        drop(connected_to_peers);
        self.disconnect_peers(to_disconnect_keys);
        self.post_to_network(&ConnectionCheckAck(42), &send_connection_ack_keys);

        recieved
    }

    pub(crate) fn update_peer_target(&self, new_target: &[PeerId]) {
        let mut target = self.connect_peer_target.lock();
        target.clear();
        target.extend_from_slice(new_target);
        if let Some(index) = target
            .iter()
            .position(|peer_id| peer_id.public_key == self.public_key)
        {
            target.remove(index);
        }
        let target = target.clone();
        let mut to_disconnect_keys = Vec::new();
        for public_key in self.connected_to_peers.lock().keys() {
            if !target.iter().any(|id| id.public_key == *public_key) {
                to_disconnect_keys.push(public_key.clone());
            }
        }
        self.disconnect_peers(to_disconnect_keys)
    }

    #[allow(clippy::cognitive_complexity)]
    /// The main loop for the listening thread.
    fn listen_loop(&self, mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>) {
        let listener =
            TcpListener::bind(&self.listen_addr).expect("Could not bind p2p tcp listener.");
        listener
            .set_nonblocking(true)
            .expect("P2P subsystem could not enable nonblocking on listening tcp port.");

        let mut last_connection_check = Instant::now();
        loop {
            // We have no obligations to network delivery so we simply exit on shutdown signal.
            if shutdown_receiver.try_recv().is_ok() {
                info!("P2P listen thread is being shut down");
                break;
            }
            std::thread::sleep(Duration::from_millis((rand::random::<u64>() % 10) + 10));
            self.check_connection(&mut last_connection_check);

            let stream = match self.establish_new_connection(&listener) {
                Ok(new_con) => new_con,
                Err(e) => {
                    debug!(?e);
                    continue;
                }
            };

            let (stream, crypto, other) = match self.perform_handshake(stream) {
                Ok(tuple) => tuple,
                Err(e) => {
                    debug!(?e);
                    continue;
                }
            };

            if !self
                .connect_peer_target
                .lock()
                .iter()
                .any(|peer_id| peer_id.public_key == other)
            {
                trace!(%other, "Dropping because not in target.");
                continue;
            }

            let mut connected_to_peers = self.connected_to_peers.lock();

            if connected_to_peers.keys().any(|key| *key == other) {
                trace!(%other, "Dropping because already connected.");
            } else if let Err(e) =
                finish_connection(crypto, stream, &mut connected_to_peers, &other)
            {
                error!(?e,
                       %other,
                       "Connecting to peer failed in final step."
                );
            }
        }
    }

    fn check_connection(&self, instant_last_sent_connection_check: &mut Instant) {
        if instant_last_sent_connection_check.elapsed().as_secs() > 2 {
            let target = self.connect_peer_target.lock();
            self.post_to_network(
                &NetworkMessage::ConnectionCheck(42),
                &target
                    .iter()
                    .map(|peer_id| peer_id.public_key.clone())
                    .collect::<Vec<_>>(),
            );
            *instant_last_sent_connection_check = Instant::now();
        }
    }

    #[allow(clippy::expect_used)]
    fn disconnect_peers(&self, to_disconnect_keys: Vec<PublicKey>) {
        let mut connected_to_peers = self.connected_to_peers.lock();
        for key in to_disconnect_keys {
            info!("Disconnecting from: {}", &key);
            let PeerConnection { stream, .. } = connected_to_peers
                .remove(&key)
                .expect("Peer no longer present. This is memory corruption");
            stream
                .shutdown(Shutdown::Both)
                .unwrap_or_else(|e| debug!(?e, "Error shutting down stream"));
        }
    }

    #[allow(
        clippy::expect_used,
        clippy::unwrap_in_result,
        clippy::integer_division
    )]
    fn establish_new_connection(&self, listener: &TcpListener) -> Result<TcpStream, Error> {
        let maybe_incoming_connection = {
            let mut incoming_connection = None;
            // ATTENTION!  This function is weird, and for good
            // reason. We want to inject some stochastic sleeps as a
            // form of Markov-chain-Monte-Carlo scheduling. This is
            // necessary to avoid high contention and an actor-like
            // model. We need to run the connection check randomly 7/8
            // times.
            //
            // The precise timings needed for optimal performance are
            // yet to be determined.
            if rand::random::<u32>() % 8 > 1 {
                for _ in 0_i32..20_i32 {
                    if let Ok((stream, addr)) = listener.accept() {
                        trace!(from=%addr, "Incoming p2p connection");
                        stream
                            .set_read_timeout(Some(P2P_TCP_TIMEOUT))
                            .expect("Could not set read timeout on socket.");
                        stream
                            .set_write_timeout(Some(P2P_TCP_TIMEOUT))
                            .expect("Could not set write timeout on socket.");
                        // DO NOT SHORT-CIRCUIT to a return, this is
                        // intentional for the timings.
                        incoming_connection = Some(stream);
                        break;
                    }
                    std::thread::sleep(ESTABLISH_CONNECTION_TIME_SLICE);
                    if rand::random::<bool>() {
                        std::thread::sleep(ESTABLISH_CONNECTION_TIME_SLICE * 2);
                    }
                }
            }
            incoming_connection
        };

        maybe_incoming_connection.map_or_else(
            || {
                self.try_resolve_address()
                    .map_or(Err(Error::Resolve), |addr| {
                        TcpStream::connect_timeout(&addr, ESTABLISH_CONNECTION_TIME_SLICE * 40)
                            .map(|stream| {
                                info!("Outgoing p2p connection to {}", &addr);
                                stream
                                    .set_read_timeout(Some(P2P_TCP_TIMEOUT))
                                    .expect("Could not set read timeout on socket.");
                                stream
                                    .set_write_timeout(Some(P2P_TCP_TIMEOUT))
                                    .expect("Could not set write timeout on socket.");
                                stream
                            })
                            .map_err(Error::Io)
                    })
            },
            Ok,
        )
    }

    #[allow(clippy::unwrap_in_result, clippy::expect_used)]
    fn perform_handshake(
        &self,
        mut stream: TcpStream,
    ) -> Result<(TcpStream, Cryptographer, PublicKey), Error> {
        let crypto = self.exchange_greetings(&mut stream)?;
        trace!("Sent public key to other peer.");
        let mut size_buf = 0_u8;
        stream.read_exact(std::slice::from_mut(&mut size_buf))?;
        if (size_buf as usize) >= MAX_HANDSHAKE_LENGTH {
            return Err(Error::HandshakeLength(size_buf as usize));
        }
        let mut null_bytes = vec![0_u8; size_buf as usize];
        stream.read_exact(&mut null_bytes)?;
        let other_public_key = Decode::decode(&mut crypto.decrypt(null_bytes)?.as_slice())?;
        trace!("Completed handshake with {}.", other_public_key);
        Ok((stream, crypto, other_public_key))
    }

    #[allow(clippy::unwrap_in_result, clippy::expect_used)]
    fn exchange_greetings(&self, stream: &mut TcpStream) -> Result<Cryptographer, Error> {
        Garbage::generate().write(stream)?;
        let mut crypto = Cryptographer::default().map_err(CryptographicError::Ursa)?;
        stream.write_all(crypto.public_key.0.as_slice())?;
        trace!("Sent hello.");
        Garbage::read(stream)?;
        let mut key = [0_u8; 32];
        stream.read_exact(&mut key)?;
        crypto.derive_shared_key(&UrsaPublicKey(Vec::from(key)))?;
        trace!("Received hello.");
        let data = crypto.encrypt(self.public_key.encode())?;
        let mut data_buf = Vec::<u8>::with_capacity(data.len() + 1);
        data_buf.push(u8::try_from(data.len()).expect("data length doesn't fit into byte."));
        data_buf.extend_from_slice(data.as_slice());
        stream.write_all(&data_buf)?;
        Ok(crypto)
    }
}

#[allow(clippy::expect_used)]
fn finish_connection(
    crypto: Cryptographer,
    mut stream: TcpStream,
    connected_to_peers: &mut HashMap<PublicKey, PeerConnection>,
    other_public_key: &PublicKey,
) -> eyre::Result<()> {
    let encrypted = crypto
        .encrypt(NetworkMessage::ConnectionCheck(42).encode())
        .expect("We should always be able to encrypt.");
    stream.write_all(
        &u32::try_from(encrypted.len())
            .expect("decoded length doesn't fit into `u32`")
            .to_le_bytes(),
    )?;
    stream.write_all(&encrypted)?;
    let mut packet_size_buf = [0_u8; 4];
    stream.read_exact(&mut packet_size_buf)?;
    let packet_size = u32::from_le_bytes(packet_size_buf);
    let mut buf = vec![0_u8; packet_size as usize];
    stream.read_exact(&mut buf)?;
    let data = crypto.decrypt(buf)?;
    if let ConnectionCheck(_) = Decode::decode(&mut data.as_slice())? {
    } else {
        error!("Actually not established connection to peer {other_public_key}.");
        // Rust errors are dumb, TODO invent an error type for this case.
    }

    info!("Established connection to peer {other_public_key}.");
    connected_to_peers.insert(
        other_public_key.clone(),
        PeerConnection {
            stream,
            crypto,
            last_connection_check: Instant::now(),
        },
    );
    Ok(())
}

/// Initiate the listening loop of the [`P2PSystem`], the public
/// entry-point for the module.
///
/// # Panics
/// This function starts a new thread and gives it a name. It panics
/// if the thread handle couldn't be spawned.
#[allow(clippy::expect_used)]
pub fn start_listen_loop(p2p: Arc<P2PSystem>) -> ThreadHandler {
    // Oneshot channel to allow forcefully stopping the thread.
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();

    let thread_handle = std::thread::Builder::new()
        .name("P2P Listen Thread".to_owned())
        .spawn(move || {
            p2p.listen_loop(shutdown_receiver);
        })
        .expect(
            "Failed to start the P2P Listening thread.\
                 Unsafe to continue. Check for being out-of-memory, conditions and `ulimits`",
        );

    let shutdown = move || {
        let _result = shutdown_sender.send(());
    };

    ThreadHandler::new(Box::new(shutdown), thread_handle)
}

const ESTABLISH_CONNECTION_TIME_SLICE: Duration = Duration::from_millis(25);

type Cryptographer = GenericCryptographer<X25519Sha256, ChaCha20Poly1305>;

impl std::fmt::Debug for Cryptographer {
    fn fmt(&self, _: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        Ok(())
    }
}

/// Cryptographic primitive
struct GenericCryptographer<K, E>
where
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Private key belonging to and identifying this peer on the network.
    secret_key: UrsaPrivateKey,
    /// Public key belonging to and identifying this peer on the network.
    public_key: UrsaPublicKey,
    /// Public key belonging to and identifying another peer on the network that is connected to this peer.
    other_public_key: Option<UrsaPublicKey>,
    /// Encryptor created from session key, that we got by Diffie-Hellman scheme.
    cipher: Option<SymmetricEncryptor<E>>,
    _key_exchange: PhantomData<K>,
}

impl<K, E> GenericCryptographer<K, E>
where
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Instantiate [`Self`].
    ///
    /// # Panics
    /// If key exchange fails to produce keypair (extremely rare)
    fn default() -> Result<Self, CryptoError> {
        let key_exchange = K::new();
        let (public_key, secret_key) = key_exchange.keypair(None)?;
        Ok(Self {
            secret_key,
            public_key,
            other_public_key: None,
            cipher: None,
            _key_exchange: PhantomData::default(),
        })
    }

    /// De-crypt `data`. If no cipher is set, `data` is returned as is.
    ///
    /// # Errors
    /// Forwards [`SymmetricEncryptor::decrypt_easy`] error
    fn decrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        match &self.cipher {
            None => Ok(data),
            Some(cipher) => Ok(cipher
                .decrypt_easy(DEFAULT_AAD.as_ref(), data.as_slice())
                .map_err(CryptographicError::Decrypt)?),
        }
    }

    /// Encrypt `data`. If no cipher is set, `data` is returned as is.
    ///
    /// # Errors
    /// Forwards [`SymmetricEncryptor::decrypt_easy`] error
    fn encrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        match &self.cipher {
            None => Ok(data),
            Some(cipher) => Ok(cipher
                .encrypt_easy(DEFAULT_AAD.as_ref(), data.as_slice())
                .map_err(CryptographicError::Encrypt)?),
        }
    }

    /// Create a shared key from two public keys (local and external),
    /// then instantiates an encryptor from that key.
    ///
    /// # Errors
    /// Fails on failure in
    /// - Compute shared secret in Diffie-Hellmann scheme
    /// - Instantiation of `SymmetricEncryptor`, which is
    /// infallible. We still forward the error, so that any changes to
    /// the URSA API which make this operation fallible don't break
    /// ours.
    fn derive_shared_key(&mut self, public_key: &UrsaPublicKey) -> Result<&Self, Error> {
        let dh = K::new();
        let shared = dh
            .compute_shared_secret(&self.secret_key, public_key)
            .map_err(CryptographicError::Ursa)?;
        trace!(key = ?shared.0, "Derived shared key");
        let encryptor = SymmetricEncryptor::<E>::new_with_key(shared.0.as_slice())
            .map_err(CryptographicError::Encrypt)?;
        self.other_public_key = Some(public_key.clone());
        self.cipher = Some(encryptor);
        Ok(self)
    }

    #[allow(clippy::expect_used)]
    fn read_from_socket(&self, stream: &mut TcpStream) -> eyre::Result<NetworkMessage> {
        let mut packet_size = 0;
        while packet_size == 0 {
            let mut null_byte = 0_u8;
            // Block for write, unblock for poll momentarily.
            stream
                .set_nonblocking(true)
                .wrap_err("Set non-blocking failed. Aborting")?;
            let byte_count_maybe = stream.peek(std::slice::from_mut(&mut null_byte));
            stream
                .set_nonblocking(false)
                .wrap_err("Set blocking failed. Aborting ")?;
            let byte_count = byte_count_maybe?;
            if byte_count == 0 {
                eyre::bail!("byte count {byte_count} not equal to zero")
            }
            let mut packet_size_buf = [0_u8; 4];
            stream.read_exact(&mut packet_size_buf)?;
            packet_size = u32::from_le_bytes(packet_size_buf);
        }

        let mut buf = vec![0_u8; packet_size as usize];
        stream.read_exact(&mut buf)?;
        let data = self.decrypt(buf)?;
        let network_message = Decode::decode(&mut data.as_slice())?;
        Ok(network_message)
    }
}

/// Placeholder that can skip garbage bytes and generate them.
struct Garbage {
    garbage: Vec<u8>,
}

impl Garbage {
    fn generate() -> Self {
        let rng = &mut rand::thread_rng();
        let mut garbage = vec![0_u8; rng.gen_range(64..256)];
        rng.fill_bytes(&mut garbage);
        Self { garbage }
    }

    fn write(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        #[allow(clippy::cast_possible_truncation)]
        stream.write_all(std::slice::from_ref(&(self.garbage.len() as u8)))?;
        stream.write_all(self.garbage.as_slice())?;
        Ok(())
    }

    fn read(stream: &mut TcpStream) -> Result<Self, Error> {
        let mut size: u8 = 0;
        stream.read_exact(std::slice::from_mut(&mut size))?;
        let size = size as usize;
        if size >= MAX_HANDSHAKE_LENGTH {
            Err(Error::HandshakeLength(size))
        } else {
            trace!(%size, "Reading garbage");
            let mut garbage = vec![0_u8; size];
            stream.read_exact(&mut garbage)?;
            Ok(Self { garbage })
        }
    }
}
