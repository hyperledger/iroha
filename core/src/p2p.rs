use core::marker::PhantomData;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, Shutdown},
    os::unix::io::{AsRawFd, FromRawFd},
    str::FromStr,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use aead::generic_array::typenum::Unsigned;
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
use thiserror::Error;
use std::time::Instant;

use std::ops::DerefMut;

use crate::{
    block_sync::BlockSynchronizer, handler::ThreadHandler, sumeragi::Sumeragi, NetworkMessage,
    NetworkMessage::*, PeerId,
};

/// Errors used in [`crate`].
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

pub const P2P_TCP_TIMEOUT: Duration = Duration::from_millis(1500);

pub struct P2PSystem {
    listen_addr: String,
    public_key: PublicKey,
    connect_peer_target: Mutex<Vec<PeerId>>,
    connected_to_peers: Mutex<HashMap<PublicKey, (TcpStream, Cryptographer, Instant)>>,
    poll_network_index: std::sync::atomic::AtomicU32,

    packet_buffers: Mutex<(Vec<Box<crate::SumeragiPacket>>, Vec<Box<crate::BlockSyncMessage>>)>,
}

impl std::fmt::Debug for P2PSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "P2PSystem")
    }
}

impl P2PSystem {
    pub fn new(listen_addr: String, public_key: PublicKey) -> Arc<P2PSystem> {
        Arc::new(P2PSystem {
            listen_addr,
            public_key,
            connect_peer_target: Mutex::new(Vec::new()),
            connected_to_peers: Mutex::new(HashMap::new()),
            poll_network_index: std::sync::atomic::AtomicU32::new(0),
            packet_buffers: Mutex::new((Vec::new(), Vec::new())),
        })
    }

    pub fn post_to_network(&self, message: NetworkMessage, recipients: Vec<PublicKey>) {
        let encoded = message.encode();

        let mut to_disconnect_keys = Vec::new();
        let mut connected_to_peers = self.connected_to_peers.lock().unwrap();
        for public_key in recipients.iter() {
            let (stream, crypto, last_connection_check) = match connected_to_peers.get_mut(&public_key) {
                Some(stuff) => stuff,
                None => {
                    trace!("P2P post failed: Not connected.");
                    continue;
                }
            };
            let encrypted = crypto
                .encrypt(encoded.clone())
                .expect("We should always be able to encrypt.");
            let write1 = stream.write_all(&(encrypted.len() as u32).to_le_bytes());
            let write2 = stream.write_all(&encrypted);

            if write1.is_err() || write2.is_err() {
                error!("Disconecting, cause: Could not post message to peer {}.", public_key);
                to_disconnect_keys.push(public_key.clone());
            }
        }
        for key in to_disconnect_keys {
            info!("Disconnecting from: {}", &key);
            let (stream, _, _) = connected_to_peers.remove(&key).unwrap();
            stream.shutdown(Shutdown::Both);
        }
    }

    pub fn post_to_own_sumeragi_buffer(&self, sumeragi_packet: Box<crate::SumeragiPacket>)
    {
        let mut packet_buffers = self.packet_buffers.lock().unwrap();
        let (ref mut sumeragi_packet_buffer, ref mut block_sync_message_buffer) = packet_buffers.deref_mut();

        sumeragi_packet_buffer.push(sumeragi_packet);
    }

    pub fn poll_network_for_sumeragi_packet(&self) -> Option<crate::SumeragiPacket> {
        let mut packet_buffers = self.packet_buffers.lock().unwrap();
        let (ref mut sumeragi_packet_buffer, ref mut block_sync_message_buffer) = packet_buffers.deref_mut();

        if !sumeragi_packet_buffer.is_empty() {
            println!("Early return sumeragi.");
            return Some(*sumeragi_packet_buffer.remove(0));
        }

        let mut connected_to_peers = self.connected_to_peers.lock().unwrap();
        let mut values : Vec<_> = connected_to_peers.iter_mut().collect();
        let value_len = values.len();

        let mut received = None;
        let mut send_connection_ack_keys = Vec::new();
        let mut to_disconnect_keys = Vec::new();

        for _ in 0..values.len() {
            let mut poll_network_index = self.poll_network_index.load(std::sync::atomic::Ordering::SeqCst);

            let (public_key, (stream, crypto, last_connection_check)) : &mut (&PublicKey, &mut (TcpStream, Cryptographer, Instant)) = &mut values[poll_network_index as usize % value_len];
            self.poll_network_index.store(poll_network_index.wrapping_add(1), std::sync::atomic::Ordering::SeqCst);

            if last_connection_check.elapsed().as_secs() > 5 {
                to_disconnect_keys.push(public_key.clone());
            }

            match read_from_socket(stream, crypto) {
                None => (),
                Some(message) => {
                    match message {
                        NetworkMessage::SumeragiPacket(packet) => {
                            received = Some(*packet);
                            break;
                        },
                        NetworkMessage::BlockSync(message) => {
                            block_sync_message_buffer.push(message);
                        }
                        Health => (),
                        ConnectionCheck(_) => {
                            send_connection_ack_keys.push(public_key.clone());
                        },
                        ConnectionCheckAck(_) => {
                            *last_connection_check = Instant::now();
                        },
                    }
                },
            }
        }
        for key in to_disconnect_keys {
            info!("Disconnecting from: {}", &key);
            let (stream, _, _) = connected_to_peers.remove(&key).unwrap();
            stream.shutdown(Shutdown::Both);
        }
        drop(connected_to_peers);
        self.post_to_network(ConnectionCheckAck(42), send_connection_ack_keys);

        None
    }

    pub fn poll_network_for_block_sync_message(&self) -> Option<crate::BlockSyncMessage> {
        let mut packet_buffers = self.packet_buffers.lock().unwrap();
        let (ref mut sumeragi_packet_buffer, ref mut block_sync_message_buffer) = packet_buffers.deref_mut();

        if !block_sync_message_buffer.is_empty() {
            println!("Early return block sync.");
            return Some(*block_sync_message_buffer.remove(0));
        }

        let mut connected_to_peers = self.connected_to_peers.lock().unwrap();
        let mut values : Vec<_> = connected_to_peers.iter_mut().collect();
        let value_len = values.len();

        let mut received = None;
        let mut send_connection_ack_keys = Vec::new();
        let mut to_disconnect_keys = Vec::new();

        for _ in 0..value_len {
            let mut poll_network_index = self.poll_network_index.load(std::sync::atomic::Ordering::SeqCst);

            let (public_key, (stream, crypto, last_connection_check)) : &mut (&PublicKey, &mut (TcpStream, Cryptographer, Instant)) = &mut values[poll_network_index as usize % value_len];
            self.poll_network_index.store(poll_network_index.wrapping_add(1), std::sync::atomic::Ordering::SeqCst);

            if last_connection_check.elapsed().as_secs() > 5 {
                to_disconnect_keys.push(public_key.clone());
            }

            match read_from_socket(stream, crypto) {
                None => (),
                Some(message) => {
                    match message {
                        NetworkMessage::SumeragiPacket(packet) => {
                            sumeragi_packet_buffer.push(packet);
                        },
                        NetworkMessage::BlockSync(message) => {
                            received = Some(*message);
                            break;
                        }
                        Health => (),
                        ConnectionCheck(_) => {
                            send_connection_ack_keys.push(public_key.clone());
                        },
                        ConnectionCheckAck(_) => {
                            *last_connection_check = Instant::now();
                        },
                    }
                },
            }
        }
        for key in to_disconnect_keys {
            info!("Disconnecting from: {}", &key);
            let (stream, _, _) = connected_to_peers.remove(&key).unwrap();
            stream.shutdown(Shutdown::Both);
        }
        drop(connected_to_peers);
        self.post_to_network(ConnectionCheckAck(42), send_connection_ack_keys);

        received
    }

    pub fn get_connected_to_peer_keys(&self) -> Vec<PublicKey> {
        let mut keys = Vec::new();
        let mut connected_to_peers = self.connected_to_peers.lock().unwrap();
        for (public_key, (stream, crypto, last_connection_check)) in connected_to_peers.iter_mut() {
            keys.push(public_key.clone());
        }
        keys
    }

    pub fn update_peer_target(&self, new_target: &[PeerId]) {
        let mut target = self.connect_peer_target.lock().unwrap();
        target.clear();
        target.extend_from_slice(new_target);
        if let Some(index) = target
            .iter()
            .position(|peer_id| peer_id.public_key == self.public_key)
        {
            target.remove(index);
        }
        let target = target.clone();
        let mut connected_to_peers = self.connected_to_peers.lock().unwrap();
        let mut to_disconnect_keys = Vec::new();
        for public_key in connected_to_peers.keys() {
            if target.iter().position(|id| id.public_key == *public_key).is_none() {
                to_disconnect_keys.push(public_key.clone());
            }
        }
        for key in to_disconnect_keys {
            println!("Disconnected because not in target from {}.", key);
            let (stream, _crypto, _last_check_connection) = connected_to_peers.remove(&key).unwrap();
            stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn read_from_socket(
    stream: &mut TcpStream,
    crypto: &Cryptographer,
) -> Option<NetworkMessage> {
    let mut packet_size = 0;
    while packet_size == 0 {
        let mut _byte = 0_u8;
        stream.set_nonblocking(true).unwrap();
        let byte_count_maybe = stream.peek(std::slice::from_mut(&mut _byte));
        stream.set_nonblocking(false).unwrap();
        let byte_count = byte_count_maybe.ok()?;
        (byte_count != 0).then_some(0)?;
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

pub fn start_listen_loop(p2p: Arc<P2PSystem>) -> ThreadHandler {
    // Oneshot channel to allow forcefully stopping the thread.
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();

    let thread_handle = std::thread::Builder::new()
        .name("P2P Listen Thread".to_owned())
        .spawn(move || {
            p2p_listen_loop(&p2p, shutdown_receiver);
        })
        .unwrap();

    let shutdown = move || {
        let _result = shutdown_sender.send(());
    };

    ThreadHandler::new(Box::new(shutdown), thread_handle)
}

// nocheckin do maps
fn p2p_listen_loop(p2p: &P2PSystem, mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>) {
    let listener = TcpListener::bind(&p2p.listen_addr).expect("Could not bind p2p tcp listener.");
    listener
        .set_nonblocking(true)
        .expect("P2P subsystem could not enable nonblocking on listening tcp port.");

    let mut instant_last_sent_connection_check = Instant::now();
    loop {
        // We have no obligations to network delivery so we simply exit on shutdown signal.
        if shutdown_receiver.try_recv().is_ok() {
            info!("P2P listen thread is being shut down");
            return;
        }
        std::thread::sleep(Duration::from_millis((rand::random::<u64>() % 10) + 10));

        if instant_last_sent_connection_check.elapsed().as_secs() > 2 {
            let target = p2p.connect_peer_target.lock().unwrap();
            p2p.post_to_network(NetworkMessage::ConnectionCheck(42), target.iter().map(|peer_id| peer_id.public_key.clone()).collect());
            instant_last_sent_connection_check = Instant::now();
        }

        let stream = match unsafe { establish_new_connection(p2p, &listener) } {
            Some(new_con) => new_con,
            None => continue,
        };

        let (mut stream, crypto, other_public_key) = match perform_handshake(&p2p, stream) {
            Some(tuple) => tuple,
            None => continue,
        };

        {
            let target = p2p.connect_peer_target.lock().unwrap();
            if target
                .iter()
                .position(|peer_id| peer_id.public_key == other_public_key)
                .is_none()
            {
                trace!("Dropping because not in target, {}.", other_public_key);
                continue;
            }
        }

        let mut connected_to_peers = p2p.connected_to_peers.lock().unwrap();

        if connected_to_peers
            .keys()
            .position(|key| *key == other_public_key)
            .is_some()
        {
            trace!("Dropping because already connected, {}.", other_public_key);
            continue;
        }

        {
            let encrypted = crypto
                .encrypt(NetworkMessage::ConnectionCheck(42).encode())
                .expect("We should always be able to encrypt.");
            let write1 = stream.write_all(&(encrypted.len() as u32).to_le_bytes());
            let write2 = stream.write_all(&encrypted);
            if write1.is_err() || write2.is_err() {
                continue;
            }


            let mut packet_size_buf = [0_u8; 4];
            if stream.read_exact(&mut packet_size_buf).is_err() {
                continue;
            }
            let packet_size = u32::from_le_bytes(packet_size_buf);

            let mut buf = vec![0_u8; packet_size as usize];
            if stream.read_exact(&mut buf).is_err() {
                continue;
            }
            if let Ok(data) = crypto.decrypt(buf) {
                if let Ok(network_message) = Decode::decode(&mut data.as_slice()) {
                    if let ConnectionCheck(_) = network_message {
                        info!("Established connection to peer {}.", other_public_key);
                        connected_to_peers.insert(other_public_key, (stream, crypto, Instant::now()));
                        continue;
                    }
                }
            }
        }
        error!("Connecting to peer failed in final step, {}.", other_public_key);
    }
}

const ESTABLISH_CONNECTION_TIME_SLICE: Duration = Duration::from_millis(25);

unsafe fn establish_new_connection(p2p: &P2PSystem, listener: &TcpListener) -> Option<TcpStream> {
    let maybe_incoming_connection = {
        let mut maybe_incoming_connection = None;
        for _ in 0..20 {
            if let Ok((mut stream, addr)) = listener.accept() {
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
        maybe_incoming_connection
    };

    match maybe_incoming_connection {
        Some(con) => Some(con),
        None => {
            let connected_to_peer_keys = p2p.get_connected_to_peer_keys();

            let target_addrs: Vec<String> = p2p
                .connect_peer_target
                .lock()
                .unwrap()
                .iter()
                .filter(|peer_id| {
                    connected_to_peer_keys
                        .iter()
                        .position(|key| key == &peer_id.public_key)
                        .is_none()
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
                    .unwrap_or(vec![].into_iter())
                    .next();
                if maybe_addr.is_none() {
                    error!("Error can't produce addr from str. str={}", &address);
                }
                maybe_addr
            }
        }
        .map_or(None, |addr| {
            if let Ok(mut stream) =
                TcpStream::connect_timeout(&addr, ESTABLISH_CONNECTION_TIME_SLICE * 40)
            {
                trace!("Outgoing p2p connection to {}", &addr);
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

fn perform_handshake(
    p2p: &P2PSystem,
    mut stream: TcpStream,
) -> Option<(TcpStream, Cryptographer, PublicKey)> {
    // Exchange hello's
    Garbage::generate().write(&mut stream).ok()?;
    let mut crypto = Cryptographer::default();
    let ursa_key_slice = crypto.public_key.0.as_slice();
    stream.write_all(ursa_key_slice).ok()?;

    trace!("Sent hello.");
    Garbage::read(&mut stream).ok()?;
    let mut key = [0_u8; 32];
    stream.read_exact(&mut key).ok()?;
    let other_ursa_key = UrsaPublicKey(Vec::from(key));
    crypto.derive_shared_key(&other_ursa_key);
    trace!("Received hello.");

    // Exchange public keys
    let data = p2p.public_key.encode();

    let data = crypto.encrypt(data).ok()?;
    let mut buf = Vec::<u8>::with_capacity(data.len() + 1);
    #[allow(clippy::cast_possible_truncation)]
    buf.push(data.len() as u8);
    buf.extend_from_slice(data.as_slice());

    stream.write_all(&buf).ok()?;
    trace!("Sent public key to other peer.");

    let mut size = 0_u8;
    stream.read_exact(std::slice::from_mut(&mut size)).ok()?;
    if (size as usize) >= MAX_HANDSHAKE_LENGTH {
        return None;
    }
    let mut data = vec![0_u8; size as usize];
    stream.read_exact(&mut data).ok()?;
    let data = crypto.decrypt(data).ok()?;
    let other_public_key = Decode::decode(&mut data.as_slice()).ok()?;

    trace!("Completed handshake with {}.", other_public_key);
    Some((stream, crypto, other_public_key))
}

type Cryptographer = GenericCryptographer<X25519Sha256, ChaCha20Poly1305>;

/// Cryptographic primitive
struct GenericCryptographer<K, E>
where
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Secret part of keypair
    pub secret_key: UrsaPrivateKey,
    /// Public part of keypair
    pub public_key: UrsaPublicKey,
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
    fn clone(&self) -> Self {
        let mut copy = Self {
            secret_key: self.secret_key.clone(),
            public_key: self.public_key.clone(),
            other_public_key: None,
            cipher: None,
            _key_exchange: self._key_exchange,
        };
        if let Some(other_public_key) = self.other_public_key.as_ref() {
            copy.derive_shared_key(other_public_key);
        }
        copy
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
    pub fn default() -> Self {
        let key_exchange = K::new();
        let (public_key, secret_key) = key_exchange
            .keypair(None)
            .expect("Cryptographer failed to produce keypair.");
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
        let shared = dh.compute_shared_secret(&self.secret_key, public_key)?;
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
        stream.read_exact(std::slice::from_mut(&mut size));
        let size = size as usize;
        if size >= MAX_HANDSHAKE_LENGTH {
            Err(HandshakeError::Length(size).into())
        } else {
            // Reading garbage
            trace!(%size, "Reading garbage");
            let mut garbage = vec![0_u8; size];
            let _ = stream.read_exact(&mut garbage)?;
            Ok(Self { garbage })
        }
    }
}
