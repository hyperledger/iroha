use core::marker::PhantomData;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    str::FromStr,
    sync::{Arc, Mutex},
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
use iroha_logger::{debug, info, trace};
use parity_scale_codec::{Decode, Encode};
use rand::{Rng, RngCore};
use thiserror::Error;

use crate::{handler::ThreadHandler, sumeragi::Sumeragi, NetworkMessage, NetworkMessage::*, PeerId};

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

pub const P2P_TCP_TIMEOUT: Duration = Duration::from_millis(500);

pub struct P2PSystem {
    listen_addr: String,
    listener: TcpListener,
    public_key: PublicKey,
    connect_peer_target: Mutex<Vec<PeerId>>,
    connected_to_peers: Mutex<HashMap<PublicKey, (TcpStream, Cryptographer)>>,
}

impl std::fmt::Debug for P2PSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "P2PSystem")
    }
}

impl P2PSystem {
    pub fn new(listen_addr: String, public_key: PublicKey) -> Arc<P2PSystem> {
        let listener = TcpListener::bind(&listen_addr).expect("Could not bind p2p tcp listener.");
        listener
            .set_nonblocking(true)
            .expect("P2P subsystem could not enable nonblocking on listening tcp port.");
        Arc::new(P2PSystem {
            listen_addr,
            listener,
            public_key,
            connect_peer_target: Mutex::new(Vec::new()),
            connected_to_peers: Mutex::new(HashMap::new()),
        })
    }

    pub fn post_to_network(&self, message: NetworkMessage, recipients: Vec<PeerId>) {
        let encoded = message.encode();

        // For protocol violators.
        let mut to_disconnect_keys = Vec::new();

        let mut connected_to_peers = self.connected_to_peers.lock().unwrap();
        for public_key in recipients.iter().map(|peer_id| &peer_id.public_key) {
            let (stream, crypto) = match connected_to_peers.get_mut(&public_key) {
                Some(stuff) => stuff,
                None => {
                    continue;
                },
            };
            let encrypted = crypto.encrypt(encoded.clone()).expect("We should always be able to encrypt.");
            let write1 = stream.write_all(&(encrypted.len() as u32).to_le_bytes());
            let write2 = stream.write_all(&encrypted);

            if write1.is_err() || write2.is_err() {
                to_disconnect_keys.push(public_key);
            }
        }

        for key in to_disconnect_keys {
            println!("Disconnected during post from {}.", key);
            connected_to_peers.remove(&key).expect("Peer to disconnect must have been in the hashmap.");
        }
    }

    pub fn update_peer_target(&self, new_target: &[PeerId]) {
        let mut target = self.connect_peer_target.lock().unwrap();
        target.clear();
        target.extend_from_slice(new_target);
        if let Some(index) = target.iter().position(|peer_id| peer_id.public_key == self.public_key) {
            target.remove(index);
        }
    }
}

pub fn start_read_loop(p2p: Arc<P2PSystem>, sumeragi: Arc<Sumeragi>) -> ThreadHandler {
    // Oneshot channel to allow forcefully stopping the thread.
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();

    let thread_handle = std::thread::spawn(move || {
        p2p_read_loop(&p2p, shutdown_receiver, &sumeragi);
    });

    let shutdown = move || {
        let _result = shutdown_sender.send(());
    };

    ThreadHandler::new(Box::new(shutdown), thread_handle)
}

fn p2p_read_loop(
    p2p: &P2PSystem,
    mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
    sumeragi: &Sumeragi,
) {
    loop {
        // We have no obligations to network delivery so we simply exit on shutdown signal.
        if shutdown_receiver.try_recv().is_ok() {
            info!("P2P thread is being shut down");
            return;
        }
        std::thread::sleep(Duration::from_millis(10));

        // For protocol violators.
        let mut to_disconnect_keys = Vec::<PublicKey>::new();

        let mut connected_to_peers = p2p.connected_to_peers.lock().unwrap();
        for (public_key, (stream, crypto)) in connected_to_peers.iter_mut() {
            if stream.write_all(&0_u32.to_le_bytes()).is_err() { // This has to be done in order to detect broken pipes.
                to_disconnect_keys.push(public_key.clone());
                continue;
            }

            let mut _byte = 0_u8;
            if let Ok(byte_count) = stream.peek(std::slice::from_mut(&mut _byte)) { // Packet incomming
                if byte_count == 0 {
                    continue;
                }
                let mut packet_size = [0_u8; 4];
                if stream.read_exact(&mut packet_size).is_err()
                {
                    to_disconnect_keys.push(public_key.clone());
                    continue;
                }
                let packet_size = u32::from_le_bytes(packet_size);
                if packet_size == 0 { continue; }

                let mut buf = vec![0_u8; packet_size as usize];
                if stream.read_exact(&mut buf).is_err() {
                    to_disconnect_keys.push(public_key.clone());
                    continue;
                }

                if let Ok(data) = crypto.decrypt(buf) {
                    let network_message_maybe = Decode::decode(&mut data.as_slice());
                    if let Ok(network_message) = network_message_maybe {
                        match network_message {
                            SumeragiPacket(data) => {
                                sumeragi.incoming_message(data.into_v1());
                            }
                            BlockSync(data) => /* nocheckin self.broker.issue_send(data.into_v1()).await*/ {},
                            Health => {}
                        }
                    } else {
                        to_disconnect_keys.push(public_key.clone());
                        continue;
                    }
                } else {
                    to_disconnect_keys.push(public_key.clone());
                    continue;
                }
            } else {
                to_disconnect_keys.push(public_key.clone());
                continue;
            }
        }

        for key in to_disconnect_keys {
            println!("Disconnected during read from {}.", key);
            connected_to_peers.remove(&key).expect("Peer to disconnect must have been in the hashmap.");
        }
    }
}

pub fn start_listen_loop(p2p: Arc<P2PSystem>) -> ThreadHandler {
    // Oneshot channel to allow forcefully stopping the thread.
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();

    let thread_handle = std::thread::spawn(move || {
        p2p_listen_loop(&p2p, shutdown_receiver);
    });

    let shutdown = move || {
        let _result = shutdown_sender.send(());
    };

    ThreadHandler::new(Box::new(shutdown), thread_handle)
}

// nocheckin replace println's with trace's.
fn p2p_listen_loop(
    p2p: &P2PSystem,
    mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
) {
    std::thread::sleep(Duration::from_millis((rand::random::<u64>() % 10) + 10));

    let mut waiting_for_server_hello = Vec::new();
    let mut send_public_key = Vec::new();

    loop {
        // We have no obligations to network delivery so we simply exit on shutdown signal.
        if shutdown_receiver.try_recv().is_ok() {
            info!("P2P thread is being shut down");
            return;
        }

        /*
        The following loop is divided into sections. The order of these sections is vital
        for stable operation. Consider two peers started at the same time connecting to
        each other. With the sections ordered 1,2,3,4,5 there was a stable configuration
        where the two peers consistently timed out each other.

        Peer A is in section 1, listening.
        Peer B is in section 2, connecting.

        A connection is established. Peer A moves to section 2, Peer B to section 3.
        Peer B reads the server hello and moves to section 4.

        Now, Peer B is waiting for Peer A to send their public key in section 4.
        Peer A however, is in section 2 connecting to Peer B. But Peer B is not
        listening.

        The result is that both Peer's timeout and the connection process fails.

        //////////////////////////////////////////////////////////////////////

        To remedy this issue, Section 2 was moved to the top. Now let me demonstrate
        how this issue is now solved.

        Peer A is in section 2, connecting.
        Peer B is in section 1, listening.

        A connection is established. Peer B moves to section 3. Peer A moves to
        section 1, listening. But since there is no client connecting it quickly
        moves on to section 3.

        Now both peers have gotten to section 3 and there is 1 tcp stream in use.
        The peers exchange keys and the connection is established.
        */

        // Section 2, initiate outgoing connections.
        {
            let connected_to_peers = p2p.connected_to_peers.lock().unwrap();
            let target = p2p.connect_peer_target.lock().unwrap();
            for peer_id in target.iter() {
                if let Ok(addr) = SocketAddr::from_str(&peer_id.address) {
                    if connected_to_peers.contains_key(&peer_id.public_key) {
                        continue;
                    }

                    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, P2P_TCP_TIMEOUT) {
                        println!("Outgoing p2p connection to {}", &addr);
                        stream
                            .set_read_timeout(Some(P2P_TCP_TIMEOUT))
                            .expect("Could not set read timeout on socket.");
                        stream
                            .set_write_timeout(Some(P2P_TCP_TIMEOUT))
                            .expect("Could not set write timeout on socket.");

                        if Garbage::generate().write(&mut stream).is_ok() {
                            let crypto = Cryptographer::default();
                            let ursa_key_slice = crypto.public_key.0.as_slice();
                            if stream.write_all(ursa_key_slice).is_ok() {
                                waiting_for_server_hello.push((addr, stream, crypto));
                            }
                        }
                    }
                }
            }
        }

        // Section 1, accept incomming connections.
        {
            let target_count = p2p.connect_peer_target.lock().unwrap().len();

            for _ in 0..target_count {
                if let Ok((mut stream, addr)) = p2p.listener.accept() {
                    println!("Incomming p2p connection from {}", &addr);
                    stream
                        .set_read_timeout(Some(P2P_TCP_TIMEOUT))
                        .expect("Could not set read timeout on socket.");
                    stream
                        .set_write_timeout(Some(P2P_TCP_TIMEOUT))
                        .expect("Could not set write timeout on socket.");
                    if Garbage::read(&mut stream).is_ok() {
                        let mut key = [0_u8; 32];
                        if stream.read_exact(&mut key).is_ok() {
                            let client_ursa_key = UrsaPublicKey(Vec::from(key));
                            println!("Recieved compliant client hello from {}, responding with server hello.", addr);

                            if Garbage::generate().write(&mut stream).is_ok() {
                                let mut crypto = Cryptographer::default();
                                let ursa_key_slice = crypto.public_key.0.as_slice();
                                if stream.write_all(ursa_key_slice).is_ok() {
                                    println!("Sent server hello to {}, pushing to send_public_key queue.", addr);
                                    crypto.derive_shared_key(&client_ursa_key);
                                    send_public_key.push((stream, crypto));
                                }
                            }
                        }
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }

        // Section 3, read server hello's.
        {
            for (addr, mut stream, mut crypto) in waiting_for_server_hello {
                if Garbage::read(&mut stream).is_ok() {
                    let mut key = [0_u8; 32];
                    if stream.read_exact(&mut key).is_ok() {
                        let server_ursa_key = UrsaPublicKey(Vec::from(key));
                        println!("Recieved compliant server hello from {}. Pushing to send_public_key_queue.", addr);

                        crypto.derive_shared_key(&server_ursa_key);
                        send_public_key.push((stream, crypto));
                    }
                }
            }
            waiting_for_server_hello = Vec::new();
        }

        let mut new_connections: Vec<(PublicKey, _, _)> = Vec::new();
        // Section 4, swap node level public keys.
        {
            let mut receive_public_key = Vec::new();
            for (mut stream, crypto) in send_public_key {
                let data = p2p.public_key.encode();

                if let Ok(data) = crypto.encrypt(data) {
                    let mut buf = Vec::<u8>::with_capacity(data.len() + 1);
                    #[allow(clippy::cast_possible_truncation)]
                    buf.push(data.len() as u8);
                    buf.extend_from_slice(data.as_slice());

                    if stream.write_all(&buf).is_ok() {
                        println!("Sent public key to other peer.");
                        receive_public_key.push((stream, crypto));
                    }
                } else {
                    println!("Encryption error, dropping connection.");
                }
            }
            send_public_key = Vec::new();
            for (mut stream, crypto) in receive_public_key {
                let mut size = 0_u8;
                if stream.read_exact(std::slice::from_mut(&mut size)).is_ok()
                    && (size as usize) < MAX_HANDSHAKE_LENGTH
                {
                    let mut data = vec![0_u8; size as usize];
                    if stream.read_exact(&mut data).is_ok() {
                        if let Ok(data) = crypto.decrypt(data) {
                            if let Ok(pub_key) = Decode::decode(&mut data.as_slice()) {
                                println!("Completed handshake with {}.", pub_key);
                                new_connections.push((pub_key, stream, crypto));
                            } else {
                                println!("ParityScale decode error, dropping connection.");
                            }
                        } else {
                            println!("Decryption error, dropping connection.");
                        }
                    }
                }
            }
        }

        // nocheckin
        // explain why this has to be stocastic

        // Section 5, handle new connections.
        {
            let mut connected_to_peers = p2p.connected_to_peers.lock().unwrap();
            for (public_key, stream, crypto) in new_connections {
                if connected_to_peers.contains_key(&public_key) {
                    if rand::random::<bool>() {
                        connected_to_peers.insert(public_key, (stream, crypto));
                    }
                } else {
                    connected_to_peers.insert(public_key, (stream, crypto));
                }
            }
        }
    }
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
    /// Encryptor created from session key, that we got by Diffie-Hellman scheme
    pub cipher: Option<SymmetricEncryptor<E>>,
    /// Phantom
    pub _key_exchange: PhantomData<K>,
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
        debug!(key = ?shared.0, "Derived shared key");
        let encryptor = {
            let key: &[u8] = shared.0.as_slice();
            SymmetricEncryptor::<E>::new_with_key(key)
        }
        .map_err(CryptographicError::Encrypt)?;
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
            debug!(%size, "Reading garbage");
            let mut garbage = vec![0_u8; size];
            let _ = stream.read_exact(&mut garbage)?;
            Ok(Self { garbage })
        }
    }
}
