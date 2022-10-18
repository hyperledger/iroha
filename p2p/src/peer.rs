//! Peer state machine and connection/handshake logic with ecnryption
//! and actor implementations.
#![allow(clippy::arithmetic, clippy::std_instead_of_alloc)]
use core::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
};

use async_stream::stream;
use futures::Stream;
use iroha_actor::{broker::Broker, Actor, Context, ContextHandler, Handler};
use iroha_crypto::ursa::{
    encryption::symm::{Encryptor, SymmetricEncryptor},
    kex::KeyExchangeScheme,
    keys::{PrivateKey, PublicKey},
};
use iroha_logger::{debug, error, info, trace, warn};
use parity_scale_codec::{Decode, DecodeAll, Encode};
use rand::{Rng, RngCore};
use tokio::{
    io,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::{
        oneshot,
        oneshot::{Receiver, Sender},
    },
};

use crate::{
    network::{ConnectionId, PeerMessage, Post, Start, StopSelf},
    CryptographicError, Error, HandshakeError, Message, MessageResult,
};

/// Max length of message handshake in bytes.
pub const MAX_HANDSHAKE_LENGTH: usize = 255;
/// Default associated data for AEAD
/// [`Authenticated encryption`](https://en.wikipedia.org/wiki/Authenticated_encryption)
pub const DEFAULT_AAD: &[u8; 10] = b"Iroha2 AAD";

/// P2P connection
#[derive(Debug)]
pub struct Connection {
    /// A unique connection id
    pub id: ConnectionId,
    /// Reading half of `TcpStream`
    pub read: Option<OwnedReadHalf>,
    /// Writing half of `TcpStream`
    pub write: Option<OwnedWriteHalf>,
    /// A flag that stops listening stream
    pub finish_sender: Option<Sender<()>>,
}

impl Connection {
    /// Instantiate new connection from `connection_id` and `stream`.
    pub fn new(id: ConnectionId, stream: TcpStream) -> Self {
        let (read, write) = stream.into_split();
        Connection {
            id,
            read: Some(read),
            write: Some(write),
            finish_sender: None,
        }
    }
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            id: rand::random(),
            read: None,
            write: None,
            finish_sender: None,
        }
    }
}

impl From<TcpStream> for Connection {
    fn from(stream: TcpStream) -> Self {
        let (read, write) = stream.into_split();
        Connection {
            read: Some(read),
            write: Some(write),
            ..Connection::default()
        }
    }
}

/// Peer's cryptographic primitives
pub struct Cryptographer<T, K, E>
where
    T: Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Secret part of keypair
    pub secret_key: PrivateKey,
    /// Public part of keypair
    pub public_key: PublicKey,
    /// Encryptor created from session key, that we got by Diffie-Hellman scheme
    pub cipher: Option<SymmetricEncryptor<E>>,
    /// Phantom
    pub _key_exchange: PhantomData<K>,
    /// Phantom2
    pub _post_type: PhantomData<T>,
}

impl<T, K, E> Cryptographer<T, K, E>
where
    T: Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Instantiate [`Self`].
    ///
    /// # Errors
    /// If key exchange fails to produce keypair (extremely rare)
    pub fn default_or_err() -> Result<Self, Error> {
        let key_exchange = K::new();
        let (public_key, secret_key) = key_exchange.keypair(None)?;
        Ok(Self {
            secret_key,
            public_key,
            cipher: None,
            _key_exchange: PhantomData::default(),
            _post_type: PhantomData::default(),
        })
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
    pub fn derive_shared_key(&mut self, public_key: &PublicKey) -> Result<&Self, Error> {
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

/// An endpoint, that juggles messages between [`crate::Network`] and another connected node.
/// Until the [`Peer`] is in the `Ready` state, it doesn't have a fully set up
pub enum Peer<T, K, E>
where
    T: Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Peer just created and beginning handshake process.
    Connecting(PeerId, Broker),
    /// Peer has a living TCP connection, ready to handshake.
    ConnectedTo(PeerId, Broker, Connection),
    /// Peer has just been connected to  from the outside.
    ConnectedFrom(PeerId, Broker, Connection),
    /// Peer ready to send its public key from its PeerId.
    SendKey(PeerId, Broker, Connection, Cryptographer<T, K, E>),
    /// Peer ready to read public key for PeerId.
    GetKey(PeerId, Broker, Connection, Cryptographer<T, K, E>),
    /// Peer completed handshake. Only this peer variant can send messages.
    Ready(PeerId, Broker, Connection, Cryptographer<T, K, E>),
    /// Peer has been (gracefully) disconnected.
    Disconnected(PeerId),
    /// Peer has stopped working with `Error`.
    Error(PeerId, Error),
}

impl<T, K, E> Peer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Get [`Peer`]'s `id`.
    pub fn id(&self) -> &PeerId {
        match self {
            Peer::Connecting(id, _)
            | Peer::ConnectedTo(id, _, _)
            | Peer::ConnectedFrom(id, _, _)
            | Peer::SendKey(id, _, _, _)
            | Peer::GetKey(id, _, _, _)
            | Peer::Ready(id, _, _, _)
            | Peer::Disconnected(id)
            | Peer::Error(id, _) => id,
        }
    }

    /// [`Peer`]'s [`crate::peer::Connection`]'s `id`.
    ///
    /// # Errors
    /// If peer is either `Connecting`, `Disconnected`, or `Error`-ed
    pub fn connection_id(&self) -> Result<ConnectionId, Error> {
        match self {
            Peer::ConnectedTo(_, _, connection)
            | Peer::ConnectedFrom(_, _, connection)
            | Peer::SendKey(_, _, connection, _)
            | Peer::GetKey(_, _, connection, _)
            | Peer::Ready(_, _, connection, _) => Ok(connection.id),
            _ => Err(Error::Field),
        }
    }

    /// Create outgoing [`Peer`]
    ///
    /// # Errors
    /// If `new_inner()` errors (RARE)
    pub async fn new_to(id: PeerId, broker: Broker) -> Result<Self, Error> {
        Self::Connecting(id, broker).connect().await
    }

    /// Bring [`Peer`] into `Ready` state, unless it's either `Disconnected` or `Error`-ed.
    ///
    /// # Errors
    /// If any of the handshake steps fail.
    async fn handshake(&mut self) -> Result<&Self, Error> {
        trace!(peer = ?self, "Attempting handshake");
        let mut temp = Self::Disconnected(self.id().clone());
        core::mem::swap(&mut temp, self);
        let mut result = match temp {
            Self::Connecting(_, _) => {
                temp.connect()
                    .await?
                    .send_client_hello()
                    .await?
                    .send_our_public_key()
                    .await?
                    .read_their_public_key()
                    .await?
            }
            Self::ConnectedTo(_, _, _) => {
                temp.send_client_hello()
                    .await?
                    .send_our_public_key()
                    .await?
                    .read_their_public_key()
                    .await?
            }
            Self::ConnectedFrom(_, _, _) => {
                temp.read_client_hello()
                    .await?
                    .send_our_public_key()
                    .await?
                    .read_their_public_key()
                    .await?
            }
            Self::SendKey(_, _, _, _) => {
                temp.send_our_public_key()
                    .await?
                    .read_their_public_key()
                    .await?
            }
            Self::GetKey(_, _, _, _) => temp.read_their_public_key().await?,
            Self::Ready(_, _, _, _) => {
                warn!("Not doing handshake, already ready.");
                temp
            }
            Self::Disconnected(_) => {
                warn!("Not doing handshake, we are disconnected.");
                temp
            }
            Self::Error(_, _) => {
                debug!("Not doing handshake in error state.");
                temp
            }
        };
        core::mem::swap(&mut result, self);
        Ok(self)
    }

    /// Read client public key from client "hello", create shared
    /// secret and send our public key to client.
    async fn read_client_hello(self) -> Result<Self, Error> {
        if let Self::ConnectedFrom(id, broker, mut connection) = self {
            let mut crypto = Cryptographer::default_or_err()?;
            debug!("Reading client hello...");
            #[allow(clippy::expect_used)]
            let read_half = connection
                .read
                .as_mut()
                .expect("Never fails as in this function we already have the stream.");
            let public_key = read_client_hello(read_half).await?;
            crypto.derive_shared_key(&public_key)?;
            #[allow(clippy::expect_used)]
            let write_half = connection
                .write
                .as_mut()
                .expect("Never fails as in this function we already have the stream.");
            send_server_hello(write_half, crypto.public_key.0.as_slice()).await?;
            Ok(Self::SendKey(id, broker, connection, crypto))
        } else {
            error!(peer = ?self, "Incorrect state.");
            Err(HandshakeError::State(format!("Should be `ConnectedFrom`. Got {self:?}")).into())
        }
    }

    /// Send client "hello" with our public key.
    async fn send_client_hello(self) -> Result<Self, Error> {
        if let Self::ConnectedTo(id, broker, mut connection) = self {
            trace!(conn = ?connection, "Sending client hello...");
            #[allow(clippy::expect_used)]
            let write_half = connection
                .write
                .as_mut()
                .expect("Never fails as in this function we already have the stream.");
            write_half.as_ref().writable().await?;
            let mut crypto = Cryptographer::default_or_err()?;
            send_client_hello(write_half, crypto.public_key.0.as_slice()).await?;
            // Read server hello with node's public key
            #[allow(clippy::expect_used)]
            let read_half = connection
                .read
                .as_mut()
                .expect("Never fails as in this function we already have the stream.");
            let public_key = read_server_hello(read_half).await?;
            crypto.derive_shared_key(&public_key)?;
            Ok(Self::SendKey(id, broker, connection, crypto))
        } else {
            error!(peer = ?self, "Incorrect state.");
            Err(HandshakeError::State(format!("Should `ConnectedTo`. Got {self:?}")).into())
        }
    }

    /// Send peer's public key
    async fn send_our_public_key(self) -> Result<Self, Error> {
        trace!(peer = ?self, "Sending our public key.");
        if let Self::SendKey(id, broker, mut connection, crypto) = self {
            #[allow(clippy::expect_used)]
            let write_half = connection
                .write
                .as_mut()
                .expect("Never fails as in this function we already have the stream.");
            write_half.as_ref().writable().await?;

            // We take our public key from our `id` and will replace it with theirs when we read it
            // Packing length and message in one network packet for efficiency
            let data = id.public_key.encode();

            let data = &crypto.encrypt(data)?;

            let mut buf = Vec::<u8>::with_capacity(data.len() + 1);
            #[allow(clippy::cast_possible_truncation)]
            buf.push(data.len() as u8);
            buf.extend_from_slice(data.as_slice());

            write_half.write_all(&buf).await?;
            Ok(Self::GetKey(id, broker, connection, crypto))
        } else {
            error!(peer = ?self, "Incorrect state.");
            Err(HandshakeError::State(format!("Should be `SendKey`. Got {self:?}")).into())
        }
    }

    /// Read external client app's public key
    async fn read_their_public_key(self) -> Result<Self, Error> {
        trace!(peer = ?self, "Reading their public key.");
        if let Self::GetKey(mut id, broker, mut connection, crypto) = self {
            #[allow(clippy::unwrap_used)]
            let read_half = connection.read.as_mut().unwrap();
            let size = read_half.read_u8().await? as usize;
            if size >= MAX_HANDSHAKE_LENGTH {
                return Err(HandshakeError::Length(size).into());
            }
            // Reading public key
            read_half.as_ref().readable().await?;
            let mut data = vec![0_u8; size];
            let _ = read_half.read_exact(&mut data).await?;

            let data = crypto.decrypt(data)?;

            let pub_key = Decode::decode(&mut data.as_slice())?;

            id.public_key = pub_key;
            Ok(Self::Ready(id, broker, connection, crypto))
        } else {
            error!(peer = ?self, "Incorrect state.");
            Err(HandshakeError::State(format!("Should be `GetKey`. Got {self:?}")).into())
        }
    }

    /// Establish a [`Connection`] with external
    /// peer. The external peer's address is encoded in
    /// `self.id.address`.
    /// # Errors
    /// If [`TcpStream::connect`] fails.
    #[allow(clippy::expect_used)]
    pub(crate) async fn connect(self) -> Result<Self, Error> {
        trace!(peer = ?self, "Establishing connection");
        if let Self::Connecting(id, broker) = self {
            let addr = id.address.clone();
            debug!(peer_addr = ?addr, "Connecting");
            let stream = TcpStream::connect(addr.clone()).await?;
            debug!(peer_addr = ?addr, "Connected to");
            let connection = Connection::new(rand::random(), stream);
            Ok(Self::ConnectedTo(id, broker, connection))
        } else {
            Err(HandshakeError::State(format!("Should be `Connecting`. Got {self:?}")).into())
        }
    }
}

impl<T, K, E> Debug for Peer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Peer::Connecting(_, _) => f.debug_struct("Connecting"),
            Peer::ConnectedTo(_, _, _) => f.debug_struct("ConnectedTo"),
            Peer::ConnectedFrom(_, _, _) => f.debug_struct("ConnectedFrom"),
            Peer::SendKey(_, _, _, _) => f.debug_struct("SendKey"),
            Peer::GetKey(_, _, _, _) => f.debug_struct("GetKey"),
            Peer::Ready(_, _, _, _) => f.debug_struct("Ready"),
            Peer::Disconnected(_) => f.debug_struct("Disconnected"),
            Peer::Error(_, _) => f.debug_struct("Error"),
        }
        .field("id.address", &self.id().address)
        .field("connection.id", &self.connection_id())
        .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl<T, K, E> Actor for Peer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        trace!(peer = ?self, "Starting actor");
        match self {
            Peer::Connecting(id, broker)
            | Peer::ConnectedTo(id, broker, _)
            | Peer::ConnectedFrom(id, broker, _)
            | Peer::SendKey(id, broker, _, _)
            | Peer::GetKey(id, broker, _, _)
            | Peer::Ready(id, broker, _, _) => {
                debug!(peer_addr = %id.address, "Starting actor for connection with peer");
                broker.subscribe::<StopSelf, _>(ctx);
            }
            Peer::Disconnected(_) => warn!("Peer already stopped."),
            Peer::Error(_, _) => warn!("Peer broken. Handle Error first."),
        };
    }
}

#[async_trait::async_trait]
impl<T, K, E> ContextHandler<Start> for Peer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, ctx: &mut Context<Self>, Start: Start) {
        let mut dummy = Self::Disconnected(self.id().clone());
        core::mem::swap(&mut dummy, self);
        trace!(
            peer = ?dummy,
            "Starting connection and handshake"
        );
        if dummy.handshake().await.is_err() {
            return;
        }
        if let Self::Ready(id, broker, mut connection, crypto) = dummy {
            debug!(peer_addr = %id.address, "Handshake finished");
            let connected_message = PeerMessage::<T>::Connected(id.clone(), connection.id);
            broker.issue_send(connected_message).await;

            #[allow(clippy::unwrap_used)]
            let read: OwnedReadHalf = connection.read.take().unwrap();

            let (sender, receiver) = oneshot::channel();
            connection.finish_sender = Some(sender);

            // Subscribe reading stream
            ctx.notify_with(read_connection_stream(read, receiver));
            dummy = Self::Ready(id, broker, connection, crypto);
            core::mem::swap(&mut dummy, self);
        } else {
            error!(peer = ?self, "Handshake didn't fail, but the peer is not ready");
        }
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<MessageResult> for Peer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, MessageResult(msg): MessageResult) {
        if let Self::Ready(id, broker, connection, crypto) = self {
            let message = match msg {
                Ok(this_message) => this_message,
                Err(error) => {
                    warn!(%error, "Error reading message");
                    // TODO implement some recovery
                    let disconnect_message =
                        PeerMessage::<T>::Disconnected(id.clone(), connection.id);
                    broker.issue_send(disconnect_message).await;
                    return;
                }
            };

            let data = match &crypto.cipher {
                None => message.0,
                Some(cipher) => {
                    match cipher.decrypt_easy(DEFAULT_AAD.as_ref(), message.0.as_slice()) {
                        Ok(data) => data,
                        Err(error) => {
                            warn!(%error, "Error decrypting message!");
                            let mut new_self =
                                Self::Error(id.clone(), CryptographicError::Decrypt(error).into());
                            core::mem::swap(&mut new_self, self);
                            return;
                        }
                    }
                }
            };
            let mut decoded: Result<T, _> = DecodeAll::decode_all(&mut data.as_slice());
            if decoded.is_err() {
                warn!("Error parsing message using all bytes");
                decoded = Decode::decode(&mut data.as_slice());
            }
            match decoded {
                Ok(decoded_data) => {
                    let message_with_data =
                        PeerMessage::Message(id.clone(), Box::new(decoded_data));
                    broker.issue_send(message_with_data).await;
                }
                Err(error) => warn!(%error, "Error parsing message!"),
            }
        } else {
            warn!(peer = ?self, "Peer not yet ready");
        };
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<Post<T>> for Peer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, msg: Post<T>) {
        trace!(msg = ?msg, peer = ?self, "Handling post request");
        if let Self::Ready(id, _, connection, crypto) = self {
            if connection.write.is_none() {
                warn!(peer = ?self, "No connection.");
                return;
            }
            let data = match &crypto.cipher {
                None => msg.data.encode(),
                Some(cipher) => match cipher.encrypt_easy(DEFAULT_AAD.as_ref(), &msg.data.encode())
                {
                    Ok(data) => data,
                    Err(error) => {
                        warn!(%error, "Error encrypting message!");
                        let mut new_self =
                            Self::Error(id.clone(), CryptographicError::Encrypt(error).into());
                        core::mem::swap(&mut new_self, self);
                        return;
                    }
                },
            };
            trace!("Sending message");
            #[allow(clippy::unwrap_used)]
            if let Err(e) = send_message(connection.write.as_mut().unwrap(), data.as_slice()).await
            {
                let mut new_self = Self::Error(id.clone(), e);
                core::mem::swap(&mut new_self, self);
            }
        } else {
            warn!("Peer not ready. Cannot send message.");
        }
    }
}

#[async_trait::async_trait]
impl<T, K, E> ContextHandler<StopSelf> for Peer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, ctx: &mut Context<Self>, msg: StopSelf) {
        trace!(peer = ?self, "Stop request");
        let stop_self = match msg {
            StopSelf::Peer(id) => match self.connection_id() {
                Ok(my_id) => id == my_id,
                Err(_) => false,
            },
            StopSelf::Network => true,
        };
        if stop_self {
            match self {
                Peer::ConnectedTo(_, _, connection)
                | Peer::ConnectedFrom(_, _, connection)
                | Peer::SendKey(_, _, connection, _)
                | Peer::GetKey(_, _, connection, _)
                | Peer::Ready(_, _, connection, _) => {
                    if let Some(sender) = connection.finish_sender.take() {
                        let _ = sender.send(());
                    }
                }
                _ => (),
            };
            info!(peer = ?self, "Stopping.");
            let mut disconnected = Self::Disconnected(self.id().clone());
            core::mem::swap(&mut disconnected, self);
            ctx.stop_now();
        }
    }
}

/// Read client hello.
///
/// # Errors
/// If reading encounters IO-error
pub async fn read_client_hello(stream: &mut OwnedReadHalf) -> Result<PublicKey, Error> {
    stream.as_ref().readable().await?;
    Garbage::read(stream).await?;
    // And then we have clients public key
    stream.as_ref().readable().await?;
    let mut key = [0_u8; 32];
    let _ = stream.read_exact(&mut key).await?;
    Ok(PublicKey(Vec::from(key)))
}

/// Send client hello.
///
/// # Errors
/// If writing to `stream` fails.
pub async fn send_client_hello(stream: &mut OwnedWriteHalf, key: &[u8]) -> io::Result<()> {
    let garbage = Garbage::generate();
    garbage.write(stream).await?;
    stream.write_all(key).await?;
    Ok(())
}

/// Read server hello.
///
/// # Errors
/// If reading from `stream` fails, or if the exact key is not present in the stream.
pub async fn read_server_hello(stream: &mut OwnedReadHalf) -> Result<PublicKey, Error> {
    stream.as_ref().readable().await?;
    Garbage::read(stream).await?;
    // Then we have servers public key
    stream.as_ref().readable().await?;
    let mut key = [0_u8; 32];
    let _ = stream.read_exact(&mut key).await?;
    Ok(PublicKey(Vec::from(key)))
}

/// Send server hello.
///
/// # Errors
/// If writing to `stream` fails.
pub async fn send_server_hello(stream: &mut OwnedWriteHalf, key: &[u8]) -> io::Result<()> {
    let garbage = Garbage::generate();
    garbage.write(stream).await?;
    stream.write_all(key).await?;
    Ok(())
}

/// Read message from `stream` returning the message truncated to `MAX_MESSAGE_LENGTH`.
///
/// # Errors
/// If reading from `stream` fails, if the stream doesn't contain exactly `size` zeroes,
/// where `size` is the first `u32` of the `stream`.
pub async fn read_message(stream: &mut OwnedReadHalf) -> Result<Message, Error> {
    let size = stream.read_u32().await? as usize;
    if size > 0 {
        let mut buf = vec![0_u8; size];
        let mut read = 0;
        while read < size {
            stream.as_ref().readable().await?;
            read += stream.read_exact(&mut buf[read..]).await?;
        }
        Ok(Message(buf))
    } else {
        Err(Error::Format)
    }
}

/// Send byte-encoded message to the peer
///
/// # Errors
/// If writing to `stream` fails.
pub async fn send_message(stream: &mut OwnedWriteHalf, data: &[u8]) -> Result<(), Error> {
    #[allow(clippy::cast_possible_truncation)]
    let size: u32 = data.len() as u32;
    let mut buf: Vec<u8> = Vec::with_capacity(data.len() + 2);
    buf.write_u32(size).await?;
    buf.write_all(data).await?;
    stream.as_ref().writable().await?;
    stream.write_all(buf.as_slice()).await?;
    stream.flush().await?;
    Ok(())
}

/// Read the peer's connection stream and close the stream once done.
pub fn read_connection_stream(
    mut read: OwnedReadHalf,
    mut finish: Receiver<()>,
) -> impl Stream<Item = MessageResult> + Send + 'static {
    stream! {
        loop {
            tokio::select! {
                readable = read.as_ref().readable() => {
                    if let Err(e) = readable {
                        yield MessageResult::new_error(Error::Io(std::sync::Arc::new(e)));
                        break;
                    }
                    let result = match read_message(&mut read).await {
                        Ok(message) => MessageResult::new_message(message),
                        Err(e) => {
                            yield MessageResult::new_error(e);
                            break;
                        }
                    };
                    yield result;
                }
                _ = (&mut finish) => {
                    info!("Connection stream finished");
                    break;
                }
                else => break,
            }
        }
    }
}

/// Peer's identification.
pub type PeerId = iroha_data_model::peer::Id;

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

    pub async fn write(&self, stream: &mut OwnedWriteHalf) -> io::Result<()> {
        #[allow(clippy::cast_possible_truncation)]
        stream.write_u8(self.garbage.len() as u8).await?;
        stream.write_all(self.garbage.as_slice()).await
    }

    pub async fn read(stream: &mut OwnedReadHalf) -> Result<Self, Error> {
        let size = stream.read_u8().await? as usize;
        if size >= MAX_HANDSHAKE_LENGTH {
            Err(HandshakeError::Length(size).into())
        } else {
            // Reading garbage
            debug!(%size, "Reading garbage");
            let mut garbage = vec![0_u8; size];
            stream.as_ref().readable().await?;
            let _ = stream.read_exact(&mut garbage).await?;
            Ok(Self { garbage })
        }
    }
}
