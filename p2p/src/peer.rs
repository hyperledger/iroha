use std::{
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
// Clippy false positive.
#[allow(unused_imports)]
use iroha_logger::ErrorLogging;
use iroha_logger::{debug, error, info, trace, warn};
use parity_scale_codec::{Decode, Encode};
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
    Error, Message, MessageResult,
};

const MAX_MESSAGE_LENGTH: usize = 16 * 1024 * 1024;
const MAX_HANDSHAKE_LENGTH: usize = 255;
/// Default associated data for AEAD
/// [`Authenticated encryption`](https://en.wikipedia.org/wiki/Authenticated_encryption)
pub const DEFAULT_AAD: &[u8; 10] = b"Iroha2 AAD";

#[derive(Debug)]
/// Peer's connection data
pub struct Connection {
    /// A unique connection id
    id: ConnectionId,
    /// Reading half of `TcpStream`
    read: Option<OwnedReadHalf>,
    /// Writing half of `TcpStream`
    write: Option<OwnedWriteHalf>,
    /// A flag that stops listening stream
    finish_sender: Option<Sender<()>>,
}

impl Connection {
    /// Instantiate new connection from `connection_id` and `stream`.
    pub fn new(connection_id: ConnectionId, stream: TcpStream) -> Self {
        let (read, write) = stream.into_split();
        // let outgoing = read.is_none() && write.is_none();
        Connection {
            id: connection_id,
            read: Some(read),
            write: Some(write),
            // outgoing,
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

/// Peer's cryptographic data
pub struct Cryptographer<T, K, E>
where
    T: Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Secret part of keypair
    secret_key: PrivateKey,
    /// Public part of keypair
    public_key: PublicKey,
    /// Encryptor created from session key, that we got by Diffie-Hellman scheme
    cipher: Option<SymmetricEncryptor<E>>,
    /// Phantom
    _key_exchange: PhantomData<K>,
    /// Phantom2
    _post_type: PhantomData<T>,
}

impl<T, K, E> Cryptographer<T, K, E>
where
    T: Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    fn default_or_err() -> Result<Self, Error> {
        // P2P encryption primitives
        let dh = K::new();
        let (public_key, secret_key) = dh.keypair(None).log_warn("Error generating keypair")?;
        Ok(Self {
            secret_key,
            public_key,
            cipher: None,
            _key_exchange: PhantomData::default(),
            _post_type: PhantomData::default(),
        })
    }

    fn decrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        match &self.cipher {
            None => Ok(data),
            Some(cipher) => Ok(cipher.decrypt_easy(DEFAULT_AAD.as_ref(), data.as_slice())?),
        }
    }

    fn encrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        match &self.cipher {
            None => Ok(data),
            Some(cipher) => Ok(cipher.encrypt_easy(DEFAULT_AAD.as_ref(), data.as_slice())?),
        }
    }

    fn new_encryptor(key: &[u8]) -> Result<SymmetricEncryptor<E>, aead::Error> {
        SymmetricEncryptor::<E>::new_with_key(key)
    }

    /// Creates a shared key from two public keys - local and external,
    /// then instantiates an encryptor from that key.
    fn derive_shared_key(&mut self, public_key: &PublicKey) -> Result<&Self, Error> {
        let dh = K::new();
        let shared = dh
            .compute_shared_secret(&self.secret_key, public_key)
            .log_warn("Error creating shared secret")?;
        debug!("Derived shared key: {:?}", &shared.0);
        let encryptor = Cryptographer::<T, K, E>::new_encryptor(shared.0.as_slice())
            .log_warn("Error creating encryptor")?;
        self.cipher = Some(encryptor);
        Ok(self)
    }
}

/// This is an endpoint, that juggles messages between [`crate::Network`] and another connected node.
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
    /// Peer's id.
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

    /// Peer's connection id
    /// # Errors
    /// If peer is either `Connecting`, `Disconnected`, or `Error`-ed
    pub fn connection_id(&self) -> Result<ConnectionId, Error> {
        match self {
            Peer::Connecting(_, _) => Err(Error::Handshake(std::line!())),
            Peer::ConnectedTo(_, _, connection)
            | Peer::ConnectedFrom(_, _, connection)
            | Peer::SendKey(_, _, connection, _)
            | Peer::GetKey(_, _, connection, _)
            | Peer::Ready(_, _, connection, _) => Ok(connection.id),
            Peer::Disconnected(_) => Err(Error::Handshake(std::line!())),
            Peer::Error(_, _) => Err(Error::Handshake(std::line!())),
        }
    }

    /// Creates an outgoing peer
    /// # Errors
    /// If `new_inner()` errors (RARE)
    pub async fn new_to(id: PeerId, broker: Broker) -> Result<Self, Error> {
        Self::Connecting(id, broker).connect().await
    }

    async fn handshake(&mut self) -> Result<&Self, Error> {
        trace!(peer = ?self, "Attempting handshake");
        let mut temp = Self::Disconnected(self.id().clone());
        std::mem::swap(&mut temp, self);
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
        std::mem::swap(&mut result, self);
        Ok(self)
    }

    /// Reads client public key from client hello,
    /// creates shared secret and sends our public key to client
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
            let mut write_half = connection
                .write
                .as_mut()
                .expect("Never fails as in this function we already have the stream.");
            send_server_hello(&mut write_half, crypto.public_key.0.as_slice()).await?;
            Ok(Self::SendKey(id, broker, connection, crypto))
        } else {
            error!(peer = ?self, "Incorrect state.");
            Err(Error::Handshake(std::line!()))
        }
    }

    /// Sends client hello with our public key
    async fn send_client_hello(self) -> Result<Self, Error> {
        if let Self::ConnectedTo(id, broker, mut connection) = self {
            trace!(conn = ?connection, "Sending client hello...");
            #[allow(clippy::expect_used)]
            let mut write_half = connection
                .write
                .as_mut()
                .expect("Never fails as in this function we already have the stream.");
            write_half.as_ref().writable().await?;
            let mut crypto = Cryptographer::default_or_err()?;
            send_client_hello(&mut write_half, crypto.public_key.0.as_slice()).await?;
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
            Err(Error::Handshake(std::line!()))
        }
    }

    /// Sends our app public key
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

            let data = &crypto.encrypt(data).log_warn("Error encrypting message")?;

            let mut buf = Vec::<u8>::with_capacity(data.len() + 1);
            #[allow(clippy::cast_possible_truncation)]
            buf.push(data.len() as u8);
            buf.extend_from_slice(data.as_slice());

            write_half.write_all(&buf).await?;
            Ok(Self::GetKey(id, broker, connection, crypto))
        } else {
            error!(peer = ?self, "Incorrect state.");
            Err(Error::Handshake(std::line!()))
        }
    }

    /// Reads theirs app public key
    async fn read_their_public_key(self) -> Result<Self, Error> {
        trace!(peer = ?self, "Reading their public key.");
        if let Self::GetKey(mut id, broker, mut connection, crypto) = self {
            #[allow(clippy::unwrap_used)]
            let read_half = connection.read.as_mut().unwrap();
            let size = read_half.read_u8().await? as usize;
            if size >= MAX_HANDSHAKE_LENGTH {
                return Err(Error::Handshake(std::line!()));
            }
            // Reading public key
            read_half.as_ref().readable().await?;
            let mut data = vec![0_u8; size];
            let _ = read_half.read_exact(&mut data).await?;

            let data = crypto.decrypt(data).log_warn("Error decrypting message")?;

            let pub_key = Decode::decode(&mut data.as_slice()).log_warn("Error decoding")?;

            id.public_key = pub_key;
            Ok(Self::Ready(id, broker, connection, crypto))
        } else {
            error!(peer = ?self, "Incorrect state.");
            Err(Error::Handshake(std::line!()))
        }
    }

    /// Creates a connection to other peer
    #[allow(clippy::expect_used)]
    pub(crate) async fn connect(self) -> Result<Self, Error> {
        trace!(peer = ?self, "Connect request");
        if let Self::Connecting(id, broker) = self {
            let addr = id.address.clone();
            debug!(addr = ?addr, "Connecting");
            let stream = TcpStream::connect(addr.clone())
                .await
                .log_warn(&format!("Failure to connect to {}", &addr))?;
            debug!(addr = ?addr, "Connected to");
            let connection = Connection::new(rand::random(), stream);
            Ok(Self::ConnectedTo(id, broker, connection))
        } else {
            Err(Error::Handshake(std::line!()))
        }
    }
}

impl<T, K, E> Debug for Peer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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
                debug!(addr = %id.address, "Starting actor for connection with peer");
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
        std::mem::swap(&mut dummy, self);
        trace!(
            peer = ?dummy,
            "Starting connection and handshake"
        );
        if dummy.handshake().await.log_err("Handshake Failed").is_err() {
            return;
        }
        if let Self::Ready(id, broker, mut connection, crypto) = dummy {
            debug!(addr = %id.address, "Handshake finished");
            let message = PeerMessage::<T>::Connected(id.clone(), connection.id);
            broker.issue_send(message).await;

            #[allow(clippy::unwrap_used)]
            let read: OwnedReadHalf = connection.read.take().unwrap();

            let (sender, receiver) = oneshot::channel();
            connection.finish_sender = Some(sender);

            // Subscribe reading stream
            ctx.notify_with(stream(read, receiver));
            dummy = Self::Ready(id, broker, connection, crypto);
            std::mem::swap(&mut dummy, self);
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
                Ok(message) => message,
                Err(error) => {
                    warn!(%error, "Error reading message");
                    // TODO implement some recovery
                    let message = PeerMessage::<T>::Disconnected(id.clone(), connection.id);
                    broker.issue_send(message).await;
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
                            let mut new_self = Self::Error(id.clone(), Error::from(error));
                            std::mem::swap(&mut new_self, self);
                            return;
                        }
                    }
                }
            };
            let decoded: Result<T, _> = Decode::decode(&mut data.as_slice());
            match decoded {
                Ok(data) => {
                    let message = PeerMessage::Message(id.clone(), Box::new(data));
                    broker.issue_send(message).await;
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
        trace!(message = ?msg, peer = ?self, "Handling post request");
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
                        let mut new_self = Self::Error(id.clone(), Error::from(error));
                        std::mem::swap(&mut new_self, self);
                        return;
                    }
                },
            };
            trace!("Sending message");
            #[allow(clippy::unwrap_used)]
            if let Err(e) = send_message(connection.write.as_mut().unwrap(), data.as_slice())
                .await
                .log_warn("Error sending message to peer")
            {
                let mut new_self = Self::Error(id.clone(), e);
                std::mem::swap(&mut new_self, self);
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

    async fn handle(&mut self, ctx: &mut Context<Self>, message: StopSelf) {
        trace!(peer = ?self, "Stop request");
        let stop_self = match message {
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
            info!(peer = ?self, "Stopping.", );
            let mut disconnected = Self::Disconnected(self.id().clone());
            std::mem::swap(&mut disconnected, self);
            ctx.stop_now();
        }
    }
}

/// Read client hello
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

/// Send client hello
/// # Errors
/// If writing encounters IO-error
pub async fn send_client_hello(stream: &mut OwnedWriteHalf, key: &[u8]) -> io::Result<()> {
    let garbage = Garbage::generate();
    garbage.write(stream).await?;
    stream.write_all(key).await?;
    Ok(())
}

/// Read server hello
/// # Errors
/// If reading encounters IO-error
pub async fn read_server_hello(stream: &mut OwnedReadHalf) -> Result<PublicKey, Error> {
    stream.as_ref().readable().await?;
    Garbage::read(stream).await?;
    // Then we have servers public key
    stream.as_ref().readable().await?;
    let mut key = [0_u8; 32];
    let _ = stream.read_exact(&mut key).await?;
    Ok(PublicKey(Vec::from(key)))
}

/// Send server hello
/// # Errors
/// If writing encounters IO-error
async fn send_server_hello(stream: &mut OwnedWriteHalf, key: &[u8]) -> io::Result<()> {
    let garbage = Garbage::generate();
    garbage.write(stream).await?;
    stream.write_all(key).await?;
    Ok(())
}

async fn read_message(stream: &mut OwnedReadHalf) -> Result<Message, Error> {
    let size = stream.read_u32().await? as usize;
    if size > 0 && size < MAX_MESSAGE_LENGTH {
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

/// Sends byte-encoded message to the peer
/// # Errors
/// If writing encounters IO-error, or the message length is more than `MAX_MESSAGE_LENGTH`.
pub async fn send_message(stream: &mut OwnedWriteHalf, data: &[u8]) -> Result<(), Error> {
    if data.len() > MAX_MESSAGE_LENGTH {
        warn!(
            "Message length exceeds maximum length of {}!",
            MAX_MESSAGE_LENGTH
        );
        Err(Error::Format)
    } else {
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
}

fn stream(
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

/// Just a placeholder, that can skip garbage bytes and generate them.
struct Garbage {
    garbage: Vec<u8>,
}

impl Garbage {
    pub fn generate() -> Self {
        let rng = &mut rand::thread_rng();
        let mut garbage = vec![0_u8; rng.gen_range(64, 256)];
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
            Err(Error::Handshake(std::line!()))
        } else {
            // Reading garbage
            debug!("Garbage size: {}, reading...", size);
            let mut garbage = vec![0_u8; size];
            stream.as_ref().readable().await?;
            let _ = stream.read_exact(&mut garbage).await?;
            Ok(Self { garbage })
        }
    }
}
