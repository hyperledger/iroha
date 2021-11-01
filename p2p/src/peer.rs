use std::{
    fmt::{Debug, Display, Formatter},
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
use iroha_logger::{debug, info, trace, warn, ErrorLogging};
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
    fn new(connection_id: ConnectionId, stream: Option<TcpStream>) -> Self {
        // If we are connected we take apart stream for two halves.
        // If we are not connected we save Nones and wait for message to start connecting.
        let (read, write) = match stream.map(TcpStream::into_split) {
            None => (None, None),
            Some((read, write)) => (Some(read), Some(write)),
        };
        // let outgoing = read.is_none() && write.is_none();
        Connection {
            id: connection_id,
            read,
            write,
            // outgoing,
            finish_sender: None,
        }
    }
}

/// Peer's cryptographic data
pub struct Cryptographer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Clone + 'static,
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
    T: Debug + Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    fn default_or_err() -> Result<Self, Error> {
        // P2P encryption primitives
        let dh = K::new();
        let (public_key, secret_key) = dh.keypair(None).warn("Error generating keypair")?;
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
            .warn("Error creating shared secret")?;
        debug!("Derived shared key: {:?}", &shared.0);
        let encryptor = Cryptographer::<T, K, E>::new_encryptor(shared.0.as_slice())
            .warn("Error creating encryptor")?;
        self.cipher = Some(encryptor);
        Ok(self)
    }
}

/// This is an endpoint, that juggles messages between [`crate::Network`] and another connected node.
pub struct Peer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Peer identification
    id: PeerId,
    /// Peer connnection
    connection: Connection,
    /// Current peer/connection state
    state: State,
    /// Cryptographic data
    crypto: Cryptographer<T, K, E>,
    /// The to send received messages upstairs
    broker: Broker,
}

impl<T, K, E> Peer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Creates a peer
    /// # Errors
    /// If keypair creation failed. (RARE)
    pub fn new_inner(
        id: PeerId,
        connection_id: ConnectionId,
        stream: Option<TcpStream>,
        state: State,
        broker: Broker,
    ) -> Result<Self, Error> {
        Ok(Self {
            id,
            connection: Connection::new(connection_id, stream),
            state,
            broker,
            crypto: Cryptographer::default_or_err()?,
        })
    }

    /// Peer's connection id
    pub fn connection_id(&self) -> ConnectionId {
        self.connection.id
    }

    /// Creates an incoming peer
    /// # Errors
    /// If `new_inner()` errors (RARE)
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    pub fn new_from(id: PeerId, stream: TcpStream, broker: Broker) -> Result<Self, Error> {
        let connection_id = rand::random();
        Self::new_inner(
            id,
            connection_id,
            Some(stream),
            State::ConnectedFrom,
            broker,
        )
    }

    /// Creates an outgoing peer
    /// # Errors
    /// If `new_inner()` errors (RARE)
    pub fn new_to(id: PeerId, broker: Broker) -> Result<Self, Error> {
        let connection_id = rand::random();
        Self::new_inner(id, connection_id, None, State::Connecting, broker)
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
                            yield MessageResult::new_error(Error::Io(e));
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

    async fn handshake(&mut self) -> Result<&Self, Error> {
        let state = self.state;
        debug!(%state, id = %self.connection_id(), addr = %self.id.address, "Attempting handshake");
        match &self.state {
            State::Connecting => {
                self.connect().await?;
            }
            State::ConnectedTo => {
                self.send_client_hello().await?;
            }
            State::ConnectedFrom => {
                self.read_client_hello().await?;
            }
            State::SendKey => {
                self.send_our_public_key().await?;
            }
            State::GetKey => {
                self.read_their_public_key().await?;
            }
            State::Ready => warn!("Not doing handshake, already ready."),
            State::Disconnected => warn!("Not doing handshake, we are disconnected."),
            State::Error => debug!("Not doing handshake in error state."),
        }
        Ok(self)
    }

    /// Reads client public key from client hello,
    /// creates shared secret and sends our public key to client
    async fn read_client_hello(&mut self) -> Result<&Self, Error> {
        debug!("Reading client hello...");
        #[allow(clippy::expect_used)]
        let read_half = self
            .connection
            .read
            .as_mut()
            .expect("Never fails as in this function we already have the stream.");
        let public_key = read_client_hello(read_half).await?;
        self.crypto.derive_shared_key(&public_key)?;
        #[allow(clippy::expect_used)]
        let mut write_half = self
            .connection
            .write
            .as_mut()
            .expect("Never fails as in this function we already have the stream.");
        send_server_hello(&mut write_half, self.crypto.public_key.0.as_slice()).await?;
        self.state = State::SendKey;
        Ok(self)
    }

    /// Sends client hello with our public key
    async fn send_client_hello(&mut self) -> Result<&Self, Error> {
        debug!("Sending client hello...");
        #[allow(clippy::expect_used)]
        let mut write_half = self
            .connection
            .write
            .as_mut()
            .expect("Never fails as in this function we already have the stream.");
        write_half.as_ref().writable().await?;
        send_client_hello(&mut write_half, self.crypto.public_key.0.as_slice()).await?;
        // Read server hello with node's public key
        #[allow(clippy::expect_used)]
        let read_half = self
            .connection
            .read
            .as_mut()
            .expect("Never fails as in this function we already have the stream.");
        let public_key = read_server_hello(read_half).await?;
        self.crypto.derive_shared_key(&public_key)?;
        self.state = State::SendKey;
        Ok(self)
    }

    /// Sends our app public key
    async fn send_our_public_key(&mut self) -> Result<&Self, Error> {
        debug!("Sending our public key...");
        #[allow(clippy::expect_used)]
        let write_half = self
            .connection
            .write
            .as_mut()
            .expect("Never fails as in this function we already have the stream.");
        write_half.as_ref().writable().await?;

        // We take our public key from this field and will replace it with theirs when we read it
        // Packing length and message in one network packet for efficiency
        let data = self.id.public_key.encode();

        let data = &self
            .crypto
            .encrypt(data)
            .warn("Error encrypting message")
            .map_err(|e| {
                self.state = State::Error;
                e
            })?;

        let mut buf = Vec::<u8>::with_capacity(data.len() + 1);
        #[allow(clippy::cast_possible_truncation)]
        buf.push(data.len() as u8);
        buf.extend_from_slice(data.as_slice());

        write_half.write_all(&buf).await?;
        self.state = State::GetKey;
        Ok(self)
    }

    /// Reads theirs app public key
    async fn read_their_public_key(&mut self) -> Result<&Self, Error> {
        debug!("Reading their public key...");
        #[allow(clippy::unwrap_used)]
        let read_half = self.connection.read.as_mut().unwrap();
        let size = read_half.read_u8().await? as usize;
        if size >= MAX_HANDSHAKE_LENGTH {
            return Err(Error::Handshake);
        }
        // Reading public key
        read_half.as_ref().readable().await?;
        let mut data = vec![0_u8; size];
        let _ = read_half.read_exact(&mut data).await?;

        let data = self
            .crypto
            .decrypt(data)
            .warn("Error decrypting message")
            .map_err(|e| {
                self.state = State::Error;
                e
            })?;

        let pub_key = Decode::decode(&mut data.as_slice())
            .warn("Error decoding")
            .map_err(|e| {
                self.state = State::Error;
                e
            })?;
        self.id.public_key = pub_key;
        self.state = State::Ready;
        Ok(self)
    }

    /// Creates a connection to other peer
    #[allow(clippy::expect_used)]
    async fn connect(&mut self) -> Result<&Self, Error> {
        let addr = self.id.address.clone();
        debug!("Connecting to [{}]", &addr);
        let stream = TcpStream::connect(addr.clone()).await;
        match stream {
            Ok(stream) => {
                debug!("Connected to [{}]", &addr);
                let (read, write) = stream.into_split();
                self.connection.read = Some(read);
                self.connection.write = Some(write);
                self.state = State::ConnectedTo;
                Ok(self)
            }
            Err(error) => {
                warn!(%error, "Could not connect to peer on {}!", addr);
                Err(Error::Io(error))
            }
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
        f.debug_struct("Peer")
            .field("id", &self.id)
            .field("state", &self.state)
            .finish()
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
        debug!(
            "Starting actor for connection with peer {}",
            &self.id.address
        );
        self.broker.subscribe::<StopSelf, _>(ctx);
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
        debug!(
            "[{}] Starting connection and handshake, id {}",
            &self.id.address, self.connection.id
        );
        while self.state != State::Ready {
            let e = match self.handshake().await {
                Ok(_) => continue,
                Err(e) => e,
            };
            warn!(
                "[{}] Error connecting to peer in state {}. {:?}",
                &self.id.address, &self.state, e
            );

            let message = PeerMessage::<T>::Disconnected(self.id.clone(), self.connection.id);
            self.broker.issue_send(message).await;
            return;
        }

        debug!("[{}] Handshake finished", &self.id.address);
        let message = PeerMessage::<T>::Connected(self.id.clone(), self.connection.id);
        self.broker.issue_send(message).await;

        #[allow(clippy::unwrap_used)]
        let read: OwnedReadHalf = self.connection.read.take().unwrap();

        let (sender, receiver) = oneshot::channel();
        self.connection.finish_sender = Some(sender);

        // Subscribe reading stream
        ctx.notify_with(Self::stream(read, receiver));
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
        let message = match msg {
            Ok(message) => message,
            Err(error) => {
                // TODO implement some recovery
                if self.state != State::Disconnected {
                    warn!(%error, "[{}] Error in peer read!", &self.id.address);
                }
                let message = PeerMessage::<T>::Disconnected(self.id.clone(), self.connection.id);
                self.broker.issue_send(message).await;
                return;
            }
        };

        let data = match &self.crypto.cipher {
            None => message.0,
            Some(cipher) => match cipher.decrypt_easy(DEFAULT_AAD.as_ref(), message.0.as_slice()) {
                Ok(data) => data,
                Err(e) => {
                    warn!(%e, "Error decrypting message!");
                    self.state = State::Error;
                    return;
                }
            },
        };
        let decoded: Result<T, _> = Decode::decode(&mut data.as_slice());
        match decoded {
            Ok(data) => {
                let message = PeerMessage::Message(self.id.clone(), Box::new(data));
                self.broker.issue_send(message).await;
            }
            Err(e) => warn!(%e, "Error parsing message!"),
        }
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
        if self.connection.write.is_none() {
            warn!("Cannot send message to peer, as we are not connected!");
            return;
        }

        let data = match &self.crypto.cipher {
            None => msg.data.encode(),
            Some(cipher) => match cipher.encrypt_easy(DEFAULT_AAD.as_ref(), &msg.data.encode()) {
                Ok(data) => data,
                Err(e) => {
                    warn!(%e, "Error encrypting message!");
                    self.state = State::Error;
                    return;
                }
            },
        };
        trace!("Sending message");
        #[allow(clippy::unwrap_used)]
        send_message(self.connection.write.as_mut().unwrap(), data.as_slice())
            .await
            .warn("Error sending message to peer")
            .unwrap_or_else(|_| {
                self.state = State::Error;
            });
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
        let stop_self = match message {
            StopSelf::Peer(id) => id == self.connection.id,
            StopSelf::Network => true,
        };
        if stop_self {
            info!(
                "[{}] Stopping self {}",
                &self.id.address, self.connection.id
            );
            self.state = State::Disconnected;
            if let Some(sender) = self.connection.finish_sender.take() {
                let _ = sender.send(());
            }
            ctx.stop_now();
        }
    }
}

/// Peer's state
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum State {
    /// This peer is trying to connect to other end
    Connecting,
    /// This peer has a living TCP connection, ready to handshake
    ConnectedTo,
    /// This peer has just connected from outside
    ConnectedFrom,
    /// We are ready to send our public key from PeerId
    SendKey,
    /// We need to read public key for PeerId
    GetKey,
    /// Peer has handshakes done, ready to toss messages
    Ready,
    /// Peer has been disconnected
    Disconnected,
    /// Something bad happened
    Error,
}

impl Display for State {
    #[allow(clippy::use_debug)]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &self)
    }
}

/// Reads client hello
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

/// Sends client hello
/// # Errors
/// If writing encounters IO-error
pub async fn send_client_hello(stream: &mut OwnedWriteHalf, key: &[u8]) -> io::Result<()> {
    let garbage = Garbage::generate();
    garbage.write(stream).await?;
    stream.write_all(key).await?;
    Ok(())
}

/// Reads server hello
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

/// Sends server hello
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
            Err(Error::Handshake)
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
