use std::{
    collections::hash_map::DefaultHasher,
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
    marker::PhantomData,
    net::SocketAddr,
};

use async_stream::stream;
use futures::Stream;
use iroha_actor::{broker::Broker, Actor, Context, ContextHandler, Handler};
use iroha_logger::{debug, warn};
use parity_scale_codec::{Decode, Encode};
use rand::{Rng, RngCore};
use tokio::{
    io,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    time,
    time::Duration,
};
use ursa::{
    encryption::symm::{Encryptor, SymmetricEncryptor},
    kex::KeyExchangeScheme,
    keys::{PrivateKey, PublicKey},
};

use crate::{
    network::{ConnectionId, PeerMessage, Post, StopSelf},
    Error, Message, MessageResult,
};

const MAX_MESSAGE_LENGTH: usize = 2 * 1024 * 1024;
const MAX_HANDSHAKE_LENGTH: usize = 255;
const MAX_CONNECTION_RETRY_COUNT: u64 = 100;
const CONNECTION_RETRY_PERIOD: u64 = 500;
/// Default associated data for AEAD
/// [`Authenticated encryption`](https://en.wikipedia.org/wiki/Authenticated_encryption)
pub const DEFAULT_AAD: &[u8; 10] = b"Iroha2 AAD";

/// This is an endpoint, that joggles messages between [`Network`] and another connected node.
pub struct Peer<T, K, E>
where
    T: Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Peer identification
    pub id: PeerId,
    /// An unique connection id
    pub connection_id: ConnectionId,
    /// Reading half of `TcpStream`
    pub read: Option<OwnedReadHalf>,
    /// Writing half of `TcpStream`
    pub write: Option<OwnedWriteHalf>,
    /// Current peer/connection state
    pub state: State,
    /// Secret part of keypair
    pub secret_key: PrivateKey,
    /// Public part of keypair
    pub public_key: PublicKey,
    /// Encryptor created from session key, that we got by Diffie-Hellman scheme
    pub cipher: Option<SymmetricEncryptor<E>>,
    /// The to send received messages upstairs
    pub broker: Broker,
    /// Phantom
    pub _key_exchange: PhantomData<K>,
    /// Phantom2
    pub _post_type: PhantomData<T>,
}

impl<T, K, E> Peer<T, K, E>
where
    T: Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Creates a peer
    /// # Errors
    /// If it can not create a keypair, so never
    pub fn new_inner(
        id: PeerId,
        connection_id: ConnectionId,
        stream: Option<TcpStream>,
        state: State,
        broker: Broker,
    ) -> Result<Self, Error> {
        // P2P encryption primitives
        let dh = K::new();
        let (public_key, secret_key) = match dh.keypair(None) {
            Ok((public_key, secret_key)) => (public_key, secret_key),
            Err(e) => {
                warn!(%e, "Error generating keypair");
                return Err(Error::Keys);
            }
        };
        // If we are connected we take apart stream for two halves.
        // If we are not connected we save Nones and wait for message to start connecting.
        let (read, write) = match stream.map(TcpStream::into_split) {
            None => (None, None),
            Some((read, write)) => (Some(read), Some(write)),
        };
        Ok(Self {
            id,
            connection_id,
            read,
            write,
            state,
            secret_key,
            public_key,
            cipher: None,
            broker,
            _key_exchange: PhantomData::default(),
            _post_type: PhantomData::default(),
        })
    }

    /// Creates an incoming peer
    /// # Errors
    /// If `new_inner()` errors.
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    pub fn new_from(id: PeerId, stream: TcpStream, broker: Broker) -> Result<Self, Error> {
        // We hash remote address here as their port will be more random
        let connection_id =
            get_connection_id(&stream.peer_addr().expect("We always have the address here"));
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
    /// If `new_inner()` errors.
    pub fn new_to(id: PeerId, broker: Broker) -> Result<Self, Error> {
        Self::new_inner(id, 0_u64, None, State::Connecting, broker)
    }

    fn stream(mut read: OwnedReadHalf) -> impl Stream<Item = MessageResult> + Send + 'static {
        stream! {
            loop {
                if let Err(e) = read.as_ref().readable().await {
                    yield MessageResult::new_error(Error::Io(e));
                    break;
                }
                let result = match read_message(&mut read).await {
                    Ok(message) => MessageResult::new_message(message),
                    Err(e) => MessageResult::new_error(e)
                };

                yield result;
            }
        }
    }

    async fn handshake(&mut self) -> Result<(), Error> {
        let state = self.state;
        debug!(%state, "Attempting handshake");
        match &self.state {
            State::Connecting => self.connect().await?,
            State::ConnectedTo => self.send_client_hello().await?,
            State::ConnectedFrom => self.read_client_hello().await?,
            State::SendKey => self.send_our_public_key().await?,
            State::GetKey => self.read_theirs_public_key().await?,
            State::Ready => warn!("Not doing handshake, already ready."),
            State::Error => warn!("Not doing handshake in error state."),
        }
        Ok(())
    }

    /// Reads client public key from client hello,
    /// creates shared secret and sends our public key to client
    async fn read_client_hello(&mut self) -> Result<(), Error> {
        debug!("Reading client hello...");
        #[allow(clippy::expect_used)]
        let read_half = self
            .read
            .as_mut()
            .expect("Never fails as in this function we already have the stream.");
        let public_key = read_client_hello(read_half).await?;
        self.derive_shared_key(&public_key)?;
        #[allow(clippy::expect_used)]
        let mut write_half = self
            .write
            .as_mut()
            .expect("Never fails as in this function we already have the stream.");
        send_server_hello(&mut write_half, self.public_key.0.as_slice()).await?;
        self.state = State::SendKey;
        Ok(())
    }

    /// Sends client hello with our public key
    async fn send_client_hello(&mut self) -> Result<(), Error> {
        debug!("Sending client hello...");
        #[allow(clippy::expect_used)]
        let mut write_half = self
            .write
            .as_mut()
            .expect("Never fails as in this function we already have the stream.");
        write_half.as_ref().writable().await?;
        send_client_hello(&mut write_half, self.public_key.0.as_slice()).await?;
        // Read server hello with node's public key
        #[allow(clippy::expect_used)]
        let read_half = self
            .read
            .as_mut()
            .expect("Never fails as in this function we already have the stream.");
        let public_key = read_server_hello(read_half).await?;
        self.derive_shared_key(&public_key)?;
        self.state = State::SendKey;
        Ok(())
    }

    /// Sends our app public key
    async fn send_our_public_key(&mut self) -> Result<(), Error> {
        debug!("Sending our public key...");
        #[allow(clippy::expect_used)]
        let write_half = self
            .write
            .as_mut()
            .expect("Never fails as in this function we already have the stream.");
        write_half.as_ref().writable().await?;

        // We take our public key from this field and will replace it with theirs when we read it
        // Packing length and message in one network packet for efficiency
        let data = self.id.public_key.encode();

        let data = match &self.cipher {
            None => data,
            Some(cipher) => match cipher.encrypt_easy(DEFAULT_AAD.as_ref(), data.as_slice()) {
                Ok(data) => data,
                Err(e) => {
                    warn!(%e, "Error decrypting message!");
                    self.state = State::Error;
                    return Err(Error::Keys);
                }
            },
        };

        let mut buf = Vec::<u8>::with_capacity(data.len() + 1);
        #[allow(clippy::cast_possible_truncation)]
        buf.push(data.len() as u8);
        buf.extend_from_slice(data.as_slice());

        write_half.write_all(&buf).await?;
        self.state = State::GetKey;
        Ok(())
    }

    /// Reads theirs app public key
    async fn read_theirs_public_key(&mut self) -> Result<(), Error> {
        debug!("Reading theirs public key...");
        #[allow(clippy::unwrap_used)]
        let read_half = self.read.as_mut().unwrap();
        let size = read_half.read_u8().await? as usize;
        if size >= MAX_HANDSHAKE_LENGTH {
            return Err(Error::Handshake);
        }
        // Reading public key
        let mut data = vec![0_u8; size];
        let _ = read_half.read_exact(&mut data).await?;

        let data = match &self.cipher {
            None => data,
            Some(cipher) => match cipher.decrypt_easy(DEFAULT_AAD.as_ref(), data.as_slice()) {
                Ok(data) => data,
                Err(e) => {
                    warn!(%e, "Error decrypting message!");
                    self.state = State::Error;
                    return Err(Error::Keys);
                }
            },
        };

        let pub_key: Result<iroha_crypto::PublicKey, _> = Decode::decode(&mut data.as_slice());
        match pub_key {
            Ok(pub_key) => {
                self.id.public_key = pub_key;
                self.state = State::Ready;
                Ok(())
            }
            Err(e) => {
                warn!(%e, "Unexpected error creating encryptor!");
                self.state = State::Error;
                Err(Error::Keys)
            }
        }
    }

    /// Creates shared key from two public keys - our and their,
    /// and creates and encryptor from that key.
    fn derive_shared_key(&mut self, public_key: &PublicKey) -> Result<(), Error> {
        let dh = K::new();
        let shared = match dh.compute_shared_secret(&self.secret_key, public_key) {
            Ok(key) => key,
            Err(e) => {
                warn!(%e, "Error creating shared secret!");
                return Err(Error::Keys);
            }
        };
        debug!("Derived shared key: {:?}", &shared.0);
        match self.new_encryptor(shared.0.as_slice()) {
            Ok(encryptor) => {
                self.cipher = Some(encryptor);
                Ok(())
            }
            Err(e) => {
                warn!(%e, "Unexpected error creating encryptor!");
                Err(Error::Keys)
            }
        }
    }

    /// Creates a connection to other peer
    #[allow(clippy::expect_used)]
    async fn connect(&mut self) -> Result<(), Error> {
        let addr = self.id.address.clone();
        let stream = TcpStream::connect(addr.clone()).await;
        match stream {
            Ok(stream) => {
                // We hash local address here as our local port will be more random
                self.connection_id = get_connection_id(
                    &stream
                        .local_addr()
                        .expect("We always have the address here"),
                );
                let (read, write) = stream.into_split();
                self.read = Some(read);
                self.write = Some(write);
                self.state = State::ConnectedTo;
                Ok(())
            }
            Err(error) => {
                debug!(%error, "Could not connect to peer on {}!", addr);
                Err(Error::Io(error))
            }
        }
    }

    #[allow(clippy::unused_self)]
    fn new_encryptor(&self, key: &[u8]) -> Result<SymmetricEncryptor<E>, aead::Error> {
        SymmetricEncryptor::<E>::new_with_key(key)
    }
}

impl<T, K, E> Debug for Peer<T, K, E>
where
    T: Encode + Decode + Send + Clone + 'static,
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
    T: Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        debug!(
            "Starting actor for connection with peer {}",
            &self.id.address
        );
        let mut count = 0;
        while self.state != State::Ready {
            if let Err(e) = self.handshake().await {
                warn!(
                    "Error connecting to peer {} in state {}. {}",
                    &self.id.address, &self.state, e
                );
                if count < MAX_CONNECTION_RETRY_COUNT {
                    count += 1;
                    let delay = CONNECTION_RETRY_PERIOD * count;
                    debug!(%e, "Error connecting to peer {}, waiting {}ms before retry.", &self.id.address, delay);
                    time::sleep(Duration::from_millis(delay)).await;
                    continue;
                }
                debug!(%e, "Error connecting to peer {}, bailing.", &self.id.address);
                let message = PeerMessage::<T>::Disconnected(self.id.clone());
                self.broker.issue_send(message).await;
                return;
            }
        }
        debug!("Handshake with {:?} finished", &self.id);
        let message = PeerMessage::<T>::Connected(self.id.clone(), self.connection_id);
        self.broker.issue_send(message).await;

        #[allow(clippy::unwrap_used)]
        let read: OwnedReadHalf = self.read.take().unwrap();

        // Subscribe reading stream
        ctx.notify_with(Self::stream(read));
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<MessageResult> for Peer<T, K, E>
where
    T: Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, MessageResult(msg): MessageResult) {
        let message = match msg {
            Ok(message) => message,
            Err(error) => {
                // TODO implement some recovery
                warn!(%error, "Error in peer read!");
                let message = PeerMessage::<T>::Disconnected(self.id.clone());
                self.broker.issue_send(message).await;
                return;
            }
        };

        debug!("Got message: {:?}", &message.0);
        let data = match &self.cipher {
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
                let message = PeerMessage::Message(self.id.clone(), data);
                self.broker.issue_send(message).await;
            }
            Err(e) => warn!(%e, "Error parsing message!"),
        }
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<Post<T>> for Peer<T, K, E>
where
    T: Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, msg: Post<T>) {
        if self.write.is_none() {
            warn!("Cannot send message to peer, as we are not connected!");
            return;
        }

        let data = match &self.cipher {
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
        debug!("Sending message: {:?}", &data);
        #[allow(clippy::unwrap_used)]
        let mut write_half = self.write.as_mut().unwrap();
        if let Err(e) = send_message(&mut write_half, data.as_slice()).await {
            warn!(%e, "Error sending message to peer!");
            self.state = State::Error;
        }
    }
}

#[async_trait::async_trait]
impl<T, K, E> ContextHandler<StopSelf> for Peer<T, K, E>
where
    T: Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, ctx: &mut Context<Self>, message: StopSelf) {
        if message.0 == self.connection_id {
            debug!("Stopping self");
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
    /// Something bad happened
    Error,
}

impl Display for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        #[allow(clippy::use_debug)]
        write!(f, "{:?}", &self)
    }
}

/// Reads client hello
/// # Errors
/// If reading encounters IO-error
pub async fn read_client_hello(stream: &mut OwnedReadHalf) -> Result<PublicKey, Error> {
    Garbage::read(stream).await?;
    // And then we have clients public key
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
    Garbage::read(stream).await?;
    // Then we have clients public key
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
            read += stream.read_exact(&mut buf[read..]).await?;
        }

        return Ok(Message(buf));
    }
    Err(Error::Format)
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
        return Err(Error::Format);
    }
    #[allow(clippy::cast_possible_truncation)]
    let size: u32 = data.len() as u32;
    let mut buf: Vec<u8> = Vec::with_capacity(data.len() + 2);
    buf.write_u32(size).await?;
    buf.write_all(data).await?;
    stream.write_all(buf.as_slice()).await?;
    stream.flush().await?;
    Ok(())
}

/// Produces pseudorandom connection id from address
fn get_connection_id(addr: &SocketAddr) -> ConnectionId {
    let mut hasher = DefaultHasher::new();
    addr.hash(&mut hasher);
    hasher.finish()
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

    pub async fn read(stream: &mut OwnedReadHalf) -> Result<(), Error> {
        let size = stream.read_u8().await? as usize;
        if size >= MAX_HANDSHAKE_LENGTH {
            return Err(Error::Handshake);
        }
        // Reading garbage
        let mut buf = vec![0_u8; size];
        let _ = stream.read_exact(&mut buf).await?;
        Ok(())
    }
}
