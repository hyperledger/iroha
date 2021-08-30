use std::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
};

use async_stream::stream;
use futures::{Stream, StreamExt};
use iroha_actor::{Actor, Addr, Context, ContextHandler, Handler};
#[allow(unused_imports)]
use iroha_logger::{debug, error, info, warn};
use parity_scale_codec::{Decode, Encode};
use rand::{Rng, RngCore};
use tokio::{
    io,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::oneshot::{self, Receiver, Sender},
    time::Duration,
};
use ursa::{
    encryption::symm::{Encryptor, SymmetricEncryptor},
    kex::KeyExchangeScheme,
    keys::{PrivateKey, PublicKey},
};

use crate::{
    network::{Connection, Disconnected, GotConnected},
    Error, Message, MessageResult, NetworkBase, PeerId, Post, Received, Stop,
};

const MAX_MESSAGE_LENGTH: usize = 2 * 1024 * 1024;
const MAX_HANDSHAKE_LENGTH: usize = 255;
const MAX_CONNECTION_RETRY_COUNT: u32 = 100;
const CONNECTION_RETRY_PERIOD: Duration = Duration::from_millis(100);

/// Default associated data for AEAD
/// [`Authenticated encryption`](https://en.wikipedia.org/wiki/Authenticated_encryption)
const DEFAULT_AAD: &[u8; 10] = b"Iroha2 AAD";

fn encrypt_easy<E: Encryptor>(
    cipher: &SymmetricEncryptor<E>,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    cipher
        .encrypt_easy(DEFAULT_AAD.as_ref(), &data)
        .map_err(|err| {
            warn!(%err, "Error encrypting message!");
            Error::Keys
        })
}

fn decrypt_easy<E: Encryptor>(
    cipher: &SymmetricEncryptor<E>,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    cipher
        .decrypt_easy(DEFAULT_AAD.as_ref(), data)
        .map_err(|err| {
            warn!(%err, "Error decrypting message!");
            Error::Keys
        })
}

pub(crate) struct Keypair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl Keypair {
    pub fn new<K: KeyExchangeScheme>() -> Result<Self, Error> {
        let dh = K::new();
        let (public, private) = match dh.keypair(None) {
            Ok((public, private)) => (public, private),
            Err(e) => {
                warn!(%e, "Error generating keypair");
                return Err(Error::Keys);
            }
        };
        Ok(Self { public, private })
    }
}

fn derive_shared_key<K: KeyExchangeScheme, E: Encryptor>(
    private: &PrivateKey,
    public: &PublicKey,
) -> Result<SymmetricEncryptor<E>, Error> {
    let dh = K::new();
    let shared = match dh.compute_shared_secret(&private, public) {
        Ok(key) => key,
        Err(e) => {
            warn!(%e, "Error creating shared secret!");
            return Err(Error::Keys);
        }
    };
    debug!(key = ?shared.0, "Derived shared key");
    SymmetricEncryptor::<E>::new_with_key(shared.0.as_slice()).map_err(|err| {
        warn!(%err, "Unexpected error creating encryptor!");
        Error::Keys
    })
}

#[derive(PartialEq, Eq, Debug)]
enum ToState {
    Connected,
    SendKey,
    GetKey,
    Ready,
}

/// This is an endpoint, that joggles messages between [`crate::Network`] and another connected node.
pub(crate) struct ToPeer<T, K, E: Encryptor> {
    /// Peer id
    pub id: PeerId,
    /// Tcp Stream
    pub stream: TcpStream,
    keypair: Keypair,
    state: ToState,
    cipher: Option<SymmetricEncryptor<E>>,

    /// Address of network
    pub network: Addr<NetworkBase<T, K, E>>,
}

impl<T, K, E> ToPeer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    pub fn new(
        id: PeerId,
        stream: TcpStream,
        network: Addr<NetworkBase<T, K, E>>,
    ) -> Result<Self, Error> {
        let state = ToState::Connected;
        let keypair = Keypair::new::<K>()?;
        Ok(Self {
            id,
            stream,
            state,
            network,
            keypair,
            cipher: None,
        })
    }

    async fn read_key(&mut self) -> Result<PublicKey, Error> {
        self.stream.readable().await?;
        Garbage::read(&mut self.stream).await?;
        // And then we have clients public key
        self.stream.readable().await?;
        let mut key = [0_u8; 32];
        let _ = self.stream.read_exact(&mut key).await?;
        Ok(PublicKey(Vec::from(key)))
    }

    /// Reads client public key from client hello,
    /// creates shared secret and sends our public key to client
    async fn read_hello(&mut self) -> Result<(), Error> {
        debug!("Reading client hello...");
        let public_key = self.read_key().await?;

        self.cipher = Some(derive_shared_key::<K, _>(
            &self.keypair.private,
            &public_key,
        )?);
        self.send_hello().await?;
        self.state = ToState::SendKey;
        Ok(())
    }

    async fn send_hello(&mut self) -> io::Result<()> {
        let key = self.keypair.public.0.as_slice();
        let garbage = Garbage::generate();
        garbage.write(&mut self.stream).await?;
        self.stream.write_all(key).await?;
        Ok(())
    }

    async fn send_public_key(&mut self) -> Result<(), Error> {
        debug!("Sending our public key...");
        self.stream.writable().await?;

        // We take our public key from this field and will replace it with theirs when we read it
        // Packing length and message in one network packet for efficiency
        let data = self.id.public_key.encode();
        let mut data = match &self.cipher {
            Some(cipher) => encrypt_easy(cipher, &data)?,
            None => data,
        };

        let mut buf = Vec::<u8>::with_capacity(data.len() + 1);
        #[allow(clippy::cast_possible_truncation)]
        buf.push(data.len() as u8);
        buf.append(&mut data);

        self.stream.write_all(&buf).await?;
        self.state = ToState::GetKey;
        Ok(())
    }

    /// Reads theirs app public key
    async fn read_public_key(&mut self) -> Result<(), Error> {
        debug!("Reading theirs public key...");
        // TODO: Make buffered sockets to avoid syscalls
        let size = self.stream.read_u8().await? as usize;
        if size >= MAX_HANDSHAKE_LENGTH {
            return Err(Error::Handshake);
        }

        // Reading public key
        self.stream.readable().await?;
        let mut data = vec![0_u8; size];
        self.stream.read_exact(&mut data).await?;

        let data = match &self.cipher {
            None => data,
            Some(cipher) => decrypt_easy(cipher, &data)?,
        };

        let pub_key = match Decode::decode(&mut data.as_slice()) {
            Ok(pub_key) => pub_key,
            Err(e) => {
                warn!(%e, "Unexpected error creating encryptor!");
                return Err(Error::Keys);
            }
        };
        self.id.public_key = pub_key;
        self.state = ToState::Ready;
        Ok(())
    }

    async fn handshake(&mut self) -> Result<(), Error> {
        debug!(?self.state, addr = %self.id.address, "Attempting handshake");
        match self.state {
            ToState::Connected => self.read_hello().await?,
            ToState::SendKey => self.send_public_key().await?,
            ToState::GetKey => self.read_public_key().await?,
            ToState::Ready => warn!("Not doing handshake, already ready."),
        }
        Ok(())
    }

    async fn into_peer(self) -> Addr<Peer<T, K, E>> {
        let (r, w) = self.stream.into_split();
        let (sender, receiver) = oneshot::channel();
        let peer = Peer::new(
            self.id,
            w,
            self.cipher.unwrap(),
            self.network,
            false,
            sender,
        );
        let stream = Peer::<T, K, E>::stream(r, receiver);

        let peer = peer.preinit();
        let addr = peer.address.clone();

        // spawning task
        tokio::spawn(async move {
            stream.for_each(|it| async { addr.do_send(it).await }).await;
        });

        peer.start().await
    }
}

#[derive(iroha_actor::Message)]
struct ContinueHandshake;

#[async_trait::async_trait]
impl<T, K, E> Actor for ToPeer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        info!(addr = ?self.id.address, "Received connection from");
        ctx.notify(ContinueHandshake);
    }

    async fn on_stop(self, _ctx: Context<Self>) {
        self.into_peer().await;
    }
}

#[async_trait::async_trait]
impl<T, K, E> ContextHandler<ContinueHandshake> for ToPeer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();
    async fn handle(
        &mut self,
        ctx: &mut Context<Self>,
        ContinueHandshake: ContinueHandshake,
    ) -> Self::Result {
        if self.state == ToState::Ready {
            return;
        }

        if let Err(err) = self.handshake().await {
            info!(addr=?self.id.address, state=?self.state, %err, "Error connecting to peer");
            ctx.stop_now();
            return;
        }
        ctx.notify(ContinueHandshake);
    }
}

#[derive(PartialEq, Eq, Debug)]
enum FromState {
    Connecting,
    Connected,
    SendKey,
    GetKey,
    Ready,
}

/// This is an endpoint, that joggles messages between [`crate::Network`] and another connected node.
pub(crate) struct FromPeer<T, K, E: Encryptor> {
    /// Peer id
    pub id: PeerId,
    /// Tcp Stream
    pub stream: Option<TcpStream>,
    keypair: Keypair,
    state: FromState,
    cipher: Option<SymmetricEncryptor<E>>,

    /// Address of network
    pub network: Addr<NetworkBase<T, K, E>>,
}

impl<T, K, E> FromPeer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    pub fn new(id: PeerId, network: Addr<NetworkBase<T, K, E>>) -> Result<Self, Error> {
        let state = FromState::Connecting;
        let keypair = Keypair::new::<K>()?;
        Ok(Self {
            id,
            stream: None,
            state,
            network,
            keypair,
            cipher: None,
        })
    }

    async fn handshake(&mut self) -> Result<(), Error> {
        use FromState::*;

        debug!(?self.state, addr = %self.id.address, "Attempting handshake");
        match self.state {
            Connecting => self.connect().await?,
            Connected => self.send_hello().await?,
            SendKey => self.send_public_key().await?,
            GetKey => self.read_public_key().await?,
            Ready => warn!("Not doing handshake, already ready."),
        }
        Ok(())
    }

    /// Creates a connection to other peer
    async fn connect(&mut self) -> Result<(), Error> {
        let addr = &self.id.address;
        debug!("Connecting to [{}]", &addr);

        match TcpStream::connect(addr).await {
            Ok(stream) => {
                debug!(%addr, "Connected to");
                self.stream = Some(stream);
                self.state = FromState::Connected;
                Ok(())
            }
            Err(error) => {
                warn!(%error, %addr, "Could not connect to peer");
                Err(error.into())
            }
        }
    }

    /// Sends client hello with our public key
    #[allow(clippy::unwrap_used)]
    async fn send_hello(&mut self) -> Result<(), Error> {
        debug!("Sending client hello...");
        let stream = self.stream.as_mut().unwrap();

        stream.writable().await?;

        let garbage = Garbage::generate();
        garbage.write(stream).await?;
        stream.write_all(self.keypair.public.0.as_slice()).await?;

        // Read server hello with node's public key
        let public_key = read_server_hello(stream).await?;
        self.cipher = Some(derive_shared_key::<K, _>(
            &self.keypair.private,
            &public_key,
        )?);
        self.state = FromState::SendKey;
        Ok(())
    }

    // TODO: Remove duplicate of this function
    #[allow(clippy::unwrap_used)]
    async fn send_public_key(&mut self) -> Result<(), Error> {
        debug!("Sending our public key...");
        let stream = self.stream.as_mut().unwrap();
        stream.writable().await?;

        // We take our public key from this field and will replace it with theirs when we read it
        // Packing length and message in one network packet for efficiency
        let data = self.id.public_key.encode();
        let mut data = match &self.cipher {
            Some(cipher) => encrypt_easy(cipher, &data)?,
            None => data,
        };

        let mut buf = Vec::<u8>::with_capacity(data.len() + 1);
        #[allow(clippy::cast_possible_truncation)]
        buf.push(data.len() as u8);
        buf.append(&mut data);

        stream.write_all(&buf).await?;
        self.state = FromState::GetKey;
        Ok(())
    }

    /// Reads theirs app public key
    // TODO: Remove duplicate of this function
    #[allow(clippy::unwrap_used)]
    async fn read_public_key(&mut self) -> Result<(), Error> {
        debug!("Reading theirs public key...");
        let stream = self.stream.as_mut().unwrap();

        // TODO: Make buffered sockets to avoid syscalls
        let size = stream.read_u8().await? as usize;
        if size >= MAX_HANDSHAKE_LENGTH {
            return Err(Error::Handshake);
        }

        // Reading public key
        stream.readable().await?;
        let mut data = vec![0_u8; size];
        stream.read_exact(&mut data).await?;

        let data = match &self.cipher {
            None => data,
            Some(cipher) => decrypt_easy(cipher, &data)?,
        };

        let pub_key = match Decode::decode(&mut data.as_slice()) {
            Ok(pub_key) => pub_key,
            Err(e) => {
                warn!(%e, "Unexpected error creating encryptor!");
                return Err(Error::Keys);
            }
        };
        self.id.public_key = pub_key;
        self.state = FromState::Ready;
        Ok(())
    }

    #[allow(clippy::unwrap_used)]
    async fn into_peer(self) -> Addr<Peer<T, K, E>> {
        let (r, w) = self.stream.unwrap().into_split();
        let (sender, receiver) = oneshot::channel();
        let peer = Peer::new(
            self.id,
            w,
            self.cipher.unwrap(),
            self.network,
            false,
            sender,
        );
        let stream = Peer::<T, K, E>::stream(r, receiver);

        let peer = peer.preinit();
        let addr = peer.address.clone();

        // spawning task
        tokio::spawn(async move {
            stream.for_each(|it| async { addr.do_send(it).await }).await;
        });

        peer.start().await
    }
}

#[async_trait::async_trait]
impl<T, K, E> Actor for FromPeer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        info!(addr = ?self.id.address, "Connecting and doing handshake");
        ctx.notify(ContinueHandshake);
    }

    async fn on_stop(self, _ctx: Context<Self>) {
        self.into_peer().await;
    }
}

#[async_trait::async_trait]
impl<T, K, E> ContextHandler<ContinueHandshake> for FromPeer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();
    async fn handle(
        &mut self,
        ctx: &mut Context<Self>,
        ContinueHandshake: ContinueHandshake,
    ) -> Self::Result {
        if self.state == FromState::Ready {
            ctx.stop_now();
            return;
        }

        if let Err(err) = self.handshake().await {
            info!(addr=?self.id.address, state=?self.state, %err, "Error connecting to peer");
            ctx.stop_now();
            return;
        }
        ctx.notify(ContinueHandshake);
    }
}

/// This is an endpoint, that joggles messages between [`crate::Network`] and another connected node.
pub(crate) struct Peer<T, K, E: Encryptor> {
    /// Peer identification
    pub id: PeerId,
    /// Writing half of `TcpStream`
    pub write: OwnedWriteHalf,
    /// Flag stating that this connection is outgoing
    pub outgoing: bool,
    /// Encryptor created from session key, that we got by Diffie-Hellman scheme
    pub cipher: SymmetricEncryptor<E>,
    /// Address of network
    pub network: Addr<NetworkBase<T, K, E>>,

    /// A flag that stops listening stream
    finish_sender: Sender<()>,

    /// Phantom in order to keep generics
    pub _t_k: PhantomData<(K, T)>,
}

impl<T, K, E> Peer<T, K, E>
where
    T: Encode + Decode + Send + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Creates a peer
    /// # Errors
    /// If it can not create a keypair, so never
    pub fn new(
        id: PeerId,
        write: OwnedWriteHalf,
        cipher: SymmetricEncryptor<E>,
        network: Addr<NetworkBase<T, K, E>>,
        outgoing: bool,
        finish_sender: Sender<()>,
    ) -> Self {
        Self {
            id,
            write,
            outgoing,
            cipher,
            network,
            finish_sender,
            _t_k: PhantomData,
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

    async fn send_message(&mut self, data: &[u8]) -> Result<(), Error> {
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
        self.write.as_ref().writable().await?;
        self.write.write_all(buf.as_slice()).await?;
        self.write.flush().await?;
        Ok(())
    }
}

impl<T, K, E: Encryptor> Debug for Peer<T, K, E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer").field("id", &self.id).finish()
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
        self.network
            .do_send(GotConnected {
                conn: Connection {
                    addr: ctx.addr(),
                    outgoing: self.outgoing,
                },
                id: self.id.clone(),
            })
            .await;
    }

    async fn on_stop(self, _ctx: Context<Self>) {
        let _ = self.finish_sender.send(());
    }
}

#[async_trait::async_trait]
impl<T, K, E> ContextHandler<MessageResult> for Peer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, ctx: &mut Context<Self>, MessageResult(msg): MessageResult) {
        let message = match msg {
            Ok(message) => message,
            Err(Error::Closed(_)) => {
                self.network
                    .do_send(Disconnected {
                        id: self.id.clone(),
                        outgoing: self.outgoing,
                    })
                    .await;
                ctx.stop_now();
                return;
            }
            Err(error) => {
                error!(%error, "Recieved error from other side. Disconnecting");
                // TODO implement some recovery
                self.network
                    .do_send(Disconnected {
                        id: self.id.clone(),
                        outgoing: self.outgoing,
                    })
                    .await;
                ctx.stop_now();
                return;
            }
        };

        let data = match decrypt_easy(&self.cipher, message.0.as_slice()) {
            Ok(data) => data,
            Err(e) => {
                warn!(%e, "Error decrypting message!");
                return;
            }
        };

        match Decode::decode(&mut data.as_slice()) {
            Ok(data) => {
                let message = Received {
                    data,
                    id: self.id.clone(),
                };
                self.network.do_send(message).await;
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

    async fn handle(&mut self, Post { data, .. }: Post<T>) {
        debug!("Sending message: {:?}", &data);
        let data = match encrypt_easy(&self.cipher, &data.encode()) {
            Ok(data) => data,
            Err(err) => {
                debug!(%err, "Encryption error!");
                return;
            }
        };
        #[allow(clippy::unwrap_used)]
        if let Err(e) = self.send_message(data.as_slice()).await {
            warn!(%e, "Error sending message to peer!");
        }
    }
}

#[async_trait::async_trait]
impl<T, K, E> ContextHandler<Stop> for Peer<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, ctx: &mut Context<Self>, Stop: Stop) {
        info!(addr = %self.id.address, "Disconnecting");
        ctx.stop_now();
    }
}

/// Reads server hello
/// # Errors
/// If reading encounters IO-error
async fn read_server_hello(stream: &mut TcpStream) -> Result<PublicKey, Error> {
    stream.readable().await?;
    Garbage::read(stream).await?;
    // Then we have servers public key
    stream.readable().await?;
    let mut key = [0_u8; 32];
    let _ = stream.read_exact(&mut key).await?;
    Ok(PublicKey(Vec::from(key)))
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

        return Ok(Message(buf));
    }
    Err(Error::Format)
}

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

    pub async fn write(&self, stream: &mut TcpStream) -> io::Result<()> {
        #[allow(clippy::cast_possible_truncation)]
        stream.write_u8(self.garbage.len() as u8).await?;
        stream.write_all(self.garbage.as_slice()).await
    }

    pub async fn read(stream: &mut TcpStream) -> Result<Self, Error> {
        let size = stream.read_u8().await? as usize;
        if size >= MAX_HANDSHAKE_LENGTH {
            return Err(Error::Handshake);
        }
        // Reading garbage
        debug!("Garbage size: {}, reading...", size);
        let mut garbage = vec![0_u8; size];
        stream.readable().await?;
        let _ = stream.read_exact(&mut garbage).await?;
        Ok(Self { garbage })
    }
}
