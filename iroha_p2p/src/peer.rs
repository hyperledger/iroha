use std::marker::PhantomData;

use async_stream::stream;
use futures::Stream;
use iroha_actor::{Actor, Context, Handler, Recipient};
use iroha_logger::warn;
use parity_scale_codec::{Decode, Encode};
use rand::{Rng, RngCore};
use tokio::{
    io,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};
use ursa::{
    encryption::symm::{Encryptor, SymmetricEncryptor},
    kex::KeyExchangeScheme,
    keys::{PrivateKey, PublicKey},
};

use crate::{
    network::{Post, Received},
    Error, Message, MessageResult,
};

const MAX_MESSAGE_LENGTH: usize = 2 * 1024 * 1024;
const MAX_HANDSHAKE_LENGTH: usize = 255;
/// Default associated data for AEAD
/// [`Authenticated encryption`](https://en.wikipedia.org/wiki/Authenticated_encryption)
pub const DEFAULT_AAD: &[u8; 12] = b"Iroha2Iroha2";

pub struct Peer<T, K, E>
where
    T: Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    pub id: PeerId,
    pub read: Option<OwnedReadHalf>,
    pub write: Option<OwnedWriteHalf>,
    pub state: State,
    pub secret_key: PrivateKey,
    pub public_key: PublicKey,
    pub cipher: Option<SymmetricEncryptor<E>>,
    pub network: Recipient<Received<T>>,
    pub _key_exchange: PhantomData<K>,
}

impl<T, K, E> Peer<T, K, E>
where
    T: Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    fn new_inner(
        id: PeerId,
        stream: Option<TcpStream>,
        state: State,
        network: Recipient<Received<T>>,
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
            read,
            write,
            state,
            secret_key,
            public_key,
            cipher: None,
            network,
            _key_exchange: PhantomData::default(),
        })
    }

    pub fn new_from(
        id: PeerId,
        stream: TcpStream,
        network: Recipient<Received<T>>,
    ) -> Result<Self, Error> {
        Self::new_inner(id, Some(stream), State::ConnectedFrom, network)
    }

    pub fn new_to(id: PeerId, network: Recipient<Received<T>>) -> Result<Self, Error> {
        Self::new_inner(id, None, State::ConnectedTo, network)
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
        match &self.state {
            State::Connecting => self.connect().await,
            State::ConnectedTo => self.send_client_hello().await?,
            State::ConnectedFrom => self.read_client_hello().await?,
            State::Ready => warn!("Not doing handshake, already ready."),
            State::Error => warn!("Not doing handshake in error state."),
        }
        Ok(())
    }

    // Reads client public key from client hello,
    // creates shared secret and sends our public key to client
    async fn read_client_hello(&mut self) -> Result<(), Error> {
        #[allow(clippy::unwrap_used)]
        let read_half = self.read.as_mut().unwrap();
        let public_key = read_client_hello(read_half).await?;
        self.derive_shared_key(&public_key)?;
        #[allow(clippy::unwrap_used)]
        let mut write_half = self.write.as_mut().unwrap();
        send_server_hello(&mut write_half, self.public_key.0.as_slice()).await?;
        self.state = State::Ready;
        Ok(())
    }

    /// Sends client hello with our public key
    async fn send_client_hello(&mut self) -> Result<(), Error> {
        #[allow(clippy::unwrap_used)]
        let mut write_half = self.write.as_mut().unwrap();
        write_half.as_ref().writable().await?;
        send_client_hello(&mut write_half, self.public_key.0.as_slice()).await?;
        // Read server hello with node's public key
        #[allow(clippy::unwrap_used)]
        let read_half = self.read.as_mut().unwrap();
        let public_key = read_server_hello(read_half).await?;
        self.derive_shared_key(&public_key)?;
        self.state = State::Ready;
        Ok(())
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
    async fn connect(&mut self) {
        let addr = self.id.address.clone();
        let stream = TcpStream::connect(addr.clone()).await;
        match stream {
            Ok(stream) => {
                let (read, write) = stream.into_split();
                self.read = Some(read);
                self.write = Some(write);
                self.state = State::ConnectedTo;
            }
            Err(e) => {
                warn!(%e, "Could not connect to peer on {}!", addr);
            }
        }
    }

    #[allow(clippy::unused_self)]
    fn new_encryptor(&self, key: &[u8]) -> Result<SymmetricEncryptor<E>, aead::Error> {
        SymmetricEncryptor::<E>::new_with_key(key)
    }
}

#[async_trait::async_trait]
impl<T, K, E> Actor for Peer<T, K, E>
where
    T: Encode + Decode + Send + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        //self.addr = Some(ctx.addr());
        while self.state != State::Ready {
            if let Err(e) = self.handshake().await {
                warn!(%e, "Error connecting to peer {}, bailing.", &self.id.address);
                break;
            }
        }
        #[allow(clippy::unwrap_used)]
        let read: OwnedReadHalf = self.read.take().unwrap();

        // Subscribe reading stream
        ctx.notify_with(Self::stream(read));
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<MessageResult> for Peer<T, K, E>
where
    T: Encode + Decode + Send + Clone + 'static,
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
                return;
            }
        };

        let data = match &self.cipher {
            None => message.0,
            Some(cipher) => match cipher.decrypt_easy(&DEFAULT_AAD[..], message.0.as_slice()) {
                Ok(data) => data,
                Err(e) => {
                    warn!(%e, "Error decrypting message!");
                    self.state = State::Error;
                    return;
                }
            },
        };
        match Decode::decode(&mut data.as_slice()) {
            Ok(data) => {
                let msg = Received {
                    data,
                    id: self.id.clone(),
                };
                self.network.send(msg).await;
            }
            Err(e) => warn!(%e, "Error parsing message!"),
        }
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<Post<T>> for Peer<T, K, E>
where
    T: Encode + Decode + Send + Clone + 'static,
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
            Some(cipher) => match cipher.encrypt_easy(&DEFAULT_AAD[..], &msg.data.encode()) {
                Ok(data) => data,
                Err(e) => {
                    warn!(%e, "Error encrypting message!");
                    self.state = State::Error;
                    return;
                }
            },
        };
        #[allow(clippy::unwrap_used)]
        let mut write_half = self.write.as_mut().unwrap();
        if let Err(e) = send_message(&mut write_half, data.as_slice()).await {
            warn!(%e, "Error sending message to peer!");
            self.state = State::Error;
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum State {
    Connecting,
    ConnectedTo,
    ConnectedFrom,
    Ready,
    Error,
}

pub async fn read_client_hello(stream: &mut OwnedReadHalf) -> Result<PublicKey, Error> {
    Garbage::read(stream).await?;
    // And then we have clients public key
    let mut key = [0_u8; 32];
    let _ = stream.read_exact(&mut key).await?;
    Ok(PublicKey(Vec::from(key)))
}

pub async fn send_client_hello(stream: &mut OwnedWriteHalf, key: &[u8]) -> io::Result<()> {
    let garbage = Garbage::generate();
    garbage.write(stream).await?;
    stream.write_all(key).await?;
    Ok(())
}

pub async fn read_server_hello(stream: &mut OwnedReadHalf) -> Result<PublicKey, Error> {
    Garbage::read(stream).await?;
    // Then we have clients public key
    let mut key = [0_u8; 32];
    let _ = stream.read_exact(&mut key).await?;
    Ok(PublicKey(Vec::from(key)))
}

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

/// Peer's identification.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct PeerId {
    /// Address of the Peer's entrypoint.
    pub address: String,
    /// Public Key of the Peer.
    pub public_key: Option<iroha_crypto::PublicKey>,
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

#[cfg(test)]
mod tests {
    use std::{fmt::Debug, time::Duration};

    use iroha_actor::Addr;
    use tokio::{
        net::TcpListener,
        sync::mpsc::{self, Receiver},
        time,
    };
    use ursa::{encryption::symm::chacha20poly1305::ChaCha20Poly1305, kex::x25519::X25519Sha256};

    use super::*;

    fn peer_id() -> PeerId {
        let port = unique_port::get_unique_free_port().unwrap();
        let address = format!("127.0.0.1:{}", port);
        PeerId {
            address,
            public_key: None,
        }
    }

    fn peer_to<T, K, E>(id: PeerId) -> (Peer<T, K, E>, Receiver<Received<T>>)
    where
        T: Encode + Decode + Send + Clone + 'static + Debug,
        K: KeyExchangeScheme + Send + 'static,
        E: Encryptor + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel(100);
        (Peer::new_to(id, sender.into()).unwrap(), receiver)
    }

    fn peer_from<T, K, E>(id: PeerId, stream: TcpStream) -> (Peer<T, K, E>, Receiver<Received<T>>)
    where
        T: Encode + Decode + Send + Clone + 'static + Debug,
        K: KeyExchangeScheme + Send + 'static,
        E: Encryptor + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel(100);
        (Peer::new_from(id, stream, sender.into()).unwrap(), receiver)
    }

    async fn peer_ping_pong<T, K, E>() -> (
        (Addr<Peer<T, K, E>>, Receiver<Received<T>>),
        (Addr<Peer<T, K, E>>, Receiver<Received<T>>),
    )
    where
        T: Encode + Decode + Send + Clone + 'static + Debug,
        K: KeyExchangeScheme + Send + 'static,
        E: Encryptor + Send + 'static,
    {
        let id = peer_id();
        let listener = TcpListener::bind(&id.address).await.unwrap();
        let jh = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream
        });

        let (to, to_recv) = peer_to(id.clone());
        dbg!("A");
        let to = to.start().await;

        dbg!("B");
        let (from, from_recv) = peer_from(id, jh.await.unwrap());
        dbg!("C");
        let from = from.start().await;
        dbg!("D");

        ((to, to_recv), (from, from_recv))
    }

    #[tokio::test]
    async fn simple_dimple() {
        #[derive(iroha_actor::Message, Clone, Debug, Copy, Decode, Encode)]
        struct TmpMessage;

        let ((to, to_recv), (from, from_recv)) = time::timeout(
            Duration::from_secs(1),
            peer_ping_pong::<TmpMessage, X25519Sha256, ChaCha20Poly1305>(),
        )
        .await;
    }
}
