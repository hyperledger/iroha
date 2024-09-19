//! Tokio actor Peer

use bytes::{Buf, BufMut, BytesMut};
use iroha_data_model::prelude::PeerId;
use message::*;
use parity_scale_codec::{DecodeAll, Encode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::{mpsc, oneshot},
    time::Duration,
};

use crate::{boilerplate::*, Error};

/// Max length of message handshake in bytes excluding first message length byte.
pub const MAX_HANDSHAKE_LENGTH: u8 = 255;
/// Default associated data for AEAD
/// [`Authenticated encryption`](https://en.wikipedia.org/wiki/Authenticated_encryption)
pub const DEFAULT_AAD: &[u8; 10] = b"Iroha2 AAD";

pub mod handles {
    //! Module with functions to start peer actor and handle to interact with it.

    use iroha_crypto::KeyPair;
    use iroha_logger::Instrument;
    use iroha_primitives::addr::SocketAddr;

    use super::{run::RunPeerArgs, *};
    use crate::unbounded_with_len;

    /// Start Peer in [`state::Connecting`] state
    pub fn connecting<T: Pload, K: Kex, E: Enc>(
        peer_addr: SocketAddr,
        key_pair: KeyPair,
        connection_id: ConnectionId,
        service_message_sender: mpsc::Sender<ServiceMessage<T>>,
        idle_timeout: Duration,
    ) {
        let peer = state::Connecting {
            peer_addr,
            key_pair,
            connection_id,
        };
        let peer = RunPeerArgs {
            peer,
            service_message_sender,
            idle_timeout,
        };
        tokio::task::spawn(run::run::<T, K, E, _>(peer).in_current_span());
    }

    /// Start Peer in [`state::ConnectedFrom`] state
    pub fn connected_from<T: Pload, K: Kex, E: Enc>(
        peer_addr: SocketAddr,
        key_pair: KeyPair,
        connection: Connection,
        service_message_sender: mpsc::Sender<ServiceMessage<T>>,
        idle_timeout: Duration,
    ) {
        let peer = state::ConnectedFrom {
            peer_addr,
            key_pair,
            connection,
        };
        let peer = RunPeerArgs {
            peer,
            service_message_sender,
            idle_timeout,
        };
        tokio::task::spawn(run::run::<T, K, E, _>(peer).in_current_span());
    }

    /// Peer actor handle.
    pub struct PeerHandle<T: Pload> {
        // NOTE: it's ok for this channel to be unbounded.
        // Because post messages originate inside the system and their rate is configurable..
        pub(super) post_sender: unbounded_with_len::Sender<T>,
    }

    impl<T: Pload> PeerHandle<T> {
        /// Post message `T` on Peer
        ///
        /// # Errors
        /// Fail if peer terminated
        pub fn post(&self, msg: T) -> Result<(), mpsc::error::SendError<T>> {
            self.post_sender.send(msg)
        }
    }
}

mod run {
    //! Module with peer [`run`] function.

    use iroha_logger::prelude::*;
    use parity_scale_codec::Decode;
    use tokio::time::Instant;

    use super::{
        cryptographer::Cryptographer,
        handshake::Handshake,
        state::{ConnectedFrom, Connecting, Ready},
        *,
    };
    use crate::unbounded_with_len;

    /// Peer task.
    #[allow(clippy::too_many_lines)]
    #[log(skip_all, fields(conn_id = peer.connection_id(), peer, disambiguator))]
    pub(super) async fn run<T: Pload, K: Kex, E: Enc, P: Entrypoint<K, E>>(
        RunPeerArgs {
            peer,
            service_message_sender,
            idle_timeout,
        }: RunPeerArgs<T, P>,
    ) {
        let conn_id = peer.connection_id();
        let mut peer_id = None;

        iroha_logger::trace!("Peer created");

        // Insure proper termination from every execution path.
        async {
            // Try to do handshake process
            let peer = match tokio::time::timeout(idle_timeout, peer.handshake()).await {
                Ok(Ok(ready)) => ready,
                Ok(Err(error)) => {
                    iroha_logger::warn!(?error, "Failure during handshake.");
                    return;
                },
                Err(_) => {
                    iroha_logger::warn!(timeout=?idle_timeout, "Other peer has been idle during handshake");
                    return;
                }
            };

            let Ready {
                peer_id: new_peer_id,
                connection:
                    Connection {
                        read,
                        write,
                        id: connection_id,
                    },
                cryptographer,
            } = peer;
            let peer_id = peer_id.insert(new_peer_id);

            let disambiguator = cryptographer.disambiguator;

            tracing::Span::current().record("peer", peer_id.to_string());
            tracing::Span::current().record("disambiguator", disambiguator);

            let (post_sender, mut post_receiver) = unbounded_with_len::unbounded_channel();
            let (peer_message_sender, peer_message_receiver) = oneshot::channel();
            let ready_peer_handle = handles::PeerHandle { post_sender };
            if service_message_sender
                .send(ServiceMessage::Connected(Connected {
                    connection_id,
                    peer_id: peer_id.clone(),
                    ready_peer_handle,
                    peer_message_sender,
                    disambiguator,
                }))
                .await
                .is_err()
            {
                iroha_logger::error!(
                    "Peer is ready, but network dropped connection sender."
                );
                return;
            }
            let Ok(peer_message_sender) = peer_message_receiver.await else {
                // NOTE: this is not considered as error, because network might decide not to connect peer.
                iroha_logger::debug!(
                    "Network decide not to connect peer."
                );
                return;
            };

            iroha_logger::trace!("Peer connected");

            let mut message_reader = MessageReader::new(read, cryptographer.clone());
            let mut message_sender = MessageSender::new(write, cryptographer);

            let mut idle_interval = tokio::time::interval_at(Instant::now() + idle_timeout, idle_timeout);
            let mut ping_interval = tokio::time::interval_at(Instant::now() + idle_timeout / 2, idle_timeout / 2);

            loop {
                tokio::select! {
                    _ = ping_interval.tick() => {
                        iroha_logger::trace!(
                            ping_period=?ping_interval.period(),
                            "The connection has been idle, pinging to check if it's alive"
                        );
                        if let Err(error) = message_sender.prepare_message(Message::<T>::Ping) {
                            iroha_logger::error!(%error, "Failed to encrypt message.");
                            break;
                        }
                    }
                    _ = idle_interval.tick() => {
                        iroha_logger::error!(
                            timeout=?idle_interval.period(),
                            "Didn't receive anything from the peer within given timeout, abandoning this connection"
                        );
                        break;
                    }
                    msg = post_receiver.recv() => {
                        let Some(msg) = msg else {
                            iroha_logger::debug!("Peer handle dropped.");
                            break;
                        };
                        iroha_logger::trace!("Post message");
                        let post_receiver_len = post_receiver.len();
                        if post_receiver_len > 100 {
                            iroha_logger::warn!(size=post_receiver_len, "Peer post messages are pilling up");
                        }
                        if let Err(error) = message_sender.prepare_message(Message::Data(msg)) {
                            iroha_logger::error!(%error, "Failed to encrypt message.");
                            break;
                        }
                    }
                    msg = message_reader.read_message() => {
                        let msg = match msg {
                            Ok(Some(msg)) => {
                                msg
                            },
                            Ok(None) => {
                                iroha_logger::debug!("Peer send whole message and close connection");
                                break;
                            }
                            Err(error) => {
                                iroha_logger::error!(?error, "Error while reading message from peer.");
                                break;
                            }
                        };
                        match msg {
                            Message::Ping => {
                                iroha_logger::trace!("Received peer ping");
                                if let Err(error) = message_sender.prepare_message(Message::<T>::Pong) {
                                    iroha_logger::error!(%error, "Failed to encrypt message.");
                                    break;
                                }
                            },
                            Message::Pong => {
                                iroha_logger::trace!("Received peer pong");
                            }
                            Message::Data(msg) => {
                                iroha_logger::trace!("Received peer message");
                                let peer_message = PeerMessage(peer_id.clone(), msg);
                                if peer_message_sender.send(peer_message).await.is_err() {
                                    iroha_logger::error!("Network dropped peer message channel.");
                                    break;
                                }
                            }
                        };
                        // Reset idle and ping timeout as peer received message from another peer
                        idle_interval.reset();
                        ping_interval.reset();
                    }
                    // `message_sender.send()` is safe to be cancelled, it won't advance the queue or write anything if another branch completes first.
                    //
                    // We need to conditionally disable it in case there is no data is to be sent, otherwise `message_sender.send()` will complete immediately
                    //
                    // The only source of data to be sent is other branches of this loop, so we do not need any async waiting mechanism for waiting for readiness.
                    result = message_sender.send(), if message_sender.ready() => {
                        if let Err(error) = result {
                            iroha_logger::error!(%error, "Failed to send message to peer.");
                            break;
                        }
                    }
                    else => break,
                }
                tokio::task::yield_now().await;
            }
        }.await;

        iroha_logger::debug!("Peer is terminated.");
        let _ = service_message_sender
            .send(ServiceMessage::Terminated(Terminated { peer_id, conn_id }))
            .await;
    }

    /// Args to pass inside [`run`] function.
    pub(super) struct RunPeerArgs<T: Pload, P> {
        pub peer: P,
        pub service_message_sender: mpsc::Sender<ServiceMessage<T>>,
        pub idle_timeout: Duration,
    }

    /// Trait for peer stages that might be used as starting point for peer's [`run`] function.
    pub(super) trait Entrypoint<K: Kex, E: Enc>: Handshake<K, E> + Send + 'static {
        fn connection_id(&self) -> ConnectionId;
    }

    impl<K: Kex, E: Enc> Entrypoint<K, E> for Connecting {
        fn connection_id(&self) -> ConnectionId {
            self.connection_id
        }
    }

    impl<K: Kex, E: Enc> Entrypoint<K, E> for ConnectedFrom {
        fn connection_id(&self) -> ConnectionId {
            self.connection.id
        }
    }

    /// Cancellation-safe way to read messages from tcp stream
    struct MessageReader<E: Enc> {
        read: OwnedReadHalf,
        buffer: bytes::BytesMut,
        cryptographer: Cryptographer<E>,
    }

    impl<E: Enc> MessageReader<E> {
        const U32_SIZE: usize = core::mem::size_of::<u32>();

        fn new(read: OwnedReadHalf, cryptographer: Cryptographer<E>) -> Self {
            Self {
                read,
                cryptographer,
                // TODO: eyeball decision of default buffer size of 1 KB, should be benchmarked and optimized
                buffer: BytesMut::with_capacity(1024),
            }
        }

        /// Read message by first reading it's size as u32 and then rest of the message
        ///
        /// # Errors
        /// - Fail in case reading from stream fails
        /// - Connection is closed by there is still unfinished message in buffer
        /// - Forward errors from [`Self::parse_message`]
        async fn read_message<T: Pload>(&mut self) -> Result<Option<T>, Error> {
            loop {
                // Try to get full message
                if let Some(msg) = self.parse_message()? {
                    return Ok(Some(msg));
                }

                if 0 == self.read.read_buf(&mut self.buffer).await? {
                    if self.buffer.is_empty() {
                        return Ok(None);
                    }
                    return Err(Error::ConnectionResetByPeer);
                }
            }
        }

        /// Parse message
        ///
        /// # Errors
        /// - Fail to decrypt message
        /// - Fail to decode message
        fn parse_message<T: Pload>(&mut self) -> Result<Option<T>, Error> {
            let mut buf = &self.buffer[..];
            if buf.remaining() < Self::U32_SIZE {
                // Not enough data to read u32
                return Ok(None);
            }
            let size = buf.get_u32() as usize;
            if buf.remaining() < size {
                // Not enough data to read the whole data
                return Ok(None);
            }

            let data = &buf[..size];
            let decrypted = self.cryptographer.decrypt(data)?;
            let decoded = DecodeAll::decode_all(&mut decrypted.as_slice())?;

            self.buffer.advance(size + Self::U32_SIZE);

            Ok(Some(decoded))
        }
    }

    struct MessageSender<E: Enc> {
        write: OwnedWriteHalf,
        cryptographer: Cryptographer<E>,
        /// Reusable buffer to encode messages
        buffer: Vec<u8>,
        /// Queue of encrypted messages waiting to be sent
        queue: BytesMut,
    }

    impl<E: Enc> MessageSender<E> {
        const U32_SIZE: usize = core::mem::size_of::<u32>();

        fn new(write: OwnedWriteHalf, cryptographer: Cryptographer<E>) -> Self {
            Self {
                write,
                cryptographer,
                // TODO: eyeball decision of default buffer size of 1 KB, should be benchmarked and optimized
                buffer: Vec::with_capacity(1024),
                queue: BytesMut::with_capacity(1024),
            }
        }

        /// Prepare message for the delivery and put it into the queue to be sent later
        ///
        /// # Errors
        /// - If encryption fail.
        fn prepare_message<T: Pload>(&mut self, msg: T) -> Result<(), Error> {
            // Start with fresh buffer
            self.buffer.clear();
            msg.encode_to(&mut self.buffer);
            let encrypted = self.cryptographer.encrypt(&self.buffer)?;

            let size = encrypted.len();
            self.queue.reserve(size + Self::U32_SIZE);
            #[allow(clippy::cast_possible_truncation)]
            self.queue.put_u32(size as u32);
            self.queue.put_slice(encrypted.as_slice());
            Ok(())
        }

        /// Send bytes of byte-encoded messages piled up in the message queue so far.
        /// On the other side peer will collect bytes and recreate original messages from them.
        ///
        /// Sends only as much data as the underlying writer will accept in one `.write` call,
        /// so must be called in a loop to ensure everything will get sent.
        ///
        /// # Errors
        /// - If write to `stream` fail.
        async fn send(&mut self) -> Result<(), Error> {
            let chunk = self.queue.chunk();
            if !chunk.is_empty() {
                let n = self.write.write(chunk).await?;
                self.queue.advance(n);
            }
            Ok(())
        }

        /// Check if message sender has data ready to be sent.
        fn ready(&self) -> bool {
            !self.queue.is_empty()
        }
    }

    /// Either message or ping
    #[derive(Encode, Decode, Clone, Debug)]
    enum Message<T> {
        Data(T),
        Ping,
        Pong,
    }
}

mod state {
    //! Module for peer stages.

    use iroha_crypto::{KeyGenOption, KeyPair, PublicKey, Signature};
    use iroha_primitives::addr::SocketAddr;

    use super::{cryptographer::Cryptographer, *};

    /// Peer that is connecting. This is the initial stage of a new
    /// outgoing peer.
    pub(super) struct Connecting {
        pub peer_addr: SocketAddr,
        pub key_pair: KeyPair,
        pub connection_id: ConnectionId,
    }

    impl Connecting {
        pub(super) async fn connect_to(
            Self {
                peer_addr,
                key_pair,
                connection_id,
            }: Self,
        ) -> Result<ConnectedTo, crate::Error> {
            let stream = TcpStream::connect(peer_addr.to_string()).await?;
            let connection = Connection::new(connection_id, stream);
            Ok(ConnectedTo {
                peer_addr,
                key_pair,
                connection,
            })
        }
    }

    /// Peer that is being connected to.
    pub(super) struct ConnectedTo {
        peer_addr: SocketAddr,
        key_pair: KeyPair,
        connection: Connection,
    }

    impl ConnectedTo {
        #[allow(clippy::similar_names)]
        pub(super) async fn send_client_hello<K: Kex, E: Enc>(
            Self {
                peer_addr,
                key_pair,
                mut connection,
            }: Self,
        ) -> Result<SendKey<K, E>, crate::Error> {
            let key_exchange = K::new();
            let (kx_local_pk, kx_local_sk) = key_exchange.keypair(KeyGenOption::Random);
            let write_half = &mut connection.write;
            write_half
                .write_all(K::encode_public_key(&kx_local_pk))
                .await?;
            // Read server hello with node's public key
            let read_half = &mut connection.read;
            let kx_remote_pk = {
                // Then we have servers public key
                let mut key = vec![0_u8; 32];
                let _ = read_half.read_exact(&mut key).await?;
                K::decode_public_key(key).map_err(iroha_crypto::error::Error::from)?
            };
            let shared_key = key_exchange.compute_shared_secret(&kx_local_sk, &kx_remote_pk);
            let cryptographer = Cryptographer::new(&shared_key);
            Ok(SendKey {
                peer_addr,
                key_pair,
                kx_local_pk,
                kx_remote_pk,
                connection,
                cryptographer,
            })
        }
    }

    /// Peer that is being connected from
    pub(super) struct ConnectedFrom {
        pub peer_addr: SocketAddr,
        pub key_pair: KeyPair,
        pub connection: Connection,
    }

    impl ConnectedFrom {
        #[allow(clippy::similar_names)]
        pub(super) async fn read_client_hello<K: Kex, E: Enc>(
            Self {
                peer_addr,
                key_pair,
                mut connection,
                ..
            }: Self,
        ) -> Result<SendKey<K, E>, crate::Error> {
            let key_exchange = K::new();
            let (kx_local_pk, kx_local_sk) = key_exchange.keypair(KeyGenOption::Random);
            let kx_local_pk_raw = K::encode_public_key(&kx_local_pk);
            let read_half = &mut connection.read;
            let kx_remote_pk = {
                // And then we have clients public key
                let mut key = vec![0_u8; 32];
                let _ = read_half.read_exact(&mut key).await?;
                K::decode_public_key(key).map_err(iroha_crypto::error::Error::from)?
            };
            let write_half = &mut connection.write;
            write_half.write_all(kx_local_pk_raw).await?;
            let shared_key = key_exchange.compute_shared_secret(&kx_local_sk, &kx_remote_pk);
            let cryptographer = Cryptographer::new(&shared_key);
            Ok(SendKey {
                peer_addr,
                key_pair,
                kx_local_pk,
                kx_remote_pk,
                connection,
                cryptographer,
            })
        }
    }

    /// Peer that needs to send key.
    pub(super) struct SendKey<K: Kex, E: Enc> {
        peer_addr: SocketAddr,
        key_pair: KeyPair,
        kx_local_pk: K::PublicKey,
        kx_remote_pk: K::PublicKey,
        connection: Connection,
        cryptographer: Cryptographer<E>,
    }

    impl<K: Kex, E: Enc> SendKey<K, E> {
        pub(super) async fn send_our_public_key(
            Self {
                peer_addr,
                key_pair,
                kx_local_pk,
                kx_remote_pk,
                mut connection,
                cryptographer,
            }: Self,
        ) -> Result<GetKey<K, E>, crate::Error> {
            let write_half = &mut connection.write;

            let payload = create_payload::<K>(&kx_local_pk, &kx_remote_pk);
            let signature = Signature::new(key_pair.private_key(), &payload);
            let data = (key_pair.public_key(), signature).encode();

            let data = &cryptographer.encrypt(data.as_slice())?;

            let mut buf = Vec::<u8>::with_capacity(data.len() + 1);
            #[allow(clippy::cast_possible_truncation)]
            buf.push(data.len() as u8);
            buf.extend_from_slice(data.as_slice());

            write_half.write_all(&buf).await?;
            Ok(GetKey {
                peer_addr,
                connection,
                kx_local_pk,
                kx_remote_pk,
                cryptographer,
            })
        }
    }

    /// Peer that needs to get key.
    pub struct GetKey<K: Kex, E: Enc> {
        peer_addr: SocketAddr,
        connection: Connection,
        kx_local_pk: K::PublicKey,
        kx_remote_pk: K::PublicKey,
        cryptographer: Cryptographer<E>,
    }

    impl<K: Kex, E: Enc> GetKey<K, E> {
        /// Read the peer's public key
        pub(super) async fn read_their_public_key(
            Self {
                peer_addr,
                mut connection,
                kx_local_pk,
                kx_remote_pk,
                cryptographer,
            }: Self,
        ) -> Result<Ready<E>, crate::Error> {
            let read_half = &mut connection.read;
            let size = read_half.read_u8().await? as usize;
            // Reading public key
            let mut data = vec![0_u8; size];
            let _ = read_half.read_exact(&mut data).await?;

            let data = cryptographer.decrypt(data.as_slice())?;

            let (remote_pub_key, signature): (PublicKey, Signature) =
                DecodeAll::decode_all(&mut data.as_slice())?;

            // Swap order of keys since we are verifying for other peer order remote/local keys is reversed
            let payload = create_payload::<K>(&kx_remote_pk, &kx_local_pk);
            signature.verify(&remote_pub_key, &payload)?;

            let peer_id = PeerId::new(peer_addr, remote_pub_key);

            Ok(Ready {
                peer_id,
                connection,
                cryptographer,
            })
        }
    }

    /// Peer that is ready for communication after finishing the
    /// handshake process.
    pub(super) struct Ready<E: Enc> {
        pub peer_id: PeerId,
        pub connection: Connection,
        pub cryptographer: Cryptographer<E>,
    }

    fn create_payload<K: Kex>(kx_local_pk: &K::PublicKey, kx_remote_pk: &K::PublicKey) -> Vec<u8> {
        let mut payload = Vec::from(K::encode_public_key(kx_local_pk));
        payload.extend_from_slice(K::encode_public_key(kx_remote_pk));
        payload
    }
}

mod handshake {
    //! Implementations of the handshake process.

    use async_trait::async_trait;

    use super::{state::*, *};

    #[async_trait]
    pub(super) trait Stage<K: Kex, E: Enc> {
        type NextStage;

        async fn advance_to_next_stage(self) -> Result<Self::NextStage, crate::Error>;
    }

    macro_rules! stage {
        ( $func:ident : $curstage:ty => $nextstage:ty ) => {
            stage!(@base self Self::$func(self).await ; $curstage => $nextstage);
        };
        ( $func:ident :: <$($generic_param:ident),+> : $curstage:ty => $nextstage:ty ) => {
            stage!(@base self Self::$func::<$($generic_param),+>(self).await ; $curstage => $nextstage);
        };
        // Internal case
        (@base $self:ident $call:expr ; $curstage:ty => $nextstage:ty ) => {
            #[async_trait]
            impl<K: Kex, E: Enc> Stage<K, E> for $curstage {
                type NextStage = $nextstage;

                async fn advance_to_next_stage(self) -> Result<Self::NextStage, crate::Error> {
                    // NOTE: Need this due to macro hygiene
                    let $self = self;
                    $call
                }
            }
        }
    }

    stage!(connect_to: Connecting => ConnectedTo);
    stage!(send_client_hello::<K, E>: ConnectedTo => SendKey<K, E>);
    stage!(read_client_hello::<K, E>: ConnectedFrom => SendKey<K, E>);
    stage!(send_our_public_key: SendKey<K, E> => GetKey<K, E>);
    stage!(read_their_public_key: GetKey<K, E> => Ready<E>);

    #[async_trait]
    pub(super) trait Handshake<K: Kex, E: Enc> {
        async fn handshake(self) -> Result<Ready<E>, crate::Error>;
    }

    macro_rules! impl_handshake {
        ( base_case $typ:ty ) => {
            // Base case, should be all states that lead to `Ready`
            #[async_trait]
            impl<K: Kex, E: Enc> Handshake<K, E> for $typ {
                #[inline]
                async fn handshake(self) -> Result<Ready<E>, crate::Error> {
                    <$typ as Stage<K, E>>::advance_to_next_stage(self).await
                }
            }
        };
        ( $typ:ty ) => {
            #[async_trait]
            impl<K: Kex, E: Enc> Handshake<K, E> for $typ {
                #[inline]
                async fn handshake(self) -> Result<Ready<E>, crate::Error> {
                    let next_stage = <$typ as Stage<K, E>>::advance_to_next_stage(self).await?;
                    <_ as Handshake<K, E>>::handshake(next_stage).await
                }
            }
        };
    }

    impl_handshake!(base_case GetKey<K, E>);
    impl_handshake!(SendKey<K, E>);
    impl_handshake!(ConnectedFrom);
    impl_handshake!(ConnectedTo);
    impl_handshake!(Connecting);
}

pub mod message {
    //! Module for peer messages

    use super::*;

    /// Connection and Handshake was successful
    pub struct Connected<T: Pload> {
        /// Peer Id
        pub peer_id: PeerId,
        /// Connection Id
        pub connection_id: ConnectionId,
        /// Handle for peer to send messages and terminate command
        pub ready_peer_handle: handles::PeerHandle<T>,
        /// Channel to send peer messages channel
        pub peer_message_sender: oneshot::Sender<mpsc::Sender<PeerMessage<T>>>,
        /// Disambiguator of connection (equal for both peers)
        pub disambiguator: u64,
    }

    /// Messages received from Peer
    pub struct PeerMessage<T: Pload>(pub PeerId, pub T);

    /// Peer faced error or `Terminate` message, send to indicate that it is terminated
    pub struct Terminated {
        /// Peer Id
        pub peer_id: Option<PeerId>,
        /// Connection Id
        pub conn_id: ConnectionId,
    }

    /// Messages sent by peer during connection process
    pub enum ServiceMessage<T: Pload> {
        /// Connection and Handshake was successful
        Connected(Connected<T>),
        /// Peer faced error or `Terminate` message, send to indicate that it is terminated
        Terminated(Terminated),
    }
}

mod cryptographer {
    use iroha_crypto::{encryption::SymmetricEncryptor, SessionKey};

    use super::*;
    use crate::blake2b_hash;

    /// Peer's cryptographic primitives
    #[derive(Clone)]
    pub struct Cryptographer<E: Enc> {
        /// Blake2b hash of the session key, used as unique shared value between two peers
        pub disambiguator: u64,
        /// Encryptor created from session key, that we got by Diffie-Hellman scheme
        pub encryptor: SymmetricEncryptor<E>,
    }

    impl<E: Enc> Cryptographer<E> {
        /// Decrypt bytes.
        ///
        /// # Errors
        /// Forwards [`SymmetricEncryptor::decrypt_easy`] error
        pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
            self.encryptor
                .decrypt_easy(DEFAULT_AAD.as_ref(), data)
                .map_err(Into::into)
        }

        /// Encrypt bytes.
        ///
        /// # Errors
        /// Forwards [`SymmetricEncryptor::decrypt_easy`] error
        pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
            self.encryptor
                .encrypt_easy(DEFAULT_AAD.as_ref(), data)
                .map_err(Into::into)
        }

        /// Derives shared key from local private key and remote public key.
        pub fn new(shared_key: &SessionKey) -> Self {
            let disambiguator = blake2b_hash(shared_key.payload());

            let encryptor = SymmetricEncryptor::<E>::new_from_session_key(shared_key);
            Self {
                disambiguator,
                encryptor,
            }
        }
    }
}

/// An identification for [`Peer`] connections.
pub type ConnectionId = u64;

/// P2P connection
#[derive(Debug)]
pub struct Connection {
    /// A unique connection id
    pub id: ConnectionId,
    /// Reading half of `TcpStream`
    pub read: OwnedReadHalf,
    /// Writing half of `TcpStream`
    pub write: OwnedWriteHalf,
}

impl Connection {
    /// Instantiate new connection from `connection_id` and `stream`.
    pub fn new(id: ConnectionId, stream: TcpStream) -> Self {
        let (read, write) = stream.into_split();
        Connection { id, read, write }
    }
}
