use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Formatter},
    io,
};

use async_stream::stream;
use futures::Stream;
use iroha_actor::{
    broker::{Broker, BrokerMessage},
    Actor, Addr, Context, ContextHandler, Handler,
};
use iroha_crypto::{
    ursa::{encryption::symm::Encryptor, kex::KeyExchangeScheme},
    PublicKey,
};
use iroha_logger::{debug, info, warn};
use parity_scale_codec::{Decode, Encode};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{
        oneshot,
        oneshot::{Receiver, Sender},
    },
};

use crate::{
    peer::{Peer, PeerId},
    Error,
};

/// Peer actor and its connection ID
#[derive(Clone, Debug)]
pub struct Connection<T, K, E>(Addr<Peer<T, K, E>>, ConnectionId)
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static;

/// Base network layer structure, holding connections, called
/// [`Peer`]s.
pub struct NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Listenting address for incoming connections. Must parse into [`std::net::SocketAddr`].
    listen_addr: String,
    /// [`Peer`]s performing [`Peer::handshake`]
    pub new_peers: HashMap<ConnectionId, Addr<Peer<T, K, E>>>,
    /// Current [`Peer`]s in `Ready` state.
    pub peers: HashMap<PublicKey, Vec<Connection<T, K, E>>>,
    /// [`TcpListener`] that is accepting [`Peer`]s' connections
    pub listener: Option<TcpListener>,
    /// Our app-level public key
    public_key: PublicKey,
    /// [`iroha_actor::broker::Broker`] for internal communication
    pub broker: Broker,
    /// Flag that stops listening stream
    finish_sender: Option<Sender<()>>,
    /// Mailbox capacity
    mailbox: usize,
}

impl<T, K, E> NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Create a network structure, holding [`Connection`]s to other nodes.
    ///
    /// # Errors
    /// If unable to start listening on specified `listen_addr` in
    /// format `address:port`.
    pub async fn new(
        broker: Broker,
        listen_addr: String,
        public_key: PublicKey,
        mailbox: usize,
    ) -> Result<Self, Error> {
        info!(%listen_addr, "Binding listener to", );
        let listener = TcpListener::bind(&listen_addr).await?;
        Ok(Self {
            listen_addr,
            new_peers: HashMap::new(),
            peers: HashMap::new(),
            listener: Some(listener),
            public_key,
            broker,
            finish_sender: None,
            mailbox,
        })
    }

    /// Yield a stream of accepted peer connections.
    fn listener_stream(
        listener: TcpListener,
        public_key: PublicKey,
        mut finish: Receiver<()>,
    ) -> impl Stream<Item = NewPeer> + Send + 'static {
        #[allow(clippy::unwrap_used)]
        let listen_addr = listener.local_addr().unwrap().to_string();
        stream! {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, addr)) => {
                                debug!("[{}] Accepted connection from {}", &listen_addr, &addr);
                                let id = PeerId { address: addr.to_string(), public_key: public_key.clone() };
                                let new_peer: NewPeer = NewPeer(Ok((stream, id)));
                                yield new_peer;
                            },
                            Err(error) => {
                                warn!(%error, "Error accepting connection");
                                yield NewPeer(Err(error));
                            }
                        }
                    }
                    _ = (&mut finish) => {
                        info!("Listening stream finished");
                        break;
                    }
                    else => break,
                }
            }
        }
    }
}

impl<T, K, E> Debug for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Network")
            .field("peers", &self.peers.len())
            .finish()
    }
}

#[async_trait::async_trait]
impl<T, K, E> Actor for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    fn mailbox_capacity(&self) -> usize {
        self.mailbox
    }

    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        info!("Starting network actor on {}...", &self.listen_addr);
        // to start connections
        self.broker.subscribe::<ConnectPeer, _>(ctx);
        // from peer
        self.broker.subscribe::<PeerMessage<T>, _>(ctx);
        // from other iroha subsystems
        self.broker.subscribe::<Post<T>, _>(ctx);
        // to be able to stop all of this
        self.broker.subscribe::<StopSelf, _>(ctx);

        let (sender, receiver) = oneshot::channel();
        self.finish_sender = Some(sender);
        // register for peers from listener
        #[allow(clippy::expect_used)]
        let listener = self
            .listener
            .take()
            .expect("Unreachable, as it is supposed to have listener on the start");
        ctx.notify_with_context(Self::listener_stream(
            listener,
            self.public_key.clone(),
            receiver,
        ));
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<ConnectPeer> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, ConnectPeer { mut id }: ConnectPeer) {
        debug!(
            "[{}] Creating new peer actor for {:?}",
            &self.listen_addr, &id
        );
        id.public_key = self.public_key.clone();
        let peer = match Peer::new_to(id, self.broker.clone()).await {
            Ok(peer) => peer,
            Err(e) => {
                warn!(%e, "Unable to create peer");
                return;
            }
        };

        #[allow(clippy::expect_used)]
        let connection_id = peer
            .connection_id()
            .expect("has connection by construction.");
        let peer = peer.start().await;
        debug!(?peer, ?connection_id, "Inserting into new_peers");
        self.new_peers.insert(connection_id, peer.clone());
        peer.do_send(Start).await;
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<Post<T>> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, msg: Post<T>) {
        match self.peers.get(&msg.id.public_key) {
            Some(peers) if !peers.is_empty() => peers[0].0.do_send(msg).await,
            None if msg.id.public_key == self.public_key => debug!("Not sending message to myself"),
            Some(_) | None => warn!(
                id=?msg.id,
                "Didn't find peer to send message",
            ),
        }
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<PeerMessage<T>> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, msg: PeerMessage<T>) {
        use PeerMessage::*;

        match msg {
            Connected(id, connection_id) => {
                debug!("Connected connection_id {}", connection_id);
                let peers = self.peers.entry(id.public_key).or_default();
                if let Some(peer) = self.new_peers.remove(&connection_id) {
                    let connection = Connection(peer, connection_id);
                    peers.push(connection);
                }
                let count = self.peers.values().filter(|conn| !conn.is_empty()).count();
                let addr: &str = &self.listen_addr;
                info!(
                    addr,
                    peers = count,
                    new = self.new_peers.len(),
                    "Connected new peer."
                );
            }
            Disconnected(id, connection_id) => {
                info!(?id, connection_id, "Peer disconnected.");
                let connections = self.peers.entry(id.public_key).or_default();
                connections.retain(|connection| connection.1 != connection_id);
                // If this connection didn't have the luck to connect
                self.new_peers.remove(&connection_id);
                self.broker.issue_send(StopSelf::Peer(connection_id)).await;
                let count = self.peers.values().filter(|conn| !conn.is_empty()).count();
                info!(
                    "[{}] Disconnected peer {}, peers: {}",
                    &self.listen_addr, &id.address, count
                );
            }
            Message(_id, msg) => {
                //info!("PeerMessage::Message {:?}", &msg);
                self.broker.issue_send(*msg).await;
            }
        };
    }
}

#[async_trait::async_trait]
impl<T, K, E> ContextHandler<StopSelf> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, ctx: &mut Context<Self>, message: StopSelf) {
        match message {
            StopSelf::Peer(_) => {}
            StopSelf::Network => {
                debug!("Stopping Network");
                if let Some(sender) = self.finish_sender.take() {
                    let _ = sender.send(());
                }
                let futures = self
                    .peers
                    .values()
                    .map(|peers| {
                        let futures = peers
                            .iter()
                            .map(|peer| peer.0.do_send(message))
                            .collect::<Vec<_>>();
                        futures::future::join_all(futures)
                    })
                    .collect::<Vec<_>>();
                futures::future::join_all(futures).await;
                ctx.stop_after_buffered_processed();
            }
        }
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<GetConnectedPeers> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ConnectedPeers;

    async fn handle(&mut self, GetConnectedPeers: GetConnectedPeers) -> Self::Result {
        let peers = self
            .peers
            .iter()
            .filter(|(_, conn)| !conn.is_empty())
            .map(|(key, _)| key.clone())
            .collect();

        ConnectedPeers { peers }
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<NewPeer> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, NewPeer(peer): NewPeer) {
        let (stream, id) = match peer {
            Ok(peer) => peer,
            Err(error) => {
                warn!(%error, "Error in listener!");
                return;
            }
        };
        let peer = Peer::ConnectedFrom(
            id.clone(),
            self.broker.clone(),
            crate::peer::Connection::from(stream),
        );
        #[allow(clippy::expect_used)]
        let connection_id = peer.connection_id().expect("Succeeds by construction");
        let peer = peer.start().await;
        self.new_peers.insert(connection_id, peer.clone());
        peer.do_send(Start).await;
    }
}

/// The message that is sent to [`NetworkBase`] to start connection to some other peer.
#[derive(Clone, Debug, iroha_actor::Message)]
pub struct ConnectPeer {
    /// Peer identification
    pub id: PeerId,
}

/// The message that is sent to [`Peer`] to start connection.
#[derive(Clone, Copy, Debug, iroha_actor::Message)]
pub struct Start;

/// The message that is sent to [`NetworkBase`] to get connected peers' ids.
#[derive(Clone, Copy, Debug, iroha_actor::Message)]
#[message(result = "ConnectedPeers")]
pub struct GetConnectedPeers;

/// The message that is sent from [`NetworkBase`] back as an answer to [`GetConnectedPeers`] message.
#[derive(Clone, Debug, iroha_actor::Message)]
pub struct ConnectedPeers {
    /// Connected peers' ids
    pub peers: HashSet<PublicKey>,
}

/// The [`Connection`]'s `id`.
pub type ConnectionId = u64;

/// Variants of messages from [`Peer`] - connection state changes and data messages
#[derive(Clone, Debug, iroha_actor::Message, Decode)]
pub enum PeerMessage<T: Encode + Decode + Debug> {
    /// [`Peer`] finished handshake and `Ready`
    Connected(PeerId, ConnectionId),
    /// [`Peer`] `Disconnected`
    Disconnected(PeerId, ConnectionId),
    /// [`Peer`] sent a message
    Message(PeerId, Box<T>),
}

/// The message to be sent to the other [`Peer`].
#[derive(Clone, Debug, iroha_actor::Message, Encode)]
pub struct Post<T: Encode + Debug> {
    /// Data to send to another peer
    pub data: T,
    /// Peer identification
    pub id: PeerId,
}

/// The message to stop the [`Peer`] with included [`ConnectionId`].
#[derive(Clone, Copy, Debug, iroha_actor::Message, Encode)]
pub enum StopSelf {
    /// Stop selected peer
    Peer(ConnectionId),
    /// Stop whole network
    Network,
}

/// The result of an incoming [`Peer`] connection.
#[derive(Debug, iroha_actor::Message)]
pub struct NewPeer(pub io::Result<(TcpStream, PeerId)>);
