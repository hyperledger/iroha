use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Formatter},
    io,
    net::SocketAddr,
};

use async_stream::stream;
use futures::Stream;
use iroha_actor::{
    broker::{Broker, BrokerMessage},
    Actor, Addr, Context, Handler,
};
use iroha_crypto::PublicKey;
use iroha_logger::{info, warn};
use parity_scale_codec::{Decode, Encode};
use tokio::net::{TcpListener, TcpStream};
use ursa::{encryption::symm::Encryptor, kex::KeyExchangeScheme};

use crate::{
    peer::{Peer, PeerId},
    Error,
};

/// Main network layer structure, that is holding connections, called [`Peer`]s.
pub struct NetworkBase<T, K, E>
where
    T: Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Current peers in any state
    pub peers: HashMap<PeerId, Addr<Peer<T, K, E>>>,
    /// A set of connected peers, ready to work with
    pub connected_peers: HashSet<PublicKey>,
    /// `TcpListener` that is accepting peers' connections
    pub listener: Option<TcpListener>,
    /// Our app-level public key
    public_key: PublicKey,
    /// Broker doing internal communication
    pub broker: Broker,
}

impl<T, K, E> NetworkBase<T, K, E>
where
    T: Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Creates a network structure, that will hold connections to other nodes.
    ///
    /// # Errors
    /// It will return Err if it is unable to start listening on specified address:port.
    pub async fn new(
        broker: Broker,
        listen_addr: String,
        public_key: PublicKey,
    ) -> Result<Self, Error> {
        let addr: SocketAddr = listen_addr.parse()?;
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            peers: HashMap::new(),
            connected_peers: HashSet::new(),
            listener: Some(listener),
            public_key,
            broker,
        })
    }

    /// Yields a stream of accepted peer connections.
    fn listener_stream(
        listener: TcpListener,
        public_key: PublicKey,
    ) -> impl Stream<Item = NewPeer> + Send + 'static {
        stream! {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        info!("Accepted connection from {}", &addr);
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
        }
    }
}

impl<T, K, E> Debug for NetworkBase<T, K, E>
where
    T: Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Network")
            .field("peers", &self.peers)
            .finish()
    }
}

#[async_trait::async_trait]
impl<T, K, E> Actor for NetworkBase<T, K, E>
where
    T: Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        info!("Starting network...");
        // to start connections
        self.broker.subscribe::<Connect, _>(ctx);
        // from peer
        self.broker.subscribe::<PeerMessage<T>, _>(ctx);
        // from other iroha subsystems
        self.broker.subscribe::<Post<T>, _>(ctx);
        // register for peers from listener
        #[allow(clippy::expect_used)]
        let listener = self
            .listener
            .take()
            .expect("Unreachable, as it is supposed to have listener on the start");
        ctx.notify_with_context(Self::listener_stream(listener, self.public_key.clone()));
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<Connect> for NetworkBase<T, K, E>
where
    T: Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, Connect { id }: Connect) {
        match Peer::new_to(id.clone(), self.broker.clone()) {
            Ok(peer) => {
                let peer = peer.start().await;
                drop(self.peers.insert(id, peer));
            }
            Err(e) => warn!(%e, "Unable to create peer"),
        }
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<Post<T>> for NetworkBase<T, K, E>
where
    T: Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, msg: Post<T>) {
        let addr: &Addr<Peer<T, K, E>> = &self.peers[&msg.id];
        addr.do_send(msg).await;
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<PeerMessage<T>> for NetworkBase<T, K, E>
where
    T: Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, msg: PeerMessage<T>) {
        match msg {
            PeerMessage::Connected(id, connection_id) => {
                if self.connected_peers.contains(&id.public_key) {
                    warn!(
                        "Peer with public key {:?} already connected!",
                        &id.public_key
                    );
                    self.broker.issue_send(StopSelf(connection_id)).await;
                } else {
                    let _ = self.connected_peers.insert(id.public_key);
                }
            }
            PeerMessage::Disconnected(id) => {
                drop(self.peers.remove(&id));
                let _ = self.connected_peers.remove(&id.public_key);
            }
            PeerMessage::Message(_id, msg) => {
                self.broker.issue_send(msg).await;
            }
        };
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<Received<T>> for NetworkBase<T, K, E>
where
    T: Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, msg: Received<T>) {
        self.broker.issue_send(msg.data).await;
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<GetConnectedPeers> for NetworkBase<T, K, E>
where
    T: Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ConnectedPeers;

    async fn handle(&mut self, GetConnectedPeers: GetConnectedPeers) -> Self::Result {
        ConnectedPeers {
            peers: self.connected_peers.clone(),
        }
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<NewPeer> for NetworkBase<T, K, E>
where
    T: Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
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
        match Peer::new_from(id.clone(), stream, self.broker.clone()) {
            Ok(peer) => {
                let peer = peer.start().await;
                drop(self.peers.insert(id, peer));
            }
            Err(e) => warn!(%e, "Unable to create peer"),
        }
    }
}

/// The message that is sent to [Network] to start connection to some other peer.
#[derive(Clone, Debug, iroha_actor::Message)]
pub struct Connect {
    /// Peer identification
    pub id: PeerId,
}

/// The message that is sent to [`Network`] to get connected peers' ids.
#[derive(Clone, Copy, Debug, iroha_actor::Message)]
#[message(result = "ConnectedPeers")]
pub struct GetConnectedPeers;

/// The message that is sent from [`Network`] back as an answer to [`GetConnectedPeers`] message.
#[derive(Clone, Debug, iroha_actor::Message)]
pub struct ConnectedPeers {
    /// Connected peers' ids
    pub peers: HashSet<PublicKey>,
}

/// An id of connection.
pub type ConnectionId = u64;

/// Variants of messages from [`Peer`] - connection state changes and data messages
#[derive(Clone, Debug, iroha_actor::Message, Decode)]
pub enum PeerMessage<T: Encode + Decode> {
    /// Peer just connected and finished handshake
    Connected(PeerId, ConnectionId),
    /// Peer disconnected
    Disconnected(PeerId),
    /// Peer sent some message
    Message(PeerId, T),
}

/// The message received from other peer.
#[derive(Clone, Debug, iroha_actor::Message, Decode)]
pub struct Received<T: Encode + Decode> {
    /// Data received from another peer
    pub data: T,
    /// Peer identification
    pub id: PeerId,
}

/// The message to be sent to some other peer.
#[derive(Clone, Debug, iroha_actor::Message, Encode)]
pub struct Post<T: Encode> {
    /// Data to send to another peer
    pub data: T,
    /// Peer identification
    pub id: PeerId,
}

/// The message to stop the peer with included connection id.
#[derive(Clone, Copy, Debug, iroha_actor::Message, Encode)]
pub struct StopSelf(pub ConnectionId);

/// The result of some incoming peer connection.
#[derive(Debug, iroha_actor::Message)]
pub struct NewPeer(pub io::Result<(TcpStream, PeerId)>);
