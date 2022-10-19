//! Network formed out of Iroha peers.
#![allow(clippy::std_instead_of_core)]
use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Formatter},
    io,
    net::SocketAddr,
};

use async_stream::stream;
use futures::{prelude::*, stream::FuturesUnordered};
use iroha_actor::{
    broker::{Broker, BrokerMessage},
    Actor, Addr, Context, ContextHandler, Handler,
};
use iroha_crypto::{
    ursa::{encryption::symm::Encryptor, kex::KeyExchangeScheme},
    PublicKey,
};
use iroha_logger::prelude::*;
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

/// Reference as a means of communication with a [`Peer`]
#[derive(Clone, Debug)]
pub struct RefPeer<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    addr: Addr<Peer<T, K, E>>,
    conn_id: ConnectionId,
    p2p_addr: String,
}

/// Base network layer structure, holding connections, called
/// [`Peer`]s.
pub struct NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Listening address for incoming connections. Must parse into [`std::net::SocketAddr`]
    listen_addr: String,
    /// [`Peer`]s performing a `handshake`
    pub new_peers: HashMap<ConnectionId, Addr<Peer<T, K, E>>>,
    /// Current [`Peer`]s in [`Peer::Ready`] state.
    pub peers: HashMap<PublicKey, RefPeer<T, K, E>>,
    /// [`HashSet`] of [`String`] which should represent the [`std::net::IpAddr`] of the untrusted remote [`Peer`]:
    /// inserted by [`DisconnectPeer`] and removed by [`ConnectPeer`] from Sumeragi.
    /// In case the [`String`] represents an unresolved hostname, the first reconnection is not refused
    untrusted_peers: HashSet<String>,
    /// [`TcpListener`] that is accepting [`Peer`]s' connections
    pub listener: Option<TcpListener>,
    /// Our app-level public key
    public_key: PublicKey,
    /// [`iroha_actor::broker::Broker`] for internal communication
    pub broker: Broker,
    /// Flag that stops listening stream
    finish_sender: Option<Sender<()>>,
    /// Buffer capacity of actor's MPSC channel
    actor_channel_capacity: u32,
}

impl<T, K, E> NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    /// Create a network structure, holding channels to other peers
    ///
    /// # Errors
    /// If unable to start listening on specified `listen_addr` in
    /// format `address:port`.
    pub async fn new(
        broker: Broker,
        listen_addr: String,
        public_key: PublicKey,
        channel_size: u32,
    ) -> Result<Self, Error> {
        info!(%listen_addr, "Binding listener");
        let listener = TcpListener::bind(&listen_addr).await?;
        Ok(Self {
            listen_addr,
            new_peers: HashMap::new(),
            peers: HashMap::new(),
            untrusted_peers: HashSet::new(),
            listener: Some(listener),
            public_key,
            broker,
            finish_sender: None,
            actor_channel_capacity: channel_size,
        })
    }

    /// Yield a stream of accepted peer connections.
    fn listener_stream(
        listener: TcpListener,
        mut finish: Receiver<()>,
    ) -> impl Stream<Item = NewPeer> + Send + 'static {
        #![allow(clippy::unwrap_used, clippy::arithmetic)]
        let listen_addr = listener.local_addr().unwrap().to_string();
        stream! {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, addr)) => {
                                debug!(%listen_addr, from_addr = %addr, "Accepted connection");
                                let new_peer = NewPeer(Ok((stream, addr)));
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

    fn online_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .map(|(key, value)| PeerId {
                address: value.p2p_addr.clone(),
                public_key: key.clone(),
            })
            .collect()
    }
}

impl<T, K, E> Debug for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
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
    fn actor_channel_capacity(&self) -> u32 {
        self.actor_channel_capacity
    }

    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        info!(listen_addr = %self.listen_addr, "Starting network actor");
        // to start connections
        self.broker.subscribe::<ConnectPeer, _>(ctx);
        // to stop connections
        self.broker.subscribe::<DisconnectPeer, _>(ctx);
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
        ctx.notify_with(Self::listener_stream(listener, receiver));
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

    async fn handle(&mut self, msg: ConnectPeer) {
        if self.peers.contains_key(&msg.peer.public_key) {
            debug!(peer = %msg.peer, "Peer already connected");
            return;
        }

        debug!(
            listen_addr = %self.listen_addr, peer.id.address = %msg.peer.address,
            "Creating new peer actor",
        );
        self.untrusted_peers.remove(&ip(&msg.peer.address));
        let peer_to_key_exchange = match Peer::new_to(
            PeerId::new(&msg.peer.address, &self.public_key),
            self.broker.clone(),
        )
        .await
        {
            Ok(peer) => peer,
            Err(error) => {
                warn!(%error, "Unable to create peer");
                return;
            }
        };
        #[allow(clippy::expect_used)]
        let conn_id = peer_to_key_exchange
            .connection_id()
            .expect("has connection by construction.");
        let addr = peer_to_key_exchange.start().await;
        debug!(%conn_id, ?addr, "Inserting into new_peers");
        self.new_peers.insert(conn_id, addr.clone());
        addr.do_send(Start).await;
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<DisconnectPeer> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + BrokerMessage + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, DisconnectPeer(public_key): DisconnectPeer) {
        let peer = match self.peers.remove(&public_key) {
            Some(peer) => peer,
            _ => return error!(?public_key, "Not found peer to disconnect"),
        };
        debug!(listen_addr = %self.listen_addr, %peer.conn_id, "Disconnecting peer");
        self.untrusted_peers.insert(ip(&peer.p2p_addr));

        self.broker
            .issue_send(NetworkBaseRelayOnlinePeers {
                online_peers: self.online_peers(),
            })
            .await;

        self.broker.issue_send(StopSelf::Peer(peer.conn_id)).await
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
        match self.peers.get(&msg.peer.public_key) {
            Some(peer) => peer.addr.do_send(msg).await,
            None if msg.peer.public_key == self.public_key => {
                debug!("Not sending message to myself")
            }
            _ => warn!(
                peer.id = ?msg.peer,
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

    #[log] // Keep this
    async fn handle(&mut self, msg: PeerMessage<T>) {
        use PeerMessage::*;

        match msg {
            Connected(id, conn_id) => {
                if let Some(addr) = self.new_peers.remove(&conn_id) {
                    let peer = RefPeer {
                        addr,
                        conn_id,
                        p2p_addr: id.address,
                    };
                    self.peers.insert(id.public_key, peer);
                }
                info!(
                    listen_addr = %self.listen_addr,
                    count.new_peers = self.new_peers.len(),
                    count.peers = self.peers.len(),
                    "Peer connected"
                );
            }
            Disconnected(id, conn_id) => {
                self.peers.remove(&id.public_key);

                // In case the peer is new and has failed to connect
                self.new_peers.remove(&conn_id);

                self.broker.issue_send(StopSelf::Peer(conn_id)).await;
                info!(
                    listen_addr = %self.listen_addr,
                    count.new_peers = self.new_peers.len(),
                    count.peers = self.peers.len(),
                    "Peer disconnected"
                );
            }
            Message(_id, msg) => {
                self.broker.issue_send(*msg).await;
            }
        };

        self.broker
            .issue_send(NetworkBaseRelayOnlinePeers {
                online_peers: self.online_peers(),
            })
            .await;
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

    async fn handle(&mut self, ctx: &mut Context<Self>, msg: StopSelf) {
        match msg {
            StopSelf::Peer(_) => {}
            StopSelf::Network => {
                debug!("Stopping Network");
                if let Some(sender) = self.finish_sender.take() {
                    let _ = sender.send(());
                }
                let futures = self
                    .peers
                    .values()
                    .map(|peer| peer.addr.do_send(msg))
                    .collect::<FuturesUnordered<_>>();

                futures.collect::<()>().await;
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

    async fn handle(&mut self, _msg: GetConnectedPeers) -> Self::Result {
        let peers: HashSet<_> = self.peers.keys().cloned().collect();

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

    async fn handle(&mut self, NewPeer(conn_result): NewPeer) {
        let (stream, soc_addr) = match conn_result {
            Ok(conn) => conn,
            Err(error) => {
                warn!(%error, "Error in listener!");
                return;
            }
        };
        if self.untrusted_peers.contains(&ip(&soc_addr.to_string())) {
            return debug!(%soc_addr, "Untrusted new peer");
        }
        let peer_to_key_exchange = Peer::ConnectedFrom(
            PeerId::new(&soc_addr.to_string(), &self.public_key),
            self.broker.clone(),
            crate::peer::Connection::from(stream),
        );
        #[allow(clippy::expect_used)]
        let conn_id = peer_to_key_exchange
            .connection_id()
            .expect("Succeeds by construction");
        let addr = peer_to_key_exchange.start().await;
        self.new_peers.insert(conn_id, addr.clone());
        addr.do_send(Start).await;
    }
}

/// Message which informs `sumeragi` of the current online peers.
///
/// # Rationale
///
/// Because of how our translation units are set up, there cannot be
/// interdependencies between `p2p` and the modules in core that use
/// `p2p`. Therefore, to put incoming messages in the appropriate
/// queues they must first be sent to `cli` and then to `core`.  
#[derive(Clone, iroha_actor::Message)]
pub struct NetworkBaseRelayOnlinePeers {
    /// A list of [`PeerId`]s of peers currently connected to us.
    pub online_peers: Vec<PeerId>,
}

/// The message that is sent to [`NetworkBase`] to start connection to
/// some other peer.
#[derive(Clone, Debug, iroha_actor::Message)]
pub struct ConnectPeer {
    /// Socket address of the outgoing peer
    pub peer: PeerId,
}

/// The message that is sent to [`NetworkBase`] to stop connection to some other peer.
#[derive(Clone, Debug, iroha_actor::Message)]
pub struct DisconnectPeer(pub PublicKey);

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

/// An identification for [`Peer`] connections.
pub type ConnectionId = u64;

/// Variants of messages from [`Peer`]: connection state changes and data messages
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
    /// Data to be sent
    pub data: T,
    /// Destination peer
    pub peer: PeerId,
}

/// The message sent to [`Peer`] or [`NetworkBase`] to stop it.
#[derive(Clone, Copy, Debug, iroha_actor::Message, Encode)]
pub enum StopSelf {
    /// Stop selected peer
    Peer(ConnectionId),
    /// Stop whole network
    Network,
}

/// The result of an incoming [`Peer`] connection.
#[derive(Debug, iroha_actor::Message)]
pub struct NewPeer(pub io::Result<(TcpStream, SocketAddr)>);

/// Substitute for [`SocketAddr::ip`]
fn ip(address: &str) -> String {
    address.split(':').next().unwrap_or_default().to_owned()
}
