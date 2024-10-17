//! Network formed out of Iroha peers.
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    net::ToSocketAddrs,
    time::Duration,
};

use futures::{stream::FuturesUnordered, StreamExt};
use iroha_config::parameters::actual::Network as Config;
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::prelude::PeerId;
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use iroha_logger::prelude::*;
use iroha_primitives::addr::SocketAddr;
use parity_scale_codec::Encode as _;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch},
};

use crate::{
    blake2b_hash,
    boilerplate::*,
    peer::{
        handles::{connected_from, connecting, PeerHandle},
        message::*,
        Connection, ConnectionId,
    },
    unbounded_with_len, Broadcast, Error, NetworkMessage, OnlinePeers, Post, UpdateTopology,
};

/// [`NetworkBase`] actor handle.
// NOTE: channels are unbounded in order to break communication cycle deadlock.
// Unbounded channels are ok here because messages frequency is either configurable (and relatively low)
// or depends on frequency of incoming messages from other peers which are bounded and backpressure is applied to them.
#[derive(derive_more::DebugCustom)]
#[debug(fmt = "core::any::type_name::<Self>()")]
pub struct NetworkBaseHandle<T: Pload, K: Kex, E: Enc> {
    /// Sender to subscribe for messages received form other peers in the network
    subscribe_to_peers_messages_sender: mpsc::UnboundedSender<mpsc::Sender<T>>,
    /// Receiver of `OnlinePeer` message
    online_peers_receiver: watch::Receiver<OnlinePeers>,
    /// [`UpdateTopology`] message sender
    update_topology_sender: mpsc::UnboundedSender<UpdateTopology>,
    /// Sender of [`NetworkMessage`] message
    network_message_sender: unbounded_with_len::Sender<NetworkMessage<T>>,
    /// Key exchange used by network
    _key_exchange: core::marker::PhantomData<K>,
    /// Encryptor used by the network
    _encryptor: core::marker::PhantomData<E>,
}

impl<T: Pload, K: Kex, E: Enc> Clone for NetworkBaseHandle<T, K, E> {
    fn clone(&self) -> Self {
        Self {
            subscribe_to_peers_messages_sender: self.subscribe_to_peers_messages_sender.clone(),
            online_peers_receiver: self.online_peers_receiver.clone(),
            update_topology_sender: self.update_topology_sender.clone(),
            network_message_sender: self.network_message_sender.clone(),
            _key_exchange: core::marker::PhantomData::<K>,
            _encryptor: core::marker::PhantomData::<E>,
        }
    }
}

impl<T: Pload, K: Kex + Sync, E: Enc + Sync> NetworkBaseHandle<T, K, E> {
    /// Start network peer and return handle to it
    ///
    /// # Errors
    /// - If binding to address fail
    #[log(skip(key_pair, shutdown_signal))]
    pub async fn start(
        key_pair: KeyPair,
        Config {
            address: listen_addr,
            idle_timeout,
        }: Config,
        shutdown_signal: ShutdownSignal,
    ) -> Result<(Self, Child), Error> {
        // TODO: enhance the error by reporting the origin of `listen_addr`
        let listener = TcpListener::bind(listen_addr.value().to_socket_addrs()?.as_slice()).await?;
        iroha_logger::info!("Network bound to listener");
        let (online_peers_sender, online_peers_receiver) = watch::channel(HashSet::new());
        let (subscribe_to_peers_messages_sender, subscribe_to_peers_messages_receiver) =
            mpsc::unbounded_channel();
        let (update_topology_sender, update_topology_receiver) = mpsc::unbounded_channel();
        let (network_message_sender, network_message_receiver) =
            unbounded_with_len::unbounded_channel();
        let (peer_message_sender, peer_message_receiver) = mpsc::channel(1);
        let (service_message_sender, service_message_receiver) = mpsc::channel(1);
        let network = NetworkBase {
            listen_addr: listen_addr.into_value(),
            listener,
            peers: HashMap::new(),
            connecting_peers: HashMap::new(),
            key_pair,
            subscribers_to_peers_messages: Vec::new(),
            subscribe_to_peers_messages_receiver,
            online_peers_sender,
            update_topology_receiver,
            network_message_receiver,
            peer_message_receiver,
            peer_message_sender,
            service_message_receiver,
            service_message_sender,
            current_conn_id: 0,
            current_topology: HashMap::new(),
            idle_timeout,
            _key_exchange: core::marker::PhantomData::<K>,
            _encryptor: core::marker::PhantomData::<E>,
        };
        let child = Child::new(
            tokio::task::spawn(network.run(shutdown_signal)),
            OnShutdown::Wait(Duration::from_secs(5)),
        );
        Ok((
            Self {
                subscribe_to_peers_messages_sender,
                online_peers_receiver,
                update_topology_sender,
                network_message_sender,
                _key_exchange: core::marker::PhantomData,
                _encryptor: core::marker::PhantomData,
            },
            child,
        ))
    }

    /// Subscribe to messages received from other peers in the network
    pub fn subscribe_to_peers_messages(&self, sender: mpsc::Sender<T>) {
        self.subscribe_to_peers_messages_sender
            .send(sender)
            .expect("NetworkBase must accept messages until there is at least one handle to it")
    }

    /// Send [`Post<T>`] message on network actor.
    pub fn post(&self, msg: Post<T>) {
        self.network_message_sender
            .send(NetworkMessage::Post(msg))
            .map_err(|_| ())
            .expect("NetworkBase must accept messages until there is at least one handle to it")
    }

    /// Send [`Broadcast<T>`] message on network actor.
    pub fn broadcast(&self, msg: Broadcast<T>) {
        self.network_message_sender
            .send(NetworkMessage::Broadcast(msg))
            .map_err(|_| ())
            .expect("NetworkBase must accept messages until there is at least one handle to it")
    }

    /// Send [`UpdateTopology`] message on network actor.
    pub fn update_topology(&self, topology: UpdateTopology) {
        self.update_topology_sender
            .send(topology)
            .expect("NetworkBase must accept messages until there is at least one handle to it")
    }

    /// Receive latest update of [`OnlinePeers`]
    pub fn online_peers<P>(&self, f: impl FnOnce(&OnlinePeers) -> P) -> P {
        f(&self.online_peers_receiver.borrow())
    }

    /// Wait for update of [`OnlinePeers`].
    pub async fn wait_online_peers_update<P>(
        &mut self,
        f: impl FnOnce(&OnlinePeers) -> P + Send,
    ) -> P {
        self.online_peers_receiver
            .changed()
            .await
            .expect("NetworkBase must accept messages until there is at least one handle to it");
        self.online_peers(f)
    }
}

/// Base network layer structure, holding connections interacting with peers.
struct NetworkBase<T: Pload, K: Kex, E: Enc> {
    /// Listening address for incoming connections. Must parse into [`std::net::SocketAddr`]
    listen_addr: SocketAddr,
    /// Current [`Peer`]s in [`Peer::Ready`] state.
    peers: HashMap<PublicKey, RefPeer<T>>,
    /// [`Peer`]s in process of being connected.
    connecting_peers: HashMap<ConnectionId, PublicKey>,
    /// [`TcpListener`] that is accepting [`Peer`]s' connections
    listener: TcpListener,
    /// Our app-level key pair
    key_pair: KeyPair,
    /// Recipients of messages received from other peers in the network.
    subscribers_to_peers_messages: Vec<mpsc::Sender<T>>,
    /// Receiver to subscribe for messages received from other peers in the network.
    subscribe_to_peers_messages_receiver: mpsc::UnboundedReceiver<mpsc::Sender<T>>,
    /// Sender of `OnlinePeer` message
    online_peers_sender: watch::Sender<OnlinePeers>,
    /// [`UpdateTopology`] message receiver
    update_topology_receiver: mpsc::UnboundedReceiver<UpdateTopology>,
    /// Receiver of [`Post`] message
    network_message_receiver: unbounded_with_len::Receiver<NetworkMessage<T>>,
    /// Channel to gather messages from all peers
    peer_message_receiver: mpsc::Receiver<PeerMessage<T>>,
    /// Sender for peer messages to provide clone of sender inside peer
    peer_message_sender: mpsc::Sender<PeerMessage<T>>,
    /// Channel to gather service messages from all peers
    service_message_receiver: mpsc::Receiver<ServiceMessage<T>>,
    /// Sender for service peer messages to provide clone of sender inside peer
    service_message_sender: mpsc::Sender<ServiceMessage<T>>,
    /// Current available connection id
    current_conn_id: ConnectionId,
    /// Current topology
    /// Bool determines who is responsible for initiating connection
    current_topology: HashMap<PeerId, bool>,
    /// Duration after which terminate connection with idle peer
    idle_timeout: Duration,
    /// Key exchange used by network
    _key_exchange: core::marker::PhantomData<K>,
    /// Encryptor used by the network
    _encryptor: core::marker::PhantomData<E>,
}

impl<T: Pload, K: Kex, E: Enc> NetworkBase<T, K, E> {
    /// [`Self`] task.
    #[log(skip(self, shutdown_signal), fields(listen_addr=%self.listen_addr, public_key=%self.key_pair.public_key()))]
    async fn run(mut self, shutdown_signal: ShutdownSignal) {
        // TODO: probably should be configuration parameter
        let mut update_topology_interval = tokio::time::interval(Duration::from_millis(1000));
        loop {
            tokio::select! {
                // Select is biased because we want to service messages to take priority over data messages.
                biased;
                // Subscribe messages is expected to exhaust at some point after starting network actor
                Some(subscriber) = self.subscribe_to_peers_messages_receiver.recv() => {
                    self.subscribe_to_peers_messages(subscriber);
                }
                // Update topology is relative low rate message (at most once every block)
                Some(update_topology) = self.update_topology_receiver.recv() => {
                    self.set_current_topology(update_topology);
                }
                // Frequency of update is relatively low, so it won't block other tasks from execution
                _ = update_topology_interval.tick() => {
                    self.update_topology()
                }
                // Every peer produce small amount of service messages so this shouldn't starve other tasks
                Some(service_message) = self.service_message_receiver.recv() => {
                    match service_message {
                        ServiceMessage::Terminated(terminated) => {
                            self.peer_terminated(terminated);
                        }
                        ServiceMessage::Connected(connected) => {
                            self.peer_connected(connected);
                        }
                    }
                }
                // Because network messages is responses to incoming messages or relatively low rate messages
                // they will be exhaust at some point given opportunity for incoming message to being processed
                network_message = self.network_message_receiver.recv() => {
                    let Some(network_message) = network_message else {
                        iroha_logger::debug!("All handles to network actor are dropped. Shutting down...");
                        break;
                    };
                    let network_message_receiver_len = self.network_message_receiver.len();
                    if network_message_receiver_len > 100 {
                        iroha_logger::warn!(size=network_message_receiver_len, "Network post messages are pilling up in the queue");
                    }
                    match network_message {
                        NetworkMessage::Post(post) => self.post(post),
                        NetworkMessage::Broadcast(broadcast) => self.broadcast(broadcast),
                    }
                }
                // Accept incoming peer connections
                accept = self.listener.accept() => {
                    match accept {
                        Ok((stream, addr)) => {
                            iroha_logger::debug!(from_addr = %addr, "Accepted connection");
                            // Handle creation of new peer
                            self.accept_new_peer(stream, &addr.into());
                        },
                        Err(error) => {
                            iroha_logger::warn!(%error, "Error accepting connection");
                        }
                    }
                }
                // Messages from other peers has lowest priority because we can't control their frequency
                Some(peer_message) = self.peer_message_receiver.recv() => {
                    self.peer_message(peer_message).await;
                }
                () = shutdown_signal.receive() => {
                    iroha_logger::debug!("Shutting down due to signal");
                    break
                }
                else => {
                    iroha_logger::debug!("All receivers are dropped, shutting down");
                    break
                },
            }
            tokio::task::yield_now().await;
        }
    }

    fn accept_new_peer(&mut self, stream: TcpStream, addr: &SocketAddr) {
        let conn_id = self.get_conn_id();
        let service_message_sender = self.service_message_sender.clone();
        connected_from::<T, K, E>(
            addr.clone(),
            self.key_pair.clone(),
            Connection::new(conn_id, stream),
            service_message_sender,
            self.idle_timeout,
        );
    }

    fn set_current_topology(&mut self, UpdateTopology(topology): UpdateTopology) {
        iroha_logger::debug!(?topology, "Network receive new topology");
        let self_public_key_hash = blake2b_hash(self.key_pair.public_key().encode());
        let topology = topology
            .into_iter()
            .filter(|peer_id| peer_id.public_key() != self.key_pair.public_key())
            .map(|peer_id| {
                // Determine who is responsible for connecting
                let peer_public_key_hash = blake2b_hash(peer_id.public_key().encode());
                let is_active = self_public_key_hash >= peer_public_key_hash;
                (peer_id, is_active)
            })
            .collect();
        self.current_topology = topology;
        self.update_topology()
    }

    fn update_topology(&mut self) {
        let to_connect = self
            .current_topology
            .iter()
            // Peer is not connected but should
            .filter_map(|(peer, is_active)| {
                (!self.peers.contains_key(&peer.public_key)
                    && !self
                        .connecting_peers
                        .values()
                        .any(|public_key| peer.public_key() == public_key)
                    && *is_active)
                    .then_some(peer)
            })
            .cloned()
            .collect::<Vec<_>>();

        let to_disconnect = self
            .peers
            .keys()
            // Peer is connected but shouldn't
            .filter(|public_key| !self.current_topology.contains_key(*public_key))
            .cloned()
            .collect::<Vec<_>>();

        for peer in to_connect {
            self.connect_peer(&peer);
        }

        for public_key in to_disconnect {
            self.disconnect_peer(&public_key)
        }
    }

    fn connect_peer(&mut self, peer: &PeerId) {
        iroha_logger::trace!(
            listen_addr = %self.listen_addr, peer.id.address = %peer.address,
            "Creating new peer actor",
        );

        let conn_id = self.get_conn_id();
        self.connecting_peers
            .insert(conn_id, peer.public_key().clone());
        let service_message_sender = self.service_message_sender.clone();
        connecting::<T, K, E>(
            // NOTE: we intentionally use peer's address and our public key, it's used during handshake
            peer.address.clone(),
            self.key_pair.clone(),
            conn_id,
            service_message_sender,
            self.idle_timeout,
        );
    }

    fn disconnect_peer(&mut self, public_key: &PublicKey) {
        let peer = match self.peers.remove(public_key) {
            Some(peer) => peer,
            _ => return iroha_logger::warn!(?public_key, "Not found peer to disconnect"),
        };
        iroha_logger::debug!(listen_addr = %self.listen_addr, %peer.conn_id, "Disconnecting peer");

        let peer_id = PeerId::new(peer.p2p_addr, public_key.clone());
        Self::remove_online_peer(&self.online_peers_sender, &peer_id);
    }

    #[log(skip_all, fields(peer=%peer_id, conn_id=connection_id, disambiguator=disambiguator))]
    fn peer_connected(
        &mut self,
        Connected {
            peer_id,
            connection_id,
            ready_peer_handle,
            peer_message_sender,
            disambiguator,
        }: Connected<T>,
    ) {
        self.connecting_peers.remove(&connection_id);

        if !self.current_topology.contains_key(&peer_id) {
            iroha_logger::warn!(%peer_id, topology=?self.current_topology, "Peer not present in topology is trying to connect");
            return;
        }

        //  Insert peer if peer not in peers yet or replace peer if it's disambiguator value is smaller than new one (simultaneous connections resolution rule)
        match self.peers.get(&peer_id.public_key) {
            Some(peer) if peer.disambiguator > disambiguator => {
                iroha_logger::debug!(
                    "Peer is disconnected due to simultaneous connection resolution policy"
                );
                return;
            }
            Some(_) => {
                iroha_logger::debug!("New peer will replace previous one due to simultaneous connection resolution policy");
            }
            None => {
                iroha_logger::debug!("Peer isn't in the peer set, inserting");
            }
        }

        let ref_peer = RefPeer {
            handle: ready_peer_handle,
            conn_id: connection_id,
            p2p_addr: peer_id.address.clone(),
            disambiguator,
        };
        let _ = peer_message_sender.send(self.peer_message_sender.clone());
        self.peers.insert(peer_id.public_key().clone(), ref_peer);
        Self::add_online_peer(&self.online_peers_sender, peer_id);
    }

    fn peer_terminated(&mut self, Terminated { peer_id, conn_id }: Terminated) {
        self.connecting_peers.remove(&conn_id);
        if let Some(peer_id) = peer_id {
            if let Some(peer) = self.peers.get(&peer_id.public_key) {
                if peer.conn_id == conn_id {
                    iroha_logger::debug!(conn_id, peer=%peer_id, "Peer terminated");
                    self.peers.remove(&peer_id.public_key);
                    Self::remove_online_peer(&self.online_peers_sender, &peer_id);
                }
            }
        }
    }

    fn post(&mut self, Post { data, peer_id }: Post<T>) {
        iroha_logger::trace!(peer=%peer_id, "Post message");
        match self.peers.get(&peer_id.public_key) {
            Some(peer) => {
                if peer.handle.post(data).is_err() {
                    iroha_logger::error!(peer=%peer_id, "Failed to send message to peer");
                    self.peers.remove(&peer_id.public_key);
                    Self::remove_online_peer(&self.online_peers_sender, &peer_id);
                }
            }
            None if peer_id.public_key() == self.key_pair.public_key() => {
                #[cfg(debug_assertions)]
                iroha_logger::trace!("Not sending message to myself")
            }
            _ => iroha_logger::warn!(peer=%peer_id, "Peer not found. Message not sent."),
        }
    }

    fn broadcast(&mut self, Broadcast { data }: Broadcast<T>) {
        iroha_logger::trace!("Broadcast message");
        let Self {
            peers,
            online_peers_sender,
            ..
        } = self;
        peers.retain(|public_key, ref_peer| {
            if ref_peer.handle.post(data.clone()).is_err() {
                let peer_id = PeerId::new(ref_peer.p2p_addr.clone(), public_key.clone());
                iroha_logger::error!(peer=%peer_id, "Failed to send message to peer");
                Self::remove_online_peer(online_peers_sender, &peer_id);
                false
            } else {
                true
            }
        });
    }

    async fn peer_message(&mut self, PeerMessage(peer_id, msg): PeerMessage<T>) {
        // TODO: consider broadcast channel instead
        iroha_logger::trace!(peer=%peer_id, "Received peer message");
        if self.subscribers_to_peers_messages.is_empty() {
            iroha_logger::warn!("No subscribers to send message to");
            return;
        }
        self.subscribers_to_peers_messages = self
            .subscribers_to_peers_messages
            .drain(..)
            .zip(core::iter::repeat(msg))
            .map(|(subscriber_t, msg)| async move {
                let is_ok = subscriber_t.send(msg).await.is_ok();
                (subscriber_t, is_ok)
            })
            .collect::<FuturesUnordered<_>>()
            .filter_map(|(subscriber_t, is_ok)| {
                futures::future::ready(is_ok.then_some(subscriber_t))
            })
            .collect::<Vec<_>>()
            .await;
    }

    fn subscribe_to_peers_messages(&mut self, subscriber: mpsc::Sender<T>) {
        self.subscribers_to_peers_messages.push(subscriber);
        iroha_logger::trace!(
            subscribers = self.subscribers_to_peers_messages.len(),
            "Network receive new message subscriber"
        );
    }

    fn add_online_peer(online_peers_sender: &watch::Sender<OnlinePeers>, peer_id: PeerId) {
        online_peers_sender.send_if_modified(|online_peers| online_peers.insert(peer_id));
    }

    fn remove_online_peer(online_peers_sender: &watch::Sender<OnlinePeers>, peer_id: &PeerId) {
        online_peers_sender.send_if_modified(|online_peers| online_peers.remove(peer_id));
    }

    fn get_conn_id(&mut self) -> ConnectionId {
        let conn_id = self.current_conn_id;
        self.current_conn_id = conn_id.wrapping_add(1);
        conn_id
    }
}

pub mod message {
    //! Module for network messages

    use super::*;

    /// Current online network peers
    pub type OnlinePeers = HashSet<PeerId>;

    /// The message that is sent to [`NetworkBase`] to update p2p topology of the network.
    #[derive(Clone, Debug)]
    pub struct UpdateTopology(pub OnlinePeers);

    /// The message to be sent to the other [`Peer`].
    #[derive(Clone, Debug)]
    pub struct Post<T> {
        /// Data to be sent
        pub data: T,
        /// Destination peer
        pub peer_id: PeerId,
    }

    /// The message to be send to the all connected [`Peer`]s.
    #[derive(Clone, Debug)]
    pub struct Broadcast<T> {
        /// Data to be send
        pub data: T,
    }

    /// Message send to network by other actors.
    pub(crate) enum NetworkMessage<T> {
        Post(Post<T>),
        Broadcast(Broadcast<T>),
    }
}

/// Reference as a means of communication with a [`Peer`]
struct RefPeer<T: Pload> {
    handle: PeerHandle<T>,
    conn_id: ConnectionId,
    p2p_addr: SocketAddr,
    /// Disambiguator serves purpose of resolving situation when both peers are tying to connect to each other at the same time.
    /// Usually in Iroha network only one peer is trying to connect to another peer, but if peer is misbehaving it could be useful.
    ///
    /// Consider timeline:
    ///
    /// ```text
    /// [peer1 outgoing connection with peer2 completes first (A)] -> [peer1 incoming connection with peer2 completes second (B)]
    ///
    /// [peer2 outgoing connection with peer1 completes first (B)] -> [peer2 incoming connection with peer1 completes second (A)]
    /// ```
    ///
    /// Because it's meaningless for peer to have more than one connection with the same peer, peer must have some way of selecting what connection to preserve.
    ///
    /// In this case native approach where new connections will replace old ones won't work because it will result in peers not being connect at all.
    ///
    /// To solve this situation disambiguator value is used.
    /// It's equal for both peers and when peer receive connection for peer already present in peers set it just select connection with higher value.
    disambiguator: u64,
}
