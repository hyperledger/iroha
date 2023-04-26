//! Network formed out of Iroha peers.
#![allow(clippy::std_instead_of_core)]
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    net::SocketAddr,
    time::Duration,
};

use futures::{stream::FuturesUnordered, StreamExt};
use iroha_crypto::PublicKey;
use iroha_data_model::prelude::PeerId;
use iroha_logger::prelude::*;
use message::*;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, watch},
};

use crate::{
    boilerplate::*,
    peer::{
        handles::{connected_from, connecting, PeerHandle},
        message::*,
        Connection, ConnectionId,
    },
    unbounded_with_len, Error,
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
    #[log(skip(public_key))]
    pub async fn start(listen_addr: String, public_key: PublicKey) -> Result<Self, Error> {
        let listener = TcpListener::bind(&listen_addr).await?;
        iroha_logger::info!("Network bound to listener");
        let (online_peers_sender, online_peers_receiver) = watch::channel(HashSet::new());
        let (subscribe_to_peers_messages_sender, subscribe_to_peers_messages_receiver) =
            mpsc::unbounded_channel();
        let (update_topology_sender, update_topology_receiver) = mpsc::unbounded_channel();
        let (network_message_sender, network_message_receiver) =
            unbounded_with_len::unbounded_channel();
        let (peer_message_sender, peer_message_receiver) = mpsc::channel(1);
        let network = NetworkBase {
            listen_addr,
            listener,
            peers: HashMap::new(),
            untrusted_peers: HashSet::new(),
            public_key,
            subscribers_to_peers_messages: Vec::new(),
            subscribe_to_peers_messages_receiver,
            online_peers_sender,
            update_topology_receiver,
            network_message_receiver,
            peer_message_receiver,
            peer_message_sender,
            connected_receivers: FuturesUnordered::new(),
            terminated_receivers: FuturesUnordered::new(),
            current_conn_id: 0,
            current_topology: HashSet::new(),
            _key_exchange: core::marker::PhantomData::<K>,
            _encryptor: core::marker::PhantomData::<E>,
        };
        tokio::task::spawn(network.run());
        Ok(Self {
            subscribe_to_peers_messages_sender,
            online_peers_receiver,
            update_topology_sender,
            network_message_sender,
            _key_exchange: core::marker::PhantomData,
            _encryptor: core::marker::PhantomData,
        })
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
    listen_addr: String,
    /// Current [`Peer`]s in [`Peer::Ready`] state.
    peers: HashMap<PublicKey, RefPeer<T>>,
    /// Map from [`std::net::IpAddr`] of the untrusted remote [`Peer`]:
    /// inserted by [`DisconnectPeer`] and removed by [`ConnectPeer`] from Sumeragi.
    /// In case the [`String`] represents an unresolved hostname, the first reconnection is not refused
    untrusted_peers: HashSet<String>,
    /// [`TcpListener`] that is accepting [`Peer`]s' connections
    listener: TcpListener,
    /// Our app-level public key
    public_key: PublicKey,
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
    /// Receivers of [`Connected`] peer message
    connected_receivers: FuturesUnordered<oneshot::Receiver<Connected<T>>>,
    /// Receivers of [`Terminated`] peer message
    terminated_receivers: FuturesUnordered<oneshot::Receiver<Terminated>>,
    /// Current available connection id
    current_conn_id: ConnectionId,
    /// Current topology
    current_topology: HashSet<PeerId>,
    /// Key exchange used by network
    _key_exchange: core::marker::PhantomData<K>,
    /// Encryptor used by the network
    _encryptor: core::marker::PhantomData<E>,
}

impl<T: Pload, K: Kex, E: Enc> NetworkBase<T, K, E> {
    /// [`Self`] task.
    async fn run(mut self) {
        // TODO: probably should be configuration parameter
        let mut update_topology_interval = tokio::time::interval(Duration::from_millis(1000));
        #[allow(clippy::arithmetic_side_effects)]
        loop {
            tokio::select! {
                // Accept incoming peer connections
                accept = self.listener.accept() => {
                    match accept {
                        Ok((stream, addr)) => {
                            iroha_logger::debug!(listen_addr=%self.listen_addr, from_addr = %addr, "Accepted connection");
                            // Handle creation of new peer
                            self.accept_new_peer(stream, addr);
                        },
                        Err(error) => {
                            iroha_logger::warn!(listen_addr=%self.listen_addr, %error, "Error accepting connection");
                        }
                    }
                }
                Some(Ok(connected)) = self.connected_receivers.next() => {
                    self.peer_connected(connected);
                }
                Some(Ok(terminated)) = self.terminated_receivers.next() => {
                    self.peer_terminated(terminated);
                }
                Some(peer_message) = self.peer_message_receiver.recv() => {
                    self.peer_message(peer_message).await;
                }
                Some(update_topology) = self.update_topology_receiver.recv() => {
                    self.set_current_topology(update_topology);
                }
                Some(subscriber) = self.subscribe_to_peers_messages_receiver.recv() => {
                    self.subscribe_to_peers_messages(subscriber);
                }
                network_message = self.network_message_receiver.recv() => {
                    let Some(network_message) = network_message else {
                        iroha_logger::info!("All handles to network actor are dropped. Shutting down...");
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
                _ = update_topology_interval.tick() => {
                    self.update_topology()
                }
                else => break,
            }
            tokio::task::yield_now().await;
        }
    }

    fn accept_new_peer(&mut self, stream: TcpStream, addr: SocketAddr) {
        if self.untrusted_peers.contains(&ip(&addr.to_string())) {
            iroha_logger::warn!(%addr, "New peer is untrusted");
            return;
        }

        let conn_id = self.get_conn_id();
        let (connected_sender, connected_receiver) = oneshot::channel();
        let (terminated_sender, terminated_receiver) = oneshot::channel();
        connected_from::<T, K, E>(
            PeerId::new(&addr.to_string(), &self.public_key),
            Connection::new(conn_id, stream),
            connected_sender,
            terminated_sender,
        );

        self.connected_receivers.push(connected_receiver);
        self.terminated_receivers.push(terminated_receiver);
    }

    fn set_current_topology(&mut self, UpdateTopology(topology): UpdateTopology) {
        iroha_logger::debug!(?topology, "Network receive new topology");
        self.current_topology = topology;
        self.update_topology()
    }

    fn update_topology(&mut self) {
        let to_connect = self.current_topology
            .iter()
            // Peer is not connected but should
            .filter(|peer| !self.peers.contains_key(&peer.public_key))
            .cloned()
            .collect::<Vec<_>>();

        let to_disconnect = self.peers
            .keys()
            // Peer is connected but shouldn't
            .filter(|public_key| !self.current_topology.contains(*public_key))
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
        if self.peers.contains_key(&peer.public_key) {
            iroha_logger::debug!(peer = %peer, "Peer already connected");
            return;
        }

        iroha_logger::trace!(
            listen_addr = %self.listen_addr, peer.id.address = %peer.address,
            "Creating new peer actor",
        );
        self.untrusted_peers.remove(&ip(&peer.address));

        let conn_id = self.get_conn_id();
        let (connected_sender, connected_receiver) = oneshot::channel();
        let (terminated_sender, terminated_receiver) = oneshot::channel();
        connecting::<T, K, E>(
            // NOTE: we intentionally use peer's address and our public key, it's used during handshake
            PeerId::new(&peer.address, &self.public_key),
            conn_id,
            connected_sender,
            terminated_sender,
        );

        self.connected_receivers.push(connected_receiver);
        self.terminated_receivers.push(terminated_receiver);
    }

    fn disconnect_peer(&mut self, public_key: &PublicKey) {
        let peer = match self.peers.remove(public_key) {
            Some(peer) => peer,
            _ => return iroha_logger::warn!(?public_key, "Not found peer to disconnect"),
        };
        iroha_logger::debug!(listen_addr = %self.listen_addr, %peer.conn_id, "Disconnecting peer");
        self.untrusted_peers.insert(ip(&peer.p2p_addr));

        let peer_id = PeerId::new(&peer.p2p_addr, public_key);
        Self::remove_online_peer(&self.online_peers_sender, &peer_id);
    }

    fn peer_connected(
        &mut self,
        Connected {
            peer_id,
            connection_id,
            ready_peer_handle,
            peer_message_sender,
        }: Connected<T>,
    ) {
        if !self.current_topology.contains(&peer_id) {
            iroha_logger::warn!(peer=%peer_id, topology=?self.current_topology, "Peer not present in topology is trying to connect");
            return;
        }

        let ref_peer = RefPeer {
            handle: ready_peer_handle,
            conn_id: connection_id,
            p2p_addr: peer_id.address.clone(),
        };
        let _ = peer_message_sender.send(self.peer_message_sender.clone());
        self.peers.insert(peer_id.public_key.clone(), ref_peer);
        Self::add_online_peer(&self.online_peers_sender, peer_id);
    }

    fn peer_terminated(&mut self, Terminated { peer_id, conn_id }: Terminated) {
        if let Some(peer) = self.peers.get(&peer_id.public_key) {
            if peer.conn_id == conn_id {
                iroha_logger::debug!(conn_id, peer=%peer_id, "Peer terminated");
                self.peers.remove(&peer_id.public_key);
                Self::remove_online_peer(&self.online_peers_sender, &peer_id);
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
            None if peer_id.public_key == self.public_key => {
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
                let peer_id = PeerId::new(&ref_peer.p2p_addr, public_key);
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

/// Substitute for [`SocketAddr::ip`]
fn ip(address: &str) -> String {
    address.split(':').next().unwrap_or_default().to_owned()
}

/// Reference as a means of communication with a [`Peer`]
struct RefPeer<T: Pload> {
    handle: PeerHandle<T>,
    conn_id: ConnectionId,
    p2p_addr: String,
}
