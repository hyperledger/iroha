//! Network formed out of Iroha peers.
#![allow(clippy::std_instead_of_core)]
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    net::SocketAddr,
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
#[derive(derive_more::DebugCustom)]
#[debug(fmt = "core::any::type_name::<Self>()")]
pub struct NetworkBaseHandle<T: Pload, K: Kex, E: Enc> {
    /// Sender to subscribe for messages received form other peers in the network
    subscribe_to_peers_messages_sender: mpsc::Sender<mpsc::Sender<T>>,
    /// Receiver of `OnlinePeer` message
    online_peers_receiver: watch::Receiver<OnlinePeers>,
    /// [`ConnectPeer`] message sender
    connect_peer_sender: mpsc::Sender<ConnectPeer>,
    /// [`DisconnectPeer`] message receiver
    disconnect_peer_sender: mpsc::Sender<DisconnectPeer>,
    /// Sender of [`Post`] message
    // NOTE: it's ok for this channel to be unbounded.
    // Because post messages originates inside system and there rate is configurable.
    post_sender: unbounded_with_len::Sender<Post<T>>,
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
            connect_peer_sender: self.connect_peer_sender.clone(),
            disconnect_peer_sender: self.disconnect_peer_sender.clone(),
            post_sender: self.post_sender.clone(),
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
        let (online_peers_sender, online_peers_receiver) = watch::channel(OnlinePeers {
            online_peers: HashSet::new(),
        });
        let (subscribe_to_peers_messages_sender, subscribe_to_peers_messages_receiver) =
            mpsc::channel(1);
        let (connect_peer_sender, connect_peer_receiver) = mpsc::channel(1);
        let (disconnect_peer_sender, disconnect_peer_receiver) = mpsc::channel(1);
        let (post_sender, post_receiver) = unbounded_with_len::unbounded_channel();
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
            connect_peer_receiver,
            disconnect_peer_receiver,
            post_receiver,
            peer_message_receiver,
            peer_message_sender,
            connected_receivers: FuturesUnordered::new(),
            terminated_receivers: FuturesUnordered::new(),
            current_conn_id: 0,
            _key_exchange: core::marker::PhantomData::<K>,
            _encryptor: core::marker::PhantomData::<E>,
        };
        tokio::task::spawn(network.run());
        Ok(Self {
            subscribe_to_peers_messages_sender,
            online_peers_receiver,
            connect_peer_sender,
            disconnect_peer_sender,
            post_sender,
            _key_exchange: core::marker::PhantomData,
            _encryptor: core::marker::PhantomData,
        })
    }

    /// Subscribe to messages received from other peers in the network
    pub async fn subscribe_to_peers_messages(&self, sender: mpsc::Sender<T>) {
        self.subscribe_to_peers_messages_sender
            .send(sender)
            .await
            .expect("NetworkBase must accept messages until there is at least one handle to it")
    }

    /// Receive latest update of [`OnlinePeers`]
    pub fn online_peers(&mut self) -> OnlinePeers {
        self.online_peers_receiver.borrow_and_update().clone()
    }

    /// Send [`Post<T>`] message on network actor.
    pub fn post(&self, msg: Post<T>) {
        self.post_sender
            .send(msg)
            .map_err(|_| ())
            .expect("NetworkBase must accept messages until there is at least one handle to it")
    }

    /// Wait for update of [`OnlinePeers`].
    pub async fn wait_online_peers_update(&mut self) -> OnlinePeers {
        self.online_peers_receiver
            .changed()
            .await
            .expect("NetworkBase must accept messages until there is at least one handle to it");
        self.online_peers()
    }
}

macro_rules! impl_handle_methods {
    ($($method_name:ident ($method_name_blocking:ident) : $message_ty:ty => $handle_field:ident),+ $(,)?) => {
        impl<T: Pload, K: Kex + Sync, E: Enc + Sync> NetworkBaseHandle<T, K, E> {
            $(
                #[doc = concat!(" Send [`", stringify!($message_ty), "`] message on network actor." )]
                pub async fn $method_name(&self, msg: $message_ty) {
                    self.$handle_field
                        .send(msg)
                        .await
                        .map_err(|_| ())
                        .expect("NetworkBase must accept messages until there is at least one handle to it")
                }

                #[doc = concat!(" Send [`", stringify!($message_ty), "`] message on network actor in blocking fashion." )]
                pub fn $method_name_blocking(&self, msg: $message_ty) {
                    self.$handle_field
                        .blocking_send(msg)
                        .map_err(|_| ())
                        .expect("NetworkBase must accept messages until there is at least one handle to it")
                }
            )+
        }
    };
}

impl_handle_methods! {
    connect_peer (connect_peer_blocking): ConnectPeer => connect_peer_sender,
    disconnect_peer (disconnect_peer_blocking): DisconnectPeer => disconnect_peer_sender,
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
    subscribe_to_peers_messages_receiver: mpsc::Receiver<mpsc::Sender<T>>,
    /// Sender of `OnlinePeer` message
    online_peers_sender: watch::Sender<OnlinePeers>,
    /// [`ConnectPeer`] message receiver
    connect_peer_receiver: mpsc::Receiver<ConnectPeer>,
    /// [`DisconnectPeer`] message receiver
    disconnect_peer_receiver: mpsc::Receiver<DisconnectPeer>,
    /// Receiver of [`Post`] message
    post_receiver: unbounded_with_len::Receiver<Post<T>>,
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
    /// Key exchange used by network
    _key_exchange: core::marker::PhantomData<K>,
    /// Encryptor used by the network
    _encryptor: core::marker::PhantomData<E>,
}

impl<T: Pload, K: Kex, E: Enc> NetworkBase<T, K, E> {
    /// [`Self`] task.
    async fn run(mut self) {
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
                Some(connect_peer) = self.connect_peer_receiver.recv() => {
                    self.connect_peer(connect_peer);
                }
                Some(disconnect_peer) = self.disconnect_peer_receiver.recv() => {
                    self.disconnect_peer(disconnect_peer);
                }
                Some(subscriber) = self.subscribe_to_peers_messages_receiver.recv() => {
                    self.subscribe_to_peers_messages(subscriber);
                }
                post = self.post_receiver.recv() => {
                    let Some(post) = post else {
                        iroha_logger::info!("All handles to network actor are dropped. Shutting down...");
                        break;
                    };
                    let post_receiver_len = self.post_receiver.len();
                    if post_receiver_len > 100 {
                        iroha_logger::warn!(size=post_receiver_len, "Network post messages are pilling up in the queue");
                    }
                    self.post(post)
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

    fn connect_peer(&mut self, ConnectPeer { peer_id: peer }: ConnectPeer) {
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
            PeerId::new(&peer.address, &self.public_key),
            conn_id,
            connected_sender,
            terminated_sender,
        );

        self.connected_receivers.push(connected_receiver);
        self.terminated_receivers.push(terminated_receiver);
    }

    fn disconnect_peer(&mut self, DisconnectPeer(public_key): DisconnectPeer) {
        let peer = match self.peers.remove(&public_key) {
            Some(peer) => peer,
            _ => return iroha_logger::warn!(?public_key, "Not found peer to disconnect"),
        };
        iroha_logger::debug!(listen_addr = %self.listen_addr, %peer.conn_id, "Disconnecting peer");
        self.untrusted_peers.insert(ip(&peer.p2p_addr));

        let peer_id = PeerId::new(&peer.p2p_addr, &public_key);
        self.remove_online_peer(&peer_id);
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
        let ref_peer = RefPeer {
            handle: ready_peer_handle,
            conn_id: connection_id,
            p2p_addr: peer_id.address.clone(),
        };
        let _ = peer_message_sender.send(self.peer_message_sender.clone());
        self.peers.insert(peer_id.public_key.clone(), ref_peer);
        self.add_online_peer(peer_id);
    }

    fn peer_terminated(&mut self, Terminated { peer_id, conn_id }: Terminated) {
        if let Some(peer) = self.peers.get(&peer_id.public_key) {
            if peer.conn_id == conn_id {
                iroha_logger::debug!(conn_id, peer=%peer_id, "Peer terminated");
                self.peers.remove(&peer_id.public_key);
                self.remove_online_peer(&peer_id);
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
                    self.remove_online_peer(&peer_id);
                }
            }
            None if peer_id.public_key == self.public_key => {
                #[cfg(debug_assertions)]
                iroha_logger::trace!("Not sending message to myself")
            }
            _ => iroha_logger::warn!(peer=%peer_id, "Peer not found. Message not sent."),
        }
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

    fn add_online_peer(&mut self, peer_id: PeerId) {
        self.online_peers_sender
            .send_if_modified(|online_peers| online_peers.online_peers.insert(peer_id));
    }

    fn remove_online_peer(&mut self, peer_id: &PeerId) {
        self.online_peers_sender
            .send_if_modified(|online_peers| online_peers.online_peers.remove(peer_id));
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

    /// Message which informs `sumeragi` of the current online peers.
    ///
    /// # Rationale
    ///
    /// Because of how our translation units are set up, there cannot be
    /// interdependencies between `p2p` and the modules in core that use
    /// `p2p`. Therefore, to put incoming messages in the appropriate
    /// queues they must first be sent to `cli` and then to `core`.
    #[derive(Clone)]
    pub struct OnlinePeers {
        /// A list of [`PeerId`]s of peers currently connected to us.
        pub online_peers: HashSet<PeerId>,
    }

    /// The message that is sent to [`NetworkBase`] to start connection to
    /// some other peer.
    #[derive(Clone, Debug)]
    pub struct ConnectPeer {
        /// Socket address of the outgoing peer
        pub peer_id: PeerId,
    }

    /// The message that is sent to [`NetworkBase`] to stop connection to some other peer.
    #[derive(Clone, Debug)]
    pub struct DisconnectPeer(pub PublicKey);

    /// The message to be sent to the other [`Peer`].
    #[derive(Clone, Debug)]
    pub struct Post<T> {
        /// Data to be sent
        pub data: T,
        /// Destination peer
        pub peer_id: PeerId,
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
