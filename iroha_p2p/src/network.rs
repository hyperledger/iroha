use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{Debug, Formatter},
    io,
};

use async_stream::stream;
use futures::Stream;
use iroha_actor::{broker::Broker, Actor, Addr, Context, ContextHandler, Handler};
use iroha_crypto::PublicKey;
#[allow(unused_imports)]
use iroha_logger::{debug, info, warn};
use parity_scale_codec::{Decode, Encode};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{
        oneshot,
        oneshot::{Receiver, Sender},
    },
};
use ursa::{encryption::symm::Encryptor, kex::KeyExchangeScheme};

use crate::{
    peer::{FromPeer, Peer, ToPeer},
    Connect, Connected, Disconnect, Error, GetConnected, PeerId, Post, Received, Stop,
};

#[derive(iroha_actor::Message)]
pub(crate) struct Connection<T, K, E: Encryptor> {
    pub addr: Addr<Peer<T, K, E>>,
    /// Did we initiated connection?
    pub outgoing: bool,
}

/// Main network layer structure, that is holding connections, called [`Peer`]s.
pub struct NetworkBase<T, K, E: Encryptor> {
    /// Listening to this address for incoming connections. Must parse into [`SocketAddr`].
    listen_addr: String,
    /// Current peers in connected state
    peers: HashMap<PublicKey, Connection<T, K, E>>,
    /// `TcpListener` that is accepting peers' connections
    pub listener: Option<TcpListener>,
    /// Our app-level public key
    public_key: PublicKey,
    /// Broker doing internal communication
    pub broker: Broker,
    /// A flag that stops listening stream
    finish_sender: Option<Sender<()>>,
}

impl<T, K, E> NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
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
        info!("Binding listener to {}...", &listen_addr);
        let listener = TcpListener::bind(&listen_addr).await?;
        Ok(Self {
            listen_addr,
            peers: HashMap::new(),
            listener: Some(listener),
            public_key,
            broker,
            finish_sender: None,
        })
    }

    /// Yields a stream of accepted peer connections.
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
                                info!("[{}] Accepted connection from {}", &listen_addr, &addr);
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
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
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
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        info!("Starting network actor on {}...", &self.listen_addr);

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
impl<T, K, E> ContextHandler<Connect> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, ctx: &mut Context<Self>, Connect { mut id }: Connect) {
        info!(addr = %self.listen_addr, ?id, "Creating new peer actor");

        id.public_key = self.public_key.clone();
        dbg!(&id, "To");
        match FromPeer::new(id, ctx.addr()) {
            Ok(peer) => peer.start().await,
            Err(e) => {
                warn!(%e, "Unable to create peer");
                return;
            }
        };
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<Post<T>> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, msg: Post<T>) {
        match self.peers.get(&msg.id.public_key) {
            Some(conn) => conn.addr.do_send(msg).await,
            None if msg.id.public_key == self.public_key => debug!("Not sending message to myself"),
            None => info!(
                "Didn't find peer to send message, have only {} connections!",
                self.peers.len()
            ),
        }
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<GotConnected<T, K, E>> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, GotConnected { id, conn }: GotConnected<T, K, E>) {
        debug!(?id, "Connected");
        let addr = &self.listen_addr;
        match self.peers.entry(id.public_key.clone()) {
            Entry::Occupied(mut entry) => {
                warn!(?addr, ?id, "Twin connection");
                warn!(
                    ?addr,
                    out = conn.outgoing,
                    keys = self.public_key > id.public_key
                );

                // If we initiated connection and our public key is bigger, then keep new connection
                let addr = match (conn.outgoing, self.public_key > id.public_key) {
                    (true, true) | (false, false) => {
                        iroha_logger::warn!(?addr, "Inserted");
                        let old = entry.insert(conn);
                        iroha_logger::warn!(?addr, old.outgoing);
                        old.addr
                    }
                    _ => conn.addr,
                };
                addr.do_send(Stop).await;
            }
            Entry::Vacant(entry) => {
                let outgoing = conn.outgoing;

                entry.insert(conn);

                info!(n_peers = self.peers.len(), addr = ?self.listen_addr, outgoing, "Connected new peer");
            }
        };
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<Disconnected> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, Disconnected { id, outgoing }: Disconnected) {
        iroha_logger::warn!(
            "Disconnect {:?}",
            (
                &id,
                outgoing,
                self.peers.get(&id.public_key).unwrap().outgoing
            )
        );
        match self.peers.entry(id.public_key) {
            Entry::Occupied(entry) if entry.get().outgoing == outgoing => drop(entry.remove()),
            _ => (),
        }
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<Received<T>> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, msg: Received<T>) {
        self.broker.issue_send(msg).await;
    }
}

#[async_trait::async_trait]
impl<T, K, E> ContextHandler<Stop> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, ctx: &mut Context<Self>, Stop: Stop) {
        let futures = self
            .peers
            .values()
            .map(|conn| conn.addr.do_send(Stop))
            .collect::<Vec<_>>();
        futures::future::join_all(futures).await;
        ctx.stop_now();
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<GetConnected> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = Connected;

    async fn handle(&mut self, GetConnected: GetConnected) -> Self::Result {
        //info!("[{}] Peers: {}, new: {}", &self.listen_addr, self.peers.len(), self.new_peers.len());
        let peers = self.peers.keys().cloned().into_iter().collect();
        Connected { peers }
    }
}

#[async_trait::async_trait]
impl<T, K, E> ContextHandler<NewPeer> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, ctx: &mut Context<Self>, NewPeer(peer): NewPeer) {
        let (stream, id) = match peer {
            Ok(peer) => peer,
            Err(error) => {
                warn!(%error, "Error in listener!");
                return;
            }
        };

        dbg!(&id, "From");
        match ToPeer::new(id.clone(), stream, ctx.addr()) {
            Ok(peer) => drop(peer.start().await),
            Err(e) => warn!(%e, "Unable to create peer"),
        }
    }
}

#[async_trait::async_trait]
impl<T, K, E> Handler<Disconnect> for NetworkBase<T, K, E>
where
    T: Debug + Encode + Decode + Send + Sync + Clone + 'static,
    K: KeyExchangeScheme + Send + 'static,
    E: Encryptor + Send + 'static,
{
    type Result = ();

    async fn handle(&mut self, Disconnect(id): Disconnect) {
        if let Entry::Occupied(entry) = self.peers.entry(id.public_key) {
            entry.get().addr.do_send(Stop).await;
            entry.remove_entry();
        }
    }
}

/// The message received from peer that it connected
#[derive(iroha_actor::Message, Decode)]
pub(crate) struct GotConnected<T, K, E: Encryptor> {
    pub id: PeerId,
    pub conn: Connection<T, K, E>,
}

/// The message received from peer that it disconnected
#[derive(Clone, Debug, iroha_actor::Message, Decode)]
pub(crate) struct Disconnected {
    pub id: PeerId,
    pub outgoing: bool,
}

/// The result of some incoming peer connection.
#[derive(Debug, iroha_actor::Message)]
pub(crate) struct NewPeer(pub io::Result<(TcpStream, PeerId)>);
