use crate::prelude::*;
use crate::sumeragi;
use futures::{future::FutureExt, lock::Mutex, pin_mut, select};
use iroha_derive::*;
use iroha_network::{prelude::*, Network};
use parity_scale_codec::{Decode, Encode};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    sync::Arc,
    time::{Duration, SystemTime},
};

type PublicKey = [u8; 32];

pub mod isi {
    use super::*;
    use iroha_derive::{IntoContract, Io};

    /// The purpose of add peer command is to write into ledger the fact of peer addition into the
    /// peer network. After a transaction with AddPeer has been committed, consensus and
    /// synchronization components will start using it.
    #[derive(Clone, Debug, PartialEq, Io, IntoContract, Encode, Decode)]
    pub struct AddPeer {
        pub peer_id: PeerId,
    }
}

const PING_SIZE: usize = 32;

#[derive(Io, Decode, Encode, Debug, Clone)]
pub enum Message {
    Ping(Ping),
    Pong(Ping),
    PendingTx(TransactionRequest),
    AddPeer(PeerId),
    NewPeer(PeerId),
    RemovePeer(PeerId),
    SumeragiMessage(sumeragi::Message),
}

#[derive(Encode, Decode, PartialEq, Eq, Debug, Clone, Hash)]
pub struct Ping {
    payload: Vec<u8>,
    to_peer: PeerId,
    from_peer: PeerId,
}

impl Ping {
    pub fn new(to_peer: PeerId, from_peer: PeerId) -> Ping {
        Ping {
            payload: [0u8; PING_SIZE].to_vec(),
            to_peer,
            from_peer,
        }
    }
}

#[derive(Encode, Decode, PartialEq, Eq, Debug, Clone, Hash, Io)]
pub struct PeerId {
    pub address: String,
    pub public_key: PublicKey,
}

struct PeerState {
    pub peers: HashSet<PeerId>,
    pub sent_pings: HashMap<Ping, Duration>,
    pub listen_address: String,
    pub tx_queue: Arc<Mutex<crate::queue::Queue>>,
    pub sumeragi: Arc<Mutex<crate::sumeragi::Sumeragi>>,
}

pub struct Peer {
    state: State<PeerState>,
    ping_interval_sec: usize,
    tx_interval_sec: usize,
}

impl Peer {
    pub fn new(
        listen_address: String,
        tx_interval_sec: usize,
        ping_interval_sec: usize,
        tx_queue: Arc<Mutex<crate::queue::Queue>>,
        sumeragi: Arc<Mutex<crate::sumeragi::Sumeragi>>,
    ) -> Peer {
        Peer {
            state: Arc::new(Mutex::new(PeerState {
                peers: HashSet::new(),
                sent_pings: HashMap::new(),
                listen_address,
                tx_queue,
                sumeragi,
            })),
            ping_interval_sec,
            tx_interval_sec,
        }
    }

    pub async fn start(&self) -> Result<(), String> {
        let listen_future = self.listen_and_reconnect().fuse();
        let tx_future = self.start_broadcasting_tx().fuse();
        let ping_future = self.start_ping().fuse();
        pin_mut!(listen_future, tx_future, ping_future);
        select! {
                listen = listen_future => unreachable!(),
                ping = ping_future => ping?,
                tx = tx_future => tx?,
        }
        Ok(())
    }

    pub async fn start_broadcasting_tx(&self) -> Result<(), String> {
        loop {
            async_std::task::sleep(Duration::from_secs(self.tx_interval_sec as u64)).await;
            Self::broadcast_tx(self.state.clone()).await?;
        }
    }

    pub async fn start_ping(&self) -> Result<(), String> {
        loop {
            async_std::task::sleep(Duration::from_secs(self.ping_interval_sec as u64)).await;
            Self::ping_all(self.state.clone()).await?;
        }
    }

    fn current_time() -> Duration {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to get duration since UNIX_EPOCH.")
    }

    async fn broadcast_tx(state: State<PeerState>) -> Result<(), String> {
        for tx in state
            .lock()
            .await
            .tx_queue
            .lock()
            .await
            .get_pending_transactions()
        {
            Self::broadcast(
                state.clone(),
                Message::PendingTx(TransactionRequest::from(tx)),
            )
            .await?;
        }
        Ok(())
    }

    async fn listen_and_reconnect(&self) {
        loop {
            if self.listen().await.is_ok() {
                unreachable!()
            }
        }
    }

    async fn listen(&self) -> Result<(), String> {
        async fn handle_request(
            state: State<PeerState>,
            request: Request,
        ) -> Result<Response, String> {
            Peer::handle_message(state, request.payload()).await?;
            Ok(Response::new())
        };

        async fn handle_connection(
            state: State<PeerState>,
            stream: Box<dyn AsyncStream>,
        ) -> Result<(), String> {
            Network::handle_message_async(state, stream, handle_request).await
        };

        let listen_address = self.state.lock().await.listen_address.clone();
        Network::listen(
            self.state.clone(),
            listen_address.as_ref(),
            handle_connection,
        )
        .await
    }

    #[allow(unused)]
    pub async fn start_and_connect(&self, peer_address: &str) -> Result<(), String> {
        let peer_id = PeerId {
            address: peer_address.to_string(),
            public_key: [0u8; 32],
        };
        self.state.lock().await.peers.insert(peer_id.clone());
        let message = Message::NewPeer(PeerId {
            address: self.state.lock().await.listen_address.clone(),
            public_key: [0u8; 32],
        });
        Self::send(message, peer_id).await?;
        self.start().await?;
        Ok(())
    }

    pub async fn send(message: Message, peer_id: PeerId) -> Result<(), String> {
        let _response = Network::send_request_to(
            peer_id.address.as_ref(),
            Request::new("/".to_string(), message.into()),
        )
        .await?;
        Ok(())
    }

    pub async fn send_to_peers(message: Message, peers: &[PeerId]) -> Result<(), String> {
        let mut send_futures = Vec::new();
        for peer_id in peers {
            send_futures.push(Self::send(message.clone(), peer_id.clone()));
        }
        let _results = futures::future::join_all(send_futures).await;
        Ok(())
    }

    async fn broadcast(state: State<PeerState>, message: Message) -> Result<(), String> {
        let peers: Vec<PeerId> = state.lock().await.peers.clone().into_iter().collect();
        Self::send_to_peers(message, &peers).await
    }

    async fn ping(state: State<PeerState>, peer_id: PeerId) -> Result<(), String> {
        let ping = Ping::new(
            peer_id.clone(),
            PeerId {
                address: state.lock().await.listen_address.clone(),
                public_key: [0u8; 32],
            },
        );
        state
            .lock()
            .await
            .sent_pings
            .insert(ping.clone(), Peer::current_time());
        Self::send(Message::Ping(ping), peer_id.clone()).await
    }

    async fn ping_all(state: State<PeerState>) -> Result<(), String> {
        for peer_id in state.lock().await.peers.clone() {
            Self::ping(state.clone(), peer_id).await?;
        }
        Ok(())
    }

    async fn handle_message(state: State<PeerState>, bytes: &[u8]) -> Result<(), String> {
        let message: Message = bytes.to_vec().try_into()?;
        match message {
            Message::Ping(ping) => {
                Self::send(Message::Pong(ping.clone()), ping.from_peer).await?;
            }
            Message::Pong(ping) => {
                let sent_pings = &mut state.lock().await.sent_pings;
                if sent_pings.contains_key(&ping) {
                    let sent_time = sent_pings
                        .get(&ping)
                        .expect("Failed to get sent ping entry.");
                    let _rtt = Peer::current_time() - sent_time.to_owned();
                    sent_pings.remove(&ping);
                }
            }
            Message::PendingTx(_tx) => {
                //TODO: handle incoming pending tx
            }
            Message::NewPeer(new_peer_id) => {
                //TODO: use transactions to add a new peer and verify on connection in swarm
                //tell node about other peers
                let mut send_futures = Vec::new();
                for peer_id in state.lock().await.peers.clone() {
                    send_futures.push(Self::send(
                        Message::AddPeer(new_peer_id.clone()),
                        peer_id.clone(),
                    ));
                }
                let _results = futures::future::join_all(send_futures).await;
                //tell other peers about the new node
                Self::broadcast(state.clone(), Message::AddPeer(new_peer_id.clone())).await?;
                //remember new node
                state.lock().await.peers.insert(new_peer_id);
            }
            Message::AddPeer(peer_id) => {
                state.lock().await.peers.insert(peer_id);
            }
            Message::RemovePeer(peer_id) => {
                state.lock().await.peers.remove(&peer_id);
            }
            Message::SumeragiMessage(message) => {
                let _result = state
                    .lock()
                    .await
                    .sumeragi
                    .lock()
                    .await
                    .handle_message(message)
                    .await;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start_peer(listen_address: &str, connect_to: Option<String>) -> Arc<Peer> {
        use async_std::task;
        let queue = Arc::new(Mutex::new(crate::queue::Queue::default()));
        let sumeragi = Arc::new(Mutex::new(
            crate::sumeragi::Sumeragi::new(
                &vec![PeerId {
                    address: "127.0.0.1:7878".to_string(),
                    public_key: [0u8; 32],
                }],
                None,
                0,
            )
            .expect("Failed to initialize Sumeragi."),
        ));
        let peer = Arc::new(Peer::new(
            listen_address.to_string(),
            10,
            15,
            queue,
            sumeragi,
        ));
        let peer_move = peer.clone();
        task::spawn(async move {
            let _result = match connect_to {
                None => peer_move.start().await,
                Some(connect_to_addr) => {
                    peer_move.start_and_connect(connect_to_addr.as_ref()).await
                }
            };
        });
        peer
    }

    #[async_std::test]
    async fn connect_three_peers() {
        let _peer0 = start_peer("127.0.0.1:7878", None);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let peer1 = start_peer("127.0.0.1:7879", Some("127.0.0.1:7878".to_string()));
        std::thread::sleep(std::time::Duration::from_millis(50));
        let _peer2 = start_peer("127.0.0.1:7880", Some("127.0.0.1:7878".to_string()));
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(peer1.state.lock().await.peers.len(), 2);
    }
}
