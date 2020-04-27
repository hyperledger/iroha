use crate::prelude::*;
use crate::sumeragi;
use futures::lock::Mutex;
use iroha_derive::*;
use iroha_network::{prelude::*, Network};
use parity_scale_codec::{Decode, Encode};
use std::{collections::HashSet, sync::Arc, time::Duration};

type PublicKey = [u8; 32];

#[derive(Io, Decode, Encode, Debug, Clone)]
pub enum Message {
    PendingTx(TransactionRequest),
    AddPeer(PeerId),
    NewPeer(PeerId),
    RemovePeer(PeerId),
    SumeragiMessage(sumeragi::Message),
}

#[derive(Encode, Decode, PartialEq, Eq, Debug, Clone, Hash, Io)]
pub struct PeerId {
    pub address: String,
    pub public_key: PublicKey,
}

struct PeerState {
    pub peers: HashSet<PeerId>,
    pub listen_address: String,
    pub tx_queue: Arc<Mutex<crate::queue::Queue>>,
    pub sumeragi: Arc<Mutex<crate::sumeragi::Sumeragi>>,
}

pub struct Peer {
    state: State<PeerState>,
    tx_interval_sec: usize,
}

impl Peer {
    pub fn new(
        listen_address: String,
        tx_interval_sec: usize,
        trusted_peers: &[PeerId],
        tx_queue: Arc<Mutex<crate::queue::Queue>>,
        sumeragi: Arc<Mutex<crate::sumeragi::Sumeragi>>,
    ) -> Peer {
        Peer {
            state: Arc::new(Mutex::new(PeerState {
                peers: trusted_peers
                    .iter()
                    .filter(|peer_id| listen_address != peer_id.address)
                    .cloned()
                    .collect(),
                listen_address,
                tx_queue,
                sumeragi,
            })),
            tx_interval_sec,
        }
    }

    pub async fn start(&self) -> Result<(), String> {
        loop {
            async_std::task::sleep(Duration::from_secs(self.tx_interval_sec as u64)).await;
            let peers: Vec<PeerId> = self.state.lock().await.peers.clone().into_iter().collect();
            for tx in self
                .state
                .lock()
                .await
                .tx_queue
                .lock()
                .await
                .get_pending_transactions()
            {
                Self::send_to_peers(Message::PendingTx(TransactionRequest::from(tx)), &peers)
                    .await?;
            }
        }
    }

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
        Network::send_request_to(
            peer_id.address.as_ref(),
            Request::new("/blocks".to_string(), message.into()),
        )
        .await?;
        self.start().await?;
        Ok(())
    }

    pub async fn send_to_peers(message: Message, peers: &[PeerId]) -> Result<(), String> {
        let mut send_futures = Vec::new();
        for peer_id in peers {
            let peer_id = peer_id.clone();
            let message = message.clone();
            send_futures.push(async move {
                let _response = Network::send_request_to(
                    peer_id.address.as_ref(),
                    Request::new("/blocks".to_string(), message.into()),
                )
                .await;
            });
        }
        let _results = futures::future::join_all(send_futures).await;
        Ok(())
    }

    pub async fn handle_message(&self, message: Message) -> Result<(), String> {
        match message {
            Message::PendingTx(_tx) => {
                //TODO: handle incoming pending tx
            }
            Message::NewPeer(new_peer_id) => {
                //TODO: use transactions to add a new peer and verify on connection in swarm
                //tell node about other peers
                let mut send_futures = Vec::new();
                for peer_id in self.state.lock().await.peers.clone() {
                    let message = Message::AddPeer(new_peer_id.clone());
                    let peer_id = peer_id.clone();
                    send_futures.push(async move {
                        let _response = Network::send_request_to(
                            peer_id.address.as_ref(),
                            Request::new("/blocks".to_string(), message.into()),
                        )
                        .await;
                    });
                }
                let _results = futures::future::join_all(send_futures).await;
                //tell other peers about the new node
                let peers: Vec<PeerId> =
                    self.state.lock().await.peers.clone().into_iter().collect();
                Self::send_to_peers(Message::AddPeer(new_peer_id.clone()), &peers).await?;
                //remember new node
                self.state.lock().await.peers.insert(new_peer_id);
            }
            Message::AddPeer(peer_id) => {
                self.state.lock().await.peers.insert(peer_id);
            }
            Message::RemovePeer(peer_id) => {
                self.state.lock().await.peers.remove(&peer_id);
            }
            Message::SumeragiMessage(message) => {
                let _result = self
                    .state
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

pub mod isi {
    use super::*;

    /// The purpose of add peer command is to write into ledger the fact of peer addition into the
    /// peer network. After a transaction with AddPeer has been committed, consensus and
    /// synchronization components will start using it.
    #[derive(Clone, Debug, PartialEq, Io, IntoContract, Encode, Decode)]
    pub struct AddPeer {
        pub peer_id: PeerId,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, queue::Queue, sumeragi::Sumeragi};
    use async_std::task;
    use std::time::Duration;

    #[async_std::test]
    async fn start_peer_should_not_panic() {
        let queue = Arc::new(Mutex::new(Queue::default()));
        let (public_key, private_key) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        let sumeragi = Arc::new(Mutex::new(
            Sumeragi::new(
                public_key,
                private_key,
                &vec![PeerId {
                    address: "127.0.0.1:7878".to_string(),
                    public_key: public_key,
                }],
                None,
                0,
            )
            .expect("Failed to initialize Sumeragi."),
        ));
        let peer = Arc::new(Peer::new(
            "127.0.0.1:7878".to_string(),
            15,
            &Vec::new(),
            queue,
            sumeragi,
        ));
        let peer_move = peer.clone();
        task::spawn(async move {
            peer_move.start().await.expect("Failed to start peer.");
        });
        std::thread::sleep(Duration::from_millis(50));
    }

    #[async_std::test]
    async fn connect_three_peers() {
        let (public_key, private_key) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        let (public_key1, private_key1) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        let (public_key2, private_key2) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        let peer_ids = vec![
            PeerId {
                address: "127.0.0.1:7878".to_string(),
                public_key,
            },
            PeerId {
                address: "127.0.0.1:7879".to_string(),
                public_key: public_key1,
            },
            PeerId {
                address: "127.0.0.1:7880".to_string(),
                public_key: public_key2,
            },
        ];
        let queue = Arc::new(Mutex::new(Queue::default()));
        let sumeragi = Arc::new(Mutex::new(
            Sumeragi::new(
                public_key,
                private_key,
                &vec![PeerId {
                    address: "127.0.0.1:7878".to_string(),
                    public_key: public_key,
                }],
                None,
                0,
            )
            .expect("Failed to initialize Sumeragi."),
        ));
        let lead_peer = Arc::new(Peer::new(
            "127.0.0.1:7878".to_string(),
            15,
            &peer_ids,
            queue,
            sumeragi,
        ));
        let peer_move = lead_peer.clone();
        task::spawn(async move {
            peer_move.start().await.expect("Failed to start peer.");
        });
        std::thread::sleep(Duration::from_millis(50));
        let queue = Arc::new(Mutex::new(Queue::default()));
        let sumeragi = Arc::new(Mutex::new(
            Sumeragi::new(
                public_key1,
                private_key1,
                &vec![PeerId {
                    address: "127.0.0.1:7879".to_string(),
                    public_key: public_key1,
                }],
                None,
                0,
            )
            .expect("Failed to initialize Sumeragi."),
        ));
        let peer1 = Arc::new(Peer::new(
            "127.0.0.1:7879".to_string(),
            15,
            &peer_ids,
            queue,
            sumeragi,
        ));
        let peer_move = peer1.clone();
        task::spawn(async move {
            peer_move.start().await.expect("Failed to start peer.");
        });
        std::thread::sleep(Duration::from_millis(50));
        let queue = Arc::new(Mutex::new(Queue::default()));
        let sumeragi = Arc::new(Mutex::new(
            Sumeragi::new(
                public_key2,
                private_key2,
                &vec![PeerId {
                    address: "127.0.0.1:7880".to_string(),
                    public_key: public_key2,
                }],
                None,
                0,
            )
            .expect("Failed to initialize Sumeragi."),
        ));
        let peer2 = Arc::new(Peer::new(
            "127.0.0.1:7880".to_string(),
            15,
            &peer_ids,
            queue,
            sumeragi,
        ));
        let peer_move = peer2.clone();
        task::spawn(async move {
            peer_move.start().await.expect("Failed to start peer.");
        });
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(peer1.state.lock().await.peers.len(), 2);
    }
}
