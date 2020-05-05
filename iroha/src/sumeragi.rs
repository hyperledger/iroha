use crate::{block::Block, crypto::Hash, kura::Kura, peer::PeerId, prelude::*, torii::uri};
use futures::lock::Mutex;
use iroha_derive::*;
use iroha_network::{Network, Request};
use parity_scale_codec::{Decode, Encode};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::{
    fmt::{self, Debug, Formatter},
    sync::Arc,
};

pub struct Sumeragi {
    public_key: PublicKey,
    private_key: PrivateKey,
    sorted_peers: Vec<PeerId>,
    max_faults: usize,
    peer_id: PeerId,
    /// Block in discussion this round
    pending_block: Option<Block>,
    kura: Arc<Mutex<Kura>>,
    wsv: Arc<Mutex<WorldStateView>>,
    network: Arc<Mutex<Network>>,
}

impl Debug for Sumeragi {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sumeragi")
            .field("public_key", &self.public_key)
            .field("sorted_peers", &self.sorted_peers)
            .field("max_faults", &self.max_faults)
            .field("peer_id", &self.peer_id)
            .field("pending_block", &self.pending_block)
            .finish()
    }
}

#[derive(Io, Decode, Encode, Debug, Clone)]
pub enum Message {
    /// Is sent by leader to all validating peers, when a new block is created.
    Created(Block),
    /// Is sent by validating peers to proxy tail and observing peers when they have signed this block.
    Signed(Block),
    /// Is sent by proxy tail to validating peers and to leader, when the block is committed.
    Committed(Block),
}

#[derive(Eq, PartialEq, Debug)]
pub enum Role {
    Leader,
    ValidatingPeer,
    ObservingPeer,
    ProxyTail,
}

impl Sumeragi {
    pub fn new(
        private_key: PrivateKey,
        peers: &[PeerId],
        peer_id: PeerId,
        max_faults: usize,
        kura: Arc<Mutex<Kura>>,
        wsv: Arc<Mutex<WorldStateView>>,
        network: Arc<Mutex<Network>>,
    ) -> Self {
        Self {
            public_key: peer_id.public_key,
            private_key,
            sorted_peers: peers.to_vec(),
            max_faults,
            peer_id,
            pending_block: None,
            kura,
            wsv,
            network,
        }
    }

    pub fn init(&mut self) -> Result<(), String> {
        if !self.sorted_peers.contains(&self.peer_id) {
            return Err("Peers list should contain this peer.".to_string());
        }
        let min_peers = 3 * self.max_faults + 1;
        if self.sorted_peers.len() >= min_peers {
            //TODO: get previous block hash from kura
            Self::sort_peers(&mut self.sorted_peers, None);
            Ok(())
        } else {
            Err(format!("Not enough peers to be Byzantine fault tolerant. Expected a least {} peers, got {}", 3 * self.max_faults + 1, self.sorted_peers.len()))
        }
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn has_pending_block(&self) -> bool {
        self.pending_block.is_some()
    }

    #[log]
    pub fn next_round(&mut self, prev_block_hash: Hash) {
        Self::sort_peers(&mut self.sorted_peers, Some(prev_block_hash));
        self.pending_block = None;
    }

    #[log]
    pub fn peers_set_a(&self) -> &[PeerId] {
        let n_a_peers = 2 * self.max_faults + 1;
        &self.sorted_peers[..n_a_peers]
    }

    #[log]
    pub fn peers_set_b(&self) -> &[PeerId] {
        &self.sorted_peers[(2 * self.max_faults + 1)..]
    }

    #[log]
    pub fn leader(&self) -> &PeerId {
        self.peers_set_a()
            .first()
            .expect("Failed to get first peer.")
    }

    #[log]
    pub fn proxy_tail(&self) -> &PeerId {
        self.peers_set_a().last().expect("Failed to get last peer.")
    }

    #[log]
    pub fn validating_peers(&self) -> &[PeerId] {
        let a_set = self.peers_set_a();
        if a_set.len() > 1 {
            &a_set[1..(a_set.len() - 1)]
        } else {
            &[]
        }
    }

    #[log]
    pub fn role(&self) -> Role {
        if *self.leader() == self.peer_id {
            Role::Leader
        } else if *self.proxy_tail() == self.peer_id {
            Role::ProxyTail
        } else if self.validating_peers().contains(&self.peer_id) {
            Role::ValidatingPeer
        } else {
            Role::ObservingPeer
        }
    }

    #[log]
    pub fn validate_access(&self, allowed_roles: &[Role]) -> Result<(), String> {
        if allowed_roles.contains(&self.role()) {
            Ok(())
        } else {
            Err(format!(
                "Peer needs to be one of {:?} for this operation.",
                allowed_roles
            ))
        }
    }

    #[log]
    pub fn sort_peers(peers: &mut Vec<PeerId>, block_hash: Option<Hash>) {
        peers.sort_by(|p1, p2| p1.address.cmp(&p2.address));
        if let Some(block_hash) = block_hash {
            let mut rng = StdRng::from_seed(block_hash);
            peers.shuffle(&mut rng);
        }
    }

    #[log]
    pub fn sign_block(&self, block: Block) -> Result<Block, String> {
        self.validate_access(&[Role::Leader, Role::ProxyTail, Role::ValidatingPeer])?;
        Ok(block.sign(&self.public_key, &self.private_key)?)
    }

    #[log]
    pub async fn validate_and_store(
        &mut self,
        transactions: Vec<Transaction>,
    ) -> Result<(), String> {
        let block = self.build_block(transactions).await?;
        let minimum_quorum_of_peers = 2;
        if self.sorted_peers.len() < minimum_quorum_of_peers {
            //If there is only one peer running skip consensus part
            let _hash = self.store(block).await?;
        } else {
            self.pending_block = Some(block.clone());
            self.on_block_created(block).await?;
        }
        Ok(())
    }

    #[log]
    pub async fn on_block_created(&self, block: Block) -> Result<(), String> {
        self.validate_access(&[Role::Leader])?;
        let block = self.sign_block(block)?;
        let mut send_futures = Vec::new();
        for peer in self.validating_peers() {
            send_futures.push(self.send_message_to(Message::Created(block.clone()), peer));
        }
        send_futures.push(self.send_message_to(Message::Created(block.clone()), self.proxy_tail()));
        let _results = futures::future::join_all(send_futures).await;
        Ok(())
    }

    #[log]
    pub async fn handle_message(&mut self, message: Message) -> Result<(), String> {
        //TODO: check that the messages come from the right peers (check roles, keys)
        match message {
            Message::Created(block) => match self.role() {
                Role::ValidatingPeer => {
                    let block = self.sign_block(block)?;
                    let _result = self
                        .send_message_to(Message::Signed(block), self.proxy_tail())
                        .await;
                    //TODO: send to set b so they can observe
                }
                Role::ProxyTail => {
                    if self.pending_block.is_none() {
                        self.pending_block = Some(block)
                    }
                }
                _ => (),
            },
            Message::Signed(block) => {
                if let Role::ProxyTail = self.role() {
                    match self.pending_block.as_mut() {
                        Some(pending_block) => {
                            // TODO: verify signatures
                            for signature in block.signatures {
                                if !pending_block.signatures.contains(&signature) {
                                    pending_block.signatures.push(signature)
                                }
                            }
                        }
                        None => self.pending_block = Some(block),
                    };
                    if let Some(block) = self.pending_block.clone() {
                        if block.signatures.len() >= 2 * self.max_faults {
                            let block = self.sign_block(block)?;
                            let hash = self.store(block.clone()).await?;
                            let mut send_futures = Vec::new();
                            for peer in self.validating_peers() {
                                send_futures.push(
                                    self.send_message_to(Message::Committed(block.clone()), peer),
                                );
                            }
                            for peer in self.peers_set_b() {
                                send_futures.push(
                                    self.send_message_to(Message::Committed(block.clone()), peer),
                                );
                            }
                            send_futures.push(
                                self.send_message_to(
                                    Message::Committed(block.clone()),
                                    self.leader(),
                                ),
                            );
                            let _results = futures::future::join_all(send_futures).await;
                            self.next_round(hash);
                        }
                    }
                }
            }
            Message::Committed(block) => {
                //TODO: check if the block is the same as pending
                let hash = self.store(block).await?;
                self.next_round(hash);
            }
        }
        Ok(())
    }

    pub async fn sign_transactions(
        &self,
        transactions: Vec<Transaction>,
    ) -> Result<Vec<Transaction>, String> {
        Ok(transactions
            .into_iter()
            .map(|tx| tx.sign(Vec::new()))
            .filter_map(Result::ok)
            .collect())
    }

    async fn build_block(&self, transactions: Vec<Transaction>) -> Result<Block, String> {
        let transactions = self.sign_transactions(transactions).await?;
        Ok(Block::builder(transactions)
            .validate_tx(&*self.wsv.lock().await)
            .build())
    }

    async fn store(&self, block: Block) -> Result<Hash, String> {
        self.kura.lock().await.store(block).await
    }

    async fn send_message_to(&self, message: Message, peer: &PeerId) -> Result<(), String> {
        let _response = self
            .network
            .lock()
            .await
            .send_request_to(
                &peer.address,
                Request::new(uri::BLOCKS_URI.to_string(), message.into()),
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use futures::channel::mpsc;

    #[test]
    #[should_panic]
    fn not_enough_peers() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::unbounded();
        let kura = Arc::new(Mutex::new(Kura::new("strict".to_string(), dir.path(), tx)));
        let (public_key, private_key) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        let listen_address = "127.0.0.1".to_string();
        let this_peer = PeerId {
            address: listen_address.clone(),
            public_key,
        };
        let wsv = Arc::new(Mutex::new(WorldStateView::new(Peer::new(
            listen_address,
            &[],
        ))));
        let network = Arc::new(Mutex::new(Network::new("127.0.0.1:8080")));
        let mut sumeragi = Sumeragi::new(
            private_key,
            &[this_peer.clone()],
            this_peer,
            3,
            kura,
            wsv,
            network,
        );
        sumeragi.init().unwrap();
    }

    #[test]
    fn different_order() {
        let mut peers1 = vec![
            PeerId {
                address: "127.0.0.1:7878".to_string(),
                public_key: [1u8; 32],
            },
            PeerId {
                address: "127.0.0.1:7879".to_string(),
                public_key: [2u8; 32],
            },
            PeerId {
                address: "127.0.0.1:7880".to_string(),
                public_key: [3u8; 32],
            },
        ];
        Sumeragi::sort_peers(&mut peers1, Some([1u8; 32]));
        let mut peers2 = peers1.clone();
        Sumeragi::sort_peers(&mut peers2, Some([2u8; 32]));
        assert_ne!(peers1, peers2);
    }

    #[test]
    fn same_order() {
        let mut peers1 = vec![
            PeerId {
                address: "127.0.0.1:7878".to_string(),
                public_key: [1u8; 32],
            },
            PeerId {
                address: "127.0.0.1:7879".to_string(),
                public_key: [2u8; 32],
            },
            PeerId {
                address: "127.0.0.1:7880".to_string(),
                public_key: [3u8; 32],
            },
        ];
        Sumeragi::sort_peers(&mut peers1, Some([1u8; 32]));
        let mut peers2 = peers1.clone();
        Sumeragi::sort_peers(&mut peers2, Some([1u8; 32]));
        assert_eq!(peers1, peers2);
    }
}
