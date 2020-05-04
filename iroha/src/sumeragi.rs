use crate::{block::Block, crypto::Hash, kura::Storage, peer::PeerId, prelude::*, torii::uri};
use futures::lock::Mutex;
use iroha_derive::*;
use iroha_network::prelude::*;
use parity_scale_codec::{Decode, Encode};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::sync::Arc;

pub struct Sumeragi<N: Network, S: Storage> {
    public_key: PublicKey,
    private_key: PrivateKey,
    sorted_peers: Vec<PeerId>,
    max_faults: usize,
    peer_id: PeerId,
    /// Block in discussion this round
    pending_block: Option<Block>,
    storage: Arc<Mutex<S>>,
    _network: N,
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

impl<N: Network, S: Storage> Sumeragi<N, S> {
    pub fn new(
        public_key: PublicKey,
        private_key: PrivateKey,
        peers: &[PeerId],
        peer_id: PeerId,
        max_faults: usize,
        storage: Arc<Mutex<S>>,
        network: N,
    ) -> Result<Self, String> {
        if !peers.contains(&peer_id) {
            return Err("Peers list should contain this peer.".to_string());
        }
        let min_peers = 3 * max_faults + 1;
        if peers.len() >= min_peers {
            let mut sorted_peers = peers.to_vec();
            //TODO: get previous block hash from kura
            Self::sort_peers(&mut sorted_peers, None);
            Ok(Self {
                public_key,
                private_key,
                sorted_peers,
                max_faults,
                //TODO: generate peer's public key, save on shutdown and load on start
                peer_id,
                pending_block: None,
                storage,
                _network: network,
            })
        } else {
            Err(format!("Not enough peers to be Byzantine fault tolerant. Expected a least {} peers, got {}", 3 * max_faults + 1, peers.len()))
        }
    }

    pub fn has_pending_block(&self) -> bool {
        self.pending_block.is_some()
    }

    pub fn next_round(&mut self, prev_block_hash: Hash) {
        Self::sort_peers(&mut self.sorted_peers, Some(prev_block_hash));
        self.pending_block = None;
    }

    pub fn peers_set_a(&self) -> &[PeerId] {
        let n_a_peers = 2 * self.max_faults + 1;
        &self.sorted_peers[..n_a_peers]
    }

    pub fn peers_set_b(&self) -> &[PeerId] {
        &self.sorted_peers[(2 * self.max_faults + 1)..]
    }

    pub fn leader(&self) -> &PeerId {
        self.peers_set_a()
            .first()
            .expect("Failed to get first peer.")
    }

    pub fn proxy_tail(&self) -> &PeerId {
        self.peers_set_a().last().expect("Failed to get last peer.")
    }

    pub fn validating_peers(&self) -> &[PeerId] {
        let a_set = self.peers_set_a();
        if a_set.len() > 1 {
            &a_set[1..(a_set.len() - 1)]
        } else {
            &[]
        }
    }

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

    pub fn sort_peers(peers: &mut Vec<PeerId>, block_hash: Option<Hash>) {
        peers.sort_by(|p1, p2| p1.address.cmp(&p2.address));
        if let Some(block_hash) = block_hash {
            let mut rng = StdRng::from_seed(block_hash);
            peers.shuffle(&mut rng);
        }
    }

    pub fn sign_block(&self, block: Block) -> Result<Block, String> {
        self.validate_access(&[Role::Leader, Role::ProxyTail, Role::ValidatingPeer])?;
        Ok(block.sign(&self.public_key, &self.private_key)?)
    }

    pub async fn validate_and_store(
        &mut self,
        transactions: Vec<Transaction>,
        wsv: Arc<Mutex<WorldStateView>>,
    ) -> Result<(), String> {
        let transactions = self.sign_transactions(transactions).await?;
        let block = Block::builder(transactions)
            .validate_tx(&*wsv.lock().await)
            .build();
        let minimum_quorum_of_peers = 2;
        if self.sorted_peers.len() < minimum_quorum_of_peers {
            //If there is only one peer running skip consensus part
            let _hash = self.storage.lock().await.store(block).await?;
        } else {
            self.pending_block = Some(block.clone());
            self.on_block_created(block).await?;
        }
        Ok(())
    }

    pub async fn on_block_created(&self, block: Block) -> Result<(), String> {
        self.validate_access(&[Role::Leader])?;
        let block = self.sign_block(block)?;
        for peer in self.validating_peers() {
            let _result = N::send_request_to(
                &peer.address,
                Request::new(
                    uri::BLOCKS_URI.to_string(),
                    Message::Created(block.clone()).into(),
                ),
            )
            .await;
        }
        let _result = N::send_request_to(
            self.proxy_tail().address.as_ref(),
            Request::new(
                uri::BLOCKS_URI.to_string(),
                Message::Created(block.clone()).into(),
            ),
        )
        .await;
        Ok(())
    }

    pub async fn handle_message(&mut self, message: Message) -> Result<(), String> {
        //TODO: check that the messages come from the right peers (check roles, keys)
        match message {
            Message::Created(block) => match self.role() {
                Role::ValidatingPeer => {
                    let block = self.sign_block(block)?;
                    let _result = N::send_request_to(
                        self.proxy_tail().address.as_ref(),
                        Request::new(uri::BLOCKS_URI.to_string(), Message::Signed(block).into()),
                    )
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
                            let hash = self.storage.lock().await.store(block.clone()).await?;
                            for peer in self.validating_peers() {
                                let _result = N::send_request_to(
                                    &peer.address,
                                    Request::new(
                                        uri::BLOCKS_URI.to_string(),
                                        Message::Committed(block.clone()).into(),
                                    ),
                                )
                                .await;
                            }
                            for peer in self.peers_set_b() {
                                let _result = N::send_request_to(
                                    &peer.address,
                                    Request::new(
                                        uri::BLOCKS_URI.to_string(),
                                        Message::Committed(block.clone()).into(),
                                    ),
                                )
                                .await;
                            }
                            let _result = N::send_request_to(
                                self.leader().address.as_ref(),
                                Request::new(
                                    uri::BLOCKS_URI.to_string(),
                                    Message::Committed(block.clone()).into(),
                                ),
                            )
                            .await;
                            self.next_round(hash);
                        }
                    }
                }
            }
            Message::Committed(block) => {
                //TODO: check if the block is the same as pending
                let hash = self.storage.lock().await.store(block).await?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, kura::Kura};
    use futures::channel::mpsc;

    #[test]
    #[should_panic]
    fn not_enough_peers() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::unbounded();
        let kura = Arc::new(Mutex::new(Kura::new("strict".to_string(), dir.path(), tx)));
        let (public_key, private_key) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        let this_peer = PeerId {
            address: "127.0.0.1:8080".to_string(),
            public_key: [0u8; 32],
        };
        let _sumeragi: Sumeragi<TcpNetwork, Kura> = Sumeragi::new(
            public_key,
            private_key,
            &[this_peer.clone()],
            this_peer,
            3,
            kura,
            TcpNetwork::new("127.0.0.1:8080"),
        )
        .unwrap();
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
        Sumeragi::<TcpNetwork, Kura>::sort_peers(&mut peers1, Some([1u8; 32]));
        let mut peers2 = peers1.clone();
        Sumeragi::<TcpNetwork, Kura>::sort_peers(&mut peers2, Some([2u8; 32]));
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
        Sumeragi::<TcpNetwork, Kura>::sort_peers(&mut peers1, Some([1u8; 32]));
        let mut peers2 = peers1.clone();
        Sumeragi::<TcpNetwork, Kura>::sort_peers(&mut peers2, Some([1u8; 32]));
        assert_eq!(peers1, peers2);
    }
}
