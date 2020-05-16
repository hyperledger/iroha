use crate::{
    block::{PendingBlock, SignedBlock},
    crypto::Hash,
    kura::Kura,
    peer::PeerId,
    prelude::*,
    torii::{uri, Message as ToriiMessage},
    ToriiMessageSender,
};
use async_std::sync::RwLock;
use iroha_derive::*;
use iroha_network::Request;
use parity_scale_codec::{Decode, Encode};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::{
    fmt::{self, Debug, Formatter},
    sync::Arc,
};

trait Consensus {
    fn round(&mut self, transactions: Vec<AcceptedTransaction>) -> Option<PendingBlock>;
}

#[derive(Io, Decode, Encode, Debug, Clone)]
pub enum Message {
    /// Is sent by leader to all validating peers, when a new block is created.
    Created(SignedBlock),
    /// Is sent by validating peers to proxy tail and observing peers when they have signed this block.
    Signed(SignedBlock),
    /// Is sent by proxy tail to validating peers and to leader, when the block is committed.
    Committed(SignedBlock),
}

impl Message {
    fn as_torii_message(&self, peer: &PeerId) -> ToriiMessage {
        ToriiMessage {
            server_url: peer.address.clone(),
            request: Request::new(uri::BLOCKS_URI.to_string(), self.into()),
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum Role {
    Leader,
    ValidatingPeer,
    ObservingPeer,
    ProxyTail,
}

pub struct Sumeragi {
    public_key: PublicKey,
    private_key: PrivateKey,
    sorted_peers: Vec<PeerId>,
    max_faults: usize,
    peer_id: PeerId,
    /// PendingBlock in discussion this round
    voting_block: Option<SignedBlock>,
    kura: Arc<RwLock<Kura>>,
    world_state_view: Arc<RwLock<WorldStateView>>,
    messages_to_torii_sender: Arc<RwLock<ToriiMessageSender>>,
}

impl Sumeragi {
    pub fn new(
        private_key: PrivateKey,
        peers: &[PeerId],
        peer_id: PeerId,
        max_faults: usize,
        kura: Arc<RwLock<Kura>>,
        world_state_view: Arc<RwLock<WorldStateView>>,
        messages_to_torii_sender: Arc<RwLock<ToriiMessageSender>>,
    ) -> Result<Self, String> {
        if !peers.contains(&peer_id) {
            return Err("Peers list should contain this peer.".to_string());
        }
        let min_peers = 3 * max_faults + 1;
        if peers.len() >= min_peers {
            //TODO: get previous block hash from kura
            let mut sorted_peers = peers.to_vec();
            Self::sort_peers(&mut sorted_peers, None);
            Ok(Self {
                public_key: peer_id.public_key,
                private_key,
                sorted_peers,
                max_faults,
                peer_id,
                voting_block: None,
                kura,
                world_state_view,
                messages_to_torii_sender,
            })
        } else {
            Err(format!("Not enough peers to be Byzantine fault tolerant. Expected a least {} peers, got {}", 3 * max_faults + 1, peers.len()))
        }
    }

    /// the leader of each round just uses the transactions they have at hand to create a block
    pub async fn round(
        &mut self,
        transactions: Vec<AcceptedTransaction>,
    ) -> Result<Option<SignedBlock>, String> {
        if let Role::Leader = self.role() {
            let block = PendingBlock::new(transactions)
                //TODO: actually chain block?
                .chain_first()
                .sign(&self.public_key, &self.private_key)?;
            let minimum_quorum_of_peers = 2;
            if self.sorted_peers.len() < minimum_quorum_of_peers {
                Ok(Some(block))
            } else {
                self.voting_block = Some(block.clone());
                let torii_sender = self.messages_to_torii_sender.write().await;
                for peer in self.validating_peers() {
                    torii_sender
                        .send(Message::Created(block.clone()).as_torii_message(peer))
                        .await;
                }
                torii_sender
                    .send(Message::Created(block.clone()).as_torii_message(self.proxy_tail()))
                    .await;
                Ok(None)
            }
        } else {
            //TODO: send pending transactions to all peers and as leader check what tx have already been committed
            //Sends transactions to leader
            let torii_sender = self.messages_to_torii_sender.write().await;
            for transaction in &transactions {
                torii_sender
                    .send(ToriiMessage {
                        server_url: self.leader().address.clone(),
                        request: Request::new(
                            uri::INSTRUCTIONS_URI.to_string(),
                            RequestedTransaction::from(transaction).into(),
                        ),
                    })
                    .await;
            }
            Ok(None)
        }
    }

    fn next_round(&mut self, prev_block_hash: Hash) {
        Self::sort_peers(&mut self.sorted_peers, Some(prev_block_hash));
        self.voting_block = None;
    }

    fn peers_set_a(&self) -> &[PeerId] {
        let n_a_peers = 2 * self.max_faults + 1;
        &self.sorted_peers[..n_a_peers]
    }

    fn peers_set_b(&self) -> &[PeerId] {
        &self.sorted_peers[(2 * self.max_faults + 1)..]
    }

    fn leader(&self) -> &PeerId {
        self.peers_set_a()
            .first()
            .expect("Failed to get first peer.")
    }

    fn proxy_tail(&self) -> &PeerId {
        self.peers_set_a().last().expect("Failed to get last peer.")
    }

    fn validating_peers(&self) -> &[PeerId] {
        let a_set = self.peers_set_a();
        if a_set.len() > 1 {
            &a_set[1..(a_set.len() - 1)]
        } else {
            &[]
        }
    }

    fn role(&self) -> Role {
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

    pub fn sort_peers(peers: &mut Vec<PeerId>, block_hash: Option<Hash>) {
        peers.sort_by(|p1, p2| p1.address.cmp(&p2.address));
        if let Some(block_hash) = block_hash {
            let mut rng = StdRng::from_seed(block_hash);
            peers.shuffle(&mut rng);
        }
    }

    #[log]
    pub async fn handle_message(&mut self, message: Message) -> Result<(), String> {
        //TODO: check that the messages come from the right peers (check roles, keys)
        match message {
            Message::Created(block) => match self.role() {
                Role::ValidatingPeer => {
                    self.messages_to_torii_sender
                        .write()
                        .await
                        .send(
                            Message::Signed(block.sign(&self.public_key, &self.private_key)?)
                                .as_torii_message(self.proxy_tail()),
                        )
                        .await;
                    //TODO: send to set b so they can observe
                }
                Role::ProxyTail => {
                    if self.voting_block.is_none() {
                        self.voting_block = Some(block)
                    }
                }
                _ => (),
            },
            Message::Signed(block) => {
                if let Role::ProxyTail = self.role() {
                    match self.voting_block.as_mut() {
                        Some(voting_block) => {
                            // TODO: verify signatures
                            for signature in block.signatures {
                                if !voting_block.signatures.contains(&signature) {
                                    voting_block.signatures.push(signature)
                                }
                            }
                        }
                        None => self.voting_block = Some(block),
                    };
                    if let Some(block) = self.voting_block.clone() {
                        if block.signatures.len() >= 2 * self.max_faults {
                            let block = block.sign(&self.public_key, &self.private_key)?;
                            let hash = self
                                .kura
                                .write()
                                .await
                                .store(
                                    block
                                        .clone()
                                        .validate(&*self.world_state_view.read().await)?,
                                )
                                .await?;
                            {
                                let torii_sender = self.messages_to_torii_sender.write().await;
                                for peer in self.validating_peers() {
                                    torii_sender
                                        .send(
                                            Message::Committed(block.clone())
                                                .as_torii_message(peer),
                                        )
                                        .await;
                                }
                                for peer in self.peers_set_b() {
                                    torii_sender
                                        .send(
                                            Message::Committed(block.clone())
                                                .as_torii_message(peer),
                                        )
                                        .await;
                                }
                                torii_sender
                                    .send(
                                        Message::Committed(block.clone())
                                            .as_torii_message(self.leader()),
                                    )
                                    .await;
                            }
                            self.next_round(hash);
                        }
                    }
                }
            }
            Message::Committed(block) => {
                //TODO: check if the block is the same as pending
                let hash = self
                    .kura
                    .write()
                    .await
                    .store(block.validate(&*self.world_state_view.read().await)?)
                    .await?;
                self.next_round(hash);
            }
        }
        Ok(())
    }
}

impl Debug for Sumeragi {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sumeragi")
            .field("public_key", &self.public_key)
            .field("sorted_peers", &self.sorted_peers)
            .field("max_faults", &self.max_faults)
            .field("peer_id", &self.peer_id)
            .field("voting_block", &self.voting_block)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use async_std::{
        prelude::*,
        sync::{self, RwLock},
    };
    use std::convert::TryFrom;

    #[test]
    #[should_panic]
    fn not_enough_peers() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = sync::channel(100);
        let (torii_sender, _torii_receiver) = sync::channel(100);
        let kura = Arc::new(RwLock::new(Kura::new("strict".to_string(), dir.path(), tx)));
        let (public_key, private_key) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        let listen_address = "127.0.0.1".to_string();
        let this_peer = PeerId {
            address: listen_address.clone(),
            public_key,
        };
        Sumeragi::new(
            private_key,
            &[this_peer.clone()],
            this_peer.clone(),
            3,
            kura,
            Arc::new(RwLock::new(WorldStateView::new(Peer::new(
                listen_address.clone(),
                &vec![this_peer],
            )))),
            Arc::new(RwLock::new(torii_sender)),
        )
        .expect("Failed to create Sumeragi.");
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

    #[async_std::test]
    async fn created_message_is_sent_by_leader() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = sync::channel(100);
        let (torii_sender, mut torii_receiver) = sync::channel(100);
        let kura = Arc::new(RwLock::new(Kura::new("strict".to_string(), dir.path(), tx)));
        let (public_key, private_key) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        //First peer by alphanumeric value of address is a leader when the block hash is None
        let peers = vec![
            PeerId {
                address: "127.0.0.1:7878".to_string(),
                public_key,
            },
            PeerId {
                address: "127.0.0.1:7879".to_string(),
                public_key: [2u8; 32],
            },
            PeerId {
                address: "127.0.0.1:7880".to_string(),
                public_key: [3u8; 32],
            },
            PeerId {
                address: "127.0.0.1:7881".to_string(),
                public_key: [4u8; 32],
            },
        ];
        let mut sumeragi = Sumeragi::new(
            private_key,
            &peers,
            peers.first().unwrap().clone(),
            1,
            kura,
            Arc::new(RwLock::new(WorldStateView::new(Peer::new(
                "127.0.0.1:7878".to_string(),
                &peers,
            )))),
            Arc::new(RwLock::new(torii_sender)),
        )
        .expect("Failed to create Sumeragi.");
        let task = async_std::task::spawn(async move {
            let mut message_counter = 0;
            while let Some(message) = torii_receiver.next().await {
                assert!(peers
                    .iter()
                    .find(|peer| peer.address == message.server_url)
                    .is_some());
                message_counter += 1;
                let message = Message::try_from(message.request.payload().to_vec())
                    .expect("Failed to parse message.");
                if let Message::Created(SignedBlock { transactions, .. }) = message {
                    assert_eq!(transactions.len(), 1)
                } else {
                    panic!("Message is not CreatedMessage.")
                }
            }
            assert_eq!(message_counter, 2);
        });
        let tx = RequestedTransaction::new(vec![], Id::new("entity", "domain"))
            .accept()
            .expect("Failed to accept tx.");
        let _result = sumeragi.round(vec![tx]).await;
        drop(sumeragi);
        task.await;
    }
}
