use crate::{
    crypto::{self, Hash},
    peer::{self, PeerId},
    prelude::*,
};
use iroha_derive::*;
use iroha_network::{Network, Request};
use parity_scale_codec::{Decode, Encode};
use std::cmp::Ordering;

pub struct Sumeragi {
    public_key: PublicKey,
    private_key: PrivateKey,
    sorted_peers: Vec<PeerId>,
    max_faults: usize,
    peer_id: PeerId,
    /// Block in discussion this round
    pending_block: Option<Block>,
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

#[allow(dead_code)]
impl Sumeragi {
    pub fn new(
        public_key: PublicKey,
        private_key: PrivateKey,
        peers: &[PeerId],
        prev_block_hash: Option<Hash>,
        max_faults: usize,
    ) -> Result<Self, String> {
        let min_peers = 3 * max_faults + 1;
        if peers.len() >= min_peers {
            let mut sorted_peers = peers.to_vec();
            Self::sort_peers(&mut sorted_peers, prev_block_hash);
            Ok(Self {
                public_key,
                private_key,
                sorted_peers,
                max_faults,
                //TODO: generate peer's public key, save on shutdown and load on start
                peer_id: PeerId {
                    address: "127.0.0.1:7878".to_string(),
                    public_key: [0u8; 32],
                },
                pending_block: None,
            })
        } else {
            Err(format!("Not enough peers to be Byzantine fault tolerant. Expected a least {} peers, got {}", 3 * max_faults + 1, peers.len()))
        }
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
        &self.peers_set_a()[1..(self.peers_set_a().len() - 1)]
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

    fn sort_peers(peers: &mut Vec<PeerId>, block_hash: Option<Hash>) {
        peers.sort_by(|p1, p2| {
            if let Some(block_hash) = block_hash {
                let mut bytes_p1 = Vec::<u8>::from(p1);
                bytes_p1.extend_from_slice(&block_hash);
                let hash_p1 = crypto::hash(bytes_p1);
                let mut bytes_p2 = Vec::<u8>::from(p2);
                bytes_p2.extend_from_slice(&block_hash);
                let hash_p2 = crypto::hash(bytes_p2);
                let order = hash_p1.cmp(&hash_p2);
                if order == Ordering::Equal {
                    p1.address.cmp(&p2.address)
                } else {
                    order
                }
            } else {
                p1.address.cmp(&p2.address)
            }
        });
    }

    pub fn sign_block(&self, block: Block) -> Result<Block, String> {
        self.validate_access(&[Role::Leader, Role::ProxyTail, Role::ValidatingPeer])?;
        Ok(block.sign(&self.public_key, &self.private_key)?)
    }

    pub async fn on_block_created(&self, block: Block) -> Result<Block, String> {
        self.validate_access(&[Role::Leader])?;
        let block = self.sign_block(block)?;
        for peer in self.validating_peers() {
            let _result = Network::send_request_to(
                &peer.address,
                Request::new(
                    "/block".to_string(),
                    peer::Message::SumeragiMessage(Message::Created(block.clone())).into(),
                ),
            )
            .await;
        }
        let _result = Network::send_request_to(
            self.proxy_tail().address.as_ref(),
            Request::new(
                "/blocks".to_string(),
                peer::Message::SumeragiMessage(Message::Created(block.clone())).into(),
            ),
        );
        Ok(block)
    }

    pub async fn handle_message(&mut self, message: Message) -> Result<(), String> {
        //TODO: check that the messages come from the right peers (check roles, keys)
        match message {
            Message::Created(block) => match self.role() {
                Role::ValidatingPeer => {
                    let block = self.sign_block(block)?;
                    let _result = Network::send_request_to(
                        self.proxy_tail().address.as_ref(),
                        Request::new(
                            "/blocks".to_string(),
                            peer::Message::SumeragiMessage(Message::Signed(block)).into(),
                        ),
                    );
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
                            //TODO: commit block to Kura
                            for peer in self.validating_peers() {
                                let _result = Network::send_request_to(
                                    &peer.address,
                                    Request::new(
                                        "/block".to_string(),
                                        peer::Message::SumeragiMessage(Message::Committed(
                                            block.clone(),
                                        ))
                                        .into(),
                                    ),
                                )
                                .await;
                            }
                            let _result = Network::send_request_to(
                                self.leader().address.as_ref(),
                                Request::new(
                                    "/blocks".to_string(),
                                    peer::Message::SumeragiMessage(Message::Created(block.clone()))
                                        .into(),
                                ),
                            );
                            //TODO: `self.next_round()`
                        }
                    }
                }
            }
            Message::Committed(_block) => {
                //TODO: check if the block is the same as pending and commit it to Kura
                //TODO: `self.next_round()`
            }
        }
        Ok(())
    }

    pub async fn sign_transactions(
        &mut self,
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
    use crate::crypto;

    #[test]
    #[should_panic]
    fn not_enough_peers() {
        let (public_key, private_key) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        let _sumeragi = Sumeragi::new(public_key, private_key, &Vec::new(), None, 3).unwrap();
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
}
