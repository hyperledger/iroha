//! This module contains structures and messages for synchronization of blocks between peers.

use self::message::*;
use crate::{
    block::ValidBlock,
    kura::Kura,
    peer::PeerId,
    sumeragi::{Role, Sumeragi},
};
use async_std::{sync::RwLock, task};
use std::{sync::Arc, time::Duration};

/// The state of `BlockSynchronizer`.
#[derive(Clone)]
enum State {
    /// Not synchronizing now.
    Idle,
    /// Synchronization is in progress: validating and committing blocks.
    InProgress(Vec<ValidBlock>),
}

/// Structure responsible for block synchronization between peers.
pub struct BlockSynchronizer {
    kura: Arc<RwLock<Kura>>,
    sumeragi: Arc<RwLock<Sumeragi>>,
    peer_id: PeerId,
    state: State,
    gossip_period: Duration,
}

impl BlockSynchronizer {
    /// Constructs `BlockSync`
    pub fn new(
        kura: Arc<RwLock<Kura>>,
        sumeragi: Arc<RwLock<Sumeragi>>,
        peer_id: PeerId,
        gossip_period: Duration,
    ) -> BlockSynchronizer {
        Self {
            kura,
            peer_id,
            sumeragi,
            state: State::Idle,
            gossip_period,
        }
    }

    /// Starts the `BlockSync`, meaning that every `gossip_period`
    /// the peers would gossip about latest block hashes
    /// and try to synchronize their blocks.
    pub fn start(&self) {
        let gossip_period = self.gossip_period;
        let kura = self.kura.clone();
        let peer_id = self.peer_id.clone();
        let sumeragi = self.sumeragi.clone();
        task::spawn(async move {
            loop {
                task::sleep(gossip_period).await;
                let message =
                    Message::LatestBlock((kura.read().await.latest_block_hash(), peer_id.clone()));
                futures::future::join_all(
                    sumeragi
                        .read()
                        .await
                        .network_topology
                        .sorted_peers
                        .iter()
                        .map(|peer| message.clone().send_to(peer)),
                )
                .await;
            }
        });
    }

    /// Continues the synchronization if it was ongoing. Should be called after `WSV` update.
    pub async fn continue_sync(&mut self) {
        if let State::InProgress(blocks) = self.state.clone() {
            if let Some((block, blocks)) = blocks.split_first() {
                let mut network_topology = self.sumeragi.read().await.network_topology.clone();
                network_topology.shift_peers_by_n(block.header.number_of_view_changes);
                if self.kura.read().await.latest_block_hash() == block.header.previous_block_hash
                    && network_topology
                        .filter_signatures_by_roles(
                            &[Role::ValidatingPeer, Role::Leader, Role::ProxyTail],
                            &block.verified_signatures(),
                        )
                        .len()
                        >= network_topology.min_votes_for_commit()
                {
                    self.state = State::InProgress(blocks.to_vec());
                    self.sumeragi
                        .write()
                        .await
                        .commit_block(block.clone())
                        .await;
                } else {
                    self.state = State::Idle;
                }
            } else {
                self.state = State::Idle;
            }
        }
    }
}

/// The module for block synchronization related peer to peer messages.
pub mod message {
    use super::{BlockSynchronizer, State};
    use crate::{block::ValidBlock, crypto::Hash, peer::PeerId, torii::uri};
    use iroha_derive::*;
    use iroha_network::prelude::*;
    use parity_scale_codec::{Decode, Encode};

    /// Message's variants that are used by peers to communicate in the process of consensus.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub enum Message {
        /// Gossip about latest block.
        LatestBlock((Hash, PeerId)),
        /// Request for blocks after the block with `Hash` for the peer with `PeerId`.
        GetBlocksAfter((Hash, PeerId)),
        /// The response to `GetBlocksAfter`. Contains the requested blocks.
        ShareBlocks(Vec<ValidBlock>),
    }

    impl Message {
        /// Handles the incoming message.
        pub async fn handle(&self, block_sync: &mut BlockSynchronizer) {
            match self {
                Message::LatestBlock((hash, peer)) => {
                    let latest_block_hash = block_sync.kura.read().await.latest_block_hash();
                    if *hash != latest_block_hash {
                        if let Err(err) =
                            Message::GetBlocksAfter((latest_block_hash, block_sync.peer_id.clone()))
                                .send_to(peer)
                                .await
                        {
                            eprintln!("Failed to request blocks: {:?}", err)
                        }
                    }
                }
                Message::GetBlocksAfter((hash, peer)) => {
                    //TODO: send batches of configurable size instead of all blocks
                    if let Some(blocks) = block_sync.kura.read().await.blocks_after(*hash) {
                        if let Err(err) = Message::ShareBlocks(blocks.to_vec()).send_to(peer).await
                        {
                            eprintln!("Failed to send blocks: {:?}", err)
                        }
                    }
                }
                Message::ShareBlocks(blocks) => {
                    if let State::Idle = block_sync.state.clone() {
                        block_sync.state = State::InProgress(blocks.clone());
                        block_sync.continue_sync().await;
                    }
                }
            }
        }

        /// Send this message over the network to the specified `peer`.
        #[log]
        pub async fn send_to(self, peer: &PeerId) -> Result<(), String> {
            match Network::send_request_to(
                &peer.address,
                Request::new(uri::BLOCK_SYNC_URI.to_string(), self.into()),
            )
            .await?
            {
                Response::Ok(_) => Ok(()),
                Response::InternalError => Err(format!(
                    "Failed to send message - Internal Error on peer: {:?}",
                    peer
                )),
            }
        }
    }
}
