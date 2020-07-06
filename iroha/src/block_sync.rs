//! This module contains structures and messages for synchronization of blocks between peers.

use self::{config::BlockSyncConfiguration, message::*};
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
    /// Contains a vector of blocks left to commit and an id of the peer from which the blocks were requested.
    InProgress(Vec<ValidBlock>, PeerId),
}

/// Structure responsible for block synchronization between peers.
pub struct BlockSynchronizer {
    kura: Arc<RwLock<Kura>>,
    sumeragi: Arc<RwLock<Sumeragi>>,
    peer_id: PeerId,
    state: State,
    gossip_period: Duration,
    batch_size: u64,
}

impl BlockSynchronizer {
    /// Constructs `BlockSync`
    pub fn from_configuration(
        config: &BlockSyncConfiguration,
        kura: Arc<RwLock<Kura>>,
        sumeragi: Arc<RwLock<Sumeragi>>,
        peer_id: PeerId,
    ) -> BlockSynchronizer {
        Self {
            kura,
            peer_id,
            sumeragi,
            state: State::Idle,
            gossip_period: Duration::from_millis(config.gossip_period_ms),
            batch_size: config.batch_size,
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
                    Message::LatestBlock(kura.read().await.latest_block_hash(), peer_id.clone());
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
        if let State::InProgress(blocks, peer_id) = self.state.clone() {
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
                    self.state = State::InProgress(blocks.to_vec(), peer_id);
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
                if let Err(e) = Message::LatestBlock(
                    self.kura.read().await.latest_block_hash(),
                    self.peer_id.clone(),
                )
                .send_to(&peer_id)
                .await
                {
                    eprintln!("Failed to request next batch of blocks. {}", e)
                }
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
        LatestBlock(Hash, PeerId),
        /// Request for blocks after the block with `Hash` for the peer with `PeerId`.
        GetBlocksAfter(Hash, PeerId),
        /// The response to `GetBlocksAfter`. Contains the requested blocks and the id of the peer who shared them.
        ShareBlocks(Vec<ValidBlock>, PeerId),
    }

    impl Message {
        /// Handles the incoming message.
        pub async fn handle(&self, block_sync: &mut BlockSynchronizer) {
            match self {
                Message::LatestBlock(hash, peer) => {
                    let latest_block_hash = block_sync.kura.read().await.latest_block_hash();
                    if *hash != latest_block_hash {
                        if let Err(err) =
                            Message::GetBlocksAfter(latest_block_hash, block_sync.peer_id.clone())
                                .send_to(peer)
                                .await
                        {
                            eprintln!("Failed to request blocks: {:?}", err)
                        }
                    }
                }
                Message::GetBlocksAfter(hash, peer) => {
                    if block_sync.batch_size > 0 {
                        if let Some(blocks) = block_sync.kura.read().await.blocks_after(*hash) {
                            if let Some(blocks_batch) =
                                blocks.chunks(block_sync.batch_size as usize).next()
                            {
                                if let Err(err) = Message::ShareBlocks(
                                    blocks_batch.to_vec(),
                                    block_sync.peer_id.clone(),
                                )
                                .send_to(peer)
                                .await
                                {
                                    eprintln!("Failed to send blocks: {:?}", err)
                                }
                            }
                        }
                    } else {
                        eprintln!("Error: not sending any blocks as batch_size is equal to zero.")
                    }
                }
                Message::ShareBlocks(blocks, peer_id) => {
                    if let State::Idle = block_sync.state.clone() {
                        block_sync.state = State::InProgress(blocks.clone(), peer_id.clone());
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

/// This module contains all configuration related logic.
pub mod config {
    use iroha_derive::*;
    use serde::Deserialize;
    use std::env;

    const BATCH_SIZE: &str = "BLOCK_SYNC_BATCH_SIZE";
    const GOSSIP_PERIOD_MS: &str = "BLOCK_SYNC_GOSSIP_PERIOD_MS";
    const DEFAULT_BATCH_SIZE: u64 = 4;
    const DEFAULT_GOSSIP_PERIOD_MS: u64 = 10000;

    /// Configuration for `BlockSynchronizer`.
    #[derive(Clone, Deserialize, Debug)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct BlockSyncConfiguration {
        /// The time between peer sharing its latest block hash with other peers in milliseconds.
        #[serde(default = "default_gossip_period")]
        pub gossip_period_ms: u64,
        /// The number of blocks, which can be send in one message.
        /// Underlying network (`iroha_network`) should support transferring messages this large.
        #[serde(default = "default_batch_size")]
        pub batch_size: u64,
    }

    impl BlockSyncConfiguration {
        /// Load environment variables and replace predefined parameters with these variables
        /// values.
        #[log]
        pub fn load_environment(&mut self) -> Result<(), String> {
            if let Ok(batch_size) = env::var(BATCH_SIZE) {
                self.batch_size = serde_json::from_str(&batch_size)
                    .map_err(|e| format!("Failed to parse batch size: {}", e))?;
            }
            if let Ok(gossip_period_ms) = env::var(GOSSIP_PERIOD_MS) {
                self.gossip_period_ms = serde_json::from_str(&gossip_period_ms)
                    .map_err(|e| format!("Failed to parse gossip period: {}", e))?;
            }
            Ok(())
        }
    }

    fn default_batch_size() -> u64 {
        DEFAULT_BATCH_SIZE
    }

    fn default_gossip_period() -> u64 {
        DEFAULT_GOSSIP_PERIOD_MS
    }
}
