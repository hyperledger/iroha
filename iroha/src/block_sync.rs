//! This module contains structures and messages for synchronization of blocks between peers.

use self::{config::BlockSyncConfiguration, message::*};
use crate::{
    kura::Kura,
    sumeragi::{Role, Sumeragi},
    VersionedValidBlock,
};
use async_std::{sync::RwLock, task};
use iroha_data_model::prelude::*;
use iroha_derive::*;
use std::{sync::Arc, time::Duration};

/// The state of `BlockSynchronizer`.
#[derive(Clone, Debug)]
enum State {
    /// Not synchronizing now.
    Idle,
    /// Synchronization is in progress: validating and committing blocks.
    /// Contains a vector of blocks left to commit and an id of the peer from which the blocks were requested.
    InProgress(Vec<VersionedValidBlock>, PeerId),
}

/// Structure responsible for block synchronization between peers.
#[derive(Debug)]
pub struct BlockSynchronizer {
    kura: Arc<RwLock<Kura>>,
    sumeragi: Arc<RwLock<Sumeragi>>,
    peer_id: PeerId,
    state: State,
    gossip_period: Duration,
    batch_size: u64,
    n_topology_shifts_before_reshuffle: u32,
}

impl BlockSynchronizer {
    /// Constructs `BlockSync`
    pub fn from_configuration(
        config: &BlockSyncConfiguration,
        kura: Arc<RwLock<Kura>>,
        sumeragi: Arc<RwLock<Sumeragi>>,
        peer_id: PeerId,
        n_topology_shifts_before_reshuffle: u32,
    ) -> BlockSynchronizer {
        Self {
            kura,
            peer_id,
            sumeragi,
            state: State::Idle,
            gossip_period: Duration::from_millis(config.gossip_period_ms),
            batch_size: config.batch_size,
            n_topology_shifts_before_reshuffle,
        }
    }

    /// Starts the `BlockSync`, meaning that every `gossip_period`
    /// the peers would gossip about latest block hashes
    /// and try to synchronize their blocks.
    #[log]
    pub fn start(&self) {
        let gossip_period = self.gossip_period;
        let kura = self.kura.clone();
        let peer_id = self.peer_id.clone();
        let sumeragi = self.sumeragi.clone();
        drop(task::spawn(async move {
            loop {
                task::sleep(gossip_period).await;
                let message =
                    Message::LatestBlock(kura.read().await.latest_block_hash(), peer_id.clone());
                drop(
                    futures::future::join_all(
                        sumeragi
                            .read()
                            .await
                            .network_topology
                            .sorted_peers()
                            .iter()
                            .map(|peer| message.clone().send_to(peer)),
                    )
                    .await,
                );
            }
        }));
    }

    /// Continues the synchronization if it was ongoing. Should be called after `WSV` update.
    pub async fn continue_sync(&mut self) {
        if let State::InProgress(blocks, peer_id) = self.state.clone() {
            log::info!(
                "Synchronizing blocks, {} blocks left in this batch.",
                blocks.len()
            );
            if let Some((block, blocks)) = blocks.split_first() {
                let mut network_topology = self
                    .sumeragi
                    .read()
                    .await
                    .network_topology_current_or_genesis(block);
                if block.header().number_of_view_changes < self.n_topology_shifts_before_reshuffle {
                    network_topology.shift_peers_by_n(block.header().number_of_view_changes);
                } else {
                    network_topology.sort_peers_by_hash_and_counter(
                        Some(block.hash()),
                        block.header().number_of_view_changes,
                    )
                }
                if self.kura.read().await.latest_block_hash() == block.header().previous_block_hash
                    && network_topology
                        .filter_signatures_by_roles(
                            &[Role::ValidatingPeer, Role::Leader, Role::ProxyTail],
                            &block.verified_signatures(),
                        )
                        .len()
                        >= network_topology.min_votes_for_commit() as usize
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
                if let Err(e) = Message::GetBlocksAfter(
                    self.kura.read().await.latest_block_hash(),
                    self.peer_id.clone(),
                )
                .send_to(&peer_id)
                .await
                {
                    log::error!("Failed to request next batch of blocks. {}", e)
                }
            }
        }
    }
}

/// The module for block synchronization related peer to peer messages.
pub mod message {
    use super::{BlockSynchronizer, State};
    use crate::{block::VersionedValidBlock, torii::uri};
    use iroha_crypto::*;
    use iroha_data_model::prelude::*;
    use iroha_derive::*;
    use iroha_error::{error, Result};
    use iroha_network::prelude::*;
    use iroha_version::prelude::*;
    use parity_scale_codec::{Decode, Encode};

    declare_versioned_with_scale!(VersionedMessage 1..2);

    /// Message's variants that are used by peers to communicate in the process of consensus.
    #[version_with_scale(n = 1, versioned = "VersionedMessage")]
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub enum Message {
        /// Gossip about latest block.
        LatestBlock(Hash, PeerId),
        /// Request for blocks after the block with `Hash` for the peer with `PeerId`.
        GetBlocksAfter(Hash, PeerId),
        /// The response to `GetBlocksAfter`. Contains the requested blocks and the id of the peer who shared them.
        ShareBlocks(Vec<VersionedValidBlock>, PeerId),
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
                            log::warn!("Failed to request blocks: {:?}", err)
                        }
                    }
                }
                Message::GetBlocksAfter(hash, peer) => {
                    if block_sync.batch_size == 0 {
                        log::warn!("Error: not sending any blocks as batch_size is equal to zero.");
                        return;
                    }

                    if let Some(blocks) = block_sync.kura.read().await.blocks_after(*hash) {
                        #[allow(clippy::cast_possible_truncation)]
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
                                log::error!("Failed to send blocks: {:?}", err)
                            }
                        }
                    } else {
                        log::error!("Error: there are no blocks after the requested block hash.")
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
        #[log("TRACE")]
        pub async fn send_to(self, peer: &PeerId) -> Result<()> {
            let message: VersionedMessage = self.into();
            match Network::send_request_to(
                &peer.address,
                Request::new(uri::BLOCK_SYNC_URI.to_string(), message.encode_versioned()?),
            )
            .await?
            {
                Response::Ok(_) => Ok(()),
                Response::InternalError => Err(error!(
                    "Failed to send message - Internal Error on peer: {:?}",
                    peer
                )),
            }
        }
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_error::{Result, WrapErr};
    use serde::Deserialize;
    use std::env;

    const BATCH_SIZE: &str = "BLOCK_SYNC_BATCH_SIZE";
    const GOSSIP_PERIOD_MS: &str = "BLOCK_SYNC_GOSSIP_PERIOD_MS";
    const DEFAULT_BATCH_SIZE: u64 = 4;
    const DEFAULT_GOSSIP_PERIOD_MS: u64 = 10000;

    /// Configuration for `BlockSynchronizer`.
    #[derive(Copy, Clone, Deserialize, Debug)]
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
        ///
        /// # Errors
        /// Can fail deserializing values from json
        pub fn load_environment(&mut self) -> Result<()> {
            if let Ok(batch_size) = env::var(BATCH_SIZE) {
                self.batch_size =
                    serde_json::from_str(&batch_size).wrap_err("Failed to parse batch size")?;
            }
            if let Ok(gossip_period_ms) = env::var(GOSSIP_PERIOD_MS) {
                self.gossip_period_ms = serde_json::from_str(&gossip_period_ms)
                    .wrap_err("Failed to parse gossip period")?;
            }
            Ok(())
        }
    }

    const fn default_batch_size() -> u64 {
        DEFAULT_BATCH_SIZE
    }

    const fn default_gossip_period() -> u64 {
        DEFAULT_GOSSIP_PERIOD_MS
    }
}
