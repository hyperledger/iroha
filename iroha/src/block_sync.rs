//! This module contains structures and messages for synchronization of blocks between peers.

use std::{sync::Arc, time::Duration};

use iroha_data_model::prelude::*;
use iroha_logger::{log, InstrumentFutures};
use tokio::{sync::RwLock, task, time};

use self::{config::BlockSyncConfiguration, message::*};
use crate::{
    sumeragi::{Role, Sumeragi},
    wsv::WorldStateView,
    VersionedCommittedBlock,
};

/// The state of `BlockSynchronizer`.
#[derive(Clone, Debug)]
enum State {
    /// Not synchronizing now.
    Idle,
    /// Synchronization is in progress: validating and committing blocks.
    /// Contains a vector of blocks left to commit and an id of the peer from which the blocks were requested.
    InProgress(Vec<VersionedCommittedBlock>, PeerId),
}

/// Structure responsible for block synchronization between peers.
#[derive(Debug)]
pub struct BlockSynchronizer {
    wsv: Arc<WorldStateView>,
    sumeragi: Arc<RwLock<Sumeragi>>,
    peer_id: PeerId,
    state: State,
    gossip_period: Duration,
    batch_size: u32,
    n_topology_shifts_before_reshuffle: u32,
}

impl BlockSynchronizer {
    /// Constructs `BlockSync`
    pub fn from_configuration(
        config: &BlockSyncConfiguration,
        wsv: Arc<WorldStateView>,
        sumeragi: Arc<RwLock<Sumeragi>>,
        peer_id: PeerId,
        n_topology_shifts_before_reshuffle: u32,
    ) -> BlockSynchronizer {
        Self {
            wsv,
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
        let wsv = Arc::clone(&self.wsv);
        let peer_id = self.peer_id.clone();
        let sumeragi = Arc::clone(&self.sumeragi);
        drop(task::spawn(
            async move {
                loop {
                    time::sleep(gossip_period).await;
                    let message = Message::LatestBlock(wsv.latest_block_hash(), peer_id.clone());
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
            }
            .in_current_span(),
        ));
    }

    /// Continues the synchronization if it was ongoing. Should be called after `WSV` update.
    #[iroha_futures::telemetry_future]
    pub async fn continue_sync(&mut self) {
        if let State::InProgress(blocks, peer_id) = self.state.clone() {
            iroha_logger::info!(
                "Synchronizing blocks, {} blocks left in this batch.",
                blocks.len()
            );
            if let Some((block, blocks)) = blocks.split_first() {
                let mut network_topology = self
                    .sumeragi
                    .read()
                    .await
                    .network_topology_current_or_genesis(&block.clone().into());
                if block.header().number_of_view_changes <= self.n_topology_shifts_before_reshuffle
                {
                    network_topology.shift_peers_by_n(block.header().number_of_view_changes);
                } else {
                    network_topology.sort_peers_by_hash_and_counter(
                        Some(block.hash()),
                        block.header().number_of_view_changes,
                    )
                }
                if self.wsv.latest_block_hash() == block.header().previous_block_hash
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
                        .commit_block(block.clone().into())
                        .await;
                } else {
                    iroha_logger::warn!("Failed to commit a block received via synchronization request - validation failed. Block hash: {}.", block.hash());
                    self.state = State::Idle;
                }
            } else {
                self.state = State::Idle;
                if let Err(e) =
                    Message::GetBlocksAfter(self.wsv.latest_block_hash(), self.peer_id.clone())
                        .send_to(&peer_id)
                        .await
                {
                    iroha_logger::error!("Failed to request next batch of blocks. {}", e)
                }
            }
        }
    }
}

/// The module for block synchronization related peer to peer messages.
pub mod message {
    use iroha_crypto::*;
    use iroha_data_model::prelude::*;
    use iroha_derive::*;
    use iroha_error::{error, Result};
    use iroha_logger::log;
    use iroha_network::prelude::*;
    use iroha_version::prelude::*;
    use parity_scale_codec::{Decode, Encode};

    use super::{BlockSynchronizer, State};
    use crate::{block::VersionedCommittedBlock, torii::uri};

    declare_versioned_with_scale!(VersionedMessage 1..2);

    impl VersionedMessage {
        /// Same as [`as_v1`] but also does conversion
        pub const fn as_inner_v1(&self) -> &Message {
            match self {
                Self::V1(v1) => &v1.0,
            }
        }

        /// Same as [`as_inner_v1`] but returns mutable reference
        pub fn as_mut_inner_v1(&mut self) -> &mut Message {
            match self {
                Self::V1(v1) => &mut v1.0,
            }
        }

        /// Same as [`into_v1`] but also does conversion
        #[allow(clippy::missing_const_for_fn)]
        pub fn into_inner_v1(self) -> Message {
            match self {
                Self::V1(v1) => v1.0,
            }
        }
    }

    /// Message's variants that are used by peers to communicate in the process of consensus.
    #[version_with_scale(n = 1, versioned = "VersionedMessage")]
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub enum Message {
        /// Gossip about latest block.
        LatestBlock(Hash, PeerId),
        /// Request for blocks after the block with `Hash` for the peer with `PeerId`.
        GetBlocksAfter(Hash, PeerId),
        /// The response to `GetBlocksAfter`. Contains the requested blocks and the id of the peer who shared them.
        ShareBlocks(Vec<VersionedCommittedBlock>, PeerId),
    }

    impl Message {
        /// Handles the incoming message.
        #[iroha_futures::telemetry_future]
        pub async fn handle(&self, block_sync: &mut BlockSynchronizer) {
            match self {
                Message::LatestBlock(hash, peer) => {
                    let latest_block_hash = block_sync.wsv.latest_block_hash();
                    if *hash != latest_block_hash {
                        if let Err(err) =
                            Message::GetBlocksAfter(latest_block_hash, block_sync.peer_id.clone())
                                .send_to(peer)
                                .await
                        {
                            iroha_logger::warn!("Failed to request blocks: {:?}", err)
                        }
                    }
                }
                Message::GetBlocksAfter(hash, peer) => {
                    if block_sync.batch_size == 0 {
                        iroha_logger::warn!(
                            "Error: not sending any blocks as batch_size is equal to zero."
                        );
                        return;
                    }

                    match block_sync.wsv.blocks_after(*hash, block_sync.batch_size) {
                        Ok(blocks) => {
                            if !blocks.is_empty() {
                                if let Err(err) =
                                    Message::ShareBlocks(blocks.clone(), block_sync.peer_id.clone())
                                        .send_to(peer)
                                        .await
                                {
                                    iroha_logger::error!("Failed to send blocks: {:?}", err)
                                }
                            }
                        }
                        Err(err) => iroha_logger::error!("{}", err),
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
        #[iroha_futures::telemetry_future]
        #[log("TRACE")]
        pub async fn send_to(self, peer: &PeerId) -> Result<()> {
            let message: VersionedMessage = self.into();
            match Network::send_request_to(
                &peer.address,
                Request::new(uri::BLOCK_SYNC_URI, message.encode_versioned()?),
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
    use iroha_config::derive::Configurable;
    use serde::{Deserialize, Serialize};

    const DEFAULT_BATCH_SIZE: u32 = 4;
    const DEFAULT_GOSSIP_PERIOD_MS: u64 = 10000;

    /// Configuration for `BlockSynchronizer`.
    #[derive(Copy, Clone, Deserialize, Serialize, Debug, Configurable)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(default)]
    #[config(env_prefix = "BLOCK_SYNC_")]
    pub struct BlockSyncConfiguration {
        /// The time between peer sharing its latest block hash with other peers in milliseconds.
        pub gossip_period_ms: u64,
        /// The number of blocks, which can be send in one message.
        /// Underlying network (`iroha_network`) should support transferring messages this large.
        pub batch_size: u32,
    }

    impl Default for BlockSyncConfiguration {
        fn default() -> Self {
            Self {
                gossip_period_ms: DEFAULT_GOSSIP_PERIOD_MS,
                batch_size: DEFAULT_BATCH_SIZE,
            }
        }
    }
}
