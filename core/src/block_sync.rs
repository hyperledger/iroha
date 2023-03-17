//! This module contains structures and messages for synchronization of blocks between peers.
#![allow(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]
use std::{fmt::Debug, sync::Arc, time::Duration};

use iroha_actor::{broker::*, prelude::*, Context};
use iroha_config::block_sync::Configuration;
use iroha_crypto::*;
use iroha_data_model::{block::VersionedCommittedBlock, prelude::*};
use iroha_logger::prelude::*;
use iroha_macro::*;
use iroha_p2p::Post;
use iroha_version::prelude::*;
use parity_scale_codec::{Decode, Encode};

use crate::{kura::Kura, sumeragi::Sumeragi, NetworkMessage};

/// Structure responsible for block synchronization between peers.
#[derive(Debug)]
pub struct BlockSynchronizer {
    sumeragi: Arc<Sumeragi>,
    kura: Arc<Kura>,
    peer_id: PeerId,
    gossip_period: Duration,
    block_batch_size: u32,
    broker: Broker,
    actor_channel_capacity: u32,
}

#[async_trait::async_trait]
impl Actor for BlockSynchronizer {
    fn actor_channel_capacity(&self) -> u32 {
        self.actor_channel_capacity
    }

    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.broker.subscribe::<message::Message, _>(ctx);
        ctx.notify_every::<message::ReceiveUpdates>(self.gossip_period);
    }
}

#[async_trait::async_trait]
impl Handler<message::ReceiveUpdates> for BlockSynchronizer {
    type Result = ();
    async fn handle(&mut self, _: message::ReceiveUpdates) {
        if let Some(random_peer) = self.sumeragi.get_random_peer_for_block_sync() {
            self.request_latest_blocks_from_peer(random_peer.id().clone())
                .await;
        }
    }
}

#[async_trait::async_trait]
impl Handler<message::Message> for BlockSynchronizer {
    type Result = ();
    async fn handle(&mut self, message: message::Message) {
        message.handle_message(self).await;
    }
}

impl BlockSynchronizer {
    /// Sends request for latest blocks to a chosen peer
    async fn request_latest_blocks_from_peer(&mut self, peer_id: PeerId) {
        let (latest_hash, previous_hash) = {
            let wsv = self.sumeragi.wsv_mutex_access();
            (wsv.latest_block_hash(), wsv.previous_block_hash())
        };
        message::Message::GetBlocksAfter(message::GetBlocksAfter::new(
            latest_hash,
            previous_hash,
            self.peer_id.clone(),
        ))
        .send_to(self.broker.clone(), peer_id)
        .await;
    }

    /// Create [`Self`] from [`Configuration`]
    pub fn from_configuration(
        config: &Configuration,
        sumeragi: Arc<Sumeragi>,
        kura: Arc<Kura>,
        peer_id: PeerId,
        broker: Broker,
    ) -> Self {
        Self {
            peer_id,
            sumeragi,
            kura,
            gossip_period: Duration::from_millis(config.gossip_period_ms),
            block_batch_size: config.block_batch_size,
            broker,
            actor_channel_capacity: config.actor_channel_capacity,
        }
    }
}

pub mod message {
    //! Module containing messages for [`BlockSynchronizer`](super::BlockSynchronizer).
    use super::*;
    use crate::{block::VersionedCandidateCommittedBlock, sumeragi::view_change::ProofChain};

    /// Message to initiate receiving of latest blocks from other peers
    ///
    /// Every `gossip_period` peer will poll one randomly selected peer for latest blocks
    #[derive(Debug, Clone, Copy, Default, iroha_actor::Message)]
    pub struct ReceiveUpdates;

    declare_versioned_with_scale!(VersionedMessage 1..2, Debug, Clone, iroha_macro::FromVariant, iroha_actor::Message);

    impl VersionedMessage {
        /// Convert from `&VersionedMessage` to V1 reference
        pub const fn as_v1(&self) -> &Message {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Convert from `&mut VersionedMessage` to V1 mutable reference
        pub fn as_mut_v1(&mut self) -> &mut Message {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Performs the conversion from `VersionedMessage` to V1
        pub fn into_v1(self) -> Message {
            match self {
                Self::V1(v1) => v1,
            }
        }
    }

    /// Get blocks after some block
    #[derive(Debug, Clone, Decode, Encode)]
    pub struct GetBlocksAfter {
        /// Hash of latest available block
        pub latest_hash: Option<HashOf<VersionedCommittedBlock>>,
        /// Hash of second to latest block
        pub previous_hash: Option<HashOf<VersionedCommittedBlock>>,
        /// Peer id
        pub peer_id: PeerId,
    }

    impl GetBlocksAfter {
        /// Construct [`GetBlocksAfter`].
        pub const fn new(
            latest_hash: Option<HashOf<VersionedCommittedBlock>>,
            previous_hash: Option<HashOf<VersionedCommittedBlock>>,
            peer_id: PeerId,
        ) -> Self {
            Self {
                latest_hash,
                previous_hash,
                peer_id,
            }
        }
    }

    /// Message variant to share blocks to peer
    #[derive(Debug, Clone, Decode, Encode)]
    pub struct ShareBlocks {
        /// Blocks
        pub blocks: Vec<VersionedCandidateCommittedBlock>,
        /// Peer id
        pub peer_id: PeerId,
    }

    impl ShareBlocks {
        /// Construct [`ShareBlocks`].
        pub const fn new(blocks: Vec<VersionedCandidateCommittedBlock>, peer_id: PeerId) -> Self {
            Self { blocks, peer_id }
        }
    }

    /// Message's variants that are used by peers to communicate in the process of consensus.
    #[version_with_scale(n = 1, versioned = "VersionedMessage")]
    #[derive(Debug, Clone, Decode, Encode, FromVariant, iroha_actor::Message)]
    pub enum Message {
        /// Request for blocks after the block with `Hash` for the peer with `PeerId`.
        GetBlocksAfter(GetBlocksAfter),
        /// The response to `GetBlocksAfter`. Contains the requested blocks and the id of the peer who shared them.
        ShareBlocks(ShareBlocks),
    }

    impl Message {
        /// Handles the incoming message.
        #[iroha_futures::telemetry_future]
        pub async fn handle_message(&self, block_sync: &mut BlockSynchronizer) {
            match self {
                Message::GetBlocksAfter(GetBlocksAfter {
                    latest_hash,
                    previous_hash,
                    peer_id,
                }) => {
                    if block_sync.block_batch_size == 0 {
                        warn!("Error: not sending any blocks as batch_size is equal to zero.");
                        return;
                    }
                    let local_latest_block_hash =
                        block_sync.sumeragi.wsv_mutex_access().latest_block_hash();
                    if *latest_hash == local_latest_block_hash
                        || *previous_hash == local_latest_block_hash
                    {
                        return;
                    }

                    let start_height = match previous_hash {
                        Some(hash) => match block_sync.kura.get_block_height_by_hash(hash) {
                            None => {
                                error!(?previous_hash, "Block hash not found");
                                return;
                            }
                            Some(height) => height + 1, // It's get blocks *after*, so we add 1.
                        },
                        None => 1,
                    };

                    let blocks = (start_height..)
                        .take(1 + block_sync.block_batch_size as usize)
                        .map_while(|height| block_sync.kura.get_block_by_height(height))
                        .skip_while(|block| Some(block.hash()) == *latest_hash)
                        .map(|block| VersionedCommittedBlock::clone(&block).into())
                        .collect::<Vec<_>>();

                    if blocks.is_empty() {
                        // The only case where the blocks array could be empty is if we got queried for blocks
                        // after the latest hash. There is a check earlier in the function that returns early
                        // so it should not be possible for us to get here.
                        error!(hash=?previous_hash, "Blocks array is empty but shouldn't be.");
                    } else {
                        trace!(hash=?previous_hash, "Sharing blocks after hash");
                        Message::ShareBlocks(ShareBlocks::new(blocks, block_sync.peer_id.clone()))
                            .send_to(block_sync.broker.clone(), peer_id.clone())
                            .await;
                    }
                }
                Message::ShareBlocks(ShareBlocks { blocks, .. }) => {
                    use crate::sumeragi::message::{BlockSyncUpdate, Message, MessagePacket};
                    for block in blocks.clone() {
                        block_sync.sumeragi.incoming_message(MessagePacket::new(
                            ProofChain::default(),
                            Message::BlockSyncUpdate(BlockSyncUpdate { block }),
                        ));
                    }
                }
            }
        }

        /// Send this message over the network to the specified `peer`.
        #[iroha_futures::telemetry_future]
        #[log("TRACE")]
        pub async fn send_to(self, broker: Broker, peer: PeerId) {
            let data = NetworkMessage::BlockSync(Box::new(VersionedMessage::from(self)));
            let message = Post {
                data,
                peer: peer.clone(),
            };
            broker.issue_send(message).await;
        }
    }
}
