//! This module contains structures and messages for synchronization of blocks between peers.
#![allow(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic
)]
use std::{fmt::Debug, sync::Arc, time::Duration};

use iroha_actor::{broker::*, prelude::*, Context};
use iroha_config::block_sync::Configuration;
use iroha_crypto::{SignatureOf, *};
use iroha_data_model::prelude::*;
use iroha_logger::prelude::*;
use iroha_macro::*;
use iroha_p2p::Post;
use iroha_version::prelude::*;
use parity_scale_codec::{Decode, Encode};

use crate::{
    prelude::*,
    sumeragi::{network_topology::Role, Sumeragi},
    NetworkMessage, VersionedCommittedBlock,
};

/// Structure responsible for block synchronization between peers.
#[derive(Debug)]
pub struct BlockSynchronizer {
    sumeragi: Arc<Sumeragi>,
    peer_id: PeerId,
    gossip_period: Duration,
    block_batch_size: u32,
    broker: Broker,
    actor_channel_capacity: u32,
}

/// Block synchronizer
pub trait BlockSynchronizerTrait: Actor + Handler<Message> {
    /// Constructs `BlockSync`
    fn from_configuration(
        config: &Configuration,
        sumeragi: Arc<Sumeragi>,
        peer_id: PeerId,
        broker: Broker,
    ) -> Self;
}

impl BlockSynchronizerTrait for BlockSynchronizer {
    fn from_configuration(
        config: &Configuration,
        sumeragi: Arc<Sumeragi>,
        peer_id: PeerId,
        broker: Broker,
    ) -> Self {
        Self {
            peer_id,
            sumeragi,
            gossip_period: Duration::from_millis(config.gossip_period_ms),
            block_batch_size: config.block_batch_size,
            broker,
            actor_channel_capacity: config.actor_channel_capacity,
        }
    }
}

/// Message to initiate receiving of latest blocks from other peers
///
/// Every `gossip_period` peer will poll one randomly selected peer for latest blocks
#[derive(Debug, Clone, Copy, Default, iroha_actor::Message)]
pub struct ReceiveUpdates;

#[async_trait::async_trait]
impl Actor for BlockSynchronizer {
    fn actor_channel_capacity(&self) -> u32 {
        self.actor_channel_capacity
    }

    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.broker.subscribe::<Message, _>(ctx);
        ctx.notify_every::<ReceiveUpdates>(self.gossip_period);
    }
}

#[async_trait::async_trait]
impl Handler<ReceiveUpdates> for BlockSynchronizer {
    type Result = ();
    async fn handle(&mut self, ReceiveUpdates: ReceiveUpdates) {
        if let Some(random_peer) = self.sumeragi.get_random_peer_for_block_sync() {
            self.request_latest_blocks_from_peer(random_peer.id.clone())
                .await;
        }
    }
}

#[async_trait::async_trait]
impl Handler<Message> for BlockSynchronizer {
    type Result = ();
    async fn handle(&mut self, message: Message) {
        message.handle_message(self).await;
    }
}

impl BlockSynchronizer {
    /// Sends request for latest blocks to a chosen peer
    async fn request_latest_blocks_from_peer(&mut self, peer_id: PeerId) {
        Message::GetBlocksAfter(GetBlocksAfter::new(
            self.sumeragi.latest_block_hash_for_use_by_block_sync(),
            self.peer_id.clone(),
        ))
        .send_to(self.broker.clone(), peer_id)
        .await;
    }
}

declare_versioned_with_scale!(VersionedMessage 1..2, Debug, Clone, iroha_macro::FromVariant, iroha_actor::Message);

impl VersionedMessage {
    /// Converts from `&VersionedMessage` to V1 reference
    pub const fn as_v1(&self) -> &Message {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedMessage` to V1 mutable reference
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
    /// Block hash
    pub hash: HashOf<VersionedCommittedBlock>,
    /// Peer id
    pub peer_id: PeerId,
}

impl GetBlocksAfter {
    /// Construct [`GetBlocksAfter`].
    pub const fn new(hash: HashOf<VersionedCommittedBlock>, peer_id: PeerId) -> Self {
        Self { hash, peer_id }
    }
}

/// Message variant to share blocks to peer
#[derive(Debug, Clone, Decode, Encode)]
pub struct ShareBlocks {
    /// Blocks
    pub blocks: Vec<VersionedCommittedBlock>,
    /// Peer id
    pub peer_id: PeerId,
}

impl ShareBlocks {
    /// Construct [`ShareBlocks`].
    pub const fn new(blocks: Vec<VersionedCommittedBlock>, peer_id: PeerId) -> Self {
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
            Message::GetBlocksAfter(GetBlocksAfter { hash, peer_id }) => {
                if block_sync.block_batch_size == 0 {
                    warn!("Error: not sending any blocks as batch_size is equal to zero.");
                    return;
                }
                if *hash
                    == block_sync
                        .sumeragi
                        .latest_block_hash_for_use_by_block_sync()
                {
                    return;
                }

                let mut blocks = block_sync.sumeragi.blocks_after_hash(*hash);
                blocks.truncate(block_sync.block_batch_size as usize);

                if blocks.is_empty() {
                    warn!(%hash, "Block hash not found");
                } else {
                    trace!("Sharing blocks after hash: {}", hash);
                    Message::ShareBlocks(ShareBlocks::new(blocks, block_sync.peer_id.clone()))
                        .send_to(block_sync.broker.clone(), peer_id.clone())
                        .await;
                }
            }
            Message::ShareBlocks(ShareBlocks { blocks, peer_id }) => {
                use crate::sumeragi::message::{BlockCommitted, Message};
                for block in blocks {
                    block_sync
                        .sumeragi
                        .incoming_message(Message::BlockCommitted(BlockCommitted {
                            block: block.clone().into(),
                        }));
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
