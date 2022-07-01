//! This module contains structures and messages for synchronization of blocks between peers.
#![allow(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic
)]
use std::{fmt::Debug, sync::Arc, time::Duration};

use iroha_actor::{broker::*, prelude::*, Context};
use iroha_config::block_sync::Configuration;
use iroha_crypto::SignatureOf;
use iroha_data_model::prelude::*;
use iroha_logger::prelude::*;

use self::message::{Message, *};
use crate::{
    prelude::*,
    sumeragi::{network_topology::Role, Sumeragi},
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
    sumeragi: Arc<Sumeragi>,
    peer_id: PeerId,
    state: State,
    gossip_period: Duration,
    block_batch_size: u32,
    broker: Broker,
    actor_channel_capacity: u32,
}

/// Block synchronizer
pub trait BlockSynchronizerTrait: Actor + Handler<ContinueSync> + Handler<Message> {
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
            state: State::Idle,
            gossip_period: Duration::from_millis(config.gossip_period_ms),
            block_batch_size: config.block_batch_size,
            broker,
            actor_channel_capacity: config.actor_channel_capacity,
        }
    }
}

/// Message to send to block synchronizer. It will call `continue_sync` method on it
#[derive(Debug, Clone, Copy, iroha_actor::Message)]
pub struct ContinueSync;

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
        self.broker.subscribe::<ContinueSync, _>(ctx);
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
impl Handler<ContinueSync> for BlockSynchronizer {
    type Result = ();
    async fn handle(&mut self, ContinueSync: ContinueSync) {
        self.continue_sync().await;
    }
}

#[async_trait::async_trait]
impl Handler<Message> for BlockSynchronizer {
    type Result = ();
    async fn handle(&mut self, message: Message) {
        message.handle(self).await;
    }
}

impl BlockSynchronizer {
    /// Sends request for latest blocks to a chosen peer
    async fn request_latest_blocks_from_peer(&mut self, peer_id: PeerId) {
        Message::GetBlocksAfter(GetBlocksAfter::new(
            self.sumeragi.latest_block_hash(),
            self.peer_id.clone(),
        ))
        .send_to(self.broker.clone(), peer_id)
        .await;
    }

    /// Continues the synchronization if it was ongoing. Should be called after `WSV` update.
    #[iroha_futures::telemetry_future]
    pub async fn continue_sync(&mut self) {
        let (blocks, peer_id) = if let State::InProgress(blocks, peer_id) = self.state.clone() {
            (blocks, peer_id)
        } else {
            return;
        };

        info!(blocks_left = blocks.len(), "Synchronizing blocks");

        let (this_block, remaining_blocks) = if let Some((blck, blcks)) = blocks.split_first() {
            (blck, blcks)
        } else {
            self.state = State::Idle;
            self.request_latest_blocks_from_peer(peer_id).await;
            return;
        };

        let mut network_topology = self.sumeragi.get_network_topology(&this_block.header());
        // If it is genesis topology we cannot apply view changes as peers have custom order!
        #[allow(clippy::expect_used)]
        if !this_block.header().is_genesis() {
            network_topology = network_topology
                .into_builder()
                .with_view_changes(this_block.header().view_change_proofs.clone())
                .build()
                .expect(
                    "Unreachable as doing view changes on valid topology will not raise an error.",
                );
        }
        if self.sumeragi.latest_block_hash() == this_block.header().previous_block_hash
            && network_topology
                .filter_signatures_by_roles(
                    &[Role::ValidatingPeer, Role::Leader, Role::ProxyTail],
                    this_block
                        .verified_signatures()
                        .map(SignatureOf::transmute_ref),
                )
                .len()
                >= network_topology.min_votes_for_commit()
        {
            self.state = State::InProgress(remaining_blocks.to_vec(), peer_id);
            /*
            TODO: REPLACE
            self.sumeragi
                .do_send(CommitBlock(this_block.clone().into()))
            .await;
            */
        } else {
            warn!(block_hash = %this_block.hash(), "Failed to commit a block received via synchronization request - validation failed");
            self.state = State::Idle;
        }
    }
}

/// The module for block synchronization related peer to peer messages.
pub mod message {
    use iroha_actor::broker::Broker;
    use iroha_crypto::*;
    use iroha_data_model::prelude::*;
    use iroha_logger::prelude::*;
    use iroha_macro::*;
    use iroha_p2p::Post;
    use iroha_version::prelude::*;
    use parity_scale_codec::{Decode, Encode};

    use super::{BlockSynchronizer, State};
    use crate::{block::VersionedCommittedBlock, sumeragi::Sumeragi, NetworkMessage};

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
        pub async fn handle(&self, block_sync: &mut BlockSynchronizer) {
            match self {
                Message::GetBlocksAfter(GetBlocksAfter { hash, peer_id }) => {
                    if block_sync.block_batch_size == 0 {
                        warn!("Error: not sending any blocks as batch_size is equal to zero.");
                        return;
                    }
                    if *hash == block_sync.sumeragi.latest_block_hash() {
                        return;
                    }

                    let blocks: Vec<_> = block_sync
                        .sumeragi
                        .blocks_after_hash(*hash)
                        .into_iter()
                        .take(block_sync.block_batch_size as usize)
                        .collect();

                    if blocks.is_empty() {
                        warn!(%hash, "Block hash not found");
                    } else {
                        Message::ShareBlocks(ShareBlocks::new(blocks, block_sync.peer_id.clone()))
                            .send_to(block_sync.broker.clone(), peer_id.clone())
                            .await;
                    }
                }
                Message::ShareBlocks(ShareBlocks { blocks, peer_id }) => {
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
