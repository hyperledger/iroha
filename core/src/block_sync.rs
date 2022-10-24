//! This module contains structures and messages for synchronization of blocks between peers.
#![allow(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic
)]
use std::{fmt::Debug, sync::Arc, time::Duration};

use iroha_config::block_sync::Configuration;
use iroha_crypto::*;
use iroha_data_model::prelude::*;
use iroha_logger::prelude::*;
use iroha_macro::*;
use iroha_version::prelude::*;
use parity_scale_codec::{Decode, Encode};

use crate::{p2p::P2PSystem, sumeragi::Sumeragi, NetworkMessage, VersionedCommittedBlock};

/// Structure responsible for block synchronization between peers.
#[derive(Debug)]
pub struct BlockSynchronizer {
    sumeragi: Arc<Sumeragi>,
    peer_id: PeerId,
    gossip_period: Duration,
    block_batch_size: u32,
    p2p: Arc<P2PSystem>,
    actor_channel_capacity: u32,
}
/*
    if let Some(random_peer) = self.sumeragi.get_random_peer_for_block_sync() {
            self.request_latest_blocks_from_peer(random_peer.id.clone())
                .await;
        }
    }
*/

impl BlockSynchronizer {
    /// Sends request for latest blocks to a chosen peer
    fn request_latest_blocks_from_peer(&mut self, peer_id: PeerId) {
        message::Message::GetBlocksAfter(message::GetBlocksAfter::new(
            self.sumeragi.latest_block_hash(),
            self.peer_id.clone(),
        ))
        .send_to(&self.p2p, peer_id);
    }

    /// Create [`Self`] from [`Configuration`]
    pub fn from_configuration(
        config: &Configuration,
        sumeragi: Arc<Sumeragi>,
        p2p: Arc<P2PSystem>,
        peer_id: PeerId,
    ) -> Arc<Self> {
        Arc::new(Self {
            peer_id,
            sumeragi,
            gossip_period: Duration::from_millis(config.gossip_period_ms),
            block_batch_size: config.block_batch_size,
            p2p,
            actor_channel_capacity: config.actor_channel_capacity,
        })
    }
}

pub mod message {
    //! Module containing messages for [`BlockSynchronizer`](super::BlockSynchronizer).

    use super::*;

    /// Message to initiate receiving of latest blocks from other peers
    ///
    /// Every `gossip_period` peer will poll one randomly selected peer for latest blocks
    #[derive(Debug, Clone, Copy, Default, iroha_actor::Message)]
    pub struct ReceiveUpdates;

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
        pub fn handle_message(&self, block_sync: &mut BlockSynchronizer) {
            match self {
                Message::GetBlocksAfter(GetBlocksAfter { hash, peer_id }) => {
                    if block_sync.block_batch_size == 0 {
                        warn!("Error: not sending any blocks as batch_size is equal to zero.");
                        return;
                    }
                    if *hash == block_sync.sumeragi.latest_block_hash() {
                        return;
                    }

                    let mut blocks = block_sync.sumeragi.blocks_after_hash(*hash);
                    blocks.truncate(block_sync.block_batch_size as usize);

                    if blocks.is_empty() {
                        warn!(%hash, "Block hash not found");
                    } else {
                        trace!("Sharing blocks after hash: {}", hash);
                        Message::ShareBlocks(ShareBlocks::new(blocks, block_sync.peer_id.clone()))
                            .send_to(&block_sync.p2p, peer_id.clone());
                    }
                }
                Message::ShareBlocks(ShareBlocks { blocks, .. }) => {
                    use crate::sumeragi::message::{BlockCommitted, Message, MessagePacket};
                    for block in blocks {
                        block_sync.sumeragi.incoming_message(MessagePacket::new(
                            Vec::new(),
                            Message::BlockCommitted(BlockCommitted {
                                block: block.clone().into(),
                            }),
                        ));
                    }
                }
            }
        }

        /// Send this message over the network to the specified `peer`.
        #[log("TRACE")]
        pub fn send_to(self, p2p: &P2PSystem, peer: PeerId) {
            let data = NetworkMessage::BlockSync(Box::new(VersionedMessage::from(self)));
            p2p.post_to_network(data, vec![peer.clone()]);
        }
    }
}
