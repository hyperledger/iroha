//! This module contains structures and messages for synchronization of blocks between peers.
#![allow(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic
)]
use std::{
    fmt::Debug,
    sync::Arc,
    time::{Duration, Instant},
};

use iroha_config::block_sync::Configuration;
use iroha_crypto::*;
use iroha_data_model::prelude::*;
use iroha_logger::prelude::*;
use iroha_macro::*;
use iroha_version::prelude::*;
use parity_scale_codec::{Decode, Encode};

use crate::{
    handler::ThreadHandler, p2p::P2PSystem, sumeragi::Sumeragi, NetworkMessage,
    VersionedCommittedBlock,
};

/// Structure responsible for block synchronization between peers.
#[derive(Debug)]
pub struct BlockSynchronizer {
    sumeragi: Arc<Sumeragi>,
    peer_id: PeerId,
    gossip_period: Duration,
    block_batch_size: u32,
    p2p: Arc<P2PSystem>,
}

impl BlockSynchronizer {
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
        })
    }
}

/// Initiate the read thread with the main loop `block_sync_read_loop`
///
/// # Panics
///
/// If thread wasn't spawned
#[allow(clippy::expect_used)]
pub fn start_read_loop(block_sync: Arc<BlockSynchronizer>) -> ThreadHandler {
    // Oneshot channel to allow forcefully stopping the thread.
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();

    let thread_handle = std::thread::Builder::new()
        .name("Block Synchronizer Thread".to_owned())
        .spawn(move || {
            block_sync_read_loop(&block_sync, shutdown_receiver);
        })
        .expect("Failed to spawn read loop thread handle. You might be hitting up against `ulimits`. Consider increasing the RAM");

    let shutdown = move || {
        let _result = shutdown_sender.send(());
    };

    ThreadHandler::new(Box::new(shutdown), thread_handle)
}

fn block_sync_read_loop(
    block_sync: &BlockSynchronizer,
    mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
) {
    let mut last_requested_blocks = Instant::now();
    let mut request_blocks_peer_index = 0_usize;
    loop {
        // We have no obligations to network delivery so we simply exit on shutdown signal.
        if shutdown_receiver.try_recv().is_ok() {
            iroha_logger::debug!("P2P thread is being shut down");
            return;
        }
        block_sync
            .p2p
            .poll_network_for_block_sync_message()
            .map_or_else(
                || {
                    std::thread::sleep(Duration::from_millis(10));
                },
                |message| {
                    message.into_v1().handle_message(block_sync);
                },
            );
        #[allow(clippy::expect_used)]
        if last_requested_blocks.elapsed() > block_sync.gossip_period {
            last_requested_blocks = Instant::now();
            let peers: Vec<PublicKey> = {
                block_sync.p2p
                    .connected_to_peers
                    .lock()
                    .expect("Mutex poisoned. Aborting")
                    .keys()
                    .cloned()
                    .collect()
            };
            if !peers.is_empty() {
                let peer_key = &peers[request_blocks_peer_index % peers.len()];
                request_blocks_peer_index = request_blocks_peer_index.wrapping_add(1);

                message::Message::GetBlocksAfter(message::GetBlocksAfter {
                    hash: block_sync.sumeragi.latest_block_hash(),
                    peer_id: block_sync.peer_id.clone(),
                })
                .send_to(&block_sync.p2p, peer_key);
                iroha_logger::debug!("call out");
            }
        }
    }
}

pub mod message {
    //! Module containing messages for [`BlockSynchronizer`](super::BlockSynchronizer).

    use super::*;

    /// Message to initiate receiving of latest blocks from other peers
    ///
    /// Every `gossip_period` peer will poll one randomly selected peer for latest blocks
    #[derive(Debug, Clone, Copy, Default)]
    pub struct ReceiveUpdates;

    declare_versioned_with_scale!(VersionedMessage 1..2, Debug, Clone, iroha_macro::FromVariant);

    impl VersionedMessage {
        /// Converts from `&VersionedMessage` to V1 reference
        #[inline]
        pub const fn as_v1(&self) -> &Message {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Converts from `&mut VersionedMessage` to V1 mutable reference
        #[inline]
        pub fn as_mut_v1(&mut self) -> &mut Message {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Performs the conversion from `VersionedMessage` to V1
        #[inline]
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
        fn handle(&self, block_sync: &BlockSynchronizer) {
            if block_sync.block_batch_size == 0 {
                warn!("Error: not sending any blocks as batch_size is equal to zero.");
                return;
            }
            if self.hash == block_sync.sumeragi.latest_block_hash() {
                return;
            }
            let mut blocks = block_sync.sumeragi.blocks_after_hash(self.hash);
            blocks.truncate(block_sync.block_batch_size as usize);
            if blocks.is_empty() {
                warn!(?self, "Block hash not found");
            } else {
                trace!("Sharing blocks after hash: {}", self.hash);
                Message::ShareBlocks(ShareBlocks {
                    blocks,
                    peer_id: block_sync.peer_id.clone(),
                })
                .send_to(&block_sync.p2p, &self.peer_id.public_key);
            }
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

    /// Message's variants that are used by peers to communicate in the process of consensus.
    #[version_with_scale(n = 1, versioned = "VersionedMessage")]
    #[derive(Debug, Clone, Decode, Encode, FromVariant)]
    pub enum Message {
        /// Request for blocks after the block with `Hash` for the peer with `PeerId`.
        GetBlocksAfter(GetBlocksAfter),
        /// The response to `GetBlocksAfter`. Contains the requested blocks and the id of the peer who shared them.
        ShareBlocks(ShareBlocks),
    }

    impl Message {
        #[allow(clippy::expect_used)]
        /// Handles the incoming message.]
        pub(crate) fn handle_message(&self, block_sync: &BlockSynchronizer) {
            match self {
                Message::GetBlocksAfter(get_blocks_after) => get_blocks_after.handle(block_sync),
                Message::ShareBlocks(ShareBlocks { blocks, .. }) => {
                    use crate::sumeragi::message::{BlockCommitted, Message, MessagePacket};
                    let mut guard = block_sync.p2p.packet_buffers
                        .lock()
                        .expect("Mutex poisoned. Aborting");
                    for block in blocks {
                        let sumeragi_packet = Box::new(
                            MessagePacket::new(
                                Vec::new(),
                                Message::BlockCommitted(BlockCommitted {
                                    block: block.clone().into(),
                                }),
                            )
                                .into(),
                        );
                        guard
                            .sumeragi_packets
                            .push(*sumeragi_packet);
                    }
                }
            }
        }

        /// Send this message over the network to the specified `peer`.
        #[log("TRACE")]
        pub(super) fn send_to(self, p2p: &P2PSystem, peer: &PublicKey) {
            p2p.post_to_network(
                &NetworkMessage::BlockSync(Box::new(VersionedMessage::from(self))),
                &[peer.clone()],
            );
        }
    }
}
