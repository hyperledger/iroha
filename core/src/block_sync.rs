//! This module contains structures and messages for synchronization of blocks between peers.
use std::{fmt::Debug, sync::Arc, time::Duration};

use iroha_config::block_sync::Configuration;
use iroha_crypto::HashOf;
use iroha_data_model::{block::SignedBlock, prelude::*};
use iroha_logger::prelude::*;
use iroha_macro::*;
use iroha_p2p::Post;
use parity_scale_codec::{Decode, Encode};
use tokio::sync::mpsc;

use crate::{kura::Kura, sumeragi::SumeragiHandle, IrohaNetwork, NetworkMessage};

/// [`BlockSynchronizer`] actor handle.
#[derive(Clone)]
pub struct BlockSynchronizerHandle {
    message_sender: mpsc::Sender<message::Message>,
}

impl BlockSynchronizerHandle {
    /// Send [`message::Message`] to [`BlockSynchronizer`] actor.
    ///
    /// # Errors
    /// Fail if [`BlockSynchronizer`] actor is shutdown.
    pub async fn message(&self, message: message::Message) {
        self.message_sender.send(message).await.expect(
            "BlockSynchronizer must handle messages until there is at least one handle to it",
        )
    }
}

/// Structure responsible for block synchronization between peers.
pub struct BlockSynchronizer {
    sumeragi: SumeragiHandle,
    kura: Arc<Kura>,
    peer_id: PeerId,
    gossip_period: Duration,
    block_batch_size: u32,
    network: IrohaNetwork,
    latest_hash: Option<HashOf<SignedBlock>>,
    previous_hash: Option<HashOf<SignedBlock>>,
}

impl BlockSynchronizer {
    /// Start [`Self`] actor.
    pub fn start(self) -> BlockSynchronizerHandle {
        let (message_sender, message_receiver) = mpsc::channel(1);
        tokio::task::spawn(self.run(message_receiver));
        BlockSynchronizerHandle { message_sender }
    }

    /// [`Self`] task.
    async fn run(mut self, mut message_receiver: mpsc::Receiver<message::Message>) {
        let mut gossip_period = tokio::time::interval(self.gossip_period);
        loop {
            tokio::select! {
                _ = gossip_period.tick() => self.request_block().await,
                _ = self.sumeragi.wsv_updated() => {
                    let (latest_hash, previous_hash) = self
                        .sumeragi
                        .apply_wsv(|wsv| (wsv.latest_block_hash(), wsv.previous_block_hash()));
                    self.latest_hash = latest_hash;
                    self.previous_hash = previous_hash;
                }
                msg = message_receiver.recv() => {
                    let Some(msg) = msg else {
                        info!("All handler to BlockSynchronizer are dropped. Shutting down...");
                        break;
                    };
                    msg.handle_message(&mut self).await;
                }
            }
            tokio::task::yield_now().await;
        }
    }

    /// Sends request for latest blocks to a random peer
    async fn request_block(&mut self) {
        if let Some(random_peer) = self.network.online_peers(Self::random_peer) {
            self.request_latest_blocks_from_peer(random_peer.id().clone())
                .await;
        }
    }

    /// Get a random online peer.
    #[allow(clippy::disallowed_types)]
    pub fn random_peer(peers: &std::collections::HashSet<PeerId>) -> Option<Peer> {
        use rand::{seq::IteratorRandom, SeedableRng};

        let rng = &mut rand::rngs::StdRng::from_entropy();
        peers.iter().choose(rng).map(|id| Peer::new(id.clone()))
    }

    /// Sends request for latest blocks to a chosen peer
    async fn request_latest_blocks_from_peer(&mut self, peer_id: PeerId) {
        message::Message::GetBlocksAfter(message::GetBlocksAfter::new(
            self.latest_hash,
            self.previous_hash,
            self.peer_id.clone(),
        ))
        .send_to(&self.network, peer_id)
        .await;
    }

    /// Create [`Self`] from [`Configuration`]
    pub fn from_configuration(
        config: &Configuration,
        sumeragi: SumeragiHandle,
        kura: Arc<Kura>,
        peer_id: PeerId,
        network: IrohaNetwork,
    ) -> Self {
        let (latest_hash, previous_hash) =
            sumeragi.apply_wsv(|wsv| (wsv.latest_block_hash(), wsv.previous_block_hash()));
        Self {
            peer_id,
            sumeragi,
            kura,
            gossip_period: Duration::from_millis(config.gossip_period_ms),
            block_batch_size: config.block_batch_size,
            network,
            latest_hash,
            previous_hash,
        }
    }
}

pub mod message {
    //! Module containing messages for [`BlockSynchronizer`](super::BlockSynchronizer).
    use super::*;
    use crate::sumeragi::view_change::ProofChain;

    /// Get blocks after some block
    #[derive(Debug, Clone, Decode, Encode)]
    pub struct GetBlocksAfter {
        /// Hash of latest available block
        pub latest_hash: Option<HashOf<SignedBlock>>,
        /// Hash of second to latest block
        pub previous_hash: Option<HashOf<SignedBlock>>,
        /// Peer id
        pub peer_id: PeerId,
    }

    impl GetBlocksAfter {
        /// Construct [`GetBlocksAfter`].
        pub const fn new(
            latest_hash: Option<HashOf<SignedBlock>>,
            previous_hash: Option<HashOf<SignedBlock>>,
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
        pub blocks: Vec<SignedBlock>,
        /// Peer id
        pub peer_id: PeerId,
    }

    impl ShareBlocks {
        /// Construct [`ShareBlocks`].
        pub const fn new(blocks: Vec<SignedBlock>, peer_id: PeerId) -> Self {
            Self { blocks, peer_id }
        }
    }

    /// Message's variants that are used by peers to communicate in the process of consensus.
    #[derive(Debug, Clone, Decode, Encode, FromVariant)]
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
                    let local_latest_block_hash = block_sync.latest_hash;
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
                        .map(|block| SignedBlock::clone(&block))
                        .collect::<Vec<_>>();

                    if blocks.is_empty() {
                        // The only case where the blocks array could be empty is if we got queried for blocks
                        // after the latest hash. There is a check earlier in the function that returns early
                        // so it should not be possible for us to get here.
                        error!(hash=?previous_hash, "Blocks array is empty but shouldn't be.");
                    } else {
                        trace!(hash=?previous_hash, "Sharing blocks after hash");
                        Message::ShareBlocks(ShareBlocks::new(blocks, block_sync.peer_id.clone()))
                            .send_to(&block_sync.network, peer_id.clone())
                            .await;
                    }
                }
                Message::ShareBlocks(ShareBlocks { blocks, .. }) => {
                    use crate::sumeragi::message::{Message, MessagePacket};
                    for block in blocks.clone() {
                        block_sync.sumeragi.incoming_message(MessagePacket::new(
                            ProofChain::default(),
                            Some(Message::BlockSyncUpdate(block.into())),
                        ));
                    }
                }
            }
        }

        /// Send this message over the network to the specified `peer`.
        #[iroha_futures::telemetry_future]
        #[log("TRACE")]
        pub async fn send_to(self, network: &IrohaNetwork, peer: PeerId) {
            let data = NetworkMessage::BlockSync(Box::new(self));
            let message = Post {
                data,
                peer_id: peer.clone(),
            };
            network.post(message);
        }
    }
}
