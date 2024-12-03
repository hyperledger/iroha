//! This module contains structures and messages for synchronization of blocks between peers.
use std::{
    collections::BTreeSet,
    fmt::Debug,
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

use iroha_config::parameters::actual::BlockSync as Config;
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::{BlockHeader, SignedBlock},
    prelude::*,
};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use iroha_logger::prelude::*;
use iroha_macro::*;
use iroha_p2p::Post;
use parity_scale_codec::{Decode, Encode};
use tokio::sync::mpsc;

use crate::{
    kura::Kura,
    state::{State, StateReadOnly},
    sumeragi::SumeragiHandle,
    IrohaNetwork, NetworkMessage,
};

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
    peer: Peer,
    gossip_period: Duration,
    gossip_size: NonZeroU32,
    network: IrohaNetwork,
    state: Arc<State>,
    seen_blocks: BTreeSet<(NonZeroUsize, HashOf<BlockHeader>)>,
    latest_height: usize,
}

impl BlockSynchronizer {
    /// Start [`Self`] actor.
    pub fn start(self, shutdown_signal: ShutdownSignal) -> (BlockSynchronizerHandle, Child) {
        let (message_sender, message_receiver) = mpsc::channel(1);
        (
            BlockSynchronizerHandle { message_sender },
            Child::new(
                tokio::spawn(self.run(message_receiver, shutdown_signal)),
                OnShutdown::Abort,
            ),
        )
    }

    /// [`Self`] task.
    async fn run(
        mut self,
        mut message_receiver: mpsc::Receiver<message::Message>,
        shutdown_signal: ShutdownSignal,
    ) {
        let mut gossip_period = tokio::time::interval(self.gossip_period);
        loop {
            tokio::select! {
                _ = gossip_period.tick() => self.request_block().await,
                Some(msg) = message_receiver.recv() => {
                    msg.handle_message(&mut self).await;
                }
                () = shutdown_signal.receive() => {
                    debug!("Shutting down block sync");
                    break;
                },
            }
            tokio::task::yield_now().await;
        }
    }

    /// Sends request for latest blocks to a random peer
    async fn request_block(&mut self) {
        let now_height = self.state.view().height();

        // This guards against a softfork and adds general redundancy.
        if now_height == self.latest_height {
            self.seen_blocks.clear();
        }
        self.latest_height = now_height;

        self.seen_blocks
            .retain(|(height, _hash)| height.get() >= now_height);

        if let Some(random_peer) = self.network.online_peers(Self::random_peer) {
            self.request_latest_blocks_from_peer(random_peer.id().clone())
                .await;
        }
    }

    /// Get a random online peer.
    #[allow(clippy::disallowed_types)]
    fn random_peer(peers: &std::collections::HashSet<Peer>) -> Option<Peer> {
        use rand::{seq::IteratorRandom, SeedableRng};

        let rng = &mut rand::rngs::StdRng::from_entropy();
        peers.iter().choose(rng).cloned()
    }

    /// Sends request for latest blocks to a chosen peer
    async fn request_latest_blocks_from_peer(&mut self, peer_id: PeerId) {
        let (prev_hash, latest_hash) = {
            let state_view = self.state.view();
            (state_view.prev_block_hash(), state_view.latest_block_hash())
        };
        message::Message::GetBlocksAfter(message::GetBlocksAfter::new(
            self.peer.id.clone(),
            prev_hash,
            latest_hash,
            self.seen_blocks
                .iter()
                .map(|(_height, hash)| *hash)
                .collect(),
        ))
        .send_to(&self.network, peer_id)
        .await;
    }

    /// Create [`Self`] from [`Configuration`]
    pub fn from_config(
        config: &Config,
        sumeragi: SumeragiHandle,
        kura: Arc<Kura>,
        peer: Peer,
        network: IrohaNetwork,
        state: Arc<State>,
    ) -> Self {
        Self {
            peer,
            sumeragi,
            kura,
            gossip_period: *config.gossip_period(),
            gossip_size: *config.gossip_size(),
            network,
            state,
            seen_blocks: BTreeSet::new(),
            latest_height: 0,
        }
    }
}

pub mod message {
    //! Module containing messages for [`BlockSynchronizer`](super::BlockSynchronizer).

    use super::*;

    /// Get blocks after some block
    #[derive(Debug, Clone, Encode)]
    pub struct GetBlocksAfter {
        /// Peer id
        pub peer_id: PeerId,
        /// Hash of second to latest block
        pub prev_hash: Option<HashOf<BlockHeader>>,
        /// Hash of latest available block
        pub latest_hash: Option<HashOf<BlockHeader>>,
        /// The block hashes already seen
        pub seen_blocks: BTreeSet<HashOf<BlockHeader>>,
    }

    impl GetBlocksAfter {
        /// Construct [`GetBlocksAfter`].
        pub const fn new(
            peer_id: PeerId,
            prev_hash: Option<HashOf<BlockHeader>>,
            latest_hash: Option<HashOf<BlockHeader>>,
            seen_blocks: BTreeSet<HashOf<BlockHeader>>,
        ) -> Self {
            Self {
                peer_id,
                prev_hash,
                latest_hash,
                seen_blocks,
            }
        }
    }

    /// Message variant to share blocks to peer
    #[derive(Debug, Clone, Encode)]
    pub struct ShareBlocks {
        /// Peer id
        pub peer_id: PeerId,
        /// Blocks
        pub blocks: Vec<SignedBlock>,
    }

    impl ShareBlocks {
        /// Construct [`ShareBlocks`].
        pub const fn new(blocks: Vec<SignedBlock>, peer_id: PeerId) -> Self {
            Self { peer_id, blocks }
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
        pub(super) async fn handle_message(&self, block_sync: &mut BlockSynchronizer) {
            match self {
                Message::GetBlocksAfter(GetBlocksAfter {
                    peer_id,
                    prev_hash,
                    latest_hash,
                    seen_blocks,
                }) => {
                    let local_latest_block_hash = block_sync.state.view().latest_block_hash();

                    if *latest_hash == local_latest_block_hash
                        || *prev_hash == local_latest_block_hash
                    {
                        return;
                    }

                    let start_height = if let Some(hash) = *prev_hash {
                        let Some(height) = block_sync.kura.get_block_height_by_hash(hash) else {
                            error!(
                                peer=%block_sync.peer,
                                block=%hash,
                                "Block hash not found"
                            );

                            return;
                        };

                        height
                            .checked_add(1)
                            .expect("INTERNAL BUG: Blockchain height overflow")
                    } else {
                        nonzero_ext::nonzero!(1_usize)
                    };

                    let blocks = block_sync
                        .state
                        .view()
                        .all_blocks(start_height)
                        .skip_while(|block| Some(block.hash()) == *latest_hash)
                        .skip_while(|block| seen_blocks.contains(&block.hash()))
                        .take(block_sync.gossip_size.get() as usize)
                        .map(|block| (*block).clone())
                        .collect::<Vec<_>>();

                    if !blocks.is_empty() {
                        trace!(hash=?prev_hash, "Sharing blocks after hash");

                        Message::ShareBlocks(ShareBlocks::new(blocks, block_sync.peer.id.clone()))
                            .send_to(&block_sync.network, peer_id.clone())
                            .await;
                    }
                }
                Message::ShareBlocks(ShareBlocks { blocks, .. }) => {
                    use crate::sumeragi::message::BlockSyncUpdate;

                    for block in blocks.clone() {
                        let height = block
                            .header()
                            .height()
                            .try_into()
                            .expect("INTERNAL BUG: block height exceeds usize::MAX");

                        block_sync.seen_blocks.insert((height, block.hash()));
                        let msg = BlockSyncUpdate::from(&block);
                        block_sync.sumeragi.incoming_block_message(msg);
                    }
                }
            }
        }

        /// Send this message over the network to the specified `peer`.
        #[iroha_futures::telemetry_future]
        #[log("TRACE")]
        pub(super) async fn send_to(self, network: &IrohaNetwork, peer: PeerId) {
            let data = NetworkMessage::BlockSync(Box::new(self));
            let message = Post {
                data,
                peer_id: peer.clone(),
            };
            network.post(message);
        }
    }

    mod candidate {
        use parity_scale_codec::Input;

        use super::*;

        #[derive(Decode)]
        struct GetBlocksAfterCandidate {
            peer: PeerId,
            prev_hash: Option<HashOf<BlockHeader>>,
            latest_hash: Option<HashOf<BlockHeader>>,
            seen_blocks: BTreeSet<HashOf<BlockHeader>>,
        }

        #[derive(Decode)]
        struct ShareBlocksCandidate {
            peer: PeerId,
            blocks: Vec<SignedBlock>,
        }

        enum ShareBlocksError {
            HeightMissed,
            PrevBlockHashMismatch,
            Empty,
        }

        impl GetBlocksAfterCandidate {
            fn validate(self) -> Result<GetBlocksAfter, parity_scale_codec::Error> {
                if self.prev_hash.is_some() && self.latest_hash.is_none() {
                    return Err(parity_scale_codec::Error::from(
                        "Latest hash must be defined if previous hash is",
                    ));
                }

                Ok(GetBlocksAfter {
                    peer_id: self.peer,
                    prev_hash: self.prev_hash,
                    latest_hash: self.latest_hash,
                    seen_blocks: self.seen_blocks,
                })
            }
        }

        impl From<ShareBlocksError> for parity_scale_codec::Error {
            fn from(value: ShareBlocksError) -> Self {
                match value {
                    ShareBlocksError::Empty => "Blocks are empty",
                    ShareBlocksError::HeightMissed => "There is a gap between blocks",
                    ShareBlocksError::PrevBlockHashMismatch => {
                        "Mismatch between previous block in the header and actual hash"
                    }
                }
                .into()
            }
        }

        impl ShareBlocksCandidate {
            fn validate(self) -> Result<ShareBlocks, ShareBlocksError> {
                if self.blocks.is_empty() {
                    return Err(ShareBlocksError::Empty);
                }

                self.blocks.windows(2).try_for_each(|wnd| {
                    if wnd[1].header().height.get() != wnd[0].header().height.get() + 1 {
                        return Err(ShareBlocksError::HeightMissed);
                    }
                    if wnd[1].header().prev_block_hash != Some(wnd[0].hash()) {
                        return Err(ShareBlocksError::PrevBlockHashMismatch);
                    }
                    Ok(())
                })?;

                Ok(ShareBlocks {
                    peer_id: self.peer,
                    blocks: self.blocks,
                })
            }
        }

        impl Decode for ShareBlocks {
            fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
                ShareBlocksCandidate::decode(input)?
                    .validate()
                    .map_err(Into::into)
            }
        }

        impl Decode for GetBlocksAfter {
            fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
                GetBlocksAfterCandidate::decode(input)?
                    .validate()
                    .map_err(Into::into)
            }
        }

        #[cfg(test)]
        mod tests {
            use iroha_crypto::{Hash, KeyPair};

            use super::*;
            use crate::block::ValidBlock;

            #[test]
            fn candidate_empty() {
                let (leader_public_key, _) = KeyPair::random().into_parts();
                let leader_peer = PeerId::new(leader_public_key);
                let candidate = ShareBlocksCandidate {
                    blocks: Vec::new(),
                    peer: leader_peer,
                };
                assert!(matches!(candidate.validate(), Err(ShareBlocksError::Empty)))
            }

            #[test]
            fn candidate_height_missed() {
                let (leader_public_key, leader_private_key) = KeyPair::random().into_parts();
                let leader_peer_id = PeerId::new(leader_public_key);
                let block0: SignedBlock = ValidBlock::new_dummy(&leader_private_key).into();
                let block1 =
                    ValidBlock::new_dummy_and_modify_header(&leader_private_key, |header| {
                        header.height = block0.header().height.checked_add(2).unwrap();
                    })
                    .into();
                let candidate = ShareBlocksCandidate {
                    blocks: vec![block0, block1],
                    peer: leader_peer_id,
                };
                assert!(matches!(
                    candidate.validate(),
                    Err(ShareBlocksError::HeightMissed)
                ))
            }

            #[test]
            fn candidate_prev_block_hash_mismatch() {
                let (leader_public_key, leader_private_key) = KeyPair::random().into_parts();
                let leader_peer_id = PeerId::new(leader_public_key);
                let block0: SignedBlock = ValidBlock::new_dummy(&leader_private_key).into();
                let block1 =
                    ValidBlock::new_dummy_and_modify_header(&leader_private_key, |header| {
                        header.height = block0.header().height.checked_add(1).unwrap();
                        header.prev_block_hash =
                            Some(HashOf::from_untyped_unchecked(Hash::prehashed([0; 32])));
                    })
                    .into();
                let candidate = ShareBlocksCandidate {
                    blocks: vec![block0, block1],
                    peer: leader_peer_id,
                };
                assert!(matches!(
                    candidate.validate(),
                    Err(ShareBlocksError::PrevBlockHashMismatch)
                ))
            }

            #[test]
            fn candidate_ok() {
                let (leader_public_key, leader_private_key) = KeyPair::random().into_parts();
                let leader_peer_id = PeerId::new(leader_public_key);
                let block0: SignedBlock = ValidBlock::new_dummy(&leader_private_key).into();
                let block1 =
                    ValidBlock::new_dummy_and_modify_header(&leader_private_key, |header| {
                        header.height = block0.header().height.checked_add(1).unwrap();
                        header.prev_block_hash = Some(block0.hash());
                    })
                    .into();
                let candidate = ShareBlocksCandidate {
                    blocks: vec![block0, block1],
                    peer: leader_peer_id,
                };
                assert!(candidate.validate().is_ok())
            }
        }
    }
}
