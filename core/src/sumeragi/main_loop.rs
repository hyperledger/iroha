//! The main event loop that powers sumeragi.
use std::sync::mpsc;

use iroha_crypto::HashOf;
use iroha_data_model::{block::*, events::pipeline::PipelineEventBox, peer::PeerId};
use iroha_p2p::UpdateTopology;
use tracing::{span, Level};

use super::{view_change::ProofBuilder, *};
use crate::{block::*, sumeragi::tracing::instrument};

/// `Sumeragi` is the implementation of the consensus.
pub struct Sumeragi {
    /// Unique id of the blockchain. Used for simple replay attack protection.
    pub chain_id: ChainId,
    /// The pair of keys used for communication given this Sumeragi instance.
    pub key_pair: KeyPair,
    /// Address of queue
    pub queue: Arc<Queue>,
    /// The peer id of myself.
    pub peer_id: PeerId,
    /// An actor that sends events
    pub events_sender: EventsSender,
    /// Time by which a newly created block should be committed. Prevents malicious nodes
    /// from stalling the network by not participating in consensus
    pub commit_time: Duration,
    /// Time by which a new block should be created regardless if there were enough transactions or not.
    /// Used to force block commits when there is a small influx of new transactions.
    pub block_time: Duration,
    /// The maximum number of transactions in the block
    pub max_txs_in_block: usize,
    /// Kura instance used for IO
    pub kura: Arc<Kura>,
    /// [`iroha_p2p::Network`] actor address
    pub network: IrohaNetwork,
    /// Receiver channel, for control flow messages.
    pub control_message_receiver: mpsc::Receiver<ControlFlowMessage>,
    /// Receiver channel.
    pub message_receiver: mpsc::Receiver<BlockMessage>,
    /// Only used in testing. Causes the genesis peer to withhold blocks when it
    /// is the proxy tail.
    pub debug_force_soft_fork: bool,
    /// The current network topology.
    pub current_topology: Topology,
    /// In order to *be fast*, we must minimize communication with
    /// other subsystems where we can. This way the performance of
    /// sumeragi is more dependent on the code that is internal to the
    /// subsystem.
    pub transaction_cache: Vec<AcceptedTransaction>,
    /// Metrics for reporting number of view changes in current round
    pub view_changes_metric: iroha_telemetry::metrics::ViewChangesGauge,
}

#[allow(clippy::missing_fields_in_debug)]
impl Debug for Sumeragi {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sumeragi")
            .field("public_key", &self.key_pair.public_key())
            .field("peer_id", &self.peer_id)
            .finish()
    }
}

impl Sumeragi {
    /// Send a sumeragi packet over the network to the specified `peer`.
    /// # Errors
    /// Fails if network sending fails
    #[instrument(skip(self, packet))]
    fn post_packet_to(&self, packet: BlockMessage, peer: &PeerId) {
        if peer == &self.peer_id {
            return;
        }

        let post = iroha_p2p::Post {
            data: NetworkMessage::SumeragiBlock(Box::new(packet)),
            peer_id: peer.clone(),
        };
        self.network.post(post);
    }

    #[allow(clippy::needless_pass_by_value, single_use_lifetimes)] // TODO: uncomment when anonymous lifetimes are stable
    fn broadcast_packet_to<'peer_id>(
        &self,
        msg: impl Into<BlockMessage>,
        ids: impl IntoIterator<Item = &'peer_id PeerId> + Send,
    ) {
        let msg = msg.into();

        for peer_id in ids {
            self.post_packet_to(msg.clone(), peer_id);
        }
    }

    fn broadcast_packet(&self, msg: impl Into<BlockMessage>) {
        let broadcast = iroha_p2p::Broadcast {
            data: NetworkMessage::SumeragiBlock(Box::new(msg.into())),
        };
        self.network.broadcast(broadcast);
    }

    fn broadcast_control_flow_packet(&self, msg: ControlFlowMessage) {
        let broadcast = iroha_p2p::Broadcast {
            data: NetworkMessage::SumeragiControlFlow(Box::new(msg)),
        };
        self.network.broadcast(broadcast);
    }

    /// Connect or disconnect peers according to the current network topology.
    fn connect_peers(&self, topology: &Topology) {
        let peers = topology.ordered_peers.clone().into_iter().collect();
        self.network.update_topology(UpdateTopology(peers));
    }

    /// The maximum time a sumeragi round can take to produce a block when
    /// there are no faulty peers in the a set.
    fn pipeline_time(&self) -> Duration {
        self.block_time + self.commit_time
    }

    fn send_event(&self, event: impl Into<EventBox>) {
        let _ = self.events_sender.send(event.into());
    }

    fn receive_network_packet(
        &self,
        state_view: &StateView<'_>,
        view_change_proof_chain: &mut ProofChain,
    ) -> (Option<BlockMessage>, bool) {
        const MAX_CONTROL_MSG_IN_A_ROW: usize = 25;

        let mut should_sleep = true;
        for _ in 0..MAX_CONTROL_MSG_IN_A_ROW {
            if let Ok(msg) = self.control_message_receiver
                .try_recv()
                .map_err(|recv_error| {
                    assert!(
                        recv_error != mpsc::TryRecvError::Disconnected,
                        "Sumeragi control message pump disconnected. This is not a recoverable error."
                    )
                }) {
                should_sleep = false;
                if let Err(error) = view_change_proof_chain.merge(
                    msg.view_change_proofs,
                    &self.current_topology.ordered_peers,
                    self.current_topology.max_faults(),
                    state_view.latest_block_hash(),
                ) {
                    trace!(%error, "Failed to add proofs into view change proof chain")
                }
            } else {
                break;
            }
        }

        let block_msg =
            self.receive_block_message_network_packet(state_view, view_change_proof_chain);

        should_sleep &= block_msg.is_none();
        (block_msg, should_sleep)
    }

    fn receive_block_message_network_packet(
        &self,
        state_view: &StateView,
        view_change_proof_chain: &ProofChain,
    ) -> Option<BlockMessage> {
        let current_view_change_index = view_change_proof_chain.verify_with_state(
            &self.current_topology.ordered_peers,
            self.current_topology.max_faults(),
            state_view.latest_block_hash(),
        ) as u64;

        loop {
            let block_msg = self
                .message_receiver
                .try_recv()
                .map_err(|recv_error| {
                    assert!(
                        recv_error != mpsc::TryRecvError::Disconnected,
                        "Sumeragi message pump disconnected. This is not a recoverable error."
                    )
                })
                .ok()?;

            let block_vc_index: Option<u64> = match &block_msg {
                BlockMessage::BlockCreated(bc) => Some(bc.block.header().view_change_index),
                // Signed and Committed contain no block.
                // Block sync updates are exempt from early pruning.
                BlockMessage::BlockSigned(_)
                | BlockMessage::BlockCommitted(_)
                | BlockMessage::BlockSyncUpdate(_) => None,
            };
            if let Some(block_vc_index) = block_vc_index {
                if block_vc_index < current_view_change_index {
                    // ignore block_message
                    continue;
                }
            }
            return Some(block_msg);
        }
    }

    fn init_listen_for_genesis(
        &mut self,
        genesis_public_key: &PublicKey,
        state: &State,
        shutdown_receiver: &mut tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), EarlyReturn> {
        info!(addr = %self.peer_id.address, "Listen for genesis");

        loop {
            std::thread::sleep(Duration::from_millis(50));
            early_return(shutdown_receiver).map_err(|e| {
                debug!(?e, "Early return.");
                e
            })?;

            match self.message_receiver.try_recv() {
                Ok(message) => {
                    let block = match message {
                        BlockMessage::BlockCreated(BlockCreated { block })
                        | BlockMessage::BlockSyncUpdate(BlockSyncUpdate { block }) => block,
                        msg => {
                            trace!(?msg, "Not handling the message, waiting for genesis...");
                            continue;
                        }
                    };

                    let mut state_block = state.block();
                    let block = match ValidBlock::validate(
                        block,
                        &self.current_topology,
                        &self.chain_id,
                        genesis_public_key,
                        &mut state_block,
                    )
                    .unpack(|e| self.send_event(e))
                    .and_then(|block| {
                        block
                            .commit(&self.current_topology)
                            .unpack(|e| self.send_event(e))
                            .map_err(|(block, error)| (block.into(), error))
                    }) {
                        Ok(block) => block,
                        Err(error) => {
                            error!(?error, "Received invalid genesis block");
                            continue;
                        }
                    };

                    *state_block.world.trusted_peers_ids = block.as_ref().commit_topology().clone();
                    self.commit_block(block, state_block);
                    return Ok(());
                }
                Err(mpsc::TryRecvError::Disconnected) => return Err(EarlyReturn::Disconnected),
                _ => (),
            }
        }
    }

    fn sumeragi_init_commit_genesis(
        &mut self,
        genesis_transaction: GenesisTransaction,
        genesis_public_key: &PublicKey,
        state: &State,
    ) {
        std::thread::sleep(Duration::from_millis(250));

        {
            let state_view = state.view();
            assert_eq!(state_view.height(), 0);
            assert_eq!(state_view.latest_block_hash(), None);
        }

        let transaction = AcceptedTransaction::accept_genesis(
            genesis_transaction,
            &self.chain_id,
            genesis_public_key,
        )
        .expect("Genesis invalid");
        let transactions = vec![transaction];

        let mut state_block = state.block();
        let genesis = BlockBuilder::new(transactions, self.current_topology.clone(), vec![])
            .chain(0, &mut state_block)
            .sign(&self.key_pair)
            .unpack(|e| self.send_event(e));

        let genesis_msg = BlockCreated::from(genesis.clone());

        let genesis = genesis
            .commit(&self.current_topology)
            .unpack(|e| self.send_event(e))
            .expect("Genesis invalid");

        assert!(
            !genesis.as_ref().transactions().any(|tx| tx.error.is_some()),
            "Genesis contains invalid transactions"
        );

        info!(
            role = ?self.current_topology.role(&self.peer_id),
            block_hash = %genesis.as_ref().hash(),
            "Genesis block created",
        );

        self.commit_block(genesis, state_block);
        self.broadcast_packet(genesis_msg);
    }

    fn commit_block(&mut self, block: CommittedBlock, state_block: StateBlock<'_>) {
        self.update_state::<NewBlockStrategy>(block, state_block);
    }

    fn replace_top_block(&mut self, block: CommittedBlock, state_block: StateBlock<'_>) {
        self.update_state::<ReplaceTopBlockStrategy>(block, state_block);
    }

    fn update_state<Strategy: ApplyBlockStrategy>(
        &mut self,
        block: CommittedBlock,
        mut state_block: StateBlock<'_>,
    ) {
        info!(
            addr=%self.peer_id.address,
            role=%self.current_topology.role(&self.peer_id),
            block_height=%block.as_ref().header().height,
            block_hash=%block.as_ref().hash(),
            "{}", Strategy::LOG_MESSAGE,
        );

        let state_events = state_block.apply_without_execution(&block);

        let new_topology = Topology::recreate_topology(
            block.as_ref(),
            0,
            state_block.world.peers().cloned().collect(),
        );

        // https://github.com/hyperledger/iroha/issues/3396
        // Kura should store the block only upon successful application to the internal state to avoid storing a corrupted block.
        // Public-facing state update should happen after that and be followed by `BlockCommited` event to prevent client access to uncommitted data.
        Strategy::kura_store_block(&self.kura, block);

        // Parameters are updated before updating public copy of sumeragi
        self.update_params(&state_block);
        self.cache_transaction(&state_block);

        self.current_topology = new_topology;
        self.connect_peers(&self.current_topology);

        // Commit new block making it's effect visible for the rest of application
        state_block.commit();
        // NOTE: This sends "Block committed" event,
        // so it should be done AFTER public facing state update
        state_events.into_iter().for_each(|e| self.send_event(e));
    }

    fn update_params(&mut self, state_block: &StateBlock<'_>) {
        use iroha_data_model::parameter::default::*;

        if let Some(block_time) = state_block.world.query_param(BLOCK_TIME) {
            self.block_time = Duration::from_millis(block_time);
        }
        if let Some(commit_time) = state_block.world.query_param(COMMIT_TIME_LIMIT) {
            self.commit_time = Duration::from_millis(commit_time);
        }
        if let Some(max_txs_in_block) = state_block
            .world
            .query_param::<u32, _>(MAX_TRANSACTIONS_IN_BLOCK)
        {
            self.max_txs_in_block = max_txs_in_block as usize;
        }
    }

    fn cache_transaction(&mut self, state_block: &StateBlock<'_>) {
        self.transaction_cache.retain(|tx| {
            !state_block.has_transaction(tx.as_ref().hash()) && !self.queue.is_expired(tx)
        });
    }

    fn vote_for_block<'state>(
        &self,
        state: &'state State,
        topology: &Topology,
        genesis_public_key: &PublicKey,
        BlockCreated { block }: BlockCreated,
    ) -> Option<VotingBlock<'state>> {
        let block_hash = block.hash();
        let addr = &self.peer_id.address;
        let role = self.current_topology.role(&self.peer_id);
        trace!(%addr, %role, block=%block_hash, "Block received, voting...");

        let mut state_block = state.block();
        let block = match ValidBlock::validate(
            block,
            topology,
            &self.chain_id,
            genesis_public_key,
            &mut state_block,
        )
        .unpack(|e| self.send_event(e))
        {
            Ok(block) => block,
            Err(error) => {
                warn!(%addr, %role, ?error, "Block validation failed");
                return None;
            }
        };

        let signed_block = block.sign(&self.key_pair);
        Some(VotingBlock::new(signed_block, state_block))
    }

    fn prune_view_change_proofs_and_calculate_current_index(
        &self,
        state_view: &StateView<'_>,
        view_change_proof_chain: &mut ProofChain,
    ) -> u64 {
        view_change_proof_chain.prune(state_view.latest_block_hash());
        view_change_proof_chain.verify_with_state(
            &self.current_topology.ordered_peers,
            self.current_topology.max_faults(),
            state_view.latest_block_hash(),
        ) as u64
    }

    #[allow(clippy::too_many_lines)]
    fn handle_message<'state>(
        &mut self,
        message: BlockMessage,
        state: &'state State,
        voting_block: &mut Option<VotingBlock<'state>>,
        current_view_change_index: u64,
        genesis_public_key: &PublicKey,
        voting_signatures: &mut Vec<SignatureOf<BlockPayload>>,
    ) {
        let current_topology = &self.current_topology;
        let role = current_topology.role(&self.peer_id);
        let addr = &self.peer_id.address;

        #[allow(clippy::suspicious_operation_groupings)]
        match (message, role) {
            (BlockMessage::BlockSyncUpdate(BlockSyncUpdate { block }), _) => {
                let block_hash = block.hash();
                info!(%addr, %role, block=%block_hash, "Block sync update received");

                // Release writer before handling block sync
                let _ = voting_block.take();
                match handle_block_sync(&self.chain_id, genesis_public_key, block, state, &|e| {
                    self.send_event(e)
                }) {
                    Ok(BlockSyncOk::CommitBlock(block, state_block)) => {
                        self.commit_block(block, state_block);
                    }
                    Ok(BlockSyncOk::ReplaceTopBlock(block, state_block)) => {
                        warn!(
                            %addr, %role,
                            peer_latest_block_hash=?state_block.latest_block_hash(),
                            peer_latest_block_view_change_index=?state_block.latest_block_view_change_index(),
                            consensus_latest_block=%block.as_ref().hash(),
                            consensus_latest_block_view_change_index=%block.as_ref().header().view_change_index,
                            "Soft fork occurred: peer in inconsistent state. Rolling back and replacing top block."
                        );
                        self.replace_top_block(block, state_block)
                    }
                    Err((_, BlockSyncError::BlockNotValid(error))) => {
                        error!(%addr, %role, block=%block_hash, ?error, "Block not valid.")
                    }
                    Err((_, BlockSyncError::SoftForkBlockNotValid(error))) => {
                        error!(%addr, %role, block=%block_hash, ?error, "Soft-fork block not valid.")
                    }
                    Err((
                        _,
                        BlockSyncError::SoftForkBlockSmallViewChangeIndex {
                            peer_view_change_index,
                            block_view_change_index,
                        },
                    )) => {
                        debug!(
                            %addr, %role,
                            peer_latest_block_hash=?state.view().latest_block_hash(),
                            peer_latest_block_view_change_index=?peer_view_change_index,
                            consensus_latest_block=%block_hash,
                            consensus_latest_block_view_change_index=%block_view_change_index,
                            "Soft fork doesn't occurred: block has the same or smaller view change index"
                        );
                    }
                    Err((
                        _,
                        BlockSyncError::BlockNotProperHeight {
                            peer_height,
                            block_height,
                        },
                    )) => {
                        warn!(%addr, %role, %block_hash, %block_height, %peer_height, "Other peer send irrelevant or outdated block to the peer (it's neither `peer_height` nor `peer_height + 1`).")
                    }
                }
            }
            (
                BlockMessage::BlockCommitted(BlockCommitted { hash, signatures }),
                Role::Leader | Role::ValidatingPeer | Role::ProxyTail | Role::ObservingPeer,
            ) => {
                let is_consensus_required = current_topology.is_consensus_required().is_some();
                if role == Role::ProxyTail && is_consensus_required
                    || role == Role::Leader && !is_consensus_required
                {
                    error!(%addr, %role, "Received BlockCommitted message, but shouldn't");
                } else if let Some(voted_block) = voting_block.take() {
                    match voted_block
                        .block
                        .commit_with_signatures(current_topology, signatures, hash)
                        .unpack(|e| self.send_event(e))
                    {
                        Ok(committed_block) => {
                            self.commit_block(committed_block, voted_block.state_block)
                        }
                        Err((
                            valid_block,
                            BlockValidationError::IncorrectHash { expected, actual },
                        )) => {
                            error!(%addr, %role, %expected, %actual, "The hash of the committed block does not match the hash of the block stored by the peer.");

                            *voting_block = Some(VotingBlock {
                                voted_at: voted_block.voted_at,
                                block: valid_block,
                                state_block: voted_block.state_block,
                            });
                        }
                        Err((_, error)) => {
                            error!(%addr, %role, %hash, ?error, "Block failed to be committed")
                        }
                    }
                } else {
                    error!(%addr, %role, %hash, "Peer missing voting block")
                }
            }
            (BlockMessage::BlockCreated(block_created), Role::ValidatingPeer) => {
                let current_topology = current_topology
                .is_consensus_required()
                .expect("Peer has `ValidatingPeer` role, which mean that current topology require consensus");

                // Release block writer before creating a new one
                let _ = voting_block.take();
                if let Some(v_block) =
                    self.vote_for_block(state, &current_topology, genesis_public_key, block_created)
                {
                    let block_hash = v_block.block.as_ref().hash();
                    let msg = BlockSigned::from(&v_block.block);

                    self.broadcast_packet_to(msg, [current_topology.proxy_tail()]);
                    info!(%addr, block=%block_hash, "Block validated, signed and forwarded");

                    *voting_block = Some(v_block);
                }
            }
            (BlockMessage::BlockCreated(BlockCreated { block }), Role::ObservingPeer) => {
                let current_topology = current_topology.is_consensus_required().expect(
                    "Peer has `ObservingPeer` role, which mean that current topology require consensus"
                );

                // Release block writer before creating new one
                let _ = voting_block.take();

                let v_block = {
                    let block_hash = block.hash_of_payload();
                    let role = self.current_topology.role(&self.peer_id);
                    trace!(%addr, %role, %block_hash, "Block received, voting...");

                    let mut state_block = state.block();
                    match ValidBlock::validate(
                        block,
                        &current_topology,
                        &self.chain_id,
                        genesis_public_key,
                        &mut state_block,
                    )
                    .unpack(|e| self.send_event(e))
                    {
                        Ok(block) => {
                            let block = if current_view_change_index >= 1 {
                                block.sign(&self.key_pair)
                            } else {
                                block
                            };

                            Some(VotingBlock::new(block, state_block))
                        }
                        Err((_, error)) => {
                            warn!(%addr, %role, ?error, "Block validation failed");
                            None
                        }
                    }
                };

                if let Some(v_block) = v_block {
                    let block_hash = v_block.block.as_ref().hash();
                    info!(%addr, %block_hash, "Block validated");
                    if current_view_change_index >= 1 {
                        self.broadcast_packet_to(
                            BlockSigned::from(&v_block.block),
                            [current_topology.proxy_tail()],
                        );
                        info!(%addr, block=%block_hash, "Block signed and forwarded");
                    }
                    *voting_block = Some(v_block);
                }
            }
            (BlockMessage::BlockCreated(block_created), Role::ProxyTail) => {
                // Release block writer before creating new one
                let _ = voting_block.take();
                if let Some(mut new_block) =
                    self.vote_for_block(state, current_topology, genesis_public_key, block_created)
                {
                    // NOTE: Up until this point it was unknown which block is expected to be received,
                    // therefore all the signatures (of any hash) were collected and will now be pruned
                    add_signatures::<false>(&mut new_block, voting_signatures.drain(..));
                    *voting_block = Some(new_block);
                }
            }
            (BlockMessage::BlockSigned(BlockSigned { hash, signatures }), Role::ProxyTail) => {
                trace!(block_hash=%hash, "Received block signatures");

                let roles: &[Role] = if current_view_change_index >= 1 {
                    &[Role::ValidatingPeer, Role::ObservingPeer]
                } else {
                    &[Role::ValidatingPeer]
                };
                let valid_signatures =
                    current_topology.filter_signatures_by_roles(roles, &signatures);

                if let Some(voted_block) = voting_block.as_mut() {
                    let voting_block_hash = voted_block.block.as_ref().hash_of_payload();

                    if hash == voting_block_hash {
                        add_signatures::<true>(voted_block, valid_signatures);
                    } else {
                        debug!(%voting_block_hash, "Received signatures are not for the current block");
                    }
                } else {
                    // NOTE: Due to the nature of distributed systems, signatures can sometimes be received before
                    // the block (sent by the leader). Collect the signatures and wait for the block to be received
                    voting_signatures.extend(valid_signatures);
                }
            }
            (msg, role) => {
                trace!(%addr, %role, ?msg, "message not handled")
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn process_message_independent<'state>(
        &mut self,
        state: &'state State,
        voting_block: &mut Option<VotingBlock<'state>>,
        current_view_change_index: u64,
        round_start_time: &Instant,
        #[cfg_attr(not(debug_assertions), allow(unused_variables))] is_genesis_peer: bool,
    ) {
        let current_topology = &self.current_topology;
        let role = current_topology.role(&self.peer_id);
        let addr = &self.peer_id.address;

        match role {
            Role::Leader => {
                if voting_block.is_none() {
                    let cache_full = self.transaction_cache.len() >= self.max_txs_in_block;
                    let deadline_reached = round_start_time.elapsed() > self.block_time;
                    let cache_non_empty = !self.transaction_cache.is_empty();

                    if cache_full || (deadline_reached && cache_non_empty) {
                        let transactions = self.transaction_cache.clone();
                        info!(%addr, txns=%transactions.len(), "Creating block...");
                        let create_block_start_time = Instant::now();

                        // TODO: properly process triggers!
                        let mut state_block = state.block();
                        let event_recommendations = Vec::new();
                        let new_block = BlockBuilder::new(
                            transactions,
                            self.current_topology.clone(),
                            event_recommendations,
                        )
                        .chain(current_view_change_index, &mut state_block)
                        .sign(&self.key_pair)
                        .unpack(|e| self.send_event(e));

                        let created_in = create_block_start_time.elapsed();
                        if current_topology.is_consensus_required().is_some() {
                            info!(%addr, created_in_ms=%created_in.as_millis(), block=%new_block.as_ref().hash(), "Block created");

                            if created_in > self.pipeline_time() / 2 {
                                warn!("Creating block takes too much time. This might prevent consensus from operating. Consider increasing `commit_time` or decreasing `max_transactions_in_block`");
                            }
                            *voting_block = Some(VotingBlock::new(new_block.clone(), state_block));

                            let msg = BlockCreated::from(new_block);
                            self.broadcast_packet(msg);
                        } else {
                            match new_block
                                .commit(current_topology)
                                .unpack(|e| self.send_event(e))
                            {
                                Ok(committed_block) => {
                                    self.broadcast_packet(BlockCommitted::from(&committed_block));
                                    self.commit_block(committed_block, state_block);
                                }
                                Err(error) => error!(%addr, role=%Role::Leader, ?error),
                            };
                        }
                    }
                }
            }
            Role::ProxyTail => {
                if let Some(voted_block) = voting_block.take() {
                    let voted_at = voted_block.voted_at;
                    let state_block = voted_block.state_block;

                    match voted_block
                        .block
                        .commit(current_topology)
                        .unpack(|e| self.send_event(e))
                    {
                        Ok(committed_block) => {
                            info!(block=%committed_block.as_ref().hash(), "Block reached required number of votes");

                            let msg = BlockCommitted::from(&committed_block);

                            #[cfg(debug_assertions)]
                            if is_genesis_peer && self.debug_force_soft_fork {
                                std::thread::sleep(self.pipeline_time() * 2);
                            } else {
                                self.broadcast_packet(msg);
                            }

                            #[cfg(not(debug_assertions))]
                            {
                                self.broadcast_packet(msg);
                            }
                            self.commit_block(committed_block, state_block);
                        }
                        Err((block, error)) => {
                            // Restore the current voting block and continue the round
                            *voting_block =
                                Some(VotingBlock::voted_at(block, state_block, voted_at));
                            trace!(?error, "Not enough signatures, waiting for more...");
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn reset_state(
    peer_id: &PeerId,
    pipeline_time: Duration,
    current_view_change_index: u64,
    old_view_change_index: &mut u64,
    old_latest_block_hash: &mut HashOf<SignedBlock>,
    latest_block: &SignedBlock,
    // below is the state that gets reset.
    current_topology: &mut Topology,
    voting_block: &mut Option<VotingBlock>,
    voting_signatures: &mut Vec<SignatureOf<BlockPayload>>,
    round_start_time: &mut Instant,
    last_view_change_time: &mut Instant,
    view_change_time: &mut Duration,
) {
    let mut was_commit_or_view_change = false;
    let current_latest_block_hash = latest_block.hash();
    if current_latest_block_hash != *old_latest_block_hash {
        // Round is only restarted on a block commit, so that in the case of
        // a view change a new block is immediately created by the leader
        *round_start_time = Instant::now();
        was_commit_or_view_change = true;
        *old_view_change_index = 0;
    }

    if *old_view_change_index < current_view_change_index {
        error!(addr=%peer_id.address, "Rotating the entire topology.");
        *old_view_change_index = current_view_change_index;
        was_commit_or_view_change = true;
    }

    // Reset state for the next round.
    if was_commit_or_view_change {
        *old_latest_block_hash = current_latest_block_hash;

        *current_topology = Topology::recreate_topology(
            latest_block,
            current_view_change_index,
            current_topology.ordered_peers.iter().cloned().collect(),
        );

        *voting_block = None;
        voting_signatures.clear();
        *last_view_change_time = Instant::now();
        *view_change_time = pipeline_time;
        info!(addr=%peer_id.address, role=%current_topology.role(peer_id), %current_view_change_index, "View change updated");
    }
}

fn should_terminate(shutdown_receiver: &mut tokio::sync::oneshot::Receiver<()>) -> bool {
    use tokio::sync::oneshot::error::TryRecvError;

    match shutdown_receiver.try_recv() {
        Err(TryRecvError::Empty) => false,
        reason => {
            info!(?reason, "Sumeragi Thread is being shut down.");
            true
        }
    }
}

#[iroha_logger::log(name = "consensus", skip_all)]
/// Execute the main loop of [`Sumeragi`]
pub(crate) fn run(
    genesis_network: GenesisWithPubKey,
    mut sumeragi: Sumeragi,
    mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
    state: Arc<State>,
) {
    // Connect peers with initial topology
    sumeragi.connect_peers(&sumeragi.current_topology);

    let span = span!(tracing::Level::TRACE, "genesis").entered();
    let is_genesis_peer =
        if state.view().height() == 0 || state.view().latest_block_hash().is_none() {
            if let Some(genesis) = genesis_network.genesis {
                sumeragi.sumeragi_init_commit_genesis(genesis, &genesis_network.public_key, &state);
                true
            } else {
                if let Err(err) = sumeragi.init_listen_for_genesis(
                    &genesis_network.public_key,
                    &state,
                    &mut shutdown_receiver,
                ) {
                    info!(?err, "Sumeragi Thread is being shut down.");
                    return;
                }
                false
            }
        } else {
            false
        };
    span.exit();

    info!(
        addr=%sumeragi.peer_id.address,
        role_in_next_round=%sumeragi.current_topology.role(&sumeragi.peer_id),
        "Sumeragi initialized",
    );

    let mut voting_block = None;
    // Proxy tail collection of voting block signatures
    let mut voting_signatures = Vec::new();
    let mut should_sleep = false;
    let mut view_change_proof_chain = ProofChain::default();
    let mut old_view_change_index = 0;
    let mut old_latest_block_hash = state
        .view()
        .latest_block_ref()
        .expect("state must have blocks")
        .hash();
    // Duration after which a view change is suggested
    let mut view_change_time = sumeragi.pipeline_time();
    // Instant when the current round started
    let mut round_start_time = Instant::now();
    // Instant when the previous view change or round happened.
    let mut last_view_change_time = Instant::now();

    while !should_terminate(&mut shutdown_receiver) {
        if should_sleep {
            let span = span!(Level::TRACE, "main_thread_sleep");
            let _enter = span.enter();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let span_for_sumeragi_cycle = span!(Level::TRACE, "main_thread_cycle");
        let _enter_for_sumeragi_cycle = span_for_sumeragi_cycle.enter();

        let state_view = state.view();

        sumeragi
            .transaction_cache
            // Checking if transactions are in the blockchain is costly
            .retain(|tx| {
                let expired = sumeragi.queue.is_expired(tx);
                if expired {
                    debug!(?tx, "Transaction expired")
                }
                expired
            });

        sumeragi.queue.get_transactions_for_block(
            &state_view,
            sumeragi.max_txs_in_block,
            &mut sumeragi.transaction_cache,
        );

        let current_view_change_index = sumeragi
            .prune_view_change_proofs_and_calculate_current_index(
                &state_view,
                &mut view_change_proof_chain,
            );

        reset_state(
            &sumeragi.peer_id,
            sumeragi.pipeline_time(),
            current_view_change_index,
            &mut old_view_change_index,
            &mut old_latest_block_hash,
            &state_view
                .latest_block_ref()
                .expect("state must have blocks"),
            &mut sumeragi.current_topology,
            &mut voting_block,
            &mut voting_signatures,
            &mut round_start_time,
            &mut last_view_change_time,
            &mut view_change_time,
        );
        sumeragi.view_changes_metric.set(old_view_change_index);

        if let Some(message) = {
            let (msg, sleep) =
                sumeragi.receive_network_packet(&state_view, &mut view_change_proof_chain);
            should_sleep = sleep;
            msg
        } {
            sumeragi.handle_message(
                message,
                &state,
                &mut voting_block,
                current_view_change_index,
                &genesis_network.public_key,
                &mut voting_signatures,
            );
        }

        // State could be changed after handling message so it is necessary to reset state before handling message independent step
        let state_view = state.view();
        let current_view_change_index = sumeragi
            .prune_view_change_proofs_and_calculate_current_index(
                &state_view,
                &mut view_change_proof_chain,
            );

        // We broadcast our view change suggestion after having processed the latest from others inside `receive_network_packet`
        let node_expects_block = !sumeragi.transaction_cache.is_empty();
        if (node_expects_block || current_view_change_index > 0)
            && last_view_change_time.elapsed() > view_change_time
        {
            let role = sumeragi.current_topology.role(&sumeragi.peer_id);

            if node_expects_block {
                if let Some(VotingBlock { block, .. }) = voting_block.as_ref() {
                    // NOTE: Suspecting the tail node because it hasn't yet committed a block produced by leader
                    warn!(peer_public_key=%sumeragi.peer_id.public_key, %role, block=%block.as_ref().hash(), "Block not committed in due time, requesting view change...");
                } else {
                    // NOTE: Suspecting the leader node because it hasn't produced a block
                    // If the current node has a transaction, the leader should have as well
                    warn!(peer_public_key=%sumeragi.peer_id.public_key, %role, "No block produced in due time, requesting view change...");
                }

                let suspect_proof =
                    ProofBuilder::new(state_view.latest_block_hash(), current_view_change_index)
                        .sign(&sumeragi.key_pair);

                view_change_proof_chain
                    .insert_proof(
                        &sumeragi.current_topology.ordered_peers,
                        sumeragi.current_topology.max_faults(),
                        state_view.latest_block_hash(),
                        suspect_proof,
                    )
                    .unwrap_or_else(|err| error!("{err}"));
            }

            let msg = ControlFlowMessage::new(view_change_proof_chain.clone());
            sumeragi.broadcast_control_flow_packet(msg);

            // NOTE: View change must be periodically suggested until it is accepted.
            // Must be initialized to pipeline time but can increase by chosen amount
            view_change_time += sumeragi.pipeline_time();
        }

        reset_state(
            &sumeragi.peer_id,
            sumeragi.pipeline_time(),
            current_view_change_index,
            &mut old_view_change_index,
            &mut old_latest_block_hash,
            &state_view
                .latest_block_ref()
                .expect("state must have blocks"),
            &mut sumeragi.current_topology,
            &mut voting_block,
            &mut voting_signatures,
            &mut round_start_time,
            &mut last_view_change_time,
            &mut view_change_time,
        );
        sumeragi.view_changes_metric.set(old_view_change_index);

        sumeragi.process_message_independent(
            &state,
            &mut voting_block,
            current_view_change_index,
            &round_start_time,
            is_genesis_peer,
        );
    }
}

fn add_signatures<const EXPECT_VALID: bool>(
    block: &mut VotingBlock,
    signatures: impl IntoIterator<Item = SignatureOf<BlockPayload>>,
) {
    for signature in signatures {
        if let Err(error) = block.block.add_signature(signature) {
            let err_msg = "Signature not valid";

            if EXPECT_VALID {
                error!(?error, err_msg);
            } else {
                debug!(?error, err_msg);
            }
        }
    }
}

/// Type enumerating early return types to reduce cyclomatic
/// complexity of the main loop items and allow direct short
/// circuiting with the `?` operator. Candidate for `impl
/// FromResidual`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EarlyReturn {
    /// Shutdown message received.
    ShutdownMessageReceived,
    /// Disconnected
    Disconnected,
}

fn early_return(
    shutdown_receiver: &mut tokio::sync::oneshot::Receiver<()>,
) -> Result<(), EarlyReturn> {
    use tokio::sync::oneshot::error::TryRecvError;

    match shutdown_receiver.try_recv() {
        Ok(()) | Err(TryRecvError::Closed) => {
            info!("Sumeragi Thread is being shut down.");
            Err(EarlyReturn::ShutdownMessageReceived)
        }
        Err(TryRecvError::Empty) => Ok(()),
    }
}

/// Strategy to apply block to sumeragi.
trait ApplyBlockStrategy {
    const LOG_MESSAGE: &'static str;

    /// Operation to invoke in kura to store block.
    fn kura_store_block(kura: &Kura, block: CommittedBlock);
}

/// Commit new block strategy. Used during normal consensus rounds.
struct NewBlockStrategy;

impl ApplyBlockStrategy for NewBlockStrategy {
    const LOG_MESSAGE: &'static str = "Committing block";

    #[inline]
    fn kura_store_block(kura: &Kura, block: CommittedBlock) {
        kura.store_block(block)
    }
}

/// Replace top block strategy. Used in case of soft-fork.
struct ReplaceTopBlockStrategy;

impl ApplyBlockStrategy for ReplaceTopBlockStrategy {
    const LOG_MESSAGE: &'static str = "Replacing top block";

    #[inline]
    fn kura_store_block(kura: &Kura, block: CommittedBlock) {
        kura.replace_top_block(block)
    }
}

enum BlockSyncOk<'state> {
    CommitBlock(CommittedBlock, StateBlock<'state>),
    ReplaceTopBlock(CommittedBlock, StateBlock<'state>),
}

#[derive(Debug)]
enum BlockSyncError {
    BlockNotValid(BlockValidationError),
    SoftForkBlockNotValid(BlockValidationError),
    SoftForkBlockSmallViewChangeIndex {
        peer_view_change_index: u64,
        block_view_change_index: u64,
    },
    BlockNotProperHeight {
        peer_height: u64,
        block_height: u64,
    },
}

fn handle_block_sync<'state, F: Fn(PipelineEventBox)>(
    chain_id: &ChainId,
    genesis_public_key: &PublicKey,
    block: SignedBlock,
    state: &'state State,
    handle_events: &F,
) -> Result<BlockSyncOk<'state>, (SignedBlock, BlockSyncError)> {
    let block_height = block.header().height;
    let state_height = state.view().height();
    if state_height + 1 == block_height {
        // Normal branch for adding new block on top of current
        let mut state_block = state.block();
        let topology = {
            let last_committed_block = state_block
                .latest_block_ref()
                .expect("Not in genesis round so must have at least genesis block");
            let new_peers = state_block.world.peers().cloned().collect();
            let view_change_index = block.header().view_change_index;
            Topology::recreate_topology(&last_committed_block, view_change_index, new_peers)
        };
        ValidBlock::validate(
            block,
            &topology,
            chain_id,
            genesis_public_key,
            &mut state_block,
        )
        .unpack(handle_events)
        .and_then(|block| {
            block
                .commit(&topology)
                .unpack(handle_events)
                .map_err(|(block, err)| (block.into(), err))
        })
        .map(|block| BlockSyncOk::CommitBlock(block, state_block))
        .map_err(|(block, error)| (block, BlockSyncError::BlockNotValid(error)))
    } else if state_height == block_height && block_height > 1 {
        // Soft-fork on genesis block isn't possible
        // Soft fork branch for replacing current block with valid one

        let peer_view_change_index = state.view().latest_block_view_change_index();
        let block_view_change_index = block.header().view_change_index;
        if peer_view_change_index >= block_view_change_index {
            return Err((
                block,
                BlockSyncError::SoftForkBlockSmallViewChangeIndex {
                    peer_view_change_index,
                    block_view_change_index,
                },
            ));
        }

        let mut state_block = state.block_and_revert();
        let topology = {
            let last_committed_block = state_block
                .latest_block_ref()
                .expect("Not in genesis round so must have at least genesis block");
            let new_peers = state_block.world.peers().cloned().collect();
            let view_change_index = block.header().view_change_index;
            Topology::recreate_topology(&last_committed_block, view_change_index, new_peers)
        };
        ValidBlock::validate(
            block,
            &topology,
            chain_id,
            genesis_public_key,
            &mut state_block,
        )
        .unpack(handle_events)
        .and_then(|block| {
            block
                .commit(&topology)
                .unpack(handle_events)
                .map_err(|(block, err)| (block.into(), err))
        })
        .map_err(|(block, error)| (block, BlockSyncError::SoftForkBlockNotValid(error)))
        .map(|block| BlockSyncOk::ReplaceTopBlock(block, state_block))
    } else {
        // Error branch other peer send irrelevant block
        Err((
            block,
            BlockSyncError::BlockNotProperHeight {
                peer_height: state_height,
                block_height,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use iroha_primitives::{unique_vec, unique_vec::UniqueVec};
    use test_samples::gen_account_in;
    use tokio::test;

    use super::*;
    use crate::{query::store::LiveQueryStore, smartcontracts::Registrable, tests::test_account};

    /// Used to inject faulty payload for testing
    fn clone_and_modify_payload(
        block: &SignedBlock,
        key_pair: &KeyPair,
        f: impl FnOnce(&mut BlockPayload),
    ) -> SignedBlock {
        let SignedBlock::V1(signed) = block;
        let mut payload = signed.payload().clone();
        f(&mut payload);

        SignedBlock::V1(SignedBlockV1::new(payload, key_pair))
    }

    fn create_data_for_test(
        chain_id: &ChainId,
        topology: &Topology,
        leader_key_pair: &KeyPair,
    ) -> (State, Arc<Kura>, SignedBlock, PublicKey) {
        // Predefined world state
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let genesis_public_key = alice_keypair.public_key().clone();
        let account = test_account(&alice_id).activate();
        let domain_id = "wonderland".parse().expect("Valid");
        let mut domain = Domain::new(domain_id).build(&alice_id);
        assert!(domain.add_account(account).is_none());
        let world = World::with([domain], topology.ordered_peers.clone());
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world, Arc::clone(&kura), query_handle);

        // Create "genesis" block
        // Creating an instruction
        let fail_box = Fail::new("Dummy isi".to_owned());

        let mut state_block = state.block();
        // Making two transactions that have the same instruction
        let tx = TransactionBuilder::new(chain_id.clone(), alice_id.clone())
            .with_instructions([fail_box])
            .sign(&alice_keypair);
        let tx = AcceptedTransaction::accept(
            tx,
            chain_id,
            &state_block.transaction_executor().transaction_limits,
        )
        .expect("Valid");

        // Creating a block of two identical transactions and validating it
        let block = BlockBuilder::new(vec![tx.clone(), tx], topology.clone(), Vec::new())
            .chain(0, &mut state_block)
            .sign(leader_key_pair)
            .unpack(|_| {});

        let genesis = block
            .commit(topology)
            .unpack(|_| {})
            .expect("Block is valid");
        let _events = state_block.apply(&genesis).expect("Failed to apply block");
        state_block.commit();
        kura.store_block(genesis);

        let block = {
            let mut state_block = state.block();
            // Making two transactions that have the same instruction
            let create_asset_definition1 = Register::asset_definition(AssetDefinition::numeric(
                "xor1#wonderland".parse().expect("Valid"),
            ));
            let create_asset_definition2 = Register::asset_definition(AssetDefinition::numeric(
                "xor2#wonderland".parse().expect("Valid"),
            ));

            let tx1 = TransactionBuilder::new(chain_id.clone(), alice_id.clone())
                .with_instructions([create_asset_definition1])
                .sign(&alice_keypair);
            let tx1 = AcceptedTransaction::accept(
                tx1,
                chain_id,
                &state_block.transaction_executor().transaction_limits,
            )
            .map(Into::into)
            .expect("Valid");
            let tx2 = TransactionBuilder::new(chain_id.clone(), alice_id)
                .with_instructions([create_asset_definition2])
                .sign(&alice_keypair);
            let tx2 = AcceptedTransaction::accept(
                tx2,
                chain_id,
                &state_block.transaction_executor().transaction_limits,
            )
            .map(Into::into)
            .expect("Valid");

            // Creating a block of two identical transactions and validating it
            BlockBuilder::new(vec![tx1, tx2], topology.clone(), Vec::new())
                .chain(0, &mut state_block)
                .sign(leader_key_pair)
                .unpack(|_| {})
        };

        (state, kura, block.into(), genesis_public_key)
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    async fn block_sync_invalid_block() {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        let leader_key_pair = KeyPair::random();
        let topology = Topology::new(unique_vec![PeerId::new(
            "127.0.0.1:8080".parse().unwrap(),
            leader_key_pair.public_key().clone(),
        )]);
        let (state, _, block, genesis_public_key) =
            create_data_for_test(&chain_id, &topology, &leader_key_pair);

        // Malform block to make it invalid
        let block = clone_and_modify_payload(&block, &leader_key_pair, |payload| {
            payload.commit_topology.clear();
        });

        let result = handle_block_sync(&chain_id, &genesis_public_key, block, &state, &|_| {});
        assert!(matches!(result, Err((_, BlockSyncError::BlockNotValid(_)))))
    }

    #[test]
    async fn block_sync_invalid_soft_fork_block() {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        let leader_key_pair = KeyPair::random();
        let topology = Topology::new(unique_vec![PeerId::new(
            "127.0.0.1:8080".parse().unwrap(),
            leader_key_pair.public_key().clone(),
        )]);
        let (state, kura, block, genesis_public_key) =
            create_data_for_test(&chain_id, &topology, &leader_key_pair);

        let mut state_block = state.block();
        let committed_block = ValidBlock::validate(
            block.clone(),
            &topology,
            &chain_id,
            &genesis_public_key,
            &mut state_block,
        )
        .unpack(|_| {})
        .unwrap()
        .commit(&topology)
        .unpack(|_| {})
        .expect("Block is valid");
        let _events = state_block.apply_without_execution(&committed_block);
        state_block.commit();
        kura.store_block(committed_block);

        // Malform block to make it invalid
        let block = clone_and_modify_payload(&block, &leader_key_pair, |payload| {
            payload.commit_topology.clear();
            payload.header.view_change_index = 1;
        });

        let result = handle_block_sync(&chain_id, &genesis_public_key, block, &state, &|_| {});
        assert!(matches!(
            result,
            Err((_, BlockSyncError::SoftForkBlockNotValid(_)))
        ))
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    async fn block_sync_not_proper_height() {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        let topology = Topology::new(UniqueVec::new());
        let leader_key_pair = KeyPair::random();
        let (state, _, block, genesis_public_key) =
            create_data_for_test(&chain_id, &topology, &leader_key_pair);

        // Change block height
        let block = clone_and_modify_payload(&block, &leader_key_pair, |payload| {
            payload.header.height = 42;
        });

        let result = handle_block_sync(&chain_id, &genesis_public_key, block, &state, &|_| {});
        assert!(matches!(
            result,
            Err((
                _,
                BlockSyncError::BlockNotProperHeight {
                    peer_height: 1,
                    block_height: 42
                }
            ))
        ))
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    async fn block_sync_commit_block() {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        let leader_key_pair = KeyPair::random();
        let topology = Topology::new(unique_vec![PeerId::new(
            "127.0.0.1:8080".parse().unwrap(),
            leader_key_pair.public_key().clone(),
        )]);
        let (state, _, block, genesis_public_key) =
            create_data_for_test(&chain_id, &topology, &leader_key_pair);
        let result = handle_block_sync(&chain_id, &genesis_public_key, block, &state, &|_| {});
        assert!(matches!(result, Ok(BlockSyncOk::CommitBlock(_, _))))
    }

    #[test]
    async fn block_sync_replace_top_block() {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        let leader_key_pair = KeyPair::random();
        let topology = Topology::new(unique_vec![PeerId::new(
            "127.0.0.1:8080".parse().unwrap(),
            leader_key_pair.public_key().clone(),
        )]);
        let (state, kura, block, genesis_public_key) =
            create_data_for_test(&chain_id, &topology, &leader_key_pair);

        let mut state_block = state.block();
        let committed_block = ValidBlock::validate(
            block.clone(),
            &topology,
            &chain_id,
            &genesis_public_key,
            &mut state_block,
        )
        .unpack(|_| {})
        .unwrap()
        .commit(&topology)
        .unpack(|_| {})
        .expect("Block is valid");
        let _events = state_block.apply_without_execution(&committed_block);
        state_block.commit();

        kura.store_block(committed_block);
        assert_eq!(state.view().latest_block_view_change_index(), 0);

        // Increase block view change index
        let block = clone_and_modify_payload(&block, &leader_key_pair, |payload| {
            payload.header.view_change_index = 42;
        });

        let result = handle_block_sync(&chain_id, &genesis_public_key, block, &state, &|_| {});
        assert!(matches!(result, Ok(BlockSyncOk::ReplaceTopBlock(_, _))))
    }

    #[test]
    async fn block_sync_small_view_change_index() {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        let leader_key_pair = KeyPair::random();
        let topology = Topology::new(unique_vec![PeerId::new(
            "127.0.0.1:8080".parse().unwrap(),
            leader_key_pair.public_key().clone(),
        )]);
        let (state, kura, block, genesis_public_key) =
            create_data_for_test(&chain_id, &topology, &leader_key_pair);

        // Increase block view change index
        let block = clone_and_modify_payload(&block, &leader_key_pair, |payload| {
            payload.header.view_change_index = 42;
        });

        let mut state_block = state.block();
        let committed_block = ValidBlock::validate(
            block.clone(),
            &topology,
            &chain_id,
            &genesis_public_key,
            &mut state_block,
        )
        .unpack(|_| {})
        .unwrap()
        .commit(&topology)
        .unpack(|_| {})
        .expect("Block is valid");
        let _events = state_block.apply_without_execution(&committed_block);
        state_block.commit();
        kura.store_block(committed_block);
        assert_eq!(state.view().latest_block_view_change_index(), 42);

        // Decrease block view change index back
        let block = clone_and_modify_payload(&block, &leader_key_pair, |payload| {
            payload.header.view_change_index = 0;
        });

        let result = handle_block_sync(&chain_id, &genesis_public_key, block, &state, &|_| {});
        assert!(matches!(
            result,
            Err((
                _,
                BlockSyncError::SoftForkBlockSmallViewChangeIndex {
                    peer_view_change_index: 42,
                    block_view_change_index: 0
                }
            ))
        ))
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    async fn block_sync_genesis_block_do_not_replace() {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        let topology = Topology::new(UniqueVec::new());
        let leader_key_pair = KeyPair::random();
        let (state, _, block, genesis_public_key) =
            create_data_for_test(&chain_id, &topology, &leader_key_pair);

        // Change block height and view change index
        // Soft-fork on genesis block is not possible
        let block = clone_and_modify_payload(&block, &leader_key_pair, |payload| {
            payload.header.view_change_index = 42;
            payload.header.height = 1;
        });

        let result = handle_block_sync(&chain_id, &genesis_public_key, block, &state, &|_| {});
        assert!(matches!(
            result,
            Err((
                _,
                BlockSyncError::BlockNotProperHeight {
                    peer_height: 1,
                    block_height: 1,
                }
            ))
        ))
    }
}
