//! The main event loop that powers sumeragi.
#![allow(clippy::cognitive_complexity)]
use std::sync::mpsc;

use iroha_data_model::{block::*, transaction::error::TransactionRejectionReason};
use iroha_p2p::UpdateTopology;
use tracing::{span, Level};

use super::*;
use crate::{block::*, sumeragi::tracing::instrument};

/// `Sumeragi` is the implementation of the consensus.
pub struct Sumeragi {
    /// The pair of keys used for communication given this Sumeragi instance.
    pub key_pair: KeyPair,
    /// Address of queue
    pub queue: Arc<Queue>,
    /// The peer id of myself.
    pub peer_id: PeerId,
    /// An actor that sends events
    pub events_sender: EventsSender,
    /// The world state view instance that is used in public contexts
    pub public_wsv_sender: watch::Sender<WorldStateView>,
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
    /// Receiver channel.
    pub message_receiver: mpsc::Receiver<MessagePacket>,
    /// Only used in testing. Causes the genesis peer to withhold blocks when it
    /// is the proxy tail.
    pub debug_force_soft_fork: bool,
    /// The current network topology.
    pub current_topology: Topology,
    /// The sumeragi internal `WorldStateView`. This will probably
    /// morph into a wsv + various patches as we attempt to
    /// multithread isi execution. In the future we might also once
    /// again merge the internal wsv with the public facing one. But
    /// as of now we keep them seperate for greater flexibility when
    /// optimizing.
    pub wsv: WorldStateView,
    /// A copy of wsv that is kept one block behind at all times. Because
    /// we currently don't support rolling back wsv block application we
    /// reset to a copy of the finalized_wsv instead. This is expensive but
    /// enables us to handle soft-forks.
    pub finalized_wsv: WorldStateView,
    /// In order to *be fast*, we must minimize communication with
    /// other subsystems where we can. This way the performance of
    /// sumeragi is more dependent on the code that is internal to the
    /// subsystem.
    pub transaction_cache: Vec<AcceptedTransaction>,
}

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
    #[allow(clippy::needless_pass_by_value)] // TODO: Fix.
    fn post_packet_to(&self, packet: MessagePacket, peer: &PeerId) {
        if peer == &self.peer_id {
            return;
        }
        let post = iroha_p2p::Post {
            data: NetworkMessage::SumeragiPacket(Box::new(packet.into())),
            peer_id: peer.clone(),
        };
        self.network.post(post);
    }

    #[allow(clippy::needless_pass_by_value, single_use_lifetimes)] // TODO: uncomment when anonymous lifetimes are stable
    fn broadcast_packet_to<'peer_id>(
        &self,
        msg: MessagePacket,
        ids: impl IntoIterator<Item = &'peer_id PeerId> + Send,
    ) {
        for peer_id in ids {
            self.post_packet_to(msg.clone(), peer_id);
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn broadcast_packet(&self, msg: MessagePacket) {
        let broadcast = iroha_p2p::Broadcast {
            data: NetworkMessage::SumeragiPacket(Box::new(msg.into())),
        };
        self.network.broadcast(broadcast);
    }

    /// Connect or disconnect peers according to the current network topology.
    fn connect_peers(&self, topology: &Topology) {
        let peers = topology.sorted_peers.clone().into_iter().collect();
        self.network.update_topology(UpdateTopology(peers));
    }

    /// The maximum time a sumeragi round can take to produce a block when
    /// there are no faulty peers in the a set.
    fn pipeline_time(&self) -> Duration {
        self.block_time + self.commit_time
    }

    fn send_events(&self, events: impl Into<Vec<Event>>) {
        let addr = &self.peer_id.address;

        if self.events_sender.receiver_count() > 0 {
            for event in events.into() {
                self.events_sender
                    .send(event)
                    .map_err(|err| warn!(%addr, ?err, "Event not sent"))
                    .unwrap_or(0);
            }
        }
    }

    #[allow(clippy::panic)]
    fn receive_network_packet(&self, view_change_proof_chain: &mut ProofChain) -> Option<Message> {
        let current_topology = &self.current_topology;
        match self.message_receiver.try_recv() {
            Ok(packet) => {
                if let Err(error) = view_change_proof_chain.merge(
                    packet.view_change_proofs,
                    &current_topology.sorted_peers,
                    current_topology.max_faults(),
                    self.wsv.latest_block_hash(),
                ) {
                    trace!(%error, "Failed to add proofs into view change proof chain")
                }
                Some(packet.message)
            }
            Err(recv_error) => match recv_error {
                mpsc::TryRecvError::Empty => None,
                mpsc::TryRecvError::Disconnected => {
                    panic!("Sumeragi message pump disconnected. This is not a recoverable error.")
                    // TODO: Use early return.
                }
            },
        }
    }

    #[allow(clippy::panic, clippy::panic_in_result_fn)]
    fn init_listen_for_genesis(
        &mut self,
        shutdown_receiver: &mut tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), EarlyReturn> {
        trace!("Listen for genesis");
        assert!(
            self.current_topology.is_consensus_required(),
            "Only peer in network, yet required to receive genesis topology. This is a configuration error."
        );
        loop {
            std::thread::sleep(Duration::from_millis(50));
            early_return(shutdown_receiver).map_err(|e| {
                debug!(?e, "Early return.");
                e
            })?;
            // we must connect to peers so that our block_sync can find us
            // the genesis block.
            match self.message_receiver.try_recv() {
                Ok(packet) => {
                    let block = match packet.message {
                        Message::BlockCreated(BlockCreated { block }) => {
                            // If we receive a committed genesis block that is
                            // valid, use it without question.  During the
                            // genesis round we blindly take on the network
                            // topology described in the provided genesis
                            // block.
                            let block = {
                                let span = span!(
                                    Level::TRACE,
                                    "Genesis Round Peer is revalidating the block."
                                );
                                let _enter = span.enter();
                                match <PendingBlock as InGenesis>::revalidate(
                                    &block,
                                    self.wsv.clone(),
                                ) {
                                    Ok(()) => block,
                                    Err(error) => {
                                        error!(?error);
                                        continue;
                                    }
                                }
                            };
                            // Omit signature verification during genesis round
                            block.commit_unchecked().into()
                        }
                        Message::BlockSyncUpdate(BlockSyncUpdate { block }) => {
                            // Omit signature verification during genesis round
                            match <VersionedCommittedBlock as InGenesis>::revalidate(
                                &block,
                                self.wsv.clone(),
                            ) {
                                Ok(()) => block,
                                Err(error) => {
                                    error!(?error);
                                    continue;
                                }
                            }
                        }
                        msg => {
                            trace!(?msg, "Not handling the message, waiting for genesis...");
                            continue;
                        }
                    };

                    if block.is_genesis() {
                        self.commit_block(block);
                        return Err(EarlyReturn::GenesisBlockReceivedAndCommitted);
                    }
                    debug!("Received a block that was not genesis.");
                }
                Err(mpsc::TryRecvError::Disconnected) => return Err(EarlyReturn::Disconnected),
                _ => (),
            }
        }
    }

    fn sumeragi_init_commit_genesis(&mut self, genesis_network: GenesisNetwork) {
        std::thread::sleep(Duration::from_millis(250));

        info!("Initializing iroha using the genesis block.");

        assert_eq!(self.wsv.height(), 0);
        assert_eq!(self.wsv.latest_block_hash(), None);

        let transactions: Vec<_> = genesis_network
            .transactions
            .into_iter()
            .map(AcceptedTransaction::accept_genesis)
            .collect();

        // Don't start genesis round. Instead just commit the genesis block.
        assert!(
            !transactions.is_empty(),
            "Genesis transaction set contains no valid transactions"
        );

        let block = BlockBuilder {
            transactions,
            event_recommendations: Vec::new(),
            view_change_index: 0,
            committed_with_topology: self.current_topology.clone(),
            key_pair: self.key_pair.clone(),
            wsv: self.wsv.clone(),
        }
        .build();
        assert!(
            block.rejected_transactions.is_empty(),
            "Genesis transaction set contains invalid transactions"
        );

        {
            info!(block_partial_hash = %block.partial_hash(), "Publishing genesis block.");

            info!(
                role = ?self.current_topology.role(&self.peer_id),
                block_partial_hash = %block.partial_hash(),
                "Created a block to commit.",
            );

            self.send_events(&block);
            let msg = MessagePacket::new(ProofChain::default(), BlockCreated::from(block.clone()));
            self.broadcast_packet(msg);
            // Omit signature verification during genesis round
            self.commit_block(block.commit_unchecked());
        }
    }

    fn commit_block(&mut self, block: impl Into<VersionedCommittedBlock>) {
        self.update_state::<NewBlockStrategy>(block);
    }

    fn replace_top_block(&mut self, block: impl Into<VersionedCommittedBlock>) {
        self.update_state::<ReplaceTopBlockStrategy>(block);
    }

    fn update_topology(&mut self, committed_block: &VersionedCommittedBlock) {
        let mut topology = Topology::new(
            committed_block
                .as_v1()
                .header()
                .committed_with_topology
                .clone(),
        );

        topology.update_topology(
            committed_block,
            self.wsv.peers_ids().iter().cloned().collect(),
        );

        self.current_topology = topology;
        self.connect_peers(&self.current_topology);
    }

    fn update_state<Strategy: ApplyBlockStrategy>(
        &mut self,
        block: impl Into<VersionedCommittedBlock>,
    ) {
        let committed_block = Arc::new(block.into());

        info!(
            addr=%self.peer_id.address,
            role=%self.current_topology.role(&self.peer_id),
            block_height=%self.wsv.height(),
            block_hash=%committed_block.hash(),
            "{}", Strategy::LOG_MESSAGE,
        );

        Strategy::before_update_hook(self);

        self.wsv
            .apply(committed_block.as_ref())
            .expect("Failed to apply block on WSV. Bailing.");

        let events_buffer = core::mem::take(&mut self.wsv.events_buffer);
        self.send_events(events_buffer);

        // Parameters are updated before updating public copy of sumeragi
        self.update_params();

        // https://github.com/hyperledger/iroha/issues/3396
        // Kura should store the block only upon successful application to the internal WSV to avoid storing a corrupted block.
        // Public-facing WSV update should happen after that and be followed by `BlockCommited` event to prevent client access to uncommitted data.
        Strategy::kura_store_block(&self.kura, Arc::clone(&committed_block));

        // Update WSV copy that is public facing
        self.public_wsv_sender
            .send_modify(|public_wsv| *public_wsv = self.wsv.clone());

        // This sends "Block committed" event, so it should be done
        // AFTER public facing WSV update
        self.send_events(committed_block.as_ref());

        self.update_topology(committed_block.as_ref());

        self.cache_transaction()
    }

    fn update_params(&mut self) {
        use iroha_data_model::parameter::default::*;

        if let Some(block_time) = self.wsv.query_param(BLOCK_TIME) {
            self.block_time = Duration::from_millis(block_time);
        }
        if let Some(commit_time) = self.wsv.query_param(COMMIT_TIME_LIMIT) {
            self.commit_time = Duration::from_millis(commit_time);
        }
        if let Some(max_txs_in_block) = self.wsv.query_param::<u32, _>(MAX_TRANSACTIONS_IN_BLOCK) {
            self.max_txs_in_block = max_txs_in_block as usize;
        }
    }

    fn cache_transaction(&mut self) {
        self.transaction_cache
            .retain(|tx| !self.wsv.has_transaction(tx.hash()) && !self.queue.is_expired(tx));
    }
}

fn suggest_view_change(
    sumeragi: &Sumeragi,
    view_change_proof_chain: &mut ProofChain,
    current_view_change_index: u64,
) {
    let suspect_proof = {
        let mut proof = Proof {
            latest_block_hash: sumeragi.wsv.latest_block_hash(),
            view_change_index: current_view_change_index,
            signatures: Vec::new(),
        };
        proof
            .sign(sumeragi.key_pair.clone())
            .expect("Proof signing failed");
        proof
    };

    view_change_proof_chain
        .insert_proof(
            &sumeragi.current_topology.sorted_peers,
            sumeragi.current_topology.max_faults(),
            sumeragi.wsv.latest_block_hash(),
            suspect_proof,
        )
        .unwrap_or_else(|err| error!("{err}"));

    let msg = MessagePacket::new(
        view_change_proof_chain.clone(),
        Message::ViewChangeSuggested,
    );
    sumeragi.broadcast_packet(msg);
}

fn prune_view_change_proofs_and_calculate_current_index(
    sumeragi: &Sumeragi,
    view_change_proof_chain: &mut ProofChain,
) -> u64 {
    view_change_proof_chain.prune(sumeragi.wsv.latest_block_hash());
    view_change_proof_chain.verify_with_state(
        &sumeragi.current_topology.sorted_peers,
        sumeragi.current_topology.max_faults(),
        sumeragi.wsv.latest_block_hash(),
    ) as u64
}

#[allow(clippy::too_many_lines)]
fn handle_message(
    message: Message,
    sumeragi: &mut Sumeragi,
    voting_block: &mut Option<VotingBlock>,
    current_view_change_index: u64,
    view_change_proof_chain: &mut ProofChain,
    voting_signatures: &mut Vec<SignatureOf<PendingBlock>>,
) {
    let current_topology = &sumeragi.current_topology;
    let role = current_topology.role(&sumeragi.peer_id);
    let addr = &sumeragi.peer_id.address;

    #[allow(clippy::suspicious_operation_groupings)]
    match (message, role) {
        (Message::ViewChangeSuggested, _) => {
            trace!("Received view change suggestion.");
        }
        (Message::BlockSyncUpdate(BlockSyncUpdate { block }), _) => {
            let block_hash = block.hash();
            info!(%addr, %role, hash=%block_hash, "Block sync update received");

            match handle_block_sync(block, &sumeragi.wsv, &sumeragi.finalized_wsv) {
                Ok(BlockSyncOk::CommitBlock(block)) => sumeragi.commit_block(block),
                Ok(BlockSyncOk::ReplaceTopBlock(block)) => {
                    warn!(
                        %addr, %role,
                        peer_latest_block_hash=?sumeragi.wsv.latest_block_hash(),
                        peer_latest_block_view_change_index=?sumeragi.wsv.latest_block_view_change_index(),
                        consensus_latest_block_hash=%block.hash(),
                        consensus_latest_block_view_change_index=%block.as_v1().header.view_change_index,
                        "Soft fork occurred: peer in inconsistent state. Rolling back and replacing top block."
                    );
                    sumeragi.replace_top_block(block)
                }
                Err(BlockSyncError::BlockNotValid(error)) => {
                    error!(%addr, %role, %block_hash, ?error, "Block not valid.")
                }
                Err(BlockSyncError::SoftForkBlockNotValid(error)) => {
                    error!(%addr, %role, %block_hash, ?error, "Soft-fork block not valid.")
                }
                Err(BlockSyncError::SoftForkBlockSmallViewChangeIndex {
                    peer_view_change_index,
                    block_view_change_index,
                }) => {
                    debug!(
                        %addr, %role,
                        peer_latest_block_hash=?sumeragi.wsv.latest_block_hash(),
                        peer_latest_block_view_change_index=?peer_view_change_index,
                        consensus_latest_block_hash=%block_hash,
                        consensus_latest_block_view_change_index=%block_view_change_index,
                        "Soft fork doesn't occurred: block has the same or smaller view change index"
                    );
                }
                Err(BlockSyncError::BlockNotProperHeight {
                    peer_height,
                    block_height,
                }) => {
                    warn!(%addr, %role, %block_hash, %block_height, %peer_height, "Other peer send irrelevant or outdated block to the peer (it's neither `peer_height` nor `peer_height + 1`).")
                }
            }
        }
        (Message::BlockCommitted(BlockCommitted { hash, signatures }), _) => {
            if role == Role::ProxyTail && current_topology.is_consensus_required()
                || role == Role::Leader && !current_topology.is_consensus_required()
            {
                error!(%addr, %role, "Received BlockCommitted message, but shouldn't");
            } else if let Some(mut voted_block) = voting_block.take() {
                let voting_block_hash = voted_block.block.partial_hash();

                if hash.internal == voting_block_hash.into() {
                    // The manipulation of the topology relies upon all peers seeing the same signature set.
                    // Therefore we must clear the signatures and accept what the proxy tail giveth.
                    voted_block.block.signatures.clear();
                    add_signatures::<true>(&mut voted_block, signatures.transmute());

                    match voted_block.block.commit(current_topology) {
                        Ok(committed_block) => sumeragi.commit_block(committed_block),
                        Err((_, err)) => {
                            error!(%addr, %role, %hash, ?err, "Block failed to be committed")
                        }
                    };
                } else {
                    error!(
                        %addr, %role, committed_block_hash=%hash, %voting_block_hash,
                        "The hash of the committed block does not match the hash of the block stored by the peer."
                    );

                    *voting_block = Some(voted_block);
                };
            } else {
                error!(%addr, %role, %hash, "Peer missing voting block")
            }
        }
        (Message::BlockCreated(block_created), Role::ValidatingPeer) => {
            if let Some(v_block) = vote_for_block(sumeragi, block_created) {
                let block_hash = v_block.block.partial_hash();

                let msg = MessagePacket::new(
                    view_change_proof_chain.clone(),
                    BlockSigned::from(&v_block.block),
                );

                sumeragi.broadcast_packet_to(msg, [current_topology.proxy_tail()]);
                info!(%addr, %block_hash, "Block validated, signed and forwarded");

                *voting_block = Some(v_block);
            }
        }
        (Message::BlockCreated(block_created), Role::ObservingPeer) => {
            if let Some(v_block) = vote_for_block(sumeragi, block_created) {
                if current_view_change_index >= 1 {
                    let block_hash = v_block.block.partial_hash();

                    let msg = MessagePacket::new(
                        view_change_proof_chain.clone(),
                        BlockSigned::from(&v_block.block),
                    );

                    sumeragi.broadcast_packet_to(msg, [current_topology.proxy_tail()]);
                    info!(%addr, %block_hash, "Block validated, signed and forwarded");
                    *voting_block = Some(v_block);
                } else {
                    error!(%addr, %role, "Received BlockCreated message, but shouldn't");
                }
            }
        }
        (Message::BlockCreated(block_created), Role::ProxyTail) => {
            // NOTE: False positive from nursery
            #[allow(clippy::iter_with_drain)]
            if let Some(mut new_block) = vote_for_block(sumeragi, block_created) {
                // NOTE: Up until this point it was unknown which block is expected to be received,
                // therefore all the signatures (of any hash) were collected and will now be pruned
                add_signatures::<false>(&mut new_block, voting_signatures.drain(..));
                *voting_block = Some(new_block);
            }
        }
        (Message::BlockSigned(BlockSigned { hash, signatures }), Role::ProxyTail) => {
            trace!(block_hash=%hash, "Received block signatures");

            let roles: &[Role] = if current_view_change_index >= 1 {
                &[Role::ValidatingPeer, Role::ObservingPeer]
            } else {
                &[Role::ValidatingPeer]
            };
            let valid_signatures = current_topology.filter_signatures_by_roles(roles, &signatures);

            if let Some(voted_block) = voting_block.as_mut() {
                let voting_block_hash = voted_block.block.partial_hash();

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
fn process_message_independent(
    sumeragi: &mut Sumeragi,
    voting_block: &mut Option<VotingBlock>,
    current_view_change_index: u64,
    view_change_proof_chain: &mut ProofChain,
    round_start_time: &Instant,
    is_genesis_peer: bool,
) {
    let current_topology = &sumeragi.current_topology;
    let role = current_topology.role(&sumeragi.peer_id);
    let addr = &sumeragi.peer_id.address;

    match role {
        Role::Leader => {
            if voting_block.is_none() {
                let cache_full = sumeragi.transaction_cache.len() >= sumeragi.max_txs_in_block;
                let deadline_reached = round_start_time.elapsed() > sumeragi.block_time;
                let cache_non_empty = !sumeragi.transaction_cache.is_empty();

                if cache_full || (deadline_reached && cache_non_empty) {
                    let transactions = sumeragi.transaction_cache.clone();
                    info!(txns=%transactions.len(), "Creating block...");

                    // TODO: properly process triggers!
                    let event_recommendations = Vec::new();
                    let new_block = BlockBuilder {
                        transactions,
                        event_recommendations,
                        view_change_index: current_view_change_index,
                        committed_with_topology: sumeragi.current_topology.clone(),
                        key_pair: sumeragi.key_pair.clone(),
                        wsv: sumeragi.wsv.clone(),
                    }
                    .build();

                    sumeragi.send_events(&new_block);
                    if current_topology.is_consensus_required() {
                        info!(%addr, partial_hash=%new_block.partial_hash(), "Block created");
                        *voting_block = Some(VotingBlock::new(new_block.clone()));

                        let msg = MessagePacket::new(
                            view_change_proof_chain.clone(),
                            BlockCreated::from(new_block),
                        );
                        if current_view_change_index >= 1 {
                            sumeragi.broadcast_packet(msg);
                        } else {
                            sumeragi.broadcast_packet_to(
                                msg,
                                current_topology
                                    .sorted_peers
                                    .iter()
                                    .take(current_topology.min_votes_for_commit()),
                            );
                        }
                    } else {
                        match new_block.commit(current_topology) {
                            Ok(committed_block) => {
                                let msg = MessagePacket::new(
                                    view_change_proof_chain.clone(),
                                    BlockCommitted::from(Into::<VersionedCommittedBlock>::into(
                                        committed_block.clone(),
                                    )),
                                );

                                sumeragi.broadcast_packet(msg);
                                sumeragi.commit_block(committed_block);
                            }
                            Err(err) => error!(%addr, role=%Role::Leader, ?err),
                        }
                    }
                }
            }
        }
        Role::ProxyTail => {
            if let Some(voted_block) = voting_block.take() {
                let voted_at = voted_block.voted_at;

                match voted_block.block.commit(current_topology) {
                    Ok(committed_block) => {
                        info!(voting_block_hash = %committed_block.hash(), "Block reached required number of votes");

                        let msg = MessagePacket::new(
                            view_change_proof_chain.clone(),
                            BlockCommitted::from(Into::<VersionedCommittedBlock>::into(
                                committed_block.clone(),
                            )),
                        );

                        #[cfg(debug_assertions)]
                        if is_genesis_peer && sumeragi.debug_force_soft_fork {
                            std::thread::sleep(sumeragi.pipeline_time() * 2);
                        } else if current_view_change_index >= 1 {
                            sumeragi.broadcast_packet(msg);
                        } else {
                            sumeragi.broadcast_packet_to(
                                msg,
                                current_topology
                                    .sorted_peers
                                    .iter()
                                    .take(current_topology.min_votes_for_commit()),
                            );
                        }

                        #[cfg(not(debug_assertions))]
                        {
                            if current_view_change_index >= 1 {
                                sumeragi.broadcast_packet(msg);
                            } else {
                                sumeragi.broadcast_packet_to(
                                    msg,
                                    current_topology
                                        .sorted_peers
                                        .iter()
                                        .take(current_topology.min_votes_for_commit()),
                                );
                            }
                        }
                        sumeragi.commit_block(committed_block);
                    }
                    Err((block, err)) => {
                        // Restore the current voting block and continue the round
                        *voting_block = Some(VotingBlock::voted_at(block, voted_at));
                        trace!(?err, "Not enough signatures, waiting for more...");
                    }
                }
            }
        }
        _ => {}
    }
}

// NOTE: False positive useless_let_if_seq from nursery
#[allow(clippy::too_many_arguments, clippy::useless_let_if_seq)]
fn reset_state(
    peer_id: &PeerId,
    pipeline_time: Duration,
    current_view_change_index: u64,
    old_view_change_index: &mut u64,
    current_latest_block_height: u64,
    old_latest_block_height: &mut u64,
    // below is the state that gets reset.
    current_topology: &mut Topology,
    voting_block: &mut Option<VotingBlock>,
    voting_signatures: &mut Vec<SignatureOf<PendingBlock>>,
    round_start_time: &mut Instant,
    last_view_change_time: &mut Instant,
    view_change_time: &mut Duration,
) {
    let mut was_commit_or_view_change = false;
    if current_latest_block_height != *old_latest_block_height {
        // Round is only restarted on a block commit, so that in the case of
        // a view change a new block is immediately created by the leader
        *round_start_time = Instant::now();
        was_commit_or_view_change = true;
        *old_view_change_index = 0;
    }

    while *old_view_change_index < current_view_change_index {
        *old_view_change_index += 1;
        error!(addr=%peer_id.address, "Rotating the entire topology.");
        current_topology.rotate_all();
        was_commit_or_view_change = true;
    }

    // Reset state for the next round.
    if was_commit_or_view_change {
        *old_latest_block_height = current_latest_block_height;

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
    genesis_network: Option<GenesisNetwork>,
    mut sumeragi: Sumeragi,
    mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
) {
    // Connect peers with initial topology
    sumeragi.connect_peers(&sumeragi.current_topology);

    let span = span!(tracing::Level::TRACE, "genesis").entered();
    let is_genesis_peer = if sumeragi.wsv.height() == 0
        || sumeragi.wsv.latest_block_hash().is_none()
    {
        if let Some(genesis_network) = genesis_network {
            sumeragi.sumeragi_init_commit_genesis(genesis_network);
            true
        } else {
            sumeragi
                .init_listen_for_genesis(&mut shutdown_receiver)
                .unwrap_or_else(|err| assert_ne!(EarlyReturn::Disconnected, err, "Disconnected"));
            false
        }
    } else {
        false
    };
    span.exit();

    trace!(
        me=%sumeragi.peer_id.public_key,
        role_in_next_round=%sumeragi.current_topology.role(&sumeragi.peer_id),
        "Finished sumeragi init.",
    );

    let mut voting_block = None;
    // Proxy tail collection of voting block signatures
    let mut voting_signatures = Vec::new();
    let mut should_sleep = false;
    let mut view_change_proof_chain = ProofChain::default();
    let mut old_view_change_index = 0;
    let mut old_latest_block_height = 0;
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
            should_sleep = false;
        }
        let span_for_sumeragi_cycle = span!(Level::TRACE, "main_thread_cycle");
        let _enter_for_sumeragi_cycle = span_for_sumeragi_cycle.enter();

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

        let mut expired_transactions = Vec::new();
        sumeragi.queue.get_transactions_for_block(
            &sumeragi.wsv,
            sumeragi.max_txs_in_block,
            &mut sumeragi.transaction_cache,
            &mut expired_transactions,
        );
        sumeragi.send_events(
            expired_transactions
                .iter()
                .map(expired_event)
                .collect::<Vec<_>>(),
        );

        let current_view_change_index = prune_view_change_proofs_and_calculate_current_index(
            &sumeragi,
            &mut view_change_proof_chain,
        );

        reset_state(
            &sumeragi.peer_id,
            sumeragi.pipeline_time(),
            current_view_change_index,
            &mut old_view_change_index,
            sumeragi.wsv.height(),
            &mut old_latest_block_height,
            &mut sumeragi.current_topology,
            &mut voting_block,
            &mut voting_signatures,
            &mut round_start_time,
            &mut last_view_change_time,
            &mut view_change_time,
        );

        let node_expects_block = !sumeragi.transaction_cache.is_empty();
        if node_expects_block && last_view_change_time.elapsed() > view_change_time {
            let role = sumeragi.current_topology.role(&sumeragi.peer_id);

            if let Some(VotingBlock { block, .. }) = voting_block.as_ref() {
                // NOTE: Suspecting the tail node because it hasn't yet committed a block produced by leader
                warn!(peer_public_key=%sumeragi.peer_id.public_key, %role, block=%block.partial_hash(), "Block not committed in due time, requesting view change...");
            } else {
                // NOTE: Suspecting the leader node because it hasn't produced a block
                // If the current node has a transaction, the leader should have as well
                warn!(peer_public_key=%sumeragi.peer_id.public_key, %role, "No block produced in due time, requesting view change...");
            }

            suggest_view_change(
                &sumeragi,
                &mut view_change_proof_chain,
                current_view_change_index,
            );

            // NOTE: View change must be periodically suggested until it is accepted.
            // Must be initialized to pipeline time but can increase by chosen amount
            view_change_time += sumeragi.pipeline_time();
        }

        sumeragi
            .receive_network_packet(&mut view_change_proof_chain)
            .map_or_else(
                || {
                    should_sleep = true;
                },
                |message| {
                    handle_message(
                        message,
                        &mut sumeragi,
                        &mut voting_block,
                        current_view_change_index,
                        &mut view_change_proof_chain,
                        &mut voting_signatures,
                    );
                },
            );

        process_message_independent(
            &mut sumeragi,
            &mut voting_block,
            current_view_change_index,
            &mut view_change_proof_chain,
            &round_start_time,
            is_genesis_peer,
        );
    }
}

fn add_signatures<const EXPECT_VALID: bool>(
    block: &mut VotingBlock,
    signatures: impl IntoIterator<Item = SignatureOf<PendingBlock>>,
) {
    for signature in signatures {
        if let Err(err) = block.block.add_signature(signature) {
            let err_msg = "Signature not valid";

            if EXPECT_VALID {
                error!(?err, err_msg);
            } else {
                debug!(?err, err_msg);
            }
        }
    }
}

/// Create expired pipeline event for the given transaction.
fn expired_event(txn: &AcceptedTransaction) -> Event {
    PipelineEvent {
        entity_kind: PipelineEntityKind::Transaction,
        status: PipelineStatus::Rejected(PipelineRejectionReason::Transaction(
            TransactionRejectionReason::Expired,
        )),
        hash: txn.payload().hash().into(),
    }
    .into()
}

fn vote_for_block(
    sumeragi: &Sumeragi,
    BlockCreated { block }: BlockCreated,
) -> Option<VotingBlock> {
    let block_hash = block.partial_hash();
    let addr = &sumeragi.peer_id.address;
    let role = sumeragi.current_topology.role(&sumeragi.peer_id);
    trace!(%addr, %role, block_hash=%block_hash, "Block received, voting...");

    let mut block = {
        let span = span!(Level::TRACE, "block revalidation");
        let _enter = span.enter();

        match <PendingBlock as InBlock>::revalidate(&block, sumeragi.wsv.clone()) {
            Ok(()) => block,
            Err(err) => {
                warn!(%addr, %role, ?err);
                return None;
            }
        }
    };

    if sumeragi
        .current_topology
        .filter_signatures_by_roles(&[Role::Leader], block.retain_verified_signatures())
        .is_empty()
    {
        error!(
            %addr, %role, leader=%sumeragi.current_topology.leader().address, hash=%block.partial_hash(),
            "The block is rejected as it is not signed by the leader."
        );

        return None;
    }

    if block.header.committed_with_topology != sumeragi.current_topology.sorted_peers {
        error!(
            %addr, %role, block_topology=?block.header.committed_with_topology, my_topology=?sumeragi.current_topology, hash=%block.partial_hash(),
            "The block is rejected as because the topology field is incorrect."
        );

        return None;
    }

    let signed_block = block
        .sign(sumeragi.key_pair.clone())
        .expect("Block signing failed");

    sumeragi.send_events(&signed_block);
    Some(VotingBlock::new(signed_block))
}

/// Type enumerating early return types to reduce cyclomatic
/// complexity of the main loop items and allow direct short
/// circuiting with the `?` operator. Candidate for `impl
/// FromResidual`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EarlyReturn {
    /// Genesis block received and committed
    GenesisBlockReceivedAndCommitted,
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

    /// Perform necessary changes in sumeragi before applying block.
    /// Like updating `wsv` or `finalized_wsv`.
    fn before_update_hook(sumeragi: &mut Sumeragi);

    /// Operation to invoke in kura to store block.
    fn kura_store_block(kura: &Kura, block: Arc<VersionedCommittedBlock>);
}

/// Commit new block strategy. Used during normal consensus rounds.
struct NewBlockStrategy;

impl ApplyBlockStrategy for NewBlockStrategy {
    const LOG_MESSAGE: &'static str = "Committing block";

    #[inline]
    fn before_update_hook(sumeragi: &mut Sumeragi) {
        // Save current wsv state in case of rollback in the future
        sumeragi.finalized_wsv = sumeragi.wsv.clone();
    }

    #[inline]
    fn kura_store_block(kura: &Kura, block: Arc<VersionedCommittedBlock>) {
        kura.store_block(block)
    }
}

/// Replace top block strategy. Used in case of soft-fork.
struct ReplaceTopBlockStrategy;

impl ApplyBlockStrategy for ReplaceTopBlockStrategy {
    const LOG_MESSAGE: &'static str = "Replacing top block";

    #[inline]
    fn before_update_hook(sumeragi: &mut Sumeragi) {
        // Rollback to previous wsv state before applying block
        sumeragi.wsv = sumeragi.finalized_wsv.clone();
    }

    #[inline]
    fn kura_store_block(kura: &Kura, block: Arc<VersionedCommittedBlock>) {
        kura.replace_top_block(block)
    }
}

#[derive(Debug)]
enum BlockSyncOk {
    CommitBlock(VersionedCommittedBlock),
    ReplaceTopBlock(VersionedCommittedBlock),
}

#[derive(Debug)]
enum BlockSyncError {
    BlockNotValid(eyre::Report),
    SoftForkBlockNotValid(eyre::Report),
    SoftForkBlockSmallViewChangeIndex {
        peer_view_change_index: u64,
        block_view_change_index: u64,
    },
    BlockNotProperHeight {
        peer_height: u64,
        block_height: u64,
    },
}

fn handle_block_sync(
    block: VersionedCommittedBlock,
    wsv: &WorldStateView,
    finalized_wsv: &WorldStateView,
) -> Result<BlockSyncOk, BlockSyncError> {
    let block_height = block.as_v1().header.height;
    let wsv_height = wsv.height();
    if wsv_height + 1 == block_height {
        // Normal branch for adding new block on top of current
        InBlock::revalidate(&block, wsv.clone())
            .map(|_| BlockSyncOk::CommitBlock(block))
            .map_err(BlockSyncError::BlockNotValid)
    } else if wsv_height == block_height && block_height > 1 {
        // Soft-fork on genesis block isn't possible
        // Soft fork branch for replacing current block with valid one
        InBlock::revalidate(&block, finalized_wsv.clone())
            .map_err(BlockSyncError::SoftForkBlockNotValid)
            .and_then(|_| {
                let peer_view_change_index = wsv.latest_block_view_change_index();
                let block_view_change_index = block.as_v1().header.view_change_index;
                if peer_view_change_index < block_view_change_index {
                    Ok(BlockSyncOk::ReplaceTopBlock(block))
                } else {
                    Err(BlockSyncError::SoftForkBlockSmallViewChangeIndex {
                        peer_view_change_index,
                        block_view_change_index,
                    })
                }
            })
    } else {
        // Error branch other peer send irrelevant block
        Err(BlockSyncError::BlockNotProperHeight {
            peer_height: wsv_height,
            block_height,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::smartcontracts::Registrable;

    fn create_data_for_test() -> (WorldStateView, Arc<Kura>, VersionedCommittedBlock) {
        // Predefined world state
        let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let alice_keys = KeyPair::generate().expect("Valid");
        let account =
            Account::new(alice_id.clone(), [alice_keys.public_key().clone()]).build(&alice_id);
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(&alice_id);
        assert!(domain.add_account(account).is_none());
        let world = World::with([domain], Vec::new());
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world, Arc::clone(&kura));

        // Create "genesis" block
        // Creating an instruction
        let fail_box: InstructionBox = FailBox::new("Dummy isi").into();

        // Making two transactions that have the same instruction
        let tx = TransactionBuilder::new(alice_id.clone())
            .with_instructions([fail_box])
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx: AcceptedTransaction =
            AcceptedTransaction::accept(tx, &wsv.transaction_validator().transaction_limits)
                .map(Into::into)
                .expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx.clone(), tx];
        let block = BlockBuilder {
            transactions,
            event_recommendations: Vec::new(),
            view_change_index: 0,
            committed_with_topology: Topology::new(Vec::new()),
            key_pair: alice_keys.clone(),
            wsv: wsv.clone(),
        }
        .build();

        let genesis_block = VersionedCommittedBlock::from(block.commit_unchecked());

        kura.store_block(genesis_block.clone());
        wsv.apply(&genesis_block).expect("Failed to apply block");

        // Create block for testing purposes
        // Creating an instruction
        let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
        let create_asset_definition: InstructionBox =
            RegisterBox::new(AssetDefinition::quantity(asset_definition_id)).into();

        // Making two transactions that have the same instruction
        let tx = TransactionBuilder::new(alice_id)
            .with_instructions([create_asset_definition])
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx: AcceptedTransaction =
            AcceptedTransaction::accept(tx, &wsv.transaction_validator().transaction_limits)
                .map(Into::into)
                .expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx.clone(), tx];
        let block = BlockBuilder {
            transactions,
            event_recommendations: Vec::new(),
            view_change_index: 0,
            committed_with_topology: Topology::new(Vec::new()),
            key_pair: alice_keys,
            wsv: wsv.clone(),
        }
        .build();

        let block = VersionedCommittedBlock::from(block.commit_unchecked());

        (wsv, kura, block)
    }

    #[test]
    fn block_sync_invalid_block() {
        let (finalized_wsv, _, mut block) = create_data_for_test();
        let wsv = finalized_wsv.clone();

        // Malform block to make it invalid
        block.as_mut_v1().transactions.clear();

        let result = handle_block_sync(block, &wsv, &finalized_wsv);
        assert!(matches!(result, Err(BlockSyncError::BlockNotValid(_))))
    }

    #[test]
    fn block_sync_invalid_soft_fork_block() {
        let (finalized_wsv, kura, mut block) = create_data_for_test();
        let mut wsv = finalized_wsv.clone();

        kura.store_block(block.clone());
        wsv.apply(&block).expect("Failed to apply block");

        // Malform block to make it invalid
        block.as_mut_v1().transactions.clear();

        let result = handle_block_sync(block, &wsv, &finalized_wsv);
        assert!(matches!(
            result,
            Err(BlockSyncError::SoftForkBlockNotValid(_))
        ))
    }

    #[test]
    fn block_sync_not_proper_height() {
        let (finalized_wsv, _, mut block) = create_data_for_test();
        let wsv = finalized_wsv.clone();

        // Change block height
        block.as_mut_v1().header.height = 42;

        let result = handle_block_sync(block, &wsv, &finalized_wsv);
        assert!(matches!(
            result,
            Err(BlockSyncError::BlockNotProperHeight {
                peer_height: 1,
                block_height: 42
            })
        ))
    }

    #[test]
    fn block_sync_commit_block() {
        let (finalized_wsv, _, block) = create_data_for_test();
        let wsv = finalized_wsv.clone();
        let result = handle_block_sync(block, &wsv, &finalized_wsv);
        assert!(matches!(result, Ok(BlockSyncOk::CommitBlock(_))))
    }

    #[test]
    fn block_sync_replace_top_block() {
        let (finalized_wsv, kura, mut block) = create_data_for_test();
        let mut wsv = finalized_wsv.clone();

        kura.store_block(block.clone());
        wsv.apply(&block).expect("Failed to apply block to wsv");
        assert_eq!(wsv.latest_block_view_change_index(), 0);

        // Increase block view change index
        block.as_mut_v1().header.view_change_index = 42;

        let result = handle_block_sync(block, &wsv, &finalized_wsv);
        assert!(matches!(result, Ok(BlockSyncOk::ReplaceTopBlock(_))))
    }

    #[test]
    fn block_sync_small_view_change_index() {
        let (finalized_wsv, kura, mut block) = create_data_for_test();
        let mut wsv = finalized_wsv.clone();

        // Increase block view change index
        block.as_mut_v1().header.view_change_index = 42;

        kura.store_block(block.clone());
        wsv.apply(&block).expect("Failed to apply block to wsv");
        assert_eq!(wsv.latest_block_view_change_index(), 42);

        // Decrease block view change index back
        block.as_mut_v1().header.view_change_index = 0;

        let result = handle_block_sync(block, &wsv, &finalized_wsv);
        assert!(matches!(
            result,
            Err(BlockSyncError::SoftForkBlockSmallViewChangeIndex {
                peer_view_change_index: 42,
                block_view_change_index: 0
            })
        ))
    }

    #[test]
    fn block_sync_genesis_block_do_not_replace() {
        let (finalized_wsv, _, mut block) = create_data_for_test();
        let wsv = finalized_wsv.clone();

        // Change block height and view change index
        // Soft-fork on genesis block is not possible
        block.as_mut_v1().header.height = 1;
        block.as_mut_v1().header.view_change_index = 42;

        let result = handle_block_sync(block, &wsv, &finalized_wsv);
        assert!(matches!(
            result,
            Err(BlockSyncError::BlockNotProperHeight {
                peer_height: 1,
                block_height: 1,
            })
        ))
    }
}
