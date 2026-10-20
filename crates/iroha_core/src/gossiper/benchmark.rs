//! Isolated fixtures measuring production queue cleanup and inbound gossip admission.
//!
//! This adapter stops at the admission worker boundary. Socket I/O, worker scheduling
//! and the P2P retention envelope are measured separately from transaction admission.

use super::*;
use crate::{kura::Kura, query::store::LiveQueryStore, state::World};
use iroha_config::parameters::actual::Queue as QueueConfig;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Level,
    account::Account,
    isi::Log,
    parameter::{
        Parameter,
        custom::CustomParameter,
        system::{
            ConsensusFingerprint, ConsensusHandshakeMetadata, SumeragiConsensusMode,
            consensus_metadata,
        },
    },
    prelude::Registrable,
    transaction::TransactionBuilder,
};
use iroha_primitives::json::Json;
use std::num::{NonZeroU64, NonZeroUsize};

/// A real queue containing signed inputs and a closed-network admission worker.
pub struct HotPathFixture {
    gossiper: TransactionGossiper,
    frames: Vec<GossipTransaction>,
    hashes: Vec<EntrypointHash>,
}

impl HotPathFixture {
    /// Admit `resident` distinct signed inputs before any measurement begins.
    /// Call from an entered Tokio runtime so State's query store can start.
    pub fn new(resident: usize) -> Self {
        let capacity = NonZeroUsize::new(resident).expect("nonempty benchmark queue");
        let key = KeyPair::try_from_seed(vec![47; 32], Algorithm::Ed25519)
            .expect("benchmark signing key");
        let authority = iroha_data_model::account::AccountId::new(key.public_key().clone());
        let account = Account::new(authority.clone()).build(&authority);
        let world = World::with([], [account], []);
        // Routing requires an explicit root scope even in this pre-genesis component
        // fixture. This installs structural metadata, not a consensus certificate.
        let metadata = ConsensusHandshakeMetadata {
            mode: SumeragiConsensusMode::Permissioned,
            block_cadence_ms: NonZeroU64::new(1000).unwrap(),
            wire_protocol_version: u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION),
            consensus_fingerprint: ConsensusFingerprint::new([0xA5; 32]),
            sumeragi_context:
                iroha_data_model::block::consensus::SumeragiGenesisContextParameters::recommended(),
        };
        metadata.validate().expect("benchmark root metadata");
        {
            let mut parameters = world.parameters.block();
            parameters
                .set_parameter(Parameter::Custom(CustomParameter::new(
                    consensus_metadata::handshake_meta_id(),
                    Json::from_norito_value_ref(&norito::json::value::to_value(&metadata).unwrap())
                        .unwrap(),
                )))
                .expect("install benchmark root metadata");
            parameters.commit();
        }
        let state = Arc::new(State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ));
        let queue = Arc::new(Queue::from_config(
            QueueConfig {
                capacity,
                capacity_per_user: capacity,
                max_retained_bytes: NonZeroU64::new(256 * 1024 * 1024).unwrap(),
                transaction_time_to_live: Duration::from_secs(3600),
                ..QueueConfig::default()
            },
            tokio::sync::broadcast::Sender::new(1),
        ));
        let now = Instant::now();
        let peer_key =
            KeyPair::try_from_seed(vec![48; 32], Algorithm::BlsNormal).expect("benchmark peer key");
        let gossiper = TransactionGossiper {
            gossip_period: Duration::from_millis(50),
            gossip_size: TRANSACTION_GOSSIP_MAX_SIZE,
            gossip_resend_ticks: NonZeroU32::new(1).unwrap(),
            gossip_tick: 0,
            gossip_deferred: vec![Vec::new()],
            peer_recently_sent: BTreeMap::new(),
            peer_recent_ring: vec![Vec::new(); GOSSIP_PEER_RECENT_SUPPRESSION_TTL_TICKS],
            last_drop_count: tx_gossip_relay_drop_count(),
            last_drop_at: None,
            network: IrohaNetwork::closed_for_tests(),
            self_peer_id: PeerId::new(peer_key.public_key().clone()),
            queue,
            state,
            tx_frame_cap: 1024 * 1024,
            dataspace_cfg: DataspaceGossip::default(),
            public_seed: GossipTargetSeed::new(1, Duration::from_secs(1), now),
            restricted_seed: GossipTargetSeed::new(2, Duration::from_secs(1), now),
        };
        let mut hashes = Vec::with_capacity(resident);
        let frames = (0..resident)
            .map(|index| {
                let mut builder = TransactionBuilder::new(
                    *gossiper.state.network_id_ref(),
                    authority.clone(),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .with_instructions([Log::new(Level::INFO, "queue benchmark".to_owned())]);
                builder.set_nonce(NonZeroU32::new(u32::try_from(index + 1).unwrap()).unwrap());
                let entrypoint = TransactionEntrypoint::External(builder.sign(key.private_key()));
                hashes.push(entrypoint.hash());
                // Exactly the post-transport shape: canonical bytes retained, no cached
                // decoded entrypoint and no trusted transaction hash supplied by the peer.
                GossipTransaction::undecoded_frame(Arc::new(encode_transaction_entrypoint(
                    &entrypoint,
                )))
            })
            .collect::<Vec<_>>();
        let fixture = Self {
            gossiper,
            frames,
            hashes,
        };
        for chunk in fixture
            .frames
            .chunks(TRANSACTION_GOSSIP_MAX_SIZE.get() as usize)
        {
            fixture.receive(Self::batch_from_frames(chunk));
        }
        assert_eq!(
            fixture.resident(),
            resident,
            "all benchmark inputs must be admitted"
        );
        fixture.drain_outgoing(resident);
        fixture
    }

    fn batch_from_frames(frames: &[GossipTransaction]) -> TransactionGossip {
        TransactionGossip {
            txs: frames.to_vec(),
            routes: vec![
                GossipRoute {
                    lane_id: LaneId::SINGLE,
                    dataspace_id: DataSpaceId::UNIVERSAL
                };
                frames.len()
            ],
            plans: vec![RoutingPlan::single(RoutingDecision::default()); frames.len()],
            plane: GossipPlane::Public,
        }
    }

    /// Clone a bounded batch of lazy canonical frames outside timing.
    pub fn batch(&self, count: usize) -> TransactionGossip {
        assert!(count <= TRANSACTION_GOSSIP_MAX_SIZE.get() as usize);
        Self::batch_from_frames(&self.frames[..count])
    }

    /// Current native queue cardinality, for sample postconditions.
    pub fn resident(&self) -> usize {
        self.gossiper.queue.active_len()
    }

    /// Run the production inbound worker's route, duplicate, decode and admission path.
    pub fn receive(&self, batch: TransactionGossip) {
        self.gossiper.handle_transaction_gossip_owned(batch);
    }

    /// Time only keyed queue cleanup after an authenticated commit has identified inputs.
    /// This benchmark models that callback; it does not manufacture certified ledger state.
    pub fn remove(&self, count: usize) -> usize {
        self.gossiper
            .queue
            .remove_committed_hashes(self.hashes[..count].iter().copied(), None)
    }

    fn drain_outgoing(&self, count: usize) {
        let _ = self
            .gossiper
            .queue
            .gossip_batch_with_state(u32::try_from(count).unwrap(), &self.gossiper.state);
    }

    /// Refill a previously removed prefix outside timing and drain outgoing notifications.
    pub fn restore(&self, count: usize) {
        self.receive(self.batch(count));
        assert_eq!(self.resident(), self.frames.len());
        self.drain_outgoing(count);
    }

    /// Prepare genuinely unknown inputs: remove queue identities and flush the signature cache.
    /// The next timed receive must decode, verify and admit the original canonical frames.
    pub fn prepare_unknown(&self, count: usize) -> TransactionGossip {
        self.drain_outgoing(count);
        assert_eq!(self.remove(count), count);
        self.gossiper
            .state
            .stateless_validation_cache()
            .lock()
            .set_cap(0);
        self.batch(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn benchmark_fixture_exercises_known_unknown_and_keyed_commit_paths() {
        let fixture = HotPathFixture::new(8);
        assert!(
            fixture
                .frames
                .iter()
                .all(|frame| frame.hash().is_none() && frame.entrypoint.get().is_none())
        );
        fixture.receive(fixture.batch(4));
        assert_eq!(fixture.resident(), 8);
        assert_eq!(fixture.remove(4), 4);
        assert_eq!(fixture.resident(), 4);
        assert_eq!(fixture.remove(4), 0);
        fixture.restore(4);
        let batch = fixture.prepare_unknown(4);
        assert_eq!(fixture.resident(), 4);
        fixture.receive(batch);
        assert_eq!(fixture.resident(), 8);
        assert!(
            fixture
                .frames
                .iter()
                .all(|frame| frame.entrypoint.get().is_none())
        );
    }
}
