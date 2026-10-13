//! Gossiper actor responsible for transaction gossiping.
use crate::retained_gossip::RetainedGossip;
use crate::{
    IrohaNetwork, NetworkMessage,
    queue::{
        GossipBatchEntry, Queue, RoutingDecision, RoutingPlan, resolve_routing_decision,
        resolve_routing_plan_against_catalogs,
    },
    state::{State, StatelessValidationContext, TransactionsReadOnly},
    tx::{
        AcceptTransactionFail, AcceptedTransaction, PreparedTransactionMetadata,
        SignatureRejectionCode, SignatureVerificationFail,
    },
};
use iroha_config::parameters::{
    actual::{
        DataspaceGossip, LaneConfig as LaneGeometry, Network as NetworkConfig, Nexus,
        TransactionGossiper as Config,
    },
    defaults::network::TRANSACTION_GOSSIP_MAX_SIZE,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    nexus::{DataSpaceCatalog, LaneCatalog, LaneVisibility},
    transaction::{SignedTransaction, signed::TransactionEntrypoint},
};
use iroha_futures::supervisor::{Child, ShutdownSignal};
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_p2p::{Broadcast, Post, Priority};
use iroha_primitives::time::TimeSource;
use norito::{
    DeserializePayload, NoritoSerialize, SerializePayload,
    codec::{Decode, Encode},
    core as ncore,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU32, NonZeroUsize},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

mod restricted;
mod worker;
type EntrypointHash = HashOf<TransactionEntrypoint>;
const DROP_REASON_NO_RESTRICTED_TARGETS: &str = "no_restricted_targets";
const DROP_REASON_ROUTE_MISMATCH: &str = "route_mismatch";
const DROP_REASON_NONCANONICAL_ROUTING_PLAN: &str = "noncanonical_routing_plan";
const DROP_REASON_INACTIVE_LANE: &str = "inactive_lane";
const DROP_REASON_PEER_RECENT_SUPPRESSION: &str = "peer_recent_suppression";
const OUTCOME_PEER_RECENT_SUPPRESSION_REPLAY: &str = "peer_recent_suppression_replay";
const GOSSIP_SEED_PUBLIC_DOMAIN: u64 = 0x5055_424C_4943_5F00;
const GOSSIP_SEED_RESTRICTED_DOMAIN: u64 = 0x5245_5354_5249_4354;
const GOSSIP_PEER_RECENT_SUPPRESSION_TTL_TICKS: usize = 8;
// A large complete admission input occupies the relay for longer than an ordinary
// default-sized gossip frame. Pace retries by the bytes actually posted to peers.
const GOSSIP_RESEND_PACING_QUANTUM_BYTES: usize = 256 * 1024;
fn tx_gossip_relay_drop_count() -> u64 {
    iroha_p2p::network::subscriber_queue_full_count()
        .saturating_add(iroha_p2p::network::post_overflow_tx_gossip_count())
}
fn active_gossip_lane_ids(state: &State, nexus: &Nexus) -> BTreeSet<LaneId> {
    nexus
        .lane_catalog
        .lanes()
        .iter()
        .filter_map(|lane| {
            state
                .is_lane_active_for_authority(lane.id)
                .then_some(lane.id)
        })
        .collect()
}
#[derive(Debug, Clone)]
struct PeerRecentSuppressionEntry {
    peer_id: PeerId,
    key: PeerRecentSendKey,
    expires_tick: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PeerRecentSendKey {
    entrypoint_hash: EntrypointHash,
}
impl PeerRecentSendKey {
    fn from_gossip(tx: &GossipTransaction) -> Self {
        Self {
            entrypoint_hash: tx.hash(),
        }
    }
}
/// Count canonical NetworkMessage framing before asking the P2P owner to count
/// its authenticated relay and Data envelopes. No transaction bytes or signatures
/// are constructed for sizing; the variant retains its Arc-owned field framing.
fn tx_gossip_data_frame_len(
    self_peer_id: &PeerId,
    target: Option<&PeerId>,
    gossip_len: usize,
) -> Option<usize> {
    let flags = ncore::default_encode_flags();
    // Norito Arc<T> length-delimits its owned T. The enum variant then
    // length-delimits that Arc field, so both prefixes belong to the frame.
    let owned_len = ncore::len_prefix_len_with_flags(gossip_len, flags).checked_add(gossip_len)?;
    let payload_len = core::mem::size_of::<u32>()
        .checked_add(ncore::len_prefix_len_with_flags(owned_len, flags))?
        .checked_add(owned_len)?;
    let frame_len = iroha_p2p::network::data_frame_wire_len_from_payload_len::<NetworkMessage>(
        self_peer_id,
        target,
        payload_len,
    );
    // The canonical P2P owner uses MAX for invalid identities or overflow.
    (frame_len != usize::MAX).then_some(frame_len)
}
fn tx_gossip_frame_payload_cap(
    network_cfg: &NetworkConfig,
    self_peer_id: &PeerId,
    max_peer_id: &PeerId,
) -> usize {
    let plaintext_cap = network_cfg
        .max_frame_bytes_tx_gossip
        .min(iroha_p2p::frame_plaintext_cap(network_cfg.max_frame_bytes));
    let mut low = 0usize;
    let mut high = plaintext_cap;
    // The complete canonical envelope is monotone, including every compact
    // length-prefix transition. A small probe cannot supply constant overhead
    // for a larger frame. At most usize::BITS count-only steps are needed.
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        let fits = tx_gossip_data_frame_len(self_peer_id, Some(max_peer_id), mid)
            .zip(tx_gossip_data_frame_len(self_peer_id, None, mid))
            .is_some_and(|(direct, broadcast)| direct.max(broadcast) <= plaintext_cap);
        if fits {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    low
}
fn splitmix64(mut state: u64) -> u64 {
    state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
#[derive(Debug)]
struct GossipTargetSeed {
    seed: u64,
    last_reshuffle: Instant,
    reshuffle_period: Duration,
}
impl GossipTargetSeed {
    fn new(seed: u64, reshuffle_period: Duration, now: Instant) -> Self {
        Self {
            seed,
            last_reshuffle: now,
            reshuffle_period,
        }
    }
    fn current(&mut self, now: Instant) -> u64 {
        if now.saturating_duration_since(self.last_reshuffle) >= self.reshuffle_period {
            self.seed = splitmix64(self.seed);
            self.last_reshuffle = now;
        }
        self.seed
    }
}
/// [`TransactionGossiper`] actor handle.
#[derive(Clone)]
pub struct TransactionGossiperHandle {
    message_sender: Option<mpsc::Sender<RetainedGossip<Arc<TransactionGossip>>>>,
}
impl TransactionGossiperHandle {
    /// Construct the inert handle used by emergency Fast mode.
    ///
    /// Transaction admission is closed in that mode, so retaining an actor,
    /// timer, queue, topology clone, or network fanout path would only consume
    /// outage-recovery resources.
    #[must_use]
    pub fn emergency_fast_disabled() -> Self {
        Self {
            message_sender: None,
        }
    }
    /// Send [`TransactionGossip`] to actor.
    ///
    /// Messages are best-effort: if the queue is full, the gossip is dropped
    /// to avoid blocking consensus traffic.
    pub fn gossip(&self, gossip: RetainedGossip<Arc<TransactionGossip>>) {
        let Some(message_sender) = self.message_sender.as_ref() else {
            return;
        };
        let txs = gossip.payload().txs.len();
        let plane = gossip_plane_label(gossip.payload().plane);
        match message_sender.try_send(gossip) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                iroha_logger::debug!(
                    plane,
                    txs,
                    "transaction gossiper queue full; dropping gossip"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                iroha_logger::warn!(
                    plane,
                    txs,
                    "transaction gossiper channel closed; dropping gossip"
                );
            }
        }
    }
}
#[cfg(test)]
mod handle_tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn gossip_drops_when_queue_full() {
        let (message_sender, mut message_receiver) = mpsc::channel(1);
        let handle = TransactionGossiperHandle {
            message_sender: Some(message_sender),
        };
        let msg1 = TransactionGossip {
            txs: Vec::new(),
            routes: Vec::new(),
            plans: Vec::new(),
            plane: GossipPlane::Public,
        };
        let msg2 = TransactionGossip {
            txs: Vec::new(),
            routes: Vec::new(),
            plans: Vec::new(),
            plane: GossipPlane::Restricted,
        };
        let (first, first_count) = RetainedGossip::with_count_for_test(Arc::new(msg1));
        let (second, second_count) = RetainedGossip::with_count_for_test(Arc::new(msg2));
        handle
            .message_sender
            .as_ref()
            .expect("ordinary test handle has a sender")
            .try_send(first)
            .expect("queue has space");
        handle.gossip(second);
        assert_eq!(
            first_count.available_permits(),
            0,
            "queued owner survives sender return"
        );
        assert_eq!(
            second_count.available_permits(),
            1,
            "rejected owner is released exactly once"
        );
        let received = message_receiver
            .try_recv()
            .expect("expected queued message");
        assert_eq!(received.payload().plane, GossipPlane::Public);
        received.with_payload(|payload| {
            assert_eq!(first_count.available_permits(), 0);
            assert_eq!(payload.plane, GossipPlane::Public);
        });
        assert_eq!(first_count.available_permits(), 1);
        assert!(matches!(
            message_receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
    #[test]
    fn emergency_fast_handle_has_no_actor_queue() {
        let handle = TransactionGossiperHandle::emergency_fast_disabled();
        assert!(handle.message_sender.is_none());
        handle.gossip(RetainedGossip::synthetic_for_test(Arc::new(
            TransactionGossip {
                txs: Vec::new(),
                routes: Vec::new(),
                plans: Vec::new(),
                plane: GossipPlane::Public,
            },
        )));
    }
}
/// Invalid execution context for the transaction-gossip actor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransactionGossiperStartError {
    /// No Tokio runtime is active on the calling thread.
    #[error("transaction gossip requires an active Tokio runtime")]
    MissingRuntime,
    /// The runtime cannot hand off an executor core during synchronous durable work.
    #[error("transaction gossip requires a multithreaded Tokio runtime")]
    UnsupportedRuntime,
    /// A zero interval cannot define bounded periodic scheduling.
    #[error("transaction gossip period must be positive")]
    ZeroPeriod,
}
/// Actor which gossips transactions and receives transaction gossips
pub struct TransactionGossiper {
    /// The time between gossip messages. More frequent gossiping shortens
    /// the time to sync, but can overload the network.
    gossip_period: Duration,
    /// Maximum transaction count for both outgoing and accepted gossip batches. Smaller values
    /// reduce synchronization throughput and bound per-message verification work.
    gossip_size: NonZeroU32,
    /// Number of gossip periods to wait before re-sending the same transactions.
    gossip_resend_ticks: NonZeroU32,
    /// Monotonic tick counter for gossip resend pacing.
    gossip_tick: u64,
    /// Deferred gossip hashes bucketed by resend tick.
    gossip_deferred: Vec<Vec<HashOf<TransactionEntrypoint>>>,
    /// Recently-sent wire identities tracked per peer to suppress duplicate fanout.
    peer_recently_sent: BTreeMap<PeerId, BTreeMap<PeerRecentSendKey, u64>>,
    /// Expiry ring for per-peer suppression entries (tick-based TTL).
    peer_recent_ring: Vec<Vec<PeerRecentSuppressionEntry>>,
    /// Subscriber and outbound TxGossip drop counter at the last backpressure observation.
    last_drop_count: u64,
    /// Timestamp of the last observed relay drop.
    last_drop_at: Option<Instant>,
    network: IrohaNetwork,
    self_peer_id: PeerId,
    queue: Arc<Queue>,
    state: Arc<State>,
    tx_frame_cap: usize,
    dataspace_cfg: DataspaceGossip,
    public_seed: GossipTargetSeed,
    restricted_seed: GossipTargetSeed,
}
impl TransactionGossiper {
    /// Start the sole gossip worker, retaining each physical operation until return.
    ///
    /// # Errors
    /// Rejects a zero period or a runtime that cannot hand off blocking work.
    pub fn start(
        mut self,
        shutdown_signal: ShutdownSignal,
    ) -> Result<(TransactionGossiperHandle, Child), TransactionGossiperStartError> {
        let (message_sender, message_receiver) = mpsc::channel(1);
        let child = worker::start(
            self.gossip_period,
            message_receiver,
            shutdown_signal,
            move |work| match work {
                worker::Work::Tick => self.gossip_transactions(),
                worker::Work::Incoming(message) => self.handle_retained_gossip(message),
            },
        )?;
        Ok((
            TransactionGossiperHandle {
                message_sender: Some(message_sender),
            },
            child,
        ))
    }
    /// Construct [`Self`], deriving target seeds from the state's exact network identity.
    #[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
    pub fn from_config(
        Config {
            gossip_period,
            gossip_size,
            gossip_resend_ticks,
            dataspace,
        }: Config,
        network_cfg: &NetworkConfig,
        self_peer_id: PeerId,
        max_peer_id: PeerId,
        network: IrohaNetwork,
        queue: Arc<Queue>,
        state: Arc<State>,
    ) -> Self {
        assert!(
            gossip_size <= TRANSACTION_GOSSIP_MAX_SIZE,
            "configured transaction gossip size {gossip_size} exceeds the canonical per-message maximum {TRANSACTION_GOSSIP_MAX_SIZE}"
        );
        let now = Instant::now();
        let dataspace_cfg = dataspace;
        let network_id = *state.network_id_ref();
        let public_seed = GossipTargetSeed::new(
            Self::initial_target_seed(
                &network_id,
                &self_peer_id,
                &max_peer_id,
                GOSSIP_SEED_PUBLIC_DOMAIN,
            ),
            dataspace_cfg.public_target_reshuffle,
            now,
        );
        let restricted_seed = GossipTargetSeed::new(
            Self::initial_target_seed(
                &network_id,
                &self_peer_id,
                &max_peer_id,
                GOSSIP_SEED_RESTRICTED_DOMAIN,
            ),
            dataspace_cfg.restricted_target_reshuffle,
            now,
        );
        // Keep gossip batches below the plaintext per-topic cap while respecting the encrypted
        // frame ceiling and the P2P message envelope overhead.
        let tx_frame_cap = tx_gossip_frame_payload_cap(network_cfg, &self_peer_id, &max_peer_id);
        let gossip_deferred = vec![Vec::new(); gossip_resend_ticks.get() as usize];
        let peer_recent_ring = vec![Vec::new(); GOSSIP_PEER_RECENT_SUPPRESSION_TTL_TICKS];
        Self {
            gossip_period,
            gossip_size,
            gossip_resend_ticks,
            gossip_tick: 0,
            gossip_deferred,
            peer_recently_sent: BTreeMap::new(),
            peer_recent_ring,
            last_drop_count: tx_gossip_relay_drop_count(),
            last_drop_at: None,
            network,
            self_peer_id,
            queue,
            state,
            tx_frame_cap,
            dataspace_cfg,
            public_seed,
            restricted_seed,
        }
    }
    fn deferred_index(&self) -> usize {
        let len = u64::from(self.gossip_resend_ticks.get());
        let len_usize = usize::try_from(len).expect("gossip_resend_ticks fits usize");
        debug_assert!(len > 0, "gossip_resend_ticks must be non-zero");
        debug_assert_eq!(
            self.gossip_deferred.len(),
            len_usize,
            "gossip_deferred must match gossip_resend_ticks"
        );
        usize::try_from(self.gossip_tick % len).expect("gossip_resend_ticks fits usize")
    }
    fn backpressure_cooldown(&self) -> Duration {
        self.gossip_period
            .checked_mul(self.gossip_resend_ticks.get())
            .unwrap_or(self.gossip_period)
    }
    fn gossip_backpressure_active(&mut self, now: Instant) -> bool {
        let current = tx_gossip_relay_drop_count();
        if current > self.last_drop_count {
            self.last_drop_count = current;
            self.last_drop_at = Some(now);
        }
        let cooldown = self.backpressure_cooldown();
        self.last_drop_at
            .is_some_and(|last| now.saturating_duration_since(last) < cooldown)
    }
    fn release_deferred_gossip(&mut self) {
        if self.gossip_deferred.is_empty() {
            return;
        }
        let index = self.deferred_index();
        let hashes = std::mem::take(&mut self.gossip_deferred[index]);
        if hashes.is_empty() {
            return;
        }
        self.queue.requeue_gossip_hashes(hashes);
    }
    fn defer_gossip_hashes(&mut self, hashes: impl IntoIterator<Item = EntrypointHash>) {
        if self.gossip_deferred.is_empty() {
            return;
        }
        let index = self.deferred_index();
        let slot = &mut self.gossip_deferred[index];
        let mut seen: BTreeSet<_> = slot.iter().copied().collect();
        for hash in hashes {
            if seen.insert(hash) {
                slot.push(hash);
            }
        }
    }
    fn retry_public_broadcast_hashes(&mut self, hashes: Vec<HashOf<TransactionEntrypoint>>) {
        self.defer_gossip_hashes(hashes);
    }
    fn advance_gossip_tick(&mut self) {
        self.gossip_tick = self.gossip_tick.wrapping_add(1);
    }
    fn peer_recent_slot_for_tick(&self, tick: u64) -> usize {
        let slots = self.peer_recent_ring.len();
        if slots == 0 {
            return 0;
        }
        let slots_u64 = u64::try_from(slots).expect("peer_recent_ring length fits u64");
        usize::try_from(tick % slots_u64).expect("slot index fits usize")
    }
    fn expire_peer_recent_suppression(&mut self) {
        if self.peer_recent_ring.is_empty() {
            return;
        }
        let slot_idx = self.peer_recent_slot_for_tick(self.gossip_tick);
        let expiring = std::mem::take(&mut self.peer_recent_ring[slot_idx]);
        if expiring.is_empty() {
            return;
        }
        let mut empty_peers = BTreeSet::new();
        let mut deferred = Vec::new();
        for entry in expiring {
            let peer_id = entry.peer_id.clone();
            if let Some(peer_map) = self.peer_recently_sent.get_mut(&peer_id) {
                match peer_map.get(&entry.key).copied() {
                    Some(expiry) if expiry == entry.expires_tick && expiry <= self.gossip_tick => {
                        peer_map.remove(&entry.key);
                    }
                    Some(expiry) if expiry == entry.expires_tick => {
                        deferred.push(entry);
                    }
                    Some(_) | None => {
                        // A newer send replaced this peer/hash expiry, or the
                        // hash was already removed. Drop the stale ring entry.
                    }
                }
                if peer_map.is_empty() {
                    empty_peers.insert(peer_id);
                }
            }
        }
        for peer in empty_peers {
            self.peer_recently_sent.remove(&peer);
        }
        for entry in deferred {
            let deferred_slot = self.peer_recent_slot_for_tick(entry.expires_tick);
            self.peer_recent_ring[deferred_slot].push(entry);
        }
    }
    fn peer_recently_seen_all_keys(&self, peer_id: &PeerId, keys: &[PeerRecentSendKey]) -> bool {
        self.peer_recently_sent
            .get(peer_id)
            .is_some_and(|seen| keys.iter().all(|key| seen.contains_key(key)))
    }
    /// A peer's recent-send set applies to individual inputs, not an entire batch. A newly
    /// arrived small input must not carry a previously posted large input back into its relay.
    fn unsent_gossip_for_peer(
        &self,
        peer_id: &PeerId,
        message: &Arc<TransactionGossip>,
        keys: &[PeerRecentSendKey],
        encoded_len: usize,
    ) -> Option<(Arc<TransactionGossip>, Vec<PeerRecentSendKey>, usize)> {
        debug_assert_eq!(message.txs.len(), keys.len());
        debug_assert_eq!(message.routes.len(), keys.len());
        debug_assert_eq!(message.plans.len(), keys.len());
        let Some(seen) = self.peer_recently_sent.get(peer_id) else {
            return Some((Arc::clone(message), keys.to_vec(), encoded_len));
        };
        let unsent = keys
            .iter()
            .enumerate()
            .filter_map(|(index, key)| (!seen.contains_key(key)).then_some(index))
            .collect::<Vec<_>>();
        if unsent.is_empty() {
            return None;
        }
        if unsent.len() == keys.len() {
            return Some((Arc::clone(message), keys.to_vec(), encoded_len));
        }
        let filtered = TransactionGossip {
            txs: unsent.iter().map(|&i| message.txs[i].clone()).collect(),
            routes: unsent.iter().map(|&i| message.routes[i]).collect(),
            plans: unsent.iter().map(|&i| message.plans[i].clone()).collect(),
            plane: message.plane,
        };
        let filtered_len = filtered.encoded_len_exact()?;
        Some((
            Arc::new(filtered),
            unsent.iter().map(|&i| keys[i]).collect(),
            filtered_len,
        ))
    }
    fn post_unsent_gossip_to_peer(
        &mut self,
        peer_id: &PeerId,
        message: &Arc<TransactionGossip>,
        keys: &[PeerRecentSendKey],
        encoded_len: usize,
        priority: Priority,
    ) -> Option<(usize, usize)> {
        let (message, sent_keys, frame_bytes) =
            self.unsent_gossip_for_peer(peer_id, message, keys, encoded_len)?;
        let sent_count = sent_keys.len();
        let overflow_before = iroha_p2p::network::post_overflow_tx_gossip_count();
        self.network.post(Post {
            data: NetworkMessage::TransactionGossiper(message),
            peer_id: peer_id.clone(),
            priority,
        });
        // Best-effort P2P post has no return value. Its synchronous overflow counter is the
        // only acknowledgement available here; a rejected post must stay eligible for retry.
        if iroha_p2p::network::post_overflow_tx_gossip_count() != overflow_before {
            return None;
        }
        self.remember_peer_recent_sends(std::slice::from_ref(peer_id), &sent_keys, frame_bytes);
        Some((sent_count, frame_bytes))
    }
    fn filter_targets_by_peer_recent_suppression(
        &self,
        targets: Vec<PeerId>,
        keys: &[PeerRecentSendKey],
    ) -> (Vec<PeerId>, usize) {
        if keys.is_empty() || targets.is_empty() {
            return (targets, 0);
        }
        let mut filtered = Vec::with_capacity(targets.len());
        let mut suppressed = 0usize;
        for peer in &targets {
            if self.peer_recently_seen_all_keys(peer, keys) {
                suppressed = suppressed.saturating_add(1);
            } else {
                filtered.push(peer.clone());
            }
        }
        (filtered, suppressed)
    }
    fn filter_targets_or_replay_recent_suppressed(
        &self,
        targets: Vec<PeerId>,
        keys: &[PeerRecentSendKey],
    ) -> (Vec<PeerId>, usize, bool) {
        if keys.is_empty() || targets.is_empty() {
            return (targets, 0, false);
        }
        let (targets, suppressed) = self.filter_targets_by_peer_recent_suppression(targets, keys);
        (targets, suppressed, false)
    }
    fn peer_recent_ttl_ticks(&self, frame_bytes: usize) -> u64 {
        let base = u64::try_from(self.peer_recent_ring.len()).expect("ring length fits u64");
        let frames = frame_bytes
            .max(1)
            .div_ceil(GOSSIP_RESEND_PACING_QUANTUM_BYTES);
        base.max(u64::try_from(frames).unwrap_or(u64::MAX))
    }
    fn remember_peer_recent_sends(
        &mut self,
        targets: &[PeerId],
        keys: &[PeerRecentSendKey],
        frame_bytes: usize,
    ) {
        if targets.is_empty() || keys.is_empty() || self.peer_recent_ring.is_empty() {
            return;
        }
        let ttl_ticks = self.peer_recent_ttl_ticks(frame_bytes);
        let expires_tick = self.gossip_tick.saturating_add(ttl_ticks);
        let slot_idx = self.peer_recent_slot_for_tick(expires_tick);
        let slot = &mut self.peer_recent_ring[slot_idx];
        for peer_id in targets {
            let peer_map = self.peer_recently_sent.entry(peer_id.clone()).or_default();
            for key in keys {
                if peer_map.insert(*key, expires_tick) != Some(expires_tick) {
                    slot.push(PeerRecentSuppressionEntry {
                        peer_id: peer_id.clone(),
                        key: *key,
                        expires_tick,
                    });
                }
            }
        }
    }
    #[allow(clippy::too_many_lines)]
    fn gossip_transactions(&mut self) {
        let now = Instant::now();
        if self.gossip_backpressure_active(now) {
            iroha_logger::trace!(
                drops = self.last_drop_count,
                cooldown_ms = self.backpressure_cooldown().as_millis(),
                "transaction gossiper skipping gossip due to relay backpressure"
            );
            return;
        }
        self.expire_peer_recent_suppression();
        self.release_deferred_gossip();
        let (entries, lane_config, lane_catalog, dataspace_catalog, active_lane_ids) = {
            let nexus = self.state.nexus_snapshot();
            let lane_config = nexus.lane_config.clone();
            let lane_catalog = nexus.lane_catalog.clone();
            let dataspace_catalog = nexus.dataspace_catalog.clone();
            let active_lane_ids = active_gossip_lane_ids(&self.state, &nexus);
            let entries = self
                .queue
                .gossip_batch_with_state(self.gossip_size.get(), &self.state);
            (
                entries,
                lane_config,
                lane_catalog,
                dataspace_catalog,
                active_lane_ids,
            )
        };
        if entries.is_empty() {
            self.advance_gossip_tick();
            return;
        }
        let public_seed = self.public_seed.current(now);
        let restricted_seed = self.restricted_seed.current(now);
        #[cfg(feature = "telemetry")]
        {
            self.record_gossip_caps();
        }
        let mut validated = Vec::with_capacity(entries.len());
        for entry in entries {
            let route = GossipRoute {
                lane_id: entry.routing.lane_id,
                dataspace_id: entry.routing.dataspace_id,
            };
            if let Err(reason) =
                validate_route(&lane_catalog, &dataspace_catalog, &active_lane_ids, route)
            {
                iroha_logger::warn!(
                    lane_id = %route.lane_id,
                    dataspace_id = %route.dataspace_id,
                    reason,
                    "dropping transaction gossip entry before broadcast"
                );
                let plane = dataspace_plane(&lane_config, route.dataspace_id)
                    .unwrap_or(GossipPlane::Restricted);
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    reason,
                    &[],
                    self.target_cap_for_plane(plane),
                    0,
                    0,
                );
                continue;
            }
            validated.push(entry);
        }
        for ((dataspace_id, lane_id), entries) in restricted::group_by_route(validated) {
            let lane_ids = [lane_id];
            let plane = dataspace_plane(&lane_config, dataspace_id).or({
                if self.dataspace_cfg.drop_unknown_dataspace {
                    None
                } else {
                    Some(GossipPlane::Restricted)
                }
            });
            let Some(plane) = plane else {
                iroha_logger::warn!(
                    dataspace = %dataspace_id,
                    "dataspace missing from lane catalog; requeueing gossip batch"
                );
                self.defer_gossip_hashes(entries.iter().map(|entry| entry.tx.hash_as_entrypoint()));
                self.record_drop_metric(
                    GossipPlane::Restricted,
                    dataspace_id,
                    &lane_ids,
                    "unknown_dataspace",
                    &[],
                    self.target_cap_for_plane(GossipPlane::Restricted),
                    entries.len(),
                    0,
                );
                continue;
            };
            match plane {
                GossipPlane::Public => {
                    self.gossip_public(dataspace_id, &lane_ids, entries, public_seed);
                }
                GossipPlane::Restricted => {
                    self.gossip_restricted(dataspace_id, lane_id, entries, restricted_seed)
                }
            }
        }
        self.advance_gossip_tick();
    }
    fn gossip_priority(&self) -> Priority {
        let pressure = self.queue.pressure_snapshot();
        if pressure.saturated_by_age || pressure.saturated_by_count {
            Priority::High
        } else {
            Priority::Low
        }
    }
    #[allow(clippy::too_many_lines)]
    fn gossip_public(
        &mut self,
        dataspace_id: DataSpaceId,
        lane_ids: &[LaneId],
        entries: Vec<GossipBatchEntry>,
        gossip_seed: u64,
    ) {
        if entries.is_empty() {
            return;
        }
        let PartitionedGossipBatch {
            message,
            requeue,
            encoded_len,
        } = partition_gossip_batch(
            self.gossip_size.get() as usize,
            self.tx_frame_cap,
            GossipPlane::Public,
            entries,
        );
        if !requeue.is_empty() {
            self.defer_gossip_hashes(requeue);
        }
        if message.txs.is_empty() {
            iroha_logger::debug!(
                frame_cap = self.tx_frame_cap,
                "Skipping transaction gossip broadcast because current frame cap cannot fit any transaction"
            );
            self.record_drop_metric(
                GossipPlane::Public,
                dataspace_id,
                lane_ids,
                "frame_cap_too_small",
                &[],
                self.target_cap_for_plane(GossipPlane::Public),
                0,
                encoded_len,
            );
            return;
        }
        let mut sent_hashes = Vec::with_capacity(message.txs.len());
        let mut sent_keys = Vec::with_capacity(message.txs.len());
        for tx in &message.txs {
            sent_hashes.push(tx.hash());
            sent_keys.push(PeerRecentSendKey::from_gossip(tx));
        }
        let batch_txs = message.txs.len();
        let frame_bytes = encoded_len;
        let targets: Vec<PeerId> = self
            .network
            .online_peers(|online| online.iter().map(|peer| peer.id().clone()).collect());
        let total_online = targets.len();
        let seed = Self::seed_for_plane(gossip_seed, dataspace_id, GOSSIP_SEED_PUBLIC_DOMAIN);
        let priority = { self.gossip_priority() };
        let public_target_cap = if matches!(priority, Priority::High) {
            None
        } else {
            Self::effective_public_target_cap(
                self.dataspace_cfg.public_target_cap,
                self.gossip_size,
                self.queue.active_len(),
                self.queue.current_backpressure().is_saturated(),
            )
        };
        let (targets, suppressed_targets, replaying_suppressed_targets) =
            self.filter_targets_or_replay_recent_suppressed(targets, &sent_keys);
        let (targets, _) = Self::select_targets_with_seed(targets, public_target_cap, seed);
        if targets.is_empty() {
            iroha_logger::debug!(
                tx_count = batch_txs,
                dataspace = %dataspace_id,
                suppressed_targets,
                "skipping public gossip batch after per-peer suppression"
            );
            self.defer_gossip_hashes(sent_hashes);
            self.record_drop_metric(
                GossipPlane::Public,
                dataspace_id,
                lane_ids,
                DROP_REASON_PEER_RECENT_SUPPRESSION,
                &[],
                self.target_cap_for_plane(GossipPlane::Public),
                batch_txs,
                frame_bytes,
            );
            return;
        }
        let message = Arc::new(message);
        if public_target_cap.is_some() {
            iroha_logger::debug!(
                tx_count = batch_txs,
                size_bytes = encoded_len,
                targets = targets.len(),
                high_priority = matches!(priority, Priority::High),
                suppressed_targets,
                replaying_suppressed_targets,
                online_peers = total_online,
                dataspace = %dataspace_id,
                "gossiping public transaction batch to capped target set"
            );
            for peer_id in &targets {
                if let Some((sent_count, sent_bytes)) = self.post_unsent_gossip_to_peer(
                    peer_id,
                    &message,
                    &sent_keys,
                    frame_bytes,
                    priority,
                ) {
                    self.record_sent_metric(
                        GossipPlane::Public,
                        dataspace_id,
                        lane_ids,
                        std::slice::from_ref(peer_id),
                        public_target_cap,
                        sent_count,
                        sent_bytes,
                        replaying_suppressed_targets
                            .then_some(OUTCOME_PEER_RECENT_SUPPRESSION_REPLAY),
                    );
                }
            }
            // Re-enqueue sent hashes when we gossip to a capped target set so the batch can
            // continue spreading to other peers in subsequent rounds.
            self.defer_gossip_hashes(sent_hashes);
        } else {
            let every_target_needs_full_batch = targets.iter().all(|peer_id| {
                self.peer_recently_sent
                    .get(peer_id)
                    .is_none_or(|seen| sent_keys.iter().all(|key| !seen.contains_key(key)))
            });
            if suppressed_targets == 0 && every_target_needs_full_batch {
                iroha_logger::debug!(
                    tx_count = batch_txs,
                    size_bytes = encoded_len,
                    high_priority = matches!(priority, Priority::High),
                    online_peers = total_online,
                    dataspace = %dataspace_id,
                    "broadcasting transaction gossip batch"
                );
                let overflow_before = iroha_p2p::network::post_overflow_tx_gossip_count();
                self.network.broadcast(Broadcast {
                    data: NetworkMessage::TransactionGossiper(Arc::clone(&message)),
                    priority,
                });
                if iroha_p2p::network::post_overflow_tx_gossip_count() == overflow_before {
                    self.record_sent_metric(
                        GossipPlane::Public,
                        dataspace_id,
                        lane_ids,
                        &targets,
                        public_target_cap,
                        batch_txs,
                        frame_bytes,
                        None,
                    );
                    self.remember_peer_recent_sends(&targets, &sent_keys, frame_bytes);
                }
            } else {
                iroha_logger::debug!(
                    tx_count = batch_txs,
                    size_bytes = encoded_len,
                    targets = targets.len(),
                    high_priority = matches!(priority, Priority::High),
                    suppressed_targets,
                    replaying_suppressed_targets,
                    online_peers = total_online,
                    dataspace = %dataspace_id,
                    "gossiping public transaction batch to unsuppressed peer subset"
                );
                for peer_id in &targets {
                    if let Some((sent_count, sent_bytes)) = self.post_unsent_gossip_to_peer(
                        peer_id,
                        &message,
                        &sent_keys,
                        frame_bytes,
                        priority,
                    ) {
                        self.record_sent_metric(
                            GossipPlane::Public,
                            dataspace_id,
                            lane_ids,
                            std::slice::from_ref(peer_id),
                            public_target_cap,
                            sent_count,
                            sent_bytes,
                            replaying_suppressed_targets
                                .then_some(OUTCOME_PEER_RECENT_SUPPRESSION_REPLAY),
                        );
                    }
                }
            }
            // Broadcast is best-effort during startup and under targeted ingress load. Keep
            // pending transactions on the resend ring until consensus removes them from the queue.
            self.retry_public_broadcast_hashes(sent_hashes);
        }
    }
    #[allow(clippy::too_many_lines)]
    fn gossip_restricted(
        &mut self,
        dataspace_id: DataSpaceId,
        lane_id: LaneId,
        entries: Vec<GossipBatchEntry>,
        gossip_seed: u64,
    ) {
        let lane_ids = &[lane_id];
        if entries.is_empty() {
            return;
        }
        let PartitionedGossipBatch {
            message,
            requeue,
            encoded_len,
        } = partition_gossip_batch(
            self.gossip_size.get() as usize,
            self.tx_frame_cap,
            GossipPlane::Restricted,
            entries,
        );
        if !requeue.is_empty() {
            self.defer_gossip_hashes(requeue);
        }
        if message.txs.is_empty() {
            iroha_logger::debug!(
                frame_cap = self.tx_frame_cap,
                %dataspace_id,
                "Skipping restricted transaction gossip because current frame cap cannot fit any transaction"
            );
            self.record_drop_metric(
                GossipPlane::Restricted,
                dataspace_id,
                lane_ids,
                "frame_cap_too_small",
                &[],
                self.target_cap_for_plane(GossipPlane::Restricted),
                0,
                encoded_len,
            );
            return;
        }
        let batch_txs = message.txs.len();
        let frame_bytes = encoded_len;
        let mut sent_hashes = Vec::with_capacity(message.txs.len());
        let mut sent_keys = Vec::with_capacity(message.txs.len());
        for tx in &message.txs {
            sent_hashes.push(tx.hash());
            sent_keys.push(PeerRecentSendKey::from_gossip(tx));
        }
        let seed = Self::seed_for_plane(gossip_seed, dataspace_id, GOSSIP_SEED_RESTRICTED_DOMAIN);
        let priority = { self.gossip_priority() };
        let targets = match self.restricted_target_plan(
            GossipRoute {
                lane_id,
                dataspace_id,
            },
            seed,
            matches!(priority, Priority::High),
        ) {
            Ok(targets) => targets,
            Err(reason) => {
                self.defer_gossip_hashes(sent_hashes);
                self.record_drop_metric(
                    GossipPlane::Restricted,
                    dataspace_id,
                    lane_ids,
                    reason,
                    &[],
                    self.target_cap_for_plane(GossipPlane::Restricted),
                    batch_txs,
                    encoded_len,
                );
                return;
            }
        };
        let (targets, suppressed_targets, replaying_suppressed_targets) =
            self.filter_targets_or_replay_recent_suppressed(targets, &sent_keys);
        if targets.is_empty() {
            self.defer_gossip_hashes(sent_hashes);
            self.record_drop_metric(
                GossipPlane::Restricted,
                dataspace_id,
                lane_ids,
                DROP_REASON_PEER_RECENT_SUPPRESSION,
                &[],
                self.target_cap_for_plane(GossipPlane::Restricted),
                batch_txs,
                encoded_len,
            );
            return;
        }
        let message = Arc::new(message);
        for peer_id in &targets {
            if let Some((sent_count, sent_bytes)) = self.post_unsent_gossip_to_peer(
                peer_id,
                &message,
                &sent_keys,
                frame_bytes,
                priority,
            ) {
                self.record_sent_metric(
                    GossipPlane::Restricted,
                    dataspace_id,
                    lane_ids,
                    std::slice::from_ref(peer_id),
                    self.dataspace_cfg.restricted_target_cap,
                    sent_count,
                    sent_bytes,
                    if replaying_suppressed_targets {
                        Some(OUTCOME_PEER_RECENT_SUPPRESSION_REPLAY)
                    } else {
                        None
                    },
                );
            }
        }
        iroha_logger::debug!(
            tx_count = message.txs.len(),
            size_bytes = encoded_len,
            targets = targets.len(),
            high_priority = matches!(priority, Priority::High),
            suppressed_targets,
            replaying_suppressed_targets,
            %dataspace_id,
            "gossiping restricted transactions to the committed native lane committee"
        );
        self.defer_gossip_hashes(sent_hashes);
    }
    #[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
    #[allow(clippy::unused_self)]
    #[allow(clippy::too_many_arguments)]
    fn record_drop_metric(
        &self,
        plane: GossipPlane,
        dataspace: DataSpaceId,
        lane_ids: &[LaneId],
        reason: &str,
        targets: &[PeerId],
        target_cap: Option<NonZeroUsize>,
        batch_txs: usize,
        frame_bytes: usize,
    ) {
        iroha_logger::debug!(
            %dataspace,
            reason,
            plane = gossip_plane_label(plane),
            lanes = ?lane_ids,
            "transaction gossip drop recorded for dataspace"
        );
        #[cfg(not(feature = "telemetry"))]
        {
            let _ = (targets, target_cap, batch_txs, frame_bytes);
        }
        #[cfg(feature = "telemetry")]
        {
            self.state.telemetry.record_tx_gossip_attempt(
                plane,
                dataspace,
                lane_ids,
                targets,
                target_cap,
                false,
                Some(reason),
                batch_txs,
                frame_bytes,
            );
        }
    }
    #[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
    #[allow(clippy::unused_self)]
    #[allow(clippy::too_many_arguments)]
    fn record_sent_metric(
        &self,
        plane: GossipPlane,
        dataspace: DataSpaceId,
        lane_ids: &[LaneId],
        targets: &[PeerId],
        target_cap: Option<NonZeroUsize>,
        batch_txs: usize,
        frame_bytes: usize,
        reason: Option<&str>,
    ) {
        iroha_logger::debug!(
            %dataspace,
            targets = targets.len(),
            plane = gossip_plane_label(plane),
            lanes = ?lane_ids,
            "transaction gossip sent metric recorded"
        );
        #[cfg(not(feature = "telemetry"))]
        {
            let _ = (target_cap, batch_txs, frame_bytes, reason);
        }
        #[cfg(feature = "telemetry")]
        {
            self.state.telemetry.record_tx_gossip_attempt(
                plane,
                dataspace,
                lane_ids,
                targets,
                target_cap,
                true,
                reason,
                batch_txs,
                frame_bytes,
            );
        }
    }
    #[cfg(feature = "telemetry")]
    fn record_gossip_caps(&self) {
        self.state.telemetry.record_tx_gossip_caps(
            self.tx_frame_cap,
            self.dataspace_cfg.public_target_cap.map(NonZeroUsize::get),
            self.dataspace_cfg
                .restricted_target_cap
                .map(NonZeroUsize::get),
            self.dataspace_cfg.drop_unknown_dataspace,
            self.dataspace_cfg.public_target_reshuffle,
            self.dataspace_cfg.restricted_target_reshuffle,
        );
    }
    fn target_cap_for_plane(&self, plane: GossipPlane) -> Option<NonZeroUsize> {
        match plane {
            GossipPlane::Public => self.dataspace_cfg.public_target_cap,
            GossipPlane::Restricted => self.dataspace_cfg.restricted_target_cap,
        }
    }
    fn effective_public_target_cap(
        configured_cap: Option<NonZeroUsize>,
        gossip_size: NonZeroU32,
        queue_active_len: usize,
        queue_saturated: bool,
    ) -> Option<NonZeroUsize> {
        let configured_cap = configured_cap?;
        if queue_saturated {
            return None;
        }
        let backlog_threshold = (gossip_size.get() as usize)
            .max(configured_cap.get())
            .saturating_mul(2);
        if queue_active_len >= backlog_threshold {
            None
        } else {
            Some(configured_cap)
        }
    }
    fn seed_for_plane(seed: u64, dataspace_id: DataSpaceId, domain: u64) -> u64 {
        splitmix64(seed ^ dataspace_id.as_u64() ^ domain)
    }
    fn initial_target_seed(
        network_id: &NetworkId,
        self_peer_id: &PeerId,
        max_peer_id: &PeerId,
        domain: u64,
    ) -> u64 {
        let self_peer = self_peer_id.encode();
        let max_peer = max_peer_id.encode();
        let mut material = Vec::with_capacity(
            b"iroha:tx-gossip-target-seed:v2\0".len()
                + Hash::LENGTH
                + core::mem::size_of::<u64>() * 3
                + self_peer.len()
                + max_peer.len(),
        );
        material.extend_from_slice(b"iroha:tx-gossip-target-seed:v2\0");
        material.extend_from_slice(network_id.as_bytes());
        material.extend_from_slice(&domain.to_be_bytes());
        material.extend_from_slice(
            &u64::try_from(self_peer.len())
                .expect("canonical peer id length fits in u64")
                .to_be_bytes(),
        );
        material.extend_from_slice(&self_peer);
        material.extend_from_slice(
            &u64::try_from(max_peer.len())
                .expect("canonical peer id length fits in u64")
                .to_be_bytes(),
        );
        material.extend_from_slice(&max_peer);
        let digest = Hash::new(&material);
        let mut seed = [0_u8; 8];
        seed.copy_from_slice(&digest.as_ref()[..8]);
        u64::from_le_bytes(seed)
    }
    /// Deterministically shuffle targets by seed and return a capped subset.
    fn select_targets_with_seed(
        mut targets: Vec<PeerId>,
        cap: Option<NonZeroUsize>,
        seed: u64,
    ) -> (Vec<PeerId>, usize) {
        targets.sort();
        targets.dedup();
        let total = targets.len();
        let Some(cap) = cap else {
            return (targets, total);
        };
        let cap = cap.get();
        if total <= cap {
            return (targets, total);
        }
        let mut scored: Vec<(u64, PeerId)> = Vec::with_capacity(total);
        for peer in targets {
            scored.push((Self::peer_target_score(&peer, seed), peer));
        }
        scored.sort_by_key(|(score, _)| *score);
        scored.truncate(cap);
        let mut targets = Vec::with_capacity(scored.len());
        for (_, peer) in scored {
            targets.push(peer);
        }
        (targets, total)
    }
    /// Stable score for a peer keyed by the gossip seed.
    fn peer_target_score(peer_id: &PeerId, seed: u64) -> u64 {
        let mut state = seed;
        let payload = match peer_id.public_key().try_to_bytes() {
            Ok((algorithm, payload)) => {
                state ^= u64::from(algorithm as u8);
                payload
            }
            Err(_) => {
                state ^= u64::from(u8::MAX);
                let marker = peer_id.public_key().to_string();
                for chunk in marker.as_bytes().chunks(8) {
                    let mut buf = [0u8; 8];
                    buf[..chunk.len()].copy_from_slice(chunk);
                    state = splitmix64(state ^ u64::from_le_bytes(buf));
                }
                return splitmix64(state);
            }
        };
        for chunk in payload.chunks(8) {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            state = splitmix64(state ^ u64::from_le_bytes(buf));
        }
        splitmix64(state)
    }
    fn restricted_target_plan(
        &self,
        route: GossipRoute,
        seed: u64,
        urgent_gossip: bool,
    ) -> Result<Vec<PeerId>, &'static str> {
        let online = self
            .network
            .online_peers(|online| online.iter().map(|peer| peer.id().clone()).collect());
        let view = self.state.view();
        restricted::targets(
            &view.world,
            u64::try_from(view.height()).unwrap_or(u64::MAX),
            route,
            &online,
            if urgent_gossip {
                None
            } else {
                self.dataspace_cfg.restricted_target_cap
            },
            seed,
        )
    }
    fn validate_restricted_recipient(&self, route: GossipRoute) -> Result<(), &'static str> {
        let view = self.state.view();
        let members = restricted::committee(
            &view.world,
            u64::try_from(view.height()).unwrap_or(u64::MAX),
            route,
        )?;
        if members.contains(&self.self_peer_id) {
            Ok(())
        } else {
            Err("not_native_lane_member")
        }
    }
    fn is_transaction_known_locally(
        &self,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
        committed_transactions: &impl TransactionsReadOnly,
    ) -> bool {
        if self.queue.contains_entrypoint_hash(entrypoint_hash) {
            return true;
        }
        committed_transactions.get(&entrypoint_hash).is_some()
    }
    fn is_transaction_known_locally_cached(
        &self,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
        committed_transactions: &impl TransactionsReadOnly,
    ) -> bool {
        if KNOWN_ENTRYPOINT_CACHE.with(|cache| cache.borrow().contains(entrypoint_hash)) {
            return true;
        }
        if self.is_transaction_known_locally(entrypoint_hash, committed_transactions) {
            KNOWN_ENTRYPOINT_CACHE.with(|cache| cache.borrow_mut().remember(entrypoint_hash));
            return true;
        }
        false
    }
    /// Consume the original authenticated transport envelope through current signed admission.
    fn handle_retained_gossip(&self, message: RetainedGossip<Arc<TransactionGossip>>) {
        message.with_payload(|gossip| match Arc::try_unwrap(gossip) {
            Ok(owned) => self.handle_transaction_gossip_owned(owned),
            Err(shared) => self.handle_transaction_gossip_shared(shared.as_ref()),
        });
    }
    /// One physical attempt using the same production receive path.
    #[cfg(test)]
    fn handle_transaction_gossip(&self, gossip: Arc<TransactionGossip>) {
        self.handle_retained_gossip(RetainedGossip::synthetic_for_test(gossip));
    }
    fn reject_oversized_incoming_batch(
        &self,
        plane: GossipPlane,
        transaction_count: usize,
    ) -> bool {
        let max_transactions = self
            .gossip_size
            .get()
            .min(TRANSACTION_GOSSIP_MAX_SIZE.get()) as usize;
        if transaction_count <= max_transactions {
            return false;
        }
        iroha_logger::warn!(
            transaction_count,
            max_transactions,
            "dropping transaction gossip batch above the configured transaction-count limit"
        );
        self.record_drop_metric(
            plane,
            DataSpaceId::UNIVERSAL,
            &[],
            "transaction_count_limit",
            &[],
            self.target_cap_for_plane(plane),
            transaction_count,
            0,
        );
        true
    }
    #[allow(clippy::too_many_lines)]
    fn handle_transaction_gossip_owned(
        &self,
        TransactionGossip {
            txs,
            routes,
            plans,
            plane,
        }: TransactionGossip,
    ) {
        struct MaterializedGossipCandidate {
            entrypoint: TransactionEntrypoint,
            payload: Arc<Vec<u8>>,
            entrypoint_hash: HashOf<TransactionEntrypoint>,
            route: GossipRoute,
            plan: RoutingPlan,
            prepared: Option<PreparedTransactionMetadata>,
            ed25519_prechecked: bool,
            precheck_rejection: Option<AcceptTransactionFail>,
        }

        iroha_logger::debug!(size = txs.len(), "received transaction gossip batch");
        let batch_txs = txs.len();
        if self.reject_oversized_incoming_batch(plane, batch_txs) {
            return;
        }
        if routes.is_empty() {
            iroha_logger::warn!("dropping transaction gossip without routing metadata");
            self.record_drop_metric(
                plane,
                DataSpaceId::UNIVERSAL,
                &[],
                "missing_routes",
                &[],
                self.target_cap_for_plane(plane),
                batch_txs,
                0,
            );
            return;
        }
        if routes.len() > txs.len() || plans.len() > txs.len() {
            let reason = match (routes.len() > txs.len(), plans.len() > txs.len()) {
                (true, true) => "extra_route_and_plan_metadata",
                (true, false) => "extra_route_metadata",
                (false, true) => "extra_plan_metadata",
                (false, false) => {
                    unreachable!("extra metadata guard only runs on overlong vectors")
                }
            };
            iroha_logger::warn!(
                routes = routes.len(),
                plans = plans.len(),
                txs = txs.len(),
                reason,
                "dropping transaction gossip with unpaired routing metadata"
            );
            self.record_drop_metric(
                plane,
                DataSpaceId::UNIVERSAL,
                &[],
                reason,
                &[],
                self.target_cap_for_plane(plane),
                batch_txs,
                0,
            );
            return;
        }
        if routes.len() != txs.len() {
            iroha_logger::warn!(
                routes = routes.len(),
                txs = txs.len(),
                "transaction gossip route/tx length mismatch; dropping entries with missing metadata"
            );
        }
        if plans.len() != txs.len() {
            iroha_logger::warn!(
                plans = plans.len(),
                txs = txs.len(),
                "transaction gossip plan/tx length mismatch; dropping entries with missing metadata"
            );
        }
        let nexus = self.state.nexus_snapshot();
        let lane_catalog = nexus.lane_catalog.clone();
        let dataspace_catalog = nexus.dataspace_catalog.clone();
        let lane_config = nexus.lane_config.clone();
        let (max_clock_drift, tx_limits) = {
            let world_view = self.state.world_view();
            let params = &world_view.parameters;
            (params.sumeragi().max_clock_drift(), params.transaction())
        };
        let crypto_cfg = self.state.crypto();
        let mut batch_seen_hashes = BTreeSet::new();
        let state = self.state.as_ref();
        let committed_transactions = state.transactions.view();
        let ed25519_batch_cap = self.state.installed_pipeline().signature_batch_max_ed25519;
        let stateless_cache_cap = self.state.installed_pipeline().stateless_cache_cap;
        let active_lane_ids = active_gossip_lane_ids(state, &nexus);
        let mut materialized = Vec::with_capacity(batch_txs);
        for (idx, tx) in txs.into_iter().enumerate() {
            let Some(route) = routes.get(idx).copied() else {
                iroha_logger::warn!("route metadata missing for transaction gossip entry");
                self.record_drop_metric(
                    plane,
                    DataSpaceId::UNIVERSAL,
                    &[],
                    "missing_route_entry",
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            };
            let Some(plan) = plans.get(idx).cloned() else {
                iroha_logger::warn!("routing plan metadata missing for transaction gossip entry");
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    "missing_plan_entry",
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            };
            if let Err(error) = crate::queue::validate_current_admission_route(&plan) {
                iroha_logger::warn!(%error, "dropping unsupported_transaction_admission gossip");
                continue;
            }
            if plan.coordinator_route() != RoutingDecision::new(route.lane_id, route.dataspace_id) {
                iroha_logger::warn!(
                    lane_id = %route.lane_id,
                    dataspace_id = %route.dataspace_id,
                    "dropping transaction gossip entry due to route/plan coordinator mismatch"
                );
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    "route_plan_mismatch",
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            }
            if let Err(reason) =
                validate_route(&lane_catalog, &dataspace_catalog, &active_lane_ids, route)
            {
                iroha_logger::warn!(
                    lane_id = %route.lane_id,
                    dataspace_id = %route.dataspace_id,
                    reason,
                    "dropping transaction gossip entry due to invalid route"
                );
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    reason,
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            }
            if let Err(reason) = validate_advertised_routing_plan(
                &lane_catalog,
                &dataspace_catalog,
                &active_lane_ids,
                &plan,
            ) {
                iroha_logger::warn!(
                    lane_id = %route.lane_id,
                    dataspace_id = %route.dataspace_id,
                    reason,
                    "dropping transaction gossip entry due to invalid routing plan"
                );
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    reason,
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            }
            let expected_plane = dataspace_plane(&lane_config, route.dataspace_id).or({
                if self.dataspace_cfg.drop_unknown_dataspace {
                    None
                } else {
                    Some(GossipPlane::Restricted)
                }
            });
            let Some(expected_plane) = expected_plane else {
                iroha_logger::warn!(
                    lane_id = %route.lane_id,
                    dataspace_id = %route.dataspace_id,
                    "dropping transaction gossip entry due to unknown dataspace"
                );
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    "unknown_dataspace",
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            };
            if plane == GossipPlane::Restricted && route.dataspace_id == DataSpaceId::UNIVERSAL {
                iroha_logger::warn!(
                    lane_id = %route.lane_id,
                    "restricted plane reported universal dataspace; dropping entry"
                );
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    "restricted_universal_dataspace",
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            }
            if expected_plane != plane {
                iroha_logger::warn!(
                    lane_id = %route.lane_id,
                    dataspace_id = %route.dataspace_id,
                    plane = ?plane,
                    expected_plane = ?expected_plane,
                    "dropping transaction gossip entry due to plane mismatch"
                );
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    "plane_mismatch",
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            }
            if plane == GossipPlane::Restricted
                && let Err(reason) = self.validate_restricted_recipient(route)
            {
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    reason,
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            }
            let entrypoint_hash = tx.hash();
            if !batch_seen_hashes.insert(entrypoint_hash) {
                crate::status::inc_gossip_duplicate_known_skipped();
                continue;
            }
            if self.is_transaction_known_locally_cached(entrypoint_hash, &committed_transactions) {
                crate::status::inc_gossip_duplicate_known_skipped();
                continue;
            }
            let (entrypoint, payload) = match tx.into_entrypoint_with_payload() {
                Ok(decoded) => decoded,
                Err(err) => {
                    iroha_logger::warn!(
                        %entrypoint_hash,
                        ?err,
                        "dropping transaction gossip entry due to entrypoint decode failure"
                    );
                    self.record_drop_metric(
                        plane,
                        route.dataspace_id,
                        &[route.lane_id],
                        "entrypoint_decode",
                        &[],
                        self.target_cap_for_plane(plane),
                        1,
                        0,
                    );
                    continue;
                }
            };

            let prepared = match &entrypoint {
                TransactionEntrypoint::External(signed) => {
                    Some(AcceptedTransaction::prepare_gossip_signed_metadata(
                        signed,
                        entrypoint_hash,
                        Arc::clone(&payload),
                    ))
                }
                _ => None,
            };
            materialized.push(MaterializedGossipCandidate {
                entrypoint,
                payload,
                entrypoint_hash,
                route,
                plan,
                prepared,
                ed25519_prechecked: false,
                precheck_rejection: None,
            });
        }
        if stateless_cache_cap > 0 && !materialized.is_empty() {
            let cache_context = StatelessValidationContext::new(
                *self.state.network_id_ref(),
                u64::try_from(max_clock_drift.as_millis()).unwrap_or(u64::MAX),
                tx_limits,
                crypto_cfg.allowed_signing.clone(),
            );
            let cache_now_ms = TimeSource::new_system().get_unix_time().as_millis();
            let mut cache = state.stateless_validation_cache().lock();
            cache.set_cap(stateless_cache_cap);
            cache.ensure_context(cache_context);
            for candidate in &mut materialized {
                let Some(prepared) = candidate.prepared.as_ref() else {
                    continue;
                };
                if prepared.single_ed25519_key.is_some()
                    && cache.get_ok(&prepared.stateless_cache_key, cache_now_ms)
                {
                    candidate.ed25519_prechecked = true;
                }
            }
        }
        if ed25519_batch_cap > 0 {
            #[derive(Clone, Copy)]
            struct Ed25519BatchItem {
                idx: usize,
            }
            fn verify_ed25519_batch_slices<'a>(
                messages: &[&'a [u8]],
                signatures: &[&'a [u8]],
                public_keys: &[iroha_crypto::Ed25519ParsedPublicKey],
                scratch: &mut iroha_crypto::Ed25519BatchScratch<'a>,
            ) -> Result<(), iroha_crypto::Error> {
                iroha_crypto::ed25519_verify_batch_preparsed_deterministic_with_scratch(
                    messages,
                    signatures,
                    public_keys,
                    scratch,
                )
            }
            fn signature_error(tx: &SignedTransaction, detail: String) -> AcceptTransactionFail {
                AcceptTransactionFail::SignatureVerification(SignatureVerificationFail::new(
                    tx.signature().clone(),
                    SignatureRejectionCode::InvalidSignature,
                    detail,
                ))
            }
            let mut batch_items = Vec::new();
            let mut messages = Vec::new();
            let mut signatures = Vec::new();
            let mut public_keys = Vec::new();
            for (idx, candidate) in materialized.iter().enumerate() {
                if candidate.ed25519_prechecked {
                    continue;
                }
                let TransactionEntrypoint::External(signed) = &candidate.entrypoint else {
                    continue;
                };
                let signature = signed.signature().payload().payload();
                if signature.len() != crate::tx::ED25519_SIGNATURE_LENGTH {
                    continue;
                }
                let Some(prepared) = candidate.prepared.as_ref() else {
                    continue;
                };
                let Some(public_key) = prepared.single_ed25519_key else {
                    continue;
                };
                let message: &[u8] = prepared.payload_hash.as_ref();
                batch_items.push(Ed25519BatchItem { idx });
                messages.push(message);
                signatures.push(signature);
                public_keys.push(public_key);
            }
            let mut scratch = iroha_crypto::Ed25519BatchScratch::default();
            let mut prechecked_indices = Vec::new();
            let mut precheck_rejections = Vec::new();
            for range_start in (0..batch_items.len()).step_by(ed25519_batch_cap) {
                let range_end = range_start
                    .saturating_add(ed25519_batch_cap)
                    .min(batch_items.len());
                let batch = &batch_items[range_start..range_end];
                let batch_messages = &messages[range_start..range_end];
                let batch_signatures = &signatures[range_start..range_end];
                let batch_public_keys = &public_keys[range_start..range_end];
                let batch_result = verify_ed25519_batch_slices(
                    batch_messages,
                    batch_signatures,
                    batch_public_keys,
                    &mut scratch,
                )
                .map_err(|err| {
                    iroha_crypto::ed25519_first_bad_preparsed_deterministic_with_scratch(
                        batch_messages,
                        batch_signatures,
                        batch_public_keys,
                        &mut scratch,
                    )
                    .map_or_else(|| (0, err.to_string()), |bad| bad)
                });
                match batch_result {
                    Ok(()) => prechecked_indices.extend(batch.iter().map(|item| item.idx)),
                    Err((relative_idx, detail)) => {
                        if let Some(item) = batch.get(relative_idx)
                            && let TransactionEntrypoint::External(signed) =
                                &materialized[item.idx].entrypoint
                        {
                            precheck_rejections.push((item.idx, signature_error(signed, detail)));
                        }
                    }
                }
            }
            drop(batch_items);
            drop(messages);
            drop(signatures);
            drop(public_keys);
            for idx in prechecked_indices {
                materialized[idx].ed25519_prechecked = true;
            }
            for (idx, err) in precheck_rejections {
                materialized[idx].precheck_rejection = Some(err);
            }
        }
        for mut candidate in materialized {
            let route = candidate.route;
            let advertised_plan = candidate.plan;
            let entrypoint_hash = candidate.entrypoint_hash;
            let payload = Some(Arc::clone(&candidate.payload));
            let accepted = if let Some(err) = candidate.precheck_rejection.take() {
                Err(err)
            } else {
                AcceptedTransaction::accept_gossip_entrypoint_with_payload_and_prepared_metadata(
                    candidate.entrypoint,
                    Arc::clone(&candidate.payload),
                    candidate.entrypoint_hash,
                    self.state.network_id_ref(),
                    max_clock_drift,
                    tx_limits,
                    crypto_cfg.as_ref(),
                    candidate.prepared.as_ref(),
                    candidate.ed25519_prechecked,
                )
            };
            match accepted {
                Ok(tx) => {
                    let advertised_route = RoutingDecision::new(route.lane_id, route.dataspace_id);
                    let local_plan = {
                        match self.queue.route_plan_for_gossip_with_state(&tx, state) {
                            Ok(plan) => plan,
                            Err(err) => {
                                iroha_logger::warn!(
                                    %entrypoint_hash,
                                    reason = %err,
                                    reason_label = err.as_label(),
                                    "dropping transaction gossip entry due to unresolved local route"
                                );
                                self.record_drop_metric(
                                    plane,
                                    route.dataspace_id,
                                    &[route.lane_id],
                                    "route_unresolved",
                                    &[],
                                    self.target_cap_for_plane(plane),
                                    1,
                                    0,
                                );
                                continue;
                            }
                        }
                    };
                    let local_route = local_plan.coordinator_route();
                    if local_route != advertised_route {
                        iroha_logger::warn!(
                                %entrypoint_hash,
                                advertised_lane_id = %route.lane_id,
                                advertised_dataspace_id = %route.dataspace_id,
                            expected_lane_id = %local_route.lane_id,
                            expected_dataspace_id = %local_route.dataspace_id,
                            "dropping transaction gossip entry due to routing mismatch"
                        );
                        self.record_drop_metric(
                            plane,
                            local_route.dataspace_id,
                            &[local_route.lane_id],
                            DROP_REASON_ROUTE_MISMATCH,
                            &[],
                            self.target_cap_for_plane(plane),
                            1,
                            0,
                        );
                        continue;
                    }
                    if local_plan != advertised_plan {
                        iroha_logger::warn!(
                            %entrypoint_hash,
                            advertised_digest = %advertised_plan.digest(),
                            expected_digest = %local_plan.digest(),
                            "dropping transaction gossip entry due to routing plan mismatch"
                        );
                        self.record_drop_metric(
                            plane,
                            local_route.dataspace_id,
                            &[local_route.lane_id],
                            DROP_REASON_ROUTE_MISMATCH,
                            &[],
                            self.target_cap_for_plane(plane),
                            1,
                            0,
                        );
                        continue;
                    }
                    let push_result = {
                        self.queue
                            .push_with_gossip_payload_with_state_and_routing_plan(
                                tx, state, local_plan, payload,
                            )
                    };
                    match push_result {
                        Ok(()) => {
                            iroha_logger::debug!(%entrypoint_hash, "transaction enqueued from gossip");
                        }
                        Err(crate::queue::Failure {
                            tx,
                            err: crate::queue::Error::InBlockchain,
                        }) => {
                            iroha_logger::debug!(
                                tx = %tx.hash_as_entrypoint(),
                                "Transaction already in blockchain, ignoring..."
                            )
                        }
                        Err(crate::queue::Failure {
                            tx,
                            err: crate::queue::Error::IsInQueue,
                        }) => {
                            iroha_logger::trace!(
                                tx = %tx.hash_as_entrypoint(),
                                "Transaction already in the queue, ignoring..."
                            )
                        }
                        Err(crate::queue::Failure {
                            tx,
                            err: crate::queue::Error::NexusFeeAdmissionRejected { code, reason },
                        }) => {
                            iroha_logger::debug!(
                                tx = %tx.hash_as_entrypoint(),
                                code = %code,
                                reason,
                                "Dropping gossiped transaction rejected by Nexus fee admission"
                            );
                            self.record_drop_metric(
                                plane,
                                local_route.dataspace_id,
                                &[local_route.lane_id],
                                "nexus_fee_rejected",
                                &[],
                                self.target_cap_for_plane(plane),
                                1,
                                0,
                            );
                        }
                        Err(crate::queue::Failure {
                            tx,
                            err:
                                crate::queue::Error::NexusFeeAdmissionConfigInvalid { code, reason },
                        }) => {
                            iroha_logger::warn!(
                                tx = %tx.hash_as_entrypoint(),
                                code = %code,
                                reason,
                                "Dropping gossiped transaction due to invalid Nexus fee configuration"
                            );
                            self.record_drop_metric(
                                plane,
                                local_route.dataspace_id,
                                &[local_route.lane_id],
                                "nexus_fee_config_invalid",
                                &[],
                                self.target_cap_for_plane(plane),
                                1,
                                0,
                            );
                        }
                        Err(crate::queue::Failure { tx, err }) => {
                            if matches!(
                                err,
                                crate::queue::Error::Full | crate::queue::Error::Deferred(_)
                            ) {
                                iroha_logger::debug!(
                                    tx = %tx.hash_as_entrypoint(),
                                    "queue rejected gossiped transaction due to backpressure"
                                );
                            } else {
                                iroha_logger::error!(
                                    ?err,
                                    tx = %tx.hash_as_entrypoint(),
                                    "Failed to enqueue transaction."
                                );
                            }
                        }
                    }
                }
                Err(err) => iroha_logger::error!(%err, "Transaction rejected"),
            }
        }
    }
    #[allow(clippy::too_many_lines)]
    fn handle_transaction_gossip_shared(&self, gossip: &TransactionGossip) {
        let txs = &gossip.txs;
        let routes = &gossip.routes;
        let plans = &gossip.plans;
        let plane = gossip.plane;
        iroha_logger::debug!(size = txs.len(), "received transaction gossip batch");
        let batch_txs = txs.len();
        if self.reject_oversized_incoming_batch(plane, batch_txs) {
            return;
        }
        if routes.is_empty() {
            iroha_logger::warn!("dropping transaction gossip without routing metadata");
            self.record_drop_metric(
                plane,
                DataSpaceId::UNIVERSAL,
                &[],
                "missing_routes",
                &[],
                self.target_cap_for_plane(plane),
                batch_txs,
                0,
            );
            return;
        }
        if routes.len() > txs.len() || plans.len() > txs.len() {
            let reason = match (routes.len() > txs.len(), plans.len() > txs.len()) {
                (true, true) => "extra_route_and_plan_metadata",
                (true, false) => "extra_route_metadata",
                (false, true) => "extra_plan_metadata",
                (false, false) => {
                    unreachable!("extra metadata guard only runs on overlong vectors")
                }
            };
            iroha_logger::warn!(
                routes = routes.len(),
                plans = plans.len(),
                txs = txs.len(),
                reason,
                "dropping transaction gossip with unpaired routing metadata"
            );
            self.record_drop_metric(
                plane,
                DataSpaceId::UNIVERSAL,
                &[],
                reason,
                &[],
                self.target_cap_for_plane(plane),
                batch_txs,
                0,
            );
            return;
        }
        if routes.len() != txs.len() {
            iroha_logger::warn!(
                routes = routes.len(),
                txs = txs.len(),
                "transaction gossip route/tx length mismatch; dropping entries with missing metadata"
            );
        }
        if plans.len() != txs.len() {
            iroha_logger::warn!(
                plans = plans.len(),
                txs = txs.len(),
                "transaction gossip plan/tx length mismatch; dropping entries with missing metadata"
            );
        }
        let nexus = self.state.nexus_snapshot();
        let lane_catalog = nexus.lane_catalog.clone();
        let dataspace_catalog = nexus.dataspace_catalog.clone();
        let lane_config = nexus.lane_config.clone();
        let (max_clock_drift, tx_limits) = {
            let world_view = self.state.world_view();
            let params = &world_view.parameters;
            (params.sumeragi().max_clock_drift(), params.transaction())
        };
        let crypto_cfg = self.state.crypto();
        let mut batch_seen_hashes = BTreeSet::new();
        let state = self.state.as_ref();
        let committed_transactions = state.transactions.view();
        let active_lane_ids = active_gossip_lane_ids(state, &nexus);
        for (idx, tx) in txs.iter().enumerate() {
            let Some(route) = routes.get(idx).copied() else {
                iroha_logger::warn!("route metadata missing for transaction gossip entry");
                self.record_drop_metric(
                    plane,
                    DataSpaceId::UNIVERSAL,
                    &[],
                    "missing_route_entry",
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            };
            let Some(advertised_plan) = plans.get(idx).cloned() else {
                iroha_logger::warn!("routing plan metadata missing for transaction gossip entry");
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    "missing_plan_entry",
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            };
            if let Err(error) = crate::queue::validate_current_admission_route(&advertised_plan) {
                iroha_logger::warn!(%error, "dropping unsupported_transaction_admission gossip");
                continue;
            }
            if advertised_plan.coordinator_route()
                != RoutingDecision::new(route.lane_id, route.dataspace_id)
            {
                iroha_logger::warn!(
                    lane_id = %route.lane_id,
                    dataspace_id = %route.dataspace_id,
                    "dropping transaction gossip entry due to route/plan coordinator mismatch"
                );
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    "route_plan_mismatch",
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            }

            if let Err(reason) =
                validate_route(&lane_catalog, &dataspace_catalog, &active_lane_ids, route)
            {
                iroha_logger::warn!(
                    lane_id = %route.lane_id,
                    dataspace_id = %route.dataspace_id,
                    reason,
                    "dropping transaction gossip entry due to invalid route"
                );
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    reason,
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            }
            if let Err(reason) = validate_advertised_routing_plan(
                &lane_catalog,
                &dataspace_catalog,
                &active_lane_ids,
                &advertised_plan,
            ) {
                iroha_logger::warn!(
                    lane_id = %route.lane_id,
                    dataspace_id = %route.dataspace_id,
                    reason,
                    "dropping transaction gossip entry due to invalid routing plan"
                );
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    reason,
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            }
            let expected_plane = dataspace_plane(&lane_config, route.dataspace_id).or({
                if self.dataspace_cfg.drop_unknown_dataspace {
                    None
                } else {
                    Some(GossipPlane::Restricted)
                }
            });
            let Some(expected_plane) = expected_plane else {
                iroha_logger::warn!(
                    lane_id = %route.lane_id,
                    dataspace_id = %route.dataspace_id,
                    "dropping transaction gossip entry due to unknown dataspace"
                );
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    "unknown_dataspace",
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            };
            if plane == GossipPlane::Restricted && route.dataspace_id == DataSpaceId::UNIVERSAL {
                iroha_logger::warn!(
                    lane_id = %route.lane_id,
                    "restricted plane reported universal dataspace; dropping entry"
                );
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    "restricted_universal_dataspace",
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            }
            if expected_plane != plane {
                iroha_logger::warn!(
                    lane_id = %route.lane_id,
                    dataspace_id = %route.dataspace_id,
                    plane = ?plane,
                    expected_plane = ?expected_plane,
                    "dropping transaction gossip entry due to plane mismatch"
                );
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    "plane_mismatch",
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            }
            if plane == GossipPlane::Restricted
                && let Err(reason) = self.validate_restricted_recipient(route)
            {
                self.record_drop_metric(
                    plane,
                    route.dataspace_id,
                    &[route.lane_id],
                    reason,
                    &[],
                    self.target_cap_for_plane(plane),
                    1,
                    0,
                );
                continue;
            }
            let entrypoint_hash = tx.hash();
            if !batch_seen_hashes.insert(entrypoint_hash) {
                crate::status::inc_gossip_duplicate_known_skipped();
                continue;
            }
            if self.is_transaction_known_locally_cached(entrypoint_hash, &committed_transactions) {
                crate::status::inc_gossip_duplicate_known_skipped();
                continue;
            }
            let entrypoint = match tx.materialize_entrypoint() {
                Ok(entrypoint) => (*entrypoint).clone(),
                Err(err) => {
                    iroha_logger::warn!(
                        %entrypoint_hash,
                        ?err,
                        "dropping transaction gossip entry due to invalid entrypoint payload"
                    );
                    self.record_drop_metric(
                        plane,
                        route.dataspace_id,
                        &[route.lane_id],
                        "invalid_entrypoint_payload",
                        &[],
                        self.target_cap_for_plane(plane),
                        1,
                        0,
                    );
                    continue;
                }
            };

            let payload = tx.payload();
            let accepted = {
                AcceptedTransaction::accept_gossip_entrypoint_with_payload(
                    entrypoint.clone(),
                    Arc::clone(&payload),
                    entrypoint_hash,
                    self.state.network_id_ref(),
                    max_clock_drift,
                    tx_limits,
                    crypto_cfg.as_ref(),
                )
            };
            match accepted {
                Ok(tx) => {
                    let advertised_route = RoutingDecision::new(route.lane_id, route.dataspace_id);
                    let local_plan = {
                        match self.queue.route_plan_for_gossip_with_state(&tx, state) {
                            Ok(plan) => plan,
                            Err(err) => {
                                iroha_logger::warn!(
                                    %entrypoint_hash,
                                    reason = %err,
                                    reason_label = err.as_label(),
                                    "dropping transaction gossip entry due to unresolved local route"
                                );
                                self.record_drop_metric(
                                    plane,
                                    route.dataspace_id,
                                    &[route.lane_id],
                                    "route_unresolved",
                                    &[],
                                    self.target_cap_for_plane(plane),
                                    1,
                                    0,
                                );
                                continue;
                            }
                        }
                    };
                    let local_route = local_plan.coordinator_route();
                    if local_route != advertised_route {
                        iroha_logger::warn!(
                                %entrypoint_hash,
                                advertised_lane_id = %route.lane_id,
                                advertised_dataspace_id = %route.dataspace_id,
                            expected_lane_id = %local_route.lane_id,
                            expected_dataspace_id = %local_route.dataspace_id,
                            "dropping transaction gossip entry due to routing mismatch"
                        );
                        self.record_drop_metric(
                            plane,
                            local_route.dataspace_id,
                            &[local_route.lane_id],
                            DROP_REASON_ROUTE_MISMATCH,
                            &[],
                            self.target_cap_for_plane(plane),
                            1,
                            0,
                        );
                        continue;
                    }
                    if local_plan != advertised_plan {
                        iroha_logger::warn!(
                            %entrypoint_hash,
                            advertised_digest = %advertised_plan.digest(),
                            expected_digest = %local_plan.digest(),
                            "dropping transaction gossip entry due to routing plan mismatch"
                        );
                        self.record_drop_metric(
                            plane,
                            local_route.dataspace_id,
                            &[local_route.lane_id],
                            DROP_REASON_ROUTE_MISMATCH,
                            &[],
                            self.target_cap_for_plane(plane),
                            1,
                            0,
                        );
                        continue;
                    }
                    let push_result = {
                        self.queue
                            .push_with_gossip_payload_with_state_and_routing_plan(
                                tx,
                                state,
                                local_plan,
                                Some(payload),
                            )
                    };
                    match push_result {
                        Ok(()) => {
                            iroha_logger::debug!(%entrypoint_hash, "transaction enqueued from gossip");
                        }
                        Err(crate::queue::Failure {
                            tx,
                            err: crate::queue::Error::InBlockchain,
                        }) => {
                            iroha_logger::debug!(
                                tx = %tx.hash_as_entrypoint(),
                                "Transaction already in blockchain, ignoring..."
                            )
                        }
                        Err(crate::queue::Failure {
                            tx,
                            err: crate::queue::Error::IsInQueue,
                        }) => {
                            iroha_logger::trace!(
                                tx = %tx.hash_as_entrypoint(),
                                "Transaction already in the queue, ignoring..."
                            )
                        }
                        Err(crate::queue::Failure {
                            tx,
                            err: crate::queue::Error::NexusFeeAdmissionRejected { code, reason },
                        }) => {
                            iroha_logger::debug!(
                                tx = %tx.hash_as_entrypoint(),
                                code = %code,
                                reason,
                                "Dropping gossiped transaction rejected by Nexus fee admission"
                            );
                            self.record_drop_metric(
                                plane,
                                local_route.dataspace_id,
                                &[local_route.lane_id],
                                "nexus_fee_rejected",
                                &[],
                                self.target_cap_for_plane(plane),
                                1,
                                0,
                            );
                        }
                        Err(crate::queue::Failure {
                            tx,
                            err:
                                crate::queue::Error::NexusFeeAdmissionConfigInvalid { code, reason },
                        }) => {
                            iroha_logger::warn!(
                                tx = %tx.hash_as_entrypoint(),
                                code = %code,
                                reason,
                                "Dropping gossiped transaction due to invalid Nexus fee configuration"
                            );
                            self.record_drop_metric(
                                plane,
                                local_route.dataspace_id,
                                &[local_route.lane_id],
                                "nexus_fee_config_invalid",
                                &[],
                                self.target_cap_for_plane(plane),
                                1,
                                0,
                            );
                        }
                        Err(crate::queue::Failure { tx, err }) => {
                            if matches!(
                                err,
                                crate::queue::Error::Full | crate::queue::Error::Deferred(_)
                            ) {
                                iroha_logger::debug!(
                                    tx = %tx.hash_as_entrypoint(),
                                    "queue rejected gossiped transaction due to backpressure"
                                );
                            } else {
                                iroha_logger::error!(
                                    ?err,
                                    tx = %tx.hash_as_entrypoint(),
                                    "Failed to enqueue transaction."
                                );
                            }
                        }
                    }
                }
                Err(err) => iroha_logger::error!(%err, "Transaction rejected"),
            }
        }
    }
}
fn validate_route(
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    active_lane_ids: &BTreeSet<LaneId>,
    route: GossipRoute,
) -> Result<(), &'static str> {
    let resolved = resolve_routing_decision(
        RoutingDecision::new(route.lane_id, route.dataspace_id),
        lane_catalog,
        dataspace_catalog,
    )
    .map_err(|err| err.as_label())?;
    if !active_lane_ids.contains(&resolved.lane_id) {
        return Err(DROP_REASON_INACTIVE_LANE);
    }
    Ok(())
}
fn validate_advertised_routing_plan(
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    active_lane_ids: &BTreeSet<LaneId>,
    plan: &RoutingPlan,
) -> Result<(), &'static str> {
    let resolved =
        resolve_routing_plan_against_catalogs(plan.clone(), lane_catalog, dataspace_catalog)
            .map_err(|err| err.as_label())?;
    if resolved != *plan {
        return Err(DROP_REASON_NONCANONICAL_ROUTING_PLAN);
    }
    for leg in resolved.legs() {
        if !active_lane_ids.contains(&leg.route.lane_id) {
            return Err(DROP_REASON_INACTIVE_LANE);
        }
    }
    Ok(())
}
fn dataspace_plane(lane_config: &LaneGeometry, dataspace_id: DataSpaceId) -> Option<GossipPlane> {
    // The lane catalog keeps one visibility per dataspace (`LaneCatalog::new`), so any lane
    // of the dataspace decides its plane.
    lane_config
        .entries()
        .iter()
        .find(|entry| entry.dataspace_id == dataspace_id)
        .map(|entry| match entry.visibility {
            LaneVisibility::Public => GossipPlane::Public,
            LaneVisibility::Restricted => GossipPlane::Restricted,
        })
}
pub(crate) fn gossip_plane_label(plane: GossipPlane) -> &'static str {
    match plane {
        GossipPlane::Public => "public",
        GossipPlane::Restricted => "restricted",
    }
}
#[cfg(test)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn dataspace_label(dataspace: DataSpaceId) -> String {
    dataspace.as_u64().to_string()
}
/// Message for gossiping batches of transactions.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::gossiper::TransactionGossip")]
#[derive(Debug, Clone)]
pub struct TransactionGossip {
    /// Batch of transactions.
    pub txs: Vec<GossipTransaction>,
    /// Routing metadata aligned with `txs`.
    pub routes: Vec<GossipRoute>,
    /// Full routing plans aligned with `txs`.
    pub plans: Vec<RoutingPlan>,
    /// Visibility plane this batch targets.
    pub plane: GossipPlane,
}
impl TransactionGossip {
    /// Constructor.
    pub fn new(txs: Vec<AcceptedTransaction<'static>>) -> Self {
        let mut gossip_txs = Vec::with_capacity(txs.len());
        gossip_txs.extend(txs.into_iter().map(GossipTransaction::new));
        Self {
            // Converting into non-accepted transaction because it's not possible
            // to guarantee that the sending peer checked transaction limits
            txs: gossip_txs,
            routes: Vec::new(),
            plans: Vec::new(),
            plane: GossipPlane::Public,
        }
    }
}
fn transaction_gossip_sequence_limit() -> usize {
    usize::try_from(TRANSACTION_GOSSIP_MAX_SIZE.get())
        .expect("the u32 transaction gossip limit must fit usize")
}
fn ensure_transaction_gossip_sequence_len(length: usize) -> Result<(), ncore::Error> {
    let limit = transaction_gossip_sequence_limit();
    if length <= limit {
        return Ok(());
    }
    Err(ncore::Error::SequenceLengthExceeded {
        length: u64::try_from(length).map_err(|_| ncore::Error::LengthMismatch)?,
        limit: u64::try_from(limit).map_err(|_| ncore::Error::LengthMismatch)?,
    })
}
fn len_prefixed_field_payload(bytes: &[u8], offset: usize) -> Result<(&[u8], usize), ncore::Error> {
    let field = bytes.get(offset..).ok_or(ncore::Error::LengthMismatch)?;
    let (field_len, header_len) = ncore::read_len_from_slice(field)?;
    let payload_start = offset
        .checked_add(header_len)
        .ok_or(ncore::Error::LengthMismatch)?;
    let payload_end = payload_start
        .checked_add(field_len)
        .ok_or(ncore::Error::LengthMismatch)?;
    let payload = bytes
        .get(payload_start..payload_end)
        .ok_or(ncore::Error::LengthMismatch)?;
    Ok((payload, payload_end))
}
fn decode_len_prefixed_field<T>(bytes: &[u8], offset: usize) -> Result<(T, usize), ncore::Error>
where
    T: SerializePayload + for<'de> DeserializePayload<'de>,
{
    let (payload, payload_end) = len_prefixed_field_payload(bytes, offset)?;
    let (value, used) = ncore::decode_field_canonical::<T>(payload)?;
    if used != payload.len() {
        return Err(ncore::Error::LengthMismatch);
    }
    Ok((value, payload_end))
}
fn decode_bounded_len_prefixed_sequence<T>(
    bytes: &[u8],
    offset: usize,
) -> Result<(Vec<T>, usize), ncore::Error>
where
    T: SerializePayload + for<'de> DeserializePayload<'de>,
{
    let (payload, payload_end) = len_prefixed_field_payload(bytes, offset)?;
    let (sequence_len, _) = ncore::inspect_seq_len_slice(payload)?;
    ensure_transaction_gossip_sequence_len(sequence_len)?;
    let (value, used) = ncore::decode_field_canonical::<Vec<T>>(payload)?;
    if used != payload.len() {
        return Err(ncore::Error::LengthMismatch);
    }
    Ok((value, payload_end))
}
fn decode_transaction_gossip_payload(
    bytes: &[u8],
) -> Result<(TransactionGossip, usize), ncore::Error> {
    let (txs, offset) = decode_bounded_len_prefixed_sequence::<GossipTransaction>(bytes, 0)?;
    let (routes, offset) = decode_bounded_len_prefixed_sequence::<GossipRoute>(bytes, offset)?;
    let (plans, offset) = decode_bounded_len_prefixed_sequence::<RoutingPlan>(bytes, offset)?;
    let (plane, offset) = decode_len_prefixed_field::<GossipPlane>(bytes, offset)?;
    Ok((
        TransactionGossip {
            txs,
            routes,
            plans,
            plane,
        },
        offset,
    ))
}
impl SerializePayload for TransactionGossip {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
        ensure_transaction_gossip_sequence_len(self.txs.len())?;
        ensure_transaction_gossip_sequence_len(self.routes.len())?;
        ensure_transaction_gossip_sequence_len(self.plans.len())?;
        ncore::write_len_prefixed(writer, &self.txs)?;
        ncore::write_len_prefixed(writer, &self.routes)?;
        ncore::write_len_prefixed(writer, &self.plans)?;
        ncore::write_len_prefixed(writer, &self.plane)?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.encoded_len_exact()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        let limit = transaction_gossip_sequence_limit();
        if self.txs.len() > limit || self.routes.len() > limit || self.plans.len() > limit {
            return None;
        }
        let txs_payload_len = gossip_vec_payload_len_exact(self.txs.iter())?;
        let routes_payload_len = gossip_routes_payload_len(self.routes.len())?;
        let plans_payload_len = gossip_encoded_vec_payload_len_exact(self.plans.iter())?;
        gossip_message_encoded_len(txs_payload_len, routes_payload_len, plans_payload_len)
    }
}
impl<'a> DeserializePayload<'a> for TransactionGossip {
    fn deserialize(archived: &'a ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("decode transaction gossip")
    }
    fn try_deserialize(archived: &'a ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(ptr)?;
        let (message, consumed) = decode_transaction_gossip_payload(bytes)?;
        ncore::note_payload_access(bytes, consumed);
        Ok(message)
    }
}
impl<'a> ncore::DecodeFromSlice<'a> for TransactionGossip {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        decode_transaction_gossip_payload(bytes)
    }
}
/// Gossip payload wrapper for transaction entrypoints.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::gossiper::GossipTransaction")]
#[derive(Debug)]
pub struct GossipTransaction {
    entrypoint: Arc<OnceLock<Arc<TransactionEntrypoint>>>,
    // Exactly one canonical Norito transaction entrypoint frame.
    encoded: Arc<Vec<u8>>,
    entrypoint_hash: EntrypointHash,
}
impl Clone for GossipTransaction {
    fn clone(&self) -> Self {
        Self {
            entrypoint: Arc::clone(&self.entrypoint),
            encoded: Arc::clone(&self.encoded),
            entrypoint_hash: self.entrypoint_hash,
        }
    }
}
const GOSSIP_TX_DECODE_CACHE_LIMIT: usize = 2048;
const GOSSIP_TX_DECODE_CACHE_BYTE_LIMIT: usize = 8 * 1024 * 1024;
const GOSSIP_KNOWN_ENTRYPOINT_HASH_CACHE_LIMIT: usize = 8192;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct GossipTxDecodeCacheKey {
    len: u32,
    prefix: u128,
    suffix: u128,
}
impl GossipTxDecodeCacheKey {
    fn from_bytes(bytes: &[u8]) -> Self {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let mut prefix_bytes = [0u8; 16];
        let mut suffix_bytes = [0u8; 16];
        let prefix_len = bytes.len().min(prefix_bytes.len());
        prefix_bytes[..prefix_len].copy_from_slice(&bytes[..prefix_len]);
        let suffix_len = bytes.len().min(suffix_bytes.len());
        if suffix_len > 0 {
            suffix_bytes[..suffix_len].copy_from_slice(&bytes[bytes.len() - suffix_len..]);
        }
        Self {
            len,
            prefix: u128::from_le_bytes(prefix_bytes),
            suffix: u128::from_le_bytes(suffix_bytes),
        }
    }
}
struct GossipTxDecodeCacheEntry {
    encoded: Arc<Vec<u8>>,
    entrypoint_hash: EntrypointHash,
    consumed: usize,
}
struct GossipTxDecodeCache {
    map: BTreeMap<GossipTxDecodeCacheKey, GossipTxDecodeCacheEntry>,
    bytes: usize,
    count_limit: usize,
    byte_limit: usize,
}
impl GossipTxDecodeCache {
    fn new() -> Self {
        Self::with_limits(
            GOSSIP_TX_DECODE_CACHE_LIMIT,
            GOSSIP_TX_DECODE_CACHE_BYTE_LIMIT,
        )
    }
    fn with_limits(count_limit: usize, byte_limit: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            bytes: 0,
            count_limit,
            byte_limit,
        }
    }
    fn get(&self, key: &GossipTxDecodeCacheKey) -> Option<&GossipTxDecodeCacheEntry> {
        self.map.get(key)
    }
    fn insert(&mut self, key: GossipTxDecodeCacheKey, entry: GossipTxDecodeCacheEntry) {
        let entry_len = entry.encoded.len();
        if let Some(previous) = self.map.remove(&key) {
            self.bytes = self.bytes.saturating_sub(previous.encoded.len());
        }
        if entry_len > self.byte_limit {
            return;
        }
        if self.map.len() >= self.count_limit
            || self.bytes.saturating_add(entry_len) > self.byte_limit
        {
            // Simple bounded cache: clear rather than paying LRU bookkeeping cost.
            self.map.clear();
            self.bytes = 0;
        }
        self.bytes = self.bytes.saturating_add(entry_len);
        self.map.insert(key, entry);
    }
}
thread_local! {
    static GOSSIP_TX_DECODE_CACHE: RefCell<GossipTxDecodeCache> =
        RefCell::new(GossipTxDecodeCache::new());
}
#[derive(Default)]
struct GossipKnownEntrypointHashCache {
    known: BTreeMap<HashOf<TransactionEntrypoint>, ()>,
}
impl GossipKnownEntrypointHashCache {
    fn contains(&self, entrypoint_hash: HashOf<TransactionEntrypoint>) -> bool {
        self.known.contains_key(&entrypoint_hash)
    }
    fn remember(&mut self, entrypoint_hash: HashOf<TransactionEntrypoint>) {
        if self.known.len() >= GOSSIP_KNOWN_ENTRYPOINT_HASH_CACHE_LIMIT {
            // Simple bounded cache: clear when full to keep overhead predictable.
            self.known.clear();
        }
        self.known.insert(entrypoint_hash, ());
    }
}
thread_local! {
    static KNOWN_ENTRYPOINT_CACHE: RefCell<GossipKnownEntrypointHashCache> =
        RefCell::new(GossipKnownEntrypointHashCache::default());
}
fn framed_payload_len(payload_len: usize, align: usize) -> Option<usize> {
    let padding = if align <= 1 {
        0
    } else {
        let rem = ncore::Header::SIZE % align;
        if rem == 0 { 0 } else { align - rem }
    };
    ncore::Header::SIZE
        .checked_add(padding)?
        .checked_add(payload_len)
}
struct FramedPrefixInfo {
    consumed: usize,
}
fn framed_prefix_info<T: NoritoSerialize>(bytes: &[u8]) -> Result<FramedPrefixInfo, ncore::Error> {
    const LEN_OFF: usize = 4 + 1 + 1 + 16 + 1;
    if bytes.len() < ncore::Header::SIZE {
        return Err(ncore::Error::LengthMismatch);
    }
    if bytes[..4] != ncore::MAGIC {
        return Err(ncore::Error::InvalidMagic);
    }
    if bytes.get(4) != Some(&ncore::VERSION_MAJOR) {
        return Err(ncore::Error::UnsupportedVersion {
            found: bytes[4],
            expected: ncore::VERSION_MAJOR,
        });
    }
    if bytes.get(5) != Some(&ncore::VERSION_MINOR) {
        return Err(ncore::Error::UnsupportedMinorVersion {
            found: bytes[5],
            supported: ncore::VERSION_MINOR,
        });
    }
    let schema = bytes.get(6..22).ok_or(ncore::Error::LengthMismatch)?;
    if schema != norito::schema::identity::frame_hash::<T>().as_slice() {
        return Err(ncore::Error::SchemaMismatch);
    }
    let compression = *bytes.get(22).ok_or(ncore::Error::LengthMismatch)?;
    if compression != ncore::Compression::None as u8 {
        return Err(ncore::Error::unsupported_compression_with(
            compression,
            &[ncore::Compression::None],
        ));
    }
    let len_bytes = bytes
        .get(LEN_OFF..LEN_OFF + 8)
        .ok_or(ncore::Error::LengthMismatch)?;
    let mut length = [0u8; 8];
    length.copy_from_slice(len_bytes);
    let payload_len =
        usize::try_from(u64::from_le_bytes(length)).map_err(|_| ncore::Error::LengthMismatch)?;
    let _padding = if ncore::archived_payload_align::<T>() <= 1 {
        0
    } else {
        let rem = ncore::Header::SIZE % ncore::archived_payload_align::<T>();
        if rem == 0 {
            0
        } else {
            ncore::archived_payload_align::<T>() - rem
        }
    };
    let consumed = framed_payload_len(payload_len, ncore::archived_payload_align::<T>())
        .filter(|size| *size <= bytes.len())
        .ok_or(ncore::Error::LengthMismatch)?;
    let _flags = *bytes
        .get(ncore::Header::SIZE - 1)
        .ok_or(ncore::Error::LengthMismatch)?;
    Ok(FramedPrefixInfo { consumed })
}
fn encode_transaction_entrypoint(entrypoint: &TransactionEntrypoint) -> Vec<u8> {
    norito::encode_canonical(entrypoint).expect("encode canonical transaction entrypoint")
}
fn decode_framed_transaction_entrypoint(
    framed: &[u8],
) -> Result<TransactionEntrypoint, ncore::Error> {
    norito::decode_canonical::<TransactionEntrypoint>(framed)
}
fn decode_gossip_transaction_payload(
    bytes: &[u8],
) -> Result<(Arc<Vec<u8>>, EntrypointHash, usize), ncore::Error> {
    let consumed = framed_prefix_info::<TransactionEntrypoint>(bytes)?.consumed;
    let framed = bytes.get(..consumed).ok_or(ncore::Error::LengthMismatch)?;
    let key = GossipTxDecodeCacheKey::from_bytes(framed);
    if let Some(hit) = GOSSIP_TX_DECODE_CACHE.with(|cache| {
        cache.borrow().get(&key).and_then(|entry| {
            (entry.consumed == consumed && entry.encoded.as_slice() == framed).then(|| {
                (
                    Arc::clone(&entry.encoded),
                    entry.entrypoint_hash,
                    entry.consumed,
                )
            })
        })
    }) {
        return Ok(hit);
    }
    let entrypoint_hash = crate::tx::entrypoint_hash_from_framed_bytes(framed)?;
    let encoded = Arc::new(framed.to_vec());
    GOSSIP_TX_DECODE_CACHE.with(|cache| {
        cache.borrow_mut().insert(
            key,
            GossipTxDecodeCacheEntry {
                encoded: Arc::clone(&encoded),
                entrypoint_hash,
                consumed,
            },
        )
    });
    Ok((encoded, entrypoint_hash, consumed))
}
impl GossipTransaction {
    /// Wrap an accepted transaction, dropping acceptance metadata for gossip.
    pub fn new(tx: AcceptedTransaction<'static>) -> Self {
        let encoded = tx.entrypoint_bytes();
        let entrypoint_hash = tx.hash_as_entrypoint();
        let entrypoint = tx.entrypoint().clone();
        let entrypoint_cache = OnceLock::new();
        let _ = entrypoint_cache.set(Arc::new(entrypoint));
        Self {
            entrypoint: Arc::new(entrypoint_cache),
            encoded,
            entrypoint_hash,
        }
    }
    /// Wrap an entrypoint with cached default full-frame bytes.
    pub fn with_encoded(
        entrypoint: impl Into<TransactionEntrypoint>,
        encoded: Arc<Vec<u8>>,
    ) -> Self {
        let entrypoint = entrypoint.into();
        let canonical = Arc::new(encode_transaction_entrypoint(&entrypoint));
        let encoded = if encoded.as_slice() == canonical.as_slice() {
            encoded
        } else {
            canonical
        };
        let entrypoint_hash = entrypoint.hash();
        let entrypoint_cache = OnceLock::new();
        let _ = entrypoint_cache.set(Arc::new(entrypoint));
        Self {
            entrypoint: Arc::new(entrypoint_cache),
            encoded,
            entrypoint_hash,
        }
    }
    fn lazy_from_encoded(encoded: Arc<Vec<u8>>, entrypoint_hash: EntrypointHash) -> Self {
        Self {
            entrypoint: Arc::new(OnceLock::new()),
            encoded,
            entrypoint_hash,
        }
    }
    /// Whether this gossip item has already materialized its transaction entrypoint.
    #[cfg(test)]
    fn is_entrypoint_materialized(&self) -> bool {
        self.entrypoint.get().is_some()
    }
    /// Borrow the exact canonical transaction entrypoint frame.
    fn payload(&self) -> Arc<Vec<u8>> {
        Arc::clone(&self.encoded)
    }
    fn materialize_entrypoint(&self) -> Result<Arc<TransactionEntrypoint>, ncore::Error> {
        if let Some(entrypoint) = self.entrypoint.get() {
            return Ok(Arc::clone(entrypoint));
        }
        let entrypoint = Arc::new(decode_framed_transaction_entrypoint(&self.encoded)?);
        let _ = self.entrypoint.set(Arc::clone(&entrypoint));
        Ok(self.entrypoint.get().map_or(entrypoint, Arc::clone))
    }
    /// Return the entrypoint hash without rehashing.
    pub fn hash(&self) -> HashOf<TransactionEntrypoint> {
        self.entrypoint_hash
    }
    /// Return the entrypoint hash without rehashing.
    pub fn hash_as_entrypoint(&self) -> HashOf<TransactionEntrypoint> {
        self.entrypoint_hash
    }
    /// Consume the wrapper and return its entrypoint and exact cached canonical frame.
    ///
    /// # Errors
    /// Returns the original Norito error if the cached canonical frame cannot be
    /// decoded into an entrypoint, including local decoder resource refusals.
    pub fn into_entrypoint_with_payload(
        self,
    ) -> Result<(TransactionEntrypoint, Arc<Vec<u8>>), ncore::Error> {
        let entrypoint = self.materialize_entrypoint()?;
        let entrypoint = Arc::try_unwrap(entrypoint).unwrap_or_else(|arc| (*arc).clone());
        Ok((entrypoint, self.payload()))
    }
}
impl From<SignedTransaction> for GossipTransaction {
    fn from(signed: SignedTransaction) -> Self {
        let entrypoint = TransactionEntrypoint::External(signed);
        let entrypoint_hash = entrypoint.hash();
        let encoded = Arc::new(encode_transaction_entrypoint(&entrypoint));
        let entrypoint_cache = OnceLock::new();
        let _ = entrypoint_cache.set(Arc::new(entrypoint));
        Self {
            entrypoint: Arc::new(entrypoint_cache),
            encoded,
            entrypoint_hash,
        }
    }
}
impl SerializePayload for GossipTransaction {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
        writer.write_all(self.encoded.as_slice())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.encoded_len_exact()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(self.encoded.len())
    }
}
impl<'a> DeserializePayload<'a> for GossipTransaction {
    fn deserialize(archived: &'a ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("decode gossip transaction")
    }
    fn try_deserialize(archived: &'a ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(ptr)?;
        let (encoded, entrypoint_hash, consumed) = decode_gossip_transaction_payload(bytes)?;
        ncore::note_payload_access(bytes, consumed);
        Ok(Self::lazy_from_encoded(encoded, entrypoint_hash))
    }
}
impl<'a> ncore::DecodeFromSlice<'a> for GossipTransaction {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        let (encoded, entrypoint_hash, consumed) = decode_gossip_transaction_payload(bytes)?;
        Ok((Self::lazy_from_encoded(encoded, entrypoint_hash), consumed))
    }
}
/// Visibility plane for transaction gossip frames.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::gossiper::GossipPlane")]
#[derive(Decode, Encode, Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipPlane {
    /// Public lanes/dataspaces; broadcast is permitted.
    Public,
    /// Restricted lanes/dataspaces; targets must be explicitly selected.
    Restricted,
}
fn gossip_route_encoded_len() -> Option<usize> {
    let route = GossipRoute {
        lane_id: LaneId::SINGLE,
        dataspace_id: DataSpaceId::UNIVERSAL,
    };
    route
        .encoded_len_exact()
        .or_else(|| route.encoded_len_hint())
}
fn gossip_plane_encoded_len() -> Option<usize> {
    GossipPlane::Public
        .encoded_len_exact()
        .or_else(|| GossipPlane::Public.encoded_len_hint())
}
fn gossip_message_empty_len() -> Option<usize> {
    let txs_payload_len = ncore::seq_len_prefix_len(0);
    let routes_payload_len = ncore::seq_len_prefix_len(0);
    let plans_payload_len = ncore::seq_len_prefix_len(0);
    gossip_message_encoded_len(txs_payload_len, routes_payload_len, plans_payload_len)
}
fn gossip_message_encoded_len(
    txs_payload_len: usize,
    routes_payload_len: usize,
    plans_payload_len: usize,
) -> Option<usize> {
    let plane_payload_len = gossip_plane_encoded_len()?;
    let mut total = ncore::len_prefix_len(txs_payload_len).checked_add(txs_payload_len)?;
    total = total
        .checked_add(ncore::len_prefix_len(routes_payload_len))?
        .checked_add(routes_payload_len)?;
    total = total
        .checked_add(ncore::len_prefix_len(plans_payload_len))?
        .checked_add(plans_payload_len)?;
    total = total
        .checked_add(ncore::len_prefix_len(plane_payload_len))?
        .checked_add(plane_payload_len)?;
    Some(total)
}
#[allow(single_use_lifetimes)]
fn gossip_vec_payload_len_exact<'a>(
    items: impl Iterator<Item = &'a GossipTransaction>,
) -> Option<usize> {
    let mut count = 0usize;
    let mut total = 0usize;
    for item in items {
        count = count.checked_add(1)?;
        let item_len = item.encoded_len_exact()?;
        total = total.checked_add(ncore::len_prefix_len(item_len))?;
        total = total.checked_add(item_len)?;
    }
    ncore::seq_len_prefix_len(count).checked_add(total)
}
fn gossip_encoded_vec_payload_len_exact<'a, T>(items: impl Iterator<Item = &'a T>) -> Option<usize>
where
    T: SerializePayload + 'a,
{
    let mut count = 0usize;
    let mut total = 0usize;
    for item in items {
        count = count.checked_add(1)?;
        let item_len = item
            .encoded_len_exact()
            .or_else(|| item.encoded_len_hint())?;
        total = total.checked_add(ncore::len_prefix_len(item_len))?;
        total = total.checked_add(item_len)?;
    }
    ncore::seq_len_prefix_len(count).checked_add(total)
}
fn gossip_routes_payload_len(len: usize) -> Option<usize> {
    let route_len = gossip_route_encoded_len()?;
    let per_elem = ncore::len_prefix_len(route_len).checked_add(route_len)?;
    let elems = per_elem.checked_mul(len)?;
    ncore::seq_len_prefix_len(len).checked_add(elems)
}
/// Lane/dataspace tags carried alongside gossiped transactions for visibility gating.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::gossiper::GossipRoute")]
#[derive(Debug, Clone, Copy, Decode, Encode)]
pub struct GossipRoute {
    /// Lane assigned to the transaction at the sender.
    pub lane_id: LaneId,
    /// Dataspace assigned to the transaction at the sender.
    pub dataspace_id: DataSpaceId,
}
struct PartitionedGossipBatch {
    message: TransactionGossip,
    requeue: Vec<HashOf<TransactionEntrypoint>>,
    encoded_len: usize,
}
fn partition_gossip_batch(
    max_count: usize,
    frame_cap_bytes: usize,
    plane: GossipPlane,
    txs: Vec<GossipBatchEntry>,
) -> PartitionedGossipBatch {
    let mut message = TransactionGossip {
        txs: Vec::new(),
        routes: Vec::new(),
        plans: Vec::new(),
        plane,
    };
    let reserved = max_count.min(txs.len());
    message.txs.reserve(reserved);
    message.routes.reserve(reserved);
    message.plans.reserve(reserved);
    let mut requeue = Vec::with_capacity(txs.len());
    let mut encoded_len = gossip_message_empty_len().unwrap_or(0);
    let Some(route_len) = gossip_route_encoded_len() else {
        requeue.extend(txs.into_iter().map(|entry| entry.tx.hash_as_entrypoint()));
        return PartitionedGossipBatch {
            message,
            requeue,
            encoded_len,
        };
    };
    let Some(route_entry_len) = ncore::len_prefix_len(route_len).checked_add(route_len) else {
        requeue.extend(txs.into_iter().map(|entry| entry.tx.hash_as_entrypoint()));
        return PartitionedGossipBatch {
            message,
            requeue,
            encoded_len,
        };
    };
    if frame_cap_bytes == 0 {
        requeue.extend(txs.into_iter().map(|entry| entry.tx.hash_as_entrypoint()));
        return PartitionedGossipBatch {
            message,
            requeue,
            encoded_len,
        };
    }
    for entry in txs {
        let hash = entry.tx.hash_as_entrypoint();
        if message.txs.len() >= max_count {
            requeue.push(hash);
            continue;
        }
        let routing = entry.routing;
        let routing_plan = entry.routing_plan;
        let gossip_transaction =
            GossipTransaction::with_encoded(entry.tx.entrypoint().clone(), entry.payload);
        let Some(tx_payload_len) = gossip_transaction.encoded_len_exact() else {
            requeue.push(hash);
            continue;
        };
        let Some(tx_entry_len) = ncore::len_prefix_len(tx_payload_len).checked_add(tx_payload_len)
        else {
            requeue.push(hash);
            continue;
        };
        let plan_len = routing_plan
            .encoded_len_exact()
            .or_else(|| routing_plan.encoded_len_hint())
            .unwrap_or_else(|| routing_plan.encode().len());
        let Some(plan_entry_len) = ncore::len_prefix_len(plan_len).checked_add(plan_len) else {
            requeue.push(hash);
            continue;
        };
        let Some(next_encoded_len) = encoded_len
            .checked_add(tx_entry_len)
            .and_then(|total| total.checked_add(route_entry_len))
            .and_then(|total| total.checked_add(plan_entry_len))
        else {
            requeue.push(hash);
            continue;
        };
        if next_encoded_len > frame_cap_bytes {
            requeue.push(hash);
            continue;
        }
        message.txs.push(gossip_transaction);
        message.routes.push(GossipRoute {
            lane_id: routing.lane_id,
            dataspace_id: routing.dataspace_id,
        });
        message.plans.push(routing_plan);
        encoded_len = next_encoded_len;
    }
    let mut exact_len = message.encoded_len_exact().unwrap_or(encoded_len);
    while exact_len > frame_cap_bytes && !message.txs.is_empty() {
        if let Some(removed) = message.txs.pop() {
            requeue.push(removed.hash());
        }
        message.routes.pop();
        message.plans.pop();
        exact_len = message.encoded_len_exact().unwrap_or(exact_len);
    }
    PartitionedGossipBatch {
        message,
        requeue,
        encoded_len: exact_len,
    }
}
#[cfg(test)]
mod payload_codec_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::NetworkMessage;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        queue::{LaneRouter, RoutingDecision},
        state::{State, World},
    };
    use iroha_config::{
        kura::FsyncMode,
        parameters::{
            actual::{
                Kura as KuraConfig, LaneConfig as LaneGeometry, LaneProfile, Queue as QueueConfig,
                RelayMode, SoranetHandshake, SoranetPrivacy, SoranetVpn,
            },
            defaults,
        },
    };
    use iroha_config_base::WithOrigin;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        Level,
        account::{AccountDetails, AccountValue},
        isi::{InstructionBox, Log},
        nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig, LaneVisibility},
        transaction::{
            TransactionBuilder,
            signed::{
                SealedTransactionCommitmentPayload, SignedSealedTransactionCommitment,
                TransactionSignature, compute_sealed_transaction_commitment,
            },
        },
    };
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use iroha_primitives::{addr::socket_addr, numeric::Quantity, time::TimeSource};
    use iroha_test_samples::{
        ALICE_ID, ALICE_KEYPAIR, BOB_KEYPAIR, CARPENTER_KEYPAIR, PEER_KEYPAIR,
    };
    use norito::{codec::Decode, core as ncore};
    use std::{
        borrow::Cow,
        collections::BTreeSet,
        num::{NonZeroU32, NonZeroUsize},
        sync::Arc,
        time::Duration,
    };
    use tempfile::tempdir;
    fn test_network_id() -> NetworkId {
        "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("valid default test network id")
    }
    pub(super) fn build_transaction(
        message: &str,
    ) -> (SignedTransaction, AcceptedTransaction<'static>) {
        let authority = (*ALICE_ID).clone();
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, message.to_string())])
        .sign(ALICE_KEYPAIR.private_key());
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(signed.clone()));
        (signed, accepted)
    }
    fn world_with_alice() -> World {
        let mut world = World::new();
        world.accounts.insert(
            (*ALICE_ID).clone(),
            AccountValue::new(AccountDetails::default()),
        );
        // This component fixture needs explicit routing metadata; it has no signed
        // genesis, certified history or native publication authority.
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                iroha_data_model::block::consensus::SumeragiRootScope::Global,
            ))
            .expect("valid fixture parameters");
        parameters.commit();
        world
    }
    fn install_active_single_lane_nexus(state: &State) {
        let lane_catalog = LaneCatalog::new(
            NonZeroU32::new(1).expect("non-zero lane count"),
            vec![LaneConfig::default()],
        )
        .expect("authoritative default lane catalog");
        let mut nexus = state.nexus.write();
        nexus.autoscale.enabled = false;
        nexus.lane_catalog = lane_catalog;
        nexus.lane_config = LaneGeometry::from_catalog(&nexus.lane_catalog);
        nexus.dataspace_catalog = DataSpaceCatalog::default();
        nexus.routing_policy = iroha_config::parameters::actual::LaneRoutingPolicy::default();
        nexus.fees.base_fee = Quantity::zero();
        nexus.fees.per_byte_fee = Quantity::zero();
        nexus.fees.per_instruction_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
    }
    pub(super) fn payload_for(tx: &SignedTransaction) -> Arc<Vec<u8>> {
        Arc::new(encode_transaction_entrypoint(
            &TransactionEntrypoint::External(tx.clone()),
        ))
    }
    fn plan_for_route(route: GossipRoute) -> RoutingPlan {
        RoutingPlan::single(RoutingDecision::new(route.lane_id, route.dataspace_id))
    }
    fn default_plan() -> RoutingPlan {
        RoutingPlan::single(RoutingDecision::default())
    }
    fn decode_gossip_message(message: &TransactionGossip) -> TransactionGossip {
        let encoded = message.encode();
        Decode::decode(&mut encoded.as_slice()).expect("decode transaction gossip")
    }
    fn corrupt_signature(tx: &mut SignedTransaction) {
        let mut signature_payload = tx.signature().payload().payload().to_vec();
        let flip_index = signature_payload
            .len()
            .checked_sub(1)
            .expect("transaction signature payload should never be empty");
        signature_payload[flip_index] ^= 0xFF;
        let forged_signature = iroha_crypto::Signature::try_from_bytes(&signature_payload)
            .expect("tampered gossip signature remains structurally admissible");
        tx.set_signature(TransactionSignature(
            iroha_crypto::SignatureOf::from_signature(forged_signature),
        ));
    }
    #[test]
    fn gossip_transaction_hash_from_framed_entrypoint_matches_canonical_hash() {
        let (signed, _accepted) = build_transaction("framed-entrypoint-hash");
        let entrypoint = TransactionEntrypoint::External(signed);
        let payload = Arc::new(encode_transaction_entrypoint(&entrypoint));
        let hash = crate::tx::entrypoint_hash_from_framed_bytes(payload.as_slice())
            .expect("hash framed entrypoint payload");
        assert_eq!(hash, entrypoint.hash());
        let gossip_tx = GossipTransaction::with_encoded(entrypoint, payload);
        assert_eq!(gossip_tx.hash_as_entrypoint(), hash);
    }
    #[test]
    fn gossip_transaction_hash_rejects_zero_filled_logical_frame_tail() {
        let (signed, _accepted) = build_transaction("framed-entrypoint-zero-tail");
        let canonical = encode_transaction_entrypoint(&TransactionEntrypoint::External(signed));
        let view = ncore::from_bytes_view(&canonical).expect("canonical entrypoint frame");
        let flags = view.flags();
        let mut tailed_payload = view.as_bytes().to_vec();
        tailed_payload.push(0);
        let reframed =
            ncore::frame_bare_with_header_flags::<TransactionEntrypoint>(&tailed_payload, flags)
                .expect("reframe checksummed tailed payload");
        assert!(matches!(
            crate::tx::entrypoint_hash_from_framed_bytes(&reframed),
            Err(ncore::Error::LengthMismatch)
        ));
    }
    #[test]
    fn gossip_transaction_rejects_alternate_layout_frame() {
        let (signed, _accepted) = build_transaction("framed-entrypoint-alternate-layout");
        let entrypoint = TransactionEntrypoint::External(signed);
        let canonical = encode_transaction_entrypoint(&entrypoint);
        let alternate_flags = ncore::default_encode_flags() ^ ncore::header_flags::COMPACT_LEN;
        let alternate = {
            let _alternate = ncore::DecodeFlagsGuard::enter(alternate_flags);
            ncore::to_bytes(&entrypoint).expect("encode alternate-layout entrypoint")
        };
        assert_ne!(alternate, canonical);
        norito::decode_from_bytes::<TransactionEntrypoint>(&alternate)
            .expect("ordinary Norito accepts the advertised alternate layout");
        assert!(matches!(
            crate::tx::entrypoint_hash_from_framed_bytes(&alternate),
            Err(ncore::Error::NonCanonicalEncoding)
        ));
        assert!(matches!(
            decode_framed_transaction_entrypoint(&alternate),
            Err(ncore::Error::NonCanonicalEncoding)
        ));
    }
    fn build_sealed_commitment_entrypoint() -> TransactionEntrypoint {
        let network_id = test_network_id();
        let authority = (*ALICE_ID).clone();
        let inner = TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "sealed-inner".to_string())])
        .sign(ALICE_KEYPAIR.private_key());
        let reveal_deadline_height = 10;
        let commitment = compute_sealed_transaction_commitment(
            &network_id,
            &inner,
            [0x5A; 32],
            reveal_deadline_height,
        );
        let payload = SealedTransactionCommitmentPayload::new(
            network_id,
            authority,
            commitment,
            5,
            reveal_deadline_height,
            None,
        );
        TransactionEntrypoint::SealedCommitment(SignedSealedTransactionCommitment::sign(
            payload,
            ALICE_KEYPAIR.private_key(),
        ))
    }

    fn checked_ram_lfe_policy_signer() -> KeyPair {
        KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("generate checked RAM-LFE policy signer")
    }

    fn register_large_hkdf_program_policy_tx() -> SignedTransaction {
        use iroha_crypto::ram_lfe::{RamLfeBackend, RamLfeVerificationMode, policy_commitment};
        use iroha_data_model::{
            isi::{Instruction as _, ram_lfe::RegisterRamLfeProgramPolicy},
            ram_lfe::{RamLfeProgramId, RamLfeProgramPolicy},
        };

        let owner = (*ALICE_ID).clone();
        let signer = checked_ram_lfe_policy_signer();
        let commitment = policy_commitment(b"gossip-policy-fixture", vec![0x5a; 64 * 1024])
            .expect("large supported HKDF policy commitment");
        let policy = RamLfeProgramPolicy::new(
            "gossip_large_hkdf"
                .parse::<RamLfeProgramId>()
                .expect("program id"),
            owner.clone(),
            RamLfeBackend::HkdfSha3_512PrfV1,
            RamLfeVerificationMode::Signed,
            commitment,
            signer.public_key().clone(),
        );
        crate::smartcontracts::isi::ram_lfe::validate_program_policy(&policy)
            .expect("gossip fixture uses a supported policy");
        let instructions: [InstructionBox; 1] =
            [Box::new(RegisterRamLfeProgramPolicy { policy }).into_instruction_box()];
        TransactionBuilder::new(
            test_network_id(),
            owner,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(instructions)
        .sign(ALICE_KEYPAIR.private_key())
    }
    #[test]
    fn gossip_transaction_decode_cache_reuses_arcs() {
        let (signed, _accepted) = build_transaction("gossip-decode-cache-test");
        let payload = payload_for(&signed);
        let wire = GossipTransaction::with_encoded(signed.clone(), payload).encode();
        let bytes = wire.as_slice();
        let (first, used1) =
            <GossipTransaction as ncore::DecodeFromSlice>::decode_from_slice(bytes)
                .expect("decode first gossip transaction");
        let (second, used2) =
            <GossipTransaction as ncore::DecodeFromSlice>::decode_from_slice(bytes)
                .expect("decode second gossip transaction");
        assert_eq!(used1, bytes.len());
        assert_eq!(used2, bytes.len());
        assert!(
            !first.is_entrypoint_materialized(),
            "decode must defer semantic entrypoint materialization"
        );
        assert!(
            !second.is_entrypoint_materialized(),
            "cached decode must stay lazy"
        );
        assert!(
            Arc::ptr_eq(&first.encoded, &second.encoded),
            "encoded bytes must be reused from cache"
        );
        assert_eq!(
            first.clone().into_entrypoint_with_payload().unwrap().0,
            TransactionEntrypoint::External(signed.clone())
        );
        assert!(first.is_entrypoint_materialized());
    }
    #[test]
    fn gossip_transaction_decode_cache_is_byte_bounded() {
        let (signed, _accepted) = build_transaction("gossip-decode-cache-byte-bound");
        let entrypoint_hash = signed.hash_as_entrypoint();
        let mut cache = GossipTxDecodeCache::with_limits(8, 10);
        let first = Arc::new(vec![1_u8; 6]);
        let first_key = GossipTxDecodeCacheKey::from_bytes(first.as_slice());
        cache.insert(
            first_key,
            GossipTxDecodeCacheEntry {
                encoded: Arc::clone(&first),
                entrypoint_hash,
                consumed: first.len(),
            },
        );
        assert!(cache.get(&first_key).is_some());
        assert_eq!(cache.bytes, first.len());
        let second = Arc::new(vec![2_u8; 6]);
        let second_key = GossipTxDecodeCacheKey::from_bytes(second.as_slice());
        cache.insert(
            second_key,
            GossipTxDecodeCacheEntry {
                encoded: Arc::clone(&second),
                entrypoint_hash,
                consumed: second.len(),
            },
        );
        assert!(
            cache.get(&first_key).is_none(),
            "inserting past the byte cap should clear older cached payloads"
        );
        assert!(cache.get(&second_key).is_some());
        assert_eq!(cache.bytes, second.len());
        let oversized = Arc::new(vec![3_u8; 11]);
        cache.insert(
            second_key,
            GossipTxDecodeCacheEntry {
                encoded: oversized,
                entrypoint_hash,
                consumed: 11,
            },
        );
        assert!(
            cache.get(&second_key).is_none(),
            "oversized payloads should not remain cached"
        );
        assert_eq!(cache.bytes, 0);
    }
    #[test]
    fn gossip_transaction_try_deserialize_uses_decode_cache() {
        let (signed, _accepted) = build_transaction("gossip-try-deserialize-cache-test");
        let payload = payload_for(&signed);
        let gossip_tx = GossipTransaction::with_encoded(
            TransactionEntrypoint::External(signed),
            Arc::clone(&payload),
        );
        let encoded = gossip_tx.encode();
        let first: GossipTransaction =
            Decode::decode(&mut encoded.as_slice()).expect("decode first gossip transaction");
        let second: GossipTransaction =
            Decode::decode(&mut encoded.as_slice()).expect("decode second gossip transaction");
        assert!(
            !first.is_entrypoint_materialized(),
            "try_deserialize must defer semantic entrypoint materialization"
        );
        assert!(
            !second.is_entrypoint_materialized(),
            "cached try_deserialize must stay lazy"
        );
        assert!(
            Arc::ptr_eq(&first.encoded, &second.encoded),
            "try_deserialize must reuse encoded bytes from cache"
        );
    }
    fn test_network_config(addr: iroha_primitives::addr::SocketAddr) -> NetworkConfig {
        let public_addr = addr.clone();
        NetworkConfig {
            address: WithOrigin::inline(addr),
            public_address: WithOrigin::inline(public_addr),
            relay_mode: RelayMode::Disabled,
            relay_hub_addresses: Vec::new(),
            relay_ttl: defaults::network::RELAY_TTL,
            soranet_handshake: SoranetHandshake::default(),
            soranet_privacy: SoranetPrivacy::default(),
            soranet_vpn: SoranetVpn::default(),
            lane_profile: LaneProfile::Core,
            require_sm_handshake_match: defaults::network::REQUIRE_SM_HANDSHAKE_MATCH,
            require_sm_openssl_preview_match: defaults::network::REQUIRE_SM_OPENSSL_PREVIEW_MATCH,
            idle_timeout: defaults::network::IDLE_TIMEOUT,
            preauth_timeout: defaults::network::PREAUTH_TIMEOUT,
            preauth_max_connections_per_ip:
                defaults::network::PREAUTH_MAX_CONNECTIONS_PER_IP,
            reply_writer_flush_timeout: defaults::network::REPLY_WRITER_FLUSH_TIMEOUT,
            connect_startup_delay: defaults::network::CONNECT_STARTUP_DELAY,
            dial_timeout: defaults::network::DIAL_TIMEOUT,
            peer_gossip_period: defaults::network::PEER_GOSSIP_PERIOD,
            peer_gossip_max_period: defaults::network::PEER_GOSSIP_PERIOD,
            trust_gossip: defaults::network::TRUST_GOSSIP,
            trust_decay_half_life: defaults::network::TRUST_DECAY_HALF_LIFE,
            trust_penalty_bad_gossip: defaults::network::TRUST_PENALTY_BAD_GOSSIP,
            trust_penalty_unknown_peer: defaults::network::TRUST_PENALTY_UNKNOWN_PEER,
            trust_min_score: defaults::network::TRUST_MIN_SCORE,
deferred_send_ttl: Duration::from_millis(defaults::network::DEFERRED_SEND_TTL_MS),
            deferred_send_max_per_peer: defaults::network::DEFERRED_SEND_MAX_PER_PEER,
            deferred_send_max_bytes_per_peer: defaults::network::DEFERRED_SEND_MAX_BYTES_PER_PEER,
            deferred_send_max_bytes_total: iroha_config::parameters::defaults::network::DEFERRED_SEND_MAX_BYTES_TOTAL,
            dns_refresh_interval: None,
            dns_refresh_ttl: None,
            p2p_proxy: None,
            p2p_proxy_required: false,
            p2p_no_proxy: Vec::new(),
            outbound_dial_allow_cidrs: Vec::new(),
            outbound_dial_deny_cidrs: Vec::new(),
            outbound_dial_allow_dns_suffixes: Vec::new(),
            outbound_dial_deny_dns_suffixes: Vec::new(),
            p2p_proxy_tls_verify: true,
            p2p_proxy_tls_pinned_cert_der_base64: None,
            quic_enabled: false,
            quic_datagrams_enabled: defaults::network::QUIC_DATAGRAMS_ENABLED,
            quic_datagram_max_payload_bytes: defaults::network::QUIC_DATAGRAM_MAX_PAYLOAD_BYTES.get(),
            quic_datagram_receive_buffer_bytes: defaults::network::QUIC_DATAGRAM_RECEIVE_BUFFER_BYTES.get(),
            quic_datagram_send_buffer_bytes: defaults::network::QUIC_DATAGRAM_SEND_BUFFER_BYTES.get(),
            p2p_queue_cap_high: defaults::network::P2P_QUEUE_CAP_HIGH,
            p2p_queue_cap_low: defaults::network::P2P_QUEUE_CAP_LOW,
            p2p_post_queue_cap: defaults::network::P2P_POST_QUEUE_CAP,
            p2p_outbound_frame_queue_max_high_bytes:
                defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_BYTES,
            p2p_outbound_frame_queue_max_low_bytes:
                defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_BYTES,
            p2p_outbound_frame_queue_max_high_frames:
                defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_FRAMES,
            p2p_outbound_frame_queue_max_low_frames:
                defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_FRAMES,
            p2p_subscriber_queue_cap: defaults::network::P2P_SUBSCRIBER_QUEUE_CAP,
            consensus_ingress_rate_per_sec: defaults::network::CONSENSUS_INGRESS_RATE_PER_SEC,
            consensus_ingress_burst: defaults::network::CONSENSUS_INGRESS_BURST,
            consensus_ingress_bytes_per_sec: defaults::network::CONSENSUS_INGRESS_BYTES_PER_SEC,
            consensus_ingress_bytes_burst: defaults::network::CONSENSUS_INGRESS_BYTES_BURST,
            consensus_ingress_critical_rate_per_sec:
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_CRITICAL_RATE_PER_SEC,
            consensus_ingress_critical_burst:
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_CRITICAL_BURST,
            consensus_ingress_critical_bytes_per_sec:
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_CRITICAL_BYTES_PER_SEC,
            consensus_ingress_critical_bytes_burst:
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_CRITICAL_BYTES_BURST,
            consensus_ingress_penalty_threshold:
                defaults::network::CONSENSUS_INGRESS_PENALTY_THRESHOLD,
            consensus_ingress_penalty_window: Duration::from_millis(
                defaults::network::CONSENSUS_INGRESS_PENALTY_WINDOW_MS,
            ),
            consensus_ingress_penalty_cooldown: Duration::from_millis(
                defaults::network::CONSENSUS_INGRESS_PENALTY_COOLDOWN_MS,
            ),
            happy_eyeballs_stagger: defaults::network::HAPPY_EYEBALLS_STAGGER,
            addr_ipv6_first: false,
            max_incoming: None,
            max_total_connections: None,
            accept_rate_per_ip_per_sec: None,
            accept_burst_per_ip: None,
            max_accept_buckets: defaults::network::MAX_ACCEPT_BUCKETS,
            accept_bucket_idle: defaults::network::ACCEPT_BUCKET_IDLE,
            accept_prefix_v4_bits: defaults::network::ACCEPT_PREFIX_V4_BITS,
            accept_prefix_v6_bits: defaults::network::ACCEPT_PREFIX_V6_BITS,
            accept_rate_per_prefix_per_sec: None,
            accept_burst_per_prefix: None,
            low_priority_rate_per_sec: None,
            low_priority_burst: None,
            low_priority_bytes_per_sec: None,
            low_priority_bytes_burst: None,
            allowlist_only: false,
            allow_keys: Vec::new(),
            deny_keys: Vec::new(),
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            disconnect_on_post_overflow: defaults::network::DISCONNECT_ON_POST_OVERFLOW,
            max_frame_bytes: defaults::network::MAX_FRAME_BYTES.get(),
            tcp_nodelay: defaults::network::TCP_NODELAY,
            tcp_keepalive: Some(defaults::network::TCP_KEEPALIVE),
            max_frame_bytes_consensus: defaults::network::MAX_FRAME_BYTES_CONSENSUS.get(),
            max_frame_bytes_control: defaults::network::MAX_FRAME_BYTES_CONTROL.get(),
            max_frame_bytes_block_sync: defaults::network::MAX_FRAME_BYTES_BLOCK_SYNC.get(),
            max_frame_bytes_tx_gossip: defaults::network::MAX_FRAME_BYTES_TX_GOSSIP.get(),
            max_frame_bytes_peer_gossip: defaults::network::MAX_FRAME_BYTES_PEER_GOSSIP.get(),
            max_frame_bytes_health: defaults::network::MAX_FRAME_BYTES_HEALTH.get(),
            max_frame_bytes_connect: iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONNECT.get(),
            max_frame_bytes_other: defaults::network::MAX_FRAME_BYTES_OTHER.get(),
            quic_max_idle_timeout: None,
        }
    }
    pub(super) fn closed_test_gossiper(resend_ticks: NonZeroU32) -> TransactionGossiper {
        let temp_dir = tempdir().expect("temp dir");
        let kura_cfg = KuraConfig {
            init_mode: iroha_config::kura::InitMode::Strict,
            store_dir: WithOrigin::inline(temp_dir.path().to_path_buf()),
            max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: defaults::kura::BLOCKS_IN_MEMORY,
            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity:
                iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes:
                iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes:
                iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
            debug_output_new_blocks: false,
            fsync_mode: FsyncMode::Batched,
            fsync_interval: defaults::kura::FSYNC_INTERVAL,
        };
        let (kura, _) =
            Kura::open_test_kura_with_configured_lane_config(&kura_cfg, &LaneGeometry::default())
                .expect("init kura");
        let live_query = LiveQueryStore::start_test();
        let state = Arc::new(State::new_for_testing(world_with_alice(), kura, live_query));
        install_active_single_lane_nexus(state.as_ref());
        let queue = Arc::new(Queue::test(
            QueueConfig::default(),
            &TimeSource::new_system(),
        ));
        let now = Instant::now();
        TransactionGossiper {
            gossip_period: Duration::from_millis(50),
            gossip_size: defaults::network::TRANSACTION_GOSSIP_SIZE,
            gossip_resend_ticks: resend_ticks,
            gossip_tick: 0,
            gossip_deferred: vec![Vec::new(); resend_ticks.get() as usize],
            peer_recently_sent: BTreeMap::new(),
            peer_recent_ring: vec![Vec::new(); GOSSIP_PEER_RECENT_SUPPRESSION_TTL_TICKS],
            last_drop_count: tx_gossip_relay_drop_count(),
            last_drop_at: None,
            network: IrohaNetwork::closed_for_tests(),
            self_peer_id: PeerId::new(PEER_KEYPAIR.public_key().clone()),
            queue,
            state,
            tx_frame_cap: 1024,
            dataspace_cfg: DataspaceGossip::default(),
            public_seed: GossipTargetSeed::new(0xBEEF_0001, Duration::from_secs(1), now),
            restricted_seed: GossipTargetSeed::new(0xBEEF_0002, Duration::from_secs(1), now),
        }
    }
    #[test]
    fn current_gossip_rejects_multiroute_work_without_suppressing_ordinary() {
        for shared in [false, true] {
            let gossiper = closed_test_gossiper(NonZeroU32::new(1).unwrap());
            let (multiroute, _) = build_transaction("unsupported multi-route");
            let (ordinary, _) = build_transaction("supported ordinary after rejected work");
            let ordinary_hash = TransactionEntrypoint::External(ordinary.clone()).hash();
            let multiroute_plan = RoutingPlan::native_amx(
                RoutingDecision::default(),
                vec![crate::queue::RouteLeg::new(
                    RoutingDecision::default(),
                    crate::queue::RouteLegRole::Participant,
                )],
            );
            let message = Arc::new(decode_gossip_message(&TransactionGossip {
                txs: vec![multiroute.into(), ordinary.into()],
                routes: vec![
                    GossipRoute {
                        lane_id: LaneId::SINGLE,
                        dataspace_id: DataSpaceId::UNIVERSAL
                    };
                    2
                ],
                plans: vec![multiroute_plan, default_plan()],
                plane: GossipPlane::Public,
            }));
            let retained = shared.then(|| Arc::clone(&message));
            gossiper.handle_transaction_gossip(message);
            assert_eq!(gossiper.queue.queued_len(), 1);
            assert!(gossiper.queue.contains_entrypoint_hash(ordinary_hash));
            drop(retained);
        }
    }
    #[test]
    fn transaction_gossip_priority_elevates_under_queue_age_pressure() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(2).expect("nonzero resend ticks"));
        let (_signed, accepted) = build_transaction("priority-pressure");
        gossiper
            .queue
            .push(accepted, gossiper.state.view())
            .expect("queue accepts tx");
        gossiper
            .queue
            .set_pressure_age_budget_for_tests(Duration::from_secs(60));
        assert_eq!(gossiper.gossip_priority(), Priority::Low);
        gossiper
            .queue
            .set_pressure_age_budget_for_tests(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(gossiper.gossip_priority(), Priority::High);
    }
    #[test]
    fn tx_gossip_frame_cap_rejects_invalid_identities_overflow_and_empty_capacity() {
        let key = KeyPair::try_from_seed(vec![0xE3; 32], Algorithm::BlsNormal).unwrap();
        let peer = PeerId::new(key.public_key().clone());
        let foreign_key = KeyPair::try_from_seed(vec![0xE4; 32], Algorithm::Ed25519).unwrap();
        let foreign = PeerId::new(foreign_key.public_key().clone());
        let mut config = test_network_config(socket_addr!(127.0.0.1:0));
        assert!(tx_gossip_frame_payload_cap(&config, &peer, &peer) > 0);
        assert_eq!(tx_gossip_frame_payload_cap(&config, &foreign, &peer), 0);
        assert_eq!(tx_gossip_frame_payload_cap(&config, &peer, &foreign), 0);
        assert_eq!(
            tx_gossip_data_frame_len(&peer, Some(&peer), usize::MAX),
            None
        );
        config.max_frame_bytes_tx_gossip = 0;
        assert_eq!(tx_gossip_frame_payload_cap(&config, &peer, &peer), 0);
        config.max_frame_bytes_tx_gossip = 1;
        assert_eq!(tx_gossip_frame_payload_cap(&config, &peer, &peer), 0);
        config.max_frame_bytes_tx_gossip = 256 * 1024;
        config.max_frame_bytes = 0;
        assert_eq!(tx_gossip_frame_payload_cap(&config, &peer, &peer), 0);
    }
    #[test]
    fn ram_lfe_policy_signer_uses_checked_ed25519_generation() {
        let keypair = checked_ram_lfe_policy_signer();
        assert_eq!(
            keypair
                .public_key()
                .try_algorithm()
                .expect("checked RAM-LFE policy signer algorithm"),
            Algorithm::Ed25519
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn gossiper_tx_frame_cap_respects_encrypted_frame_limit() {
        let temp_dir = tempdir().expect("temp dir");
        let kura_cfg = KuraConfig {
            init_mode: iroha_config::kura::InitMode::Strict,
            store_dir: WithOrigin::inline(temp_dir.path().to_path_buf()),
            max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: defaults::kura::BLOCKS_IN_MEMORY,
            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity:
                iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes:
                iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes:
                iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
            debug_output_new_blocks: false,
            fsync_mode: FsyncMode::Batched,
            fsync_interval: defaults::kura::FSYNC_INTERVAL,
        };
        let (kura, _) =
            Kura::open_test_kura_with_configured_lane_config(&kura_cfg, &LaneGeometry::default())
                .expect("init kura");
        let live_query = LiveQueryStore::start_test();
        let state = Arc::new(State::new_for_testing(World::new(), kura, live_query));
        let queue = Arc::new(Queue::test(
            QueueConfig::default(),
            &TimeSource::new_system(),
        ));
        let mut network_cfg = test_network_config(socket_addr!(127.0.0.1:0));
        network_cfg.max_frame_bytes = 512;
        network_cfg.max_frame_bytes_tx_gossip = 1024;
        let self_peer_id = PeerId::new(PEER_KEYPAIR.public_key().clone());
        let max_peer_id = self_peer_id.clone();
        let expected = tx_gossip_frame_payload_cap(&network_cfg, &self_peer_id, &max_peer_id);
        let network = IrohaNetwork::closed_for_tests();
        let gossiper = TransactionGossiper::from_config(
            Config {
                gossip_period: Duration::from_millis(1000),
                gossip_size: NonZeroU32::new(1).expect("nonzero size"),
                gossip_resend_ticks: defaults::network::TRANSACTION_GOSSIP_RESEND_TICKS,
                dataspace: DataspaceGossip::default(),
            },
            &network_cfg,
            self_peer_id,
            max_peer_id,
            network,
            queue,
            Arc::clone(&state),
        );
        assert_eq!(gossiper.tx_frame_cap, expected);
    }
    #[test]
    fn gossip_defers_requeue_until_resend_tick() {
        let temp_dir = tempdir().expect("temp dir");
        let kura_cfg = KuraConfig {
            init_mode: iroha_config::kura::InitMode::Strict,
            store_dir: WithOrigin::inline(temp_dir.path().to_path_buf()),
            max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: defaults::kura::BLOCKS_IN_MEMORY,
            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity:
                iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes:
                iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes:
                iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
            debug_output_new_blocks: false,
            fsync_mode: FsyncMode::Batched,
            fsync_interval: defaults::kura::FSYNC_INTERVAL,
        };
        let (kura, _) =
            Kura::open_test_kura_with_configured_lane_config(&kura_cfg, &LaneGeometry::default())
                .expect("init kura");
        let live_query = LiveQueryStore::start_test();
        let state = Arc::new(State::new_for_testing(world_with_alice(), kura, live_query));
        install_active_single_lane_nexus(state.as_ref());
        let queue = Arc::new(Queue::test(
            QueueConfig::default(),
            &TimeSource::new_system(),
        ));
        let (_signed, accepted) = build_transaction("defer");
        queue
            .push(accepted, state.view())
            .expect("queue accepts tx");
        let batch = queue.gossip_batch(1, &state.view());
        assert_eq!(batch.len(), 1);
        let hash = batch[0].tx.hash_as_entrypoint();
        let resend_ticks = NonZeroU32::new(2).expect("nonzero resend ticks");
        let now = Instant::now();
        let mut gossiper = TransactionGossiper {
            gossip_period: Duration::from_millis(50),
            gossip_size: NonZeroU32::new(1).expect("nonzero size"),
            gossip_resend_ticks: resend_ticks,
            gossip_tick: 0,
            gossip_deferred: vec![Vec::new(); resend_ticks.get() as usize],
            peer_recently_sent: BTreeMap::new(),
            peer_recent_ring: vec![Vec::new(); GOSSIP_PEER_RECENT_SUPPRESSION_TTL_TICKS],
            last_drop_count: tx_gossip_relay_drop_count(),
            last_drop_at: None,
            network: IrohaNetwork::closed_for_tests(),
            self_peer_id: PeerId::new(PEER_KEYPAIR.public_key().clone()),
            queue: Arc::clone(&queue),
            state: Arc::clone(&state),
            tx_frame_cap: 1024,
            dataspace_cfg: DataspaceGossip::default(),
            public_seed: GossipTargetSeed::new(0xBEEF_0001, Duration::from_secs(1), now),
            restricted_seed: GossipTargetSeed::new(0xBEEF_0002, Duration::from_secs(1), now),
        };
        gossiper.release_deferred_gossip();
        gossiper.defer_gossip_hashes(vec![hash]);
        gossiper.advance_gossip_tick();
        assert!(queue.gossip_batch(1, &state.view()).is_empty());
        gossiper.release_deferred_gossip();
        gossiper.advance_gossip_tick();
        assert!(queue.gossip_batch(1, &state.view()).is_empty());
        gossiper.release_deferred_gossip();
        let batch = queue.gossip_batch(1, &state.view());
        assert_eq!(batch.len(), 1);
    }
    #[test]
    fn gossip_deferred_slot_deduplicates_repeated_hashes() {
        let resend_ticks = NonZeroU32::new(2).expect("nonzero resend ticks");
        let mut gossiper = closed_test_gossiper(resend_ticks);
        let (_signed, accepted) = build_transaction("deferred-dedup");
        let hash = accepted.hash_as_entrypoint();
        gossiper
            .queue
            .push(accepted, gossiper.state.view())
            .expect("queue accepts tx");
        gossiper.defer_gossip_hashes([hash, hash]);
        gossiper.defer_gossip_hashes([hash]);
        assert_eq!(
            gossiper.gossip_deferred[gossiper.deferred_index()].len(),
            1,
            "same entrypoint hash should be retained once per resend slot"
        );
    }
    #[test]
    fn public_broadcast_retry_hashes_return_to_gossip_backlog() {
        let resend_ticks = NonZeroU32::new(2).expect("nonzero resend ticks");
        let mut gossiper = closed_test_gossiper(resend_ticks);
        let (_signed, accepted) = build_transaction("public-broadcast-retry");
        gossiper
            .queue
            .push(accepted, gossiper.state.view())
            .expect("queue accepts tx");
        let first_batch = gossiper.queue.gossip_batch(1, &gossiper.state.view());
        assert_eq!(first_batch.len(), 1);
        let hash = first_batch[0].tx.hash_as_entrypoint();
        assert!(
            gossiper
                .queue
                .gossip_batch(1, &gossiper.state.view())
                .is_empty()
        );
        gossiper.retry_public_broadcast_hashes(vec![hash]);
        gossiper.advance_gossip_tick();
        gossiper.release_deferred_gossip();
        assert!(
            gossiper
                .queue
                .gossip_batch(1, &gossiper.state.view())
                .is_empty(),
            "retry should wait until the configured resend tick"
        );
        gossiper.advance_gossip_tick();
        gossiper.release_deferred_gossip();
        let retried_batch = gossiper.queue.gossip_batch(1, &gossiper.state.view());
        assert_eq!(retried_batch.len(), 1);
    }
    #[test]
    fn gossip_backpressure_cooldown_respects_last_drop() {
        let temp_dir = tempdir().expect("temp dir");
        let kura_cfg = KuraConfig {
            init_mode: iroha_config::kura::InitMode::Strict,
            store_dir: WithOrigin::inline(temp_dir.path().to_path_buf()),
            max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: defaults::kura::BLOCKS_IN_MEMORY,
            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity:
                iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes:
                iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes:
                iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
            debug_output_new_blocks: false,
            fsync_mode: FsyncMode::Batched,
            fsync_interval: defaults::kura::FSYNC_INTERVAL,
        };
        let (kura, _) =
            Kura::open_test_kura_with_configured_lane_config(&kura_cfg, &LaneGeometry::default())
                .expect("init kura");
        let live_query = LiveQueryStore::start_test();
        let state = Arc::new(State::new_for_testing(World::new(), kura, live_query));
        let queue = Arc::new(Queue::test(
            QueueConfig::default(),
            &TimeSource::new_system(),
        ));
        let resend_ticks = NonZeroU32::new(2).expect("nonzero resend ticks");
        let now = Instant::now();
        let mut gossiper = TransactionGossiper {
            gossip_period: Duration::from_millis(50),
            gossip_size: NonZeroU32::new(1).expect("nonzero size"),
            gossip_resend_ticks: resend_ticks,
            gossip_tick: 0,
            gossip_deferred: vec![Vec::new(); resend_ticks.get() as usize],
            peer_recently_sent: BTreeMap::new(),
            peer_recent_ring: vec![Vec::new(); GOSSIP_PEER_RECENT_SUPPRESSION_TTL_TICKS],
            last_drop_count: u64::MAX,
            last_drop_at: Some(now),
            network: IrohaNetwork::closed_for_tests(),
            self_peer_id: PeerId::new(PEER_KEYPAIR.public_key().clone()),
            queue,
            state,
            tx_frame_cap: 1024,
            dataspace_cfg: DataspaceGossip::default(),
            public_seed: GossipTargetSeed::new(0xBEEF_0001, Duration::from_secs(1), now),
            restricted_seed: GossipTargetSeed::new(0xBEEF_0002, Duration::from_secs(1), now),
        };
        assert!(gossiper.gossip_backpressure_active(now));
        let cooldown = gossiper.backpressure_cooldown();
        let past = now
            .checked_sub(cooldown.saturating_add(Duration::from_millis(1)))
            .unwrap_or(now);
        gossiper.last_drop_at = Some(past);
        assert!(!gossiper.gossip_backpressure_active(now));
    }
    fn ordinary_send_key(entrypoint_hash: EntrypointHash) -> PeerRecentSendKey {
        PeerRecentSendKey { entrypoint_hash }
    }
    #[test]
    fn peer_recent_suppression_expires_after_ttl_ticks() {
        let resend_ticks = NonZeroU32::new(2).expect("nonzero resend ticks");
        let mut gossiper = closed_test_gossiper(resend_ticks);
        let peer: PeerId = (*PEER_KEYPAIR).public_key().clone().into();
        let (signed, _) = build_transaction("suppression-expiry");
        let key = ordinary_send_key(signed.hash_as_entrypoint());
        gossiper.remember_peer_recent_sends(
            std::slice::from_ref(&peer),
            std::slice::from_ref(&key),
            1,
        );
        let (targets, suppressed) = gossiper.filter_targets_by_peer_recent_suppression(
            vec![peer.clone()],
            std::slice::from_ref(&key),
        );
        assert!(
            targets.is_empty(),
            "all-suppressed target sets should wait for resend TTL instead of replaying immediately"
        );
        assert_eq!(suppressed, 1);
        for _ in 0..GOSSIP_PEER_RECENT_SUPPRESSION_TTL_TICKS {
            gossiper.expire_peer_recent_suppression();
            gossiper.advance_gossip_tick();
        }
        gossiper.expire_peer_recent_suppression();
        let (targets, suppressed) = gossiper.filter_targets_by_peer_recent_suppression(
            vec![peer.clone()],
            std::slice::from_ref(&key),
        );
        assert_eq!(targets, vec![peer]);
        assert_eq!(suppressed, 0);
    }
    #[test]
    fn peer_recent_suppression_deduplicates_same_tick_entries() {
        let resend_ticks = NonZeroU32::new(2).expect("nonzero resend ticks");
        let mut gossiper = closed_test_gossiper(resend_ticks);
        let peer: PeerId = (*PEER_KEYPAIR).public_key().clone().into();
        let (signed, _) = build_transaction("suppression-same-tick-dedup");
        let key = ordinary_send_key(signed.hash_as_entrypoint());
        let slot = gossiper.peer_recent_slot_for_tick(
            gossiper
                .gossip_tick
                .saturating_add(GOSSIP_PEER_RECENT_SUPPRESSION_TTL_TICKS as u64),
        );
        gossiper.remember_peer_recent_sends(
            std::slice::from_ref(&peer),
            std::slice::from_ref(&key),
            1,
        );
        gossiper.remember_peer_recent_sends(
            std::slice::from_ref(&peer),
            std::slice::from_ref(&key),
            1,
        );
        assert_eq!(
            gossiper.peer_recent_ring[slot].len(),
            1,
            "same peer/hash expiry should have one ring entry"
        );
    }
    #[test]
    fn peer_recent_suppression_drops_stale_replaced_ring_entries() {
        let resend_ticks = NonZeroU32::new(2).expect("nonzero resend ticks");
        let mut gossiper = closed_test_gossiper(resend_ticks);
        let peer: PeerId = (*PEER_KEYPAIR).public_key().clone().into();
        let (signed, _) = build_transaction("suppression-stale-ring-entry");
        let key = ordinary_send_key(signed.hash_as_entrypoint());
        let ttl = GOSSIP_PEER_RECENT_SUPPRESSION_TTL_TICKS as u64;
        let first_expiry = gossiper.gossip_tick.saturating_add(ttl);
        let first_slot = gossiper.peer_recent_slot_for_tick(first_expiry);
        gossiper.remember_peer_recent_sends(
            std::slice::from_ref(&peer),
            std::slice::from_ref(&key),
            1,
        );
        gossiper.advance_gossip_tick();
        let second_expiry = gossiper.gossip_tick.saturating_add(ttl);
        let second_slot = gossiper.peer_recent_slot_for_tick(second_expiry);
        gossiper.remember_peer_recent_sends(
            std::slice::from_ref(&peer),
            std::slice::from_ref(&key),
            1,
        );
        assert_eq!(gossiper.peer_recent_ring[first_slot].len(), 1);
        assert_eq!(gossiper.peer_recent_ring[second_slot].len(), 1);
        gossiper.gossip_tick = first_expiry;
        gossiper.expire_peer_recent_suppression();
        assert!(
            gossiper.peer_recent_ring[first_slot].is_empty(),
            "overwritten expiry entry should be dropped instead of retained forever"
        );
        assert!(
            gossiper
                .peer_recently_sent
                .get(&peer)
                .is_some_and(|seen| seen.get(&key) == Some(&second_expiry)),
            "newer suppression expiry should remain active"
        );
        gossiper.gossip_tick = second_expiry;
        gossiper.expire_peer_recent_suppression();
        assert!(
            !gossiper.peer_recently_sent.contains_key(&peer),
            "current suppression entry should still expire normally"
        );
    }
    #[test]
    fn peer_recent_suppression_keeps_peers_missing_any_hash() {
        let resend_ticks = NonZeroU32::new(2).expect("nonzero resend ticks");
        let mut gossiper = closed_test_gossiper(resend_ticks);
        let peer_a: PeerId = (*ALICE_KEYPAIR).public_key().clone().into();
        let peer_b: PeerId = (*BOB_KEYPAIR).public_key().clone().into();
        let (signed_a, _) = build_transaction("peer-a");
        let (signed_b, _) = build_transaction("peer-b");
        let key_a = ordinary_send_key(signed_a.hash_as_entrypoint());
        let key_b = ordinary_send_key(signed_b.hash_as_entrypoint());
        let all_keys = vec![key_a, key_b];
        gossiper.remember_peer_recent_sends(std::slice::from_ref(&peer_a), &[key_a], 1);
        gossiper.remember_peer_recent_sends(std::slice::from_ref(&peer_b), &all_keys, 1);
        let (targets, suppressed) = gossiper.filter_targets_by_peer_recent_suppression(
            vec![peer_a.clone(), peer_b.clone()],
            &all_keys,
        );
        assert_eq!(targets, vec![peer_a]);
        assert_eq!(suppressed, 1);
    }
    #[test]
    fn peer_recent_suppression_defers_when_every_target_was_recently_sent() {
        let resend_ticks = NonZeroU32::new(2).expect("nonzero resend ticks");
        let mut gossiper = closed_test_gossiper(resend_ticks);
        let peer_a: PeerId = (*ALICE_KEYPAIR).public_key().clone().into();
        let peer_b: PeerId = (*BOB_KEYPAIR).public_key().clone().into();
        let (signed, _) = build_transaction("peer-recent-defer");
        let key = ordinary_send_key(signed.hash_as_entrypoint());
        let targets = vec![peer_a.clone(), peer_b.clone()];
        gossiper.remember_peer_recent_sends(&targets, std::slice::from_ref(&key), 1);
        let (targets, suppressed, replayed) = gossiper
            .filter_targets_or_replay_recent_suppressed(targets, std::slice::from_ref(&key));
        assert!(targets.is_empty());
        assert_eq!(suppressed, 2);
        assert!(!replayed);
    }
    #[test]
    fn large_gossip_frame_extends_suppression_until_relay_can_drain() {
        let mut gossiper = closed_test_gossiper(NonZeroU32::new(2).unwrap());
        let peer: PeerId = (*PEER_KEYPAIR).public_key().clone().into();
        let (signed, _) = build_transaction("large-frame-pacing");
        let key = ordinary_send_key(signed.hash_as_entrypoint());
        let frame_bytes = 10 * 1024 * 1024;
        let ttl = gossiper.peer_recent_ttl_ticks(frame_bytes);
        assert_eq!(ttl, 40);
        gossiper.remember_peer_recent_sends(std::slice::from_ref(&peer), &[key], frame_bytes);
        gossiper.gossip_tick = GOSSIP_PEER_RECENT_SUPPRESSION_TTL_TICKS as u64;
        gossiper.expire_peer_recent_suppression();
        let (targets, suppressed) =
            gossiper.filter_targets_by_peer_recent_suppression(vec![peer.clone()], &[key]);
        assert!(targets.is_empty());
        assert_eq!(suppressed, 1);
        gossiper.gossip_tick = ttl;
        gossiper.expire_peer_recent_suppression();
        let (targets, suppressed) =
            gossiper.filter_targets_by_peer_recent_suppression(vec![peer.clone()], &[key]);
        assert_eq!(targets, vec![peer]);
        assert_eq!(suppressed, 0);
    }
    #[test]
    fn new_small_input_does_not_resend_recent_large_input_to_same_peer() {
        let mut gossiper = closed_test_gossiper(NonZeroU32::new(2).unwrap());
        let peer_a: PeerId = (*ALICE_KEYPAIR).public_key().clone().into();
        let peer_b: PeerId = (*BOB_KEYPAIR).public_key().clone().into();
        let (large, _) = build_transaction(&"L".repeat(128 * 1024));
        let (small, _) = build_transaction("new-small-input");
        let route = GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        let message = Arc::new(TransactionGossip {
            txs: vec![large.clone().into(), small.clone().into()],
            routes: vec![route, route],
            plans: vec![default_plan(), default_plan()],
            plane: GossipPlane::Public,
        });
        let keys = message
            .txs
            .iter()
            .map(PeerRecentSendKey::from_gossip)
            .collect::<Vec<_>>();
        let full_len = message
            .as_ref()
            .encoded_len_exact()
            .expect("complete batch length");
        gossiper.remember_peer_recent_sends(std::slice::from_ref(&peer_a), &keys[..1], full_len);

        let (filtered, filtered_keys, filtered_len) = gossiper
            .unsent_gossip_for_peer(&peer_a, &message, &keys, full_len)
            .expect("new input needs delivery");
        assert_eq!(filtered.txs.len(), 1);
        assert_eq!(filtered.txs[0].hash(), small.hash_as_entrypoint());
        assert_eq!(filtered_keys, keys[1..]);
        assert_eq!(filtered.routes.len(), 1);
        assert_eq!(filtered.plans.len(), 1);
        assert_eq!(filtered_len, filtered.as_ref().encode().len());
        assert!(filtered_len < full_len / 2);
        let network_bytes = NetworkMessage::TransactionGossiper(Arc::clone(&filtered)).encode();
        let decoded: NetworkMessage = Decode::decode(&mut network_bytes.as_slice())
            .expect("filtered batch is a valid network message");
        match decoded {
            NetworkMessage::TransactionGossiper(decoded) => {
                assert_eq!(decoded.txs.len(), 1);
                assert_eq!(decoded.txs[0].hash(), small.hash_as_entrypoint());
            }
            _ => panic!("filtered network message changed its variant"),
        }

        let (complete, complete_keys, complete_len) = gossiper
            .unsent_gossip_for_peer(&peer_b, &message, &keys, full_len)
            .expect("other peer needs complete batch");
        assert!(Arc::ptr_eq(&complete, &message));
        assert_eq!(complete_keys, keys);
        assert_eq!(complete_len, full_len);
    }
    include!("gossiper/gossip_partition_and_nexus_activity_tests.rs");
    #[test]
    fn validate_route_rejects_inactive_lane() {
        let lane = iroha_data_model::nexus::LaneConfig {
            id: LaneId::new(2),
            dataspace_id: DataSpaceId::new(9),
            alias: "inactive".to_string(),
            visibility: LaneVisibility::Restricted,
            ..iroha_data_model::nexus::LaneConfig::default()
        };
        let catalog = LaneCatalog::new(
            core::num::NonZeroU32::new(3).expect("nonzero lanes"),
            vec![lane],
        )
        .expect("lane catalog");
        let dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
            id: DataSpaceId::new(9),
            alias: "inactive-dataspace".to_string(),
            description: None,
            fault_tolerance: 1,
        }])
        .expect("dataspace catalog");
        let active_lane_ids = BTreeSet::from([LaneId::SINGLE]);
        let route = GossipRoute {
            lane_id: LaneId::new(2),
            dataspace_id: DataSpaceId::new(9),
        };
        assert_eq!(
            validate_route(&catalog, &dataspace_catalog, &active_lane_ids, route),
            Err(DROP_REASON_INACTIVE_LANE)
        );
    }
    #[test]
    fn dataspace_plane_follows_the_single_dataspace_visibility() {
        let lane = |id: u32, alias: &str, visibility| iroha_data_model::nexus::LaneConfig {
            id: LaneId::new(id),
            dataspace_id: DataSpaceId::new(42),
            alias: alias.to_string(),
            visibility,
            ..iroha_data_model::nexus::LaneConfig::default()
        };
        let nonzero = core::num::NonZeroU32::new(2).expect("nonzero lanes");
        // A dataspace cannot mix public and restricted lanes.
        assert!(
            LaneCatalog::new(
                nonzero,
                vec![
                    lane(0, "public-lane", LaneVisibility::Public),
                    lane(1, "restricted-lane", LaneVisibility::Restricted),
                ],
            )
            .is_err()
        );
        let catalog = LaneCatalog::new(
            nonzero,
            vec![
                lane(0, "restricted-a", LaneVisibility::Restricted),
                lane(1, "restricted-b", LaneVisibility::Restricted),
            ],
        )
        .expect("lane catalog");
        let lane_config = LaneGeometry::from_catalog(&catalog);
        assert_eq!(
            dataspace_plane(&lane_config, DataSpaceId::new(42)),
            Some(GossipPlane::Restricted)
        );
    }
    #[test]
    fn dataspace_plane_handles_unknown_dataspace() {
        let catalog = LaneCatalog::default();
        let lane_config = LaneGeometry::from_catalog(&catalog);
        assert_eq!(dataspace_plane(&lane_config, DataSpaceId::new(999)), None);
    }
    #[test]
    fn gossip_plane_labels_are_stable() {
        assert_eq!(gossip_plane_label(GossipPlane::Public), "public");
        assert_eq!(gossip_plane_label(GossipPlane::Restricted), "restricted");
    }
    #[test]
    fn dataspace_label_renders_numeric_id() {
        let dataspace = DataSpaceId::new(42);
        assert_eq!(dataspace_label(dataspace), "42");
    }
    #[test]
    fn select_targets_dedups_and_caps_with_seed() {
        let targets = vec![
            (*ALICE_KEYPAIR).public_key().clone().into(),
            (*BOB_KEYPAIR).public_key().clone().into(),
            (*ALICE_KEYPAIR).public_key().clone().into(),
            (*PEER_KEYPAIR).public_key().clone().into(),
        ];
        let cap = NonZeroUsize::new(2).expect("non-zero cap");
        let seed = 0xA5A5_1234;
        let (selected, total) =
            TransactionGossiper::select_targets_with_seed(targets.clone(), Some(cap), seed);
        let unique: BTreeSet<_> = targets.into_iter().collect();
        assert_eq!(total, unique.len(), "total should count unique targets");
        assert_eq!(selected.len(), cap.get(), "selection should respect cap");
        assert!(
            selected.iter().all(|peer| unique.contains(peer)),
            "selection must be a subset of inputs"
        );
    }
    #[test]
    fn select_targets_is_deterministic_for_seed() {
        let targets = vec![
            (*ALICE_KEYPAIR).public_key().clone().into(),
            (*BOB_KEYPAIR).public_key().clone().into(),
            (*PEER_KEYPAIR).public_key().clone().into(),
            (*CARPENTER_KEYPAIR).public_key().clone().into(),
        ];
        let cap = NonZeroUsize::new(3).expect("non-zero cap");
        let seed = 0xDEAD_BEEF;
        let (first, _) =
            TransactionGossiper::select_targets_with_seed(targets.clone(), Some(cap), seed);
        let (second, _) = TransactionGossiper::select_targets_with_seed(targets, Some(cap), seed);
        assert_eq!(
            first, second,
            "selection should be stable for the same seed"
        );
    }
    #[test]
    fn public_gossip_fanout_keeps_cap_without_backlog() {
        let cap = NonZeroUsize::new(4).expect("non-zero cap");
        let gossip_size = NonZeroU32::new(8).expect("non-zero gossip size");
        let effective =
            TransactionGossiper::effective_public_target_cap(Some(cap), gossip_size, 7, false);
        assert_eq!(effective, Some(cap));
    }
    #[test]
    fn public_gossip_fanout_widens_under_targeted_backlog() {
        let cap = NonZeroUsize::new(4).expect("non-zero cap");
        let gossip_size = NonZeroU32::new(8).expect("non-zero gossip size");
        let effective =
            TransactionGossiper::effective_public_target_cap(Some(cap), gossip_size, 16, false);
        assert_eq!(
            effective, None,
            "backlogged public ingress should feed the whole online validator set"
        );
    }
    #[test]
    fn public_gossip_fanout_widens_when_queue_is_saturated() {
        let cap = NonZeroUsize::new(4).expect("non-zero cap");
        let gossip_size = NonZeroU32::new(8).expect("non-zero gossip size");
        let effective =
            TransactionGossiper::effective_public_target_cap(Some(cap), gossip_size, 1, true);
        assert_eq!(effective, None);
    }
    #[test]
    fn seed_for_plane_changes_with_dataspace() {
        let base = 0xCAFE_BABE;
        let first = TransactionGossiper::seed_for_plane(
            base,
            DataSpaceId::new(1),
            GOSSIP_SEED_PUBLIC_DOMAIN,
        );
        let second = TransactionGossiper::seed_for_plane(
            base,
            DataSpaceId::new(2),
            GOSSIP_SEED_PUBLIC_DOMAIN,
        );
        assert_ne!(first, second, "dataspace should perturb the gossip seed");
    }
    #[test]
    fn gossip_target_seed_holds_until_reshuffle_period() {
        let now = Instant::now();
        let mut seed = GossipTargetSeed::new(0xA5A5_1234, Duration::from_secs(5), now);
        let first = seed.current(now);
        let still = seed.current(now + Duration::from_secs(4));
        assert_eq!(first, still, "seed should remain stable before reshuffle");
    }
    #[test]
    fn gossip_target_seed_advances_after_reshuffle_period() {
        let now = Instant::now();
        let mut seed = GossipTargetSeed::new(0xBEEF_0001, Duration::from_secs(5), now);
        let first = seed.current(now);
        let updated = seed.current(now + Duration::from_secs(5));
        assert_eq!(
            updated,
            splitmix64(first),
            "seed should advance on reshuffle"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn gossip_accepts_valid_entries_with_invalid_routes_present() {
        let temp_dir = tempdir().expect("temp dir");
        let kura_cfg = KuraConfig {
            init_mode: iroha_config::kura::InitMode::Strict,
            store_dir: WithOrigin::inline(temp_dir.path().to_path_buf()),
            max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: defaults::kura::BLOCKS_IN_MEMORY,
            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity:
                iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes:
                iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes:
                iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
            debug_output_new_blocks: false,
            fsync_mode: FsyncMode::Batched,
            fsync_interval: defaults::kura::FSYNC_INTERVAL,
        };
        let (kura, _) =
            Kura::open_test_kura_with_configured_lane_config(&kura_cfg, &LaneGeometry::default())
                .expect("init kura");
        let live_query = LiveQueryStore::start_test();
        let state = Arc::new(State::new_for_testing(world_with_alice(), kura, live_query));
        install_active_single_lane_nexus(state.as_ref());
        let queue = Arc::new(Queue::test(
            QueueConfig::default(),
            &TimeSource::new_system(),
        ));
        let now = Instant::now();
        let gossiper = TransactionGossiper {
            gossip_period: Duration::from_millis(50),
            gossip_size: NonZeroU32::new(2).expect("nonzero size"),
            gossip_resend_ticks: defaults::network::TRANSACTION_GOSSIP_RESEND_TICKS,
            gossip_tick: 0,
            gossip_deferred: vec![
                Vec::new();
                defaults::network::TRANSACTION_GOSSIP_RESEND_TICKS.get() as usize
            ],
            peer_recently_sent: BTreeMap::new(),
            peer_recent_ring: vec![Vec::new(); GOSSIP_PEER_RECENT_SUPPRESSION_TTL_TICKS],
            last_drop_count: tx_gossip_relay_drop_count(),
            last_drop_at: None,
            network: IrohaNetwork::closed_for_tests(),
            self_peer_id: PeerId::new(PEER_KEYPAIR.public_key().clone()),
            queue: Arc::clone(&queue),
            state: Arc::clone(&state),
            tx_frame_cap: 1024,
            dataspace_cfg: DataspaceGossip::default(),
            public_seed: GossipTargetSeed::new(0xBEEF_0001, Duration::from_secs(1), now),
            restricted_seed: GossipTargetSeed::new(0xBEEF_0002, Duration::from_secs(1), now),
        };
        let (invalid_signed, _) = build_transaction("invalid");
        let (valid_signed, _) = build_transaction("valid");
        let invalid_route = GossipRoute {
            lane_id: LaneId::new(9),
            dataspace_id: DataSpaceId::new(9),
        };
        let valid_route = GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        gossiper.handle_transaction_gossip(Arc::new(TransactionGossip {
            txs: vec![invalid_signed.into(), valid_signed.into()],
            routes: vec![invalid_route, valid_route],
            plans: vec![plan_for_route(invalid_route), plan_for_route(valid_route)],
            plane: GossipPlane::Public,
        }));
        assert_eq!(queue.queued_len(), 1);
    }
    #[test]
    fn gossip_accepts_valid_prefix_when_route_metadata_is_short() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        let (valid, _) = build_transaction("valid-before-missing-route");
        let (missing_route, _) = build_transaction("missing-route");
        let route = GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        gossiper.handle_transaction_gossip(Arc::new(TransactionGossip {
            txs: vec![valid.into(), missing_route.into()],
            routes: vec![route],
            plans: vec![default_plan(), default_plan()],
            plane: GossipPlane::Public,
        }));
        assert_eq!(
            gossiper.queue.queued_len(),
            1,
            "missing suffix route metadata must not suppress aligned valid entries"
        );
    }
    #[test]
    fn gossip_accepts_valid_prefix_when_plan_metadata_is_short() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        let (valid, _) = build_transaction("valid-before-missing-plan");
        let (missing_plan, _) = build_transaction("missing-plan");
        let route = GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        gossiper.handle_transaction_gossip(Arc::new(TransactionGossip {
            txs: vec![valid.into(), missing_plan.into()],
            routes: vec![route, route],
            plans: vec![default_plan()],
            plane: GossipPlane::Public,
        }));
        assert_eq!(
            gossiper.queue.queued_len(),
            1,
            "missing suffix plan metadata must not suppress aligned valid entries"
        );
    }
    #[test]
    fn gossip_drops_batch_with_extra_routing_metadata() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        let (extra_route_tx, _) = build_transaction("extra-route-metadata");
        let route = GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        gossiper.handle_transaction_gossip(Arc::new(TransactionGossip {
            txs: vec![extra_route_tx.into()],
            routes: vec![route, route],
            plans: vec![default_plan()],
            plane: GossipPlane::Public,
        }));
        assert_eq!(
            gossiper.queue.queued_len(),
            0,
            "unpaired extra route metadata must reject the whole gossip frame"
        );
        let (extra_plan_tx, _) = build_transaction("extra-plan-metadata");
        gossiper.handle_transaction_gossip(Arc::new(TransactionGossip {
            txs: vec![extra_plan_tx.into()],
            routes: vec![route],
            plans: vec![default_plan(), default_plan()],
            plane: GossipPlane::Public,
        }));
        assert_eq!(
            gossiper.queue.queued_len(),
            0,
            "unpaired extra plan metadata must reject the whole gossip frame"
        );
    }
    #[test]
    fn gossip_drops_owned_batch_above_transaction_count_limit() {
        let mut gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        gossiper.gossip_size = NonZeroU32::new(1).expect("nonzero batch limit");
        let (first, _) = build_transaction("owned-count-limit-first");
        let (second, _) = build_transaction("owned-count-limit-second");
        let route = GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        gossiper.handle_transaction_gossip(Arc::new(TransactionGossip {
            txs: vec![first.into(), second.into()],
            routes: vec![route, route],
            plans: vec![default_plan(), default_plan()],
            plane: GossipPlane::Public,
        }));
        assert_eq!(gossiper.queue.queued_len(), 0);
    }
    #[test]
    fn gossip_drops_shared_batch_above_transaction_count_limit_before_materialization() {
        let mut gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        gossiper.gossip_size = NonZeroU32::new(1).expect("nonzero batch limit");
        let (first, _) = build_transaction("shared-count-limit-first");
        let (second, _) = build_transaction("shared-count-limit-second");
        let route = GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        let decoded = decode_gossip_message(&TransactionGossip {
            txs: vec![first.into(), second.into()],
            routes: vec![route, route],
            plans: vec![default_plan(), default_plan()],
            plane: GossipPlane::Public,
        });
        assert!(
            decoded
                .txs
                .iter()
                .all(|transaction| !transaction.is_entrypoint_materialized())
        );
        let message = Arc::new(decoded);
        let retained = Arc::clone(&message);
        gossiper.handle_transaction_gossip(message);
        assert_eq!(gossiper.queue.queued_len(), 0);
        assert!(
            retained
                .txs
                .iter()
                .all(|transaction| !transaction.is_entrypoint_materialized()),
            "count rejection must happen before entrypoint decoding"
        );
    }
    #[test]
    fn shared_gossip_accepts_valid_prefix_when_route_metadata_is_short() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        let (valid, _) = build_transaction("shared-valid-before-missing-route");
        let (missing_route, _) = build_transaction("shared-missing-route");
        let route = GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        let decoded = decode_gossip_message(&TransactionGossip {
            txs: vec![
                GossipTransaction::with_encoded(valid.clone(), payload_for(&valid)),
                GossipTransaction::with_encoded(missing_route.clone(), payload_for(&missing_route)),
            ],
            routes: vec![route],
            plans: vec![default_plan(), default_plan()],
            plane: GossipPlane::Public,
        });
        assert!(!decoded.txs[1].is_entrypoint_materialized());
        let shared = Arc::new(decoded);
        let retained = Arc::clone(&shared);
        gossiper.handle_transaction_gossip(shared);
        assert_eq!(
            gossiper.queue.queued_len(),
            1,
            "shared route-short gossip must keep aligned valid entries"
        );
        assert!(
            !retained.txs[1].is_entrypoint_materialized(),
            "missing route metadata must drop before entrypoint materialization"
        );
    }
    #[test]
    fn shared_gossip_accepts_valid_prefix_when_plan_metadata_is_short() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        let (valid, _) = build_transaction("shared-valid-before-missing-plan");
        let (missing_plan, _) = build_transaction("shared-missing-plan");
        let route = GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        let decoded = decode_gossip_message(&TransactionGossip {
            txs: vec![
                GossipTransaction::with_encoded(valid.clone(), payload_for(&valid)),
                GossipTransaction::with_encoded(missing_plan.clone(), payload_for(&missing_plan)),
            ],
            routes: vec![route, route],
            plans: vec![default_plan()],
            plane: GossipPlane::Public,
        });
        assert!(!decoded.txs[1].is_entrypoint_materialized());
        let shared = Arc::new(decoded);
        let retained = Arc::clone(&shared);
        gossiper.handle_transaction_gossip(shared);
        assert_eq!(
            gossiper.queue.queued_len(),
            1,
            "shared plan-short gossip must keep aligned valid entries"
        );
        assert!(
            !retained.txs[1].is_entrypoint_materialized(),
            "missing plan metadata must drop before entrypoint materialization"
        );
    }
    #[test]
    fn shared_gossip_drops_batch_with_extra_routing_metadata_without_materialization() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        let (valid, _) = build_transaction("shared-extra-routing-metadata");
        let route = GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        let decoded = decode_gossip_message(&TransactionGossip {
            txs: vec![GossipTransaction::with_encoded(
                valid.clone(),
                payload_for(&valid),
            )],
            routes: vec![route],
            plans: vec![default_plan(), default_plan()],
            plane: GossipPlane::Public,
        });
        assert!(!decoded.txs[0].is_entrypoint_materialized());
        let shared = Arc::new(decoded);
        let retained = Arc::clone(&shared);
        gossiper.handle_transaction_gossip(shared);
        assert_eq!(
            gossiper.queue.queued_len(),
            0,
            "shared gossip with unpaired extra metadata must reject the whole frame"
        );
        assert!(
            !retained.txs[0].is_entrypoint_materialized(),
            "extra routing metadata must drop before entrypoint materialization"
        );
    }
    #[test]
    fn shared_gossip_drops_noncanonical_single_plan_without_materialization() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        let (invalid, _) = build_transaction("shared-noncanonical-single-plan");
        let (valid, _) = build_transaction("shared-valid-after-noncanonical-single-plan");
        let route = GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        let noncanonical_plan = RoutingPlan::Single(crate::queue::RouteLeg::new(
            RoutingDecision::default(),
            crate::queue::RouteLegRole::Participant,
        ));
        let decoded = decode_gossip_message(&TransactionGossip {
            txs: vec![
                GossipTransaction::with_encoded(invalid.clone(), payload_for(&invalid)),
                GossipTransaction::with_encoded(valid.clone(), payload_for(&valid)),
            ],
            routes: vec![route, route],
            plans: vec![noncanonical_plan, default_plan()],
            plane: GossipPlane::Public,
        });
        assert!(!decoded.txs[0].is_entrypoint_materialized());
        let shared = Arc::new(decoded);
        let retained = Arc::clone(&shared);
        gossiper.handle_transaction_gossip(shared);
        assert_eq!(
            gossiper.queue.queued_len(),
            1,
            "shared noncanonical routing plan must keep valid entries"
        );
        assert!(
            !retained.txs[0].is_entrypoint_materialized(),
            "noncanonical routing plan must drop before materialization"
        );
    }
    #[test]
    fn route_invalid_gossip_drop_does_not_materialize_entrypoint() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        let (signed, _) = build_transaction("lazy-invalid-route");
        let decoded = decode_gossip_message(&TransactionGossip {
            txs: vec![GossipTransaction::with_encoded(
                signed.clone(),
                payload_for(&signed),
            )],
            routes: vec![GossipRoute {
                lane_id: LaneId::new(9),
                dataspace_id: DataSpaceId::new(9),
            }],
            plans: vec![RoutingPlan::single(RoutingDecision::new(
                LaneId::new(9),
                DataSpaceId::new(9),
            ))],
            plane: GossipPlane::Public,
        });
        assert!(
            !decoded.txs[0].is_entrypoint_materialized(),
            "decoded gossip should start without semantic entrypoint materialization"
        );
        let shared = Arc::new(decoded);
        let retained = Arc::clone(&shared);
        gossiper.handle_transaction_gossip(shared);
        assert!(
            !retained.txs[0].is_entrypoint_materialized(),
            "route rejection should not force entrypoint decode"
        );
        assert_eq!(gossiper.queue.queued_len(), 0);
    }
    #[test]
    fn inactive_autoscale_route_gossip_drop_does_not_materialize_entrypoint() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        let inactive_lane = LaneId::new(1);
        let mut autoscale_lane = iroha_data_model::nexus::LaneConfig {
            id: inactive_lane,
            alias: "elastic-lane-1".to_string(),
            dataspace_id: DataSpaceId::UNIVERSAL,
            visibility: iroha_data_model::nexus::LaneVisibility::Public,
            ..iroha_data_model::nexus::LaneConfig::default()
        };
        autoscale_lane.metadata.insert(
            iroha_data_model::nexus::AUTOSCALE_META_MANAGED.to_string(),
            "true".to_string(),
        );
        autoscale_lane.metadata.insert(
            iroha_data_model::nexus::AUTOSCALE_META_CREATED_HEIGHT.to_string(),
            "7".to_string(),
        );
        crate::state::attach_synthetic_autoscale_committee_for_test(&mut autoscale_lane);
        let lane_catalog = LaneCatalog::new(
            core::num::NonZeroU32::new(2).expect("nonzero lanes"),
            vec![
                iroha_data_model::nexus::LaneConfig::default(),
                autoscale_lane,
            ],
        )
        .expect("future-created autoscale lane catalog");
        let mut nexus = iroha_config::parameters::actual::Nexus {
            lane_config: LaneGeometry::from_catalog(&lane_catalog),
            lane_catalog,
            ..iroha_config::parameters::actual::Nexus::default()
        };
        nexus.autoscale.enabled = true;
        nexus.autoscale.min_lane_id = NonZeroU32::new(1).expect("nonzero min lanes");
        nexus.autoscale.max_lane_id_exclusive = NonZeroU32::new(2).expect("nonzero max lanes");
        gossiper
            .state
            .install_synthetic_routing_snapshot_for_testing(nexus);
        assert_eq!(
            crate::state::nexus_active_lane_dataspace_at_height(
                inactive_lane,
                &gossiper.state.nexus_snapshot(),
                7,
            ),
            Some(DataSpaceId::UNIVERSAL),
            "future-created autoscale gossip fixture must be a valid elastic lane at its creation height"
        );
        assert!(
            !gossiper.state.is_lane_active_for_authority(inactive_lane),
            "future-created autoscale gossip fixture must be inactive at the committed lane-authority height"
        );
        let route = GossipRoute {
            lane_id: inactive_lane,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        let (signed, _) = build_transaction("lazy-inactive-autoscale-route");
        let decoded = decode_gossip_message(&TransactionGossip {
            txs: vec![GossipTransaction::with_encoded(
                signed.clone(),
                payload_for(&signed),
            )],
            routes: vec![route],
            plans: vec![plan_for_route(route)],
            plane: GossipPlane::Public,
        });
        assert!(
            !decoded.txs[0].is_entrypoint_materialized(),
            "decoded gossip should start without semantic entrypoint materialization"
        );
        let shared = Arc::new(decoded);
        let retained = Arc::clone(&shared);
        gossiper.handle_transaction_gossip(shared);
        assert!(
            !retained.txs[0].is_entrypoint_materialized(),
            "inactive route rejection should not force entrypoint decode"
        );
        assert_eq!(gossiper.queue.queued_len(), 0);
    }
    #[test]
    fn known_duplicate_gossip_drop_does_not_materialize_entrypoint() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        let (signed, accepted) = build_transaction("lazy-known-duplicate");
        gossiper
            .queue
            .push(accepted, gossiper.state.view())
            .expect("seed queue with known transaction");
        let decoded = decode_gossip_message(&TransactionGossip {
            txs: vec![GossipTransaction::with_encoded(
                signed.clone(),
                payload_for(&signed),
            )],
            routes: vec![GossipRoute {
                lane_id: LaneId::SINGLE,
                dataspace_id: DataSpaceId::UNIVERSAL,
            }],
            plans: vec![default_plan()],
            plane: GossipPlane::Public,
        });
        assert!(!decoded.txs[0].is_entrypoint_materialized());
        let shared = Arc::new(decoded);
        let retained = Arc::clone(&shared);
        gossiper.handle_transaction_gossip(shared);
        assert!(
            !retained.txs[0].is_entrypoint_materialized(),
            "known duplicate rejection should not force entrypoint decode"
        );
        assert_eq!(gossiper.queue.queued_len(), 1);
    }
    #[test]
    fn gossip_ed25519_batch_precheck_accepts_all_valid_single_key_transactions() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        let (first, _) = build_transaction("batch-valid-a");
        let (second, _) = build_transaction("batch-valid-b");
        gossiper.handle_transaction_gossip(Arc::new(TransactionGossip {
            txs: vec![first.into(), second.into()],
            routes: vec![
                GossipRoute {
                    lane_id: LaneId::SINGLE,
                    dataspace_id: DataSpaceId::UNIVERSAL,
                },
                GossipRoute {
                    lane_id: LaneId::SINGLE,
                    dataspace_id: DataSpaceId::UNIVERSAL,
                },
            ],
            plans: vec![default_plan(), default_plan()],
            plane: GossipPlane::Public,
        }));
        assert_eq!(gossiper.queue.queued_len(), 2);
    }
    #[test]
    fn gossip_ed25519_batch_precheck_drops_invalid_single_key_signature() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        let (valid, _) = build_transaction("batch-valid-before-invalid");
        let (mut invalid, _) = build_transaction("batch-invalid-signature");
        corrupt_signature(&mut invalid);
        gossiper.handle_transaction_gossip(Arc::new(TransactionGossip {
            txs: vec![valid.into(), invalid.into()],
            routes: vec![
                GossipRoute {
                    lane_id: LaneId::SINGLE,
                    dataspace_id: DataSpaceId::UNIVERSAL,
                },
                GossipRoute {
                    lane_id: LaneId::SINGLE,
                    dataspace_id: DataSpaceId::UNIVERSAL,
                },
            ],
            plans: vec![default_plan(), default_plan()],
            plane: GossipPlane::Public,
        }));
        assert_eq!(gossiper.queue.queued_len(), 1);
    }
    #[test]
    fn gossip_rejects_changed_signature_after_exact_valid_envelope_warms_cache() {
        let gossiper = closed_test_gossiper(NonZeroU32::new(1).expect("nonzero resend ticks"));
        assert!(gossiper.state.installed_pipeline().stateless_cache_cap > 0);
        let (valid, _) = build_transaction("signature-cache-identity");
        let (max_clock_drift, limits) = gossiper.state.transaction_admission_limits();
        let (_clock, time_source) = TimeSource::new_mock(valid.creation_time());
        let accepted = AcceptedTransaction::accept_with_time_source(
            valid.clone(),
            gossiper.state.network_id_ref(),
            max_clock_drift,
            limits,
            &gossiper.state.crypto(),
            &time_source,
        )
        .expect("validate the complete original signed envelope");
        gossiper
            .state
            .warm_stateless_validation_cache_for_torii_prechecked_batch([&accepted]);
        let valid_key = crate::tx::StatelessValidationCacheKey::new(&valid);
        assert!(
            gossiper
                .state
                .stateless_validation_cache()
                .lock()
                .contains_key(&valid_key)
        );
        let mut invalid = valid.clone();
        corrupt_signature(&mut invalid);
        assert_eq!(
            valid.hash_as_entrypoint(),
            invalid.hash_as_entrypoint(),
            "the signature substitution preserves logical transaction identity"
        );
        assert_ne!(
            valid_key,
            crate::tx::StatelessValidationCacheKey::new(&invalid)
        );
        gossiper.handle_transaction_gossip(Arc::new(TransactionGossip {
            txs: vec![invalid.into()],
            routes: vec![GossipRoute {
                lane_id: LaneId::SINGLE,
                dataspace_id: DataSpaceId::UNIVERSAL,
            }],
            plans: vec![default_plan()],
            plane: GossipPlane::Public,
        }));
        assert_eq!(
            gossiper.queue.queued_len(),
            0,
            "an invalid signature cannot reuse the valid envelope's precheck"
        );
        gossiper.handle_transaction_gossip(Arc::new(TransactionGossip {
            txs: vec![valid.into()],
            routes: vec![GossipRoute {
                lane_id: LaneId::SINGLE,
                dataspace_id: DataSpaceId::UNIVERSAL,
            }],
            plans: vec![default_plan()],
            plane: GossipPlane::Public,
        }));
        assert_eq!(gossiper.queue.queued_len(), 1);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn gossip_skips_already_known_transaction_hashes() {
        let temp_dir = tempdir().expect("temp dir");
        let kura_cfg = KuraConfig {
            init_mode: iroha_config::kura::InitMode::Strict,
            store_dir: WithOrigin::inline(temp_dir.path().to_path_buf()),
            max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: defaults::kura::BLOCKS_IN_MEMORY,
            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity:
                iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes:
                iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes:
                iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
            debug_output_new_blocks: false,
            fsync_mode: FsyncMode::Batched,
            fsync_interval: defaults::kura::FSYNC_INTERVAL,
        };
        let (kura, _) =
            Kura::open_test_kura_with_configured_lane_config(&kura_cfg, &LaneGeometry::default())
                .expect("init kura");
        let live_query = LiveQueryStore::start_test();
        let state = Arc::new(State::new_for_testing(world_with_alice(), kura, live_query));
        install_active_single_lane_nexus(state.as_ref());
        let queue = Arc::new(Queue::test(
            QueueConfig::default(),
            &TimeSource::new_system(),
        ));
        let network = IrohaNetwork::closed_for_tests();
        let (known_signed, _) = build_transaction("known");
        queue
            .push(
                AcceptedTransaction::new_unchecked(Cow::Owned(known_signed.clone())),
                state.view(),
            )
            .expect("seed queue with known tx");
        assert_eq!(queue.queued_len(), 1, "queue should contain the seeded tx");
        let now = Instant::now();
        let gossiper = TransactionGossiper {
            gossip_period: Duration::from_millis(50),
            gossip_size: NonZeroU32::new(1).expect("nonzero size"),
            gossip_resend_ticks: defaults::network::TRANSACTION_GOSSIP_RESEND_TICKS,
            gossip_tick: 0,
            gossip_deferred: vec![
                Vec::new();
                defaults::network::TRANSACTION_GOSSIP_RESEND_TICKS.get() as usize
            ],
            peer_recently_sent: BTreeMap::new(),
            peer_recent_ring: vec![Vec::new(); GOSSIP_PEER_RECENT_SUPPRESSION_TTL_TICKS],
            last_drop_count: tx_gossip_relay_drop_count(),
            last_drop_at: None,
            network,
            self_peer_id: PeerId::new(PEER_KEYPAIR.public_key().clone()),
            queue: Arc::clone(&queue),
            state,
            tx_frame_cap: 1024,
            dataspace_cfg: DataspaceGossip::default(),
            public_seed: GossipTargetSeed::new(0xBEEF_0001, Duration::from_secs(1), now),
            restricted_seed: GossipTargetSeed::new(0xBEEF_0002, Duration::from_secs(1), now),
        };
        gossiper.handle_transaction_gossip(Arc::new(TransactionGossip {
            txs: vec![known_signed.into()],
            routes: vec![GossipRoute {
                lane_id: LaneId::SINGLE,
                dataspace_id: DataSpaceId::UNIVERSAL,
            }],
            plans: vec![default_plan()],
            plane: GossipPlane::Public,
        }));
        assert_eq!(
            queue.queued_len(),
            1,
            "already-known gossip should be ignored without queue churn"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn gossip_drops_route_mismatch() {
        struct FixedRouter {
            lane: LaneId,
            dataspace: DataSpaceId,
        }
        impl LaneRouter for FixedRouter {
            fn try_route(
                &self,
                _tx: &dyn crate::queue::TransactionRoutingView,
            ) -> Result<RoutingDecision, crate::queue::RoutingResolveError> {
                Ok(RoutingDecision::new(self.lane, self.dataspace))
            }
        }
        let mismatched_lane = LaneId::new(1);
        let mismatched_dataspace = DataSpaceId::new(7);
        let lane_catalog = LaneCatalog::new(
            NonZeroU32::new(2).expect("nonzero lanes"),
            vec![
                iroha_data_model::nexus::LaneConfig::default(),
                iroha_data_model::nexus::LaneConfig {
                    id: mismatched_lane,
                    dataspace_id: mismatched_dataspace,
                    alias: "mismatched".to_string(),
                    ..iroha_data_model::nexus::LaneConfig::default()
                },
            ],
        )
        .expect("lane catalog");
        let dataspace_catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: mismatched_dataspace,
                alias: "mismatched".to_string(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("dataspace catalog");
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.lane_catalog = lane_catalog.clone();
        nexus.lane_config = LaneGeometry::from_catalog(&lane_catalog);
        nexus.dataspace_catalog = dataspace_catalog.clone();
        let state = Arc::new(State::new_with_nexus_for_testing(
            World::new(),
            nexus,
            LiveQueryStore::start_test(),
        ));
        let lane_catalog = Arc::new(lane_catalog);
        let dataspace_catalog = Arc::new(dataspace_catalog);
        let queue = Arc::new(Queue::from_config_with_router_limits_and_catalogs(
            QueueConfig::default(),
            tokio::sync::broadcast::Sender::new(1),
            Arc::new(FixedRouter {
                lane: mismatched_lane,
                dataspace: mismatched_dataspace,
            }),
            crate::queue::QueueLimits::default(),
            &lane_catalog,
            &dataspace_catalog,
            None,
        ));
        queue.install_test_router_metadata_for_nexus(&state.nexus_snapshot());
        let now = Instant::now();
        let gossiper = TransactionGossiper {
            gossip_period: Duration::from_millis(50),
            gossip_size: NonZeroU32::new(1).expect("nonzero size"),
            gossip_resend_ticks: defaults::network::TRANSACTION_GOSSIP_RESEND_TICKS,
            gossip_tick: 0,
            gossip_deferred: vec![
                Vec::new();
                defaults::network::TRANSACTION_GOSSIP_RESEND_TICKS.get() as usize
            ],
            peer_recently_sent: BTreeMap::new(),
            peer_recent_ring: vec![Vec::new(); GOSSIP_PEER_RECENT_SUPPRESSION_TTL_TICKS],
            last_drop_count: tx_gossip_relay_drop_count(),
            last_drop_at: None,
            network: IrohaNetwork::closed_for_tests(),
            self_peer_id: PeerId::new(PEER_KEYPAIR.public_key().clone()),
            queue: Arc::clone(&queue),
            state,
            tx_frame_cap: 1024,
            dataspace_cfg: DataspaceGossip::default(),
            public_seed: GossipTargetSeed::new(0xBEEF_0001, Duration::from_secs(1), now),
            restricted_seed: GossipTargetSeed::new(0xBEEF_0002, Duration::from_secs(1), now),
        };
        let (signed, _) = build_transaction("route-mismatch");
        let route = GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        gossiper.handle_transaction_gossip(Arc::new(TransactionGossip {
            txs: vec![signed.into()],
            routes: vec![route],
            plans: vec![plan_for_route(route)],
            plane: GossipPlane::Public,
        }));
        assert_eq!(queue.queued_len(), 0);
    }
    include!("gossiper/certified_single_owner_tests.rs");
    include!("gossiper_network_domain_tests.rs");
    include!("gossiper_restricted_route_tests.rs");
    #[test]
    fn lazy_gossip_materialization_retains_every_complete_original_carrier() {
        use iroha_data_model::transaction::signed::SealedTransactionReveal;
        let (signed, _) = build_transaction("complete-gossip-carrier");
        let inputs = [
            TransactionEntrypoint::External(signed.clone()),
            build_sealed_commitment_entrypoint(),
            TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
                iroha_crypto::Hash::new(b"original-gossip-commitment"),
                signed,
                [0x91; 32],
            )),
        ];
        for input in inputs {
            let bytes = Arc::new(encode_transaction_entrypoint(&input));
            let (decoded, used) =
                <GossipTransaction as ncore::DecodeFromSlice>::decode_from_slice(&bytes)
                    .expect("decode the canonical complete carrier");
            assert_eq!(used, bytes.len());
            assert!(!decoded.is_entrypoint_materialized());
            assert_eq!(decoded.hash(), input.hash());
            let original_frame = decoded.payload();
            for _ in 0..2 {
                let (retained, frame) = decoded.clone().into_entrypoint_with_payload().unwrap();
                assert_eq!(retained, input);
                assert_eq!(retained.hash(), input.hash());
                assert_eq!(frame.as_slice(), bytes.as_slice());
                assert!(Arc::ptr_eq(&frame, &original_frame));
                assert!(decoded.is_entrypoint_materialized());
            }
        }
    }
    #[test]
    fn lazy_gossip_decode_error_preserves_unmaterialized_original_for_retry() {
        let (signed, _) = build_transaction("refused-gossip-carrier");
        let original = Arc::new(vec![0_u8; ncore::Header::SIZE]);
        let item = GossipTransaction::lazy_from_encoded(
            Arc::clone(&original),
            signed.hash_as_entrypoint(),
        );
        let identity = item.hash();
        for _ in 0..2 {
            assert!(item.clone().into_entrypoint_with_payload().is_err());
            assert!(!item.is_entrypoint_materialized());
            assert!(Arc::ptr_eq(&item.payload(), &original));
            assert_eq!(item.payload().as_slice(), original.as_slice());
            assert_eq!(item.hash(), identity);
        }
    }
    #[test]
    fn native_gossip_item_is_one_canonical_frame_and_rejects_retired_prefixes() {
        let (signed, _) = build_transaction("native-gossip-frame");
        let frame = payload_for(&signed);
        let item = GossipTransaction::with_encoded(signed.clone(), Arc::clone(&frame));
        let bytes = item.encode();
        assert_eq!(bytes.as_slice(), frame.as_slice());
        assert_eq!(item.encoded_len_exact(), Some(frame.len()));
        let (decoded, used) =
            <GossipTransaction as ncore::DecodeFromSlice>::decode_from_slice(&bytes)
                .expect("canonical item");
        assert_eq!(used, bytes.len());
        assert_eq!(
            decoded.clone().into_entrypoint_with_payload().unwrap().0,
            TransactionEntrypoint::External(signed.clone())
        );
        for retired_tag in [0, 1] {
            let mut retired = vec![retired_tag];
            retired.extend_from_slice(&bytes);
            assert!(
                <GossipTransaction as ncore::DecodeFromSlice>::decode_from_slice(&retired).is_err()
            );
        }
        let mut followed = bytes.clone();
        followed.extend_from_slice(&[0xA5, 0x5A]);
        let (_, boundary) =
            <GossipTransaction as ncore::DecodeFromSlice>::decode_from_slice(&followed)
                .expect("bounded prefix");
        assert_eq!(boundary, bytes.len());
        assert_eq!(&followed[boundary..], &[0xA5, 0x5A]);
    }
}
