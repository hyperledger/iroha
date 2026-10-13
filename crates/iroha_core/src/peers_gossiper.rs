//! Peers gossiper is actor which is responsible for gossiping addresses of peers.
//!
//! E.g. peer A changes address, connects to peer B,
//! and then peer B will broadcast address of peer A to other peers.
#![allow(clippy::disallowed_types)]
use crate::{IrohaNetwork, NetworkMessage};
use iroha_config::parameters::actual::TrustedPeers;
use iroha_crypto::{KeyPair, Signature};
use iroha_data_model::{NetworkId, peer::Peer};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use iroha_model_base::peer::PeerId;
use iroha_p2p::{
    Broadcast, PeerTransportCapabilities, UpdatePeerCapabilities, UpdatePeers, UpdateTopology,
    UpdateTrustedPeers, UpdateValidatorTopology,
};
use iroha_primitives::{addr::SocketAddr, unique_vec::UniqueVec};
use norito::{
    DeserializePayload, NoritoDeserialize, NoritoSerialize, SerializePayload, codec::Encode,
    core as ncore,
};
#[allow(clippy::disallowed_types)]
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::Duration,
};
use tokio::sync::mpsc;
/// Trust tracking entry with decay metadata.
#[derive(Debug, Clone)]
struct TrustEntry {
    score: i64,
    last_updated: std::time::Instant,
}
#[derive(Debug, Clone, Copy)]
struct TrustPenalties {
    bad_gossip: i64,
    unknown_peer: i64,
}
const PENALTY_REASON_INVALID_SIGNATURE: &str = "invalid_signature";
const PENALTY_REASON_UNKNOWN_PEER: &str = "unknown_peer";
#[derive(Debug, Clone, Copy)]
enum TrustPenaltyKind {
    BadGossip,
    UnknownPeer,
}
impl TrustPenaltyKind {
    fn amount(self, penalties: &TrustPenalties) -> i64 {
        match self {
            Self::BadGossip => penalties.bad_gossip,
            Self::UnknownPeer => penalties.unknown_peer,
        }
    }
}
/// Deterministic trust tracker used by the peers gossiper.
#[derive(Debug, Clone)]
struct TrustBook {
    entries: BTreeMap<PeerId, TrustEntry>,
    decay_half_life: Duration,
    penalties: TrustPenalties,
    min_score: i64,
}
impl TrustBook {
    fn new(decay_half_life: Duration, penalties: TrustPenalties, min_score: i32) -> Self {
        Self {
            entries: BTreeMap::new(),
            decay_half_life,
            penalties,
            min_score: i64::from(min_score),
        }
    }
    fn seed<I: IntoIterator<Item = PeerId>>(&mut self, peers: I, now: std::time::Instant) {
        for peer in peers {
            self.entries.entry(peer).or_insert(TrustEntry {
                score: 0,
                last_updated: now,
            });
        }
    }
    fn decay_entry(
        entry: &mut TrustEntry,
        decay_half_life: std::time::Duration,
        now: std::time::Instant,
    ) -> u64 {
        if decay_half_life.is_zero() {
            entry.last_updated = now;
            return 0;
        }
        let elapsed = now.saturating_duration_since(entry.last_updated);
        let steps = elapsed.as_millis() / decay_half_life.as_millis();
        if steps == 0 {
            return 0;
        }
        let steps_u64 = u64::try_from(steps).unwrap_or(u64::MAX);
        let mut remaining_steps = steps_u64;
        while remaining_steps > 0 && entry.score != 0 {
            entry.score /= 2;
            remaining_steps -= 1;
        }
        entry.last_updated = entry
            .last_updated
            .checked_add(decay_half_life * u32::try_from(steps_u64).unwrap_or(u32::MAX))
            .unwrap_or(now);
        steps_u64
    }
    fn with_entry<R, F>(&mut self, peer: &PeerId, now: std::time::Instant, mut f: F) -> R
    where
        F: FnMut(&mut TrustEntry) -> R,
    {
        let (result, ticks) = {
            let entry = self.entries.entry(peer.clone()).or_insert(TrustEntry {
                score: 0,
                last_updated: now,
            });
            let ticks = Self::decay_entry(entry, self.decay_half_life, now);
            let result = f(entry);
            (result, ticks)
        };
        self.record_decay(peer, ticks);
        result
    }
    fn score(&mut self, peer: &PeerId, now: std::time::Instant) -> i64 {
        let score = self.with_entry(peer, now, |entry| entry.score);
        self.record_score(peer, score);
        score
    }
    fn penalize(
        &mut self,
        peer: &PeerId,
        kind: TrustPenaltyKind,
        reason_label: &str,
        now: std::time::Instant,
    ) -> i64 {
        let penalty = kind.amount(&self.penalties);
        let score = self.with_entry(peer, now, |entry| {
            entry.score = entry.score.saturating_sub(penalty);
            entry.score
        });
        self.record_score(peer, score);
        self.record_penalty(reason_label);
        score
    }
    fn min_score(&self) -> i64 {
        self.min_score
    }
    fn should_drop(&mut self, peer: &PeerId, now: std::time::Instant) -> bool {
        self.score(peer, now) <= self.min_score
    }
    fn record_score(&self, peer: &PeerId, score: i64) {
        let _ = self;
        if let Some(metrics) = iroha_telemetry::metrics::global() {
            let peer_label = peer.to_string();
            metrics
                .p2p_trust_score
                .with_label_values(&[peer_label.as_str()])
                .set(score);
        }
    }
    fn record_decay(&self, peer: &PeerId, ticks: u64) {
        if ticks == 0 {
            return;
        }
        let _ = self;
        if let Some(metrics) = iroha_telemetry::metrics::global() {
            let peer_label = peer.to_string();
            metrics
                .p2p_trust_decay_ticks_total
                .with_label_values(&[peer_label.as_str()])
                .inc_by(ticks);
        }
    }
    fn record_penalty(&self, reason: &str) {
        let _ = self;
        if let Some(metrics) = iroha_telemetry::metrics::global() {
            metrics
                .p2p_trust_penalties_total
                .with_label_values(&[reason])
                .inc();
        }
    }
}
/// [`PeersGossiper`] actor handle.
#[derive(Debug)]
enum GossipEvent {
    Peers(crate::retained_gossip::RetainedGossip<(PeersGossip, Peer)>),
    Trust(crate::retained_gossip::RetainedGossip<(PeerTrustGossip, Peer)>),
}
/// Handle to interact with the peers gossiper actor.
#[derive(Clone)]
pub struct PeersGossiperHandle {
    message_sender: mpsc::Sender<GossipEvent>,
    update_topology_sender: mpsc::UnboundedSender<UpdateTopology>,
}
impl PeersGossiperHandle {
    /// Send [`PeersGossip`] to actor.
    ///
    /// Messages are best-effort: if the queue is full, the gossip is dropped
    /// to avoid blocking consensus traffic.
    pub fn gossip(&self, gossip: crate::retained_gossip::RetainedGossip<(PeersGossip, Peer)>) {
        let peer_id = gossip.payload().1.id().clone();
        match self.message_sender.try_send(GossipEvent::Peers(gossip)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                iroha_logger::debug!(
                    peer = %peer_id,
                    "peers gossiper queue full; dropping peers gossip message"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                iroha_logger::warn!(
                    peer = %peer_id,
                    "peers gossiper channel closed; dropping peers gossip message"
                );
            }
        }
    }
    /// Send signed trust gossip to actor.
    ///
    /// Messages are best-effort: if the queue is full, the gossip is dropped
    /// to avoid blocking consensus traffic.
    pub fn gossip_trust(
        &self,
        gossip: crate::retained_gossip::RetainedGossip<(PeerTrustGossip, Peer)>,
    ) {
        let peer_id = gossip.payload().1.id().clone();
        match self.message_sender.try_send(GossipEvent::Trust(gossip)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                iroha_logger::debug!(
                    peer = %peer_id,
                    "peers gossiper queue full; dropping trust gossip message"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                iroha_logger::warn!(
                    peer = %peer_id,
                    "peers gossiper channel closed; dropping trust gossip message"
                );
            }
        }
    }
    /// Send the complete active validator roster to the gossiper actor.
    ///
    /// The roster includes this node exactly when it is an active validator;
    /// observers must not be inserted merely because they run the actor.
    pub fn update_topology(&self, topology: UpdateTopology) {
        if let Err(err) = self.update_topology_sender.send(topology) {
            iroha_logger::warn!(?err, "Peers gossiper dropped topology update");
        }
    }
    /// Build a handle that drops all gossip messages, for unit tests that do not need a live
    /// gossiper task.
    #[cfg(test)]
    pub(crate) fn closed_for_tests() -> Self {
        let (message_sender, message_receiver) = mpsc::channel(1);
        drop(message_receiver);
        let (update_topology_sender, update_topology_receiver) = mpsc::unbounded_channel();
        drop(update_topology_receiver);
        Self {
            message_sender,
            update_topology_sender,
        }
    }
}
/// Actor which gossips peers addresses.
pub struct PeersGossiper {
    /// Id of the current peer
    peer_id: PeerId,
    /// Exact genesis-derived identity of the network whose trust records are accepted.
    network_id: NetworkId,
    /// Peers provided at startup
    initial_peers: BTreeMap<PeerId, SocketAddr>,
    /// Consensus mode to decide observer admission policy.
    consensus_mode: iroha_data_model::block::consensus::ConsensusMode,
    /// Trusted peers configured locally
    trusted_peers: BTreeSet<PeerId>,
    /// Configured peers that stay trusted even if topology excludes them (e.g., observers).
    static_trusted_peers: BTreeSet<PeerId>,
    /// Configured validator identities eligible for pairwise dial ownership.
    /// Dynamic/gossiped identities and configured observers never enter this set.
    configured_validator_peers: BTreeSet<PeerId>,
    /// Peers we can re-promote once trust decays above the floor.
    trust_candidates: BTreeSet<PeerId>,
    /// Peers received via gossiping from other peers First-level key corresponds to `SocketAddr`
    /// Second-level key - peer from which such `SocketAddr` was received
    gossip_peers: BTreeMap<PeerId, BTreeMap<PeerId, SocketAddr>>,
    /// Transport capabilities known for peers in topology.
    peer_capabilities: BTreeMap<PeerId, PeerTransportCapabilities>,
    /// Consensus validators whose matching reports can authorize a gossiped dial address.
    validator_topology: BTreeSet<PeerId>,
    current_topology: BTreeSet<PeerId>,
    key_pair: KeyPair,
    gossip_period: Duration,
    gossip_max_period: Duration,
    gossip_backoff: Duration,
    gossip_next_deadline: std::time::Instant,
    gossip_pending: bool,
    last_gossip_fingerprint: Option<Vec<u8>>,
    last_drop_count: u64,
    last_drop_at: Option<std::time::Instant>,
    trust: TrustBook,
    network: IrohaNetwork,
}
struct TrustGossipOutcome {
    newly_trusted: BTreeSet<PeerId>,
    drop_sender: bool,
}
/// Terminology:
/// * Topology - public keys of current network derived from blockchain (Register/Unregister Peer Isi)
/// * Peers addresses - currently known addresses for peers in topology. Might be unknown for some peer.
///
/// There are two authoritative sources of peer addresses:
/// 1. The startup peer configuration.
/// 2. A matching address claim from at least `f + 1` distinct active validators
///    in the exact `3f + 1` roster.
///
/// Honest gossip republishes only operator-provided mappings. A peer's
/// self-asserted handshake address is not an address authority.
impl PeersGossiper {
    /// Determine the gossip interval using the configured value.
    fn gossip_interval(configured: Duration) -> Duration {
        configured
    }
    fn next_gossip_backoff(
        current: Duration,
        min: Duration,
        max: Duration,
        had_pending: bool,
    ) -> Duration {
        if had_pending {
            return min;
        }
        current.saturating_mul(2).min(max)
    }
    fn note_gossip_change(&mut self, now: std::time::Instant) {
        self.gossip_pending = true;
        self.gossip_backoff = self.gossip_period;
        let next = now.checked_add(self.gossip_period).unwrap_or(now);
        if next < self.gossip_next_deadline {
            self.gossip_next_deadline = next;
        }
    }
    fn drop_backpressure_active(&mut self, now: std::time::Instant) -> bool {
        let current = iroha_p2p::network::subscriber_queue_full_count();
        if current > self.last_drop_count {
            self.last_drop_count = current;
            self.last_drop_at = Some(now);
        }
        self.last_drop_at
            .is_some_and(|last| now.saturating_duration_since(last) < self.gossip_backoff)
    }
    fn maybe_gossip(&mut self, now: std::time::Instant) {
        if now < self.gossip_next_deadline {
            return;
        }
        if self.drop_backpressure_active(now) {
            self.gossip_next_deadline = now.checked_add(self.gossip_backoff).unwrap_or(now);
            iroha_logger::trace!(
                drops = self.last_drop_count,
                cooldown_ms = self.gossip_backoff.as_millis(),
                "peers gossiper skipping gossip due to relay backpressure"
            );
            return;
        }
        let sent_gossip = self.gossip_peers();
        self.network_update_peers_addresses();
        let had_pending = self.gossip_pending && sent_gossip;
        self.gossip_pending = false;
        self.gossip_backoff = Self::next_gossip_backoff(
            self.gossip_backoff,
            self.gossip_period,
            self.gossip_max_period,
            had_pending,
        );
        self.gossip_next_deadline = now.checked_add(self.gossip_backoff).unwrap_or(now);
    }
    /// Start actor.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        peer_id: PeerId,
        network_id: NetworkId,
        trusted_peers: TrustedPeers,
        mut configured_validator_peers: BTreeSet<PeerId>,
        key_pair: KeyPair,
        gossip_period: Duration,
        gossip_max_period: Duration,
        consensus_mode: iroha_data_model::block::consensus::ConsensusMode,
        trust_decay_half_life: Duration,
        trust_penalty_bad_gossip: i32,
        trust_penalty_unknown_peer: i32,
        trust_min_score: i32,
        network: IrohaNetwork,
        shutdown_signal: ShutdownSignal,
    ) -> (PeersGossiperHandle, Child) {
        let trusted_list = trusted_peers.others;
        let initial_peers = trusted_list
            .iter()
            .map(|peer| (peer.id().clone(), peer.address().clone()))
            .collect();
        let mut trusted_set: BTreeSet<_> =
            trusted_list.iter().map(|peer| peer.id().clone()).collect();
        trusted_set.insert(peer_id.clone());
        let static_trusted_peers = trusted_set.clone();
        configured_validator_peers.retain(|peer_id| static_trusted_peers.contains(peer_id));
        let validator_topology =
            Self::validator_reporter_topology(configured_validator_peers.iter().cloned());
        let initial_topology: BTreeSet<_> = trusted_set.clone();
        let trust_candidates = trusted_set.clone();
        let gossip_max_period = gossip_max_period.max(gossip_period);
        let now = std::time::Instant::now();
        let mut gossiper = Self {
            peer_id,
            network_id,
            initial_peers,
            consensus_mode,
            trusted_peers: trusted_set,
            static_trusted_peers,
            configured_validator_peers,
            trust_candidates,
            gossip_peers: BTreeMap::new(),
            peer_capabilities: BTreeMap::new(),
            validator_topology,
            current_topology: initial_topology.clone(),
            key_pair,
            gossip_period,
            gossip_max_period,
            gossip_backoff: gossip_period,
            gossip_next_deadline: now,
            gossip_pending: true,
            last_gossip_fingerprint: None,
            last_drop_count: iroha_p2p::network::subscriber_queue_full_count(),
            last_drop_at: None,
            trust: TrustBook::new(
                trust_decay_half_life,
                TrustPenalties {
                    bad_gossip: i64::from(trust_penalty_bad_gossip),
                    unknown_peer: i64::from(trust_penalty_unknown_peer),
                },
                trust_min_score,
            ),
            network,
        };
        // Seed consensus membership and pairwise dial ownership as one actor
        // transition so startup cannot expose validators as eager dynamic peers.
        gossiper
            .network
            .update_validator_topology(UpdateValidatorTopology {
                topology: initial_topology.iter().cloned().collect(),
                validator_dial_roster: gossiper
                    .configured_validator_peers
                    .iter()
                    .cloned()
                    .collect(),
            });
        gossiper
            .trust
            .seed(gossiper.trusted_peers.clone(), std::time::Instant::now());
        let _ = gossiper.refresh_online_peer_capabilities();
        gossiper.network_update_peers_addresses();
        gossiper.network_update_peer_capabilities();
        gossiper.update_trusted_peers_on_network();
        let (message_sender, message_receiver) = mpsc::channel(1);
        let (update_topology_sender, update_topology_receiver) = mpsc::unbounded_channel();
        (
            PeersGossiperHandle {
                message_sender,
                update_topology_sender,
            },
            Child::new(
                tokio::task::spawn(gossiper.run(
                    message_receiver,
                    update_topology_receiver,
                    shutdown_signal,
                )),
                OnShutdown::Abort,
            ),
        )
    }
    async fn run(
        mut self,
        mut message_receiver: mpsc::Receiver<GossipEvent>,
        mut update_topology_receiver: mpsc::UnboundedReceiver<UpdateTopology>,
        shutdown_signal: ShutdownSignal,
    ) {
        let mut gossip_period = tokio::time::interval(Self::gossip_interval(self.gossip_period));
        loop {
            let should_check_gossip = tokio::select! {
                Some(update_topology) = update_topology_receiver.recv() => {
                    let changed = self.set_current_topology(update_topology);
                    if changed {
                        self.note_gossip_change(std::time::Instant::now());
                    }
                    true
                }
                _ = gossip_period.tick() => {
                    true
                }
                result = self.network.wait_online_peers_update(|_| ()) => {
                    match result {
                        Ok(()) => {
                            self.network_update_peers_addresses();
                            self.note_gossip_change(std::time::Instant::now());
                            true
                        }
                        Err(err) => {
                            iroha_logger::debug!(?err, "Network online peers channel closed");
                            break;
                        }
                    }
                }
                Some(event) = message_receiver.recv() => {
                    match event {
                        GossipEvent::Peers(message) => message.with_payload(|(gossip, from)| {
                            if self.handle_peers_gossip(gossip, &from) {
                                self.note_gossip_change(std::time::Instant::now());
                            }
                        }),
                        GossipEvent::Trust(message) => message.with_payload(|(gossip, from)| {
                            if self.handle_trust_gossip(gossip, &from) {
                                self.note_gossip_change(std::time::Instant::now());
                            }
                        }),
                    }
                    true
                }
                () = shutdown_signal.receive() => {
                    iroha_logger::debug!("Shutting down peers gossiper");
                    break;
                },
            };
            if should_check_gossip {
                self.maybe_gossip(std::time::Instant::now());
            }
            tokio::task::yield_now().await;
        }
    }
    fn set_current_topology(&mut self, UpdateTopology(topology): UpdateTopology) -> bool {
        let force_disconnect = topology.is_empty();
        // `UpdateTopology` is the authoritative complete validator roster.
        // Do not infer local membership from the immutable startup set: a
        // demoted validator and a newly promoted validator must both use the
        // current roster's exact 3f + 1 geometry.
        let validator_topology = Self::validator_reporter_topology(topology.iter().cloned());
        let validator_dial_roster: HashSet<_> = topology
            .iter()
            .filter(|peer_id| self.configured_validator_peers.contains(*peer_id))
            .cloned()
            .collect();
        let mut new_topology: BTreeSet<_> = topology.into_iter().collect();
        if !force_disconnect {
            new_topology.extend(self.static_trusted_peers.iter().cloned());
        }
        Self::retain_authorized_address_votes(
            &mut self.gossip_peers,
            &new_topology,
            &validator_topology,
        );
        let removed: Vec<_> = self
            .current_topology
            .difference(&new_topology)
            .cloned()
            .collect();
        let added: Vec<_> = new_topology
            .difference(&self.current_topology)
            .cloned()
            .collect();
        let unchanged = new_topology == self.current_topology;
        let mut trust_changed = false;
        if force_disconnect {
            trust_changed |= !self.trusted_peers.is_empty()
                || !self.trust_candidates.is_empty()
                || !self.trust.entries.is_empty();
            self.trusted_peers.clear();
            self.trust_candidates.clear();
            self.trust.entries.clear();
        } else {
            for peer in removed {
                if self.static_trusted_peers.contains(&peer) {
                    continue;
                }
                trust_changed |= self.trusted_peers.remove(&peer);
                self.trust_candidates.remove(&peer);
                self.trust.entries.remove(&peer);
            }
            if !added.is_empty() {
                let now = std::time::Instant::now();
                self.trust.seed(added.iter().cloned(), now);
                for peer in &added {
                    trust_changed |= self.trusted_peers.insert(peer.clone());
                    self.trust_candidates.insert(peer.clone());
                }
            }
        }
        if trust_changed {
            self.update_trusted_peers_on_network();
        }
        self.validator_topology = validator_topology;
        self.current_topology.clone_from(&new_topology);
        let mut capabilities_changed = false;
        self.peer_capabilities.retain(|peer_id, _| {
            let keep = *peer_id != self.peer_id && self.current_topology.contains(peer_id);
            if !keep {
                capabilities_changed = true;
            }
            keep
        });
        // Keep the network dial set in sync with the current topology so removed peers
        // are disconnected promptly and new peers are contacted.
        self.network
            .update_validator_topology(UpdateValidatorTopology {
                topology: new_topology.iter().cloned().collect(),
                validator_dial_roster,
            });
        self.network_update_peers_addresses();
        if capabilities_changed {
            self.network_update_peer_capabilities();
        }
        if unchanged {
            iroha_logger::debug!(
                topology_len = self.current_topology.len(),
                "received unchanged topology; re-advertising to enforce dial set"
            );
        }
        !unchanged || capabilities_changed
    }
    fn retain_authorized_address_votes(
        gossip_peers: &mut BTreeMap<PeerId, BTreeMap<PeerId, SocketAddr>>,
        current_topology: &BTreeSet<PeerId>,
        validator_topology: &BTreeSet<PeerId>,
    ) {
        gossip_peers.retain(|peer, map| {
            if !current_topology.contains(peer) {
                return false;
            }
            map.retain(|reporter, _| validator_topology.contains(reporter));
            !map.is_empty()
        });
    }
    fn sorted_online_peers<I>(peers: I) -> UniqueVec<Peer>
    where
        I: IntoIterator<Item = Peer>,
    {
        let mut peers: Vec<_> = peers.into_iter().collect();
        peers.sort();
        UniqueVec::from_iter(peers)
    }
    fn validator_reporter_topology<I>(topology: I) -> BTreeSet<PeerId>
    where
        I: IntoIterator<Item = PeerId>,
    {
        topology.into_iter().collect()
    }
    fn locally_configured_online_peers<I>(
        peers: I,
        initial_peers: &BTreeMap<PeerId, SocketAddr>,
    ) -> Vec<Peer>
    where
        I: IntoIterator<Item = Peer>,
    {
        peers
            .into_iter()
            .filter_map(|peer| {
                initial_peers
                    .get(peer.id())
                    .map(|address| Peer::new(address.clone(), peer.id().public_key().clone()))
            })
            .collect()
    }
    fn gossip_fingerprint(
        peers: &UniqueVec<Peer>,
        peer_capabilities: &BTreeMap<PeerId, PeerTransportCapabilities>,
        trust_infos: &[PeerTrustInfo],
    ) -> Vec<u8> {
        let mut fingerprint = Vec::from(b"iroha-peer-gossip-v1".as_slice());
        fingerprint.extend_from_slice(
            &u64::try_from(peers.iter().count())
                .unwrap_or(u64::MAX)
                .encode(),
        );
        for peer in peers {
            fingerprint.extend_from_slice(&peer.encode());
        }
        fingerprint.extend_from_slice(
            &u64::try_from(peer_capabilities.len())
                .unwrap_or(u64::MAX)
                .encode(),
        );
        for (peer_id, capabilities) in peer_capabilities {
            fingerprint.extend_from_slice(&peer_id.encode());
            fingerprint.extend_from_slice(&capabilities.encode());
        }
        fingerprint.extend_from_slice(
            &u64::try_from(trust_infos.len())
                .unwrap_or(u64::MAX)
                .encode(),
        );
        for info in trust_infos {
            fingerprint.extend_from_slice(&info.peer_id.encode());
            fingerprint.extend_from_slice(&info.trusted.encode());
            fingerprint.extend_from_slice(&info.score.encode());
        }
        fingerprint
    }
    fn gossip_peers(&mut self) -> bool {
        let online_peers = self.network.online_peers(Clone::clone);
        if self.refresh_online_peer_capabilities() {
            self.network_update_peer_capabilities();
        }
        // Only operator-provided addresses are third-party gossip authority.
        // A peer's signed handshake address is still self-asserted: echoing it
        // through honest validators would make one Byzantine peer appear to
        // have independent address endorsements.
        let online_peers = Self::locally_configured_online_peers(online_peers, &self.initial_peers);
        let online_peers = Self::sorted_online_peers(online_peers);
        let now = std::time::Instant::now();
        let trust_infos = self.trust_infos(now);
        let fingerprint =
            Self::gossip_fingerprint(&online_peers, &self.peer_capabilities, &trust_infos);
        if self.last_gossip_fingerprint.as_ref() == Some(&fingerprint) {
            iroha_logger::trace!("peers gossiper skipping unchanged gossip payload");
            return false;
        }
        self.last_gossip_fingerprint = Some(fingerprint);
        let peers_msg = NetworkMessage::PeersGossiper(Box::new(PeersGossip {
            peers: online_peers,
            peer_capabilities: self.peer_capabilities.clone(),
        }));
        self.network.broadcast(Broadcast {
            data: peers_msg,
            priority: iroha_p2p::Priority::Low,
        });
        let trust = self.sign_trust_entries(&trust_infos);
        if !trust.is_empty() {
            let trust_msg = NetworkMessage::PeerTrustGossip(Box::new(PeerTrustGossip {
                network_id: self.network_id,
                trust,
            }));
            self.network.broadcast(Broadcast {
                data: trust_msg,
                priority: iroha_p2p::Priority::Low,
            });
        }
        true
    }
    fn trust_payload(network_id: &NetworkId, info: &PeerTrustInfo) -> Vec<u8> {
        let mut payload = Vec::from(b"iroha-peer-trust:v2\0".as_slice());
        payload.extend_from_slice(network_id.as_bytes());
        payload.extend_from_slice(&info.peer_id.encode());
        payload.extend_from_slice(&info.trusted.encode());
        payload.extend_from_slice(&info.score.encode());
        payload
    }
    fn trust_infos(&mut self, now: std::time::Instant) -> Vec<PeerTrustInfo> {
        self.trusted_peers
            .iter()
            .map(|peer_id| {
                let score = self.trust.score(peer_id, now);
                let clamped = i32::try_from(score.clamp(i64::from(i32::MIN), i64::from(i32::MAX)))
                    .expect("clamped trust score must fit in i32");
                PeerTrustInfo {
                    peer_id: peer_id.clone(),
                    trusted: score > self.trust.min_score,
                    score: clamped,
                }
            })
            .collect()
    }
    fn sign_trust_entries(&self, infos: &[PeerTrustInfo]) -> Vec<SignedPeerTrust> {
        infos
            .iter()
            .cloned()
            .filter_map(|info| {
                let payload = Self::trust_payload(&self.network_id, &info);
                match Signature::try_new(self.key_pair.private_key(), &payload) {
                    Ok(signature) => Some(SignedPeerTrust {
                        info,
                        signature: signature.payload().to_vec(),
                    }),
                    Err(err) => {
                        iroha_logger::warn!(
                            peer=%info.peer_id,
                            ?err,
                            "Skipping peer trust gossip entry after signing failure"
                        );
                        None
                    }
                }
            })
            .collect()
    }
    fn evict_if_low_trust(&mut self, peer_id: &PeerId, now: std::time::Instant) -> bool {
        if self.trust.should_drop(peer_id, now) {
            if self.trusted_peers.remove(peer_id) {
                self.update_trusted_peers_on_network();
            }
            iroha_logger::warn!(peer=%peer_id, "Dropping gossip from low-trust peer");
            true
        } else {
            false
        }
    }
    fn restore_if_recovered(&mut self, peer_id: &PeerId, now: std::time::Instant) {
        if self.trust_candidates.contains(peer_id)
            && !self.trusted_peers.contains(peer_id)
            && self.trust.score(peer_id, now) > self.trust.min_score
        {
            iroha_logger::debug!(peer=%peer_id, "Reinstating peer after trust decay recovery");
            self.trusted_peers.insert(peer_id.clone());
            self.update_trusted_peers_on_network();
        }
    }
    fn handle_peers_gossip(
        &mut self,
        PeersGossip {
            peers,
            peer_capabilities,
        }: PeersGossip,
        from_peer: &Peer,
    ) -> bool {
        if !Self::is_authorized_peer_gossip_sender(
            from_peer.id(),
            &self.current_topology,
            &self.static_trusted_peers,
        ) {
            return false;
        }
        let now = std::time::Instant::now();
        if self.evict_if_low_trust(from_peer.id(), now) {
            return false;
        }
        self.restore_if_recovered(from_peer.id(), now);
        let mut addresses_changed = false;
        let mut capabilities_changed = false;
        let can_report_addresses =
            Self::is_authorized_address_reporter(from_peer.id(), &self.validator_topology);
        for peer in peers {
            let peer_allowed =
                self.current_topology.contains(peer.id()) || self.trusted_peers.contains(peer.id());
            if !can_report_addresses || !peer_allowed {
                // Only active validators can vote on addresses, and only for
                // peers in the active topology.
                continue;
            }
            let map = self.gossip_peers.entry(peer.id().clone()).or_default();
            let address = peer.address().clone();
            let previous = map.insert(from_peer.id().clone(), address.clone());
            if previous.as_ref() != Some(&address) {
                addresses_changed = true;
            }
        }
        for (peer_id, capabilities) in peer_capabilities {
            if !Self::is_authorized_capability_reporter(from_peer.id(), &peer_id) {
                // Third-party capability hints are not scheduling authority.
                // They are not signed by the subject and otherwise let one
                // reporter force an extra preferred-transport dial attempt.
                continue;
            }
            let peer_allowed =
                self.current_topology.contains(&peer_id) || self.trusted_peers.contains(&peer_id);
            if !peer_allowed || peer_id == self.peer_id {
                continue;
            }
            if self.peer_capabilities.insert(peer_id, capabilities) != Some(capabilities) {
                capabilities_changed = true;
            }
        }
        if addresses_changed {
            self.network_update_peers_addresses();
        }
        if capabilities_changed {
            self.network_update_peer_capabilities();
        }
        addresses_changed || capabilities_changed
    }
    fn is_authorized_peer_gossip_sender(
        reporter: &PeerId,
        current_topology: &BTreeSet<PeerId>,
        static_trusted_peers: &BTreeSet<PeerId>,
    ) -> bool {
        // Runtime trust gossip cannot promote a public observer into a peer
        // metadata authority. Locally configured peers may still contribute
        // capability metadata, while address votes are restricted below.
        current_topology.contains(reporter) || static_trusted_peers.contains(reporter)
    }
    fn is_authorized_address_reporter(
        reporter: &PeerId,
        validator_topology: &BTreeSet<PeerId>,
    ) -> bool {
        validator_topology.contains(reporter)
    }
    fn is_authorized_capability_reporter(reporter: &PeerId, subject: &PeerId) -> bool {
        reporter == subject
    }
    fn handle_trust_gossip(
        &mut self,
        PeerTrustGossip { network_id, trust }: PeerTrustGossip,
        from_peer: &Peer,
    ) -> bool {
        if network_id != self.network_id {
            iroha_logger::warn!(
                peer = %from_peer,
                expected_network_id = %self.network_id,
                actual_network_id = %network_id,
                "Rejected peer trust gossip from a foreign network"
            );
            return false;
        }
        let allow_public = matches!(
            self.consensus_mode,
            iroha_data_model::block::consensus::ConsensusMode::Npos
        );
        if !self.trusted_peers.contains(from_peer.id())
            && !allow_public
            && !self.current_topology.contains(from_peer.id())
        {
            return false;
        }
        let now = std::time::Instant::now();
        if self.evict_if_low_trust(from_peer.id(), now) {
            return false;
        }
        self.restore_if_recovered(from_peer.id(), now);
        let outcome = process_trust_records(
            &self.network_id,
            trust,
            from_peer,
            allow_public,
            &self.current_topology,
            &self.trusted_peers,
            &mut self.trust,
            now,
        );
        if outcome.drop_sender && self.evict_if_low_trust(from_peer.id(), now) {
            return false;
        }
        let newly_trusted = outcome.newly_trusted;
        let trust_changed = !newly_trusted.is_empty();
        if trust_changed {
            self.trusted_peers.extend(newly_trusted.iter().cloned());
            self.trust_candidates.extend(newly_trusted);
        }
        if trust_changed {
            self.update_trusted_peers_on_network();
        }
        trust_changed
    }
    fn selected_peer_addresses(
        initial_peers: &BTreeMap<PeerId, SocketAddr>,
        gossip_peers: &BTreeMap<PeerId, BTreeMap<PeerId, SocketAddr>>,
        validator_count: usize,
    ) -> BTreeMap<PeerId, SocketAddr> {
        let mut peers = initial_peers.clone();
        if let Some(required_reports) = required_address_reports(validator_count) {
            for (id, addresses) in gossip_peers {
                if peers.contains_key(id) {
                    continue;
                }
                if let Some(address) = choose_address_with_quorum(addresses, required_reports) {
                    peers.insert(id.clone(), address);
                }
            }
        }
        peers
    }
    fn network_update_peers_addresses(&self) {
        let peers = Self::selected_peer_addresses(
            &self.initial_peers,
            &self.gossip_peers,
            self.validator_topology.len(),
        );
        // Always send the full set of known addresses; the network layer will
        // avoid redundant dials to already-connected peers.
        let update = UpdatePeers(
            peers
                .into_iter()
                .filter(|(id, _)| id != &self.peer_id && self.current_topology.contains(id))
                .collect(),
        );
        self.network.update_peers_addresses(update);
    }
    fn refresh_online_peer_capabilities(&mut self) -> bool {
        let observed = self.network.online_peer_capabilities(Clone::clone);
        let mut changed = false;
        for (peer_id, capabilities) in observed {
            if peer_id == self.peer_id || !self.current_topology.contains(&peer_id) {
                continue;
            }
            if self.peer_capabilities.insert(peer_id, capabilities) != Some(capabilities) {
                changed = true;
            }
        }
        changed
    }
    fn network_update_peer_capabilities(&self) {
        let update = UpdatePeerCapabilities(
            self.peer_capabilities
                .iter()
                .filter(|(peer_id, _)| {
                    *peer_id != &self.peer_id && self.current_topology.contains(*peer_id)
                })
                .map(|(peer_id, capabilities)| (peer_id.clone(), *capabilities))
                .collect(),
        );
        self.network.update_peer_capabilities(update);
    }
    fn update_trusted_peers_on_network(&self) {
        self.network.update_trusted_peers(UpdateTrustedPeers(
            self.trusted_peers.clone().into_iter().collect(),
        ));
    }
}
fn process_trust_records(
    network_id: &NetworkId,
    trust: Vec<SignedPeerTrust>,
    from_peer: &Peer,
    allow_public: bool,
    current_topology: &BTreeSet<PeerId>,
    trusted_peers: &BTreeSet<PeerId>,
    trust_book: &mut TrustBook,
    now: std::time::Instant,
) -> TrustGossipOutcome {
    let mut newly_trusted = BTreeSet::new();
    for SignedPeerTrust { info, signature } in trust {
        let payload = PeersGossiper::trust_payload(network_id, &info);
        let signature = match from_peer.id().public_key().try_algorithm() {
            Ok(iroha_crypto::Algorithm::Ed25519) => {
                iroha_crypto::ed25519_parse_signature(&signature).ok()
            }
            Ok(iroha_crypto::Algorithm::MlDsa) => {
                iroha_crypto::mldsa65_parse_signature(&signature).ok()
            }
            _ => Signature::try_from_bytes(&signature).ok(),
        };
        let invalid_signature =
            signature.is_none_or(|sig| sig.verify(from_peer.id().public_key(), &payload).is_err());
        if invalid_signature {
            iroha_logger::warn!(peer=%from_peer, "Rejected trust gossip with invalid signature");
            let score = trust_book.penalize(
                from_peer.id(),
                TrustPenaltyKind::BadGossip,
                PENALTY_REASON_INVALID_SIGNATURE,
                now,
            );
            if score <= trust_book.min_score() {
                return TrustGossipOutcome {
                    newly_trusted,
                    drop_sender: true,
                };
            }
            continue;
        }
        let sender_trusted =
            trusted_peers.contains(from_peer.id()) || current_topology.contains(from_peer.id());
        let allow_trusted_introduction = sender_trusted && info.trusted;
        let peer_allowed = current_topology.contains(&info.peer_id)
            || allow_public
            || trusted_peers.contains(&info.peer_id)
            || allow_trusted_introduction;
        if !peer_allowed {
            if !allow_public {
                iroha_logger::warn!(
                    peer=%from_peer,
                    advertised_peer=%info.peer_id,
                    "Penalizing trust gossip about peer outside the active topology"
                );
                let score = trust_book.penalize(
                    from_peer.id(),
                    TrustPenaltyKind::UnknownPeer,
                    PENALTY_REASON_UNKNOWN_PEER,
                    now,
                );
                if score <= trust_book.min_score() {
                    return TrustGossipOutcome {
                        newly_trusted,
                        drop_sender: true,
                    };
                }
            }
            continue;
        }
        if info.trusted {
            newly_trusted.insert(info.peer_id.clone());
        }
    }
    TrustGossipOutcome {
        newly_trusted,
        drop_sender: false,
    }
}
fn required_address_reports(validator_count: usize) -> Option<usize> {
    (validator_count > 0 && validator_count % 3 == 1)
        .then_some(validator_count.saturating_sub(1) / 3 + 1)
}
fn choose_address_with_quorum(
    addresses: &BTreeMap<PeerId, SocketAddr>,
    required_reports: usize,
) -> Option<SocketAddr> {
    let mut count_map = BTreeMap::new();
    for address in addresses.values() {
        *count_map.entry(address).or_insert(0) += 1;
    }
    let max_count = count_map.values().copied().max()?;
    if max_count < required_reports
        || count_map
            .values()
            .filter(|count| **count == max_count)
            .count()
            != 1
    {
        return None;
    }
    count_map
        .into_iter()
        .find_map(|(address, count)| (count == max_count).then(|| address.clone()))
}
/// Message for gossiping peers addresses.
#[derive(Debug, Clone, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::peers_gossiper::PeersGossip")]
pub struct PeersGossip {
    /// Peers known to the sender, deduplicated but encoded in insertion order.
    pub peers: UniqueVec<Peer>,
    /// Transport capabilities known to the sender keyed by peer id.
    pub peer_capabilities: BTreeMap<PeerId, PeerTransportCapabilities>,
}
/// Wire representation for peers gossip.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::peers_gossiper::PeersGossipWire")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize)]
struct PeersGossipWire {
    peers: Vec<Peer>,
    peer_capabilities: BTreeMap<PeerId, PeerTransportCapabilities>,
}
/// Signed trust gossip payload.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::peers_gossiper::PeerTrustGossip")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize)]
pub struct PeerTrustGossip {
    /// Exact genesis-derived network identity bound by every enclosed signature.
    pub network_id: NetworkId,
    /// Signed trust reports emitted by the sender.
    pub trust: Vec<SignedPeerTrust>,
}
/// Trust information about a peer as reported by the sender.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::peers_gossiper::PeerTrustInfo")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize)]
pub struct PeerTrustInfo {
    /// Id of the peer the trust info is about.
    pub peer_id: PeerId,
    /// Whether the sender currently considers the peer trusted.
    pub trusted: bool,
    /// Trust score recorded by the sender.
    pub score: i32,
}
/// Trust report bundled with a signature from the sender.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::peers_gossiper::SignedPeerTrust")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize)]
pub struct SignedPeerTrust {
    /// Reported trust values.
    pub info: PeerTrustInfo,
    /// Signature proving authenticity of the trust record.
    pub signature: Vec<u8>,
}
impl SerializePayload for PeersGossip {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
        // Serialize peers as Vec to preserve insertion order.
        let wire = PeersGossipWire {
            peers: self.peers.iter().map(Clone::clone).collect(),
            peer_capabilities: self.peer_capabilities.clone(),
        };
        wire.serialize(writer)
    }
}
impl<'a> DeserializePayload<'a> for PeersGossip {
    fn deserialize(archived: &'a ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("PeersGossip decode")
    }
    fn try_deserialize(archived: &'a ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(ptr)?;
        if let Ok((wire, consumed)) = ncore::decode_field_canonical::<PeersGossipWire>(bytes) {
            if consumed == bytes.len() {
                return Ok(Self {
                    peers: UniqueVec::from_iter(wire.peers),
                    peer_capabilities: wire.peer_capabilities,
                });
            }
        }
        let (peers, consumed) = ncore::decode_field_canonical::<Vec<Peer>>(bytes)?;
        if consumed != bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        Ok(Self {
            peers: UniqueVec::from_iter(peers),
            peer_capabilities: BTreeMap::new(),
        })
    }
}
impl<'a> ncore::DecodeFromSlice<'a> for PeersGossip {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        if let Ok((wire, used)) = ncore::decode_field_canonical::<PeersGossipWire>(bytes) {
            return Ok((
                Self {
                    peers: UniqueVec::from_iter(wire.peers),
                    peer_capabilities: wire.peer_capabilities,
                },
                used,
            ));
        }
        let (peers, used) = <Vec<Peer> as ncore::DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok((
            Self {
                peers: UniqueVec::from_iter(peers),
                peer_capabilities: BTreeMap::new(),
            },
            used,
        ))
    }
}
impl<'a> ncore::DecodeFromSlice<'a> for PeerTrustGossip {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        ncore::decode_field_canonical(bytes)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::{
        base::WithOrigin,
        parameters::actual::{
            LaneProfile, Network as NetworkConfig, RelayMode, SoranetHandshake, SoranetPrivacy,
            SoranetVpn, TrustedPeers as TrustedPeersConfig,
        },
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::block::{BlockHeader, consensus::ConsensusMode};
    use std::{
        collections::{BTreeMap, BTreeSet, HashSet},
        time::Instant,
    };
    fn test_network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([seed; Hash::LENGTH]),
        ))
    }
    fn trust_test_network_id() -> NetworkId {
        test_network_id(0x51)
    }
    #[test]
    fn public_observer_is_not_an_address_authority() {
        let validator = PeerId::from(checked_seed_keypair(&[1, 2, 3, 4]).public_key().clone());
        let configured_observer =
            PeerId::from(checked_seed_keypair(&[5, 6, 7, 8]).public_key().clone());
        let public_observer =
            PeerId::from(checked_seed_keypair(&[9, 10, 11, 12]).public_key().clone());
        let topology = BTreeSet::from([validator.clone()]);
        let trusted = BTreeSet::from([configured_observer.clone()]);
        assert!(PeersGossiper::is_authorized_address_reporter(
            &validator, &topology
        ));
        assert!(!PeersGossiper::is_authorized_address_reporter(
            &configured_observer,
            &topology
        ));
        assert!(!PeersGossiper::is_authorized_address_reporter(
            &public_observer,
            &topology
        ));
        assert!(PeersGossiper::is_authorized_peer_gossip_sender(
            &configured_observer,
            &topology,
            &trusted
        ));
        assert!(!PeersGossiper::is_authorized_peer_gossip_sender(
            &public_observer,
            &topology,
            &trusted
        ));
        assert!(PeersGossiper::is_authorized_capability_reporter(
            &validator, &validator
        ));
        assert!(!PeersGossiper::is_authorized_capability_reporter(
            &validator,
            &configured_observer
        ));

        let full_validator_roster: BTreeSet<_> = (20_u8..24)
            .map(|seed| {
                PeerId::from(
                    checked_seed_keypair(&[seed, seed + 1, seed + 2, seed + 3])
                        .public_key()
                        .clone(),
                )
            })
            .collect();
        let reporter_topology =
            PeersGossiper::validator_reporter_topology(full_validator_roster.clone());
        assert_eq!(reporter_topology, full_validator_roster);
        assert!(!reporter_topology.contains(&public_observer));
        assert_eq!(required_address_reports(reporter_topology.len()), Some(2));
    }
    #[test]
    fn address_gossip_requires_f_plus_one_matching_validator_reports() {
        let reporters: Vec<_> = (0_u8..4)
            .map(|seed| {
                PeerId::from(
                    checked_seed_keypair(&[seed, seed + 1, seed + 2, seed + 3])
                        .public_key()
                        .clone(),
                )
            })
            .collect();
        let first: SocketAddr = "192.0.2.10:1337".parse().expect("first address");
        let second: SocketAddr = "192.0.2.11:1337".parse().expect("second address");
        assert_eq!(required_address_reports(4), Some(2));
        assert_eq!(required_address_reports(7), Some(3));
        assert_eq!(required_address_reports(3), None);

        let mut reports = BTreeMap::from([(reporters[0].clone(), first.clone())]);
        assert_eq!(choose_address_with_quorum(&reports, 2), None);
        reports.insert(reporters[1].clone(), first.clone());
        assert_eq!(choose_address_with_quorum(&reports, 2), Some(first.clone()));
        reports.insert(reporters[2].clone(), second.clone());
        reports.insert(reporters[3].clone(), second);
        assert_eq!(
            choose_address_with_quorum(&reports, 2),
            None,
            "conflicting quorum-sized reports must fail closed"
        );
    }
    #[test]
    fn validator_rotation_purges_removed_reporter_address_votes() {
        let validators: Vec<_> = (70_u8..74)
            .map(|seed| {
                PeerId::from(
                    checked_seed_keypair(&[seed, seed + 1, seed + 2, seed + 3])
                        .public_key()
                        .clone(),
                )
            })
            .collect();
        let replacement =
            PeerId::from(checked_seed_keypair(&[80, 81, 82, 83]).public_key().clone());
        let target = validators[3].clone();
        let address: SocketAddr = "192.0.2.44:1337".parse().expect("test address");
        let mut votes = BTreeMap::from([(
            target.clone(),
            BTreeMap::from([
                (validators[0].clone(), address.clone()),
                (validators[1].clone(), address.clone()),
                (validators[2].clone(), address),
            ]),
        )]);
        let rotated = BTreeSet::from([
            validators[0].clone(),
            validators[2].clone(),
            target.clone(),
            replacement,
        ]);

        PeersGossiper::retain_authorized_address_votes(&mut votes, &rotated, &rotated);

        let retained = votes.get(&target).expect("target remains active");
        assert_eq!(retained.len(), 2);
        assert!(!retained.contains_key(&validators[1]));

        let without_target = rotated
            .into_iter()
            .filter(|peer_id| peer_id != &target)
            .collect();
        PeersGossiper::retain_authorized_address_votes(
            &mut votes,
            &without_target,
            &without_target,
        );
        assert!(votes.is_empty());
    }
    #[test]
    fn configured_address_cannot_be_replaced_by_gossip_quorum() {
        let target = PeerId::from(checked_seed_keypair(&[40, 41, 42, 43]).public_key().clone());
        let configured: SocketAddr = "198.51.100.20:1337".parse().expect("configured address");
        let attacker_chosen: SocketAddr = "127.0.0.1:22".parse().expect("gossip address");
        let reporters: Vec<_> = (44_u8..46)
            .map(|seed| {
                PeerId::from(
                    checked_seed_keypair(&[seed, seed + 1, seed + 2, seed + 3])
                        .public_key()
                        .clone(),
                )
            })
            .collect();
        let initial_peers = BTreeMap::from([(target.clone(), configured.clone())]);
        let gossip_peers = BTreeMap::from([(
            target.clone(),
            BTreeMap::from([
                (reporters[0].clone(), attacker_chosen.clone()),
                (reporters[1].clone(), attacker_chosen),
            ]),
        )]);

        let selected = PeersGossiper::selected_peer_addresses(&initial_peers, &gossip_peers, 4);

        assert_eq!(selected.get(&target), Some(&configured));
    }
    #[test]
    fn peer_gossip_never_echoes_a_self_asserted_handshake_address() {
        let configured_key = checked_seed_keypair(&[20, 21, 22, 23]);
        let unknown_key = checked_seed_keypair(&[24, 25, 26, 27]);
        let configured_id = PeerId::from(configured_key.public_key().clone());
        let configured_address: SocketAddr =
            "198.51.100.10:1337".parse().expect("configured address");
        let attacker_chosen_address: SocketAddr =
            "127.0.0.1:22".parse().expect("self-asserted address");
        let initial_peers = BTreeMap::from([(configured_id.clone(), configured_address.clone())]);
        let online = vec![
            Peer::new(
                attacker_chosen_address.clone(),
                configured_key.public_key().clone(),
            ),
            Peer::new(attacker_chosen_address, unknown_key.public_key().clone()),
        ];

        let advertised = PeersGossiper::locally_configured_online_peers(online, &initial_peers);
        assert_eq!(advertised.len(), 1);
        assert_eq!(advertised[0].id(), &configured_id);
        assert_eq!(advertised[0].address(), &configured_address);
    }
    fn signed_trust_payload_for_network(
        signer: &KeyPair,
        network_id: &NetworkId,
        info: &PeerTrustInfo,
    ) -> Vec<u8> {
        Signature::try_new(
            signer.private_key(),
            &PeersGossiper::trust_payload(network_id, info),
        )
        .expect("trust gossip fixture should sign")
        .payload()
        .to_vec()
    }
    fn signed_trust_payload(signer: &KeyPair, info: &PeerTrustInfo) -> Vec<u8> {
        signed_trust_payload_for_network(signer, &trust_test_network_id(), info)
    }
    fn checked_seed_keypair(seed: &[u8]) -> KeyPair {
        KeyPair::try_from_seed(seed.to_vec(), Algorithm::Ed25519)
            .expect("derive checked peers gossiper Ed25519 fixture keypair")
    }
    fn checked_seed_keypair_with_algorithm(seed: &[u8], algorithm: Algorithm) -> KeyPair {
        KeyPair::try_from_seed(seed.to_vec(), algorithm)
            .expect("derive checked peers gossiper fixture keypair")
    }
    fn checked_random_bls_keypair() -> KeyPair {
        KeyPair::try_random_with_algorithm(Algorithm::BlsNormal)
            .expect("generate checked peers gossiper BLS fixture keypair")
    }
    #[test]
    fn captured_original_core_peers_frames() {
        use crate::frame_identity_tests::shapes;
        let kp1 = checked_seed_keypair(&[1, 2, 3, 4]);
        let kp2 = checked_seed_keypair(&[5, 6, 7, 8]);
        let peer1 = Peer::new("127.0.0.1:8080".parse().unwrap(), kp1.public_key().clone());
        let peer2 = Peer::new("127.0.0.1:8081".parse().unwrap(), kp2.public_key().clone());
        let gossip = PeersGossip {
            peers: UniqueVec::from_iter(vec![peer1.clone(), peer2.clone()]),
            peer_capabilities: BTreeMap::from([(
                peer1.id().clone(),
                PeerTransportCapabilities {
                    scion_supported: true,
                },
            )]),
        };
        let bytes = ncore::to_bytes(&gossip).expect("existing populated gossip frame");
        let decoded: PeersGossip =
            norito::decode_from_bytes(&bytes).expect("existing gossip decode");
        assert_eq!(
            decoded.peers.into_iter().collect::<Vec<_>>(),
            vec![peer1.clone(), peer2.clone()]
        );
        assert_eq!(
            decoded.peer_capabilities.get(peer1.id()),
            Some(&PeerTransportCapabilities {
                scion_supported: true
            })
        );
        shapes("peers_gossip", "populated", &gossip);
        shapes(
            "network_message",
            "peers_gossip",
            &crate::NetworkMessage::PeersGossiper(Box::new(gossip)),
        );
        let empty = PeersGossip {
            peers: UniqueVec::new(),
            peer_capabilities: BTreeMap::new(),
        };
        shapes("peers_gossip", "empty", &empty);
    }

    #[test]
    fn peers_gossip_roundtrip() {
        // Use seeded keypairs to produce valid Ed25519 public keys deterministically.
        let kp1 = checked_seed_keypair(&[1, 2, 3, 4]);
        let kp2 = checked_seed_keypair(&[5, 6, 7, 8]);
        let peer1 = Peer::new("127.0.0.1:8080".parse().unwrap(), kp1.public_key().clone());
        let peer2 = Peer::new("127.0.0.1:8081".parse().unwrap(), kp2.public_key().clone());
        let gossip = PeersGossip {
            peers: UniqueVec::from_iter(vec![peer1.clone(), peer2.clone()]),
            peer_capabilities: BTreeMap::from([(
                peer1.id().clone(),
                PeerTransportCapabilities {
                    scion_supported: true,
                },
            )]),
        };
        let bytes = ncore::to_bytes(&gossip).expect("serialize gossip");
        let decoded: PeersGossip = norito::decode_from_bytes(&bytes).expect("decode gossip");
        let decoded_peers: Vec<_> = decoded.peers.into_iter().collect();
        assert_eq!(decoded_peers, vec![peer1.clone(), peer2.clone()]);
        assert_eq!(
            decoded.peer_capabilities.get(peer1.id()),
            Some(&PeerTransportCapabilities {
                scion_supported: true
            })
        );
    }
    #[test]
    fn peer_trust_gossip_roundtrip() {
        let kp = checked_seed_keypair(&[9, 10, 11, 12]);
        let peer = Peer::new("127.0.0.1:8082".parse().unwrap(), kp.public_key().clone());
        let info = PeerTrustInfo {
            peer_id: peer.id().clone(),
            trusted: true,
            score: 2,
        };
        let sig = signed_trust_payload(&kp, &info);
        let gossip = PeerTrustGossip {
            network_id: trust_test_network_id(),
            trust: vec![SignedPeerTrust {
                info: info.clone(),
                signature: sig.clone(),
            }],
        };
        let message = crate::NetworkMessage::PeerTrustGossip(Box::new(gossip));
        let bytes = ncore::to_bytes(&message).expect("serialize network trust gossip frame");
        assert_eq!(
            bytes[6..22],
            norito::schema::identity::frame_hash::<crate::NetworkMessage>()
        );
        let crate::NetworkMessage::PeerTrustGossip(decoded) =
            norito::decode_from_bytes(&bytes).expect("decode network trust gossip frame")
        else {
            panic!("network frame must retain the trust gossip variant");
        };
        assert_eq!(decoded.trust.len(), 1);
        assert_eq!(decoded.network_id, trust_test_network_id());
        assert_eq!(decoded.trust[0].info.peer_id, info.peer_id);
        assert_eq!(decoded.trust[0].signature, sig);
    }
    #[test]
    fn sign_trust_entries_produces_verifiable_records() {
        let signer = checked_seed_keypair(&[59, 60, 61, 62]);
        let signer_peer = Peer::new(
            "127.0.0.1:9500".parse().expect("addr"),
            signer.public_key().clone(),
        );
        let reported = checked_seed_keypair(&[63, 64, 65, 66]);
        let reported_peer = Peer::new(
            "127.0.0.1:9501".parse().expect("addr"),
            reported.public_key().clone(),
        );
        let signer_id = signer_peer.id().clone();
        let topology = BTreeSet::from([signer_id.clone(), reported_peer.id().clone()]);
        let mut gossiper = PeersGossiper {
            peer_id: signer_id,
            network_id: trust_test_network_id(),
            initial_peers: BTreeMap::new(),
            consensus_mode: ConsensusMode::Permissioned,
            trusted_peers: topology.clone(),
            static_trusted_peers: topology.clone(),
            configured_validator_peers: BTreeSet::new(),
            trust_candidates: topology.clone(),
            gossip_peers: BTreeMap::new(),
            peer_capabilities: BTreeMap::new(),
            validator_topology: topology.clone(),
            current_topology: topology,
            key_pair: signer.clone(),
            gossip_period: Duration::from_secs(1),
            gossip_max_period: Duration::from_secs(1),
            gossip_backoff: Duration::from_secs(1),
            gossip_next_deadline: std::time::Instant::now(),
            gossip_pending: true,
            last_gossip_fingerprint: None,
            last_drop_count: 0,
            last_drop_at: None,
            trust: TrustBook::new(
                Duration::ZERO,
                TrustPenalties {
                    bad_gossip: 4,
                    unknown_peer: 3,
                },
                -4,
            ),
            network: IrohaNetwork::closed_for_tests(),
        };
        let infos = [PeerTrustInfo {
            peer_id: reported_peer.id().clone(),
            trusted: true,
            score: 2,
        }];
        let signed_payload = gossiper.sign_trust_entries(&infos);
        assert_eq!(signed_payload.len(), 1);
        assert_eq!(signed_payload[0].info.peer_id, infos[0].peer_id);
        Signature::try_from_bytes(&signed_payload[0].signature)
            .expect("checked peer-trust signature fixture")
            .verify(
                signer.public_key(),
                &PeersGossiper::trust_payload(&gossiper.network_id, &signed_payload[0].info),
            )
            .expect("trust record signature must verify");
        let foreign_network_id = test_network_id(0x52);
        Signature::try_from_bytes(&signed_payload[0].signature)
            .expect("checked peer-trust signature fixture")
            .verify(
                signer.public_key(),
                &PeersGossiper::trust_payload(&foreign_network_id, &signed_payload[0].info),
            )
            .expect_err("a trust signature must not verify for another genesis lineage");
        assert!(gossiper.trust.entries.is_empty());
        assert!(!gossiper.handle_trust_gossip(
            PeerTrustGossip {
                network_id: foreign_network_id,
                trust: signed_payload,
            },
            &signer_peer,
        ));
        assert!(
            gossiper.trust.entries.is_empty(),
            "foreign-network trust gossip must be rejected before trust-book mutation"
        );
    }
    #[test]
    fn trust_book_penalty_and_decay() {
        let mut trust = TrustBook::new(
            Duration::from_millis(200),
            TrustPenalties {
                bad_gossip: 4,
                unknown_peer: 3,
            },
            -4,
        );
        let kp = checked_seed_keypair(&[13, 14, 15, 16]);
        let peer = Peer::new("127.0.0.1:8083".parse().unwrap(), kp.public_key().clone());
        let peer_id = peer.id().clone();
        let now = Instant::now();
        trust.seed([peer_id.clone()], now);
        assert_eq!(trust.score(&peer_id, now), 0);
        let after_penalty =
            trust.penalize(&peer_id, TrustPenaltyKind::BadGossip, "bad_gossip", now);
        assert_eq!(after_penalty, -4);
        assert!(trust.should_drop(&peer_id, now));
        let later = now + Duration::from_millis(200);
        assert_eq!(trust.score(&peer_id, later), -2);
        let drop_score = trust.penalize(&peer_id, TrustPenaltyKind::BadGossip, "bad_gossip", later);
        assert_eq!(drop_score, -6);
        let later_again = later + Duration::from_millis(400);
        assert_eq!(trust.score(&peer_id, later_again), -1);
        assert!(!trust.should_drop(&peer_id, later_again));
        let unknown = trust.penalize(
            &peer_id,
            TrustPenaltyKind::UnknownPeer,
            PENALTY_REASON_UNKNOWN_PEER,
            later_again,
        );
        assert_eq!(unknown, -4);
        assert!(trust.should_drop(&peer_id, later_again));
    }
    #[test]
    fn gossip_interval_respects_config_value() {
        let configured = Duration::from_millis(250);
        assert_eq!(PeersGossiper::gossip_interval(configured), configured);
    }
    #[test]
    fn gossip_backoff_doubles_and_resets() {
        let min = Duration::from_millis(100);
        let max = Duration::from_millis(800);
        let backoff = PeersGossiper::next_gossip_backoff(min, min, max, false);
        assert_eq!(backoff, Duration::from_millis(200));
        let backoff = PeersGossiper::next_gossip_backoff(backoff, min, max, false);
        assert_eq!(backoff, Duration::from_millis(400));
        let backoff = PeersGossiper::next_gossip_backoff(backoff, min, max, false);
        assert_eq!(backoff, Duration::from_millis(800));
        let reset = PeersGossiper::next_gossip_backoff(backoff, min, max, true);
        assert_eq!(reset, min);
    }
    #[test]
    fn gossip_fingerprint_is_stable_and_detects_changes() {
        let kp1 = checked_seed_keypair(&[51, 52, 53, 54]);
        let kp2 = checked_seed_keypair(&[55, 56, 57, 58]);
        let peer1 = Peer::new(
            "127.0.0.1:9400".parse().expect("addr"),
            kp1.public_key().clone(),
        );
        let peer2 = Peer::new(
            "127.0.0.1:9401".parse().expect("addr"),
            kp2.public_key().clone(),
        );
        let ordered = PeersGossiper::sorted_online_peers(vec![peer1.clone(), peer2.clone()]);
        let reversed = PeersGossiper::sorted_online_peers(vec![peer2.clone(), peer1.clone()]);
        let capabilities = BTreeMap::from([(
            peer1.id().clone(),
            PeerTransportCapabilities {
                scion_supported: true,
            },
        )]);
        let trust = vec![PeerTrustInfo {
            peer_id: peer1.id().clone(),
            trusted: true,
            score: 0,
        }];
        let ordered_fingerprint =
            PeersGossiper::gossip_fingerprint(&ordered, &capabilities, &trust);
        let reversed_fingerprint =
            PeersGossiper::gossip_fingerprint(&reversed, &capabilities, &trust);
        assert_eq!(
            ordered_fingerprint, reversed_fingerprint,
            "peer order should be canonicalized before fingerprinting"
        );
        let changed_trust = vec![PeerTrustInfo {
            peer_id: peer1.id().clone(),
            trusted: false,
            score: -1,
        }];
        assert_ne!(
            ordered_fingerprint,
            PeersGossiper::gossip_fingerprint(&ordered, &capabilities, &changed_trust),
            "trust changes should force a fresh gossip payload"
        );
        let changed_capabilities = BTreeMap::from([(
            peer1.id().clone(),
            PeerTransportCapabilities {
                scion_supported: false,
            },
        )]);
        assert_ne!(
            ordered_fingerprint,
            PeersGossiper::gossip_fingerprint(&ordered, &changed_capabilities, &trust),
            "capability changes should force a fresh gossip payload"
        );
    }
    #[test]
    fn retained_peers_and_trust_events_keep_credit_until_processing_or_rejection() {
        use crate::retained_gossip::RetainedGossip;
        for trust_first in [false, true] {
            let (message_sender, mut receiver) = mpsc::channel(1);
            let (update_topology_sender, _updates) = mpsc::unbounded_channel();
            let handle = PeersGossiperHandle {
                message_sender,
                update_topology_sender,
            };
            let key = checked_seed_keypair(&[98, 97, 96, 95]);
            let peer = Peer::new("127.0.0.1:9998".parse().unwrap(), key.public_key().clone());
            let (peers, peers_count) = RetainedGossip::with_count_for_test((
                PeersGossip {
                    peers: UniqueVec::from_iter(vec![peer.clone()]),
                    peer_capabilities: BTreeMap::new(),
                },
                peer.clone(),
            ));
            let (trust, trust_count) = RetainedGossip::with_count_for_test((
                PeerTrustGossip {
                    network_id: trust_test_network_id(),
                    trust: Vec::new(),
                },
                peer,
            ));
            let (queued, rejected) = if trust_first {
                handle.gossip_trust(trust);
                handle.gossip(peers);
                (trust_count, peers_count)
            } else {
                handle.gossip(peers);
                handle.gossip_trust(trust);
                (peers_count, trust_count)
            };
            assert_eq!(queued.available_permits(), 0);
            assert_eq!(rejected.available_permits(), 1);
            match receiver.try_recv().unwrap() {
                GossipEvent::Peers(message) => message.with_payload(|(gossip, _)| {
                    assert!(!trust_first);
                    assert_eq!(gossip.peers.len(), 1);
                    assert_eq!(queued.available_permits(), 0);
                }),
                GossipEvent::Trust(message) => message.with_payload(|(gossip, _)| {
                    assert!(trust_first);
                    assert!(gossip.trust.is_empty());
                    assert_eq!(queued.available_permits(), 0);
                }),
            }
            assert_eq!(queued.available_permits(), 1);
            assert!(matches!(
                receiver.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }
    }
    #[test]
    fn gossiper_handle_drops_messages_when_receiver_closed() {
        let handle = PeersGossiperHandle::closed_for_tests();
        let kp = checked_seed_keypair(&[99, 98, 97, 96]);
        let peer = Peer::new(
            "127.0.0.1:9999".parse().expect("addr"),
            kp.public_key().clone(),
        );
        handle.gossip(crate::retained_gossip::RetainedGossip::synthetic_for_test(
            (
                PeersGossip {
                    peers: UniqueVec::from_iter(vec![peer.clone()]),
                    peer_capabilities: BTreeMap::new(),
                },
                peer.clone(),
            ),
        ));
        handle.gossip_trust(crate::retained_gossip::RetainedGossip::synthetic_for_test(
            (
                PeerTrustGossip {
                    network_id: trust_test_network_id(),
                    trust: Vec::new(),
                },
                peer,
            ),
        ));
        handle.update_topology(UpdateTopology(HashSet::new()));
    }
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn topology_update_preserves_static_trusted_peers() {
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let key_pair = checked_random_bls_keypair();
        let peer_id = PeerId::from(key_pair.public_key().clone());
        let network_cfg = NetworkConfig {
            address: WithOrigin::inline(listen_addr.clone()),
            public_address: WithOrigin::inline(listen_addr.clone()),
            relay_mode: RelayMode::Disabled,
            relay_hub_addresses: Vec::new(),
            relay_ttl: iroha_config::parameters::defaults::network::RELAY_TTL,
            soranet_handshake: SoranetHandshake::default(),
            soranet_privacy: SoranetPrivacy::default(),
            soranet_vpn: SoranetVpn::default(),
            lane_profile: LaneProfile::Core,
            require_sm_handshake_match:
                iroha_config::parameters::defaults::network::REQUIRE_SM_HANDSHAKE_MATCH,
            require_sm_openssl_preview_match:
                iroha_config::parameters::defaults::network::REQUIRE_SM_OPENSSL_PREVIEW_MATCH,
            idle_timeout: iroha_config::parameters::defaults::network::IDLE_TIMEOUT,
            preauth_timeout: iroha_config::parameters::defaults::network::PREAUTH_TIMEOUT,
            preauth_max_connections_per_ip:
                iroha_config::parameters::defaults::network::PREAUTH_MAX_CONNECTIONS_PER_IP,
            reply_writer_flush_timeout:
                iroha_config::parameters::defaults::network::REPLY_WRITER_FLUSH_TIMEOUT,
            connect_startup_delay:
                iroha_config::parameters::defaults::network::CONNECT_STARTUP_DELAY,
            dial_timeout: iroha_config::parameters::defaults::network::DIAL_TIMEOUT,
            peer_gossip_period: iroha_config::parameters::defaults::network::PEER_GOSSIP_PERIOD,
            peer_gossip_max_period: iroha_config::parameters::defaults::network::PEER_GOSSIP_PERIOD,
            trust_gossip: iroha_config::parameters::defaults::network::TRUST_GOSSIP,
            trust_decay_half_life:
                iroha_config::parameters::defaults::network::TRUST_DECAY_HALF_LIFE,
            trust_penalty_bad_gossip:
                iroha_config::parameters::defaults::network::TRUST_PENALTY_BAD_GOSSIP,
            trust_penalty_unknown_peer:
                iroha_config::parameters::defaults::network::TRUST_PENALTY_UNKNOWN_PEER,
            trust_min_score: iroha_config::parameters::defaults::network::TRUST_MIN_SCORE,
            deferred_send_ttl: Duration::from_millis(
                iroha_config::parameters::defaults::network::DEFERRED_SEND_TTL_MS,
            ),
            deferred_send_max_per_peer:
                iroha_config::parameters::defaults::network::DEFERRED_SEND_MAX_PER_PEER,
            deferred_send_max_bytes_per_peer:
                iroha_config::parameters::defaults::network::DEFERRED_SEND_MAX_BYTES_PER_PEER,
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
            quic_datagrams_enabled: iroha_config::parameters::defaults::network::QUIC_DATAGRAMS_ENABLED,
            quic_datagram_max_payload_bytes: iroha_config::parameters::defaults::network::QUIC_DATAGRAM_MAX_PAYLOAD_BYTES.get(),
            quic_datagram_receive_buffer_bytes: iroha_config::parameters::defaults::network::QUIC_DATAGRAM_RECEIVE_BUFFER_BYTES.get(),
            quic_datagram_send_buffer_bytes: iroha_config::parameters::defaults::network::QUIC_DATAGRAM_SEND_BUFFER_BYTES.get(),
            p2p_queue_cap_high: iroha_config::parameters::defaults::network::P2P_QUEUE_CAP_HIGH,
            p2p_queue_cap_low: iroha_config::parameters::defaults::network::P2P_QUEUE_CAP_LOW,
            p2p_post_queue_cap: iroha_config::parameters::defaults::network::P2P_POST_QUEUE_CAP,
            p2p_outbound_frame_queue_max_high_bytes:
                iroha_config::parameters::defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_BYTES,
            p2p_outbound_frame_queue_max_low_bytes:
                iroha_config::parameters::defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_BYTES,
            p2p_outbound_frame_queue_max_high_frames:
                iroha_config::parameters::defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_FRAMES,
            p2p_outbound_frame_queue_max_low_frames:
                iroha_config::parameters::defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_FRAMES,
            p2p_subscriber_queue_cap:
                iroha_config::parameters::defaults::network::P2P_SUBSCRIBER_QUEUE_CAP,
            consensus_ingress_rate_per_sec:
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_RATE_PER_SEC,
            consensus_ingress_burst:
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_BURST,
            consensus_ingress_bytes_per_sec:
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_BYTES_PER_SEC,
            consensus_ingress_bytes_burst:
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_BYTES_BURST,
            consensus_ingress_critical_rate_per_sec:
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_CRITICAL_RATE_PER_SEC,
            consensus_ingress_critical_burst:
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_CRITICAL_BURST,
            consensus_ingress_critical_bytes_per_sec:
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_CRITICAL_BYTES_PER_SEC,
            consensus_ingress_critical_bytes_burst:
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_CRITICAL_BYTES_BURST,
            consensus_ingress_penalty_threshold:
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_PENALTY_THRESHOLD,
            consensus_ingress_penalty_window: Duration::from_millis(
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_PENALTY_WINDOW_MS,
            ),
            consensus_ingress_penalty_cooldown: Duration::from_millis(
                iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_PENALTY_COOLDOWN_MS,
            ),
            happy_eyeballs_stagger:
                iroha_config::parameters::defaults::network::HAPPY_EYEBALLS_STAGGER,
            addr_ipv6_first: false,
            max_incoming: None,
            max_total_connections: None,
            accept_rate_per_ip_per_sec: None,
            accept_burst_per_ip: None,
            max_accept_buckets: iroha_config::parameters::defaults::network::MAX_ACCEPT_BUCKETS,
            accept_bucket_idle: iroha_config::parameters::defaults::network::ACCEPT_BUCKET_IDLE,
            accept_prefix_v4_bits:
                iroha_config::parameters::defaults::network::ACCEPT_PREFIX_V4_BITS,
            accept_prefix_v6_bits:
                iroha_config::parameters::defaults::network::ACCEPT_PREFIX_V6_BITS,
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
            disconnect_on_post_overflow:
                iroha_config::parameters::defaults::network::DISCONNECT_ON_POST_OVERFLOW,
            max_frame_bytes: iroha_config::parameters::defaults::network::MAX_FRAME_BYTES.get(),
            tcp_nodelay: iroha_config::parameters::defaults::network::TCP_NODELAY,
            tcp_keepalive: Some(iroha_config::parameters::defaults::network::TCP_KEEPALIVE),
            max_frame_bytes_consensus:
                iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONSENSUS.get(),
            max_frame_bytes_control:
                iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONTROL.get(),
            max_frame_bytes_block_sync:
                iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_BLOCK_SYNC.get(),
            max_frame_bytes_tx_gossip:
                iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_TX_GOSSIP.get(),
            max_frame_bytes_peer_gossip:
                iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_PEER_GOSSIP.get(),
            max_frame_bytes_health:
                iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_HEALTH.get(),
            max_frame_bytes_connect: iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONNECT.get(),
            max_frame_bytes_other:
                iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_OTHER.get(),
            quic_max_idle_timeout: None,
        };
        let network = IrohaNetwork::closed_for_tests();
        let local_peer = Peer::new(listen_addr, peer_id.clone());
        let observer_kp = checked_random_bls_keypair();
        let observer_peer = Peer::new(
            "127.0.0.1:9101".parse().expect("addr"),
            observer_kp.public_key().clone(),
        );
        let trusted_peers = TrustedPeersConfig {
            myself: local_peer,
            others: UniqueVec::from_iter(vec![observer_peer.clone()]),
            pops: BTreeMap::new(),
        };
        let trusted_list = trusted_peers.others.clone();
        let initial_peers = trusted_list
            .iter()
            .map(|peer| (peer.id().clone(), peer.address().clone()))
            .collect();
        let trusted_set: BTreeSet<_> = trusted_list.iter().map(|peer| peer.id().clone()).collect();
        let current_topology = trusted_set.clone();
        let trust_candidates = trusted_set.clone();
        let mut gossiper = PeersGossiper {
            peer_id,
            network_id: trust_test_network_id(),
            initial_peers,
            consensus_mode: ConsensusMode::Permissioned,
            trusted_peers: trusted_set.clone(),
            static_trusted_peers: trusted_set.clone(),
            configured_validator_peers: BTreeSet::new(),
            trust_candidates,
            gossip_peers: BTreeMap::new(),
            peer_capabilities: BTreeMap::new(),
            validator_topology: current_topology.clone(),
            current_topology,
            key_pair: key_pair.clone(),
            gossip_period: network_cfg.peer_gossip_period,
            gossip_max_period: network_cfg.peer_gossip_max_period,
            gossip_backoff: network_cfg.peer_gossip_period,
            gossip_next_deadline: std::time::Instant::now(),
            gossip_pending: true,
            last_gossip_fingerprint: None,
            last_drop_count: iroha_p2p::network::subscriber_queue_full_count(),
            last_drop_at: None,
            trust: TrustBook::new(
                network_cfg.trust_decay_half_life,
                TrustPenalties {
                    bad_gossip: i64::from(network_cfg.trust_penalty_bad_gossip),
                    unknown_peer: i64::from(network_cfg.trust_penalty_unknown_peer),
                },
                network_cfg.trust_min_score,
            ),
            network: network.clone(),
        };
        let dynamic_kp = checked_random_bls_keypair();
        let dynamic_peer_id = PeerId::from(dynamic_kp.public_key().clone());
        gossiper.trusted_peers.insert(dynamic_peer_id.clone());
        gossiper.trust_candidates.insert(dynamic_peer_id.clone());
        gossiper.current_topology.insert(dynamic_peer_id.clone());
        gossiper.trust.entries.insert(
            dynamic_peer_id.clone(),
            TrustEntry {
                score: 0,
                last_updated: Instant::now(),
            },
        );
        let validator_kp = checked_random_bls_keypair();
        let validator_peer_id = PeerId::from(validator_kp.public_key().clone());
        gossiper.set_current_topology(UpdateTopology([validator_peer_id].into_iter().collect()));
        assert!(
            gossiper.trusted_peers.contains(observer_peer.id()),
            "configured observer should remain trusted even if excluded from topology"
        );
        assert!(
            gossiper.current_topology.contains(observer_peer.id()),
            "static trusted peers should remain in the p2p topology"
        );
        assert!(
            !gossiper.trusted_peers.contains(&dynamic_peer_id),
            "non-static peer should be dropped from trust when removed from topology"
        );
        assert!(
            !gossiper.current_topology.contains(&dynamic_peer_id),
            "dynamic peers removed from topology should not remain in the p2p topology"
        );
        assert!(
            gossiper.trust_candidates.contains(observer_peer.id()),
            "configured observer should remain a trust candidate"
        );
        assert!(
            !gossiper.trust_candidates.contains(&dynamic_peer_id),
            "removed dynamic peer should not remain a trust candidate"
        );
        gossiper.set_current_topology(UpdateTopology(HashSet::new()));
        assert!(
            gossiper.current_topology.is_empty(),
            "empty topology updates should force the local dial set to disconnect"
        );
        assert!(
            gossiper.trusted_peers.is_empty(),
            "empty topology updates should clear runtime trusted peers"
        );
        assert!(
            gossiper.trust_candidates.is_empty(),
            "empty topology updates should clear runtime trust candidates"
        );
    }
    #[test]
    fn topology_update_adds_new_trusted_peers() {
        let key_pair = checked_random_bls_keypair();
        let peer_id = PeerId::from(key_pair.public_key().clone());
        let _local_peer = Peer::new("127.0.0.1:9100".parse().expect("addr"), peer_id.clone());
        let observer_kp = checked_random_bls_keypair();
        let observer_peer = Peer::new(
            "127.0.0.1:9101".parse().expect("addr"),
            observer_kp.public_key().clone(),
        );
        let trusted_set: BTreeSet<_> = [peer_id.clone(), observer_peer.id().clone()]
            .into_iter()
            .collect();
        let trust_candidates = trusted_set.clone();
        let current_topology = trusted_set.clone();
        let initial_peers =
            BTreeMap::from([(observer_peer.id().clone(), observer_peer.address().clone())]);
        let mut gossiper = PeersGossiper {
            peer_id,
            network_id: trust_test_network_id(),
            initial_peers,
            consensus_mode: ConsensusMode::Permissioned,
            trusted_peers: trusted_set.clone(),
            static_trusted_peers: trusted_set,
            configured_validator_peers: BTreeSet::new(),
            trust_candidates,
            gossip_peers: BTreeMap::new(),
            peer_capabilities: BTreeMap::new(),
            validator_topology: current_topology.clone(),
            current_topology,
            key_pair,
            gossip_period: std::time::Duration::from_secs(1),
            gossip_max_period: std::time::Duration::from_secs(1),
            gossip_backoff: std::time::Duration::from_secs(1),
            gossip_next_deadline: std::time::Instant::now(),
            gossip_pending: true,
            last_gossip_fingerprint: None,
            last_drop_count: iroha_p2p::network::subscriber_queue_full_count(),
            last_drop_at: None,
            trust: TrustBook::new(
                std::time::Duration::from_secs(1),
                TrustPenalties {
                    bad_gossip: 1,
                    unknown_peer: 1,
                },
                -1,
            ),
            network: IrohaNetwork::closed_for_tests(),
        };
        let added_kp = checked_random_bls_keypair();
        let added_peer = Peer::new(
            "127.0.0.1:9102".parse().expect("addr"),
            added_kp.public_key().clone(),
        );
        let added_id = added_peer.id().clone();
        let update = UpdateTopology(HashSet::from_iter(vec![added_id.clone()]));
        gossiper.set_current_topology(update);
        assert!(
            gossiper.trusted_peers.contains(&added_id),
            "new topology member should be trusted"
        );
        assert!(
            gossiper.trust_candidates.contains(&added_id),
            "new topology member should be tracked as a trust candidate"
        );
        assert!(
            gossiper.trust.entries.contains_key(&added_id),
            "new topology member should be seeded in trust book"
        );
    }
    #[test]
    fn trust_gossip_penalizes_unknown_peer_in_permissioned_mode() {
        let kp_sender = checked_seed_keypair(&[17, 18, 19, 20]);
        let kp_unknown = checked_seed_keypair(&[21, 22, 23, 24]);
        let from_peer = Peer::new(
            "127.0.0.1:9000".parse().expect("addr"),
            kp_sender.public_key().clone(),
        );
        let unknown_peer = Peer::new(
            "127.0.0.1:9001".parse().expect("addr"),
            kp_unknown.public_key().clone(),
        );
        let info = PeerTrustInfo {
            peer_id: unknown_peer.id().clone(),
            trusted: false,
            score: 1,
        };
        let signature = signed_trust_payload(&kp_sender, &info);
        let trust = vec![SignedPeerTrust { info, signature }];
        let now = Instant::now();
        let mut trust_book = TrustBook::new(
            Duration::from_millis(0),
            TrustPenalties {
                bad_gossip: 4,
                unknown_peer: 3,
            },
            -2,
        );
        trust_book.seed([from_peer.id().clone()], now);
        let outcome = process_trust_records(
            &trust_test_network_id(),
            trust,
            &from_peer,
            false,
            &BTreeSet::new(),
            &BTreeSet::from([from_peer.id().clone()]),
            &mut trust_book,
            now,
        );
        assert!(
            outcome.drop_sender,
            "sender should be dropped after unknown peer penalty"
        );
        assert!(outcome.newly_trusted.is_empty());
        assert!(trust_book.score(from_peer.id(), now) <= -2);
    }
    #[test]
    fn trust_gossip_penalizes_all_zero_signature_material() {
        let kp_sender = checked_seed_keypair(&[17, 18, 19, 20]);
        let kp_reported = checked_seed_keypair(&[21, 22, 23, 24]);
        let from_peer = Peer::new(
            "127.0.0.1:9000".parse().expect("addr"),
            kp_sender.public_key().clone(),
        );
        let reported_peer = Peer::new(
            "127.0.0.1:9001".parse().expect("addr"),
            kp_reported.public_key().clone(),
        );
        let info = PeerTrustInfo {
            peer_id: reported_peer.id().clone(),
            trusted: true,
            score: 1,
        };
        let trust = vec![SignedPeerTrust {
            info,
            signature: vec![0_u8; 64],
        }];
        let now = Instant::now();
        let mut trust_book = TrustBook::new(
            Duration::from_millis(0),
            TrustPenalties {
                bad_gossip: 4,
                unknown_peer: 3,
            },
            -2,
        );
        trust_book.seed([from_peer.id().clone()], now);
        let outcome = process_trust_records(
            &trust_test_network_id(),
            trust,
            &from_peer,
            false,
            &BTreeSet::from([reported_peer.id().clone()]),
            &BTreeSet::from([from_peer.id().clone()]),
            &mut trust_book,
            now,
        );
        assert!(
            outcome.drop_sender,
            "sender should be dropped after all-zero trust-signature penalty"
        );
        assert!(outcome.newly_trusted.is_empty());
        assert!(trust_book.score(from_peer.id(), now) <= -2);
    }
    #[test]
    fn trust_gossip_penalizes_malformed_ed25519_signature_r() {
        const SMALL_ORDER_R: [u8; 32] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const NONCANONICAL_R: [u8; 32] = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let kp_sender = checked_seed_keypair(&[18, 19, 20, 21]);
        let kp_reported = checked_seed_keypair(&[22, 23, 24, 25]);
        let from_peer = Peer::new(
            "127.0.0.1:9002".parse().expect("addr"),
            kp_sender.public_key().clone(),
        );
        let reported_peer = Peer::new(
            "127.0.0.1:9003".parse().expect("addr"),
            kp_reported.public_key().clone(),
        );
        let info = PeerTrustInfo {
            peer_id: reported_peer.id().clone(),
            trusted: true,
            score: 1,
        };
        let valid_signature = signed_trust_payload(&kp_sender, &info);
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_R),
            ("noncanonical", NONCANONICAL_R),
        ] {
            let mut malformed_signature = valid_signature.clone();
            malformed_signature[..replacement_r.len()].copy_from_slice(&replacement_r);
            let trust = vec![SignedPeerTrust {
                info: info.clone(),
                signature: malformed_signature,
            }];
            let now = Instant::now();
            let mut trust_book = TrustBook::new(
                Duration::from_millis(0),
                TrustPenalties {
                    bad_gossip: 4,
                    unknown_peer: 3,
                },
                -2,
            );
            trust_book.seed([from_peer.id().clone()], now);
            let outcome = process_trust_records(
                &trust_test_network_id(),
                trust,
                &from_peer,
                false,
                &BTreeSet::from([reported_peer.id().clone()]),
                &BTreeSet::from([from_peer.id().clone()]),
                &mut trust_book,
                now,
            );
            assert!(
                outcome.drop_sender,
                "{label} Ed25519 trust signature R must drop the sender"
            );
            assert!(outcome.newly_trusted.is_empty());
            assert!(
                trust_book.score(from_peer.id(), now) <= -2,
                "{label} Ed25519 trust signature R must penalize the sender"
            );
        }
    }
    #[test]
    fn trust_gossip_penalizes_malformed_mldsa_signature_lengths() {
        let kp_sender =
            checked_seed_keypair_with_algorithm(b"trust-gossip-mldsa-sender", Algorithm::MlDsa);
        let kp_reported = checked_seed_keypair(&[23, 24, 25, 26]);
        let from_peer = Peer::new(
            "127.0.0.1:9004".parse().expect("addr"),
            kp_sender.public_key().clone(),
        );
        let reported_peer = Peer::new(
            "127.0.0.1:9005".parse().expect("addr"),
            kp_reported.public_key().clone(),
        );
        let info = PeerTrustInfo {
            peer_id: reported_peer.id().clone(),
            trusted: true,
            score: 1,
        };
        let valid_signature = signed_trust_payload(&kp_sender, &info);
        iroha_crypto::mldsa65_parse_signature(&valid_signature)
            .expect("valid trust-gossip ML-DSA signature parses");
        for (label, replacement_signature) in [
            (
                "short",
                valid_signature[..valid_signature.len() - 1].to_vec(),
            ),
            ("overlong", {
                let mut payload = valid_signature.clone();
                payload.push(0x27);
                payload
            }),
        ] {
            let trust = vec![SignedPeerTrust {
                info: info.clone(),
                signature: replacement_signature,
            }];
            let now = Instant::now();
            let mut trust_book = TrustBook::new(
                Duration::from_millis(0),
                TrustPenalties {
                    bad_gossip: 4,
                    unknown_peer: 3,
                },
                -2,
            );
            trust_book.seed([from_peer.id().clone()], now);
            let outcome = process_trust_records(
                &trust_test_network_id(),
                trust,
                &from_peer,
                false,
                &BTreeSet::from([reported_peer.id().clone()]),
                &BTreeSet::from([from_peer.id().clone()]),
                &mut trust_book,
                now,
            );
            assert!(
                outcome.drop_sender,
                "{label} ML-DSA trust signature length must drop the sender"
            );
            assert!(outcome.newly_trusted.is_empty());
            assert!(
                trust_book.score(from_peer.id(), now) <= -2,
                "{label} ML-DSA trust signature length must penalize the sender"
            );
        }
    }
    #[test]
    fn unknown_peer_penalty_evicts_and_recovers_after_decay() {
        let kp_sender = checked_seed_keypair(&[33, 34, 35, 36]);
        let kp_unknown = checked_seed_keypair(&[37, 38, 39, 40]);
        let from_peer = Peer::new(
            "127.0.0.1:9200".parse().expect("addr"),
            kp_sender.public_key().clone(),
        );
        let unknown_peer = Peer::new(
            "127.0.0.1:9201".parse().expect("addr"),
            kp_unknown.public_key().clone(),
        );
        let info = PeerTrustInfo {
            peer_id: unknown_peer.id().clone(),
            trusted: false,
            score: 1,
        };
        let signature = signed_trust_payload(&kp_sender, &info);
        let trust = vec![SignedPeerTrust { info, signature }];
        let now = Instant::now();
        let mut trust_book = TrustBook::new(
            Duration::from_millis(100),
            TrustPenalties {
                bad_gossip: 4,
                unknown_peer: 3,
            },
            -2,
        );
        trust_book.seed([from_peer.id().clone()], now);
        let outcome = process_trust_records(
            &trust_test_network_id(),
            trust,
            &from_peer,
            false,
            &BTreeSet::new(),
            &BTreeSet::from([from_peer.id().clone()]),
            &mut trust_book,
            now,
        );
        assert!(outcome.drop_sender);
        assert!(trust_book.should_drop(from_peer.id(), now));
        // After decay, the sender can clear the floor and be reinstated via the recovery path.
        let recovered_at = now + Duration::from_millis(300);
        let recovered_score = trust_book.score(from_peer.id(), recovered_at);
        assert!(
            recovered_score > trust_book.min_score(),
            "decay should allow recovery after penalties"
        );
        let mut trusted_peers = BTreeSet::new();
        let trust_candidates = BTreeSet::from([from_peer.id().clone()]);
        if trust_candidates.contains(from_peer.id())
            && trust_book.score(from_peer.id(), recovered_at) > trust_book.min_score()
        {
            trusted_peers.insert(from_peer.id().clone());
        }
        assert!(
            trusted_peers.contains(from_peer.id()),
            "peer should be eligible for reinstatement after decay"
        );
    }
    #[test]
    fn trust_gossip_allows_public_mode_without_penalty() {
        let kp_sender = checked_seed_keypair(&[25, 26, 27, 28]);
        let kp_unknown = checked_seed_keypair(&[29, 30, 31, 32]);
        let from_peer = Peer::new(
            "127.0.0.1:9100".parse().expect("addr"),
            kp_sender.public_key().clone(),
        );
        let unknown_peer = Peer::new(
            "127.0.0.1:9101".parse().expect("addr"),
            kp_unknown.public_key().clone(),
        );
        let info = PeerTrustInfo {
            peer_id: unknown_peer.id().clone(),
            trusted: true,
            score: 2,
        };
        let signature = signed_trust_payload(&kp_sender, &info);
        let trust = vec![SignedPeerTrust { info, signature }];
        let now = Instant::now();
        let mut trust_book = TrustBook::new(
            Duration::from_millis(0),
            TrustPenalties {
                bad_gossip: 4,
                unknown_peer: 3,
            },
            -4,
        );
        trust_book.seed([from_peer.id().clone()], now);
        let outcome = process_trust_records(
            &trust_test_network_id(),
            trust,
            &from_peer,
            true,
            &BTreeSet::new(),
            &BTreeSet::from([from_peer.id().clone()]),
            &mut trust_book,
            now,
        );
        assert!(!outcome.drop_sender);
        assert_eq!(outcome.newly_trusted.len(), 1);
        assert_eq!(
            outcome
                .newly_trusted
                .iter()
                .next()
                .expect("contains one peer"),
            unknown_peer.id()
        );
        assert_eq!(trust_book.score(from_peer.id(), now), 0);
    }
    #[test]
    fn trust_gossip_allows_trusted_sender_to_introduce_peer() {
        let kp_sender = checked_seed_keypair(&[41, 42, 43, 44]);
        let kp_unknown = checked_seed_keypair(&[45, 46, 47, 48]);
        let from_peer = Peer::new(
            "127.0.0.1:9300".parse().expect("addr"),
            kp_sender.public_key().clone(),
        );
        let unknown_peer = Peer::new(
            "127.0.0.1:9301".parse().expect("addr"),
            kp_unknown.public_key().clone(),
        );
        let info = PeerTrustInfo {
            peer_id: unknown_peer.id().clone(),
            trusted: true,
            score: 1,
        };
        let signature = signed_trust_payload(&kp_sender, &info);
        let trust = vec![SignedPeerTrust { info, signature }];
        let now = Instant::now();
        let mut trust_book = TrustBook::new(
            Duration::from_millis(0),
            TrustPenalties {
                bad_gossip: 4,
                unknown_peer: 3,
            },
            -2,
        );
        trust_book.seed([from_peer.id().clone()], now);
        let outcome = process_trust_records(
            &trust_test_network_id(),
            trust,
            &from_peer,
            false,
            &BTreeSet::new(),
            &BTreeSet::from([from_peer.id().clone()]),
            &mut trust_book,
            now,
        );
        assert!(!outcome.drop_sender);
        assert!(
            outcome.newly_trusted.contains(unknown_peer.id()),
            "trusted sender should be able to introduce a new peer"
        );
        assert_eq!(trust_book.score(from_peer.id(), now), 0);
    }
}
