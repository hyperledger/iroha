//! The node's relay of inbound P2P traffic other than consensus: transaction, peer and trust
//! gossip, streaming control and network time.
//!
//! Sumeragi frames reach the consensus driver on their own route
//! (`iroha_core::sumeragi::node::start_on_network`); Torii proxy, Connect and health frames have
//! dedicated subscribers. Each semantic class has its own subscriber and task, so a flood in one
//! class never delays another; low-priority gossip is rate limited per authenticated peer.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use iroha_core::{
    IrohaNetwork, NetworkMessage, gossiper::TransactionGossiperHandle,
    peers_gossiper::PeersGossiperHandle, retained_gossip::RetainedGossip,
    streaming::StreamingHandle,
};
use iroha_data_model::peer::Peer;
use iroha_futures::supervisor::ShutdownSignal;
use iroha_model_base::peer::PeerId;
use iroha_p2p::{
    TransportAdmissionClass,
    network::{SubscriberFilter, message::Topic},
    peer::message::{PeerMessage, PeerMessageRetentionGuard},
};
use tokio::sync::mpsc;

/// Bound of the single peer/trust subscriber of the read-only emergency runtime.
const EMERGENCY_FAST_SUBSCRIBER_CAP: usize = 32;
/// Pause before a refused or closed subscription is registered again.
const RESUBSCRIBE_DELAY: Duration = Duration::from_millis(50);

/// The relay's inputs.
pub struct NetworkRelay {
    pub(crate) tx_gossiper: TransactionGossiperHandle,
    pub(crate) peers_gossiper: PeersGossiperHandle,
    pub(crate) network: IrohaNetwork,
    pub(crate) streaming: StreamingHandle,
    pub(crate) low_priority_ingress: LowPriorityIngressLimiter,
    /// Emergency Fast startup: only peer and trust gossip, nothing that admits or persists.
    pub(crate) emergency_fast: bool,
}

struct Shared {
    tx_gossiper: TransactionGossiperHandle,
    peers_gossiper: PeersGossiperHandle,
    network: IrohaNetwork,
    streaming: StreamingHandle,
    low_priority_ingress: Mutex<LowPriorityIngressLimiter>,
    emergency_fast: bool,
}

impl NetworkRelay {
    /// Relay until `shutdown_signal`.
    pub(crate) async fn run(self, shutdown_signal: ShutdownSignal) {
        let shared = Arc::new(Shared {
            tx_gossiper: self.tx_gossiper,
            peers_gossiper: self.peers_gossiper,
            network: self.network,
            streaming: self.streaming,
            low_priority_ingress: Mutex::new(self.low_priority_ingress),
            emergency_fast: self.emergency_fast,
        });
        let subscriptions = if shared.emergency_fast {
            vec![(
                SubscriberFilter::topics([Topic::PeerGossip, Topic::TrustGossip]),
                EMERGENCY_FAST_SUBSCRIBER_CAP,
            )]
        } else {
            let base = shared.network.subscriber_queue_cap().get().max(2);
            TransportAdmissionClass::ALL
                .iter()
                .map(|&class| (SubscriberFilter::semantic_class(class), base))
                .collect()
        };
        let mut tasks = tokio::task::JoinSet::new();
        for (filter, capacity) in subscriptions {
            tasks.spawn(subscribe_and_relay(Arc::clone(&shared), filter, capacity));
        }
        shutdown_signal.receive().await;
        tasks.abort_all();
    }
}

/// Keep one subscriber registered and relay what it receives, in order.
async fn subscribe_and_relay(shared: Arc<Shared>, filter: SubscriberFilter, capacity: usize) {
    loop {
        let (sender, mut receiver) = mpsc::channel(capacity);
        if shared
            .network
            .subscribe_to_peers_messages_with_filter(sender, filter.clone())
            .is_err()
        {
            tokio::time::sleep(RESUBSCRIBE_DELAY).await;
            continue;
        }
        while let Some(message) = receiver.recv().await {
            shared.handle(message);
        }
        iroha_logger::warn!(?filter, "relay subscriber closed; subscribing again");
        tokio::time::sleep(RESUBSCRIBE_DELAY).await;
    }
}

impl Shared {
    fn handle(&self, message: PeerMessage<NetworkMessage>) {
        let (peer, authenticated_via, payload, size_bytes, retention) = message.into_parts();
        if Self::low_priority(&payload) && !self.admit_low_priority(&authenticated_via, size_bytes)
        {
            iroha_logger::debug!(
                %peer,
                via = %authenticated_via,
                size_bytes,
                "dropping inbound low-priority message due to ingress limits"
            );
            return;
        }
        self.dispatch(peer, authenticated_via, payload, retention);
    }

    fn dispatch(
        &self,
        peer: Peer,
        _authenticated_via: PeerId,
        payload: NetworkMessage,
        retention: PeerMessageRetentionGuard,
    ) {
        use NetworkMessage::*;
        match payload {
            StreamingControl(frame) => {
                // Streaming control persists session snapshots: never in emergency Fast.
                if !self.emergency_fast
                    && let Err(error) = self.streaming.process_control_frame(&peer, frame.as_ref())
                {
                    iroha_logger::warn!(%peer, ?error, "failed to process streaming control frame");
                }
            }
            TransactionGossiper(data) => {
                if !self.emergency_fast {
                    self.tx_gossiper
                        .gossip(RetainedGossip::new(data, retention));
                }
            }
            PeersGossiper(data) => self
                .peers_gossiper
                .gossip(RetainedGossip::new((*data, peer), retention)),
            PeerTrustGossip(data) => self
                .peers_gossiper
                .gossip_trust(RetainedGossip::new((*data, peer), retention)),
            TimePing(ping) => {
                iroha_core::time::handle_message(peer, TimePing(ping), &self.network);
            }
            TimePong(pong) => {
                iroha_core::time::handle_message(peer, TimePong(pong), &self.network);
            }
            // The consensus driver's own route carries Sumeragi frames.
            Sumeragi(_) | ToriiProxyRequest(_) | ToriiProxyResponse(_) | Health | Connect(_) => {} // Dedicated subscribers (Torii, health) handle these.
        }
    }

    fn low_priority(message: &NetworkMessage) -> bool {
        use iroha_p2p::network::message::ClassifyTopic;
        matches!(
            message.topic(),
            Topic::TxGossip
                | Topic::TxGossipRestricted
                | Topic::PeerGossip
                | Topic::TrustGossip
                | Topic::Health
                | Topic::Connect
                | Topic::Other
        ) || matches!(message, NetworkMessage::StreamingControl(_))
    }

    fn admit_low_priority(&self, authenticated_via: &PeerId, size_bytes: usize) -> bool {
        self.low_priority_ingress
            .lock()
            .expect("low-priority ingress mutex poisoned")
            .should_drop_from(authenticated_via, size_bytes)
            .is_none()
    }
}

/// Why a low-priority message was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LowPriorityIngressDropReason {
    Rate,
    Bytes,
}

#[derive(Clone, Copy, Debug)]
pub struct BucketConfig {
    pub(crate) rate_per_sec: std::num::NonZeroU32,
    pub(crate) burst: std::num::NonZeroU32,
}

/// Per-peer message and byte rate limits of low-priority traffic.
pub struct LowPriorityIngressLimiter {
    msg_rate: Option<BucketConfig>,
    bytes_rate: Option<BucketConfig>,
    peers: HashMap<PeerId, LowPriorityPeerState>,
}

struct LowPriorityPeerState {
    msg_bucket: Option<TokenBucket>,
    bytes_bucket: Option<TokenBucket>,
}

#[derive(Debug)]
struct TokenBucket {
    rate_per_sec: f64,
    capacity: f64,
    tokens: f64,
    last_refill: Instant,
}

impl LowPriorityIngressLimiter {
    pub(crate) fn from_config(network: &iroha_config::parameters::actual::Network) -> Self {
        let msg_rate = network.low_priority_rate_per_sec.map(|rate| BucketConfig {
            rate_per_sec: rate,
            burst: network.low_priority_burst.unwrap_or(rate),
        });
        let bytes_rate = network.low_priority_bytes_per_sec.map(|rate| BucketConfig {
            rate_per_sec: rate,
            burst: network.low_priority_bytes_burst.unwrap_or(rate),
        });
        Self::new(msg_rate, bytes_rate)
    }

    pub(crate) fn new(msg_rate: Option<BucketConfig>, bytes_rate: Option<BucketConfig>) -> Self {
        Self {
            msg_rate,
            bytes_rate,
            peers: HashMap::new(),
        }
    }

    pub(crate) fn should_drop_from(
        &mut self,
        authenticated_via: &PeerId,
        size_bytes: usize,
    ) -> Option<LowPriorityIngressDropReason> {
        if self.msg_rate.is_none() && self.bytes_rate.is_none() {
            return None;
        }
        let now = Instant::now();
        let (msg_rate, bytes_rate) = (self.msg_rate, self.bytes_rate);
        let entry = self
            .peers
            .entry(authenticated_via.clone())
            .or_insert_with(|| LowPriorityPeerState {
                msg_bucket: msg_rate.map(|config| TokenBucket::new(config, now)),
                bytes_bucket: bytes_rate.map(|config| TokenBucket::new(config, now)),
            });
        if let Some(bucket) = entry.msg_bucket.as_mut()
            && !bucket.allow(1.0, now)
        {
            return Some(LowPriorityIngressDropReason::Rate);
        }
        let size = f64::from(u32::try_from(size_bytes).unwrap_or(u32::MAX));
        if let Some(bucket) = entry.bytes_bucket.as_mut()
            && !bucket.allow(size, now)
        {
            return Some(LowPriorityIngressDropReason::Bytes);
        }
        None
    }
}

impl TokenBucket {
    fn new(config: BucketConfig, now: Instant) -> Self {
        let capacity = f64::from(config.burst.get());
        Self {
            rate_per_sec: f64::from(config.rate_per_sec.get()),
            capacity,
            tokens: capacity,
            last_refill: now,
        }
    }

    fn allow(&mut self, cost: f64, now: Instant) -> bool {
        if cost <= 0.0 {
            return true;
        }
        let elapsed = now.saturating_duration_since(self.last_refill);
        if !elapsed.is_zero() {
            self.tokens = elapsed
                .as_secs_f64()
                .mul_add(self.rate_per_sec, self.tokens)
                .min(self.capacity);
            self.last_refill = now;
        }
        if cost > self.capacity || self.tokens < cost {
            return false;
        }
        self.tokens -= cost;
        true
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use iroha_crypto::KeyPair;

    use super::*;

    fn config(rate: u32, burst: u32) -> BucketConfig {
        BucketConfig {
            rate_per_sec: NonZeroU32::new(rate).expect("non-zero"),
            burst: NonZeroU32::new(burst).expect("non-zero"),
        }
    }

    #[test]
    fn low_priority_limits_are_per_peer() {
        let mut limiter = LowPriorityIngressLimiter::new(Some(config(1, 2)), None);
        let a = PeerId::new(KeyPair::random().public_key().clone());
        let b = PeerId::new(KeyPair::random().public_key().clone());
        assert!(limiter.should_drop_from(&a, 10).is_none());
        assert!(limiter.should_drop_from(&a, 10).is_none());
        assert_eq!(
            limiter.should_drop_from(&a, 10),
            Some(LowPriorityIngressDropReason::Rate)
        );
        assert!(limiter.should_drop_from(&b, 10).is_none());
    }

    #[test]
    fn byte_limit_rejects_a_message_above_the_burst() {
        let mut limiter = LowPriorityIngressLimiter::new(None, Some(config(100, 100)));
        let a = PeerId::new(KeyPair::random().public_key().clone());
        assert_eq!(
            limiter.should_drop_from(&a, 101),
            Some(LowPriorityIngressDropReason::Bytes)
        );
        assert!(limiter.should_drop_from(&a, 100).is_none());
    }

    #[test]
    fn no_limits_admit_everything() {
        let mut limiter = LowPriorityIngressLimiter::new(None, None);
        let a = PeerId::new(KeyPair::random().public_key().clone());
        for _ in 0..1000 {
            assert!(limiter.should_drop_from(&a, usize::MAX).is_none());
        }
    }
}
