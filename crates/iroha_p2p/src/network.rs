//! Network formed out of Iroha peers.
#![allow(
    clippy::unused_async,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]
use crate::boilerplate;
#[cfg(feature = "quic")]
use crate::preauth::DeadlineElapsed;
use crate::{
    Broadcast, Error, NetworkMessage, OnlinePeers, P2pIdentityKeys, Post, Priority, RelayRole,
    UpdatePeers, UpdateTopology, UpdateTrustedPeers,
    boilerplate::*,
    peer::{
        Connection, ConnectionId, OutboundFrameQueueLimits, OutboundPostByteBudgets,
        SharedByteBudget, SharedByteLease,
        handles::{PeerHandle, RecoverPostError, connected_from, connecting},
        message::*,
    },
    preauth::{PreauthDeadline, PreauthSourceGate, canonical_remote_ip},
    sampler::LogSampler,
    soranet_handshake_runtime::{SoranetHandshakeRuntime, runtime_from_handshake},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use iroha_config::parameters::actual::{
    Network as Config, SoranetHandshake as ActualSoranetHandshake,
};
use iroha_crypto::{Algorithm, Hash, KeyPair, Signature};
use iroha_data_model::{NetworkId, prelude::Peer};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use iroha_logger::prelude::*;
use iroha_model_base::peer::PeerId;
use iroha_primitives::addr::SocketAddr;
use norito::{
    codec::{Decode, Encode},
    core as ncore,
};
#[cfg(test)]
use std::net::IpAddr;
use std::net::ToSocketAddrs;
#[cfg(feature = "quic")]
use std::sync::OnceLock;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    fmt::Debug,
    io,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
#[cfg(test)]
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
#[cfg(test)]
fn test_network_id(seed: &str) -> NetworkId {
    NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
        seed.as_bytes(),
    )))
}
#[cfg(test)]
fn low_cost_test_soranet_handshake() -> ActualSoranetHandshake {
    let mut handshake = ActualSoranetHandshake::default();
    handshake.pow.difficulty = 1;
    handshake.pow.puzzle.memory_kib =
        std::num::NonZeroU32::new(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB)
            .expect("minimum puzzle memory is non-zero");
    handshake.pow.puzzle.time_cost = std::num::NonZeroU32::new(1).unwrap();
    handshake.pow.puzzle.lanes = std::num::NonZeroU32::new(1).unwrap();
    handshake
}
#[cfg(test)]
fn test_soranet_handshake_config() -> ActualSoranetHandshake {
    static REPLAY_DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    static NEXT_REPLAY_STORE: AtomicU64 = AtomicU64::new(0);
    let replay_dir =
        REPLAY_DIR.get_or_init(|| tempfile::tempdir().expect("test SoraNet replay directory"));
    let store_id = NEXT_REPLAY_STORE.fetch_add(1, Ordering::Relaxed);
    let mut handshake = low_cost_test_soranet_handshake();
    handshake.pow.revocation_store_path = replay_dir
        .path()
        .join(format!("ticket_revocations_{store_id}.norito"))
        .to_string_lossy()
        .into_owned()
        .into();
    handshake
}
#[cfg(test)]
fn test_soranet_handshake_runtime() -> Arc<SoranetHandshakeRuntime> {
    runtime_from_handshake(test_soranet_handshake_config()).expect("test SoraNet handshake runtime")
}
#[cfg(feature = "quic")]
static NEXT_QUIC_CONN_ID: OnceLock<AtomicU64> = OnceLock::new();
static NEXT_TLS_CONN_ID: std::sync::OnceLock<AtomicU64> = std::sync::OnceLock::new();
#[cfg(test)]
const TCP_LISTEN_BACKLOG: i32 = 1024;
type ControlUpdateSender<T> = watch::Sender<Option<Arc<T>>>;
type ControlUpdateReceiver<T> = watch::Receiver<Option<Arc<T>>>;
const HANDSHAKE_UPDATE_CHANNEL_CAPACITY: usize = 1;
// Each control category gets its own single retained snapshot so unrelated
// updates cannot overwrite one another. Store snapshots behind `Arc` so
// receiver cloning never holds the watch read lock while copying a large
// topology, address book, or ACL; synchronous publishers do not wait for a
// full payload clone.
fn control_update_channel<T>() -> (ControlUpdateSender<T>, ControlUpdateReceiver<T>) {
    watch::channel(None)
}
/// Latest source-authority control snapshots awaiting one atomic actor commit.
#[derive(Clone, Debug, Default)]
struct PendingReplySourceAuthority {
    topology: Option<UpdateTopology>,
    validator_dial_roster: Option<message::UpdateValidatorDialRoster>,
    trusted: Option<UpdateTrustedPeers>,
    acl: Option<ValidatedAclUpdate>,
}
impl PendingReplySourceAuthority {
    fn is_empty(&self) -> bool {
        self.topology.is_none()
            && self.validator_dial_roster.is_none()
            && self.trusted.is_none()
            && self.acl.is_none()
    }
}
/// Retained validator-dial authority updates.
///
/// Consensus topology changes use the coupled variant so a newly admitted
/// validator can never be observed as an unmanaged eager-dial peer between two
/// independently scheduled actor updates.
#[derive(Clone, Debug)]
enum ValidatorDialControlUpdate {
    Roster(message::UpdateValidatorDialRoster),
    Topology(message::UpdateValidatorTopology),
}
#[derive(Clone, Debug)]
struct ReplySourceAuthorityProjection {
    protected_sources: HashSet<PeerId>,
    reconciliation_topology: HashSet<PeerId>,
}
/// Deterministic ownership of configured-validator connection establishment.
///
/// The canonical roster defines a balanced tournament: every unordered pair
/// has one preferred dialer, while each node owns either `floor((n - 1) / 2)`
/// or `ceil((n - 1) / 2)` of its pairs.  A standby installs its takeover
/// deadline only when that pair first has an address to dial, so daemon startup
/// work before topology publication cannot consume the failover interval.
#[derive(Debug)]
struct ValidatorDialScheduler {
    configured_roster: BTreeSet<PeerId>,
    roster: BTreeSet<PeerId>,
    standby_not_before: HashMap<PeerId, tokio::time::Instant>,
    takeover_delay: Duration,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValidatorDialRole {
    /// Relay, observer, dynamic, or otherwise unmanaged peer.
    Unmanaged,
    /// This endpoint owns the pair's immediate dial attempt.
    Preferred,
    /// The other endpoint owns the immediate attempt; this endpoint is backup.
    Standby,
}
/// One outbound authentication tenure includes its bounded dial and the
/// configured pre-authentication work, never established-session idleness.
fn checked_outbound_authentication_timeout(
    dial_timeout: Duration,
    preauth_timeout: Duration,
) -> Option<Duration> {
    let timeout = dial_timeout.checked_add(preauth_timeout)?;
    PreauthDeadline::from_now(timeout)?;
    Some(timeout)
}
impl ValidatorDialScheduler {
    fn new(roster: HashSet<PeerId>, takeover_delay: Duration) -> Self {
        let roster: BTreeSet<_> = roster.into_iter().collect();
        Self {
            configured_roster: roster.clone(),
            roster,
            standby_not_before: HashMap::new(),
            takeover_delay,
        }
    }
    fn replace_roster(&mut self, roster: HashSet<PeerId>, self_id: &PeerId) {
        self.roster = roster
            .into_iter()
            .filter(|peer_id| self.configured_roster.contains(peer_id))
            .collect();
        let roster = &self.roster;
        self.standby_not_before.retain(|peer_id, _| {
            Self::role_in(roster, self_id, peer_id) == ValidatorDialRole::Standby
        });
    }
    fn role(&self, self_id: &PeerId, peer_id: &PeerId) -> ValidatorDialRole {
        Self::role_in(&self.roster, self_id, peer_id)
    }
    fn role_in(roster: &BTreeSet<PeerId>, self_id: &PeerId, peer_id: &PeerId) -> ValidatorDialRole {
        if self_id == peer_id || !roster.contains(self_id) || !roster.contains(peer_id) {
            return ValidatorDialRole::Unmanaged;
        }
        let Some(self_rank) = roster.iter().position(|candidate| candidate == self_id) else {
            return ValidatorDialRole::Unmanaged;
        };
        let Some(peer_rank) = roster.iter().position(|candidate| candidate == peer_id) else {
            return ValidatorDialRole::Unmanaged;
        };
        let count = roster.len();
        let forward = (peer_rank + count - self_rank) % count;
        let reverse = count - forward;
        let preferred = forward < reverse || (forward == reverse && self_rank < peer_rank);
        if preferred {
            ValidatorDialRole::Preferred
        } else {
            ValidatorDialRole::Standby
        }
    }
    /// Return the earliest instant at which this endpoint may dial `peer_id`.
    ///
    /// `None` means immediate. Repeated calls retain the first standby deadline;
    /// topology refreshes and malicious address gossip therefore cannot postpone
    /// takeover indefinitely or create additional retry epochs.
    fn not_before(
        &mut self,
        self_id: &PeerId,
        peer_id: &PeerId,
        now: tokio::time::Instant,
        startup_not_before: tokio::time::Instant,
    ) -> Option<tokio::time::Instant> {
        match self.role(self_id, peer_id) {
            ValidatorDialRole::Unmanaged | ValidatorDialRole::Preferred => {
                self.standby_not_before.remove(peer_id);
                None
            }
            ValidatorDialRole::Standby => {
                let base = core::cmp::max(now, startup_not_before);
                Some(
                    *self
                        .standby_not_before
                        .entry(peer_id.clone())
                        .or_insert_with(|| base + self.takeover_delay),
                )
            }
        }
    }
    /// Start a fresh failover epoch after an authenticated session exists.
    fn note_session_established(
        &mut self,
        self_id: &PeerId,
        peer_id: &PeerId,
        now: tokio::time::Instant,
        startup_not_before: tokio::time::Instant,
    ) {
        match self.role(self_id, peer_id) {
            ValidatorDialRole::Standby => {
                let base = core::cmp::max(now, startup_not_before);
                self.standby_not_before
                    .insert(peer_id.clone(), base + self.takeover_delay);
            }
            ValidatorDialRole::Unmanaged | ValidatorDialRole::Preferred => {
                self.standby_not_before.remove(peer_id);
            }
        }
    }
}
#[cfg(test)]
fn bind_reusable_tcp_listener(addrs: &[std::net::SocketAddr]) -> io::Result<TcpListener> {
    let mut last_error = None;
    for addr in addrs {
        match bind_reusable_tcp_listener_addr(*addr) {
            Ok(listener) => return Ok(listener),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no socket addresses resolved for TCP listener",
        )
    }))
}
#[cfg(test)]
fn bind_reusable_tcp_listener_addr(addr: std::net::SocketAddr) -> io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(TCP_LISTEN_BACKLOG)?;
    TcpListener::from_std(socket.into())
}
mod admission;
mod connection_arbitration;
#[cfg(test)]
pub(crate) use connection_arbitration::fixture as reader_arbitration_fixture;
#[cfg(test)]
#[path = "network/tcp_listener_bind_tests.rs"]
mod tcp_listener_bind_tests;
use admission::*;
#[derive(Clone, Debug)]
struct ValidatedAclUpdate {
    allowlist_only: bool,
    allow_keys: Vec<iroha_crypto::PublicKey>,
    deny_keys: Vec<iroha_crypto::PublicKey>,
    allow_nets: Vec<IpNet>,
    deny_nets: Vec<IpNet>,
}
impl ValidatedAclUpdate {
    fn parse(
        message::UpdateAcl {
            allowlist_only,
            allow_keys,
            deny_keys,
            allow_cidrs,
            deny_cidrs,
        }: message::UpdateAcl,
    ) -> Result<Self, String> {
        let (allow_nets, deny_nets) = parse_acl_cidrs(&allow_cidrs, &deny_cidrs)?;
        Ok(Self {
            allowlist_only,
            allow_keys,
            deny_keys,
            allow_nets,
            deny_nets,
        })
    }
}
fn relay_role_from_mode(mode: iroha_config::parameters::actual::RelayMode) -> RelayRole {
    match mode {
        iroha_config::parameters::actual::RelayMode::Hub => RelayRole::Hub,
        iroha_config::parameters::actual::RelayMode::Spoke => RelayRole::Spoke,
        iroha_config::parameters::actual::RelayMode::Disabled
        | iroha_config::parameters::actual::RelayMode::Assist => RelayRole::Disabled,
    }
}
#[cfg(test)]
#[path = "network/runtime_tests.rs"]
mod runtime_tests;
mod net_channel {
    use tokio::sync::mpsc;
    pub type Sender<T> = mpsc::Sender<T>;
    pub type Receiver<T> = mpsc::Receiver<T>;
    pub fn channel_with_capacity<T>(cap: usize) -> (Sender<T>, Receiver<T>) {
        mpsc::channel(cap)
    }
}
/// Count of network posts dropped due to full bounded queue.
static DROPPED_POSTS: AtomicU64 = AtomicU64::new(0);
/// Count of network broadcasts dropped due to full bounded queue.
static DROPPED_BROADCASTS: AtomicU64 = AtomicU64::new(0);
/// High/Low split for bounded queue drops (posts)
static DROPPED_POSTS_HI: AtomicU64 = AtomicU64::new(0);
static DROPPED_POSTS_LO: AtomicU64 = AtomicU64::new(0);
/// High/Low split for bounded queue drops (broadcasts)
static DROPPED_BROADCASTS_HI: AtomicU64 = AtomicU64::new(0);
static DROPPED_BROADCASTS_LO: AtomicU64 = AtomicU64::new(0);
/// Latest observed depth for the high-priority network message queue.
static NETWORK_QUEUE_DEPTH_HIGH: AtomicU64 = AtomicU64::new(0);
/// Latest observed depth for the isolated authoritative-consensus safety queue.
static NETWORK_QUEUE_DEPTH_SAFETY: AtomicU64 = AtomicU64::new(0);
/// Latest observed depth for the semantic-progress network message queue.
static NETWORK_QUEUE_DEPTH_PROGRESS: AtomicU64 = AtomicU64::new(0);
/// Latest observed depth for the low-priority network message queue.
static NETWORK_QUEUE_DEPTH_LOW: AtomicU64 = AtomicU64::new(0);
/// Count of DNS interval-based hostname refreshes performed.
static DNS_REFRESHES: AtomicU64 = AtomicU64::new(0);
/// Count of DNS TTL-based hostname refreshes performed.
static DNS_TTL_REFRESHES: AtomicU64 = AtomicU64::new(0);
/// Count of hostname reconnect successes after a refresh.
static DNS_RECONNECT_SUCCESSES: AtomicU64 = AtomicU64::new(0);
/// Count of hostname resolution/connection failures for hostname peers.
static DNS_RESOLUTION_FAILURES: AtomicU64 = AtomicU64::new(0);
/// Count of scheduled per-address backoffs.
static BACKOFF_SCHEDULED: AtomicU64 = AtomicU64::new(0);
/// Total deferred outbound frames enqueued while peer session was missing.
static DEFERRED_SEND_ENQUEUED: AtomicU64 = AtomicU64::new(0);
/// Total deferred outbound frames dropped due to TTL expiry, stale connection binding, or cap.
static DEFERRED_SEND_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Total reconnect attempts triggered because outbound frames were deferred for missing sessions.
static SESSION_RECONNECT_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Cumulative reconnect retry delay in milliseconds.
static CONNECT_RETRY_MILLIS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Count of inbound SCION connections accepted.
static SCION_INBOUND_ACCEPTED: AtomicU64 = AtomicU64::new(0);
/// Count of outbound SCION connections successfully established.
static SCION_OUTBOUND_SUCCESSES: AtomicU64 = AtomicU64::new(0);
/// Count of accepted connections dropped due to per-IP accept throttle.
static ACCEPT_THROTTLED: AtomicU64 = AtomicU64::new(0);
/// Count of accept throttle bucket evictions (idle or capacity).
static ACCEPT_BUCKET_EVICTIONS: AtomicU64 = AtomicU64::new(0);
/// Current number of active accept throttle buckets (prefix + per-IP).
static ACCEPT_BUCKETS_CURRENT: AtomicU64 = AtomicU64::new(0);
/// Count of prefix bucket cache hits.
static ACCEPT_PREFIX_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
/// Count of prefix bucket cache misses.
static ACCEPT_PREFIX_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
/// Count of prefix throttle rejections.
static ACCEPT_PREFIX_THROTTLED: AtomicU64 = AtomicU64::new(0);
/// Count of prefix throttle allowances.
static ACCEPT_PREFIX_ALLOWED: AtomicU64 = AtomicU64::new(0);
/// Count of per-IP throttle allowances.
static ACCEPT_IP_ALLOWED: AtomicU64 = AtomicU64::new(0);
/// Count of per-IP throttle rejections.
static ACCEPT_IP_THROTTLED: AtomicU64 = AtomicU64::new(0);
/// Count of accepted connections dropped due to `max_incoming` cap.
static INCOMING_CAP_REJECTS: AtomicU64 = AtomicU64::new(0);
/// Count of accepted connections dropped due to `max_total_connections` cap.
static TOTAL_CAP_REJECTS: AtomicU64 = AtomicU64::new(0);
/// Count of accepted connections dropped due to the concurrent pre-auth source cap.
static PREAUTH_SOURCE_CAP_REJECTS: AtomicU64 = AtomicU64::new(0);
/// Count of low-priority post messages throttled by per-peer token buckets.
static LOW_THROTTLED_POSTS: AtomicU64 = AtomicU64::new(0);
/// Count of low-priority broadcast deliveries throttled per peer.
static LOW_THROTTLED_BROADCASTS: AtomicU64 = AtomicU64::new(0);
/// Count of trust-gossip frames skipped because the capability is disabled locally or remotely.
static TRUST_GOSSIP_SKIPPED_CAP_OFF: AtomicU64 = AtomicU64::new(0);
/// Count of inbound messages dropped because subscriber queues are full.
static SUBSCRIBER_QUEUE_FULL: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_QUEUE_FULL_CONSENSUS_SAFETY: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_QUEUE_FULL_CONSENSUS: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_QUEUE_FULL_CONSENSUS_CHUNK: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_QUEUE_FULL_CONTROL: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_QUEUE_FULL_BLOCK_SYNC: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_QUEUE_FULL_TX_GOSSIP: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_QUEUE_FULL_PEER_GOSSIP: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_QUEUE_FULL_HEALTH: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_QUEUE_FULL_OTHER: AtomicU64 = AtomicU64::new(0);
/// Count of inbound frames dropped because no subscriber matches the topic.
static SUBSCRIBER_UNROUTED: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_UNROUTED_CONSENSUS_SAFETY: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_UNROUTED_CONSENSUS: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_UNROUTED_CONSENSUS_CHUNK: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_UNROUTED_CONTROL: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_UNROUTED_BLOCK_SYNC: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_UNROUTED_TX_GOSSIP: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_UNROUTED_PEER_GOSSIP: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_UNROUTED_HEALTH: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBER_UNROUTED_OTHER: AtomicU64 = AtomicU64::new(0);
/// Count of per-peer post channel overflows (bounded per-topic channels).
static POST_OVERFLOWS: AtomicU64 = AtomicU64::new(0);
/// Per-topic frame cap violations
static CAP_VIOL_CONSENSUS: AtomicU64 = AtomicU64::new(0);
static CAP_VIOL_CONSENSUS_SAFETY: AtomicU64 = AtomicU64::new(0);
static CAP_VIOL_CONTROL: AtomicU64 = AtomicU64::new(0);
static CAP_VIOL_BLOCK_SYNC: AtomicU64 = AtomicU64::new(0);
static CAP_VIOL_TX_GOSSIP: AtomicU64 = AtomicU64::new(0);
static CAP_VIOL_PEER_GOSSIP: AtomicU64 = AtomicU64::new(0);
static CAP_VIOL_HEALTH: AtomicU64 = AtomicU64::new(0);
static CAP_VIOL_OTHER: AtomicU64 = AtomicU64::new(0);
// Per-priority breakdown (High/Low) per topic
static POST_OVERFLOWS_HI_CONSENSUS: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_HI_CONSENSUS_SAFETY: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_HI_CONTROL: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_HI_BLOCK_SYNC: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_HI_TX_GOSSIP: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_HI_PEER_GOSSIP: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_HI_HEALTH: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_HI_OTHER: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_LO_CONSENSUS: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_LO_CONSENSUS_SAFETY: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_LO_CONTROL: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_LO_BLOCK_SYNC: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_LO_TX_GOSSIP: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_LO_PEER_GOSSIP: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_LO_HEALTH: AtomicU64 = AtomicU64::new(0);
static POST_OVERFLOWS_LO_OTHER: AtomicU64 = AtomicU64::new(0);
// Jittered exponential backoff for reconnect attempts.
const BACKOFF_INITIAL: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(5);
const SERVICE_MESSAGE_BUDGET: usize = 32;
const INBOUND_PEER_HIGH_BUDGET: usize = 32;
const CONSENSUS_SAFETY_DRAIN_BUDGET: usize = 64;
/// Bound semantic-progress work ahead of ordinary high traffic on each actor turn.
const NETWORK_PROGRESS_ACTOR_DRAIN_BUDGET: usize = 64;
/// At most this many send waiters may sit outside each high-priority actor
/// channel. The byte reservation carried by every waiter is shared with the
/// channel itself, so this is a task-count bound rather than a second payload
/// capacity.
const NETWORK_ACTOR_DEFERRED_MAX: usize = 64;
const NETWORK_HIGH_ACTOR_DRAIN_BASE: usize = 64;
const NETWORK_HIGH_ACTOR_DRAIN_PRESSURED: usize = 512;
const NETWORK_HIGH_ACTOR_DRAIN_SATURATED: usize = 2_048;
/// Domain separating end-to-end relay-origin signatures from every other use
/// of a node's application key.
const RELAY_ORIGIN_SIGNATURE_DOMAIN: &[u8] = b"iroha:p2p:relay-origin:v1\n";
/// Exact first-release BLS-normal node public-key payload size.
const RELAY_NODE_PUBLIC_KEY_BYTES: usize = 48;
/// Exact first-release relay-origin signature size for BLS-normal node identities.
const RELAY_ORIGIN_SIGNATURE_BYTES: usize = Algorithm::BlsNormal.signature_payload_len();
/// Default hop limit for relay forwarding (origin hub hop + spoke hop).
#[cfg(test)]
const DEFAULT_RELAY_TTL: u8 = 8;
// Stagger delay between multi-address dial attempts for the same peer.
// Stagger for parallel dialing is configurable via node config per instance.
fn high_actor_drain_limit(queue_len_after_first_recv: usize) -> usize {
    if queue_len_after_first_recv > 256 {
        NETWORK_HIGH_ACTOR_DRAIN_SATURATED
    } else if queue_len_after_first_recv > 64 {
        NETWORK_HIGH_ACTOR_DRAIN_PRESSURED
    } else {
        NETWORK_HIGH_ACTOR_DRAIN_BASE
    }
}
fn should_stop_high_actor_drain(
    drained: usize,
    drain_limit: usize,
    service_pending: bool,
    shutdown_requested: bool,
) -> bool {
    drained >= drain_limit || service_pending || shutdown_requested
}
#[derive(Clone, Debug, Encode, Decode)]
pub(crate) enum RelayTarget {
    Broadcast,
    Direct(PeerId),
}
#[derive(Clone, Debug, Encode, Decode)]
#[norito(decode_from_slice)]
pub(crate) struct RelayMessage<T> {
    origin: PeerId,
    target: RelayTarget,
    ttl: u8,
    origin_signature: Vec<u8>,
    payload: T,
}
impl<T: norito::NoritoSchema> norito::NoritoSchema for RelayMessage<T> {
    fn nominal_name() -> String {
        norito::schema::identity::generic_name(
            "iroha_p2p::network::RelayMessage",
            &[T::nominal_name()],
        )
    }
}
impl<T: Encode> RelayMessage<T> {
    fn try_new(
        key_pair: &KeyPair,
        target: RelayTarget,
        ttl: u8,
        payload: T,
    ) -> Result<Self, iroha_crypto::error::Error> {
        let origin = PeerId::from(key_pair.public_key().clone());
        ensure_relay_node_identity(&origin)?;
        if let RelayTarget::Direct(target) = &target {
            ensure_relay_node_identity(target)?;
        }
        let digest = relay_origin_signature_digest(&origin, &target, &payload);
        let origin_signature = Signature::try_new(key_pair.private_key(), digest.as_ref())?
            .payload()
            .to_vec();
        Ok(Self {
            origin,
            target,
            ttl,
            origin_signature,
            payload,
        })
    }
    pub(crate) fn new_signed(key_pair: &KeyPair, target: RelayTarget, ttl: u8, payload: T) -> Self {
        Self::try_new(key_pair, target, ttl, payload)
            .expect("a validated local P2P key pair must sign relay-origin material")
    }
    #[cfg(test)]
    fn new(origin: PeerId, target: RelayTarget, ttl: u8, payload: T) -> Self {
        ensure_relay_node_identity(&origin).expect("test relay origin must be BLS-normal");
        if let RelayTarget::Direct(target) = &target {
            ensure_relay_node_identity(target).expect("test relay target must be BLS-normal");
        }
        let origin_signature = vec![0xA5; RELAY_ORIGIN_SIGNATURE_BYTES];
        Self {
            origin,
            target,
            ttl,
            origin_signature,
            payload,
        }
    }
    pub(crate) fn verify_origin_signature(&self) -> Result<(), iroha_crypto::error::Error> {
        ensure_relay_node_identity(&self.origin)?;
        if let RelayTarget::Direct(target) = &self.target {
            ensure_relay_node_identity(target)?;
        }
        if self.origin_signature.len() != RELAY_ORIGIN_SIGNATURE_BYTES {
            return Err(iroha_crypto::error::Error::Other(format!(
                "P2P relay BLS-normal signature is {} bytes; expected {RELAY_ORIGIN_SIGNATURE_BYTES}",
                self.origin_signature.len()
            )));
        }
        let digest = relay_origin_signature_digest(&self.origin, &self.target, &self.payload);
        Signature::try_from_bytes(&self.origin_signature)?
            .verify(self.origin.public_key(), digest.as_ref())
    }
    fn forwarded_with_ttl(&self, ttl: u8) -> Self
    where
        T: Clone,
    {
        let mut forwarded = self.clone();
        forwarded.ttl = ttl;
        forwarded
    }
}
fn ensure_relay_node_identity(origin: &PeerId) -> Result<(), iroha_crypto::error::Error> {
    let algorithm = origin
        .public_key()
        .try_algorithm()
        .map_err(iroha_crypto::error::Error::from)?;
    if algorithm != Algorithm::BlsNormal {
        return Err(iroha_crypto::error::Error::Other(format!(
            "P2P relay node identity must be BLS-normal, found {algorithm:?}"
        )));
    }
    Ok(())
}
fn relay_origin_signature_digest<T: Encode>(
    origin: &PeerId,
    target: &RelayTarget,
    payload: &T,
) -> Hash {
    let origin = origin.encode();
    let target = target.encode();
    let payload = payload.encode();
    let origin_len = u64::try_from(origin.len())
        .expect("an in-memory relay origin length must fit u64")
        .to_le_bytes();
    let target_len = u64::try_from(target.len())
        .expect("an in-memory relay target length must fit u64")
        .to_le_bytes();
    let payload_len = u64::try_from(payload.len())
        .expect("an in-memory relay payload length must fit u64")
        .to_le_bytes();
    Hash::new_from_chunks(&[
        RELAY_ORIGIN_SIGNATURE_DOMAIN,
        &origin_len,
        &origin,
        &target_len,
        &target,
        &payload_len,
        &payload,
    ])
}
/// Return the plaintext wire length of a P2P data frame containing `payload`.
///
/// This accounts for the relay envelope and the `Message::Data` wrapper but
/// excludes encryption overhead (use `frame_plaintext_cap` to apply caps).
pub fn data_frame_wire_len<T: Encode + Clone>(
    origin: &PeerId,
    target: Option<&PeerId>,
    payload: &T,
) -> usize {
    data_frame_wire_len_from_payload_len::<T>(origin, target, payload.encoded_len())
}
/// Materialize a genuinely signed canonical relay/Data frame for cross-crate
/// admission-size regressions. This helper does not authorize or send its payload.
///
/// # Errors
/// Returns identity/signature/codec errors from the actual canonical owners.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn materialized_signed_data_frame_len_for_test<T: Pload>(
    key: &KeyPair,
    target: Option<PeerId>,
    payload: T,
) -> Result<usize, Error> {
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let target = target.map_or(RelayTarget::Broadcast, RelayTarget::Direct);
    let relay = RelayMessage::try_new(key, target, 1, payload)?;
    relay.verify_origin_signature()?;
    crate::peer::materialized_data_message_wire_len(relay).map_err(Error::NoritoCodec)
}

/// Decode a genuinely signed relay under its production inbound payload limits.
///
/// This exercises the owned relay and payload graph without starting a peer.
///
/// # Errors
/// Returns identity, signature, or bounded Norito decode errors.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn signed_relay_decode_with_limits_for_test<T: Pload + message::ClassifyTopic>(
    key: &KeyPair,
    target: PeerId,
    payload: T,
) -> Result<T, Error> {
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let relay = RelayMessage::try_new(key, RelayTarget::Direct(target), 1, payload)?;
    relay.verify_origin_signature()?;
    let encoded = ncore::to_bytes(&relay).map_err(Error::NoritoCodec)?;
    let view = ncore::from_bytes_view(&encoded).map_err(Error::NoritoCodec)?;
    let limits = <RelayMessage<T> as message::ClassifyTopic>::inbound_decode_limits(
        view.as_bytes(),
        encoded.len(),
        view.flags(),
    )
    .map_err(Error::NoritoCodec)?
    .ok_or(Error::Format)?;
    let decoded: RelayMessage<T> =
        ncore::decode_from_bytes_with_limits(&encoded, limits).map_err(Error::NoritoCodec)?;
    decoded.verify_origin_signature()?;
    Ok(decoded.payload)
}

fn checked_len_prefixed(payload_len: usize, flags: u8) -> Option<usize> {
    ncore::len_prefix_len_with_flags(payload_len, flags).checked_add(payload_len)
}
fn peer_id_wire_len_from_raw_key_bytes(raw_key_bytes: usize, flags: u8) -> Option<usize> {
    // PublicKey stores one compact algorithm tag before the algorithm-specific payload.
    let key_bytes = raw_key_bytes.checked_add(1)?;
    let encoded_byte_len = checked_len_prefixed(core::mem::size_of::<u8>(), flags)?;
    let public_key_len = ncore::seq_len_prefix_len(key_bytes)
        .checked_add(key_bytes.checked_mul(encoded_byte_len)?)?;
    checked_len_prefixed(public_key_len, flags)
}
fn byte_sequence_wire_len(bytes: usize) -> Option<usize> {
    // `Vec<u8>` always uses Norito's raw-byte sequence fast path: a fixed-width
    // element count followed by the bytes themselves, regardless of layout flags.
    ncore::seq_len_prefix_len(bytes).checked_add(bytes)
}
fn relay_target_wire_len(target_raw_key_bytes: Option<usize>, flags: u8) -> Option<usize> {
    let discriminant_len = core::mem::size_of::<u32>();
    let Some(target_raw_key_bytes) = target_raw_key_bytes else {
        return Some(discriminant_len);
    };
    discriminant_len.checked_add(checked_len_prefixed(
        peer_id_wire_len_from_raw_key_bytes(target_raw_key_bytes, flags)?,
        flags,
    )?)
}
fn relay_message_wire_payload_len(direct: bool, payload_len: usize, flags: u8) -> Option<usize> {
    let origin_len = peer_id_wire_len_from_raw_key_bytes(RELAY_NODE_PUBLIC_KEY_BYTES, flags)?;
    let target_len = relay_target_wire_len(direct.then_some(RELAY_NODE_PUBLIC_KEY_BYTES), flags)?;
    let ttl_len = core::mem::size_of::<u8>();
    let origin_signature_len = byte_sequence_wire_len(RELAY_ORIGIN_SIGNATURE_BYTES)?;
    let field_lens = [
        origin_len,
        target_len,
        ttl_len,
        origin_signature_len,
        payload_len,
    ];
    field_lens.into_iter().try_fold(0usize, |total, field_len| {
        total.checked_add(checked_len_prefixed(field_len, flags)?)
    })
}
/// Return the plaintext wire length of a canonical direct P2P data frame from
/// an application payload length.
///
/// `T` must be the real application payload type whose serialization produced
/// `payload_len`; it is used only to preserve the outer Norito frame alignment.
/// Arithmetic overflow fails closed as `usize::MAX`.
pub fn direct_data_frame_wire_len_from_payload_len<T>(payload_len: usize) -> usize {
    let flags = ncore::default_encode_flags();
    let Some(relay_len) = relay_message_wire_payload_len(true, payload_len, flags) else {
        return usize::MAX;
    };
    crate::peer::data_message_wire_len_from_payload_len::<RelayMessage<T>>(relay_len)
}
/// Return the plaintext wire length of a canonical broadcast P2P data frame
/// from an application payload length.
///
/// `T` must be the real application payload type whose serialization produced
/// `payload_len`; it is used only to preserve the outer Norito frame alignment.
/// Arithmetic overflow fails closed as `usize::MAX`.
pub fn broadcast_data_frame_wire_len_from_payload_len<T>(payload_len: usize) -> usize {
    let flags = ncore::default_encode_flags();
    let Some(relay_len) = relay_message_wire_payload_len(false, payload_len, flags) else {
        return usize::MAX;
    };
    crate::peer::data_message_wire_len_from_payload_len::<RelayMessage<T>>(relay_len)
}
/// Return the plaintext wire length of a P2P data frame from the canonical
/// bare encoded length of its application payload, without allocating or
/// serializing that payload.
///
/// `T` must be the real application payload type whose serialization produced
/// `payload_len`; it preserves the outer Norito frame alignment. For custom
/// wrappers such as Sumeragi's cached consensus wire value, pass the wrapper's
/// encoded length because those bytes are exactly what its `NoritoSerialize`
/// implementation emits into the relay field. Invalid peer keys or arithmetic
/// overflow fail closed as `usize::MAX`.
pub fn data_frame_wire_len_from_payload_len<T>(
    origin: &PeerId,
    target: Option<&PeerId>,
    payload_len: usize,
) -> usize {
    if ensure_relay_node_identity(origin).is_err() {
        return usize::MAX;
    }
    if target.is_some_and(|target| ensure_relay_node_identity(target).is_err()) {
        return usize::MAX;
    }
    target.map_or_else(
        || broadcast_data_frame_wire_len_from_payload_len::<T>(payload_len),
        |_| direct_data_frame_wire_len_from_payload_len::<T>(payload_len),
    )
}
type WireMessage<T> = RelayMessage<T>;
fn relay_message_payload_field(payload: &[u8], flags: u8) -> Result<&[u8], ncore::Error> {
    const FIELD_COUNT: usize = 5;
    const PAYLOAD_FIELD_INDEX: usize = FIELD_COUNT - 1;
    ncore::validate_header_flags(flags)?;
    let mut remaining = payload;
    for index in 0..FIELD_COUNT {
        let (field_len, prefix_len) = ncore::read_len_from_slice_with_flags(remaining, flags)?;
        let field_end = prefix_len
            .checked_add(field_len)
            .ok_or(ncore::Error::LengthMismatch)?;
        let field = remaining
            .get(prefix_len..field_end)
            .ok_or(ncore::Error::LengthMismatch)?;
        remaining = remaining
            .get(field_end..)
            .ok_or(ncore::Error::LengthMismatch)?;
        if index == PAYLOAD_FIELD_INDEX {
            if !remaining.is_empty() {
                return Err(ncore::Error::LengthMismatch);
            }
            return Ok(field);
        }
    }
    Err(ncore::Error::LengthMismatch)
}
impl<T: message::ClassifyTopic> message::ClassifyTopic for RelayMessage<T> {
    const HAS_INBOUND_DECODE_LIMITS: bool = T::HAS_INBOUND_DECODE_LIMITS;
    fn topic(&self) -> message::Topic {
        self.payload.topic()
    }
    fn admission_class(&self) -> message::TransportAdmissionClass {
        self.payload.admission_class()
    }
    fn inbound_admission_class(
        payload: &[u8],
        flags: u8,
    ) -> Result<message::TransportAdmissionClass, ncore::Error> {
        T::inbound_admission_class(relay_message_payload_field(payload, flags)?, flags)
    }
    fn priority(&self) -> message::Priority {
        self.payload.topic().scheduling_priority()
    }
    fn subscriber_route(&self) -> message::SubscriberRoute {
        self.payload.subscriber_route()
    }
    fn inbound_topic(payload: &[u8], flags: u8) -> Result<Option<message::Topic>, ncore::Error> {
        let nested_payload = relay_message_payload_field(payload, flags)?;
        T::inbound_topic(nested_payload, flags)
    }
    fn inbound_decode_limits(
        payload: &[u8],
        framed_len: usize,
        flags: u8,
    ) -> Result<Option<norito::DecodeLimits>, ncore::Error> {
        if !T::HAS_INBOUND_DECODE_LIMITS {
            return Ok(None);
        }
        let nested_payload = relay_message_payload_field(payload, flags)?;
        T::inbound_decode_limits(nested_payload, framed_len, flags)
    }
    fn is_outbound_allowed(&self) -> bool {
        self.payload.is_outbound_allowed()
    }
}
fn peer_message_channel<T: Pload>(
    cap: core::num::NonZeroUsize,
) -> (
    mpsc::Sender<PeerMessage<WireMessage<T>>>,
    mpsc::Receiver<PeerMessage<WireMessage<T>>>,
) {
    mpsc::channel(cap.get())
}
#[derive(Debug)]
struct DeferredPeerFrame<T: Pload> {
    frame: RelayMessage<T>,
    topic: message::Topic,
    enqueued_at: tokio::time::Instant,
    bound_connection_id: Option<ConnectionId>,
    /// Exact prefix-plus-AEAD stream charge retained by this deferred payload.
    wire_bytes: usize,
    /// Monotonic network-local order used for deterministic global eviction.
    sequence: u128,
    /// Aggregate ownership follows the entry through take/restore and retry.
    _aggregate_lease: SharedByteLease,
}
impl<T: Pload + message::ClassifyTopic> DeferredPeerFrame<T> {
    fn is_progress(&self) -> bool {
        is_reliable_progress_route(
            self.topic,
            message::ClassifyTopic::subscriber_route(&self.frame.payload),
        )
    }
}
const DEFERRED_SAFETY_BURST_MAX: u8 = 4;
const DEFERRED_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const DEFERRED_RETRY_PEER_BUDGET: usize = 32;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SubscriberProgressClass {
    Lane,
    Bulk,
}
/// Stable scheduling class for a reliable progress route.
///
/// Consensus producers use the same classification as the network actor so a
/// blocked bulk stream cannot accidentally share FIFO or reservation state
/// with safety and lane traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReliableProgressClass {
    /// Votes, quorum certificates, timeout evidence, and proposals.
    Safety,
    /// Small consensus-control messages.
    Lane,
    /// Payload chunks, certified bodies, and block-sync responses.
    Bulk,
}
/// Maximum number of lane-relay envelopes whose actor handoff one local
/// broadcaster may retain concurrently.
///
/// The lane-relay producer imports this constant directly. Keeping the queue
/// bound here makes it part of the actor waiter geometry instead of a second,
/// independently maintained assumption.
pub const RELIABLE_PROGRESS_LANE_RELAY_OWNER_CAPACITY: usize = 64;
/// Maximum number of exact-output actor calls exposed for one target and
/// scheduling class by the Sumeragi worker at a time.
pub const RELIABLE_PROGRESS_EXACT_OUTPUT_PRODUCERS_PER_SOURCE: usize = 1;
/// Complete local-producer waiter reserve for one authenticated target and
/// actor scheduling class.
///
/// The bound covers the lane-relay owner queue and the Sumeragi exact-output
/// scheduler. Both producer families have fixed, code-owned geometry.
const RELIABLE_PROGRESS_WAITERS_PER_SOURCE: usize = RELIABLE_PROGRESS_LANE_RELAY_OWNER_CAPACITY
    + RELIABLE_PROGRESS_EXACT_OUTPUT_PRODUCERS_PER_SOURCE;
fn subscriber_progress_class(
    topic: message::Topic,
    route: message::SubscriberRoute,
) -> Option<SubscriberProgressClass> {
    match (topic, route) {
        (message::Topic::Consensus, _) => Some(SubscriberProgressClass::Lane),
        (
            message::Topic::ConsensusPayload
            | message::Topic::ConsensusChunk
            | message::Topic::BlockSync,
            _,
        ) => Some(SubscriberProgressClass::Bulk),
        _ => None,
    }
}
/// Classify one topic/consumer route accepted by reliable progress admission.
///
/// Returns `None` for traffic that the reliable actor corridor would reject.
#[must_use]
pub fn reliable_progress_class(
    topic: message::Topic,
    route: message::SubscriberRoute,
) -> Option<ReliableProgressClass> {
    if matches!(topic, message::Topic::ConsensusSafety) {
        return Some(ReliableProgressClass::Safety);
    }
    match subscriber_progress_class(topic, route)? {
        SubscriberProgressClass::Lane => Some(ReliableProgressClass::Lane),
        SubscriberProgressClass::Bulk => Some(ReliableProgressClass::Bulk),
    }
}
#[derive(Debug)]
struct DeferredPeerFrameQueue<T: Pload> {
    /// Ordinary deferred traffic within the aggregate per-peer cap.
    by_peer: HashMap<PeerId, VecDeque<DeferredPeerFrame<T>>>,
    /// Authoritative-consensus safety traffic, protected from ordinary eviction.
    safety_by_peer: HashMap<PeerId, VecDeque<DeferredPeerFrame<T>>>,
    max_per_peer: usize,
    max_bytes_per_peer: usize,
    max_bytes_total: usize,
    ordinary_max_bytes_total: usize,
    safety_reserve_bytes: usize,
    frame_queue_overhead_bytes: usize,
    aggregate_budget: Arc<SharedByteBudget>,
    /// Persistent per-peer debt bounding safety service ahead of ordinary progress.
    safety_burst_by_peer: HashMap<PeerId, u8>,
    /// Fair retry ring for live peers whose topic channel was full.
    retry_peers: VecDeque<PeerId>,
    /// Duplicate guard for `retry_peers`.
    retry_members: HashSet<PeerId>,
    next_sequence: u128,
    ttl: Duration,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeferredEnqueueOutcome {
    expired: usize,
    overflow: usize,
    enqueued: bool,
}
fn admitted_deferred_wire_bytes(
    counted: Result<usize, ncore::Error>,
    max_bytes_per_peer: usize,
) -> Option<usize> {
    counted
        .ok()
        .filter(|wire_bytes| *wire_bytes <= max_bytes_per_peer)
}
impl<T: Pload + message::ClassifyTopic> DeferredPeerFrameQueue<T> {
    #[cfg(test)]
    fn new(max_per_peer: usize, max_bytes_per_peer: usize, ttl: Duration) -> Self {
        let safety_reserve_bytes = max_bytes_per_peer.min(usize::MAX / 2);
        Self::new_with_total(
            max_per_peer,
            max_bytes_per_peer,
            usize::MAX,
            safety_reserve_bytes,
            crate::frame_queue_charge(0).expect("default deferred-frame overhead must fit"),
            ttl,
        )
        .expect("unbounded test deferred-send geometry must fit")
    }
    fn new_with_total(
        max_per_peer: usize,
        max_bytes_per_peer: usize,
        max_bytes_total: usize,
        safety_reserve_bytes: usize,
        frame_queue_overhead_bytes: usize,
        ttl: Duration,
    ) -> Option<Self> {
        let ordinary_max_bytes = max_bytes_total.checked_sub(safety_reserve_bytes)?;
        Some(Self {
            by_peer: HashMap::new(),
            safety_by_peer: HashMap::new(),
            max_per_peer: max_per_peer.max(1),
            max_bytes_per_peer: max_bytes_per_peer.max(1),
            max_bytes_total,
            ordinary_max_bytes_total: ordinary_max_bytes,
            safety_reserve_bytes,
            frame_queue_overhead_bytes,
            aggregate_budget: SharedByteBudget::new(ordinary_max_bytes, safety_reserve_bytes)?,
            safety_burst_by_peer: HashMap::new(),
            retry_peers: VecDeque::new(),
            retry_members: HashSet::new(),
            next_sequence: 0,
            ttl,
        })
    }
    fn retained_wire_bytes(entries: &VecDeque<DeferredPeerFrame<T>>) -> Option<usize> {
        entries
            .iter()
            .try_fold(0usize, |total, entry| total.checked_add(entry.wire_bytes))
    }
    fn retained_wire_bytes_by_peer(
        queues: &HashMap<PeerId, VecDeque<DeferredPeerFrame<T>>>,
    ) -> Option<usize> {
        queues.values().try_fold(0usize, |total, entries| {
            total.checked_add(Self::retained_wire_bytes(entries)?)
        })
    }
    fn prune_expired(
        entries: &mut VecDeque<DeferredPeerFrame<T>>,
        now: tokio::time::Instant,
        ttl: Duration,
    ) -> usize {
        let before = entries.len();
        entries.retain(|entry| {
            entry.is_progress()
                || (!ttl.is_zero() && now.saturating_duration_since(entry.enqueued_at) <= ttl)
        });
        before.saturating_sub(entries.len())
    }
    fn prune_all_expired(&mut self, now: tokio::time::Instant) -> usize {
        let mut dropped = 0usize;
        self.by_peer.retain(|_, entries| {
            dropped = dropped.saturating_add(Self::prune_expired(entries, now, self.ttl));
            !entries.is_empty()
        });
        self.safety_by_peer.retain(|_, entries| {
            dropped = dropped.saturating_add(Self::prune_expired(entries, now, self.ttl));
            !entries.is_empty()
        });
        self.safety_burst_by_peer.retain(|peer_id, _| {
            self.by_peer.contains_key(peer_id) || self.safety_by_peer.contains_key(peer_id)
        });
        self.retry_peers.retain(|peer_id| {
            self.by_peer.contains_key(peer_id) || self.safety_by_peer.contains_key(peer_id)
        });
        self.retry_members.retain(|peer_id| {
            self.by_peer.contains_key(peer_id) || self.safety_by_peer.contains_key(peer_id)
        });
        dropped
    }
    fn peer_retained(&self, peer_id: &PeerId) -> Option<(usize, usize, usize, usize)> {
        let safety = self.safety_by_peer.get(peer_id);
        let ordinary = self.by_peer.get(peer_id);
        let safety_len = safety.map_or(0, VecDeque::len);
        let ordinary_len = ordinary.map_or(0, VecDeque::len);
        let safety_bytes = safety.map_or(Some(0), Self::retained_wire_bytes)?;
        let ordinary_bytes = ordinary.map_or(Some(0), Self::retained_wire_bytes)?;
        Some((
            safety_len.checked_add(ordinary_len)?,
            safety_bytes.checked_add(ordinary_bytes)?,
            safety_len,
            safety_bytes,
        ))
    }
    fn peer_progress_class_present(
        &self,
        peer_id: &PeerId,
        class: SubscriberProgressClass,
    ) -> bool {
        self.by_peer.get(peer_id).is_some_and(|entries| {
            entries.iter().any(|entry| {
                subscriber_progress_class(
                    entry.topic,
                    message::ClassifyTopic::subscriber_route(&entry.frame.payload),
                ) == Some(class)
            })
        })
    }
    fn progress_count_capacity(
        &self,
        peer_id: &PeerId,
        topic: message::Topic,
        route: message::SubscriberRoute,
    ) -> usize {
        let safety_present = self
            .safety_by_peer
            .get(peer_id)
            .is_some_and(|entries| !entries.is_empty());
        let lane_present = self.peer_progress_class_present(peer_id, SubscriberProgressClass::Lane);
        let bulk_present = self.peer_progress_class_present(peer_id, SubscriberProgressClass::Bulk);
        let incoming = if matches!(topic, message::Topic::ConsensusSafety) {
            None
        } else {
            subscriber_progress_class(topic, route)
        };
        let missing_other_classes = match incoming {
            None => usize::from(!lane_present).saturating_add(usize::from(!bulk_present)),
            Some(SubscriberProgressClass::Lane) => {
                usize::from(!safety_present).saturating_add(usize::from(!bulk_present))
            }
            Some(SubscriberProgressClass::Bulk) => {
                usize::from(!safety_present).saturating_add(usize::from(!lane_present))
            }
        };
        let reserved = missing_other_classes.min(self.max_per_peer.saturating_sub(1));
        self.max_per_peer.saturating_sub(reserved).max(1)
    }
    fn pop_peer_oldest_matching(
        &mut self,
        peer_id: &PeerId,
        safety: bool,
        evictable: impl Fn(&DeferredPeerFrame<T>) -> bool,
    ) -> bool {
        let queues = if safety {
            &mut self.safety_by_peer
        } else {
            &mut self.by_peer
        };
        let Some(entries) = queues.get_mut(peer_id) else {
            return false;
        };
        let popped = entries
            .iter()
            .position(evictable)
            .and_then(|index| entries.remove(index))
            .is_some();
        if entries.is_empty() {
            queues.remove(peer_id);
        }
        popped
    }
    fn oldest_global_entry(
        &self,
        safety: bool,
        evictable: impl Fn(&DeferredPeerFrame<T>) -> bool,
    ) -> Option<(PeerId, usize)> {
        let queues = if safety {
            &self.safety_by_peer
        } else {
            &self.by_peer
        };
        queues
            .iter()
            .filter_map(|(peer_id, entries)| {
                entries
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| evictable(entry))
                    .min_by_key(|(_, entry)| entry.sequence)
                    .map(|(index, entry)| (peer_id.clone(), index, entry.sequence))
            })
            .min_by_key(|(_, _, sequence)| *sequence)
            .map(|(peer_id, index, _)| (peer_id, index))
    }
    fn pop_global_oldest_matching(
        &mut self,
        safety: bool,
        evictable: impl Fn(&DeferredPeerFrame<T>) -> bool,
    ) -> bool {
        let Some((peer_id, index)) = self.oldest_global_entry(safety, evictable) else {
            return false;
        };
        let queues = if safety {
            &mut self.safety_by_peer
        } else {
            &mut self.by_peer
        };
        let Some(entries) = queues.get_mut(&peer_id) else {
            return false;
        };
        let removed = entries.remove(index).is_some();
        if entries.is_empty() {
            queues.remove(&peer_id);
        }
        removed
    }
    fn enqueue(
        &mut self,
        peer_id: PeerId,
        frame: RelayMessage<T>,
        topic: message::Topic,
        bound_connection_id: Option<ConnectionId>,
        now: tokio::time::Instant,
    ) -> DeferredEnqueueOutcome {
        let counted_wire_bytes = crate::peer::checked_data_message_wire_len(&frame)
            .ok()
            .and_then(|plaintext| plaintext.checked_add(self.frame_queue_overhead_bytes));
        let Some(wire_bytes) = admitted_deferred_wire_bytes(
            counted_wire_bytes.ok_or(ncore::Error::LengthMismatch),
            self.max_bytes_per_peer,
        ) else {
            return DeferredEnqueueOutcome {
                expired: 0,
                overflow: 1,
                enqueued: false,
            };
        };
        if wire_bytes > self.max_bytes_total {
            return DeferredEnqueueOutcome {
                expired: 0,
                overflow: 1,
                enqueued: false,
            };
        }
        let Some(next_sequence) = self.next_sequence.checked_add(1) else {
            return DeferredEnqueueOutcome {
                expired: 0,
                overflow: 1,
                enqueued: false,
            };
        };
        let sequence = self.next_sequence;
        self.next_sequence = next_sequence;
        let expired = self.prune_all_expired(now);
        if self.peer_retained(&peer_id).is_none() {
            return DeferredEnqueueOutcome {
                expired,
                overflow: 1,
                enqueued: false,
            };
        }
        let is_safety = matches!(topic, message::Topic::ConsensusSafety);
        let route = message::ClassifyTopic::subscriber_route(&frame.payload);
        let is_progress = is_reliable_progress_route(topic, route);
        let count_capacity = if is_progress {
            self.progress_count_capacity(&peer_id, topic, route)
        } else {
            self.max_per_peer
        };
        if !is_safety && wire_bytes > self.ordinary_max_bytes_total {
            return DeferredEnqueueOutcome {
                expired,
                overflow: 1,
                enqueued: false,
            };
        }
        if is_safety
            && Self::retained_wire_bytes_by_peer(&self.safety_by_peer)
                .and_then(|retained| retained.checked_add(wire_bytes))
                .is_none_or(|required| required > self.safety_reserve_bytes)
        {
            return DeferredEnqueueOutcome {
                expired,
                overflow: 1,
                enqueued: false,
            };
        }
        let mut overflow = 0usize;
        loop {
            let Some((retained_len, retained_bytes, _, _)) = self.peer_retained(&peer_id) else {
                return DeferredEnqueueOutcome {
                    expired,
                    overflow: overflow.saturating_add(1),
                    enqueued: false,
                };
            };
            if retained_len < count_capacity
                && retained_bytes
                    .checked_add(wire_bytes)
                    .is_some_and(|required| required <= self.max_bytes_per_peer)
            {
                break;
            }
            let evicted =
                self.pop_peer_oldest_matching(&peer_id, false, |entry| !entry.is_progress());
            if !evicted {
                return DeferredEnqueueOutcome {
                    expired,
                    overflow: overflow.saturating_add(1),
                    enqueued: false,
                };
            }
            overflow = overflow.saturating_add(1);
        }
        let aggregate_lease = loop {
            if let Some(lease) = self.aggregate_budget.try_reserve(wire_bytes, is_safety) {
                break lease;
            }
            let evicted = !is_safety
                && is_progress
                && self.pop_global_oldest_matching(false, |entry| !entry.is_progress());
            if !evicted {
                return DeferredEnqueueOutcome {
                    expired,
                    overflow: overflow.saturating_add(1),
                    enqueued: false,
                };
            }
            overflow = overflow.saturating_add(1);
        };
        let entry = DeferredPeerFrame {
            frame,
            topic,
            enqueued_at: now,
            bound_connection_id,
            wire_bytes,
            sequence,
            _aggregate_lease: aggregate_lease,
        };
        if is_safety {
            self.safety_by_peer
                .entry(peer_id)
                .or_default()
                .push_back(entry);
        } else {
            self.by_peer.entry(peer_id).or_default().push_back(entry);
        }
        DeferredEnqueueOutcome {
            expired,
            overflow,
            enqueued: true,
        }
    }
    fn retain_peers(&mut self, allowed: &HashSet<PeerId>) -> usize {
        let mut dropped = 0usize;
        self.by_peer.retain(|peer_id, entries| {
            if !allowed.contains(peer_id) {
                dropped = dropped.saturating_add(entries.len());
                return false;
            }
            !entries.is_empty()
        });
        self.safety_by_peer.retain(|peer_id, entries| {
            if !allowed.contains(peer_id) {
                dropped = dropped.saturating_add(entries.len());
                return false;
            }
            !entries.is_empty()
        });
        self.retain_live_scheduling_metadata();
        dropped
    }
    fn remove_peer(&mut self, peer_id: &PeerId) -> usize {
        let mut dropped = 0usize;
        for queues in [&mut self.by_peer, &mut self.safety_by_peer] {
            if let Some(entries) = queues.remove(peer_id) {
                dropped = dropped.saturating_add(entries.len());
            }
        }
        self.retain_live_scheduling_metadata();
        dropped
    }
    fn retain_live_scheduling_metadata(&mut self) {
        self.safety_burst_by_peer.retain(|peer_id, _| {
            self.by_peer.contains_key(peer_id) || self.safety_by_peer.contains_key(peer_id)
        });
        self.retry_peers.retain(|peer_id| {
            self.by_peer.contains_key(peer_id) || self.safety_by_peer.contains_key(peer_id)
        });
        self.retry_members.retain(|peer_id| {
            self.by_peer.contains_key(peer_id) || self.safety_by_peer.contains_key(peer_id)
        });
    }
    /// Release `peer_id` work from one retired volatile connection tenure.
    ///
    /// Deferred frames remain owned by their semantic peer. Removing only the
    /// retired tenure binding lets a later live tenure service the same exact
    /// frame without manufacturing or updating a reply capability.
    fn release_retired_tenure_binding(&mut self, peer_id: &PeerId, tenure: ConnectionId) -> usize {
        let mut cleared = 0usize;
        for queues in [&mut self.safety_by_peer, &mut self.by_peer] {
            if let Some(entries) = queues.get_mut(peer_id) {
                for entry in entries {
                    if entry.bound_connection_id == Some(tenure) {
                        entry.bound_connection_id = None;
                        cleared = cleared.saturating_add(1);
                    }
                }
            }
        }
        cleared
    }
    fn take_peer(
        &mut self,
        peer_id: &PeerId,
        now: tokio::time::Instant,
    ) -> (VecDeque<DeferredPeerFrame<T>>, usize) {
        let mut safety = self.safety_by_peer.remove(peer_id).unwrap_or_default();
        let mut ordinary = self.by_peer.remove(peer_id).unwrap_or_default();
        let expired = Self::prune_expired(&mut safety, now, self.ttl)
            .saturating_add(Self::prune_expired(&mut ordinary, now, self.ttl));
        if safety.is_empty() && ordinary.is_empty() {
            self.safety_burst_by_peer.remove(peer_id);
        }
        let mut ordered = VecDeque::with_capacity(safety.len().saturating_add(ordinary.len()));
        let mut safety_burst = self.safety_burst_by_peer.get(peer_id).copied().unwrap_or(0);
        while !safety.is_empty() || !ordinary.is_empty() {
            if !safety.is_empty()
                && (ordinary.is_empty() || safety_burst < DEFERRED_SAFETY_BURST_MAX)
            {
                ordered.push_back(safety.pop_front().expect("checked non-empty"));
                safety_burst = safety_burst.saturating_add(1);
            } else {
                ordered.push_back(ordinary.pop_front().expect("ordinary turn must exist"));
                safety_burst = 0;
            }
        }
        (ordered, expired)
    }
    fn restore_peer(&mut self, peer_id: PeerId, entries: VecDeque<DeferredPeerFrame<T>>) {
        let (safety, ordinary): (VecDeque<_>, VecDeque<_>) = entries
            .into_iter()
            .partition(|entry| matches!(entry.topic, message::Topic::ConsensusSafety));
        if !safety.is_empty() {
            self.safety_by_peer.insert(peer_id.clone(), safety);
        }
        if !ordinary.is_empty() {
            self.by_peer.insert(peer_id, ordinary);
        }
    }
    fn note_served(&mut self, peer_id: &PeerId, topic: message::Topic) {
        if matches!(topic, message::Topic::ConsensusSafety) {
            let burst = self
                .safety_burst_by_peer
                .entry(peer_id.clone())
                .or_default();
            *burst = burst.saturating_add(1).min(DEFERRED_SAFETY_BURST_MAX);
        } else {
            self.safety_burst_by_peer.remove(peer_id);
        }
    }
    fn reset_service_rank(&mut self, peer_id: &PeerId) {
        self.safety_burst_by_peer.remove(peer_id);
    }
    fn schedule_retry(&mut self, peer_id: &PeerId) {
        if self.retry_members.insert(peer_id.clone()) {
            self.retry_peers.push_back(peer_id.clone());
        }
    }
    fn cancel_retry(&mut self, peer_id: &PeerId) {
        if self.retry_members.remove(peer_id) {
            self.retry_peers.retain(|queued| queued != peer_id);
        }
    }
    fn take_retry_batch(&mut self, budget: usize) -> Vec<PeerId> {
        let attempts = budget.min(self.retry_peers.len());
        let mut peers = Vec::with_capacity(attempts);
        for _ in 0..attempts {
            let peer_id = self
                .retry_peers
                .pop_front()
                .expect("retry batch length is bounded by the queue length");
            self.retry_members.remove(&peer_id);
            peers.push(peer_id);
        }
        peers
    }
}
#[cfg(test)]
#[path = "network/data_frame_wire_len_tests.rs"]
mod data_frame_wire_len_tests;
/// Returns the number of dropped post messages (bounded queues only).
///
/// In unbounded mode this counter stays at 0.
pub fn dropped_post_count() -> u64 {
    DROPPED_POSTS.load(Ordering::Relaxed)
}
/// Returns the number of dropped broadcast messages (bounded queues only).
///
/// In unbounded mode this counter stays at 0.
pub fn dropped_broadcast_count() -> u64 {
    DROPPED_BROADCASTS.load(Ordering::Relaxed)
}
/// Returns the number of dropped post messages for High priority.
pub fn dropped_post_high_count() -> u64 {
    DROPPED_POSTS_HI.load(Ordering::Relaxed)
}
/// Returns the number of dropped post messages for Low priority.
pub fn dropped_post_low_count() -> u64 {
    DROPPED_POSTS_LO.load(Ordering::Relaxed)
}
/// Returns the number of dropped broadcast messages for High priority.
pub fn dropped_broadcast_high_count() -> u64 {
    DROPPED_BROADCASTS_HI.load(Ordering::Relaxed)
}
/// Returns the number of dropped broadcast messages for Low priority.
pub fn dropped_broadcast_low_count() -> u64 {
    DROPPED_BROADCASTS_LO.load(Ordering::Relaxed)
}
fn record_network_actor_queue_drop(priority: Priority, broadcast: bool) {
    if broadcast {
        DROPPED_BROADCASTS.fetch_add(1, Ordering::Relaxed);
        match priority {
            Priority::High => DROPPED_BROADCASTS_HI.fetch_add(1, Ordering::Relaxed),
            Priority::Low => DROPPED_BROADCASTS_LO.fetch_add(1, Ordering::Relaxed),
        };
    } else {
        DROPPED_POSTS.fetch_add(1, Ordering::Relaxed);
        match priority {
            Priority::High => DROPPED_POSTS_HI.fetch_add(1, Ordering::Relaxed),
            Priority::Low => DROPPED_POSTS_LO.fetch_add(1, Ordering::Relaxed),
        };
    }
}
#[derive(Debug)]
struct NetworkActorByteBudget {
    max_bytes: usize,
    safety_reserve_bytes: usize,
    retained: Mutex<NetworkActorRetainedBytes>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NetworkActorRetainedBytes {
    total: usize,
    ordinary: usize,
}
impl NetworkActorByteBudget {
    fn new(ordinary_max_bytes: usize, safety_reserve_bytes: usize) -> Option<Arc<Self>> {
        let max_bytes = ordinary_max_bytes.checked_add(safety_reserve_bytes)?;
        Some(Arc::new(Self {
            max_bytes,
            safety_reserve_bytes,
            retained: Mutex::new(NetworkActorRetainedBytes::default()),
        }))
    }
    fn try_reserve(self: &Arc<Self>, bytes: usize, safety: bool) -> Option<NetworkActorByteLease> {
        let mut retained = self
            .retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let total = retained.total.checked_add(bytes)?;
        if total > self.max_bytes {
            return None;
        }
        let ordinary = if safety {
            retained.ordinary
        } else {
            retained.ordinary.checked_add(bytes)?
        };
        if ordinary > self.max_bytes - self.safety_reserve_bytes {
            return None;
        }
        retained.total = total;
        retained.ordinary = ordinary;
        Some(NetworkActorByteLease {
            budget: Arc::clone(self),
            bytes,
            safety,
        })
    }
    #[cfg(test)]
    fn retained(&self) -> NetworkActorRetainedBytes {
        *self
            .retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
#[derive(Debug)]
struct NetworkActorByteLease {
    budget: Arc<NetworkActorByteBudget>,
    bytes: usize,
    safety: bool,
}
impl Drop for NetworkActorByteLease {
    fn drop(&mut self) {
        let mut retained = self
            .budget
            .retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        retained.total = retained
            .total
            .checked_sub(self.bytes)
            .expect("network actor byte lease must have matching total ownership");
        if !self.safety {
            retained.ordinary = retained
                .ordinary
                .checked_sub(self.bytes)
                .expect("ordinary network actor byte lease must have matching ownership");
        }
    }
}
/// One exact tenure of a peer in the accepted relay-aware topology.
///
/// Removal invalidates only this tenure. Re-adding the same public key creates
/// a new generation, so a delayed retry from before the removal cannot cross
/// the remove/re-add boundary by observing the peer id alone.
#[derive(Debug)]
struct ReliableProgressMembership {
    peer_id: PeerId,
    generation: u64,
    active: AtomicBool,
}
impl ReliableProgressMembership {
    fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
    fn cancel(&self) {
        self.active.store(false, Ordering::Release);
    }
}
#[derive(Debug)]
struct ReliableProgressTopology {
    generation: u64,
    members: Vec<Arc<ReliableProgressMembership>>,
}
impl ReliableProgressTopology {
    fn empty() -> Self {
        Self {
            generation: 0,
            members: Vec::new(),
        }
    }
    fn snapshot(&self) -> Vec<Arc<ReliableProgressMembership>> {
        self.members.clone()
    }
    /// Publish one accepted topology transition and cancel only memberships
    /// removed by that transition. Unchanged peers retain their exact token.
    fn reconcile<T>(
        &mut self,
        topology: &T,
        self_id: &PeerId,
    ) -> Vec<Arc<ReliableProgressMembership>>
    where
        for<'a> &'a T: IntoIterator<Item = &'a PeerId>,
    {
        let mut expected: Vec<_> = topology
            .into_iter()
            .filter(|peer_id| *peer_id != self_id)
            .cloned()
            .collect();
        expected.sort();
        expected.dedup();
        let current: Vec<_> = self
            .members
            .iter()
            .map(|membership| membership.peer_id.clone())
            .collect();
        if current == expected {
            return Vec::new();
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .expect("reliable topology generation cannot wrap while live ownership exists");
        let mut prior: HashMap<_, _> = self
            .members
            .drain(..)
            .map(|membership| (membership.peer_id.clone(), membership))
            .collect();
        let mut members = Vec::with_capacity(expected.len());
        for peer_id in expected {
            if let Some(membership) = prior.remove(&peer_id) {
                members.push(membership);
            } else {
                members.push(Arc::new(ReliableProgressMembership {
                    peer_id,
                    generation: next_generation,
                    active: AtomicBool::new(true),
                }));
            }
        }
        let removed = prior.into_values().collect::<Vec<_>>();
        for membership in &removed {
            membership.cancel();
        }
        self.generation = next_generation;
        self.members = members;
        removed
    }
}
/// One exact authenticated connection tenure which may carry a reply to a
/// semantic origin reached through that transport peer.
#[derive(Debug)]
struct ReliableReplyRouteTenure {
    owner: Arc<()>,
    /// Retains the exact PeerId-keyed source owner after transport teardown.
    _source_credits: crate::peer::message::AuthenticatedSourceCredits,
    delivery_peer: PeerId,
    connection_id: ConnectionId,
    connection_ordinal: u128,
    source_capacity: usize,
    /// Inbound deliveries may mint capabilities until the peer producer has
    /// closed and every already-dispatched local delivery has completed.
    delivery_active: AtomicBool,
    /// Outbound admission ends as soon as this connection stops being the
    /// source's current writer. It never reopens for this tenure.
    reply_writable: AtomicBool,
    /// Exact receiver-completion fence shared with the peer dispatch lanes.
    delivery_drain: Arc<InboundDeliveryDrain>,
    /// Prevents duplicate termination notices from spawning duplicate waiters.
    termination_seen: AtomicBool,
}
impl ReliableReplyRouteTenure {
    fn is_active(&self) -> bool {
        self.delivery_active.load(Ordering::Acquire)
    }
    fn is_reply_writable(&self) -> bool {
        self.is_active() && self.reply_writable.load(Ordering::Acquire)
    }
    fn mark_draining(&self) {
        self.reply_writable.store(false, Ordering::Release);
    }
    fn mark_termination_seen(&self) -> bool {
        !self.termination_seen.swap(true, Ordering::AcqRel)
    }
    fn cancel(&self) {
        self.reply_writable.store(false, Ordering::Release);
        self.delivery_active.store(false, Ordering::Release);
    }
}
/// Immutable actor-minted binding between one local delivery occurrence and
/// the exact authenticated connection tenure which created it.
///
/// The weak tenure reference avoids a cycle: a route keeps both the tenure and
/// this binding alive, while the binding proves that neither the tenure nor
/// actor owner was substituted after minting. No history-sized registry is
/// required to validate that intrinsic relationship.
#[derive(Debug)]
struct ReliableReplyDeliveryBinding {
    owner: Arc<()>,
    minting_tenure: Weak<ReliableReplyRouteTenure>,
    semantic_target: PeerId,
    delivery_ordinal: u128,
}
/// Opaque return route attached to an authenticated inbound P2P message.
///
/// The semantic target can differ from the authenticated delivery peer when a
/// trusted hub relays the request. The route is valid only for the exact
/// authenticated connection tenure which delivered that request; callers
/// cannot construct or retarget it.
#[derive(Clone)]
pub struct NetworkReplyRoute {
    semantic_target: PeerId,
    tenure: Arc<ReliableReplyRouteTenure>,
    delivery_ordinal: u128,
    delivery_binding: Arc<ReliableReplyDeliveryBinding>,
    /// Sealed from the immutable delivery tuple when this private capability is minted.
    process_local_identity: Hash,
    /// Shared immutable source identity; obtaining or cloning a key neither
    /// rehashes its peer nor allocates another source owner.
    source_key: NetworkReplySourceKey,
}
/// Test-only authority for minting opaque authenticated reply-route tenures.
///
/// This fixture is absent from normal builds. It lets dependent-crate tests
/// exercise capability preservation and per-source delivery updates while
/// keeping [`NetworkReplyRoute`]'s production constructor private.
#[cfg(any(test, feature = "test-fixtures"))]
pub struct NetworkReplyRouteTestFixture {
    owner: Arc<()>,
    delivery_peer: PeerId,
    next_connection_id: ConnectionId,
    next_connection_ordinal: u128,
    next_delivery_ordinal: u128,
    source_capacity: usize,
}
#[cfg(any(test, feature = "test-fixtures"))]
impl NetworkReplyRouteTestFixture {
    /// Create an isolated actor authority whose routes are delivered through
    /// `delivery_peer`.
    #[must_use]
    pub fn new(delivery_peer: PeerId) -> Self {
        Self::with_source_capacity(delivery_peer, 8)
    }
    /// Create an isolated actor authority with an explicit authenticated-source bound.
    #[must_use]
    pub fn with_source_capacity(delivery_peer: PeerId, source_capacity: usize) -> Self {
        assert!(
            source_capacity > 0,
            "test reply-route source capacity must be non-zero"
        );
        Self {
            owner: Arc::new(()),
            delivery_peer,
            next_connection_id: 0,
            next_connection_ordinal: 0,
            next_delivery_ordinal: 0,
            source_capacity,
        }
    }
    /// Mint the next live authenticated connection tenure for one semantic
    /// reply target.
    ///
    /// Successive calls produce strictly ordered tenures owned by the same
    /// synthetic actor, matching production reconnect semantics.
    #[must_use]
    pub fn mint(&mut self, semantic_target: PeerId) -> NetworkReplyRoute {
        let delivery_peer = self.delivery_peer.clone();
        self.mint_via(semantic_target, delivery_peer)
    }
    /// Mint the next live tenure through an explicitly selected delivery peer.
    ///
    /// One production network actor owns routes for every concurrently live
    /// peer connection. This variant lets adversarial tests reproduce fallback
    /// from a cancelled newer hub connection to an older hub which stayed live.
    #[must_use]
    pub fn mint_via(
        &mut self,
        semantic_target: PeerId,
        delivery_peer: PeerId,
    ) -> NetworkReplyRoute {
        let connection_id = self.next_connection_id;
        self.next_connection_id = connection_id
            .checked_add(1)
            .expect("test reply-route connection id cannot wrap");
        let connection_ordinal = self.next_connection_ordinal;
        self.next_connection_ordinal = connection_ordinal
            .checked_add(1)
            .expect("test reply-route connection ordinal cannot wrap");
        let delivery_ordinal = self.next_delivery_ordinal;
        self.next_delivery_ordinal = delivery_ordinal
            .checked_add(1)
            .expect("test reply-route delivery ordinal cannot wrap");
        NetworkReplyRoute::new(
            semantic_target,
            Arc::new(ReliableReplyRouteTenure {
                owner: Arc::clone(&self.owner),
                _source_credits: crate::peer::message::AuthenticatedSourceCredits::new(1),
                delivery_peer,
                connection_id,
                connection_ordinal,
                source_capacity: self.source_capacity,
                delivery_active: AtomicBool::new(true),
                reply_writable: AtomicBool::new(true),
                delivery_drain: InboundDeliveryDrain::completed_for_test(),
                termination_seen: AtomicBool::new(false),
            }),
            delivery_ordinal,
        )
    }
    /// Mint a later delivery on the exact same authenticated connection tenure.
    ///
    /// Returns `None` when `prior` belongs to another fixture. The new
    /// capability has the same source and tenure but a strictly later
    /// actor-global delivery ordinal.
    #[must_use]
    pub fn redeliver(&mut self, prior: &NetworkReplyRoute) -> Option<NetworkReplyRoute> {
        if !Arc::ptr_eq(&self.owner, &prior.tenure.owner)
            || prior.validate_delivery_binding().is_err()
        {
            return None;
        }
        let delivery_ordinal = self.next_delivery_ordinal;
        self.next_delivery_ordinal = delivery_ordinal
            .checked_add(1)
            .expect("test reply-route delivery ordinal cannot wrap");
        Some(NetworkReplyRoute::new(
            prior.semantic_target.clone(),
            Arc::clone(&prior.tenure),
            delivery_ordinal,
        ))
    }
    /// Forge an adversarial capability which reuses `prior`'s immutable
    /// delivery binding under a distinct connection tenure.
    ///
    /// This exists only for cross-crate rejection tests. Production minting
    /// never substitutes the tenure in an actor-minted delivery binding.
    /// Returns `None` when `prior` belongs to another fixture authority.
    #[must_use]
    pub fn forge_equal_ordinal_different_tenure(
        &mut self,
        prior: &NetworkReplyRoute,
        semantic_target: PeerId,
        delivery_peer: PeerId,
    ) -> Option<NetworkReplyRoute> {
        if !Arc::ptr_eq(&self.owner, &prior.tenure.owner)
            || prior.validate_delivery_binding().is_err()
        {
            return None;
        }
        let connection_id = self.next_connection_id;
        self.next_connection_id = connection_id
            .checked_add(1)
            .expect("test reply-route connection id cannot wrap");
        let connection_ordinal = self.next_connection_ordinal;
        self.next_connection_ordinal = connection_ordinal
            .checked_add(1)
            .expect("test reply-route connection ordinal cannot wrap");
        let tenure = Arc::new(ReliableReplyRouteTenure {
            owner: Arc::clone(&self.owner),
            _source_credits: crate::peer::message::AuthenticatedSourceCredits::new(1),
            delivery_peer,
            connection_id,
            connection_ordinal,
            source_capacity: self.source_capacity,
            delivery_active: AtomicBool::new(true),
            reply_writable: AtomicBool::new(true),
            delivery_drain: InboundDeliveryDrain::completed_for_test(),
            termination_seen: AtomicBool::new(false),
        });
        let mut forged = NetworkReplyRoute::new(semantic_target, tenure, prior.delivery_ordinal);
        // Keep projections bound to the forged tuple; only the intrinsic
        // delivery binding is substituted so ordinary validation rejects it.
        forged.delivery_binding = Arc::clone(&prior.delivery_binding);
        Some(forged)
    }
    /// Forge an adversarial capability which reuses `prior`'s actor-global
    /// connection ordinal under a distinct, otherwise valid tenure.
    ///
    /// This exists only for cross-crate rejection tests. Production minting
    /// allocates each connection ordinal once. Returns `None` when `prior`
    /// belongs to another fixture authority.
    #[must_use]
    pub fn forge_equal_connection_ordinal_different_tenure(
        &mut self,
        prior: &NetworkReplyRoute,
        semantic_target: PeerId,
        delivery_peer: PeerId,
    ) -> Option<NetworkReplyRoute> {
        if !Arc::ptr_eq(&self.owner, &prior.tenure.owner)
            || prior.validate_delivery_binding().is_err()
        {
            return None;
        }
        let connection_id = self.next_connection_id;
        self.next_connection_id = connection_id
            .checked_add(1)
            .expect("test reply-route connection id cannot wrap");
        let delivery_ordinal = self.next_delivery_ordinal;
        self.next_delivery_ordinal = delivery_ordinal
            .checked_add(1)
            .expect("test reply-route delivery ordinal cannot wrap");
        let tenure = Arc::new(ReliableReplyRouteTenure {
            owner: Arc::clone(&self.owner),
            _source_credits: crate::peer::message::AuthenticatedSourceCredits::new(1),
            delivery_peer,
            connection_id,
            connection_ordinal: prior.tenure.connection_ordinal,
            source_capacity: self.source_capacity,
            delivery_active: AtomicBool::new(true),
            reply_writable: AtomicBool::new(true),
            delivery_drain: InboundDeliveryDrain::completed_for_test(),
            termination_seen: AtomicBool::new(false),
        });
        Some(NetworkReplyRoute::new(
            semantic_target,
            tenure,
            delivery_ordinal,
        ))
    }
    /// Cancel a route minted by this fixture, matching actor-side connection
    /// teardown. Returns `false` for a route owned by another fixture.
    pub fn retire(&self, route: &NetworkReplyRoute) -> bool {
        if !Arc::ptr_eq(&self.owner, &route.tenure.owner) {
            return false;
        }
        route.tenure.cancel();
        true
    }
    /// Make an owned route delivery-active but reply-unwritable.
    ///
    /// This models the interval after the actor has begun connection teardown
    /// but before final local receiver ownership retires the tenure. It is
    /// intentionally distinct from [`Self::retire`], which also removes local
    /// delivery authority. Returns `false` for a foreign or already-retired
    /// route.
    pub fn mark_reply_unwritable_while_delivery_active(&self, route: &NetworkReplyRoute) -> bool {
        if !Arc::ptr_eq(&self.owner, &route.tenure.owner) || !route.is_active() {
            return false;
        }
        route.tenure.mark_draining();
        debug_assert!(route.is_active());
        debug_assert!(!route.is_reply_writable());
        true
    }
}
/// Opaque fairness key for replies sharing one authenticated transport source.
///
/// The key deliberately excludes the semantic origin and connection tenure:
/// every origin relayed by the same authenticated peer shares one source lane,
/// including after that peer reconnects. Actor identity is retained opaquely so
/// keys minted by independent network actors can never alias. This is a
/// process-local scheduling key and must not enter wire or consensus state.
#[derive(Clone)]
pub struct NetworkReplySourceKey {
    identity: Arc<NetworkReplySourceIdentity>,
}
/// Immutable source tuple owned independently of delivery and connection state.
/// Different deliveries may allocate equal tuples; pointer equality of this
/// allocation never defines source equality or ordering.
struct NetworkReplySourceIdentity {
    owner: Arc<()>,
    authenticated_via: PeerId,
    process_local_identity: Hash,
}
impl NetworkReplySourceKey {
    fn owner_address(&self) -> usize {
        Arc::as_ptr(&self.identity.owner) as usize
    }
    /// Authenticated transport peer which owns this bounded source lane.
    ///
    /// The peer identity is stable across network-actor restarts. Callers may
    /// use it only for durable capacity accounting; the opaque source key
    /// remains required for process-local scheduling and capability checks.
    #[must_use]
    pub fn authenticated_source_peer(&self) -> &PeerId {
        &self.identity.authenticated_via
    }
    /// Equality-preserving in-process projection of this authenticated source lane.
    ///
    /// The digest binds the opaque network-actor owner and canonical peer
    /// identity. It is deliberately process-local: pointer identity is neither
    /// stable across restarts nor suitable for wire, persistence, or consensus
    /// state. Callers use it only when a fixed-width projection must preserve
    /// [`Self`]'s exact equality semantics, including across connection-tenure
    /// changes owned by the same actor.
    #[must_use]
    pub fn process_local_identity_hash(&self) -> Hash {
        self.identity.process_local_identity
    }
}
impl PartialEq for NetworkReplySourceKey {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity.owner, &other.identity.owner)
            && self.identity.authenticated_via == other.identity.authenticated_via
    }
}
impl Eq for NetworkReplySourceKey {}
impl core::hash::Hash for NetworkReplySourceKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::hash::Hash::hash(&self.owner_address(), state);
        core::hash::Hash::hash(&self.identity.authenticated_via, state);
    }
}
impl PartialOrd for NetworkReplySourceKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for NetworkReplySourceKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.owner_address()
            .cmp(&other.owner_address())
            .then_with(|| {
                self.identity
                    .authenticated_via
                    .cmp(&other.identity.authenticated_via)
            })
    }
}
impl core::fmt::Debug for NetworkReplySourceKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NetworkReplySourceKey(..)")
    }
}
impl core::fmt::Debug for NetworkReplyRoute {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NetworkReplyRoute")
            .field("semantic_target", &self.semantic_target)
            .field("delivery_active", &self.is_active())
            .field("reply_writable", &self.is_reply_writable())
            .finish_non_exhaustive()
    }
}
impl NetworkReplyRoute {
    fn new(
        semantic_target: PeerId,
        tenure: Arc<ReliableReplyRouteTenure>,
        delivery_ordinal: u128,
    ) -> Self {
        let (process_local_identity, process_local_source_identity) =
            Self::seal_process_local_identities(&semantic_target, &tenure, delivery_ordinal);
        let delivery_binding = Arc::new(ReliableReplyDeliveryBinding {
            owner: Arc::clone(&tenure.owner),
            minting_tenure: Arc::downgrade(&tenure),
            semantic_target: semantic_target.clone(),
            delivery_ordinal,
        });
        let source_key = NetworkReplySourceKey {
            identity: Arc::new(NetworkReplySourceIdentity {
                owner: Arc::clone(&tenure.owner),
                authenticated_via: tenure.delivery_peer.clone(),
                process_local_identity: process_local_source_identity,
            }),
        };
        Self {
            semantic_target,
            tenure,
            delivery_ordinal,
            delivery_binding,
            process_local_identity,
            source_key,
        }
    }
    fn validate_delivery_binding(&self) -> Result<(), NetworkReplyRouteError> {
        let valid = Arc::ptr_eq(&self.delivery_binding.owner, &self.tenure.owner)
            && self.delivery_binding.delivery_ordinal == self.delivery_ordinal
            && self.delivery_binding.semantic_target == self.semantic_target
            && self
                .delivery_binding
                .minting_tenure
                .upgrade()
                .is_some_and(|minting_tenure| Arc::ptr_eq(&minting_tenure, &self.tenure));
        valid
            .then_some(())
            .ok_or(NetworkReplyRouteError::EqualOrdinalDifferentTenure)
    }
    /// Semantic peer identity to which a reply must be addressed.
    #[must_use]
    pub fn semantic_target(&self) -> &PeerId {
        &self.semantic_target
    }
    /// Return the opaque authenticated-source key used for fair reply service.
    ///
    /// Semantic origins reached through one relay intentionally return the
    /// same key. No connection identifier or tenure ordinal is exposed.
    #[must_use]
    pub fn source_key(&self) -> NetworkReplySourceKey {
        self.source_key.clone()
    }
    /// Whether this capability was minted for the supplied authenticated delivery peer.
    ///
    /// This predicate lets transport boundaries bind an opaque route to their
    /// independently authenticated hop without exposing connection identifiers
    /// or the route's delivery peer.
    #[must_use]
    pub fn is_authenticated_via(&self, peer: &PeerId) -> bool {
        &self.tenure.delivery_peer == peer
    }
    /// Return the authenticated transport peer which owns this source lane.
    ///
    /// Unlike the semantic target, this identity is stable across connection
    /// tenures and can name a bounded durable source slot. The opaque route
    /// remains the sole authority for delivery and writer admission.
    #[must_use]
    pub fn authenticated_source_peer(&self) -> &PeerId {
        &self.tenure.delivery_peer
    }
    pub(crate) fn authenticated_via(&self) -> &PeerId {
        self.authenticated_source_peer()
    }
    /// Whether both routes were minted from the exact same authenticated
    /// connection tenure.
    ///
    /// Semantic targets are deliberately not compared: one relay tenure may
    /// carry requests for many origins. Callers which key by requester can use
    /// this predicate without learning a connection identifier.
    #[must_use]
    pub fn same_tenure(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.tenure, &other.tenure)
    }
    /// Whether both capabilities represent the exact same authenticated local delivery.
    #[must_use]
    pub fn same_delivery(&self, other: &Self) -> bool {
        self.same_tenure(other)
            && self.semantic_target == other.semantic_target
            && self.delivery_ordinal == other.delivery_ordinal
    }
    /// Whether one actor-global delivery ordinal was paired with two tenures.
    ///
    /// The ordinal itself remains opaque. Equal numeric ordinals minted by
    /// independent network actors do not conflict, while any reuse within one
    /// actor under another connection tenure is an invalid capability even if
    /// one of those tenures has since retired.
    #[must_use]
    pub fn equal_ordinal_different_tenure(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.tenure.owner, &other.tenure.owner)
            && self.delivery_ordinal == other.delivery_ordinal
            && !self.same_tenure(other)
    }
    /// Whether one actor-global connection ordinal was paired with two tenures.
    ///
    /// Production allocates this ordinal once per accepted connection tenure.
    /// Reuse under another tenure Arc is therefore a forged capability even
    /// when the two routes have distinct delivery ordinals.
    #[must_use]
    pub fn equal_connection_ordinal_different_tenure(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.tenure.owner, &other.tenure.owner)
            && self.tenure.connection_ordinal == other.tenure.connection_ordinal
            && !self.same_tenure(other)
    }
    /// Whether two capabilities belong to the same authenticated source lane.
    ///
    /// Reconnects from the same peer retain this identity. A different relay
    /// hub is an independent source even when it carries the same semantic
    /// request.
    #[must_use]
    pub fn same_source(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.tenure.owner, &other.tenure.owner)
            && self.tenure.delivery_peer == other.tenure.delivery_peer
    }
    /// Classify this capability as an exact or later delivery for one retained source.
    ///
    /// This rejects cross-actor, retargeted, inactive, stale, and forged
    /// equal-ordinal capabilities. A reconnect is distinguished from a later
    /// delivery on the same tenure because admission authority is tenure-bound.
    /// Callers must replace tenure-bound tickets while preserving their
    /// semantic source cursor and retrying its current immutable item.
    ///
    /// # Errors
    ///
    /// Returns the precise capability violation when `self` cannot update
    /// `prior` for the same authenticated source.
    pub fn source_update_from(
        &self,
        prior: &Self,
    ) -> Result<NetworkReplyRouteSourceUpdate, NetworkReplyRouteError> {
        if !self.is_active() {
            return Err(NetworkReplyRouteError::Inactive);
        }
        self.source_update_from_snapshot(prior)
    }
    /// Classify immutable same-source freshness without consulting liveness.
    ///
    /// This is used only after an owned route-history operation has already
    /// linearized its active snapshot. Freshness is a partial order: a later
    /// same-tenure delivery must advance the actor-global delivery ordinal, and
    /// a reconnect must strictly advance both the actor-global connection
    /// tenure and delivery ordinals. A delayed delivery from an older tenure
    /// therefore cannot replace a newer writer merely because it received a
    /// larger global delivery ordinal.
    ///
    /// # Errors
    ///
    /// Returns the precise immutable capability or freshness violation.
    pub fn source_update_from_snapshot(
        &self,
        prior: &Self,
    ) -> Result<NetworkReplyRouteSourceUpdate, NetworkReplyRouteError> {
        match self.source_freshness_from(prior)? {
            NetworkReplyRouteSourceFreshness::Exact => Ok(NetworkReplyRouteSourceUpdate::Exact),
            NetworkReplyRouteSourceFreshness::LaterDelivery => {
                Ok(NetworkReplyRouteSourceUpdate::LaterDelivery)
            }
            NetworkReplyRouteSourceFreshness::Reconnected => {
                Ok(NetworkReplyRouteSourceUpdate::Reconnected)
            }
            NetworkReplyRouteSourceFreshness::Stale => Err(NetworkReplyRouteError::Stale),
        }
    }
    fn source_freshness_from(
        &self,
        prior: &Self,
    ) -> Result<NetworkReplyRouteSourceFreshness, NetworkReplyRouteError> {
        self.validate_delivery_binding()?;
        prior.validate_delivery_binding()?;
        if !Arc::ptr_eq(&self.tenure.owner, &prior.tenure.owner) {
            return Err(NetworkReplyRouteError::ForeignOwner);
        }
        if self.semantic_target != prior.semantic_target {
            return Err(NetworkReplyRouteError::Retargeted);
        }
        if self.tenure.delivery_peer != prior.tenure.delivery_peer {
            return Err(NetworkReplyRouteError::DifferentSource);
        }
        if self.same_tenure(prior) {
            return Ok(match self.delivery_ordinal.cmp(&prior.delivery_ordinal) {
                std::cmp::Ordering::Less => NetworkReplyRouteSourceFreshness::Stale,
                std::cmp::Ordering::Equal => NetworkReplyRouteSourceFreshness::Exact,
                std::cmp::Ordering::Greater => NetworkReplyRouteSourceFreshness::LaterDelivery,
            });
        }
        if self.delivery_ordinal == prior.delivery_ordinal {
            return Err(NetworkReplyRouteError::EqualOrdinalDifferentTenure);
        }
        if self.tenure.connection_ordinal == prior.tenure.connection_ordinal {
            return Err(NetworkReplyRouteError::EqualConnectionOrdinalDifferentTenure);
        }
        Ok(
            if self.tenure.connection_ordinal > prior.tenure.connection_ordinal
                && self.delivery_ordinal > prior.delivery_ordinal
            {
                NetworkReplyRouteSourceFreshness::Reconnected
            } else {
                NetworkReplyRouteSourceFreshness::Stale
            },
        )
    }
    /// Whether this capability belongs to the same actor and semantic request target.
    #[must_use]
    pub fn same_request_authority(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.tenure.owner, &other.tenure.owner)
            && self.semantic_target == other.semantic_target
    }
    /// Whether the intrinsic delivery binding is valid and authenticated local
    /// delivery authority is still retained.
    ///
    /// This can remain true after the transport and reply writer stop: already
    /// dispatched messages keep their exact tenure alive until the final local
    /// receiver releases them. Use [`Self::is_reply_writable`] for outbound
    /// admission.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.validate_delivery_binding().is_ok() && self.tenure.is_active()
    }
    /// Whether this delivery capability still names the connection's current
    /// reply writer.
    ///
    /// A draining capability remains active for already-authenticated inbound
    /// delivery, but exact output must park until a newer same-source tenure is
    /// observed instead of transferring ownership to an obsolete writer.
    #[must_use]
    pub fn is_reply_writable(&self) -> bool {
        self.validate_delivery_binding().is_ok() && self.tenure.is_reply_writable()
    }
    /// Immutable process-local identity of this exact authenticated delivery.
    ///
    /// The digest deliberately includes opaque actor and tenure identities as
    /// well as both actor-global ordinals, the authenticated source, and the
    /// semantic target. It never includes connection liveness and has no wire
    /// representation; callers use it only to protect in-process ownership
    /// projections from substitution.
    #[must_use]
    pub fn process_local_identity_hash(&self) -> Hash {
        self.process_local_identity
    }
    /// Encode each immutable peer identity once when minting a delivery.
    /// Liveness remains checked independently by the capability predicates.
    fn seal_process_local_identities(
        semantic_target: &PeerId,
        tenure: &Arc<ReliableReplyRouteTenure>,
        delivery_ordinal: u128,
    ) -> (Hash, Hash) {
        const ROUTE_DOMAIN: &[u8] = b"iroha:p2p:reply-route-process-local-identity:v1\n";
        const SOURCE_DOMAIN: &[u8] = b"iroha:p2p:reply-source-process-local-identity:v1\n";
        let actor = (Arc::as_ptr(&tenure.owner) as usize as u128).to_le_bytes();
        let tenure_identity = (Arc::as_ptr(tenure) as usize as u128).to_le_bytes();
        let connection_ordinal = tenure.connection_ordinal.to_le_bytes();
        let delivery_ordinal = delivery_ordinal.to_le_bytes();
        let source_capacity = u64::try_from(tenure.source_capacity)
            .expect("bounded reply-source capacity fits u64")
            .to_le_bytes();
        let authenticated_source = tenure.delivery_peer.encode();
        let semantic_target = semantic_target.encode();
        let route = Hash::new_from_chunks(&[
            ROUTE_DOMAIN,
            &actor,
            &tenure_identity,
            &connection_ordinal,
            &delivery_ordinal,
            &source_capacity,
            &authenticated_source,
            &semantic_target,
        ]);
        let source = Hash::new_from_chunks(&[SOURCE_DOMAIN, &actor, &authenticated_source]);
        (route, source)
    }
}
/// Valid update of one authenticated reply-source attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkReplyRouteSourceUpdate {
    /// The exact same local delivery capability was observed again.
    Exact,
    /// A later delivery arrived on the same connection tenure.
    LaterDelivery,
    /// A later delivery arrived after the authenticated source reconnected.
    Reconnected,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetworkReplyRouteSourceFreshness {
    Exact,
    LaterDelivery,
    Reconnected,
    Stale,
}
/// Permanent reason an authenticated reply capability cannot join a semantic request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NetworkReplyRouteError {
    /// The capability's connection tenure has been retired.
    #[error("reply capability is inactive")]
    Inactive,
    /// The capability belongs to another network actor instance.
    #[error("reply capability belongs to another actor")]
    ForeignOwner,
    /// The capability addresses another semantic request target.
    #[error("reply capability was retargeted")]
    Retargeted,
    /// The capability belongs to another authenticated source lane.
    #[error("reply capability belongs to a different authenticated source")]
    DifferentSource,
    /// A newer delivery for this source is already retained.
    #[error("reply capability delivery ordinal is stale")]
    Stale,
    /// One actor-global delivery ordinal was paired with a different tenure.
    #[error("reply capability reused a delivery ordinal for another tenure")]
    EqualOrdinalDifferentTenure,
    /// One actor-global connection ordinal was paired with a different tenure.
    #[error("reply capability reused a connection ordinal for another tenure")]
    EqualConnectionOrdinalDifferentTenure,
    /// The configured authenticated-source geometry is already fully reserved.
    #[error("reply capability set exceeds configured source capacity")]
    Capacity,
}
/// Bounded independent return routes for one canonical semantic request.
///
/// At most one attempt is retained per authenticated source. Updating one
/// source cannot replace another source's attempt, and the bound is copied
/// from the network actor's configured connection geometry.
#[derive(Clone)]
pub struct NetworkReplyRoutes {
    semantic_target: PeerId,
    owner: Arc<()>,
    source_capacity: usize,
    /// Immutable history preimage prefix; active and retired maps stay dynamic.
    process_local_identity_prefix: Arc<[u8]>,
    attempts: BTreeMap<NetworkReplySourceKey, NetworkReplyRoute>,
    /// Latest delivery which left the live attempt set for each source.
    ///
    /// The map is independently bounded by `source_capacity`. Holding the
    /// opaque capabilities preserves source-local stale checks and the
    /// equal-ordinal/different-tenure diagnostic across destructive live-route
    /// pruning, while lower ordinals from another authenticated source remain
    /// valid independent attempts.
    retired_attempts: BTreeMap<NetworkReplySourceKey, NetworkReplyRoute>,
}
/// Opaque proof that one route set was pruned by one exact liveness snapshot.
///
/// The receipt is process-local, cannot be constructed outside this module,
/// and has no wire codec. Downstream ownership carriers consume it to bind
/// their cursor projection to the route operation which actually occurred.
pub struct NetworkReplyRoutesPruneReceipt {
    before: NetworkReplyRoutes,
    after: NetworkReplyRoutes,
}
impl core::fmt::Debug for NetworkReplyRoutesPruneReceipt {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NetworkReplyRoutesPruneReceipt")
            .field("before_attempts", &self.before.attempts.len())
            .field("after_attempts", &self.after.attempts.len())
            .finish_non_exhaustive()
    }
}
impl NetworkReplyRoutesPruneReceipt {
    /// Consume this receipt for its exact input and return the bound output.
    ///
    /// A caller cannot supply or substitute an output route set. Failure means
    /// the supplied input was not the exact history pruned by this operation.
    #[must_use]
    pub fn into_output(self, before: &NetworkReplyRoutes) -> Option<NetworkReplyRoutes> {
        (self.before.same_exact_history(before)
            && self.before.has_valid_container_shape()
            && self.after.has_valid_container_shape())
        .then_some(self.after)
    }
}
#[derive(Debug)]
struct NetworkReplyRoutesMergeTransition {
    left: NetworkReplyRoutes,
    right: NetworkReplyRoutes,
    merged: NetworkReplyRoutes,
}
impl NetworkReplyRoutesMergeTransition {
    fn into_output(
        self,
        left: &NetworkReplyRoutes,
        right: &NetworkReplyRoutes,
    ) -> Option<NetworkReplyRoutes> {
        (self.left.same_exact_history(left)
            && self.right.same_exact_history(right)
            && self.left.has_valid_container_shape()
            && self.right.has_valid_container_shape()
            && self.merged.has_valid_container_shape())
        .then_some(self.merged)
    }
}
/// Opaque proof that a strict route merge produced one exact output history.
///
/// The receipt is process-local, non-cloneable, and non-serializable. Consuming
/// it returns the operation-owned output rather than accepting a caller's
/// independently mutable route set.
pub struct NetworkReplyRoutesStrictMergeReceipt {
    transition: NetworkReplyRoutesMergeTransition,
}
impl core::fmt::Debug for NetworkReplyRoutesStrictMergeReceipt {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NetworkReplyRoutesStrictMergeReceipt")
            .field("left_attempts", &self.transition.left.attempts.len())
            .field("right_attempts", &self.transition.right.attempts.len())
            .field("merged_attempts", &self.transition.merged.attempts.len())
            .finish_non_exhaustive()
    }
}
impl NetworkReplyRoutesStrictMergeReceipt {
    /// Consume this strict-merge receipt and return its bound output history.
    #[must_use]
    pub fn into_output(
        self,
        left: &NetworkReplyRoutes,
        right: &NetworkReplyRoutes,
    ) -> Option<NetworkReplyRoutes> {
        self.transition.into_output(left, right)
    }
}
/// Opaque proof that observed-history reconciliation produced one exact output.
///
/// This receipt is deliberately distinct from a strict-merge receipt so a
/// tolerant stale observation cannot be reused at a strict admission seam.
pub struct NetworkReplyRoutesObservedMergeReceipt {
    transition: NetworkReplyRoutesMergeTransition,
}
impl core::fmt::Debug for NetworkReplyRoutesObservedMergeReceipt {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NetworkReplyRoutesObservedMergeReceipt")
            .field("left_attempts", &self.transition.left.attempts.len())
            .field("right_attempts", &self.transition.right.attempts.len())
            .field("merged_attempts", &self.transition.merged.attempts.len())
            .finish_non_exhaustive()
    }
}
impl NetworkReplyRoutesObservedMergeReceipt {
    /// Consume this observed-merge receipt and return its bound output history.
    #[must_use]
    pub fn into_output(
        self,
        left: &NetworkReplyRoutes,
        right: &NetworkReplyRoutes,
    ) -> Option<NetworkReplyRoutes> {
        self.transition.into_output(left, right)
    }
}
impl core::fmt::Debug for NetworkReplyRoutes {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NetworkReplyRoutes")
            .field("semantic_target", &self.semantic_target)
            .field("attempts", &self.attempts.len())
            .field("retired_attempts", &self.retired_attempts.len())
            .field("source_capacity", &self.source_capacity)
            .finish_non_exhaustive()
    }
}
impl NetworkReplyRoutes {
    /// Start a bounded route set from one live authenticated delivery.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkReplyRouteError::EqualOrdinalDifferentTenure`] for a
    /// capability whose immutable delivery binding names another tenure, or
    /// [`NetworkReplyRouteError::Inactive`] for a retired capability.
    pub fn try_from_route(route: NetworkReplyRoute) -> Result<Self, NetworkReplyRouteError> {
        route.validate_delivery_binding()?;
        if !route.is_active() {
            return Err(NetworkReplyRouteError::Inactive);
        }
        let source_capacity = route.tenure.source_capacity;
        if source_capacity == 0 {
            return Err(NetworkReplyRouteError::Capacity);
        }
        let semantic_target = route.semantic_target.clone();
        let owner = Arc::clone(&route.tenure.owner);
        let process_local_identity_prefix =
            Self::seal_process_local_identity_prefix(&semantic_target, &owner, source_capacity);
        let attempts = BTreeMap::from([(route.source_key(), route)]);
        Ok(Self {
            semantic_target,
            owner,
            source_capacity,
            process_local_identity_prefix,
            attempts,
            retired_attempts: BTreeMap::new(),
        })
    }
    /// Semantic peer identity shared by every retained route attempt.
    #[must_use]
    pub fn semantic_target(&self) -> &PeerId {
        &self.semantic_target
    }
    /// Configured upper bound on independent authenticated sources.
    #[must_use]
    pub const fn source_capacity(&self) -> usize {
        self.source_capacity
    }
    /// Number of currently retained authenticated-source attempts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.attempts.len()
    }
    /// Whether no authenticated-source attempt is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attempts.is_empty()
    }
    /// Iterate over independent source attempts in stable local order.
    pub fn iter(&self) -> impl Iterator<Item = &NetworkReplyRoute> {
        self.attempts.values()
    }
    /// Whether two carriers contain the same exact active and retired history.
    ///
    /// This comparison is process-local and liveness-independent. It includes
    /// opaque actor ownership, container geometry, map/source bindings, active
    /// delivery placement, and bounded tombstones.
    #[must_use]
    pub fn has_same_exact_history(&self, other: &Self) -> bool {
        self.has_valid_container_shape()
            && other.has_valid_container_shape()
            && self.same_exact_history(other)
    }
    /// Immutable process-local digest of the complete route history.
    ///
    /// Both active attempts and retired tombstones are included. The digest
    /// deliberately excludes current connection liveness and has no wire
    /// representation.
    #[must_use]
    pub fn process_local_exact_history_hash(&self) -> Hash {
        let mut projection = self.process_local_identity_prefix.to_vec();
        projection.extend_from_slice(
            &u64::try_from(self.attempts.len())
                .expect("bounded active route count fits u64")
                .to_le_bytes(),
        );
        for route in self.attempts.values() {
            projection.push(0);
            projection.extend_from_slice(route.process_local_identity_hash().as_ref());
        }
        projection.extend_from_slice(
            &u64::try_from(self.retired_attempts.len())
                .expect("bounded retired route count fits u64")
                .to_le_bytes(),
        );
        for route in self.retired_attempts.values() {
            projection.push(1);
            projection.extend_from_slice(route.process_local_identity_hash().as_ref());
        }
        Hash::new(projection)
    }
    /// Seal only immutable container geometry, never mutable route membership.
    fn seal_process_local_identity_prefix(
        semantic_target: &PeerId,
        owner: &Arc<()>,
        source_capacity: usize,
    ) -> Arc<[u8]> {
        const DOMAIN: &[u8] = b"iroha:p2p:reply-route-history-process-local:v1\n";
        let actor = (Arc::as_ptr(owner) as usize as u128).to_le_bytes();
        let source_capacity = u64::try_from(source_capacity)
            .expect("bounded reply-source capacity fits u64")
            .to_le_bytes();
        let semantic_target = semantic_target.encode();
        let mut prefix = Vec::new();
        prefix.extend_from_slice(DOMAIN);
        prefix.extend_from_slice(&actor);
        prefix.extend_from_slice(&source_capacity);
        prefix.extend_from_slice(&semantic_target);
        prefix.into()
    }
    /// Drop connection tenures which are retired in one bounded snapshot.
    ///
    /// This is local ownership maintenance, not candidate admission: callers
    /// should validate every newly observed route before invoking it. The
    /// snapshot is authoritative for this pass: a route which retires after
    /// its liveness was sampled remains retained until the next pass, so no
    /// route can be removed without recording its exact retired delivery. The
    /// returned count is the number of authenticated-source attempts retained
    /// for dispatch after this pass; a concurrently retired attempt can remain
    /// in that count until the next bounded snapshot.
    pub fn retain_active(&mut self) -> usize {
        self.retain_active_with_receipt().0
    }
    /// Prune one bounded inactive-route snapshot and return its opaque receipt.
    ///
    /// Unlike a post-hoc predicate, the receipt binds the exact before/after
    /// histories captured by the operation itself and therefore cannot accept
    /// a caller-invented omission after liveness changes again.
    pub fn retain_active_with_receipt(&mut self) -> (usize, NetworkReplyRoutesPruneReceipt) {
        self.retain_active_with_receipt_after_snapshot(|| {})
    }
    /// Apply one exact inactive-route snapshot after exposing its linearization
    /// boundary to a caller-supplied hook.
    ///
    /// Production pruning supplies a no-op hook. Keeping the boundary explicit
    /// lets the race regression retire a tenure immediately after sampling and
    /// prove that a later liveness transition is deferred to the next pass.
    fn retain_active_with_receipt_after_snapshot<F>(
        &mut self,
        after_snapshot: F,
    ) -> (usize, NetworkReplyRoutesPruneReceipt)
    where
        F: FnOnce(),
    {
        let before = self.clone();
        let retired_snapshot = self
            .attempts
            .iter()
            .filter(|(_, route)| !route.is_active())
            .map(|(source, route)| (source.clone(), route.clone()))
            .collect::<Vec<_>>();
        after_snapshot();
        for (source, snapshot_route) in retired_snapshot {
            if self
                .attempts
                .get(&source)
                .is_some_and(|current| current.same_delivery(&snapshot_route))
            {
                let retired = self
                    .attempts
                    .remove(&source)
                    .expect("exact snapshotted reply route must remain present");
                self.record_retired_delivery(retired);
            }
        }
        let retained = self.attempts.len();
        let receipt = NetworkReplyRoutesPruneReceipt {
            before,
            after: self.clone(),
        };
        debug_assert!(receipt.before.has_valid_container_shape());
        debug_assert!(receipt.after.has_valid_container_shape());
        (retained, receipt)
    }
    /// Remove one source attempt after its semantic output cursor completes.
    ///
    /// This is process-local queue maintenance. The authenticated source may
    /// remain connected and active; only this exact semantic output no longer
    /// needs its route.
    pub fn remove_completed_source(&mut self, source: &NetworkReplySourceKey) -> bool {
        self.retired_attempts.remove(source);
        self.attempts.remove(source).is_some()
    }
    /// Attach all valid source attempts from `candidate` atomically.
    ///
    /// Exact duplicates do not change retained rank. A later delivery updates
    /// only its source, while a newly observed source receives an independent
    /// attempt. Any invalid member rejects the entire merge.
    ///
    /// # Errors
    ///
    /// Returns a capability or capacity error without changing `self`.
    pub fn merge(&mut self, candidate: &Self) -> Result<(), NetworkReplyRouteError> {
        self.merge_with_receipt(candidate).map(drop)
    }
    /// Strictly merge a candidate and return the exact operation receipt.
    ///
    /// # Errors
    ///
    /// Returns a capability or capacity error without changing `self`.
    pub fn merge_with_receipt(
        &mut self,
        candidate: &Self,
    ) -> Result<NetworkReplyRoutesStrictMergeReceipt, NetworkReplyRouteError> {
        self.preflight_merge(candidate)?;
        let left = self.clone();
        let right = candidate.clone();
        let mut merged = self.clone();
        merged.retain_active();
        for retired in candidate.retired_attempts.values().cloned() {
            merged.merge_retired_delivery(retired)?;
        }
        for route in candidate.iter().cloned() {
            merged.attach(route)?;
        }
        let receipt = NetworkReplyRoutesStrictMergeReceipt {
            transition: NetworkReplyRoutesMergeTransition {
                left,
                right,
                merged: merged.clone(),
            },
        };
        debug_assert!(receipt.transition.left.has_valid_container_shape());
        debug_assert!(receipt.transition.right.has_valid_container_shape());
        debug_assert!(receipt.transition.merged.has_valid_container_shape());
        *self = merged;
        Ok(receipt)
    }
    /// Reconcile an independently observed route history atomically.
    ///
    /// A stale delivery or a capability whose tenure retired after it was
    /// observed is a benign no-op for that source. Other live members of the
    /// same candidate are still admitted. Authority, target, actor geometry,
    /// equal-ordinal tenure, and capacity violations reject the whole merge.
    /// Retired observations are retained as bounded tombstones so ignoring a
    /// stale source cannot erase collision history for a fresh sibling.
    ///
    /// # Errors
    ///
    /// Returns a non-stale capability or capacity error without changing
    /// `self`.
    pub fn merge_observed(&mut self, candidate: &Self) -> Result<(), NetworkReplyRouteError> {
        self.merge_observed_with_receipt(candidate).map(drop)
    }
    /// Reconcile observed history and return the exact operation receipt.
    ///
    /// # Errors
    ///
    /// Returns a non-stale capability or capacity error without changing
    /// `self`.
    pub fn merge_observed_with_receipt(
        &mut self,
        candidate: &Self,
    ) -> Result<NetworkReplyRoutesObservedMergeReceipt, NetworkReplyRouteError> {
        self.preflight_merge(candidate)?;
        let left = self.clone();
        let right = candidate.clone();
        let mut merged = self.clone();
        merged.retain_active();
        let observed_routes = candidate
            .iter()
            .cloned()
            .map(|route| {
                let observed_active = route.is_active();
                (route, observed_active)
            })
            .collect::<Vec<_>>();
        for retired in candidate.retired_attempts.values().cloned() {
            merged.merge_retired_delivery(retired)?;
        }
        for (route, observed_active) in &observed_routes {
            if !*observed_active {
                merged.merge_retired_delivery(route.clone())?;
            }
        }
        for (route, observed_active) in observed_routes {
            if !observed_active {
                continue;
            }
            match merged.attach(route.clone()) {
                Ok(()) | Err(NetworkReplyRouteError::Stale) => {}
                Err(NetworkReplyRouteError::Inactive) => {
                    merged.merge_retired_delivery(route)?;
                }
                Err(error) => return Err(error),
            }
        }
        merged.retain_active();
        let receipt = NetworkReplyRoutesObservedMergeReceipt {
            transition: NetworkReplyRoutesMergeTransition {
                left,
                right,
                merged: merged.clone(),
            },
        };
        debug_assert!(receipt.transition.left.has_valid_container_shape());
        debug_assert!(receipt.transition.right.has_valid_container_shape());
        debug_assert!(receipt.transition.merged.has_valid_container_shape());
        *self = merged;
        Ok(receipt)
    }
    fn same_exact_history(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
            && self.semantic_target == other.semantic_target
            && self.source_capacity == other.source_capacity
            && self.attempts.len() == other.attempts.len()
            && self.retired_attempts.len() == other.retired_attempts.len()
            && self.attempts.iter().all(|(source, route)| {
                other
                    .attempts
                    .get(source)
                    .is_some_and(|other| route.same_delivery(other))
            })
            && self.retired_attempts.iter().all(|(source, route)| {
                other
                    .retired_attempts
                    .get(source)
                    .is_some_and(|other| route.same_delivery(other))
            })
    }
    fn has_valid_container_shape(&self) -> bool {
        let member_is_exact = |source: &NetworkReplySourceKey, route: &NetworkReplyRoute| {
            source == &route.source_key()
                && Arc::ptr_eq(&self.owner, &route.tenure.owner)
                && self.semantic_target == route.semantic_target
                && self.source_capacity == route.tenure.source_capacity
                && route.validate_delivery_binding().is_ok()
        };
        if self.source_capacity == 0
            || self.attempts.len() > self.source_capacity
            || self.retired_attempts.len() > self.source_capacity
            || self
                .attempts
                .iter()
                .chain(&self.retired_attempts)
                .any(|(source, route)| !member_is_exact(source, route))
        {
            return false;
        }
        let attempts_are_distinct = self.attempts.iter().all(|(source, route)| {
            self.attempts.iter().all(|(other_source, other)| {
                source == other_source
                    || (!route.same_delivery(other)
                        && !route.equal_ordinal_different_tenure(other)
                        && !route.equal_connection_ordinal_different_tenure(other))
            })
        });
        let retired_are_distinct = self.retired_attempts.iter().all(|(source, route)| {
            self.retired_attempts.iter().all(|(other_source, other)| {
                source == other_source
                    || (!route.same_delivery(other)
                        && !route.equal_ordinal_different_tenure(other)
                        && !route.equal_connection_ordinal_different_tenure(other))
            })
        });
        let histories_are_ordered = self.attempts.iter().all(|(source, route)| {
            self.retired_attempts.get(source).is_none_or(|retired| {
                matches!(
                    retired.source_freshness_from(route),
                    Ok(NetworkReplyRouteSourceFreshness::Stale)
                )
            })
        });
        let histories_do_not_collide = self.attempts.values().all(|route| {
            self.retired_attempts.values().all(|retired| {
                !route.same_delivery(retired)
                    && !route.equal_ordinal_different_tenure(retired)
                    && !route.equal_connection_ordinal_different_tenure(retired)
            })
        });
        attempts_are_distinct
            && retired_are_distinct
            && histories_are_ordered
            && histories_do_not_collide
    }
    fn preflight_merge(&self, candidate: &Self) -> Result<(), NetworkReplyRouteError> {
        for route in self
            .attempts
            .values()
            .chain(self.retired_attempts.values())
            .chain(candidate.attempts.values())
            .chain(candidate.retired_attempts.values())
        {
            route.validate_delivery_binding()?;
        }
        if !Arc::ptr_eq(&self.owner, &candidate.owner) {
            return Err(NetworkReplyRouteError::ForeignOwner);
        }
        if self.semantic_target != candidate.semantic_target {
            return Err(NetworkReplyRouteError::Retargeted);
        }
        if self.source_capacity != candidate.source_capacity {
            return Err(NetworkReplyRouteError::ForeignOwner);
        }
        let candidate_history = candidate
            .attempts
            .iter()
            .chain(&candidate.retired_attempts)
            .collect::<Vec<_>>();
        for (source, route) in &candidate_history {
            if *source != &route.source_key()
                || !Arc::ptr_eq(&self.owner, &route.tenure.owner)
                || route.tenure.source_capacity != self.source_capacity
            {
                return Err(NetworkReplyRouteError::ForeignOwner);
            }
            if self.semantic_target != route.semantic_target {
                return Err(NetworkReplyRouteError::Retargeted);
            }
            if self
                .attempts
                .values()
                .chain(self.retired_attempts.values())
                .any(|prior| {
                    prior.equal_ordinal_different_tenure(route)
                        || prior.equal_connection_ordinal_different_tenure(route)
                })
            {
                return Err(
                    if self
                        .attempts
                        .values()
                        .chain(self.retired_attempts.values())
                        .any(|prior| prior.equal_ordinal_different_tenure(route))
                    {
                        NetworkReplyRouteError::EqualOrdinalDifferentTenure
                    } else {
                        NetworkReplyRouteError::EqualConnectionOrdinalDifferentTenure
                    },
                );
            }
        }
        if candidate_history
            .iter()
            .enumerate()
            .any(|(index, (_, route))| {
                candidate_history[index + 1..].iter().any(|(_, other)| {
                    route.equal_ordinal_different_tenure(other)
                        || route.equal_connection_ordinal_different_tenure(other)
                })
            })
        {
            let delivery_collision =
                candidate_history
                    .iter()
                    .enumerate()
                    .any(|(index, (_, route))| {
                        candidate_history[index + 1..]
                            .iter()
                            .any(|(_, other)| route.equal_ordinal_different_tenure(other))
                    });
            return Err(if delivery_collision {
                NetworkReplyRouteError::EqualOrdinalDifferentTenure
            } else {
                NetworkReplyRouteError::EqualConnectionOrdinalDifferentTenure
            });
        }
        Ok(())
    }
    fn attach(&mut self, route: NetworkReplyRoute) -> Result<(), NetworkReplyRouteError> {
        route.validate_delivery_binding()?;
        if !route.is_active() {
            return Err(NetworkReplyRouteError::Inactive);
        }
        if !Arc::ptr_eq(&self.owner, &route.tenure.owner) {
            return Err(NetworkReplyRouteError::ForeignOwner);
        }
        if self.semantic_target != route.semantic_target {
            return Err(NetworkReplyRouteError::Retargeted);
        }
        if self.attempts.values().any(|prior| {
            prior.equal_ordinal_different_tenure(&route)
                || prior.equal_connection_ordinal_different_tenure(&route)
        }) {
            return Err(
                if self
                    .attempts
                    .values()
                    .any(|prior| prior.equal_ordinal_different_tenure(&route))
                {
                    NetworkReplyRouteError::EqualOrdinalDifferentTenure
                } else {
                    NetworkReplyRouteError::EqualConnectionOrdinalDifferentTenure
                },
            );
        }
        let source = route.source_key();
        if let Some(prior) = self.attempts.get(&source) {
            match route.source_update_from(prior)? {
                NetworkReplyRouteSourceUpdate::Exact => {}
                NetworkReplyRouteSourceUpdate::LaterDelivery
                | NetworkReplyRouteSourceUpdate::Reconnected => {
                    self.validate_after_retired_delivery(&route)?;
                    let prior = prior.clone();
                    self.attempts.insert(source, route);
                    self.record_retired_delivery(prior);
                }
            }
            return Ok(());
        }
        self.validate_after_retired_delivery(&route)?;
        if self.attempts.len() >= self.source_capacity {
            return Err(NetworkReplyRouteError::Capacity);
        }
        self.attempts.insert(source, route);
        Ok(())
    }
    fn validate_after_retired_delivery(
        &self,
        route: &NetworkReplyRoute,
    ) -> Result<(), NetworkReplyRouteError> {
        if self.retired_attempts.values().any(|retired| {
            retired.equal_ordinal_different_tenure(route)
                || retired.equal_connection_ordinal_different_tenure(route)
        }) {
            return Err(
                if self
                    .retired_attempts
                    .values()
                    .any(|retired| retired.equal_ordinal_different_tenure(route))
                {
                    NetworkReplyRouteError::EqualOrdinalDifferentTenure
                } else {
                    NetworkReplyRouteError::EqualConnectionOrdinalDifferentTenure
                },
            );
        }
        if let Some(retired) = self.retired_attempts.get(&route.source_key()) {
            match route.source_update_from(retired)? {
                NetworkReplyRouteSourceUpdate::Exact => {
                    return Err(NetworkReplyRouteError::Stale);
                }
                NetworkReplyRouteSourceUpdate::LaterDelivery
                | NetworkReplyRouteSourceUpdate::Reconnected => {}
            }
        }
        Ok(())
    }
    fn merge_retired_delivery(
        &mut self,
        retired: NetworkReplyRoute,
    ) -> Result<(), NetworkReplyRouteError> {
        retired.validate_delivery_binding()?;
        if !Arc::ptr_eq(&self.owner, &retired.tenure.owner) {
            return Err(NetworkReplyRouteError::ForeignOwner);
        }
        if self.semantic_target != retired.semantic_target {
            return Err(NetworkReplyRouteError::Retargeted);
        }
        if self.source_capacity != retired.tenure.source_capacity {
            return Err(NetworkReplyRouteError::ForeignOwner);
        }
        if self
            .attempts
            .values()
            .chain(self.retired_attempts.values())
            .any(|current| {
                current.equal_ordinal_different_tenure(&retired)
                    || current.equal_connection_ordinal_different_tenure(&retired)
            })
        {
            return Err(
                if self
                    .attempts
                    .values()
                    .chain(self.retired_attempts.values())
                    .any(|current| current.equal_ordinal_different_tenure(&retired))
                {
                    NetworkReplyRouteError::EqualOrdinalDifferentTenure
                } else {
                    NetworkReplyRouteError::EqualConnectionOrdinalDifferentTenure
                },
            );
        }
        let source = retired.source_key();
        let retires_live_attempt = self
            .attempts
            .get(&source)
            .map(|current| retired.source_freshness_from(current))
            .transpose()?
            .is_some_and(|freshness| !matches!(freshness, NetworkReplyRouteSourceFreshness::Stale));
        if retires_live_attempt && let Some(superseded) = self.attempts.remove(&source) {
            self.record_retired_delivery(superseded);
        }
        self.record_retired_delivery(retired);
        Ok(())
    }
    fn record_retired_delivery(&mut self, retired: NetworkReplyRoute) {
        let source = retired.source_key();
        if let Some(current) = self.retired_attempts.get_mut(&source) {
            if matches!(
                retired.source_freshness_from(current),
                Ok(NetworkReplyRouteSourceFreshness::LaterDelivery
                    | NetworkReplyRouteSourceFreshness::Reconnected)
            ) {
                *current = retired;
            }
            return;
        }
        if self.retired_attempts.len() >= self.source_capacity
            && let Some(oldest) = self
                .retired_attempts
                .iter()
                .min_by_key(|(_, route)| route.delivery_ordinal)
                .map(|(source, _)| source.clone())
        {
            self.retired_attempts.remove(&oldest);
        }
        self.retired_attempts.insert(source, retired);
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProgressAuthorityIdentity {
    Topology(u64),
    Reply(u128),
}
#[derive(Clone, Debug)]
enum ProgressDeliveryAuthority {
    Topology(Arc<ReliableProgressMembership>),
    Reply(NetworkReplyRoute),
}
impl ProgressDeliveryAuthority {
    fn identity(&self) -> ProgressAuthorityIdentity {
        match self {
            Self::Topology(membership) => {
                ProgressAuthorityIdentity::Topology(membership.generation)
            }
            Self::Reply(route) => ProgressAuthorityIdentity::Reply(route.tenure.connection_ordinal),
        }
    }
    fn source_target(&self) -> &PeerId {
        match self {
            Self::Topology(membership) => &membership.peer_id,
            Self::Reply(route) => &route.tenure.delivery_peer,
        }
    }
    fn is_active(&self) -> bool {
        match self {
            Self::Topology(membership) => membership.is_active(),
            Self::Reply(route) => route.is_reply_writable(),
        }
    }
    fn downgrade(&self) -> WeakProgressDeliveryAuthority {
        match self {
            Self::Topology(membership) => {
                WeakProgressDeliveryAuthority::Topology(Arc::downgrade(membership))
            }
            Self::Reply(route) => WeakProgressDeliveryAuthority::Reply {
                semantic_target: route.semantic_target.clone(),
                tenure: Arc::downgrade(&route.tenure),
            },
        }
    }
}
#[derive(Debug)]
enum WeakProgressDeliveryAuthority {
    Topology(Weak<ReliableProgressMembership>),
    Reply {
        semantic_target: PeerId,
        tenure: Weak<ReliableReplyRouteTenure>,
    },
}
impl WeakProgressDeliveryAuthority {
    fn matches(&self, authority: &ProgressDeliveryAuthority) -> bool {
        match (self, authority) {
            (Self::Topology(retained), ProgressDeliveryAuthority::Topology(candidate)) => retained
                .upgrade()
                .is_some_and(|retained| Arc::ptr_eq(&retained, candidate)),
            (
                Self::Reply {
                    semantic_target,
                    tenure: retained,
                },
                ProgressDeliveryAuthority::Reply(candidate),
            ) => {
                semantic_target == candidate.semantic_target()
                    && retained
                        .upgrade()
                        .is_some_and(|retained| Arc::ptr_eq(&retained, &candidate.tenure))
            }
            (Self::Topology(_), ProgressDeliveryAuthority::Reply(_))
            | (Self::Reply { .. }, ProgressDeliveryAuthority::Topology(_)) => false,
        }
    }
    fn is_cancelled(&self) -> bool {
        match self {
            Self::Topology(membership) => membership
                .upgrade()
                .is_none_or(|membership| !membership.is_active()),
            Self::Reply { tenure, .. } => tenure
                .upgrade()
                .is_none_or(|tenure| !tenure.is_reply_writable()),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProgressTicketShape {
    topic: message::Topic,
    stream_wire_bytes: usize,
    broadcast: bool,
    /// Exact reply timeout generation retained across admission retries.
    ///
    /// Topology-authorized posts and broadcasts carry no adaptive timeout.
    reply_writer_timeout_attempt: Option<u8>,
    /// Binds the ticket to the exact canonical request which created it.
    request_digest: Hash,
    /// Exact actor-published tenure which authorizes this target delivery.
    /// Budget-only unit fixtures use `None`; live direct and broadcast posts
    /// always bind an actor-published membership generation.
    authority: Option<ProgressAuthorityIdentity>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ActorProgressClass {
    Safety,
    Lane,
    Bulk,
}
impl ActorProgressClass {
    const COUNT: usize = 3;
    const ALL: [Self; Self::COUNT] = [Self::Safety, Self::Lane, Self::Bulk];
    const fn index(self) -> usize {
        match self {
            Self::Safety => 0,
            Self::Lane => 1,
            Self::Bulk => 2,
        }
    }
    fn for_payload<T: message::ClassifyTopic>(payload: &T) -> Option<Self> {
        use message::TransportAdmissionClass as Class;
        if !is_reliable_progress_route(payload.topic(), payload.subscriber_route()) {
            return None;
        }
        match payload.admission_class() {
            Class::Safety => Some(Self::Safety),
            Class::Lane => Some(Self::Lane),
            Class::Payload | Class::BlockSync => Some(Self::Bulk),
            Class::Control | Class::Low => None,
        }
    }
    // Explicit ordinary-message fixture only: production classifies the payload.
    #[cfg(test)]
    fn for_route(topic: message::Topic, route: message::SubscriberRoute) -> Option<Self> {
        match reliable_progress_class(topic, route)? {
            ReliableProgressClass::Safety => Some(Self::Safety),
            ReliableProgressClass::Lane => Some(Self::Lane),
            ReliableProgressClass::Bulk => Some(Self::Bulk),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ActorProgressByteLimits {
    safety: usize,
    lane: usize,
    bulk: usize,
}
impl ActorProgressByteLimits {
    fn uniform(bytes: usize) -> Self {
        Self {
            safety: bytes,
            lane: bytes,
            bulk: bytes,
        }
    }
    fn for_class(self, class: ActorProgressClass) -> usize {
        match class {
            ActorProgressClass::Safety => self.safety,
            ActorProgressClass::Lane => self.lane,
            ActorProgressClass::Bulk => self.bulk,
        }
    }
    fn checked_per_target_total(self) -> Option<usize> {
        ActorProgressClass::ALL
            .into_iter()
            .try_fold(0usize, |sum, class| sum.checked_add(self.for_class(class)))
    }
}
/// The three-class waiter envelope: every class keeps all 65 ranks per source,
/// independently of blocked work in another class. The 64-envelope
/// `LaneRelayBroadcaster` emits Lane only; the other producer is the bounded
/// exact-output scheduler.
fn actor_waiter_limits() -> Option<[usize; ActorProgressClass::COUNT]> {
    let limit = RELIABLE_PROGRESS_WAITERS_PER_SOURCE;
    (limit >= RELIABLE_PROGRESS_EXACT_OUTPUT_PRODUCERS_PER_SOURCE)
        .then_some([limit; ActorProgressClass::COUNT])
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ActorProgressSource {
    /// Production progress owners are always target-specific. `None` exists
    /// only for budget-only unit fixtures and is never an actor fanout lane.
    target: Option<PeerId>,
    class: ActorProgressClass,
}
impl ActorProgressSource {
    fn for_message<T: message::ClassifyTopic>(message: &NetworkMessage<T>) -> Option<Self> {
        let NetworkMessage::Post(post) = message else {
            // Reliable broadcasts acquire an explicit target source from the
            // accepted topology before actor admission.
            return None;
        };
        let class = ActorProgressClass::for_payload(&post.data)?;
        Some(Self {
            target: Some(post.peer_id.clone()),
            class,
        })
    }
    fn for_admitted_payload<T: message::ClassifyTopic>(
        payload: &AdmittedNetworkPayload<T>,
    ) -> Option<Self> {
        match payload {
            AdmittedNetworkPayload::Unsigned(message) => Self::for_message(message),
            AdmittedNetworkPayload::Signed(frame) => {
                let RelayTarget::Direct(target) = &frame.target else {
                    // Reliable broadcasts acquire an explicit target source
                    // before actor admission.
                    return None;
                };
                let class = ActorProgressClass::for_payload(&frame.payload)?;
                Some(Self {
                    target: Some(target.clone()),
                    class,
                })
            }
        }
    }
    #[cfg(test)]
    fn test() -> Self {
        Self {
            target: None,
            class: ActorProgressClass::Lane,
        }
    }
}
#[derive(Debug)]
struct NetworkActorProgressBudget {
    per_class_max_bytes: ActorProgressByteLimits,
    max_sources: usize,
    max_sources_per_class: usize,
    max_total_bytes: usize,
    max_waiters: usize,
    max_waiters_per_class: [usize; ActorProgressClass::COUNT],
    max_waiters_per_source: [usize; ActorProgressClass::COUNT],
    state: Mutex<NetworkActorProgressState>,
}
#[derive(Clone, Copy, Debug)]
struct NetworkActorProgressRetention {
    bytes: usize,
    items: usize,
    request_digest: Hash,
    broadcast: bool,
    authority: Option<ProgressAuthorityIdentity>,
}
#[derive(Clone, Copy, Debug)]
struct NetworkActorProgressWaiter {
    id: u64,
    shape: ProgressTicketShape,
}
#[derive(Debug, Default)]
struct NetworkActorProgressState {
    retained_bytes: usize,
    retained_items: usize,
    retained_sources_by_class: [usize; ActorProgressClass::COUNT],
    retained_by_source: HashMap<ActorProgressSource, NetworkActorProgressRetention>,
    next_ticket: u64,
    waiters: HashMap<ActorProgressSource, VecDeque<NetworkActorProgressWaiter>>,
    waiter_count: usize,
    waiters_by_class: [usize; ActorProgressClass::COUNT],
    #[cfg(any(test, feature = "test-fixtures"))]
    ticket_drop_cancellations: usize,
}
/// Per-source service position owned by a caller retrying progress admission.
///
/// The ticket contains no payload, but carries a digest binding it to the
/// exact canonical request. The original [`Post`] or [`Broadcast`] remains
/// with the caller whenever admission is backpressured. Dropping a ticket
/// cancels its place in the bounded waiter queue.
#[derive(Debug)]
pub struct NetworkActorAdmissionTicket {
    budget: Arc<NetworkActorProgressBudget>,
    id: u64,
    shape: ProgressTicketShape,
    source: ActorProgressSource,
    authority: Option<WeakProgressDeliveryAuthority>,
    active: bool,
}
/// Immutable identity of the ticket which crossed actor admission.
///
/// This projection remains process-local: pointer ownership prevents ticket
/// identifiers reused by another actor budget from aliasing this ticket.
#[derive(Clone)]
struct NetworkActorAdmittedTicketIdentity {
    budget: Arc<NetworkActorProgressBudget>,
    id: u64,
    rank: usize,
    shape: ProgressTicketShape,
    source: ActorProgressSource,
    authority: ProgressDeliveryAuthority,
}
impl NetworkActorAdmittedTicketIdentity {
    fn from_ready_ticket(
        ticket: &NetworkActorAdmissionTicket,
        authority: &ProgressDeliveryAuthority,
        rank: usize,
    ) -> Self {
        debug_assert!(ticket.active);
        debug_assert_eq!(rank, 1);
        Self {
            budget: Arc::clone(&ticket.budget),
            id: ticket.id,
            // Capture the rank computed under the budget lock before commit
            // removes the waiter and makes a later rank query impossible.
            rank,
            shape: ticket.shape,
            source: ticket.source.clone(),
            authority: authority.clone(),
        }
    }
    fn same_ticket(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.budget, &other.budget)
            && self.id == other.id
            && self.rank == other.rank
            && self.shape == other.shape
            && self.source == other.source
    }
    /// Equality-preserving process-local digest of the admitted ticket.
    ///
    /// This deliberately mirrors every field used by [`Self::same_ticket`],
    /// including the opaque actor-budget owner. It is never serialized or
    /// used as consensus state.
    fn process_local_identity_hash(&self) -> Hash {
        const DOMAIN: &[u8] = b"iroha:p2p:admitted-ticket-process-local-identity:v1\n";
        let mut projection = Vec::new();
        projection.extend_from_slice(&(Arc::as_ptr(&self.budget) as usize as u128).to_le_bytes());
        projection.extend_from_slice(&self.id.to_le_bytes());
        projection.extend_from_slice(&(self.rank as u128).to_le_bytes());
        projection.push(match self.shape.topic {
            message::Topic::ConsensusSafety => 1,
            message::Topic::Consensus => 2,
            message::Topic::ConsensusChunk => 3,
            message::Topic::ConsensusPayload => 4,
            message::Topic::Control => 5,
            message::Topic::BlockSync => 6,
            message::Topic::TxGossip => 7,
            message::Topic::TxGossipRestricted => 8,
            message::Topic::PeerGossip => 9,
            message::Topic::TrustGossip => 10,
            message::Topic::Health => 11,
            message::Topic::Other => 12,
            message::Topic::Connect => 13,
        });
        projection.extend_from_slice(&(self.shape.stream_wire_bytes as u128).to_le_bytes());
        projection.push(u8::from(self.shape.broadcast));
        match self.shape.reply_writer_timeout_attempt {
            None => projection.push(0),
            Some(attempt) => {
                projection.push(1);
                projection.push(attempt);
            }
        }
        projection.extend_from_slice(self.shape.request_digest.as_ref());
        match self.shape.authority {
            None => projection.push(0),
            Some(ProgressAuthorityIdentity::Topology(generation)) => {
                projection.push(1);
                projection.extend_from_slice(&generation.to_le_bytes());
            }
            Some(ProgressAuthorityIdentity::Reply(connection_ordinal)) => {
                projection.push(2);
                projection.extend_from_slice(&connection_ordinal.to_le_bytes());
            }
        }
        match &self.source.target {
            None => projection.push(0),
            Some(target) => {
                projection.push(1);
                projection.extend_from_slice(&target.encode());
            }
        }
        projection.push(match self.source.class {
            ActorProgressClass::Safety => 1,
            ActorProgressClass::Lane => 2,
            ActorProgressClass::Bulk => 3,
        });
        Hash::new_from_chunks(&[DOMAIN, projection.as_slice()])
    }
}
impl NetworkActorAdmissionTicket {
    /// Return the ticket's one-based per-source service rank, or `None` after cancellation.
    #[must_use]
    pub fn rank(&self) -> Option<usize> {
        self.active
            .then(|| self.budget.rank(&self.source, self.id, self.shape))
            .flatten()
    }
    fn commit(&mut self) {
        if self.active {
            let authority_cancelled = self
                .authority
                .as_ref()
                .is_some_and(WeakProgressDeliveryAuthority::is_cancelled);
            self.budget
                .commit(&self.source, self.id, self.shape, authority_cancelled);
            self.active = false;
        }
    }
}
impl Drop for NetworkActorAdmissionTicket {
    fn drop(&mut self) {
        if self.active {
            self.budget.cancel(&self.source, self.id, self.shape);
            self.active = false;
        }
    }
}
/// Test-only owner of a genuine actor-admission waiter and its cancellation witness.
///
/// This fixture is absent unless tests or the `test-fixtures` feature are
/// enabled. It lets dependent-crate tests move a real admission ticket through
/// an ownership container without exposing the production budget internals.
#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Clone, Debug)]
pub struct NetworkActorAdmissionTicketTestFixture {
    budget: Arc<NetworkActorProgressBudget>,
    topology_membership: Option<Arc<ReliableProgressMembership>>,
}
#[cfg(any(test, feature = "test-fixtures"))]
impl NetworkActorAdmissionTicketTestFixture {
    /// Create an active admission ticket bound to an exact topology post.
    #[must_use]
    pub fn for_topology<T>(post: &Post<T>) -> (Self, NetworkActorAdmissionTicket)
    where
        T: Pload + message::ClassifyTopic,
    {
        let topic = post.data.topic();
        let subscriber_route = post.data.subscriber_route();
        assert!(
            is_reliable_progress_route(topic, subscriber_route),
            "test topology post must use a reliable-progress route"
        );
        let mut canonical_post = post.clone();
        canonical_post.priority =
            canonical_outbound_priority(topic, subscriber_route, canonical_post.priority);
        let stream_wire_bytes = ncore::encoded_payload_len(&canonical_post.data)
            .expect("test topology payload must have a canonical Norito encoding")
            .max(1);
        let canonical = NetworkMessage::Post(canonical_post);
        let class = ActorProgressClass::for_payload(&post.data)
            .expect("reliable test topology route must have an actor class");
        let membership = Arc::new(ReliableProgressMembership {
            peer_id: post.peer_id.clone(),
            generation: 1,
            active: AtomicBool::new(true),
        });
        let authority = ProgressDeliveryAuthority::Topology(Arc::clone(&membership));
        let shape = ProgressTicketShape {
            topic,
            stream_wire_bytes,
            broadcast: false,
            reply_writer_timeout_attempt: None,
            request_digest: progress_ticket_request_digest(&canonical),
            authority: Some(authority.identity()),
        };
        let source = ActorProgressSource {
            target: Some(post.peer_id.clone()),
            class,
        };
        let fixture = Self {
            budget: NetworkActorProgressBudget::new(stream_wire_bytes, 1, 1)
                .expect("test actor admission geometry must fit"),
            topology_membership: Some(membership),
        };
        let ProgressLeaseAttempt::Ready { lease, ticket } = fixture.budget.try_reserve_for_source(
            stream_wire_bytes,
            shape,
            source,
            Some(&authority),
            None,
        ) else {
            panic!("fresh test actor admission ticket must own rank one");
        };
        // Model an actor queue which filled after budget reservation. The
        // exact waiter and canonical post return to the caller for retry.
        drop(lease);
        debug_assert_eq!(ticket.rank(), Some(1));
        (fixture, ticket)
    }
    /// Create an active admission ticket bound to an exact canonical reply.
    #[must_use]
    pub fn for_reply<T>(
        post: &Post<T>,
        route: &NetworkReplyRoute,
    ) -> (Self, NetworkActorAdmissionTicket)
    where
        T: Pload + message::ClassifyTopic,
    {
        Self::for_reply_at_attempt(post, route, 0)
    }
    /// Create a reply admission ticket bound to one adaptive timeout generation.
    #[must_use]
    pub fn for_reply_at_attempt<T>(
        post: &Post<T>,
        route: &NetworkReplyRoute,
        reply_writer_timeout_attempt: u8,
    ) -> (Self, NetworkActorAdmissionTicket)
    where
        T: Pload + message::ClassifyTopic,
    {
        assert!(
            route.is_reply_writable(),
            "test reply route must accept admission"
        );
        assert_eq!(
            &post.peer_id,
            route.semantic_target(),
            "test reply post must retain the route's semantic target"
        );
        let topic = post.data.topic();
        let subscriber_route = post.data.subscriber_route();
        assert!(
            is_reliable_progress_route(topic, subscriber_route),
            "test reply post must use a reliable-progress route"
        );
        let mut canonical_post = post.clone();
        canonical_post.priority =
            canonical_outbound_priority(topic, subscriber_route, canonical_post.priority);
        let stream_wire_bytes = ncore::encoded_payload_len(&canonical_post.data)
            .expect("test reply payload must have a canonical Norito encoding")
            .max(1);
        let canonical = NetworkMessage::Post(canonical_post);
        let class = ActorProgressClass::for_payload(&post.data)
            .expect("reliable test reply route must have an actor class");
        let authority = ProgressDeliveryAuthority::Reply(route.clone());
        let shape = ProgressTicketShape {
            topic,
            stream_wire_bytes,
            broadcast: false,
            reply_writer_timeout_attempt: Some(reply_writer_timeout_attempt),
            request_digest: progress_ticket_request_digest(&canonical),
            authority: Some(authority.identity()),
        };
        let source = ActorProgressSource {
            target: Some(route.tenure.delivery_peer.clone()),
            class,
        };
        let fixture = Self {
            budget: NetworkActorProgressBudget::new(stream_wire_bytes, 1, 1)
                .expect("test actor admission geometry must fit"),
            topology_membership: None,
        };
        let ProgressLeaseAttempt::Ready { lease, ticket } = fixture.budget.try_reserve_for_source(
            stream_wire_bytes,
            shape,
            source,
            Some(&authority),
            None,
        ) else {
            panic!("fresh test actor admission ticket must own rank one");
        };
        // This is the state returned to a caller when actor-queue admission
        // fails after budget reservation: the lease returns to the budget,
        // while the exact waiter ticket and canonical post stay caller-owned.
        drop(lease);
        debug_assert_eq!(ticket.rank(), Some(1));
        (fixture, ticket)
    }
    /// Return the number of live waiters in this isolated budget.
    #[must_use]
    pub fn waiter_count(&self) -> usize {
        self.budget
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .waiter_count
    }
    /// Cancel the exact topology tenure retained by [`Self::for_topology`].
    ///
    /// This mirrors actor topology reconciliation: the membership becomes
    /// inactive before every waiter bound to that generation is removed.
    #[must_use]
    pub fn cancel_topology_membership(&self) -> usize {
        let membership = self
            .topology_membership
            .as_ref()
            .expect("only a topology ticket fixture owns topology membership");
        membership.cancel();
        self.budget.cancel_membership(membership, false)
    }
    /// Return the number of exact waiters removed by admission-ticket drop.
    #[must_use]
    pub fn ticket_drop_cancellations(&self) -> usize {
        self.budget
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ticket_drop_cancellations
    }
}
mod best_effort_admission;
pub use best_effort_admission::{NetworkActorAdmissionRejection, NetworkPostAdmissionError};
/// Recoverable result of semantic-progress admission into the network actor.
#[derive(Debug)]
pub enum NetworkActorAdmissionError<M> {
    /// Capacity is temporarily unavailable; the exact message is returned.
    Backpressured {
        /// Original message, including its caller-supplied priority.
        message: M,
        /// Per-source ticket when the bounded source set had room.
        ticket: Option<NetworkActorAdmissionTicket>,
        /// Current one-based source rank; rank two means another caller owns rank one.
        rank: usize,
    },
    /// The network actor has terminated; retrying this handle cannot succeed.
    Closed {
        /// Original message, including its caller-supplied priority.
        message: M,
    },
    /// The request is permanently invalid for this admission API.
    Rejected {
        /// Original message, including its caller-supplied priority.
        message: M,
        /// Stable reason for rejection.
        reason: NetworkActorAdmissionRejection,
    },
}
impl<M> NetworkActorAdmissionError<M> {
    fn map_message<N>(self, map: impl FnOnce(M) -> N) -> NetworkActorAdmissionError<N> {
        match self {
            Self::Backpressured {
                message,
                ticket,
                rank,
            } => NetworkActorAdmissionError::Backpressured {
                message: map(message),
                ticket,
                rank,
            },
            Self::Closed { message } => NetworkActorAdmissionError::Closed {
                message: map(message),
            },
            Self::Rejected { message, reason } => NetworkActorAdmissionError::Rejected {
                message: map(message),
                reason,
            },
        }
    }
}
/// Non-blocking state of one process-local reliable reply completion.
///
/// Completion is deliberately not serializable: it witnesses only the local
/// network actor observing a successful full write and flush by the exact peer
/// writer which owns the admitted reply occurrence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkReplyFlushAckStatus {
    /// The admitted actor item has not yet observed a successful writer flush.
    Pending,
    /// The exact admitted reply was fully written and flushed by its peer writer.
    Flushed,
    /// The exact admitted reply exceeded its actor-owned writer deadline.
    TimedOut,
    /// Actor ownership ended without observing a successful writer flush.
    Closed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetworkReplyFlushCompletion {
    Flushed,
    TimedOut,
}
/// Immutable process-local identity of one admitted reliable-reply flush.
///
/// The identity retains the opaque route tenure and actor-budget owner which
/// admitted the exact canonical request. Numeric ordinals and ticket ids are
/// therefore facts about this identity, never ambient globally forgeable ids.
/// It intentionally has no wire codec.
#[derive(Clone)]
pub struct NetworkReplyFlushIdentity {
    route: NetworkReplyRoute,
    ticket: NetworkActorAdmittedTicketIdentity,
    /// Linear claim shared by every clone of this exact actor completion.
    ///
    /// A consumer may therefore retain immutable identity projections without
    /// allowing an already-applied writer receipt to advance a later,
    /// byte-identical rematerialization of the same semantic request.
    completion_claimed: Arc<AtomicBool>,
}
impl core::fmt::Debug for NetworkReplyFlushIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NetworkReplyFlushIdentity")
            .field("semantic_target", &self.route.semantic_target)
            .field("authenticated_source", &self.route.tenure.delivery_peer)
            .field(
                "connection_tenure_ordinal",
                &self.route.tenure.connection_ordinal,
            )
            .field("delivery_ordinal", &self.route.delivery_ordinal)
            .field("ticket_id", &self.ticket.id)
            .field("ticket_rank", &self.ticket.rank)
            .field("topic", &self.ticket.shape.topic)
            .field("stream_wire_bytes", &self.ticket.shape.stream_wire_bytes)
            .field(
                "reply_writer_timeout_attempt",
                &self.ticket.shape.reply_writer_timeout_attempt,
            )
            .finish_non_exhaustive()
    }
}
impl NetworkReplyFlushIdentity {
    /// Build the completion identity for a ticket already validated by reply
    /// admission.
    ///
    /// Production calls this only after the actor budget has admitted the
    /// exact reply shape. The checks remain fail-closed defense in depth for
    /// malformed internal tickets.
    fn from_admitted_ticket(ticket: NetworkActorAdmittedTicketIdentity) -> Option<Self> {
        let ProgressDeliveryAuthority::Reply(route) = &ticket.authority else {
            return None;
        };
        let expected_authority = Some(ProgressAuthorityIdentity::Reply(
            route.tenure.connection_ordinal,
        ));
        if ticket.shape.reply_writer_timeout_attempt.is_none()
            || ticket.shape.authority != expected_authority
            || ticket.source.target.as_ref() != Some(&route.tenure.delivery_peer)
            || ticket.shape.broadcast
        {
            return None;
        }
        let route = route.clone();
        debug_assert_eq!(ticket.shape.authority, expected_authority);
        debug_assert_eq!(
            ticket.source.target.as_ref(),
            Some(&route.tenure.delivery_peer)
        );
        debug_assert!(!ticket.shape.broadcast);
        Some(Self {
            route,
            ticket,
            completion_claimed: Arc::new(AtomicBool::new(false)),
        })
    }
    /// Semantic peer to which the admitted reply is addressed.
    #[must_use]
    pub fn semantic_target(&self) -> &PeerId {
        self.route.semantic_target()
    }
    /// Opaque authenticated-source identity which owns this reply attempt.
    #[must_use]
    pub fn source_key(&self) -> NetworkReplySourceKey {
        self.route.source_key()
    }
    /// Authenticated transport peer which owns this reply attempt.
    #[must_use]
    pub fn authenticated_source_peer(&self) -> &PeerId {
        &self.route.tenure.delivery_peer
    }
    /// Whether the reply was admitted through `peer` as its authenticated source.
    #[must_use]
    pub fn is_authenticated_via(&self, peer: &PeerId) -> bool {
        self.route.is_authenticated_via(peer)
    }
    /// Actor-global ordinal of the authenticated connection tenure.
    #[must_use]
    pub fn connection_tenure_ordinal(&self) -> u128 {
        self.route.tenure.connection_ordinal
    }
    /// Actor-global ordinal of this local delivery occurrence.
    ///
    /// This occurrence ordinal is deliberately excluded from
    /// [`Self::same_ticket_identity`].
    #[must_use]
    pub fn delivery_ordinal(&self) -> u128 {
        self.route.delivery_ordinal
    }
    /// Actor-budget-local ticket identifier which crossed admission.
    #[must_use]
    pub fn ticket_id(&self) -> u64 {
        self.ticket.id
    }
    /// One-based service rank at the instant this ticket crossed admission.
    #[must_use]
    pub fn ticket_rank(&self) -> usize {
        self.ticket.rank
    }
    /// Canonical reliable-progress topic bound into the admitted ticket.
    #[must_use]
    pub fn ticket_topic(&self) -> message::Topic {
        self.ticket.shape.topic
    }
    /// Exact encrypted-stream queue charge bound into the admitted ticket.
    #[must_use]
    pub fn ticket_stream_wire_bytes(&self) -> usize {
        self.ticket.shape.stream_wire_bytes
    }
    /// Bounded adaptive writer-timeout generation admitted with this reply.
    #[must_use]
    pub fn reply_writer_timeout_attempt(&self) -> u8 {
        self.ticket
            .shape
            .reply_writer_timeout_attempt
            .expect("reply flush identity construction requires a timeout attempt")
    }
    /// Digest of the canonical priority, semantic target, and encoded payload.
    #[must_use]
    pub fn canonical_request_digest(&self) -> Hash {
        self.ticket.shape.request_digest
    }
    /// Process-local identity of the exact admitted delivery route.
    ///
    /// Unlike the semantic source key, this changes across reconnects and
    /// later deliveries. It has no wire, persistence, or consensus meaning.
    #[must_use]
    pub fn process_local_route_identity_hash(&self) -> Hash {
        self.route.process_local_identity_hash()
    }
    /// Process-local identity of this exact actor-minted writer completion.
    ///
    /// The digest binds the equality-preserving admitted-ticket identity, the
    /// exact delivery route, and the clone-shared linear completion claim. An
    /// independently rebuilt identity therefore cannot alias the completion
    /// originally returned by the actor even when all visible ticket and route
    /// fields are equal. This identity is never serialized or persisted.
    #[must_use]
    pub fn process_local_writer_occurrence_identity_hash(&self) -> Hash {
        const DOMAIN: &[u8] = b"iroha:p2p:writer-flush-process-local-identity:v1\n";
        let ticket = self.ticket.process_local_identity_hash();
        let route = self.route.process_local_identity_hash();
        let completion_claim =
            (Arc::as_ptr(&self.completion_claimed) as usize as u128).to_le_bytes();
        Hash::new_from_chunks(&[DOMAIN, ticket.as_ref(), route.as_ref(), &completion_claim])
    }
    /// Consume this exact actor-minted writer completion at most once.
    ///
    /// Cloned identities share the same process-local claim. This operation
    /// does not attest that the writer flushed; callers must first obtain the
    /// terminal [`NetworkReplyFlushAckStatus::Flushed`] result from the
    /// matching [`NetworkReplyFlushAck`].
    #[must_use]
    pub fn claim_writer_flush_once(&self) -> bool {
        self.completion_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
    /// Whether `route` is the exact authenticated tenure and semantic target.
    ///
    /// A later delivery on that tenure remains tenure-bound even though it is
    /// not the same delivery occurrence.
    #[must_use]
    pub fn is_bound_to_tenure(&self, route: &NetworkReplyRoute) -> bool {
        self.route.same_tenure(route)
            && self.route.semantic_target == route.semantic_target
            && self.route.same_source(route)
    }
    /// Whether `route` is the exact local delivery occurrence admitted here.
    #[must_use]
    pub fn is_bound_to_delivery(&self, route: &NetworkReplyRoute) -> bool {
        self.route.same_delivery(route)
    }
    /// Whether `post` has the exact canonical semantic target and payload
    /// identity admitted by this reply ticket.
    #[must_use]
    pub fn is_bound_to_canonical_reply<T>(&self, post: &Post<T>) -> bool
    where
        T: Pload + message::ClassifyTopic,
    {
        if !post.data.is_outbound_allowed() {
            return false;
        }
        let topic = post.data.topic();
        let route = post.data.subscriber_route();
        if !is_reliable_progress_route(topic, route) {
            return false;
        }
        let canonical = NetworkMessage::Post(Post {
            data: post.data.clone(),
            peer_id: post.peer_id.clone(),
            priority: canonical_outbound_priority(topic, route, post.priority),
        });
        self.route.semantic_target == post.peer_id
            && self.ticket.shape.topic == topic
            && !self.ticket.shape.broadcast
            && self.ticket.shape.request_digest == progress_ticket_request_digest(&canonical)
    }
    /// Whether both completions came from the exact actor ticket, route
    /// tenure, semantic target, authenticated source, and canonical payload.
    ///
    /// The delivery ordinal is intentionally absent: a later occurrence on
    /// the same tenure retains ticket identity, whereas another tenure,
    /// source, payload, or actor budget cannot alias it.
    #[must_use]
    pub fn same_ticket_identity(&self, other: &Self) -> bool {
        self.ticket.same_ticket(&other.ticket)
            && self.route.same_tenure(&other.route)
            && self.route.semantic_target == other.route.semantic_target
            && self.route.same_source(&other.route)
    }
    /// Whether both completions identify the same ticket and exact delivery occurrence.
    #[must_use]
    pub fn same_delivery_occurrence(&self, other: &Self) -> bool {
        self.same_ticket_identity(other) && self.route.same_delivery(&other.route)
    }
    /// Whether both values are clones of the exact actor-minted writer completion.
    ///
    /// Ticket and delivery equality alone is insufficient: independently
    /// rebuilding an identity from the same admitted ticket would allocate
    /// another linear completion claim. Only clones of the original identity
    /// may accompany its writer acknowledgement across the runner boundary.
    #[must_use]
    pub fn same_writer_flush_occurrence(&self, other: &Self) -> bool {
        self.same_delivery_occurrence(other)
            && Arc::ptr_eq(&self.completion_claimed, &other.completion_claimed)
    }
}
/// Ownership result from reliable reply admission when no flush witness is requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkReplyAdmissionOutcome {
    /// The network actor accepted the exact reply occurrence.
    Admitted,
    /// The authenticated delivery remains valid, but its writer no longer
    /// accepts output. No actor ownership transferred; requester
    /// retransmission or a newer same-source route must retry and re-admit the
    /// immutable current reply item.
    ReplyWriterUnavailable,
}
/// Opaque process-local completion for a newly admitted reliable reply.
///
/// Route retirement, actor shutdown, cancellation, or dropping the retained
/// actor item closes the handle without producing a false successful result.
/// The handle is intentionally neither cloneable nor serializable, so one
/// caller owns the exact local completion witness.
#[derive(Debug)]
#[must_use = "dropping the flush acknowledgement discards the delivery witness"]
pub struct NetworkReplyFlushAck {
    identity: NetworkReplyFlushIdentity,
    receiver: Option<tokio::sync::oneshot::Receiver<NetworkReplyFlushCompletion>>,
    terminal: Option<NetworkReplyFlushAckStatus>,
}
impl NetworkReplyFlushAck {
    fn new(
        identity: NetworkReplyFlushIdentity,
        receiver: tokio::sync::oneshot::Receiver<NetworkReplyFlushCompletion>,
    ) -> Self {
        Self {
            identity,
            receiver: Some(receiver),
            terminal: None,
        }
    }
    /// Immutable route, ticket, and canonical-payload identity for this completion.
    #[must_use]
    pub fn identity(&self) -> &NetworkReplyFlushIdentity {
        &self.identity
    }
    /// Poll without blocking for the local writer-flush outcome.
    ///
    /// Once this returns a terminal result, every later poll returns that same
    /// result.
    pub fn poll(&mut self) -> NetworkReplyFlushAckStatus {
        if let Some(terminal) = self.terminal {
            return terminal;
        }
        let receiver = self
            .receiver
            .as_mut()
            .expect("nonterminal reply flush acknowledgement owns its receiver");
        match receiver.try_recv() {
            Ok(NetworkReplyFlushCompletion::Flushed) => {
                self.receiver = None;
                self.terminal = Some(NetworkReplyFlushAckStatus::Flushed);
                NetworkReplyFlushAckStatus::Flushed
            }
            Ok(NetworkReplyFlushCompletion::TimedOut) => {
                self.receiver = None;
                self.terminal = Some(NetworkReplyFlushAckStatus::TimedOut);
                NetworkReplyFlushAckStatus::TimedOut
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                NetworkReplyFlushAckStatus::Pending
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                self.receiver = None;
                self.terminal = Some(NetworkReplyFlushAckStatus::Closed);
                NetworkReplyFlushAckStatus::Closed
            }
        }
    }
}
/// Test-only controller for one opaque reply writer-flush completion.
#[cfg(any(test, feature = "test-fixtures"))]
pub struct NetworkReplyFlushAckTestFixture {
    sender: Option<tokio::sync::oneshot::Sender<NetworkReplyFlushCompletion>>,
}
#[cfg(any(test, feature = "test-fixtures"))]
impl NetworkReplyFlushAckTestFixture {
    /// Create one pending completion and its sole test controller.
    #[must_use = "retain both the controller and acknowledgement to observe writer completion"]
    pub fn new() -> (Self, NetworkReplyFlushAck) {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let route_owner = Arc::new(());
        let authenticated_source = PeerId::from(
            KeyPair::random_with_algorithm(Algorithm::BlsNormal)
                .public_key()
                .clone(),
        );
        let semantic_target = PeerId::from(
            KeyPair::random_with_algorithm(Algorithm::BlsNormal)
                .public_key()
                .clone(),
        );
        let route = NetworkReplyRoute::new(
            semantic_target,
            Arc::new(ReliableReplyRouteTenure {
                owner: route_owner,
                _source_credits: crate::peer::message::AuthenticatedSourceCredits::new(1),
                delivery_peer: authenticated_source.clone(),
                connection_id: 0,
                connection_ordinal: 0,
                source_capacity: 1,
                delivery_active: AtomicBool::new(true),
                reply_writable: AtomicBool::new(true),
                delivery_drain: InboundDeliveryDrain::completed_for_test(),
                termination_seen: AtomicBool::new(false),
            }),
            0,
        );
        let ticket = NetworkActorAdmittedTicketIdentity {
            budget: NetworkActorProgressBudget::new(1, 1, 1)
                .expect("test flush identity geometry must be valid"),
            id: 0,
            rank: 1,
            shape: ProgressTicketShape {
                topic: message::Topic::Consensus,
                stream_wire_bytes: 1,
                broadcast: false,
                reply_writer_timeout_attempt: Some(0),
                request_digest: Hash::new(b"test-only-reply-flush-identity"),
                authority: Some(ProgressAuthorityIdentity::Reply(0)),
            },
            source: ActorProgressSource {
                target: Some(authenticated_source),
                class: ActorProgressClass::Lane,
            },
            authority: ProgressDeliveryAuthority::Reply(route.clone()),
        };
        let identity = NetworkReplyFlushIdentity::from_admitted_ticket(ticket)
            .expect("test completion must retain reply authority");
        (
            Self {
                sender: Some(sender),
            },
            NetworkReplyFlushAck::new(identity, receiver),
        )
    }
    /// Create a pending completion bound to an exact canonical reply post and route.
    ///
    /// Independent calls deliberately mint distinct synthetic actor budgets, so
    /// tests cannot mistake equal visible ticket fields for the same opaque
    /// admission authority.
    #[must_use = "retain both the controller and acknowledgement to observe writer completion"]
    pub fn for_reply<T>(post: &Post<T>, route: &NetworkReplyRoute) -> (Self, NetworkReplyFlushAck)
    where
        T: Pload + message::ClassifyTopic,
    {
        Self::for_reply_at_attempt(post, route, 0)
    }
    /// Create a pending completion bound to one adaptive timeout generation.
    #[must_use = "retain both the controller and acknowledgement to observe writer completion"]
    pub fn for_reply_at_attempt<T>(
        post: &Post<T>,
        route: &NetworkReplyRoute,
        reply_writer_timeout_attempt: u8,
    ) -> (Self, NetworkReplyFlushAck)
    where
        T: Pload + message::ClassifyTopic,
    {
        assert!(route.is_active(), "test reply route must remain active");
        assert_eq!(
            &post.peer_id,
            route.semantic_target(),
            "test reply post must retain the route's semantic target"
        );
        let topic = post.data.topic();
        let subscriber_route = post.data.subscriber_route();
        assert!(
            is_reliable_progress_route(topic, subscriber_route),
            "test reply post must use a reliable-progress route"
        );
        let mut canonical_post = post.clone();
        canonical_post.priority =
            canonical_outbound_priority(topic, subscriber_route, canonical_post.priority);
        // The fixture has no local peer/encryptor context from which to reproduce
        // the production stream charge, so retain a deterministic positive budget
        // from the same canonical payload serialization used by actor admission.
        let stream_wire_bytes = ncore::encoded_payload_len(&canonical_post.data)
            .expect("test reply payload must have a canonical Norito encoding")
            .max(1);
        let canonical = NetworkMessage::Post(canonical_post);
        let class = ActorProgressClass::for_payload(&post.data)
            .expect("reliable test reply route must have an actor class");
        let ticket = NetworkActorAdmittedTicketIdentity {
            budget: NetworkActorProgressBudget::new(stream_wire_bytes, 1, 1)
                .expect("test flush identity geometry must be valid"),
            id: 0,
            rank: 1,
            shape: ProgressTicketShape {
                topic,
                stream_wire_bytes,
                broadcast: false,
                reply_writer_timeout_attempt: Some(reply_writer_timeout_attempt),
                request_digest: progress_ticket_request_digest(&canonical),
                authority: Some(ProgressAuthorityIdentity::Reply(
                    route.tenure.connection_ordinal,
                )),
            },
            source: ActorProgressSource {
                target: Some(route.tenure.delivery_peer.clone()),
                class,
            },
            authority: ProgressDeliveryAuthority::Reply(route.clone()),
        };
        let identity = NetworkReplyFlushIdentity::from_admitted_ticket(ticket)
            .expect("test completion must retain reply authority");
        let (sender, receiver) = tokio::sync::oneshot::channel();
        (
            Self {
                sender: Some(sender),
            },
            NetworkReplyFlushAck::new(identity, receiver),
        )
    }
    /// Publish the exact successful writer-flush witness once.
    pub fn flush(&mut self) -> bool {
        self.sender
            .take()
            .is_some_and(|sender| sender.send(NetworkReplyFlushCompletion::Flushed).is_ok())
    }
    /// Publish the exact actor-owned writer-timeout result once.
    pub fn timeout(&mut self) -> bool {
        self.sender
            .take()
            .is_some_and(|sender| sender.send(NetworkReplyFlushCompletion::TimedOut).is_ok())
    }
    /// Close the completion without publishing success once.
    pub fn close(&mut self) -> bool {
        self.sender.take().is_some()
    }
}
#[derive(Debug)]
struct NetworkBroadcastTargetTicket {
    membership: Arc<ReliableProgressMembership>,
    actor_ticket: Option<NetworkActorAdmissionTicket>,
}
/// Opaque, exact per-target ownership returned when only part of a reliable
/// broadcast fanout could cross actor admission.
///
/// The ticket owns no payload. The caller must retain the returned broadcast
/// and pass this ticket with that same canonical request. Each target carries
/// its accepted-topology membership generation, preventing a delayed retry
/// from crossing a remove/re-add transition for the same peer id. Tickets are
/// also bound to the originating actor budget and topology publication; they
/// cannot be moved to another network handle, including before first snapshot.
#[derive(Debug)]
pub struct NetworkBroadcastAdmissionTicket {
    request_digest: Hash,
    budget: Arc<NetworkActorProgressBudget>,
    topology: Arc<Mutex<ReliableProgressTopology>>,
    /// `true` until a non-empty accepted topology can be snapshotted.
    needs_topology_snapshot: bool,
    targets: VecDeque<NetworkBroadcastTargetTicket>,
}
impl NetworkBroadcastAdmissionTicket {
    fn fresh(
        request_digest: Hash,
        budget: Arc<NetworkActorProgressBudget>,
        topology: Arc<Mutex<ReliableProgressTopology>>,
    ) -> Self {
        Self {
            request_digest,
            budget,
            topology,
            needs_topology_snapshot: true,
            targets: VecDeque::new(),
        }
    }
    /// Number of already-snapshotted target copies which remain with the caller.
    ///
    /// Zero does not mean completion while [`Self::awaiting_topology_snapshot`]
    /// is true, because actor-accepted target authority has not been published
    /// yet.
    #[must_use]
    pub fn pending_targets(&self) -> usize {
        self.targets.len()
    }
    /// Whether this ticket still awaits its first non-empty actor-accepted
    /// topology snapshot.
    #[must_use]
    pub fn awaiting_topology_snapshot(&self) -> bool {
        self.needs_topology_snapshot
    }
}
/// Ownership-preserving result of a targetized reliable broadcast admission.
#[derive(Debug)]
pub enum NetworkBroadcastAdmissionError<M> {
    /// Some exact target copies remain with the caller under this retry ticket.
    Backpressured {
        /// Original canonical broadcast.
        message: M,
        /// Exact remaining target set and per-target FIFO positions.
        ticket: NetworkBroadcastAdmissionTicket,
        /// Smallest current one-based rank among target copies with a rank.
        rank: usize,
    },
    /// The actor has terminated; the returned target copies were not admitted.
    Closed {
        /// Original canonical broadcast.
        message: M,
        /// Exact target copies which remain with the caller.
        ticket: NetworkBroadcastAdmissionTicket,
    },
    /// The request or supplied retry ticket permanently violates admission.
    Rejected {
        /// Original canonical broadcast.
        message: M,
        /// Supplied target ownership, when rejection happened during a retry.
        ticket: Option<NetworkBroadcastAdmissionTicket>,
        /// Stable rejection reason.
        reason: NetworkActorAdmissionRejection,
    },
}
#[derive(Debug)]
struct NetworkActorProgressLease {
    budget: Arc<NetworkActorProgressBudget>,
    bytes: usize,
    source: ActorProgressSource,
    /// One-based waiter rank observed under the admission budget lock.
    admission_rank: usize,
    /// Cryptographic identity of the canonical request which owns this lease.
    request_digest: Hash,
    broadcast: bool,
    authority: Option<ProgressAuthorityIdentity>,
}
enum ProgressLeaseAttempt {
    Ready {
        lease: NetworkActorProgressLease,
        ticket: NetworkActorAdmissionTicket,
    },
    /// This target lane already owns the same idempotent broadcast request in
    /// the same accepted-topology membership generation.
    SameRequestAlreadyOwned,
    /// The accepted-topology membership was removed before actor admission.
    CancelledMembership,
    Waiting {
        ticket: Option<NetworkActorAdmissionTicket>,
        rank: usize,
    },
    InvalidTicket,
    Oversize,
}
impl NetworkActorProgressBudget {
    fn new(
        per_source_max_bytes: usize,
        max_sources: usize,
        max_waiters: usize,
    ) -> Option<Arc<Self>> {
        if per_source_max_bytes == 0 || max_sources == 0 || max_waiters == 0 {
            return None;
        }
        let max_total_bytes = per_source_max_bytes.checked_mul(max_sources)?;
        Some(Arc::new(Self {
            per_class_max_bytes: ActorProgressByteLimits::uniform(per_source_max_bytes),
            max_sources,
            max_sources_per_class: max_sources,
            max_total_bytes,
            max_waiters,
            max_waiters_per_class: [max_waiters; ActorProgressClass::COUNT],
            max_waiters_per_source: [max_waiters; ActorProgressClass::COUNT],
            state: Mutex::new(NetworkActorProgressState::default()),
        }))
    }
    fn new_classed(
        per_class_max_bytes: ActorProgressByteLimits,
        target_sources: usize,
        max_waiters: usize,
    ) -> Option<Arc<Self>> {
        if target_sources == 0
            || max_waiters == 0
            || ActorProgressClass::ALL
                .into_iter()
                .any(|class| per_class_max_bytes.for_class(class) == 0)
        {
            return None;
        }
        let max_sources = target_sources.checked_mul(ActorProgressClass::COUNT)?;
        let max_waiters_per_source = actor_waiter_limits()?;
        let mut max_waiters_per_class = [0usize; ActorProgressClass::COUNT];
        let mut required_waiters = 0usize;
        for class in ActorProgressClass::ALL {
            let i = class.index();
            max_waiters_per_class[i] = target_sources.checked_mul(max_waiters_per_source[i])?;
            required_waiters = required_waiters.checked_add(max_waiters_per_class[i])?;
        }
        if max_waiters != required_waiters {
            return None;
        }
        let max_total_bytes = per_class_max_bytes
            .checked_per_target_total()?
            .checked_mul(target_sources)?;
        Some(Arc::new(Self {
            per_class_max_bytes,
            max_sources,
            max_sources_per_class: target_sources,
            max_total_bytes,
            max_waiters,
            max_waiters_per_class,
            max_waiters_per_source,
            state: Mutex::new(NetworkActorProgressState::default()),
        }))
    }
    #[cfg(test)]
    fn try_reserve(
        self: &Arc<Self>,
        bytes: usize,
        shape: ProgressTicketShape,
        ticket: Option<NetworkActorAdmissionTicket>,
    ) -> ProgressLeaseAttempt {
        self.try_reserve_for_source(bytes, shape, ActorProgressSource::test(), None, ticket)
    }
    fn try_reserve_for_source(
        self: &Arc<Self>,
        bytes: usize,
        shape: ProgressTicketShape,
        source: ActorProgressSource,
        authority: Option<&ProgressDeliveryAuthority>,
        ticket: Option<NetworkActorAdmissionTicket>,
    ) -> ProgressLeaseAttempt {
        let per_source_max_bytes = self.per_class_max_bytes.for_class(source.class);
        if bytes > per_source_max_bytes {
            return ProgressLeaseAttempt::Oversize;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let class_index = source.class.index();
        match authority {
            Some(authority)
                if shape.authority == Some(authority.identity())
                    && source.target.as_ref() == Some(authority.source_target()) =>
            {
                // Membership cancellation is published before the topology
                // reconciler acquires this budget lock. Therefore either this
                // check observes the cancellation, or the later reconciliation
                // sweep observes and removes the waiter inserted below.
                if !authority.is_active() {
                    drop(state);
                    drop(ticket);
                    return ProgressLeaseAttempt::CancelledMembership;
                }
            }
            None if !shape.broadcast && shape.authority.is_none() => {}
            _ => {
                drop(state);
                drop(ticket);
                return ProgressLeaseAttempt::InvalidTicket;
            }
        }
        let ticket = if let Some(ticket) = ticket {
            if !ticket.active
                || !Arc::ptr_eq(&ticket.budget, self)
                || ticket.shape != shape
                || ticket.source != source
                || match (&ticket.authority, authority) {
                    (Some(retained), Some(candidate)) => !retained.matches(candidate),
                    (None, None) => false,
                    (Some(_), None) | (None, Some(_)) => true,
                }
                || !state.waiters.get(&source).is_some_and(|waiters| {
                    waiters
                        .iter()
                        .any(|waiter| waiter.id == ticket.id && waiter.shape == ticket.shape)
                })
            {
                drop(state);
                drop(ticket);
                return ProgressLeaseAttempt::InvalidTicket;
            }
            if shape.broadcast
                && shape.authority.is_some()
                && state
                    .retained_by_source
                    .get(&source)
                    .is_some_and(|retained| {
                        retained.broadcast
                            && retained.request_digest == shape.request_digest
                            && retained.authority == shape.authority
                    })
            {
                drop(state);
                drop(ticket);
                return ProgressLeaseAttempt::SameRequestAlreadyOwned;
            }
            ticket
        } else {
            if shape.broadcast
                && shape.authority.is_some()
                && state
                    .retained_by_source
                    .get(&source)
                    .is_some_and(|retained| {
                        retained.broadcast
                            && retained.request_digest == shape.request_digest
                            && retained.authority == shape.authority
                    })
            {
                return ProgressLeaseAttempt::SameRequestAlreadyOwned;
            }
            // Bound every source independently so several local producers can
            // retain a real FIFO rank without consuming the ticket geometry
            // reserved for every other authenticated target and class.
            let unregistered_rank = state.waiters.get(&source).map_or(1, |waiters| {
                waiters
                    .len()
                    .checked_add(1)
                    .expect("bounded per-source waiter rank cannot overflow")
            });
            if state
                .waiters
                .get(&source)
                .is_some_and(|waiters| waiters.len() >= self.max_waiters_per_source[class_index])
            {
                return ProgressLeaseAttempt::Waiting {
                    ticket: None,
                    rank: unregistered_rank,
                };
            }
            if state.waiter_count >= self.max_waiters
                || state.waiters_by_class[class_index] >= self.max_waiters_per_class[class_index]
            {
                return ProgressLeaseAttempt::Waiting {
                    ticket: None,
                    rank: unregistered_rank,
                };
            }
            // Reset only once no live ticket can still carry the old sequence.
            // Checked allocation then makes wraparound impossible.
            if state.waiter_count == 0 {
                state.next_ticket = 0;
            }
            let id = state.next_ticket;
            let Some(next_ticket) = state.next_ticket.checked_add(1) else {
                return ProgressLeaseAttempt::Waiting {
                    ticket: None,
                    rank: unregistered_rank,
                };
            };
            state.next_ticket = next_ticket;
            state
                .waiters
                .entry(source.clone())
                .or_default()
                .push_back(NetworkActorProgressWaiter { id, shape });
            state.waiter_count = state
                .waiter_count
                .checked_add(1)
                .expect("bounded actor waiter count cannot overflow");
            state.waiters_by_class[class_index] = state.waiters_by_class[class_index]
                .checked_add(1)
                .expect("bounded actor class waiter count cannot overflow");
            NetworkActorAdmissionTicket {
                budget: Arc::clone(self),
                id,
                shape,
                source: source.clone(),
                authority: authority.map(ProgressDeliveryAuthority::downgrade),
                active: true,
            }
        };
        let rank = state
            .waiters
            .get(&source)
            .into_iter()
            .flatten()
            .position(|waiter| waiter.id == ticket.id && waiter.shape == ticket.shape)
            .map_or(0, |position| {
                position
                    .checked_add(1)
                    .expect("bounded per-source ticket rank cannot overflow")
            });
        if rank != 1 {
            return ProgressLeaseAttempt::Waiting {
                ticket: Some(ticket),
                rank,
            };
        }
        let source_retained = state.retained_by_source.get(&source).copied();
        if source_retained.is_some_and(|retained| retained.items >= 1) {
            return ProgressLeaseAttempt::Waiting {
                ticket: Some(ticket),
                rank,
            };
        }
        if source_retained
            .map_or(0, |retained| retained.bytes)
            .checked_add(bytes)
            .is_none_or(|retained| retained > per_source_max_bytes)
        {
            return ProgressLeaseAttempt::Waiting {
                ticket: Some(ticket),
                rank,
            };
        }
        if !state.retained_by_source.contains_key(&source)
            && state.retained_by_source.len() >= self.max_sources
        {
            return ProgressLeaseAttempt::Waiting {
                ticket: Some(ticket),
                rank,
            };
        }
        if state.retained_sources_by_class[class_index] >= self.max_sources_per_class {
            return ProgressLeaseAttempt::Waiting {
                ticket: Some(ticket),
                rank,
            };
        }
        let Some(retained_items) = state.retained_items.checked_add(1) else {
            return ProgressLeaseAttempt::Waiting {
                ticket: Some(ticket),
                rank,
            };
        };
        if retained_items > self.max_sources {
            return ProgressLeaseAttempt::Waiting {
                ticket: Some(ticket),
                rank,
            };
        }
        let Some(retained_bytes) = state.retained_bytes.checked_add(bytes) else {
            return ProgressLeaseAttempt::Waiting {
                ticket: Some(ticket),
                rank,
            };
        };
        if retained_bytes > self.max_total_bytes {
            return ProgressLeaseAttempt::Waiting {
                ticket: Some(ticket),
                rank,
            };
        }
        state.retained_bytes = retained_bytes;
        state.retained_items = retained_items;
        state.retained_sources_by_class[class_index] = state.retained_sources_by_class[class_index]
            .checked_add(1)
            .expect("bounded actor class source count cannot overflow");
        state.retained_by_source.insert(
            source.clone(),
            NetworkActorProgressRetention {
                bytes,
                items: 1,
                request_digest: shape.request_digest,
                broadcast: shape.broadcast,
                authority: shape.authority,
            },
        );
        drop(state);
        ProgressLeaseAttempt::Ready {
            lease: NetworkActorProgressLease {
                budget: Arc::clone(self),
                bytes,
                source,
                admission_rank: rank,
                request_digest: shape.request_digest,
                broadcast: shape.broadcast,
                authority: shape.authority,
            },
            ticket,
        }
    }
    fn rank(
        &self,
        source: &ActorProgressSource,
        id: u64,
        shape: ProgressTicketShape,
    ) -> Option<usize> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .waiters
            .get(source)?
            .iter()
            .position(|waiter| waiter.id == id && waiter.shape == shape)
            .map(|position| {
                position
                    .checked_add(1)
                    .expect("bounded per-source ticket rank cannot overflow")
            })
    }
    fn commit(
        &self,
        source: &ActorProgressSource,
        id: u64,
        shape: ProgressTicketShape,
        authority_cancelled: bool,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let position = state.waiters.get(source).and_then(|waiters| {
            waiters
                .iter()
                .position(|waiter| waiter.id == id && waiter.shape == shape)
        });
        match position {
            Some(0) => {
                let removed = state.waiters.get_mut(source).and_then(VecDeque::pop_front);
                debug_assert!(removed.is_some());
            }
            Some(_) => panic!("only the exact head progress ticket may commit"),
            None if authority_cancelled => return,
            None => panic!("an active progress ticket must retain its exact waiter"),
        }
        state.waiter_count = state
            .waiter_count
            .checked_sub(1)
            .expect("progress ticket commit must match waiter ownership");
        let class_index = source.class.index();
        state.waiters_by_class[class_index] = state.waiters_by_class[class_index]
            .checked_sub(1)
            .expect("progress ticket commit must match class ownership");
        if state.waiters.get(source).is_some_and(VecDeque::is_empty) {
            state.waiters.remove(source);
        }
        if state.waiter_count == 0 {
            state.next_ticket = 0;
        }
    }
    fn cancel(&self, source: &ActorProgressSource, id: u64, shape: ProgressTicketShape) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let removed = state.waiters.get_mut(source).is_some_and(|waiters| {
            let Some(position) = waiters
                .iter()
                .position(|waiter| waiter.id == id && waiter.shape == shape)
            else {
                return false;
            };
            waiters.remove(position);
            true
        });
        if removed {
            state.waiter_count = state
                .waiter_count
                .checked_sub(1)
                .expect("progress ticket cancellation must match waiter ownership");
            let class_index = source.class.index();
            state.waiters_by_class[class_index] = state.waiters_by_class[class_index]
                .checked_sub(1)
                .expect("progress ticket cancellation must match class ownership");
            #[cfg(any(test, feature = "test-fixtures"))]
            {
                state.ticket_drop_cancellations = state
                    .ticket_drop_cancellations
                    .checked_add(1)
                    .expect("bounded test ticket cancellation count cannot overflow");
            }
        }
        if state.waiters.get(source).is_some_and(VecDeque::is_empty) {
            state.waiters.remove(source);
        }
        if state.waiter_count == 0 {
            state.next_ticket = 0;
        }
    }
    /// Cancel every caller-held waiter bound to one removed topology tenure.
    ///
    /// The payload remains with its caller, but topology removal is the exact
    /// semantic cancellation witness for that target copy. Matching the full
    /// waiter shape prevents a delayed old ticket from deleting a freshly
    /// allocated waiter after the ticket sequence resets.
    fn cancel_membership(&self, membership: &ReliableProgressMembership, broadcast: bool) -> usize {
        self.cancel_authority_waiters(
            &membership.peer_id,
            ProgressAuthorityIdentity::Topology(membership.generation),
            broadcast,
        )
    }
    fn cancel_reply_route(&self, tenure: &ReliableReplyRouteTenure) -> usize {
        self.cancel_authority_waiters(
            &tenure.delivery_peer,
            ProgressAuthorityIdentity::Reply(tenure.connection_ordinal),
            false,
        )
    }
    fn cancel_authority_waiters(
        &self,
        source_peer: &PeerId,
        authority: ProgressAuthorityIdentity,
        broadcast: bool,
    ) -> usize {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut cancelled = 0usize;
        for class in ActorProgressClass::ALL {
            let source = ActorProgressSource {
                target: Some(source_peer.clone()),
                class,
            };
            let removed = state.waiters.get_mut(&source).map_or(0, |waiters| {
                let before = waiters.len();
                waiters.retain(|waiter| {
                    !(waiter.shape.broadcast == broadcast
                        && waiter.shape.authority == Some(authority))
                });
                before
                    .checked_sub(waiters.len())
                    .expect("retaining waiters cannot increase their count")
            });
            if removed == 0 {
                continue;
            }
            cancelled = cancelled
                .checked_add(removed)
                .expect("bounded cancelled waiter count cannot overflow");
            state.waiter_count = state
                .waiter_count
                .checked_sub(removed)
                .expect("membership cancellation must match waiter ownership");
            let class_index = class.index();
            state.waiters_by_class[class_index] = state.waiters_by_class[class_index]
                .checked_sub(removed)
                .expect("membership cancellation must match class ownership");
            if state.waiters.get(&source).is_some_and(VecDeque::is_empty) {
                state.waiters.remove(&source);
            }
        }
        if state.waiter_count == 0 {
            state.next_ticket = 0;
        }
        cancelled
    }
    #[cfg(test)]
    fn retained(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retained_bytes
    }
}
impl Drop for NetworkActorProgressLease {
    fn drop(&mut self) {
        let mut state = self
            .budget
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retained_bytes = state
            .retained_bytes
            .checked_sub(self.bytes)
            .expect("progress actor byte lease must have matching ownership");
        state.retained_items = state
            .retained_items
            .checked_sub(1)
            .expect("progress actor item lease must have matching ownership");
        let class_index = self.source.class.index();
        state.retained_sources_by_class[class_index] = state.retained_sources_by_class[class_index]
            .checked_sub(1)
            .expect("progress actor class source lease must have matching ownership");
        {
            let retained = state
                .retained_by_source
                .get_mut(&self.source)
                .expect("progress actor source must own every live lease");
            assert_eq!(
                retained.request_digest, self.request_digest,
                "progress actor source lease must retain its canonical request identity"
            );
            assert_eq!(
                retained.broadcast, self.broadcast,
                "progress actor source lease must retain its delivery kind"
            );
            assert_eq!(
                retained.authority, self.authority,
                "progress actor source lease must retain its delivery-authority identity"
            );
            retained.bytes = retained
                .bytes
                .checked_sub(self.bytes)
                .expect("progress actor source lease must have matching ownership");
            retained.items = retained
                .items
                .checked_sub(1)
                .expect("progress actor source item lease must have matching ownership");
            assert_eq!(retained.bytes, 0);
            assert_eq!(retained.items, 0);
        }
        state.retained_by_source.remove(&self.source);
    }
}
mod reliable_actor;
use reliable_actor::*;
#[cfg(any(test, feature = "test-fixtures"))]
#[path = "network/actor_admission_fixture.rs"]
mod actor_admission_fixture;
#[cfg(any(test, feature = "test-fixtures"))]
pub use actor_admission_fixture::NetworkActorAdmissionTestFixture;
#[derive(Clone, Copy, Debug)]
pub(crate) struct TopicFrameCaps {
    consensus: usize,
    control: usize,
    block_sync: usize,
    tx_gossip: usize,
    peer_gossip: usize,
    health: usize,
    connect: usize,
    other: usize,
}
impl TopicFrameCaps {
    /// Complete canonical plaintext maxima, not encrypted-frame or payload-only sizes.
    pub(crate) fn admission_maxima(
        self,
        max_plaintext: usize,
    ) -> Result<[usize; message::TransportAdmissionClass::COUNT], Error> {
        let maximum = [
            self.control,
            self.consensus,
            self.block_sync,
            self.control,
            self.block_sync,
            self.tx_gossip
                .max(self.peer_gossip)
                .max(self.health)
                .max(self.connect)
                .max(self.other),
        ];
        if maximum.iter().any(|n| *n == 0 || *n > max_plaintext) {
            return Err(invalid_transport_geometry(
                "semantic admission maximum exceeds the exact encrypted transport limit",
            ));
        }
        Ok(maximum)
    }
    #[cfg(test)]
    pub(crate) const fn uniform(bytes: usize) -> Self {
        Self {
            consensus: bytes,
            control: bytes,
            block_sync: bytes,
            tx_gossip: bytes,
            peer_gossip: bytes,
            health: bytes,
            connect: bytes,
            other: bytes,
        }
    }
    pub(crate) fn for_topic(self, topic: message::Topic) -> usize {
        match topic {
            message::Topic::ConsensusSafety | message::Topic::Control => self.control,
            message::Topic::Consensus => self.consensus,
            message::Topic::ConsensusPayload
            | message::Topic::ConsensusChunk
            | message::Topic::BlockSync => self.block_sync,
            message::Topic::TxGossip | message::Topic::TxGossipRestricted => self.tx_gossip,
            message::Topic::PeerGossip | message::Topic::TrustGossip => self.peer_gossip,
            message::Topic::Health => self.health,
            message::Topic::Connect => self.connect,
            message::Topic::Other => self.other,
        }
    }
    fn all(self) -> [usize; 8] {
        [
            self.consensus,
            self.control,
            self.block_sync,
            self.tx_gossip,
            self.peer_gossip,
            self.health,
            self.connect,
            self.other,
        ]
    }
    /// Complete plaintext maxima eligible for the low-priority path.
    fn low(self) -> [usize; 6] {
        [
            self.block_sync,
            self.tx_gossip,
            self.peer_gossip,
            self.health,
            self.connect,
            self.other,
        ]
    }
}
fn canonical_outbound_priority(
    topic: message::Topic,
    route: message::SubscriberRoute,
    requested: Priority,
) -> Priority {
    if is_reliable_progress_route(topic, route) {
        Priority::High
    } else {
        requested
    }
}
fn outbound_actor_message_wire_bytes<T: Pload>(
    message: &NetworkMessage<T>,
    origin: &PeerId,
    _relay_ttl: u8,
) -> Result<usize, ncore::Error> {
    let wire_bytes = match message {
        NetworkMessage::Post(post) => data_frame_wire_len_from_payload_len::<T>(
            origin,
            Some(&post.peer_id),
            ncore::encoded_payload_len(&post.data)?,
        ),
        NetworkMessage::Broadcast(broadcast) => data_frame_wire_len_from_payload_len::<T>(
            origin,
            None,
            ncore::encoded_payload_len(&broadcast.data)?,
        ),
    };
    if wire_bytes == usize::MAX {
        Err(ncore::Error::LengthMismatch)
    } else {
        Ok(wire_bytes)
    }
}
fn progress_ticket_request_digest<T: Pload>(message: &NetworkMessage<T>) -> Hash {
    const DOMAIN: &[u8] = b"iroha:p2p-progress-admission-ticket:v1\n";
    let priority_tag = |priority| match priority {
        Priority::High => 0_u8,
        Priority::Low => 1_u8,
    };
    match message {
        NetworkMessage::Post(post) => {
            let metadata = [0_u8, priority_tag(post.priority)];
            let target = post.peer_id.encode();
            let payload = post.data.encode();
            Hash::new_from_chunks(&[DOMAIN, &metadata, &target, &payload])
        }
        NetworkMessage::Broadcast(broadcast) => {
            let metadata = [1_u8, priority_tag(broadcast.priority)];
            let payload = broadcast.data.encode();
            Hash::new_from_chunks(&[DOMAIN, &metadata, &payload])
        }
    }
}
#[expect(
    clippy::result_large_err,
    reason = "backpressure must return the original admitted message and its byte lease without allocating"
)]
fn defer_high_priority_network_message<T: Pload + Sync>(
    sender: net_channel::Sender<AdmittedNetworkMessage<T>>,
    message: AdmittedNetworkMessage<T>,
    broadcast: bool,
    topic: message::Topic,
    deferred_permits: &Arc<Semaphore>,
) -> Result<(), AdmittedNetworkMessage<T>> {
    let kind = if broadcast { "broadcast" } else { "post" };
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        iroha_logger::debug!(
            ?topic,
            kind,
            "Cannot defer high-priority network message because no Tokio runtime is active"
        );
        return Err(message);
    };
    let Ok(permit) = Arc::clone(deferred_permits).try_acquire_owned() else {
        iroha_logger::debug!(
            ?topic,
            kind,
            "High-priority network actor deferral queue is full"
        );
        return Err(message);
    };
    iroha_logger::debug!(
        ?topic,
        kind,
        "High-priority network actor queue is full; deferring message until capacity is available"
    );
    handle.spawn(async move {
        let _permit = permit;
        if sender.send(message).await.is_err() {
            record_network_actor_queue_drop(Priority::High, broadcast);
            iroha_logger::debug!(
                ?topic,
                kind,
                "Network actor is closed, dropping deferred high-priority message"
            );
        }
    });
    Ok(())
}
/// Returns the last observed depth of the high-priority network queue.
pub fn network_queue_depth_high() -> u64 {
    NETWORK_QUEUE_DEPTH_HIGH.load(Ordering::Relaxed)
}
/// Returns the last observed depth of the authoritative-consensus safety queue.
pub fn network_queue_depth_safety() -> u64 {
    NETWORK_QUEUE_DEPTH_SAFETY.load(Ordering::Relaxed)
}
/// Returns the last observed depth of the reliable semantic-progress queue.
pub fn network_queue_depth_progress() -> u64 {
    NETWORK_QUEUE_DEPTH_PROGRESS.load(Ordering::Relaxed)
}
/// Returns the last observed depth of the low-priority network queue.
pub fn network_queue_depth_low() -> u64 {
    NETWORK_QUEUE_DEPTH_LOW.load(Ordering::Relaxed)
}
// Update cached queue depths for telemetry metrics.
fn update_network_queue_depth_high(len: usize) {
    NETWORK_QUEUE_DEPTH_HIGH.store(len as u64, Ordering::Relaxed);
}
fn update_network_queue_depth_safety(len: usize) {
    NETWORK_QUEUE_DEPTH_SAFETY.store(len as u64, Ordering::Relaxed);
}
fn update_network_queue_depth_progress(len: usize) {
    NETWORK_QUEUE_DEPTH_PROGRESS.store(len as u64, Ordering::Relaxed);
}
fn update_network_queue_depth_low(len: usize) {
    NETWORK_QUEUE_DEPTH_LOW.store(len as u64, Ordering::Relaxed);
}
/// Returns the number of inbound messages dropped because subscriber queues are full.
pub fn subscriber_queue_full_count() -> u64 {
    SUBSCRIBER_QUEUE_FULL.load(Ordering::Relaxed)
}
/// Returns the number of subscriber-queue drops for authoritative consensus safety traffic.
pub fn subscriber_queue_full_consensus_safety_count() -> u64 {
    SUBSCRIBER_QUEUE_FULL_CONSENSUS_SAFETY.load(Ordering::Relaxed)
}
/// Returns the number of subscriber-queue drops for topic Consensus.
pub fn subscriber_queue_full_consensus_count() -> u64 {
    SUBSCRIBER_QUEUE_FULL_CONSENSUS.load(Ordering::Relaxed)
}
/// Returns the number of subscriber-queue drops for topic `ConsensusChunk`.
pub fn subscriber_queue_full_consensus_chunk_count() -> u64 {
    SUBSCRIBER_QUEUE_FULL_CONSENSUS_CHUNK.load(Ordering::Relaxed)
}
/// Returns the number of subscriber-queue drops for topic Control.
pub fn subscriber_queue_full_control_count() -> u64 {
    SUBSCRIBER_QUEUE_FULL_CONTROL.load(Ordering::Relaxed)
}
/// Returns the number of subscriber-queue drops for topic `BlockSync`.
pub fn subscriber_queue_full_block_sync_count() -> u64 {
    SUBSCRIBER_QUEUE_FULL_BLOCK_SYNC.load(Ordering::Relaxed)
}
/// Returns the number of subscriber-queue drops for topic `TxGossip`.
pub fn subscriber_queue_full_tx_gossip_count() -> u64 {
    SUBSCRIBER_QUEUE_FULL_TX_GOSSIP.load(Ordering::Relaxed)
}
/// Returns the number of subscriber-queue drops for topic `PeerGossip`.
pub fn subscriber_queue_full_peer_gossip_count() -> u64 {
    SUBSCRIBER_QUEUE_FULL_PEER_GOSSIP.load(Ordering::Relaxed)
}
/// Returns the number of subscriber-queue drops for topic Health.
pub fn subscriber_queue_full_health_count() -> u64 {
    SUBSCRIBER_QUEUE_FULL_HEALTH.load(Ordering::Relaxed)
}
/// Returns the number of subscriber-queue drops for topic Other.
pub fn subscriber_queue_full_other_count() -> u64 {
    SUBSCRIBER_QUEUE_FULL_OTHER.load(Ordering::Relaxed)
}
/// Returns the number of inbound messages dropped due to no matching subscriber.
pub fn subscriber_unrouted_count() -> u64 {
    SUBSCRIBER_UNROUTED.load(Ordering::Relaxed)
}
/// Returns the number of unrouted authoritative consensus safety messages.
pub fn subscriber_unrouted_consensus_safety_count() -> u64 {
    SUBSCRIBER_UNROUTED_CONSENSUS_SAFETY.load(Ordering::Relaxed)
}
/// Returns the number of unrouted inbound messages for topic Consensus.
pub fn subscriber_unrouted_consensus_count() -> u64 {
    SUBSCRIBER_UNROUTED_CONSENSUS.load(Ordering::Relaxed)
}
/// Returns the number of unrouted inbound messages for topic `ConsensusChunk`.
pub fn subscriber_unrouted_consensus_chunk_count() -> u64 {
    SUBSCRIBER_UNROUTED_CONSENSUS_CHUNK.load(Ordering::Relaxed)
}
/// Returns the number of unrouted inbound messages for topic Control.
pub fn subscriber_unrouted_control_count() -> u64 {
    SUBSCRIBER_UNROUTED_CONTROL.load(Ordering::Relaxed)
}
/// Returns the number of unrouted inbound messages for topic `BlockSync`.
pub fn subscriber_unrouted_block_sync_count() -> u64 {
    SUBSCRIBER_UNROUTED_BLOCK_SYNC.load(Ordering::Relaxed)
}
/// Returns the number of unrouted inbound messages for topic `TxGossip`.
pub fn subscriber_unrouted_tx_gossip_count() -> u64 {
    SUBSCRIBER_UNROUTED_TX_GOSSIP.load(Ordering::Relaxed)
}
/// Returns the number of unrouted inbound messages for topic `PeerGossip`.
pub fn subscriber_unrouted_peer_gossip_count() -> u64 {
    SUBSCRIBER_UNROUTED_PEER_GOSSIP.load(Ordering::Relaxed)
}
/// Returns the number of unrouted inbound messages for topic Health.
pub fn subscriber_unrouted_health_count() -> u64 {
    SUBSCRIBER_UNROUTED_HEALTH.load(Ordering::Relaxed)
}
/// Returns the number of unrouted inbound messages for topic Other.
pub fn subscriber_unrouted_other_count() -> u64 {
    SUBSCRIBER_UNROUTED_OTHER.load(Ordering::Relaxed)
}
/// Testing helper: increment bounded queue drop counters directly.
///
/// - `priority_high`: true for High, false for Low.
/// - `broadcast`: true for Broadcast, false for Post.
/// - `n`: amount to add.
pub fn inc_queue_drop_for_test(priority_high: bool, broadcast: bool, n: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    if broadcast {
        DROPPED_BROADCASTS.fetch_add(n, Relaxed);
        if priority_high {
            DROPPED_BROADCASTS_HI.fetch_add(n, Relaxed);
        } else {
            DROPPED_BROADCASTS_LO.fetch_add(n, Relaxed);
        }
    } else {
        DROPPED_POSTS.fetch_add(n, Relaxed);
        if priority_high {
            DROPPED_POSTS_HI.fetch_add(n, Relaxed);
        } else {
            DROPPED_POSTS_LO.fetch_add(n, Relaxed);
        }
    }
}
/// Testing helper: set the observed network queue depth for High/Low queues.
pub fn set_network_queue_depth_for_test(priority_high: bool, len: usize) {
    if priority_high {
        update_network_queue_depth_high(len);
    } else {
        update_network_queue_depth_low(len);
    }
}
/// Testing helper: set the isolated authoritative-consensus safety queue depth.
pub fn set_network_safety_queue_depth_for_test(len: usize) {
    update_network_queue_depth_safety(len);
}
/// Testing helper: set the semantic-progress actor queue depth.
pub fn set_network_progress_queue_depth_for_test(len: usize) {
    update_network_queue_depth_progress(len);
}
/// Testing helper: increment subscriber-queue-full counters directly for a topic.
pub fn inc_subscriber_queue_full_for_test(topic: message::Topic, n: u64) {
    for _ in 0..n {
        inc_subscriber_queue_full_for(topic);
    }
}
/// Testing helper: increment subscriber unrouted counters directly for a topic.
pub fn inc_subscriber_unrouted_for_test(topic: message::Topic, n: u64) {
    for _ in 0..n {
        inc_subscriber_unrouted_for(topic);
    }
}
/// Returns the number of interval-based DNS refresh cycles performed.
pub fn dns_refresh_count() -> u64 {
    DNS_REFRESHES.load(Ordering::Relaxed)
}
/// Returns the number of TTL-based DNS refresh cycles performed.
pub fn dns_ttl_refresh_count() -> u64 {
    DNS_TTL_REFRESHES.load(Ordering::Relaxed)
}
/// Returns the number of hostname reconnect successes after refresh cycles.
pub fn dns_reconnect_success_count() -> u64 {
    DNS_RECONNECT_SUCCESSES.load(Ordering::Relaxed)
}
/// Returns the number of hostname resolution/connection failures for hostname peers.
pub fn dns_resolution_fail_count() -> u64 {
    DNS_RESOLUTION_FAILURES.load(Ordering::Relaxed)
}
/// Increment the hostname resolution failure counter.
pub fn inc_dns_resolution_fail() {
    DNS_RESOLUTION_FAILURES.fetch_add(1, Ordering::Relaxed);
}
/// Returns the number of scheduled per-address backoffs.
pub fn backoff_scheduled_count() -> u64 {
    BACKOFF_SCHEDULED.load(Ordering::Relaxed)
}
/// Returns total deferred outbound frames enqueued while peer session was missing.
pub fn deferred_send_enqueued_count() -> u64 {
    DEFERRED_SEND_ENQUEUED.load(Ordering::Relaxed)
}
/// Returns total deferred outbound frames dropped (TTL, stale connection binding, cap).
pub fn deferred_send_dropped_count() -> u64 {
    DEFERRED_SEND_DROPPED.load(Ordering::Relaxed)
}
/// Returns total reconnect attempts triggered because outbound frames were deferred.
pub fn session_reconnect_total() -> u64 {
    SESSION_RECONNECT_TOTAL.load(Ordering::Relaxed)
}
/// Returns cumulative reconnect retry delay in seconds (rounded up from milliseconds).
pub fn connect_retry_seconds_total() -> u64 {
    CONNECT_RETRY_MILLIS_TOTAL
        .load(Ordering::Relaxed)
        .div_ceil(1_000)
}
/// Increment SCION inbound accepted counter.
pub fn inc_scion_inbound() {
    SCION_INBOUND_ACCEPTED.fetch_add(1, Ordering::Relaxed);
}
/// Increment SCION outbound success counter.
pub fn inc_scion_outbound() {
    SCION_OUTBOUND_SUCCESSES.fetch_add(1, Ordering::Relaxed);
}
/// Total accepted inbound SCION connections.
pub fn scion_inbound_total() -> u64 {
    SCION_INBOUND_ACCEPTED.load(Ordering::Relaxed)
}
/// Total successful outbound SCION connections.
pub fn scion_outbound_total() -> u64 {
    SCION_OUTBOUND_SUCCESSES.load(Ordering::Relaxed)
}
/// Returns the number of connections rejected by the per‑IP accept throttle.
pub fn accept_throttled_count() -> u64 {
    ACCEPT_THROTTLED.load(Ordering::Relaxed)
}
/// Returns the number of accept throttle bucket evictions (idle or capacity).
pub fn accept_bucket_evictions_count() -> u64 {
    ACCEPT_BUCKET_EVICTIONS.load(Ordering::Relaxed)
}
/// Returns the current count of accept throttle buckets (prefix + per-IP).
pub fn accept_bucket_count() -> u64 {
    ACCEPT_BUCKETS_CURRENT.load(Ordering::Relaxed)
}
/// Returns the number of prefix throttle cache hits.
pub fn accept_prefix_hits_count() -> u64 {
    ACCEPT_PREFIX_CACHE_HITS.load(Ordering::Relaxed)
}
/// Returns the number of prefix throttle cache misses.
pub fn accept_prefix_misses_count() -> u64 {
    ACCEPT_PREFIX_CACHE_MISSES.load(Ordering::Relaxed)
}
/// Returns the number of connections allowed by the prefix throttle bucket.
pub fn accept_prefix_allowed_count() -> u64 {
    ACCEPT_PREFIX_ALLOWED.load(Ordering::Relaxed)
}
/// Returns the number of prefix throttle rejections.
pub fn accept_prefix_throttled_count() -> u64 {
    ACCEPT_PREFIX_THROTTLED.load(Ordering::Relaxed)
}
/// Returns the number of connections allowed by the per-IP throttle bucket.
pub fn accept_ip_allowed_count() -> u64 {
    ACCEPT_IP_ALLOWED.load(Ordering::Relaxed)
}
/// Returns the number of per-IP throttle rejections.
pub fn accept_ip_throttled_count() -> u64 {
    ACCEPT_IP_THROTTLED.load(Ordering::Relaxed)
}
/// Returns the number of connections rejected by the incoming cap.
pub fn incoming_cap_reject_count() -> u64 {
    INCOMING_CAP_REJECTS.load(Ordering::Relaxed)
}
/// Returns the number of connections rejected by the total connections cap.
pub fn total_cap_reject_count() -> u64 {
    TOTAL_CAP_REJECTS.load(Ordering::Relaxed)
}
/// Returns the number of connections rejected by the concurrent pre-auth source cap.
pub fn preauth_source_cap_reject_count() -> u64 {
    PREAUTH_SOURCE_CAP_REJECTS.load(Ordering::Relaxed)
}
/// Returns the number of low-priority post messages dropped by per-peer throttle.
pub fn low_post_throttled_count() -> u64 {
    LOW_THROTTLED_POSTS.load(Ordering::Relaxed)
}
/// Returns the number of low-priority broadcast deliveries skipped by per-peer throttle.
pub fn low_broadcast_throttled_count() -> u64 {
    LOW_THROTTLED_BROADCASTS.load(Ordering::Relaxed)
}
/// Returns the number of trust-gossip frames skipped because the capability is disabled.
pub fn trust_gossip_skipped_capability_off_count() -> u64 {
    TRUST_GOSSIP_SKIPPED_CAP_OFF.load(Ordering::Relaxed)
}
/// Returns true when trust gossip is permitted for the given topic/capability flag.
fn trust_gossip_allowed(topic: message::Topic, trust_gossip: bool) -> bool {
    !matches!(topic, message::Topic::TrustGossip) || trust_gossip
}
fn is_consensus_topic(topic: message::Topic) -> bool {
    matches!(
        topic,
        message::Topic::ConsensusSafety
            | message::Topic::Consensus
            | message::Topic::ConsensusPayload
            | message::Topic::ConsensusChunk
    )
}
pub(crate) fn is_reliable_progress_route(
    topic: message::Topic,
    route: message::SubscriberRoute,
) -> bool {
    reliable_progress_class(topic, route).is_some()
}
fn inc_subscriber_queue_full_for(topic: message::Topic) -> u64 {
    let total = SUBSCRIBER_QUEUE_FULL.fetch_add(1, Ordering::Relaxed) + 1;
    match topic {
        message::Topic::ConsensusSafety => {
            SUBSCRIBER_QUEUE_FULL_CONSENSUS_SAFETY.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::Consensus | message::Topic::ConsensusPayload => {
            SUBSCRIBER_QUEUE_FULL_CONSENSUS.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::ConsensusChunk => {
            SUBSCRIBER_QUEUE_FULL_CONSENSUS_CHUNK.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::Control => {
            SUBSCRIBER_QUEUE_FULL_CONTROL.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::BlockSync => {
            SUBSCRIBER_QUEUE_FULL_BLOCK_SYNC.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::TxGossip | message::Topic::TxGossipRestricted => {
            SUBSCRIBER_QUEUE_FULL_TX_GOSSIP.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::PeerGossip | message::Topic::TrustGossip => {
            SUBSCRIBER_QUEUE_FULL_PEER_GOSSIP.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::Health => {
            SUBSCRIBER_QUEUE_FULL_HEALTH.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::Connect | message::Topic::Other => {
            SUBSCRIBER_QUEUE_FULL_OTHER.fetch_add(1, Ordering::Relaxed);
        }
    }
    total
}
fn inc_subscriber_unrouted_for(topic: message::Topic) -> u64 {
    let total = SUBSCRIBER_UNROUTED.fetch_add(1, Ordering::Relaxed) + 1;
    match topic {
        message::Topic::ConsensusSafety => {
            SUBSCRIBER_UNROUTED_CONSENSUS_SAFETY.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::Consensus | message::Topic::ConsensusPayload => {
            SUBSCRIBER_UNROUTED_CONSENSUS.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::ConsensusChunk => {
            SUBSCRIBER_UNROUTED_CONSENSUS_CHUNK.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::Control => {
            SUBSCRIBER_UNROUTED_CONTROL.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::BlockSync => {
            SUBSCRIBER_UNROUTED_BLOCK_SYNC.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::TxGossip | message::Topic::TxGossipRestricted => {
            SUBSCRIBER_UNROUTED_TX_GOSSIP.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::PeerGossip | message::Topic::TrustGossip => {
            SUBSCRIBER_UNROUTED_PEER_GOSSIP.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::Health => {
            SUBSCRIBER_UNROUTED_HEALTH.fetch_add(1, Ordering::Relaxed);
        }
        message::Topic::Connect | message::Topic::Other => {
            SUBSCRIBER_UNROUTED_OTHER.fetch_add(1, Ordering::Relaxed);
        }
    }
    total
}
/// Returns the number of per-peer post channel overflows observed.
pub fn post_overflow_count() -> u64 {
    POST_OVERFLOWS.load(Ordering::Relaxed)
}
fn inc_trust_gossip_skipped(direction: &'static str, reason: &'static str) {
    use std::sync::atomic::Ordering::Relaxed;
    TRUST_GOSSIP_SKIPPED_CAP_OFF.fetch_add(1, Relaxed);
    iroha_logger::trace!(direction, reason, "trust gossip message skipped");
}
fn inc_post_overflow_for_prio(topic: message::Topic, high: bool) {
    match (high, topic) {
        (true, message::Topic::ConsensusSafety) => {
            POST_OVERFLOWS_HI_CONSENSUS_SAFETY.fetch_add(1, Ordering::Relaxed)
        }
        (true, message::Topic::Consensus | message::Topic::ConsensusPayload) => {
            POST_OVERFLOWS_HI_CONSENSUS.fetch_add(1, Ordering::Relaxed)
        }
        (true, message::Topic::ConsensusChunk | message::Topic::BlockSync) => {
            POST_OVERFLOWS_HI_BLOCK_SYNC.fetch_add(1, Ordering::Relaxed)
        }
        (true, message::Topic::Control) => {
            POST_OVERFLOWS_HI_CONTROL.fetch_add(1, Ordering::Relaxed)
        }
        (true, message::Topic::TxGossip | message::Topic::TxGossipRestricted) => {
            POST_OVERFLOWS_HI_TX_GOSSIP.fetch_add(1, Ordering::Relaxed)
        }
        (true, message::Topic::PeerGossip | message::Topic::TrustGossip) => {
            POST_OVERFLOWS_HI_PEER_GOSSIP.fetch_add(1, Ordering::Relaxed)
        }
        (true, message::Topic::Health) => POST_OVERFLOWS_HI_HEALTH.fetch_add(1, Ordering::Relaxed),
        (true, message::Topic::Connect | message::Topic::Other) => {
            POST_OVERFLOWS_HI_OTHER.fetch_add(1, Ordering::Relaxed)
        }
        (false, message::Topic::ConsensusSafety) => {
            POST_OVERFLOWS_LO_CONSENSUS_SAFETY.fetch_add(1, Ordering::Relaxed)
        }
        (false, message::Topic::Consensus | message::Topic::ConsensusPayload) => {
            POST_OVERFLOWS_LO_CONSENSUS.fetch_add(1, Ordering::Relaxed)
        }
        (false, message::Topic::ConsensusChunk | message::Topic::BlockSync) => {
            POST_OVERFLOWS_LO_BLOCK_SYNC.fetch_add(1, Ordering::Relaxed)
        }
        (false, message::Topic::Control) => {
            POST_OVERFLOWS_LO_CONTROL.fetch_add(1, Ordering::Relaxed)
        }
        (false, message::Topic::TxGossip | message::Topic::TxGossipRestricted) => {
            POST_OVERFLOWS_LO_TX_GOSSIP.fetch_add(1, Ordering::Relaxed)
        }
        (false, message::Topic::PeerGossip | message::Topic::TrustGossip) => {
            POST_OVERFLOWS_LO_PEER_GOSSIP.fetch_add(1, Ordering::Relaxed)
        }
        (false, message::Topic::Health) => POST_OVERFLOWS_LO_HEALTH.fetch_add(1, Ordering::Relaxed),
        (false, message::Topic::Connect | message::Topic::Other) => {
            POST_OVERFLOWS_LO_OTHER.fetch_add(1, Ordering::Relaxed)
        }
    };
}
/// Count of post channel overflows for topic `TxGossip` across both priorities.
pub fn post_overflow_tx_gossip_count() -> u64 {
    POST_OVERFLOWS_HI_TX_GOSSIP
        .load(Ordering::Relaxed)
        .saturating_add(POST_OVERFLOWS_LO_TX_GOSSIP.load(Ordering::Relaxed))
}
pub(crate) fn record_inbound_cap_violation(topic: message::Topic) {
    match topic {
        message::Topic::ConsensusSafety => {
            CAP_VIOL_CONSENSUS_SAFETY.fetch_add(1, Ordering::Relaxed)
        }
        message::Topic::Consensus | message::Topic::ConsensusPayload => {
            CAP_VIOL_CONSENSUS.fetch_add(1, Ordering::Relaxed)
        }
        message::Topic::ConsensusChunk | message::Topic::BlockSync => {
            CAP_VIOL_BLOCK_SYNC.fetch_add(1, Ordering::Relaxed)
        }
        message::Topic::Control => CAP_VIOL_CONTROL.fetch_add(1, Ordering::Relaxed),
        message::Topic::TxGossip | message::Topic::TxGossipRestricted => {
            CAP_VIOL_TX_GOSSIP.fetch_add(1, Ordering::Relaxed)
        }
        message::Topic::PeerGossip | message::Topic::TrustGossip => {
            CAP_VIOL_PEER_GOSSIP.fetch_add(1, Ordering::Relaxed)
        }
        message::Topic::Health => CAP_VIOL_HEALTH.fetch_add(1, Ordering::Relaxed),
        message::Topic::Connect | message::Topic::Other => {
            CAP_VIOL_OTHER.fetch_add(1, Ordering::Relaxed)
        }
    };
}
/// Total number of dropped inbound messages exceeding the Consensus topic cap.
pub fn cap_violations_consensus() -> u64 {
    CAP_VIOL_CONSENSUS.load(Ordering::Relaxed)
}
/// Total number of safety messages exceeding the authoritative consensus cap.
pub fn cap_violations_consensus_safety() -> u64 {
    CAP_VIOL_CONSENSUS_SAFETY.load(Ordering::Relaxed)
}
/// Total number of dropped inbound messages exceeding the Control topic cap.
pub fn cap_violations_control() -> u64 {
    CAP_VIOL_CONTROL.load(Ordering::Relaxed)
}
/// Total number of dropped inbound messages exceeding the `BlockSync` topic cap.
pub fn cap_violations_block_sync() -> u64 {
    CAP_VIOL_BLOCK_SYNC.load(Ordering::Relaxed)
}
/// Total number of dropped inbound messages exceeding the `TxGossip` topic cap.
pub fn cap_violations_tx_gossip() -> u64 {
    CAP_VIOL_TX_GOSSIP.load(Ordering::Relaxed)
}
/// Total number of dropped inbound messages exceeding the `PeerGossip` topic cap.
pub fn cap_violations_peer_gossip() -> u64 {
    CAP_VIOL_PEER_GOSSIP.load(Ordering::Relaxed)
}
/// Total number of dropped inbound messages exceeding the Health topic cap.
pub fn cap_violations_health() -> u64 {
    CAP_VIOL_HEALTH.load(Ordering::Relaxed)
}
/// Total number of dropped inbound messages exceeding the Other topic cap.
pub fn cap_violations_other() -> u64 {
    CAP_VIOL_OTHER.load(Ordering::Relaxed)
}
/// Count of High-priority post overflows for topic Consensus.
pub fn post_overflow_consensus_high_count() -> u64 {
    POST_OVERFLOWS_HI_CONSENSUS.load(Ordering::Relaxed)
}
/// Count of high-priority post overflows for authoritative consensus safety traffic.
pub fn post_overflow_consensus_safety_high_count() -> u64 {
    POST_OVERFLOWS_HI_CONSENSUS_SAFETY.load(Ordering::Relaxed)
}
/// Count of High-priority post overflows for topic Control.
pub fn post_overflow_control_high_count() -> u64 {
    POST_OVERFLOWS_HI_CONTROL.load(Ordering::Relaxed)
}
/// Count of High-priority post overflows for topic `BlockSync`.
pub fn post_overflow_block_sync_high_count() -> u64 {
    POST_OVERFLOWS_HI_BLOCK_SYNC.load(Ordering::Relaxed)
}
/// Count of High-priority post overflows for topic `TxGossip`.
pub fn post_overflow_tx_gossip_high_count() -> u64 {
    POST_OVERFLOWS_HI_TX_GOSSIP.load(Ordering::Relaxed)
}
/// Count of High-priority post overflows for topic `PeerGossip`.
pub fn post_overflow_peer_gossip_high_count() -> u64 {
    POST_OVERFLOWS_HI_PEER_GOSSIP.load(Ordering::Relaxed)
}
/// Count of High-priority post overflows for topic Health.
pub fn post_overflow_health_high_count() -> u64 {
    POST_OVERFLOWS_HI_HEALTH.load(Ordering::Relaxed)
}
/// Count of High-priority post overflows for topic Other.
pub fn post_overflow_other_high_count() -> u64 {
    POST_OVERFLOWS_HI_OTHER.load(Ordering::Relaxed)
}
/// Count of Low-priority post overflows for topic Consensus.
pub fn post_overflow_consensus_low_count() -> u64 {
    POST_OVERFLOWS_LO_CONSENSUS.load(Ordering::Relaxed)
}
/// Count of low-priority post overflows for authoritative consensus safety traffic.
pub fn post_overflow_consensus_safety_low_count() -> u64 {
    POST_OVERFLOWS_LO_CONSENSUS_SAFETY.load(Ordering::Relaxed)
}
/// Count of Low-priority post overflows for topic Control.
pub fn post_overflow_control_low_count() -> u64 {
    POST_OVERFLOWS_LO_CONTROL.load(Ordering::Relaxed)
}
/// Count of Low-priority post overflows for topic `BlockSync`.
pub fn post_overflow_block_sync_low_count() -> u64 {
    POST_OVERFLOWS_LO_BLOCK_SYNC.load(Ordering::Relaxed)
}
/// Count of Low-priority post overflows for topic `TxGossip`.
pub fn post_overflow_tx_gossip_low_count() -> u64 {
    POST_OVERFLOWS_LO_TX_GOSSIP.load(Ordering::Relaxed)
}
/// Count of Low-priority post overflows for topic `PeerGossip`.
pub fn post_overflow_peer_gossip_low_count() -> u64 {
    POST_OVERFLOWS_LO_PEER_GOSSIP.load(Ordering::Relaxed)
}
/// Count of Low-priority post overflows for topic Health.
pub fn post_overflow_health_low_count() -> u64 {
    POST_OVERFLOWS_LO_HEALTH.load(Ordering::Relaxed)
}
/// Count of Low-priority post overflows for topic Other.
pub fn post_overflow_other_low_count() -> u64 {
    POST_OVERFLOWS_LO_OTHER.load(Ordering::Relaxed)
}
/// Testing helper: increment per-topic/per-priority overflow counters directly.
/// Increments overall total as well.
pub fn inc_post_overflow_for_test(priority_high: bool, topic: message::Topic, n: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    POST_OVERFLOWS.fetch_add(n, Relaxed);
    for _ in 0..n {
        inc_post_overflow_for_prio(topic, priority_high);
    }
}
// LogSampler is provided by crate::sampler
/// Filter for peer-message subscriptions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscriberFilter {
    /// One semantic application class on one independently owned delivery route.
    SemanticClass {
        /// Class authenticated and checked by the mandatory transport reader.
        class: message::TransportAdmissionClass,
        /// Unique final application route.
        route: message::SubscriberRoute,
    },
    /// Receive every incoming message.
    All,
    /// Receive messages whose topic matches one of the listed entries.
    ///
    /// Topic-only subscriptions own the general application route.
    Topics(Vec<message::Topic>),
    /// Receive the listed topics on one explicit application delivery route.
    TopicsForRoute {
        /// Logical topics accepted by this subscriber.
        topics: Vec<message::Topic>,
        /// Variant-disjoint application route.
        route: message::SubscriberRoute,
    },
}
impl SubscriberFilter {
    /// Subscribe to one semantic FIFO on the general application route.
    pub fn semantic_class(class: message::TransportAdmissionClass) -> Self {
        Self::SemanticClass {
            class,
            route: message::SubscriberRoute::General,
        }
    }

    /// Build a filter from an iterable of topics.
    pub fn topics<I>(topics: I) -> Self
    where
        I: IntoIterator<Item = message::Topic>,
    {
        Self::Topics(topics.into_iter().collect())
    }
    /// Build a topic filter for one variant-disjoint application route.
    pub fn topics_for_route<I>(topics: I, route: message::SubscriberRoute) -> Self
    where
        I: IntoIterator<Item = message::Topic>,
    {
        Self::TopicsForRoute {
            topics: topics.into_iter().collect(),
            route,
        }
    }
    fn matches(
        &self,
        topic: message::Topic,
        route: message::SubscriberRoute,
        class: message::TransportAdmissionClass,
    ) -> bool {
        match self {
            Self::SemanticClass {
                class: expected,
                route: expected_route,
            } => *expected == class && *expected_route == route,
            Self::All => true,
            Self::Topics(topics) => {
                matches!(route, message::SubscriberRoute::General) && topics.contains(&topic)
            }
            Self::TopicsForRoute {
                topics,
                route: expected,
            } => *expected == route && topics.contains(&topic),
        }
    }
    fn overlaps_reliable(&self, other: &Self) -> bool {
        const TOPICS: [message::Topic; 6] = [
            message::Topic::ConsensusSafety,
            message::Topic::Consensus,
            message::Topic::ConsensusPayload,
            message::Topic::ConsensusChunk,
            message::Topic::BlockSync,
            message::Topic::Control,
        ];
        const ROUTES: [message::SubscriberRoute; 4] = [
            message::SubscriberRoute::General,
            message::SubscriberRoute::ToriiProxy,
            message::SubscriberRoute::Connect,
            message::SubscriberRoute::Sumeragi,
        ];
        TOPICS.into_iter().any(|topic| {
            ROUTES.into_iter().any(|route| {
                is_reliable_progress_route(topic, route)
                    && message::TransportAdmissionClass::ALL
                        .into_iter()
                        .any(|class| {
                            // Exhaustive semantic/topic relationship.
                            class == message::TransportAdmissionClass::ordinary_for_topic(topic)
                                && self.matches(topic, route, class)
                                && other.matches(topic, route, class)
                        })
            })
        })
    }
}
struct Subscriber<T: Pload> {
    sender: mpsc::Sender<PeerMessage<T>>,
    filter: SubscriberFilter,
    safety_pending_by_peer: HashMap<PeerId, VecDeque<PeerMessage<T>>>,
    safety_pending_order: VecDeque<PeerId>,
    safety_pending_len: usize,
    progress_pending_by_peer: HashMap<(PeerId, SubscriberProgressClass), VecDeque<PeerMessage<T>>>,
    progress_pending_order: VecDeque<(PeerId, SubscriberProgressClass)>,
    progress_pending_len: usize,
    prefer_progress: bool,
}
struct UnroutedReliableDelivery<T: Pload> {
    message: PeerMessage<T>,
    admission_peer_id: PeerId,
}
impl<T: Pload> Subscriber<T> {
    fn new(
        sender: mpsc::Sender<PeerMessage<T>>,
        filter: SubscriberFilter,
        _subscriber_channel_cap: usize,
    ) -> Self {
        Self {
            sender,
            filter,
            safety_pending_by_peer: HashMap::new(),
            safety_pending_order: VecDeque::new(),
            safety_pending_len: 0,
            progress_pending_by_peer: HashMap::new(),
            progress_pending_order: VecDeque::new(),
            progress_pending_len: 0,
            prefer_progress: false,
        }
    }
    /// Retain an already byte-admitted reliable delivery.
    ///
    /// `PeerMessage` carries its inbound-dispatch byte lease through this
    /// backlog, so memory remains bounded by the checked process/per-source
    /// geometry upstream. Applying a second count cap after ownership transfer
    /// would have no caller to return the exact message to and would therefore
    /// turn ordinary subscriber pressure into protocol loss.
    fn enqueue_safety(&mut self, msg: PeerMessage<T>, admission_peer_id: PeerId) {
        let entries = self
            .safety_pending_by_peer
            .entry(admission_peer_id.clone())
            .or_default();
        if entries.is_empty() {
            self.safety_pending_order.push_back(admission_peer_id);
        }
        entries.push_back(msg);
        self.safety_pending_len = self
            .safety_pending_len
            .checked_add(1)
            .expect("byte-bounded safety subscriber backlog count cannot overflow");
    }
    fn flush_safety(&mut self, budget: usize) -> Result<usize, ()> {
        use tokio::sync::mpsc::error::TrySendError;
        let mut sent = 0usize;
        while sent < budget {
            let Some(peer_id) = self.safety_pending_order.pop_front() else {
                break;
            };
            let Some(mut entries) = self.safety_pending_by_peer.remove(&peer_id) else {
                continue;
            };
            let Some(msg) = entries.pop_front() else {
                continue;
            };
            match self.sender.try_send(msg) {
                Ok(()) => {
                    self.safety_pending_len = self
                        .safety_pending_len
                        .checked_sub(1)
                        .expect("safety subscriber backlog count must match its queues");
                    sent = sent.saturating_add(1);
                    if !entries.is_empty() {
                        self.safety_pending_by_peer.insert(peer_id.clone(), entries);
                        self.safety_pending_order.push_back(peer_id);
                    }
                }
                Err(TrySendError::Full(msg)) => {
                    entries.push_front(msg);
                    self.safety_pending_by_peer.insert(peer_id.clone(), entries);
                    self.safety_pending_order.push_front(peer_id);
                    break;
                }
                Err(TrySendError::Closed(msg)) => {
                    entries.push_front(msg);
                    self.safety_pending_by_peer.insert(peer_id.clone(), entries);
                    self.safety_pending_order.push_front(peer_id);
                    return Err(());
                }
            }
        }
        Ok(sent)
    }
    fn enqueue_progress(
        &mut self,
        msg: PeerMessage<T>,
        admission_peer_id: PeerId,
        class: SubscriberProgressClass,
    ) {
        let key = (admission_peer_id, class);
        let entries = self
            .progress_pending_by_peer
            .entry(key.clone())
            .or_default();
        if entries.is_empty() {
            self.progress_pending_order.push_back(key);
        }
        entries.push_back(msg);
        self.progress_pending_len = self
            .progress_pending_len
            .checked_add(1)
            .expect("byte-bounded progress subscriber backlog count cannot overflow");
    }
    fn flush_progress(&mut self, budget: usize) -> Result<usize, ()> {
        use tokio::sync::mpsc::error::TrySendError;
        let mut sent = 0usize;
        while sent < budget {
            let Some(key) = self.progress_pending_order.pop_front() else {
                break;
            };
            let Some(mut entries) = self.progress_pending_by_peer.remove(&key) else {
                continue;
            };
            let Some(msg) = entries.pop_front() else {
                continue;
            };
            match self.sender.try_send(msg) {
                Ok(()) => {
                    self.progress_pending_len = self
                        .progress_pending_len
                        .checked_sub(1)
                        .expect("progress subscriber backlog count must match its queues");
                    sent = sent.saturating_add(1);
                    if !entries.is_empty() {
                        self.progress_pending_by_peer.insert(key.clone(), entries);
                        self.progress_pending_order.push_back(key);
                    }
                }
                Err(TrySendError::Full(msg)) => {
                    entries.push_front(msg);
                    self.progress_pending_by_peer.insert(key.clone(), entries);
                    self.progress_pending_order.push_front(key);
                    break;
                }
                Err(TrySendError::Closed(msg)) => {
                    entries.push_front(msg);
                    self.progress_pending_by_peer.insert(key.clone(), entries);
                    self.progress_pending_order.push_front(key);
                    return Err(());
                }
            }
        }
        Ok(sent)
    }
    fn flush_reliable(&mut self, budget: usize) -> Result<usize, ()> {
        let mut sent = 0usize;
        while sent < budget {
            let safety_ready = self.safety_pending_len > 0;
            let progress_ready = self.progress_pending_len > 0;
            if !safety_ready && !progress_ready {
                break;
            }
            let progress_first = progress_ready && (!safety_ready || self.prefer_progress);
            let delivered = if progress_first {
                self.flush_progress(1)?
            } else {
                self.flush_safety(1)?
            };
            if delivered == 0 {
                break;
            }
            sent = sent.saturating_add(delivered);
            if safety_ready && progress_ready {
                self.prefer_progress = !progress_first;
            }
        }
        Ok(sent)
    }
    /// Return every still-owned reliable delivery when this subscriber closes.
    ///
    /// Per-peer and per-class FIFO is preserved. Safety and progress are kept
    /// as independent fair lanes, so their relative order was never a protocol
    /// ordering guarantee and need not be reconstructed here.
    fn drain_reliable_pending(&mut self) -> VecDeque<UnroutedReliableDelivery<T>> {
        let mut pending = VecDeque::with_capacity(
            self.safety_pending_len
                .saturating_add(self.progress_pending_len),
        );
        while let Some(peer_id) = self.safety_pending_order.pop_front() {
            let Some(entries) = self.safety_pending_by_peer.remove(&peer_id) else {
                continue;
            };
            pending.extend(entries.into_iter().map(|message| UnroutedReliableDelivery {
                message,
                admission_peer_id: peer_id.clone(),
            }));
        }
        while let Some((peer_id, class)) = self.progress_pending_order.pop_front() {
            let Some(entries) = self
                .progress_pending_by_peer
                .remove(&(peer_id.clone(), class))
            else {
                continue;
            };
            pending.extend(entries.into_iter().map(|message| UnroutedReliableDelivery {
                message,
                admission_peer_id: peer_id.clone(),
            }));
        }
        self.safety_pending_len = 0;
        self.progress_pending_len = 0;
        pending
    }
}
#[derive(Debug, Default)]
struct ConfiguredPeerState {
    generation: u64,
    peer_ids: Vec<PeerId>,
}

/// Test-only capability for replacing one closed handle's configured-peer snapshot.
///
/// The capability is created only alongside
/// [`NetworkBaseHandle::closed_for_tests_with_configured_peer_snapshot`], so it
/// cannot mutate a live network actor's published topology.
#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Debug)]
pub struct ConfiguredPeerSnapshotTestFixture {
    state: Arc<Mutex<ConfiguredPeerState>>,
}

#[cfg(any(test, feature = "test-fixtures"))]
impl ConfiguredPeerSnapshotTestFixture {
    /// Replace the isolated configured-peer generation with one canonical snapshot.
    pub fn replace(&self, mut peer_ids: Vec<PeerId>) {
        peer_ids.sort();
        peer_ids.dedup();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.peer_ids != peer_ids {
            state.generation = state
                .generation
                .checked_add(1)
                .expect("test configured-peer generation space exhausted");
            state.peer_ids = peer_ids;
        }
    }
}

/// One bounded, rotating view of the configured logical peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfiguredPeerBatch {
    /// Membership generation from which this batch was selected.
    pub generation: u64,
    /// Total configured logical peers in the captured generation.
    pub total_peer_count: usize,
    /// Canonically ordered peers selected for this sampling round.
    pub peer_ids: Vec<PeerId>,
    /// Start index to use for the next sampling round.
    pub next_start_index: usize,
}

/// `NetworkBase` actor handle.
// NOTE: safety/high/low network queues are bounded by configuration. The
// authoritative-consensus safety channel is independent so auxiliary control
// traffic cannot consume its admission capacity.
#[derive(derive_more::Debug)]
#[debug("core::any::type_name::<Self>()")]
pub struct NetworkBaseHandle<T: Pload, E: Enc> {
    /// Sender to subscribe for messages received form other peers in the network
    subscribe_to_peers_messages_sender: mpsc::Sender<Subscriber<T>>,
    /// Receiver of `OnlinePeer` message
    online_peers_receiver: watch::Receiver<OnlinePeers>,
    /// Receiver of online peer transport capabilities.
    online_peer_capabilities_receiver: watch::Receiver<message::OnlinePeerCapabilities>,
    /// Relay-aware accepted topology shared with targetized broadcast admission.
    reliable_broadcast_topology: Arc<Mutex<ReliableProgressTopology>>,
    /// Accepted logical-topology and authenticated-peer authority for direct
    /// reliable progress posts.
    reliable_direct_topology: Arc<Mutex<ReliableProgressTopology>>,
    /// Actor-published, key-ACL-filtered configured logical peer ids.
    configured_peer_ids: Arc<Mutex<ConfiguredPeerState>>,
    /// Unforgeable identity binding reply-route tokens to this actor instance.
    reply_route_owner: Arc<()>,
    /// Maximum independent authenticated reply sources derived from connection geometry.
    reply_route_source_capacity: usize,
    /// Latest [`UpdateTopology`] snapshot sender.
    update_topology_sender: ControlUpdateSender<UpdateTopology>,
    /// Latest [`UpdatePeers`] snapshot sender.
    update_peers_sender: ControlUpdateSender<UpdatePeers>,
    /// Latest configured-validator dial-roster snapshot sender.
    update_validator_dial_roster_sender: ControlUpdateSender<ValidatorDialControlUpdate>,
    /// Latest [`UpdatePeerCapabilities`] snapshot sender.
    update_peer_capabilities_sender: ControlUpdateSender<message::UpdatePeerCapabilities>,
    /// Latest trusted-peers snapshot sender.
    update_trusted_peers_sender: ControlUpdateSender<UpdateTrustedPeers>,
    /// Latest [`UpdateAcl`] snapshot sender.
    update_acl_sender: ControlUpdateSender<message::UpdateAcl>,
    /// Exact [`UpdateHandshake`] request sender.
    update_handshake_sender: mpsc::Sender<message::UpdateHandshake>,
    /// Sender of high priority messages
    network_message_high_sender: net_channel::Sender<AdmittedNetworkMessage<T>>,
    /// Sender of authoritative-consensus safety messages.
    network_message_safety_sender: net_channel::Sender<AdmittedNetworkMessage<T>>,
    /// Sender of reliable semantic-progress messages.
    network_message_progress_sender: net_channel::Sender<AdmittedNetworkMessage<T>>,
    /// Sender of low priority messages
    network_message_low_sender: net_channel::Sender<AdmittedNetworkMessage<T>>,
    /// Bounds overflow waiters for the ordinary high-priority actor queue.
    network_message_high_deferred_permits: Arc<Semaphore>,
    /// Bounds overflow waiters for the isolated consensus-safety actor queue.
    network_message_safety_deferred_permits: Arc<Semaphore>,
    /// Bounds overflow waiters for the semantic-progress actor queue.
    network_message_progress_deferred_permits: Arc<Semaphore>,
    /// Exact aggregate wire-byte ownership for ordinary high traffic. Its
    /// additive safety tranche cannot be consumed by ordinary callers.
    network_actor_byte_budget: Arc<NetworkActorByteBudget>,
    /// Source-keyed reliable owner. One Safety/Lane/Bulk slot per target
    /// structurally reserves each class from the others. Broadcast copies use
    /// those target slots and return unadmitted targets to their producer.
    network_actor_progress_budget: Arc<NetworkActorProgressBudget>,
    /// Exact aggregate wire-byte ownership for the low-priority actor queue.
    network_actor_low_byte_budget: Arc<NetworkActorByteBudget>,
    /// Local identity used to count the exact relay envelope before admission.
    self_id: PeerId,
    /// Relay hop limit included in the exact outbound actor-frame geometry.
    relay_ttl: u8,
    /// Per-topic outbound frame caps enforced before actor-queue admission.
    topic_frame_caps: TopicFrameCaps,
    /// Configured capacity for subscriber queues.
    subscriber_queue_cap: core::num::NonZeroUsize,
    /// Encryptor used by the network
    _encryptor: core::marker::PhantomData<E>,
}
impl<T: Pload, E: Enc> Clone for NetworkBaseHandle<T, E> {
    fn clone(&self) -> Self {
        Self {
            subscribe_to_peers_messages_sender: self.subscribe_to_peers_messages_sender.clone(),
            online_peers_receiver: self.online_peers_receiver.clone(),
            online_peer_capabilities_receiver: self.online_peer_capabilities_receiver.clone(),
            reliable_broadcast_topology: Arc::clone(&self.reliable_broadcast_topology),
            reliable_direct_topology: Arc::clone(&self.reliable_direct_topology),
            configured_peer_ids: Arc::clone(&self.configured_peer_ids),
            reply_route_owner: Arc::clone(&self.reply_route_owner),
            reply_route_source_capacity: self.reply_route_source_capacity,
            update_topology_sender: self.update_topology_sender.clone(),
            update_peers_sender: self.update_peers_sender.clone(),
            update_validator_dial_roster_sender: self.update_validator_dial_roster_sender.clone(),
            update_peer_capabilities_sender: self.update_peer_capabilities_sender.clone(),
            update_trusted_peers_sender: self.update_trusted_peers_sender.clone(),
            update_acl_sender: self.update_acl_sender.clone(),
            update_handshake_sender: self.update_handshake_sender.clone(),
            network_message_high_sender: self.network_message_high_sender.clone(),
            network_message_safety_sender: self.network_message_safety_sender.clone(),
            network_message_progress_sender: self.network_message_progress_sender.clone(),
            network_message_low_sender: self.network_message_low_sender.clone(),
            network_message_high_deferred_permits: Arc::clone(
                &self.network_message_high_deferred_permits,
            ),
            network_message_safety_deferred_permits: Arc::clone(
                &self.network_message_safety_deferred_permits,
            ),
            network_message_progress_deferred_permits: Arc::clone(
                &self.network_message_progress_deferred_permits,
            ),
            network_actor_byte_budget: Arc::clone(&self.network_actor_byte_budget),
            network_actor_progress_budget: Arc::clone(&self.network_actor_progress_budget),
            network_actor_low_byte_budget: Arc::clone(&self.network_actor_low_byte_budget),
            self_id: self.self_id.clone(),
            relay_ttl: self.relay_ttl,
            topic_frame_caps: self.topic_frame_caps,
            subscriber_queue_cap: self.subscriber_queue_cap,
            _encryptor: core::marker::PhantomData::<E>,
        }
    }
}
fn validate_encrypted_frame_cap(max_frame_bytes: usize) -> Result<(), Error> {
    if max_frame_bytes > crate::MAX_ENCRYPTED_FRAME_BYTES {
        return Err(Error::FrameTooLarge);
    }
    Ok(())
}
fn invalid_transport_geometry(message: impl Into<String>) -> Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into()).into()
}

/// Resolve the finite byte burst before starting any transport worker.
///
/// `low_allow_bytes` charges the complete canonical Data/relay frame, before AEAD and the
/// stream prefix. Queue credits separately charge those bytes and are never enlarged here.
fn resolve_low_byte_burst(
    rate: Option<core::num::NonZeroU32>,
    configured: Option<core::num::NonZeroU32>,
    topic_caps: TopicFrameCaps,
) -> Result<u32, Error> {
    let maximum = topic_caps.low().into_iter().max().unwrap_or(0);
    let maximum = u32::try_from(maximum).map_err(|_| {
        invalid_transport_geometry("maximum low-topic plaintext frame exceeds u32 byte shaping")
    })?;
    if let Some(burst) = configured {
        if burst.get() < maximum {
            return Err(invalid_transport_geometry(format!(
                "network.low_priority_bytes_burst ({burst}) cannot admit one maximum eligible low-topic frame ({maximum} canonical plaintext bytes)"
            )));
        }
        return Ok(burst.get());
    }
    Ok(maximum.max(rate.map_or(1, core::num::NonZeroU32::get)))
}

const QUIC_DATAGRAM_DEPENDENCY_BLOCK_REASON: &str = "network.quic_datagrams_enabled=true is unavailable pending DATAGRAM transport requalification of locked quinn-proto 0.11.18; fixed per-entry accounting bounds zero-length frames but does not qualify the complete transport";

const QUIC_DEPENDENCY_BLOCK_REASON: &str = "network.quic_enabled=true is unavailable pending transport requalification of locked quinn-proto 0.11.18; dependency memory and panic fixes alone do not establish authenticated transport, resource, or interoperability qualification";

fn validate_shipping_quic_policy(configured: bool) -> Result<bool, Error> {
    if configured {
        return Err(invalid_transport_geometry(QUIC_DEPENDENCY_BLOCK_REASON));
    }
    Ok(false)
}

fn validate_shipping_quic_datagram_policy(configured: bool) -> Result<bool, Error> {
    if configured {
        return Err(invalid_transport_geometry(
            QUIC_DATAGRAM_DEPENDENCY_BLOCK_REASON,
        ));
    }
    Ok(false)
}

fn validate_quic_configuration(
    quic_enabled: bool,
    quic_datagrams_enabled: bool,
    datagram_max_payload_bytes: usize,
    datagram_receive_buffer_bytes: usize,
    datagram_send_buffer_bytes: usize,
) -> Result<(), Error> {
    if quic_datagrams_enabled && !quic_enabled {
        return Err(invalid_transport_geometry(
            "network.quic_datagrams_enabled=true requires network.quic_enabled=true",
        ));
    }
    if quic_datagrams_enabled {
        // The locked quinn-proto 0.11.18 requalification path charges
        // `size_of::<Datagram>()`; that private frame contains exactly one
        // `Bytes`, so mirror the fixed entry charge without depending on a
        // private Quinn type.
        let minimum_buffer = datagram_max_payload_bytes
            .checked_add(core::mem::size_of::<bytes::Bytes>())
            .ok_or_else(|| {
                invalid_transport_geometry("QUIC DATAGRAM buffer geometry overflows usize")
            })?;
        if datagram_receive_buffer_bytes < minimum_buffer
            || datagram_send_buffer_bytes < minimum_buffer
        {
            return Err(invalid_transport_geometry(format!(
                "network QUIC DATAGRAM receive and send buffers must each be at least {minimum_buffer} bytes for a {datagram_max_payload_bytes}-byte payload limit"
            )));
        }
    }
    Ok(())
}

#[derive(Debug)]
struct AbortOnDropTask {
    handle: Option<tokio::task::JoinHandle<()>>,
}
impl AbortOnDropTask {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self {
            handle: Some(handle),
        }
    }
    fn abort(&self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
    fn is_finished(&self) -> bool {
        self.handle
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
    }
    async fn join(mut self) {
        if let Some(handle) = self.handle.as_mut() {
            let _ = handle.await;
        }
        self.handle.take();
    }
}
impl Drop for AbortOnDropTask {
    fn drop(&mut self) {
        self.abort();
    }
}
/// Owns one accepted pre-authentication slot until a peer task takes over.
///
/// Dropping an in-flight listener or external-stream future must not leave its
/// `incoming_pending` entry charged forever. Cancellation delivery is itself
/// reliable under bounded service-channel backpressure.
struct InboundReservationGuard<T: Pload> {
    conn_id: ConnectionId,
    service_message_sender: mpsc::Sender<ServiceMessage<T>>,
    armed: bool,
}
impl<T: Pload> InboundReservationGuard<T> {
    fn new(conn_id: ConnectionId, service_message_sender: mpsc::Sender<ServiceMessage<T>>) -> Self {
        Self {
            conn_id,
            service_message_sender,
            armed: true,
        }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl<T: Pload> Drop for InboundReservationGuard<T> {
    fn drop(&mut self) {
        use tokio::sync::mpsc::error::TrySendError;
        if !self.armed {
            return;
        }
        let message = ServiceMessage::InboundCancelled(self.conn_id);
        match self.service_message_sender.try_send(message) {
            Ok(()) | Err(TrySendError::Closed(_)) => {}
            Err(TrySendError::Full(message)) => {
                let Ok(runtime) = tokio::runtime::Handle::try_current() else {
                    iroha_logger::error!(
                        conn_id = self.conn_id,
                        "Cannot release an inbound reservation outside its Tokio runtime"
                    );
                    return;
                };
                let service_message_sender = self.service_message_sender.clone();
                runtime.spawn(async move {
                    let _ = service_message_sender.send(message).await;
                });
            }
        }
    }
}
fn inbound_source_memory_bound(
    shared_high_bytes: usize,
    shared_low_bytes: usize,
    progress_bytes_per_peer: usize,
    max_total_connections: usize,
) -> Option<usize> {
    progress_bytes_per_peer
        .checked_mul(max_total_connections)
        .and_then(|reserved| reserved.checked_add(shared_high_bytes))
        .and_then(|high| high.checked_add(shared_low_bytes))
}
fn network_actor_progress_target_capacity(max_total_connections: usize) -> Option<usize> {
    // Direct authority is the union of at most one bounded logical topology
    // and at most one bounded authenticated-peer set. Broadcast route targets
    // are a subset of those identities. Keep both sets independently usable
    // during connection/topology transitions instead of letting stale direct
    // identities consume validator-reserved slots.
    max_total_connections.checked_mul(2)
}
fn network_actor_progress_source_capacity(max_total_connections: usize) -> Option<usize> {
    // Every authorized target can own one item in each protected semantic class.
    // Reliable broadcasts acquire these same target lanes before crossing
    // admission; there is deliberately no class-wide broadcast parent.
    network_actor_progress_target_capacity(max_total_connections)?
        .checked_mul(ActorProgressClass::COUNT)
}
fn network_actor_progress_waiter_capacity(max_total_connections: usize) -> Option<usize> {
    network_actor_progress_target_capacity(max_total_connections)?
        .checked_mul(3)?
        .checked_mul(RELIABLE_PROGRESS_WAITERS_PER_SOURCE)
}
fn inbound_source_credit_capacity(
    aggregate_queue_capacity: usize,
    max_total_connections: usize,
) -> Option<usize> {
    if aggregate_queue_capacity == 0 || max_total_connections == 0 {
        return None;
    }
    // A ceil-divided share keeps the configured aggregate useful when the
    // connection bound is larger than the queue while ensuring every
    // authenticated source owns at least one service rank per isolated lane.
    let quotient = aggregate_queue_capacity.checked_div(max_total_connections)?;
    let remainder = aggregate_queue_capacity.checked_rem(max_total_connections)?;
    quotient
        .checked_add(usize::from(remainder != 0))
        .map(|capacity| capacity.max(1))
}
#[cfg(test)]
mod inbound_source_memory_bound_tests {
    use super::{
        RELIABLE_PROGRESS_EXACT_OUTPUT_PRODUCERS_PER_SOURCE,
        RELIABLE_PROGRESS_LANE_RELAY_OWNER_CAPACITY, RELIABLE_PROGRESS_WAITERS_PER_SOURCE,
        inbound_source_credit_capacity, inbound_source_memory_bound,
        network_actor_progress_source_capacity, network_actor_progress_target_capacity,
        network_actor_progress_waiter_capacity,
    };
    #[test]
    fn exact_per_peer_source_reserve_geometry_is_checked() {
        assert_eq!(inbound_source_memory_bound(10, 5, 3, 4), Some(27));
        assert_eq!(
            inbound_source_memory_bound(usize::MAX, 0, 1, 1),
            None,
            "aggregate addition must fail closed"
        );
        assert_eq!(
            inbound_source_memory_bound(0, 0, usize::MAX, 2),
            None,
            "per-peer reserve multiplication must fail closed"
        );
        assert_eq!(
            inbound_source_memory_bound(usize::MAX - 1, 2, 0, 0),
            None,
            "the independent low-stream owner is part of the process bound"
        );
    }
    #[test]
    fn reliable_actor_source_geometry_counts_targets_broadcasts_and_classes() {
        assert_eq!(network_actor_progress_target_capacity(4), Some(8));
        assert_eq!(network_actor_progress_source_capacity(4), Some(24));
        let configured_per_source = RELIABLE_PROGRESS_LANE_RELAY_OWNER_CAPACITY
            + RELIABLE_PROGRESS_EXACT_OUTPUT_PRODUCERS_PER_SOURCE;
        assert_eq!(RELIABLE_PROGRESS_WAITERS_PER_SOURCE, configured_per_source);
        assert_eq!(
            network_actor_progress_waiter_capacity(4),
            Some(24 * configured_per_source)
        );
        assert_eq!(network_actor_progress_target_capacity(usize::MAX), None);
        assert_eq!(
            network_actor_progress_source_capacity(usize::MAX),
            None,
            "connection-plus-broadcast source arithmetic must fail closed"
        );
    }
    #[test]
    fn reliable_actor_waiter_geometry_rejects_source_overflow() {
        assert_eq!(
            network_actor_progress_waiter_capacity(usize::MAX),
            None,
            "configured producer/source multiplication must fail closed"
        );
    }
    #[test]
    fn authenticated_source_count_share_is_checked_and_never_zero() {
        assert_eq!(inbound_source_credit_capacity(64, 4), Some(16));
        assert_eq!(inbound_source_credit_capacity(1, 4), Some(1));
        assert_eq!(inbound_source_credit_capacity(0, 4), None);
        assert_eq!(inbound_source_credit_capacity(4, 0), None);
        assert_eq!(
            inbound_source_credit_capacity(usize::MAX, 2),
            Some(usize::MAX / 2 + 1)
        );
    }
}
fn validate_channel_capacity_geometry(
    high: usize,
    low: usize,
    post: usize,
    subscriber: usize,
) -> Result<(), Error> {
    if high < message::TransportAdmissionClass::ORDINARY_HIGH.len()
        || low < message::TransportAdmissionClass::LOW.len()
        || subscriber < 2
    {
        return Err(invalid_transport_geometry(
            "mandatory semantic queue partitions do not fit configured count ceilings",
        ));
    }
    let max = Semaphore::MAX_PERMITS;
    for (name, value) in [
        ("network.p2p_queue_cap_high", high),
        ("network.p2p_queue_cap_low", low),
        ("network.p2p_post_queue_cap", post),
        ("network.p2p_subscriber_queue_cap", subscriber),
    ] {
        if value > max {
            return Err(invalid_transport_geometry(format!(
                "{name} ({value}) exceeds Tokio channel maximum {max}"
            )));
        }
    }
    let derived = [
        ("relay high subscriber", subscriber.checked_mul(4)),
        ("relay payload subscriber", subscriber.checked_mul(2)),
        ("relay high worker", subscriber.checked_mul(8)),
        ("relay payload worker", subscriber.checked_mul(4)),
    ];
    for (name, value) in derived {
        let Some(value) = value else {
            return Err(invalid_transport_geometry(format!(
                "{name} capacity overflows usize from network.p2p_subscriber_queue_cap={subscriber}"
            )));
        };
        if value > max {
            return Err(invalid_transport_geometry(format!(
                "{name} capacity {value} exceeds Tokio channel maximum {max}"
            )));
        }
    }
    Ok(())
}
#[expect(
    clippy::struct_field_names,
    reason = "the repeated _bytes suffix makes byte units explicit beside count-based transport limits and prevents queue-geometry unit confusion"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TransportQueueGeometry {
    /// Additive global reserve used only by authoritative safety traffic.
    safety_reserve_bytes: usize,
    /// Per-authenticated-peer reserve used by every reliable high/progress frame.
    progress_reserve_bytes: usize,
    /// Exact per-source actor limits for safety, lane, and bulk progress.
    actor_progress_bytes: ActorProgressByteLimits,
}
fn validate_transport_queue_geometry<E: Enc>(
    max_frame_bytes: usize,
    topic_caps: TopicFrameCaps,
    high_max_bytes: usize,
    low_max_bytes: usize,
    deferred_send_max_bytes_total: usize,
    deferred_send_max_bytes_per_peer: usize,
    deferred_send_max_per_peer: usize,
    high_channel_cap: usize,
    low_channel_cap: usize,
    post_channel_cap: usize,
    subscriber_channel_cap: usize,
) -> Result<TransportQueueGeometry, Error> {
    validate_encrypted_frame_cap(max_frame_bytes)?;
    validate_channel_capacity_geometry(
        high_channel_cap,
        low_channel_cap,
        post_channel_cap,
        subscriber_channel_cap,
    )?;
    let plaintext_ceiling = crate::frame_plaintext_cap_for::<E>(max_frame_bytes);
    for cap in topic_caps.all() {
        if cap > plaintext_ceiling {
            return Err(invalid_transport_geometry(format!(
                "P2P topic plaintext cap {cap} exceeds the AEAD-specific global plaintext ceiling {plaintext_ceiling}"
            )));
        }
    }
    let max_topic_charge = topic_caps
        .all()
        .into_iter()
        .map(|cap| crate::frame_queue_charge_for::<E>(cap).ok_or(Error::FrameTooLarge))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .unwrap_or(0);
    if high_max_bytes < max_topic_charge {
        return Err(invalid_transport_geometry(format!(
            "network.p2p_outbound_frame_queue_max_high_bytes ({high_max_bytes}) cannot retain one maximum eligible topic frame ({max_topic_charge} stream bytes)"
        )));
    }
    let max_low_topic_charge = topic_caps
        .low()
        .into_iter()
        .map(|cap| crate::frame_queue_charge_for::<E>(cap).ok_or(Error::FrameTooLarge))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .unwrap_or(0);
    if low_max_bytes < max_low_topic_charge {
        return Err(invalid_transport_geometry(format!(
            "network.p2p_outbound_frame_queue_max_low_bytes ({low_max_bytes}) cannot retain one maximum eligible low-topic frame ({max_low_topic_charge} stream bytes)"
        )));
    }
    let safety_reserve_bytes =
        crate::frame_queue_charge_for::<E>(topic_caps.control).ok_or(Error::FrameTooLarge)?;
    let lane_reserve_bytes = safety_reserve_bytes
        .max(crate::frame_queue_charge_for::<E>(topic_caps.consensus).ok_or(Error::FrameTooLarge)?);
    let bulk_reserve_bytes =
        crate::frame_queue_charge_for::<E>(topic_caps.block_sync).ok_or(Error::FrameTooLarge)?;
    let progress_reserve_bytes = safety_reserve_bytes
        .max(lane_reserve_bytes)
        .max(bulk_reserve_bytes);
    let deferred_minimum = safety_reserve_bytes
        .checked_add(max_topic_charge)
        .ok_or_else(|| {
            invalid_transport_geometry(format!(
                "deferred-send byte geometry overflows: maximum ordinary progress frame {max_topic_charge} plus safety reserve {safety_reserve_bytes}"
            ))
        })?;
    if deferred_send_max_bytes_total < deferred_minimum {
        return Err(invalid_transport_geometry(format!(
            "network.deferred_send_max_bytes_total ({deferred_send_max_bytes_total}) cannot retain one maximum ordinary progress frame ({max_topic_charge} stream bytes) plus the additive safety reserve ({safety_reserve_bytes} stream bytes); minimum is {deferred_minimum}"
        )));
    }
    if deferred_send_max_bytes_per_peer < deferred_minimum {
        return Err(invalid_transport_geometry(format!(
            "network.deferred_send_max_bytes_per_peer ({deferred_send_max_bytes_per_peer}) cannot retain one maximum ordinary progress frame ({max_topic_charge} stream bytes) plus the additive safety reserve ({safety_reserve_bytes} stream bytes); minimum is {deferred_minimum}"
        )));
    }
    if deferred_send_max_per_peer < 3 {
        return Err(invalid_transport_geometry(format!(
            "network.deferred_send_max_per_peer ({deferred_send_max_per_peer}) cannot isolate one safety, lane-progress, and bulk-progress frame; minimum is 3"
        )));
    }
    high_max_bytes
        .checked_add(safety_reserve_bytes)
        .ok_or_else(|| {
            invalid_transport_geometry(format!(
                "high transport byte capacity overflows: ordinary {high_max_bytes} plus safety reserve {safety_reserve_bytes}"
            ))
        })?;
    Ok(TransportQueueGeometry {
        safety_reserve_bytes,
        progress_reserve_bytes,
        actor_progress_bytes: ActorProgressByteLimits {
            safety: safety_reserve_bytes,
            lane: lane_reserve_bytes,
            bulk: bulk_reserve_bytes,
        },
    })
}
fn network_actor_byte_budget(
    ordinary_high_bytes: usize,
    safety_reserve_bytes: usize,
) -> Result<Arc<NetworkActorByteBudget>, Error> {
    if ordinary_high_bytes < safety_reserve_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "network.p2p_outbound_frame_queue_max_high_bytes ({ordinary_high_bytes}) cannot retain one maximum control/safety frame ({safety_reserve_bytes} encrypted stream bytes)"
            ),
        )
        .into());
    }
    NetworkActorByteBudget::new(ordinary_high_bytes, safety_reserve_bytes).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "network actor aggregate byte capacity overflows: ordinary high budget {ordinary_high_bytes} plus safety reserve {safety_reserve_bytes}"
            ),
        )
        .into()
    })
}
impl<T: Pload + message::ClassifyTopic + Sync, E: Enc + Sync> NetworkBaseHandle<T, E> {
    /// Maximum independent authenticated reply sources reserved by this actor.
    #[must_use]
    pub const fn reply_route_source_capacity(&self) -> usize {
        self.reply_route_source_capacity
    }
    /// Start network peer and return handle to it
    ///
    /// # Errors
    /// Returns an error for invalid frame/queue geometry, listener binding or
    /// transport setup failures, and incompatible handshake configuration.
    #[log(skip(identity_keys, shutdown_signal))]
    pub async fn start(
        identity_keys: P2pIdentityKeys,
        config: Config,
        network_id: NetworkId,
        consensus_caps: Option<crate::ConsensusHandshakeCaps>,
        confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
        shutdown_signal: ShutdownSignal,
    ) -> Result<(Self, Child), Error> {
        Box::pin(Self::start_with_crypto(
            identity_keys,
            config,
            network_id,
            consensus_caps,
            confidential_caps,
            None,
            shutdown_signal,
        ))
        .await
    }
    /// Construct a closed network handle for tests that cannot bind sockets.
    ///
    /// The returned handle drops all outgoing messages and reports no online peers.
    #[must_use]
    pub fn closed_for_tests() -> Self {
        let (subscribe_tx, _subscribe_rx) = mpsc::channel::<Subscriber<T>>(1);
        let (update_topology_tx, update_topology_rx) = control_update_channel();
        let (update_peers_tx, update_peers_rx) = control_update_channel();
        let (update_validator_dial_roster_tx, update_validator_dial_roster_rx) =
            control_update_channel();
        let (update_peer_capabilities_tx, update_peer_capabilities_rx) = control_update_channel();
        let (update_trusted_tx, update_trusted_rx) = control_update_channel();
        let (update_acl_tx, update_acl_rx) = control_update_channel();
        let (update_handshake_tx, update_handshake_rx) =
            mpsc::channel(HANDSHAKE_UPDATE_CHANNEL_CAPACITY);
        let (network_message_high_sender, _network_message_high_rx) =
            net_channel::channel_with_capacity(1);
        let (network_message_safety_sender, _network_message_safety_rx) =
            net_channel::channel_with_capacity(1);
        let (network_message_progress_sender, _network_message_progress_rx) =
            net_channel::channel_with_capacity(1);
        let (network_message_low_sender, _network_message_low_rx) =
            net_channel::channel_with_capacity(1);
        let (_online_peers_tx, online_peers_receiver) = watch::channel(HashSet::new());
        let (_online_peer_capabilities_tx, online_peer_capabilities_receiver) =
            watch::channel(HashMap::new());
        let reliable_broadcast_topology = Arc::new(Mutex::new(ReliableProgressTopology::empty()));
        let reliable_direct_topology = Arc::new(Mutex::new(ReliableProgressTopology::empty()));
        let configured_peer_ids = Arc::new(Mutex::new(ConfiguredPeerState::default()));
        let reply_route_owner = Arc::new(());
        drop(update_topology_rx);
        drop(update_peers_rx);
        drop(update_validator_dial_roster_rx);
        drop(update_peer_capabilities_rx);
        drop(update_trusted_rx);
        drop(update_acl_rx);
        drop(update_handshake_rx);
        Self {
            subscribe_to_peers_messages_sender: subscribe_tx,
            online_peers_receiver,
            online_peer_capabilities_receiver,
            reliable_broadcast_topology,
            reliable_direct_topology,
            configured_peer_ids,
            reply_route_owner,
            reply_route_source_capacity: 1,
            update_topology_sender: update_topology_tx,
            update_peers_sender: update_peers_tx,
            update_validator_dial_roster_sender: update_validator_dial_roster_tx,
            update_peer_capabilities_sender: update_peer_capabilities_tx,
            update_trusted_peers_sender: update_trusted_tx,
            update_acl_sender: update_acl_tx,
            update_handshake_sender: update_handshake_tx,
            network_message_high_sender,
            network_message_safety_sender,
            network_message_progress_sender,
            network_message_low_sender,
            network_message_high_deferred_permits: Arc::new(Semaphore::new(1)),
            network_message_safety_deferred_permits: Arc::new(Semaphore::new(1)),
            network_message_progress_deferred_permits: Arc::new(Semaphore::new(1)),
            network_actor_byte_budget: NetworkActorByteBudget::new(usize::MAX, 0)
                .expect("zero safety reserve must fit the test budget"),
            network_actor_progress_budget: NetworkActorProgressBudget::new(usize::MAX, 1, 1)
                .expect("single-source unbounded test progress budget must fit"),
            network_actor_low_byte_budget: NetworkActorByteBudget::new(usize::MAX, 0)
                .expect("zero-reserve low test budget must fit"),
            self_id: PeerId::from(
                KeyPair::random_with_algorithm(Algorithm::BlsNormal)
                    .public_key()
                    .clone(),
            ),
            relay_ttl: 0,
            topic_frame_caps: TopicFrameCaps {
                consensus: usize::MAX,
                control: usize::MAX,
                block_sync: usize::MAX,
                tx_gossip: usize::MAX,
                peer_gossip: usize::MAX,
                health: usize::MAX,
                connect: usize::MAX,
                other: usize::MAX,
            },
            subscriber_queue_cap: core::num::NonZeroUsize::new(1).expect("nonzero"),
            _encryptor: core::marker::PhantomData::<E>,
        }
    }
    /// Construct a closed handle and the sole capability for its configured-peer snapshot.
    ///
    /// This is available only to tests and never exposes a mutation capability
    /// for a live actor-owned handle.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn closed_for_tests_with_configured_peer_snapshot()
    -> (Self, ConfiguredPeerSnapshotTestFixture) {
        let handle = Self::closed_for_tests();
        let fixture = ConfiguredPeerSnapshotTestFixture {
            state: Arc::clone(&handle.configured_peer_ids),
        };
        (handle, fixture)
    }
    /// Launch the P2P runtime with pluggable handshake capability overrides.
    ///
    /// Use this entrypoint when tests or specialised deployments need to force
    /// specific handshake capabilities (e.g., consensus/torii lanes, confidential
    /// transport) instead of relying on the defaults wired through [`Config`].
    /// The returned handle lets callers stream peer events, publish network
    /// messages, and coordinate shutdown for the spawned reactor.
    ///
    /// # Errors
    ///
    /// Returns an error if `network.max_frame_bytes` exceeds the deterministic
    /// 2,147,483,643-byte encrypted-frame runtime limit, if the configured high
    /// byte owner cannot retain one maximum control/safety frame plus its
    /// additive actor reserve, if the listener cannot bind to the requested
    /// address, if the crypto handshake fails during bootstrap, or if the
    /// reactor tasks fail to initialise (for example, due to TLS key/cert issues
    /// or capability mismatches).
    #[log(skip(identity_keys, shutdown_signal))]
    #[allow(clippy::too_many_lines, clippy::used_underscore_binding)]
    #[expect(
        clippy::large_futures,
        reason = "the source-sealed wrapper preserves exact startup delegation and avoids a release-path allocation"
    )]
    pub async fn start_with_crypto(
        identity_keys: P2pIdentityKeys,
        config: Config,
        network_id: NetworkId,
        consensus_caps: Option<crate::ConsensusHandshakeCaps>,
        confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
        crypto_caps: Option<crate::CryptoHandshakeCaps>,
        shutdown_signal: ShutdownSignal,
    ) -> Result<(Self, Child), Error> {
        Self::start_with_crypto_and_initial_trusted_sources(
            identity_keys,
            config,
            network_id,
            consensus_caps,
            confidential_caps,
            crypto_caps,
            HashSet::new(),
            shutdown_signal,
        )
        .await
    }
    /// Launch the P2P runtime with a source-authority projection installed
    /// before any listener can accept an authenticated peer.
    ///
    /// `initial_trusted_sources` is resource-allocation authority, not a
    /// substitute for topology, ACL, or handshake authorization. Irohad passes
    /// its configured remote trusted peers here so a zero-delay localnet cannot
    /// race the later actor update and reject valid consensus traffic.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::start_with_crypto`],
    /// and when the initial protected-source projection exceeds
    /// `network.max_total_connections`.
    #[log(skip(identity_keys, shutdown_signal))]
    #[allow(clippy::too_many_lines, clippy::used_underscore_binding)]
    pub async fn start_with_crypto_and_initial_trusted_sources(
        identity_keys: P2pIdentityKeys,
        config: Config,
        network_id: NetworkId,
        consensus_caps: Option<crate::ConsensusHandshakeCaps>,
        confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
        crypto_caps: Option<crate::CryptoHandshakeCaps>,
        initial_trusted_sources: HashSet<PeerId>,
        shutdown_signal: ShutdownSignal,
    ) -> Result<(Self, Child), Error> {
        Self::start_with_crypto_and_initial_authorities(
            identity_keys,
            config,
            network_id,
            consensus_caps,
            confidential_caps,
            crypto_caps,
            initial_trusted_sources,
            HashSet::new(),
            shutdown_signal,
        )
        .await
    }
    /// Launch with protected-source authority and the configured validator roster.
    /// The roster is installed before topology processing to prevent a startup race.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid network bounds, authority, transport policy, or listeners.
    #[log(skip(
        identity_keys,
        initial_trusted_sources,
        initial_validator_dial_roster,
        shutdown_signal
    ))]
    #[allow(clippy::too_many_lines, clippy::used_underscore_binding)]
    pub async fn start_with_crypto_and_initial_authorities(
        identity_keys: P2pIdentityKeys,
        Config {
            address: listen_addr,
            public_address,
            relay_mode,
            relay_hub_addresses,
            relay_ttl,
            soranet_handshake,
            idle_timeout,
            preauth_timeout,
            reply_writer_flush_timeout,
            connect_startup_delay,
            dial_timeout,
            deferred_send_ttl,
            deferred_send_max_per_peer,
            deferred_send_max_bytes_per_peer,
            deferred_send_max_bytes_total,
            peer_gossip_period,
            trust_gossip,
            quic_enabled,
            quic_datagrams_enabled,
            quic_datagram_max_payload_bytes,
            quic_datagram_receive_buffer_bytes,
            quic_datagram_send_buffer_bytes,
            p2p_queue_cap_high,
            p2p_queue_cap_low,
            p2p_post_queue_cap,
            p2p_outbound_frame_queue_max_high_bytes,
            p2p_outbound_frame_queue_max_low_bytes,
            p2p_outbound_frame_queue_max_high_frames,
            p2p_outbound_frame_queue_max_low_frames,
            p2p_subscriber_queue_cap,
            dns_refresh_interval,
            dns_refresh_ttl,
            p2p_proxy,
            p2p_proxy_required,
            p2p_no_proxy,
            outbound_dial_allow_cidrs,
            outbound_dial_deny_cidrs,
            outbound_dial_allow_dns_suffixes,
            outbound_dial_deny_dns_suffixes,
            p2p_proxy_tls_verify,
            p2p_proxy_tls_pinned_cert_der_base64,
            happy_eyeballs_stagger: config_happy_eyeballs_stagger,
            addr_ipv6_first,
            max_incoming,
            max_total_connections,
            preauth_max_connections_per_ip,
            accept_rate_per_ip_per_sec,
            accept_burst_per_ip,
            max_accept_buckets,
            accept_bucket_idle,
            accept_prefix_v4_bits,
            accept_prefix_v6_bits,
            accept_rate_per_prefix_per_sec,
            accept_burst_per_prefix,
            low_priority_rate_per_sec,
            low_priority_burst,
            low_priority_bytes_per_sec,
            low_priority_bytes_burst,
            allowlist_only,
            allow_keys,
            deny_keys,
            allow_cidrs,
            deny_cidrs,
            disconnect_on_post_overflow,
            max_frame_bytes,
            max_frame_bytes_consensus,
            max_frame_bytes_control,
            max_frame_bytes_block_sync,
            max_frame_bytes_tx_gossip,
            max_frame_bytes_peer_gossip,
            max_frame_bytes_health,
            max_frame_bytes_connect,
            max_frame_bytes_other,
            tcp_nodelay,
            tcp_keepalive,
            quic_max_idle_timeout,
            ..
        }: Config,
        // Canonical chain identity bound into every peer handshake signature.
        network_id: NetworkId,
        // Optional consensus capabilities for handshake gating (mode/proto/fingerprint)
        consensus_caps: Option<crate::ConsensusHandshakeCaps>,
        confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
        crypto_caps: Option<crate::CryptoHandshakeCaps>,
        mut initial_trusted_sources: HashSet<PeerId>,
        mut initial_validator_dial_roster: HashSet<PeerId>,
        shutdown_signal: ShutdownSignal,
    ) -> Result<(Self, Child), Error> {
        // Reject vulnerable QUIC before listener or dialer sockets are created.
        // Returning the validated values also keeps every downstream
        // capability, transport, and actor configuration on the same
        // fail-closed branch.
        let quic_enabled = validate_shipping_quic_policy(quic_enabled)?;
        let quic_datagrams_enabled =
            validate_shipping_quic_datagram_policy(quic_datagrams_enabled)?;
        validate_quic_configuration(
            quic_enabled,
            quic_datagrams_enabled,
            quic_datagram_max_payload_bytes,
            quic_datagram_receive_buffer_bytes,
            quic_datagram_send_buffer_bytes,
        )?;
        let (allow_nets, deny_nets) =
            parse_acl_cidrs(&allow_cidrs, &deny_cidrs).map_err(invalid_transport_geometry)?;
        validate_accept_throttle_geometry(
            accept_rate_per_prefix_per_sec.is_some(),
            accept_rate_per_ip_per_sec.is_some(),
            max_accept_buckets.get(),
        )
        .map_err(invalid_transport_geometry)?;
        let P2pIdentityKeys {
            node: key_pair,
            soranet_transport,
        } = identity_keys;
        // Continue startup preflight before QUIC or TCP listener setup can bind
        // sockets. This prevents a sender from reaching encryption with a frame
        // length that the deterministic contiguous-buffer limit cannot represent.
        let topic_frame_caps = TopicFrameCaps {
            consensus: max_frame_bytes_consensus,
            control: max_frame_bytes_control,
            block_sync: max_frame_bytes_block_sync,
            tx_gossip: max_frame_bytes_tx_gossip,
            peer_gossip: max_frame_bytes_peer_gossip,
            health: max_frame_bytes_health,
            connect: max_frame_bytes_connect,
            other: max_frame_bytes_other,
        };
        let transport_geometry = validate_transport_queue_geometry::<E>(
            max_frame_bytes,
            topic_frame_caps,
            p2p_outbound_frame_queue_max_high_bytes.get(),
            p2p_outbound_frame_queue_max_low_bytes.get(),
            deferred_send_max_bytes_total,
            deferred_send_max_bytes_per_peer,
            deferred_send_max_per_peer,
            p2p_queue_cap_high.get(),
            p2p_queue_cap_low.get(),
            p2p_post_queue_cap.get(),
            p2p_subscriber_queue_cap.get(),
        )?;
        let low_bytes_burst = f64::from(resolve_low_byte_burst(
            low_priority_bytes_per_sec,
            low_priority_bytes_burst,
            topic_frame_caps,
        )?);
        let safety_reserve_bytes = transport_geometry.safety_reserve_bytes;
        let progress_reserve_bytes = transport_geometry.progress_reserve_bytes;
        let max_total_connections = max_total_connections.map_or(
            iroha_config::parameters::defaults::network::lane_profile::CORE_MAX_TOTAL_CONNECTIONS,
            core::num::NonZeroUsize::get,
        );
        crate::preauth::PreauthDeadline::from_now(preauth_timeout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "network.preauth_timeout_ms cannot be represented by the monotonic clock",
            )
        })?;
        let outbound_authentication_timeout =
            checked_outbound_authentication_timeout(dial_timeout, preauth_timeout).ok_or_else(
                || {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "network.dial_timeout_ms + network.preauth_timeout_ms cannot be represented by the monotonic clock",
                    )
                },
            )?;
        let authenticated_source_credit_capacity = inbound_source_credit_capacity(
            p2p_subscriber_queue_cap.get(),
            max_total_connections,
        )
        .ok_or_else(|| {
            invalid_transport_geometry(
                "subscriber queue capacity cannot provide a non-zero authenticated-source share",
            )
        })?;
        #[cfg(feature = "quic")]
        let quic_max_incoming = max_incoming
            .map_or(max_total_connections, core::num::NonZeroUsize::get)
            .min(max_total_connections);
        #[cfg(feature = "quic")]
        let quic_flow_control = crate::transport::quic::FlowControlConfig {
            max_encrypted_frame_bytes: max_frame_bytes,
            max_total_connections,
            process_budget_bytes: p2p_outbound_frame_queue_max_high_bytes.get(),
        };
        #[cfg(feature = "quic")]
        if quic_enabled {
            crate::transport::quic::endpoint_buffer_geometry(
                quic_flow_control,
                quic_max_incoming,
                quic_datagrams_enabled.then_some(quic_datagram_receive_buffer_bytes),
                if quic_datagrams_enabled {
                    quic_datagram_send_buffer_bytes
                } else {
                    0
                },
            )
            .map_err(|error| {
                invalid_transport_geometry(format!("invalid QUIC endpoint geometry: {error}"))
            })?;
        }
        let _max_inbound_source_bytes = inbound_source_memory_bound(
            p2p_outbound_frame_queue_max_high_bytes.get(),
            p2p_outbound_frame_queue_max_low_bytes.get(),
            progress_reserve_bytes,
            max_total_connections,
        )
            .ok_or_else(|| {
                invalid_transport_geometry(
                    "shared high/low source budgets plus network.max_total_connections × the exact maximum progress-frame reserve overflow the inbound source-memory bound",
                )
            })?;
        let network_actor_progress_waiters =
            network_actor_progress_waiter_capacity(max_total_connections).ok_or_else(|| {
                invalid_transport_geometry(
                    "network.max_total_connections overflows the reliable actor producer/source waiter geometry",
                )
            })?;
        let network_actor_progress_targets =
            network_actor_progress_target_capacity(max_total_connections).ok_or_else(|| {
                invalid_transport_geometry(
                    "network.max_total_connections overflows the reliable actor target geometry",
                )
            })?;
        let self_id = PeerId::from(key_pair.public_key().clone());
        let receive_maximum = topic_frame_caps
            .admission_maxima(crate::frame_plaintext_cap_for::<E>(max_frame_bytes))?;
        let network_actor_byte_budget = network_actor_byte_budget(
            p2p_outbound_frame_queue_max_high_bytes.get(),
            safety_reserve_bytes,
        )?;
        let network_actor_progress_budget = NetworkActorProgressBudget::new_classed(
            transport_geometry.actor_progress_bytes,
            network_actor_progress_targets,
            network_actor_progress_waiters,
        )
        .ok_or_else(|| {
            invalid_transport_geometry(
                "per-class reliable actor frame reserves × target sources overflow usize",
            )
        })?;
        let network_actor_low_byte_budget =
            NetworkActorByteBudget::new(p2p_outbound_frame_queue_max_low_bytes.get(), 0)
                .expect("zero-reserve low actor byte geometry cannot overflow");
        initial_validator_dial_roster
            .retain(|peer_id| peer_id == &self_id || initial_trusted_sources.contains(peer_id));
        let validator_dial_scheduler = ValidatorDialScheduler::new(
            initial_validator_dial_roster,
            outbound_authentication_timeout,
        );
        initial_trusted_sources.remove(&self_id);
        let authenticated_source_geometry =
            crate::peer::AuthenticatedSourceGeometry::new(max_total_connections);
        let inbound_frame_byte_budgets =
            crate::peer::InboundFrameByteBudgets::new_with_source_geometry(
                p2p_outbound_frame_queue_max_high_bytes.get(),
                p2p_outbound_frame_queue_max_low_bytes.get(),
                progress_reserve_bytes,
                authenticated_source_geometry.clone(),
            )
            .expect("validated inbound source budgets must fit");
        if !inbound_frame_byte_budgets.install_protected_sources(initial_trusted_sources) {
            return Err(invalid_transport_geometry(format!(
                "initial trusted peer count exceeds network.max_total_connections ({max_total_connections})"
            )));
        }
        let inbound_dispatch_byte_budgets = crate::peer::InboundDispatchByteBudgets::new(
            p2p_outbound_frame_queue_max_high_bytes.get(),
            p2p_outbound_frame_queue_max_low_bytes.get(),
            safety_reserve_bytes,
        )
        .expect("validated inbound dispatch budgets must fit");
        // Mandatory first-release semantic geometry is admitted before any
        // listener/dialer starts. No caller-priority or broad-Topic substitute.
        let receive_credit_pool = crate::peer::receive_credit::Pool::new(
            inbound_frame_byte_budgets.clone(),
            inbound_dispatch_byte_budgets.clone(),
            authenticated_source_credit_capacity,
            receive_maximum,
        )?;
        let relay_role = relay_role_from_mode(relay_mode);
        let relay_ttl = relay_ttl;
        let outbound_frame_queue_limits = OutboundFrameQueueLimits::new_with_progress_reserve(
            p2p_outbound_frame_queue_max_high_bytes.get(),
            p2p_outbound_frame_queue_max_low_bytes.get(),
            progress_reserve_bytes,
            p2p_outbound_frame_queue_max_high_frames.get(),
            p2p_outbound_frame_queue_max_low_frames.get(),
        );
        crate::peer::receive_credit::writer_partitions(
            receive_maximum,
            outbound_frame_queue_limits,
        ).map_err(|error| invalid_transport_geometry(format!(
            "network.p2p_outbound_frame_queue_max_high_bytes ({}) and network.p2p_outbound_frame_queue_max_low_bytes ({}) with high/low frame slots ({}/{}) cannot fund separate plaintext/encryption copies and envelopes for semantic frame maxima {receive_maximum:?}: {error}",
            outbound_frame_queue_limits.high_max_bytes,
            outbound_frame_queue_limits.low_max_bytes,
            outbound_frame_queue_limits.high_max_frames,
            outbound_frame_queue_limits.low_max_frames,
        )))?;
        let outbound_post_byte_budgets = OutboundPostByteBudgets::new_with_source_geometry(
            outbound_frame_queue_limits.high_max_bytes,
            outbound_frame_queue_limits.low_max_bytes,
            outbound_frame_queue_limits.progress_reserve_bytes,
            authenticated_source_geometry,
        )
        .expect("validated process-wide outbound byte geometry must fit");
        let semantic_post_pool = outbound_post_byte_budgets.install_semantic(receive_maximum)?;
        let trust_gossip_config = trust_gossip;
        let trust_gossip = trust_gossip_config && soranet_handshake.trust_gossip;
        let soranet_runtime = runtime_from_handshake(soranet_handshake)?;
        let connect_startup_delay_until = tokio::time::Instant::now() + connect_startup_delay;
        if quic_enabled && !cfg!(feature = "quic") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "network.quic_enabled=true requires a build with iroha_p2p/quic",
            )
            .into());
        }
        // Parse before any proxy-policy early return so the credential-bearing
        // source URL is scrubbed on both success and error paths.
        let proxy_policy = crate::transport::ProxyPolicy::from_config(p2p_proxy, p2p_no_proxy)?;
        let outbound_dial_policy = Arc::new(crate::dial_policy::OutboundDialPolicy::from_config(
            outbound_dial_allow_cidrs,
            outbound_dial_deny_cidrs,
            outbound_dial_allow_dns_suffixes,
            outbound_dial_deny_dns_suffixes,
        )?);
        let proxy_is_https = proxy_policy.uses_https_proxy();
        if p2p_proxy_required {
            if !proxy_policy.is_configured() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "network.p2p_proxy_required=true but network.p2p_proxy is not set",
                )
                .into());
            }
            if proxy_policy.has_no_proxy_entries() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "network.p2p_proxy_required=true is incompatible with network.p2p_no_proxy; remove no-proxy exemptions to enforce the proxy",
                )
                .into());
            }
            // QUIC uses UDP and bypasses the TCP proxy dialer entirely.
            if quic_enabled {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "network.p2p_proxy_required=true is incompatible with network.quic_enabled=true (QUIC bypasses the proxy); set network.quic_enabled=false",
                )
                .into());
            }
        }
        if proxy_is_https {
            if !p2p_proxy_tls_verify {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "network.p2p_proxy_tls_verify cannot be disabled for an https:// proxy",
                )
                .into());
            }
            let pin_present = p2p_proxy_tls_pinned_cert_der_base64
                .as_deref()
                .is_some_and(|raw| !raw.trim().is_empty());
            if !pin_present {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "network.p2p_proxy_tls_pinned_cert_der_base64 is required when using an https:// proxy",
                )
                .into());
            }
        }
        let local_scion_supported = quic_enabled;
        let proxy_tls_pinned_cert_der: Option<std::sync::Arc<[u8]>> =
            if let Some(raw) = p2p_proxy_tls_pinned_cert_der_base64.as_deref() {
                let raw = raw.trim();
                if raw.is_empty() {
                    None
                } else {
                    let bytes = BASE64_STANDARD.decode(raw.as_bytes()).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("network.p2p_proxy_tls_pinned_cert_der_base64: {e}"),
                        )
                    })?;
                    Some(std::sync::Arc::<[u8]>::from(bytes))
                }
            } else {
                None
            };
        // Only after all non-I/O configuration preflights succeed, create the
        // process-lifetime delegated authentication material. Share each
        // private key from this point onward so peer actors never duplicate it.
        let soranet_transport_key_pair = Arc::new(soranet_transport);
        let relay_authentication_mldsa65_key_pair = Arc::new(
            KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::MlDsa).map_err(
                |error| {
                    Error::HandshakeSoranet(format!(
                        "failed to generate process-lifetime SoraNet ML-DSA-65 authentication key: {error}"
                    ))
                },
            )?,
        );
        let soranet_transport_certificate = crate::peer::create_soranet_transport_certificate_v5(
            &key_pair,
            Arc::clone(&soranet_transport_key_pair),
            relay_authentication_mldsa65_key_pair,
            &network_id,
        )?;
        let key_pair = Arc::new(key_pair);
        let quic_dialer: Option<crate::transport::QuicDialer> = {
            #[cfg(feature = "quic")]
            {
                if quic_enabled {
                    // Reuse a single UDP socket for all outbound QUIC dials.
                    Some(
                        crate::transport::quic::Dialer::bind(
                            "0.0.0.0:0".parse().expect("valid bind addr"),
                            crate::transport::quic::DialerConfig {
                                max_idle_timeout: quic_max_idle_timeout,
                                datagram_receive_buffer: quic_datagrams_enabled
                                    .then_some(quic_datagram_receive_buffer_bytes),
                                datagram_send_buffer: if quic_datagrams_enabled {
                                    quic_datagram_send_buffer_bytes
                                } else {
                                    0
                                },
                                flow_control: quic_flow_control,
                                ..Default::default()
                            },
                        )
                        .map_err(|error| {
                            io::Error::new(
                                io::ErrorKind::AddrNotAvailable,
                                format!(
                                    "failed to initialize mandatory requested QUIC dialer: {error}"
                                ),
                            )
                        })?,
                    )
                } else {
                    None
                }
            }
            #[cfg(not(feature = "quic"))]
            {
                let _ = quic_enabled;
                let _ = quic_datagrams_enabled;
                let _ = quic_datagram_max_payload_bytes;
                let _ = quic_datagram_receive_buffer_bytes;
                let _ = quic_datagram_send_buffer_bytes;
                let _ = quic_max_idle_timeout;
                None
            }
        };
        let (online_peers_sender, online_peers_receiver) = watch::channel(HashSet::new());
        let (online_peer_capabilities_sender, online_peer_capabilities_receiver) =
            watch::channel(HashMap::new());
        let reliable_broadcast_topology = Arc::new(Mutex::new(ReliableProgressTopology::empty()));
        let reliable_direct_topology = Arc::new(Mutex::new(ReliableProgressTopology::empty()));
        let configured_peer_ids = Arc::new(Mutex::new(ConfiguredPeerState::default()));
        let reply_route_owner = Arc::new(());
        let (subscribe_to_peers_messages_sender, subscribe_to_peers_messages_receiver) =
            mpsc::channel(p2p_subscriber_queue_cap.get());
        let (update_topology_sender, update_topology_receiver) = control_update_channel();
        let (update_peers_sender, update_peers_receiver) = control_update_channel();
        let (update_validator_dial_roster_sender, update_validator_dial_roster_receiver) =
            control_update_channel();
        let (update_peer_capabilities_sender, update_peer_capabilities_receiver) =
            control_update_channel();
        let (update_trusted_peers_sender, update_trusted_peers_receiver) = control_update_channel();
        let (update_acl_sender, update_acl_receiver) = control_update_channel();
        let (update_handshake_sender, update_handshake_receiver) =
            mpsc::channel(HANDSHAKE_UPDATE_CHANNEL_CAPACITY);
        // Bounded queue capacities are supplied from node configuration so the
        // default build enforces backpressure without relying on feature flags.
        let (network_message_high_sender, network_message_high_receiver) =
            net_channel::channel_with_capacity(p2p_queue_cap_high.get());
        let (network_message_safety_sender, network_message_safety_receiver) =
            net_channel::channel_with_capacity(p2p_queue_cap_high.get());
        let (network_message_progress_sender, network_message_progress_receiver) =
            net_channel::channel_with_capacity(p2p_queue_cap_high.get());
        let (network_message_low_sender, network_message_low_receiver) =
            net_channel::channel_with_capacity(p2p_queue_cap_low.get());
        // Each physical FIFO is a positive partition of the existing lane
        // count; adding semantic owners cannot multiply any configured total.
        let high_total = p2p_queue_cap_high.get();
        let high_n = message::TransportAdmissionClass::ORDINARY_HIGH.len();
        let share = std::num::NonZeroUsize::new(high_total / high_n).ok_or_else(|| {
            invalid_transport_geometry("high queue cap cannot fund all mandatory classes")
        })?;
        let lane_share = std::num::NonZeroUsize::new(high_total / high_n + high_total % high_n)
            .expect("positive high share");
        let low_n = message::TransportAdmissionClass::LOW.len();
        let low_total = p2p_queue_cap_low.get();
        let low_share = std::num::NonZeroUsize::new(low_total / low_n).ok_or_else(|| {
            invalid_transport_geometry("low queue cap cannot fund BlockSync and other low traffic")
        })?;
        let sync_share = std::num::NonZeroUsize::new(low_total / low_n + low_total % low_n)
            .expect("positive low share");
        let (peer_message_high_sender, peer_message_high_receiver) =
            peer_message_channel::<T>(lane_share);
        let (peer_message_payload_sender, peer_message_payload_receiver) =
            peer_message_channel::<T>(share);
        let (peer_message_control_sender, peer_message_control_receiver) =
            peer_message_channel::<T>(share);
        let (peer_message_safety_sender, peer_message_safety_receiver) =
            peer_message_channel::<T>(p2p_queue_cap_high);
        let (peer_message_block_sync_sender, peer_message_block_sync_receiver) =
            peer_message_channel::<T>(sync_share);
        let (peer_message_low_sender, peer_message_low_receiver) =
            peer_message_channel::<T>(low_share);
        let (service_message_sender, service_message_receiver) =
            mpsc::channel::<ServiceMessage<WireMessage<T>>>(1);
        let listener_socket_addr =
            listen_addr
                .value()
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "network.address resolved to no authenticated listener addresses",
                    )
                })?;
        let preauth_capacity = Arc::new(Semaphore::new(max_total_connections));
        let preauth_source_gate = Arc::new(PreauthSourceGate::new(preauth_max_connections_per_ip));
        let mut listener_tasks = Vec::new();
        #[cfg(feature = "quic")]
        if quic_enabled {
            // An explicitly requested QUIC listener is part of startup, not a
            // best-effort hint. Initialization failure therefore fails closed.
            let task = start_quic_listener::<WireMessage<T>, E>(
                &listener_socket_addr,
                Arc::clone(&key_pair),
                Arc::clone(&soranet_transport_key_pair),
                Arc::clone(&soranet_transport_certificate),
                public_address.value().clone(),
                service_message_sender.clone(),
                idle_timeout,
                preauth_timeout,
                quic_max_idle_timeout,
                quic_datagrams_enabled,
                quic_datagram_max_payload_bytes,
                quic_datagram_receive_buffer_bytes,
                quic_datagram_send_buffer_bytes,
                network_id.clone(),
                consensus_caps.clone(),
                confidential_caps.clone(),
                crypto_caps.clone(),
                p2p_post_queue_cap.get(),
                outbound_frame_queue_limits,
                outbound_post_byte_budgets.clone(),
                inbound_frame_byte_budgets.clone(),
                trust_gossip_config,
                max_frame_bytes,
                soranet_runtime.clone(),
                local_scion_supported,
                relay_role,
                quic_flow_control,
                quic_max_incoming,
                Arc::clone(&preauth_source_gate),
                Arc::clone(&preauth_capacity),
                shutdown_signal.clone(),
            )
            .await?;
            listener_tasks.push(task);
        }
        let task = start_tls_listener::<WireMessage<T>, E>(
            listener_socket_addr,
            Arc::clone(&key_pair),
            Arc::clone(&soranet_transport_key_pair),
            Arc::clone(&soranet_transport_certificate),
            public_address.value().clone(),
            service_message_sender.clone(),
            idle_timeout,
            preauth_timeout,
            network_id,
            consensus_caps,
            confidential_caps.clone(),
            crypto_caps,
            p2p_post_queue_cap.get(),
            outbound_frame_queue_limits,
            outbound_post_byte_budgets.clone(),
            inbound_frame_byte_budgets.clone(),
            TlsListenerOptions {
                peer_capabilities: TlsPeerCapabilities {
                    trust_gossip: trust_gossip_config,
                    quic_datagrams_enabled,
                    quic_datagram_max_payload_bytes,
                    local_scion_supported,
                },
                tcp_nodelay,
                tcp_keepalive,
            },
            max_frame_bytes,
            soranet_runtime.clone(),
            relay_role,
            Arc::clone(&preauth_source_gate),
            Arc::clone(&preauth_capacity),
            shutdown_signal.clone(),
        )
        .await?;
        listener_tasks.push(task);
        let accept_params = AcceptThrottleParams::new(
            accept_rate_per_prefix_per_sec
                .map(core::num::NonZeroU32::get)
                .map(f64::from),
            accept_burst_per_prefix
                .map(core::num::NonZeroU32::get)
                .map(f64::from),
            accept_prefix_v4_bits,
            accept_prefix_v6_bits,
            accept_rate_per_ip_per_sec
                .map(core::num::NonZeroU32::get)
                .map(f64::from),
            accept_burst_per_ip
                .map(core::num::NonZeroU32::get)
                .map(f64::from),
            max_accept_buckets.get(),
            accept_bucket_idle,
        );
        let network = NetworkBase {
            listen_addr: listen_addr.into_value(),
            listener_tasks,
            peer_tasks: Vec::new(),
            public_address: public_address.into_value(),
            relay_role,
            relay_mode,
            relay_hub_addresses,
            relay_hub_peer: None,
            relay_hub_candidates: HashSet::new(),
            relay_trusted_peers: HashSet::new(),
            relay_ttl,
            trust_gossip_config,
            trust_gossip,
            self_id: self_id.clone(),
            address_book: HashMap::new(),
            peer_reputations: PeerReputationBook::default(),
            soranet_handshake: soranet_runtime.clone(),
            peers: HashMap::new(),
            reader_arbitration: connection_arbitration::Arbitration::default(),
            connecting_peers: HashMap::new(),
            outbound_connections: HashSet::new(),
            key_pair,
            subscribers_to_peers_messages: Vec::new(),
            unrouted_reliable_deliveries: VecDeque::new(),
            subscribe_to_peers_messages_receiver,
            online_peers_sender,
            online_peer_capabilities_sender,
            reliable_broadcast_topology: Arc::clone(&reliable_broadcast_topology),
            reliable_direct_topology: Arc::clone(&reliable_direct_topology),
            configured_peer_ids: Arc::clone(&configured_peer_ids),
            reply_route_owner: Arc::clone(&reply_route_owner),
            reply_route_tenures: HashMap::new(),
            next_reply_connection_ordinal: 0,
            next_reply_delivery_ordinal: 0,
            pending_reply_source_authority: PendingReplySourceAuthority::default(),
            pending_configured_hub_source: None,
            network_actor_progress_budget: Arc::clone(&network_actor_progress_budget),
            update_topology_receiver,
            update_peers_receiver,
            update_validator_dial_roster_receiver,
            update_peer_capabilities_receiver,
            update_trusted_peers_receiver,
            update_acl_receiver,
            update_handshake_receiver,
            network_message_high_receiver,
            network_message_safety_receiver,
            network_message_progress_receiver,
            network_message_low_receiver,
            peer_message_high_receiver,
            peer_message_payload_sender, peer_message_payload_receiver,
            peer_message_block_sync_sender, peer_message_block_sync_receiver,
            peer_message_control_sender, peer_message_control_receiver,
            peer_message_safety_receiver,
            peer_message_low_receiver,
            peer_message_high_sender,
            peer_message_safety_sender,
            peer_message_low_sender,
            service_message_receiver,
            service_message_sender,
            current_conn_id: 0,
            requested_topology: HashSet::new(),
            current_topology: HashSet::new(),
            validator_dial_scheduler,
            current_peers_addresses: Vec::new(),
            idle_timeout,
            reply_writer_flush_timeout,
            dial_timeout,
            outbound_authentication_timeout,
            connect_startup_delay_until,
            network_id,
            consensus_caps,
            confidential_caps,
            crypto_caps,
            peer_capabilities: HashMap::new(),
            post_queue_cap: p2p_post_queue_cap.get(),
            outbound_frame_queue_limits,
            outbound_post_byte_budgets,
            inbound_frame_byte_budgets: inbound_frame_byte_budgets.clone(),
            _receive_credit_pool: receive_credit_pool,
            _semantic_post_pool:Some(semantic_post_pool),
            inbound_dispatch_byte_budgets,
            authenticated_source_credit_capacity,
            max_frame_bytes,
            cap_consensus: max_frame_bytes_consensus,
            cap_control: max_frame_bytes_control,
            cap_block_sync: max_frame_bytes_block_sync,
            cap_tx_gossip: max_frame_bytes_tx_gossip,
            cap_peer_gossip: max_frame_bytes_peer_gossip,
            cap_health: max_frame_bytes_health,
            cap_connect: max_frame_bytes_connect,
            cap_other: max_frame_bytes_other,
            dns_refresh_interval,
            dns_refresh_ttl,
            dns_last_refresh: HashMap::new(),
            topology_update_interval: peer_gossip_period.max(Duration::from_millis(1)),
            dns_pending_refresh: HashSet::new(),
            quic_enabled,
            quic_datagrams_enabled,
            quic_datagram_max_payload_bytes,
            local_scion_supported,
            proxy_policy,
            outbound_dial_policy,
            proxy_tls_verify: p2p_proxy_tls_verify,
            proxy_tls_pinned_cert_der,
            quic_dialer,
            allowlist_only,
            allow_keys: allow_keys.into_iter().collect(),
            deny_keys: deny_keys.into_iter().collect(),
            allow_nets,
            deny_nets,
            retry_backoff: HashMap::new(),
            pending_connects: Vec::new(),
            deferred_send_queue: DeferredPeerFrameQueue::new_with_total(
                deferred_send_max_per_peer,
                deferred_send_max_bytes_per_peer,
                deferred_send_max_bytes_total,
                safety_reserve_bytes,
                crate::frame_queue_charge_for::<E>(0).ok_or(Error::FrameTooLarge)?,
                deferred_send_ttl,
            )
            .ok_or_else(|| {
                invalid_transport_geometry(
                    "network.deferred_send_max_bytes_total cannot represent the configured additive safety reserve",
                )
            })?,
            happy_eyeballs_stagger: config_happy_eyeballs_stagger,
            addr_ipv6_first,
            last_active: HashMap::new(),
            incoming_pending: HashSet::new(),
            incoming_active: HashSet::new(),
            terminating_connections: HashSet::new(),
            protocol_rejected_connections: HashSet::new(),
            max_incoming: max_incoming.map(core::num::NonZeroUsize::get),
            max_total_connections: Some(max_total_connections),
            accept_params,
            accept_prefix_buckets: HashMap::new(),
            accept_ip_buckets: HashMap::new(),
            sampler_high_queue_warn: LogSampler::new(),
            sampler_low_queue_warn: LogSampler::new(),
            tcp_nodelay,
            tcp_keepalive,
            low_rate_per_sec: low_priority_rate_per_sec
                .map(core::num::NonZeroU32::get)
                .map(f64::from),
            low_burst: low_priority_burst
                .map(core::num::NonZeroU32::get)
                .map(f64::from),
            low_buckets: HashMap::new(),
            low_bytes_per_sec: low_priority_bytes_per_sec
                .map(core::num::NonZeroU32::get)
                .map(f64::from),
            low_bytes_burst,
            low_bytes_buckets: HashMap::new(),
            disconnect_on_post_overflow,
            _encryptor: core::marker::PhantomData::<E>,
        };
        let child = Child::new(
            tokio::task::spawn(network.run(shutdown_signal)),
            OnShutdown::Wait(Duration::from_secs(5)),
        );
        Ok((
            Self {
                subscribe_to_peers_messages_sender,
                online_peers_receiver,
                online_peer_capabilities_receiver,
                reliable_broadcast_topology,
                reliable_direct_topology,
                configured_peer_ids,
                reply_route_owner,
                reply_route_source_capacity: max_total_connections,
                update_topology_sender,
                update_peers_sender,
                update_validator_dial_roster_sender,
                update_peer_capabilities_sender,
                update_trusted_peers_sender,
                update_acl_sender,
                update_handshake_sender,
                // Use the pre-cloned sender since the original was moved into the actor state
                network_message_high_sender,
                network_message_safety_sender,
                network_message_progress_sender,
                network_message_low_sender,
                network_message_high_deferred_permits: Arc::new(Semaphore::new(
                    p2p_queue_cap_high.get().min(NETWORK_ACTOR_DEFERRED_MAX),
                )),
                network_message_safety_deferred_permits: Arc::new(Semaphore::new(
                    p2p_queue_cap_high.get().min(NETWORK_ACTOR_DEFERRED_MAX),
                )),
                network_message_progress_deferred_permits: Arc::new(Semaphore::new(
                    p2p_queue_cap_high.get().min(NETWORK_ACTOR_DEFERRED_MAX),
                )),
                network_actor_byte_budget,
                network_actor_progress_budget,
                network_actor_low_byte_budget,
                self_id,
                relay_ttl,
                topic_frame_caps,
                subscriber_queue_cap: p2p_subscriber_queue_cap,
                _encryptor: core::marker::PhantomData,
            },
            child,
        ))
    }
    /// Subscribe to messages received from other peers in the network.
    ///
    /// Returns `Ok(())` when the bounded registration request is enqueued. If
    /// the underlying network task has already shut down, the original sender
    /// is returned so the caller may retry or decide how to handle the failure
    /// without triggering a panic.
    ///
    /// Reliable protocol routes are single-consumer. The actor keeps the first
    /// registered owner for each reliable `(topic, route)` and rejects later
    /// overlapping filters; production subscribers should therefore use
    /// disjoint topic/route filters. Best-effort routes may still fan out.
    ///
    /// # Errors
    ///
    /// Returns the supplied `sender` when the network actor has already
    /// terminated and cannot accept new subscriptions.
    ///
    /// The supplied [`SubscriberFilter`] limits which topics are delivered to
    /// the subscriber queue.
    pub fn subscribe_to_peers_messages_with_filter(
        &self,
        sender: mpsc::Sender<PeerMessage<T>>,
        filter: SubscriberFilter,
    ) -> Result<(), mpsc::Sender<PeerMessage<T>>> {
        let subscriber = Subscriber::new(sender, filter, self.subscriber_queue_cap.get());
        self.subscribe_to_peers_messages_sender
            .try_send(subscriber)
            .map_err(|err| {
                let subscriber = match err {
                    mpsc::error::TrySendError::Full(subscriber) => {
                        warn!(
                            cap = self.subscriber_queue_cap.get(),
                            "P2P subscriber registration queue is full; dropping subscription request"
                        );
                        subscriber
                    }
                    mpsc::error::TrySendError::Closed(subscriber) => {
                        warn!(
                            "P2P subscriber registration failed because the network actor has already shut down"
                        );
                        subscriber
                    }
                };
                subscriber.sender
            })
    }
    /// Subscribe to messages received from other peers using the default filter.
    ///
    /// # Errors
    ///
    /// Returns the supplied `sender` when the network actor has already
    /// terminated and cannot accept new subscriptions.
    pub fn subscribe_to_peers_messages(
        &self,
        sender: mpsc::Sender<PeerMessage<T>>,
    ) -> Result<(), mpsc::Sender<PeerMessage<T>>> {
        self.subscribe_to_peers_messages_with_filter(sender, SubscriberFilter::All)
    }
    /// Configured capacity for P2P subscriber queues.
    #[must_use]
    pub fn subscriber_queue_cap(&self) -> core::num::NonZeroUsize {
        self.subscriber_queue_cap
    }
    /// Configured encoded frame bound for an outbound P2P topic.
    ///
    /// This reports local transport capacity, not consensus admission policy.
    #[must_use]
    pub fn outbound_topic_frame_cap(&self, topic: message::Topic) -> usize {
        self.topic_frame_caps.for_topic(topic)
    }
    /// Per-lane count ownership reserved for each authenticated transport source.
    ///
    /// The network actor derives this exact share from the configured subscriber
    /// queue and authenticated-source geometry. Downstream reliable consumers
    /// must use the same value when layering source-keyed ownership so an item
    /// which still retains its upstream credit can acquire the downstream owner
    /// without waiting behind another item from the same source.
    #[must_use]
    pub fn authenticated_source_credit_capacity(&self) -> core::num::NonZeroUsize {
        let capacity = inbound_source_credit_capacity(
            self.subscriber_queue_cap.get(),
            self.reply_route_source_capacity,
        )
        .expect("validated network source-credit geometry remains non-zero");
        core::num::NonZeroUsize::new(capacity)
            .expect("validated network source-credit capacity remains non-zero")
    }
    fn outbound_actor_wire_bytes(
        &self,
        message: &NetworkMessage<T>,
        topic: message::Topic,
    ) -> Option<usize> {
        self.outbound_actor_wire_bytes_recoverable(message, topic)
            .map_err(|reason| {
                iroha_logger::warn!(
                    ?topic,
                    ?reason,
                    "Rejected an outbound P2P message at exact actor-byte admission"
                );
            })
            .ok()
    }
    fn outbound_actor_wire_bytes_recoverable(
        &self,
        message: &NetworkMessage<T>,
        topic: message::Topic,
    ) -> Result<usize, NetworkActorAdmissionRejection> {
        let plaintext_frame_bytes =
            outbound_actor_message_wire_bytes(message, &self.self_id, self.relay_ttl)
                .map_err(|_| NetworkActorAdmissionRejection::WireLength)?;
        let cap = self.topic_frame_caps.for_topic(topic);
        if plaintext_frame_bytes > cap {
            record_inbound_cap_violation(topic);
            return Err(NetworkActorAdmissionRejection::FrameTooLarge);
        }
        crate::frame_queue_charge_for::<E>(plaintext_frame_bytes)
            .ok_or(NetworkActorAdmissionRejection::StreamChargeOverflow)
    }
    fn admit_high_actor_message(
        &self,
        message: NetworkMessage<T>,
        topic: message::Topic,
        safety: bool,
    ) -> Option<AdmittedNetworkMessage<T>> {
        let wire_bytes = self.outbound_actor_wire_bytes(&message, topic)?;
        let Some(byte_lease) = self
            .network_actor_byte_budget
            .try_reserve(wire_bytes, safety)
        else {
            iroha_logger::warn!(
                ?topic,
                wire_bytes,
                safety,
                max_bytes = self.network_actor_byte_budget.max_bytes,
                safety_reserve_bytes = self.network_actor_byte_budget.safety_reserve_bytes,
                "Network actor byte budget is full"
            );
            return None;
        };
        Some(AdmittedNetworkMessage::new(message, byte_lease))
    }
    fn admit_low_actor_message(
        &self,
        message: NetworkMessage<T>,
        topic: message::Topic,
    ) -> Option<AdmittedNetworkMessage<T>> {
        let wire_bytes = self.outbound_actor_wire_bytes(&message, topic)?;
        let Some(byte_lease) = self
            .network_actor_low_byte_budget
            .try_reserve(wire_bytes, false)
        else {
            iroha_logger::warn!(
                ?topic,
                wire_bytes,
                max_bytes = self.network_actor_low_byte_budget.max_bytes,
                "Low-priority network actor byte budget is full"
            );
            return None;
        };
        Some(AdmittedNetworkMessage::new(message, byte_lease))
    }
    #[expect(
        clippy::result_large_err,
        reason = "refusal returns the original message and admission ticket; boxing would allocate while capacity is unavailable"
    )]
    fn submit_progress_message_to_source(
        &self,
        message: NetworkMessage<T>,
        topic: message::Topic,
        broadcast: bool,
        source: ActorProgressSource,
        authority: ProgressDeliveryAuthority,
        ticket: Option<NetworkActorAdmissionTicket>,
        reply_writer_timeout_attempt: Option<u8>,
        reply_flush_ack: Option<tokio::sync::oneshot::Sender<NetworkReplyFlushCompletion>>,
    ) -> Result<
        Option<NetworkActorAdmittedTicketIdentity>,
        NetworkActorAdmissionError<NetworkMessage<T>>,
    > {
        use tokio::sync::mpsc::error::TrySendError;
        let wire_bytes = match self.outbound_actor_wire_bytes_recoverable(&message, topic) {
            Ok(wire_bytes) => wire_bytes,
            Err(reason) => {
                return Err(NetworkActorAdmissionError::Rejected { message, reason });
            }
        };
        debug_assert!(source.target.is_some());
        if matches!(
            match &message {
                NetworkMessage::Post(post) => post.data.progress_reconstruction(),
                NetworkMessage::Broadcast(broadcast) => {
                    broadcast.data.progress_reconstruction()
                }
            },
            message::ProgressReconstruction::Exact
        ) {
            return Err(NetworkActorAdmissionError::Rejected {
                message,
                reason: NetworkActorAdmissionRejection::MissingReconstruction,
            });
        }
        let shape = ProgressTicketShape {
            topic,
            stream_wire_bytes: wire_bytes,
            broadcast,
            reply_writer_timeout_attempt,
            request_digest: progress_ticket_request_digest(&message),
            authority: Some(authority.identity()),
        };
        let (lease, mut ticket) = match self.network_actor_progress_budget.try_reserve_for_source(
            wire_bytes,
            shape,
            source,
            Some(&authority),
            ticket,
        ) {
            ProgressLeaseAttempt::Ready { lease, ticket } => (lease, ticket),
            ProgressLeaseAttempt::Waiting { ticket, rank } => {
                return Err(NetworkActorAdmissionError::Backpressured {
                    message,
                    ticket,
                    rank,
                });
            }
            ProgressLeaseAttempt::SameRequestAlreadyOwned
            | ProgressLeaseAttempt::CancelledMembership => return Ok(None),
            ProgressLeaseAttempt::InvalidTicket => {
                return Err(NetworkActorAdmissionError::Rejected {
                    message,
                    reason: NetworkActorAdmissionRejection::InvalidTicket,
                });
            }
            ProgressLeaseAttempt::Oversize => {
                return Err(NetworkActorAdmissionError::Rejected {
                    message,
                    reason: NetworkActorAdmissionRejection::FrameTooLarge,
                });
            }
        };
        let admitted_ticket_identity = NetworkActorAdmittedTicketIdentity::from_ready_ticket(
            &ticket,
            &authority,
            lease.admission_rank,
        );
        let (sender, deferred_permits) = if matches!(topic, message::Topic::ConsensusSafety) {
            (
                &self.network_message_safety_sender,
                &self.network_message_safety_deferred_permits,
            )
        } else {
            (
                &self.network_message_progress_sender,
                &self.network_message_progress_deferred_permits,
            )
        };
        let admitted = if broadcast {
            debug_assert!(reply_flush_ack.is_none());
            debug_assert!(reply_writer_timeout_attempt.is_none());
            AdmittedNetworkMessage::new_targeted_broadcast(message, lease, authority)
        } else {
            AdmittedNetworkMessage::new_targeted_post(
                message,
                lease,
                authority,
                reply_writer_timeout_attempt,
                reply_flush_ack,
            )
        };
        match sender.try_send(admitted) {
            Ok(()) => {
                ticket.commit();
                Ok(Some(admitted_ticket_identity))
            }
            Err(TrySendError::Closed(admitted)) => {
                let (message, lease) = admitted.into_parts();
                drop(lease);
                Err(NetworkActorAdmissionError::Closed { message })
            }
            Err(TrySendError::Full(admitted)) => {
                let admitted = match defer_high_priority_network_message(
                    sender.clone(),
                    admitted,
                    broadcast,
                    topic,
                    deferred_permits,
                ) {
                    Ok(()) => {
                        ticket.commit();
                        return Ok(Some(admitted_ticket_identity));
                    }
                    Err(admitted) => admitted,
                };
                let (message, lease) = admitted.into_parts();
                drop(lease);
                let rank = ticket.rank().unwrap_or(1);
                Err(NetworkActorAdmissionError::Backpressured {
                    message,
                    ticket: Some(ticket),
                    rank,
                })
            }
        }
    }
    /// Admit a reliable semantic-progress post without losing source ownership.
    ///
    /// Pass the ticket returned by a previous [`NetworkActorAdmissionError::Backpressured`]
    /// result when retrying the exact returned message. Fresh callers from the
    /// same source cannot overtake a live ticket. On every failure the exact original post,
    /// including its requested priority, is returned.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkActorAdmissionError::Backpressured`] with per-source rank for
    /// temporary pressure, [`NetworkActorAdmissionError::Closed`] after actor
    /// shutdown, or [`NetworkActorAdmissionError::Rejected`] for a permanent
    /// admission violation.
    #[allow(clippy::needless_pass_by_value)]
    #[expect(
        clippy::result_large_err,
        reason = "the recoverable API returns the exact original post and ticket without allocating on refusal"
    )]
    pub fn post_recoverable(
        &self,
        mut msg: Post<T>,
        mut ticket: Option<NetworkActorAdmissionTicket>,
    ) -> Result<(), NetworkActorAdmissionError<Post<T>>> {
        let requested_priority = msg.priority;
        if !msg.data.is_outbound_allowed() {
            return Err(NetworkActorAdmissionError::Rejected {
                message: msg,
                reason: NetworkActorAdmissionRejection::OutboundDisallowed,
            });
        }
        let topic = msg.data.topic();
        let route = msg.data.subscriber_route();
        if !is_reliable_progress_route(topic, route) {
            return Err(NetworkActorAdmissionError::Rejected {
                message: msg,
                reason: NetworkActorAdmissionRejection::NotReliableProgress,
            });
        }
        msg.priority = canonical_outbound_priority(topic, route, msg.priority);
        let message = NetworkMessage::Post(msg);
        let restore_requested_priority = |message| match message {
            NetworkMessage::Post(mut post) => {
                post.priority = requested_priority;
                post
            }
            NetworkMessage::Broadcast(_) => {
                unreachable!("direct admission must return the submitted post")
            }
        };
        if let Err(reason) = self.outbound_actor_wire_bytes_recoverable(&message, topic) {
            return Err(NetworkActorAdmissionError::Rejected {
                message: restore_requested_priority(message),
                reason,
            });
        }
        let actor_closed = if matches!(topic, message::Topic::ConsensusSafety) {
            self.network_message_safety_sender.is_closed()
        } else {
            self.network_message_progress_sender.is_closed()
        };
        if actor_closed {
            return Err(NetworkActorAdmissionError::Closed {
                message: restore_requested_priority(message),
            });
        }
        let peer_id = match &message {
            NetworkMessage::Post(post) => &post.peer_id,
            NetworkMessage::Broadcast(_) => {
                unreachable!("direct admission contains one post")
            }
        };
        let membership = self
            .reliable_direct_topology
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot()
            .into_iter()
            .find(|membership| &membership.peer_id == peer_id);
        if let Some(existing_ticket) = ticket.as_ref() {
            let (prior_is_cancelled, same_membership) = match existing_ticket.authority.as_ref() {
                Some(WeakProgressDeliveryAuthority::Topology(prior)) => {
                    let prior = prior.upgrade();
                    (
                        prior
                            .as_ref()
                            .is_none_or(|membership| !membership.is_active()),
                        prior.as_ref().is_some_and(|prior| {
                            membership
                                .as_ref()
                                .is_some_and(|current| Arc::ptr_eq(prior, current))
                        }),
                    )
                }
                Some(WeakProgressDeliveryAuthority::Reply { .. }) | None => (false, false),
            };
            if prior_is_cancelled {
                // Topology removal is the exact cancellation witness for the
                // old rank. Retry under a re-added tenure as a fresh request.
                drop(ticket.take());
            } else if !same_membership {
                return Err(NetworkActorAdmissionError::Rejected {
                    message: restore_requested_priority(message),
                    reason: NetworkActorAdmissionRejection::InvalidTicket,
                });
            }
        }
        let Some(membership) = membership else {
            drop(ticket);
            return Err(NetworkActorAdmissionError::Backpressured {
                message: restore_requested_priority(message),
                ticket: None,
                rank: 1,
            });
        };
        let source = ActorProgressSource::for_message(&message)
            .expect("a reliable post must have one exact target/class source");
        self.submit_progress_message_to_source(
            message,
            topic,
            false,
            source,
            ProgressDeliveryAuthority::Topology(membership),
            ticket,
            None,
            None,
        )
        .map(|_| ())
        .map_err(|error| error.map_message(restore_requested_priority))
    }
    /// Admit a reliable reply over the exact authenticated route which
    /// delivered its request.
    ///
    /// Relayed requests address replies to their semantic origin while actor
    /// accounting and writer ownership remain keyed by the authenticated hub
    /// connection. A draining connection stops accepting replies immediately,
    /// while its already-dispatched inbound deliveries retain capability
    /// authority until their final local receivers release them. The requester's
    /// durable source retains its exact retry state throughout.
    ///
    /// # Errors
    ///
    /// Returns the same recoverable admission errors as [`Self::post_recoverable`].
    /// A route from another actor, a retargeted post, or a live ticket from a
    /// different route is rejected as an invalid ticket.
    ///
    /// [`NetworkReplyAdmissionOutcome::ReplyWriterUnavailable`] is not an
    /// error, but also is not admission: callers must rely on requester
    /// retransmission or rebuild the exact reply for a newer same-source route.
    #[allow(clippy::needless_pass_by_value)]
    #[expect(
        clippy::result_large_err,
        reason = "the recoverable API returns the exact original post and ticket without allocating on refusal"
    )]
    pub fn post_reply_recoverable(
        &self,
        msg: Post<T>,
        reply_route: &NetworkReplyRoute,
        ticket: Option<NetworkActorAdmissionTicket>,
    ) -> Result<NetworkReplyAdmissionOutcome, NetworkActorAdmissionError<Post<T>>> {
        self.post_reply_recoverable_with_flush_ack(msg, reply_route, ticket)
            .map(|flush_ack| {
                flush_ack.map_or(
                    NetworkReplyAdmissionOutcome::ReplyWriterUnavailable,
                    |_flush_ack| NetworkReplyAdmissionOutcome::Admitted,
                )
            })
    }
    /// Admit a reliable reply and return its process-local writer-flush completion.
    ///
    /// `Some` is returned only when this call admits a new actor-owned item.
    /// Its immutable [`NetworkReplyFlushIdentity`] binds the exact route
    /// tenure, delivery occurrence, admission ticket, and canonical request;
    /// the identity remains unchanged as completion advances.
    /// Actor admission alone leaves the handle pending. It becomes
    /// [`NetworkReplyFlushAckStatus::Flushed`] only after the network actor
    /// observes the peer writer's complete write and flush. An actor-owned
    /// deadline publishes [`NetworkReplyFlushAckStatus::TimedOut`] after
    /// retiring that exact writer tenure; unrelated writer shutdown, route
    /// retirement, or retained-item drop otherwise closes it, but a ready
    /// writer flush wins their terminal fence. `None` means
    /// no actor ownership transferred: the tenure either retired after the
    /// public delivery-authority precheck or entered its delivery-active but
    /// reply-unwritable drain phase. Callers must retain the exact current item
    /// for a newer same-source route and must not treat `None` as a delivery
    /// receipt or as proof that local delivery authority has retired.
    ///
    /// # Errors
    ///
    /// Returns the same recoverable admission errors as
    /// [`Self::post_reply_recoverable`].
    #[allow(clippy::needless_pass_by_value)]
    #[expect(
        clippy::result_large_err,
        reason = "the recoverable API returns the exact original post and ticket without allocating on refusal"
    )]
    pub fn post_reply_recoverable_with_flush_ack(
        &self,
        msg: Post<T>,
        reply_route: &NetworkReplyRoute,
        ticket: Option<NetworkActorAdmissionTicket>,
    ) -> Result<Option<NetworkReplyFlushAck>, NetworkActorAdmissionError<Post<T>>> {
        self.post_reply_recoverable_with_flush_ack_at_attempt(msg, reply_route, ticket, 0)
    }
    /// Admit a reliable reply using the caller's bounded adaptive timeout generation.
    ///
    /// The timeout generation is part of actor-ticket identity and therefore
    /// cannot be changed while retrying a backpressured admission ticket.
    ///
    /// # Errors
    ///
    /// Returns the same recoverable admission errors as
    /// [`Self::post_reply_recoverable`].
    #[allow(clippy::needless_pass_by_value)]
    #[expect(
        clippy::result_large_err,
        reason = "the recoverable API returns the exact original post and ticket without allocating on refusal"
    )]
    pub fn post_reply_recoverable_with_flush_ack_at_attempt(
        &self,
        msg: Post<T>,
        reply_route: &NetworkReplyRoute,
        ticket: Option<NetworkActorAdmissionTicket>,
        reply_writer_timeout_attempt: u8,
    ) -> Result<Option<NetworkReplyFlushAck>, NetworkActorAdmissionError<Post<T>>> {
        self.post_reply_recoverable_with_flush_ack_inner(
            msg,
            reply_route,
            ticket,
            reply_writer_timeout_attempt,
            || {},
        )
    }
    #[allow(clippy::needless_pass_by_value)]
    #[expect(
        clippy::result_large_err,
        reason = "the recoverable API returns the exact original post and ticket without allocating on refusal"
    )]
    fn post_reply_recoverable_with_flush_ack_inner(
        &self,
        mut msg: Post<T>,
        reply_route: &NetworkReplyRoute,
        mut ticket: Option<NetworkActorAdmissionTicket>,
        reply_writer_timeout_attempt: u8,
        after_route_preflight: impl FnOnce(),
    ) -> Result<Option<NetworkReplyFlushAck>, NetworkActorAdmissionError<Post<T>>> {
        let (reply_flush_sender, reply_flush_receiver) = tokio::sync::oneshot::channel();
        let requested_priority = msg.priority;
        if !msg.data.is_outbound_allowed() {
            return Err(NetworkActorAdmissionError::Rejected {
                message: msg,
                reason: NetworkActorAdmissionRejection::OutboundDisallowed,
            });
        }
        let topic = msg.data.topic();
        let route = msg.data.subscriber_route();
        if !is_reliable_progress_route(topic, route) {
            return Err(NetworkActorAdmissionError::Rejected {
                message: msg,
                reason: NetworkActorAdmissionRejection::NotReliableProgress,
            });
        }
        if msg.peer_id != *reply_route.semantic_target()
            || !Arc::ptr_eq(&reply_route.tenure.owner, &self.reply_route_owner)
            || reply_route.validate_delivery_binding().is_err()
        {
            return Err(NetworkActorAdmissionError::Rejected {
                message: msg,
                reason: NetworkActorAdmissionRejection::InvalidTicket,
            });
        }
        let actor_closed = if matches!(topic, message::Topic::ConsensusSafety) {
            self.network_message_safety_sender.is_closed()
        } else {
            self.network_message_progress_sender.is_closed()
        };
        if actor_closed {
            return Err(NetworkActorAdmissionError::Closed { message: msg });
        }
        if let Some(existing_ticket) = ticket.as_ref() {
            let (prior_is_cancelled, same_route) = match existing_ticket.authority.as_ref() {
                Some(WeakProgressDeliveryAuthority::Reply {
                    semantic_target,
                    tenure,
                }) => {
                    let tenure = tenure.upgrade();
                    (
                        tenure
                            .as_ref()
                            .is_none_or(|tenure| !tenure.is_reply_writable()),
                        semantic_target == reply_route.semantic_target()
                            && tenure
                                .as_ref()
                                .is_some_and(|prior| Arc::ptr_eq(prior, &reply_route.tenure)),
                    )
                }
                Some(WeakProgressDeliveryAuthority::Topology(_)) | None => (false, false),
            };
            if !same_route {
                return Err(NetworkActorAdmissionError::Rejected {
                    message: msg,
                    reason: NetworkActorAdmissionRejection::InvalidTicket,
                });
            }
            if prior_is_cancelled {
                drop(ticket.take());
            }
        }
        if !reply_route.is_active() {
            drop(ticket);
            return Err(NetworkActorAdmissionError::Rejected {
                message: msg,
                reason: NetworkActorAdmissionRejection::InactiveReplyRoute,
            });
        }
        if !reply_route.is_reply_writable() {
            // The delivery remains authenticated while its peer receiver
            // drains, but this exact writer tenure can no longer accept reply
            // ownership. Returning `None` leaves the immutable payload and
            // cursor with the caller for a same-source reconnect.
            drop(ticket);
            return Ok(None);
        }
        after_route_preflight();
        msg.priority = canonical_outbound_priority(topic, route, msg.priority);
        let class = ActorProgressClass::for_payload(&msg.data)
            .expect("a reliable typed progress message must have one actor class");
        let message = NetworkMessage::Post(msg);
        let source = ActorProgressSource {
            target: Some(reply_route.tenure.delivery_peer.clone()),
            class,
        };
        self.submit_progress_message_to_source(
            message,
            topic,
            false,
            source,
            ProgressDeliveryAuthority::Reply(reply_route.clone()),
            ticket,
            Some(reply_writer_timeout_attempt),
            Some(reply_flush_sender),
        )
        .map(|admitted_ticket| {
            admitted_ticket.map(|ticket| {
                let identity = NetworkReplyFlushIdentity::from_admitted_ticket(ticket)
                    .expect("validated reply admission must retain its exact reply shape");
                NetworkReplyFlushAck::new(identity, reply_flush_receiver)
            })
        })
        .map_err(|error| {
            error.map_message(|message| match message {
                NetworkMessage::Post(mut post) => {
                    post.priority = requested_priority;
                    post
                }
                NetworkMessage::Broadcast(_) => {
                    unreachable!("reply admission must return the submitted post")
                }
            })
        })
    }
    /// Admit a reliable semantic-progress broadcast as independent target copies.
    ///
    /// Responsive targets cross admission even when another target/class lane
    /// is occupied. The returned aggregate ticket owns only the exact target
    /// copies which did not cross. Retry it with the same canonical broadcast.
    /// A byte-identical retry may coalesce with an owner for the same target and
    /// topology membership; a distinct digest or a remove/re-add generation
    /// never does.
    ///
    /// # Errors
    ///
    /// Returns the original broadcast and all unadmitted target ownership in
    /// every error variant.
    #[allow(clippy::needless_pass_by_value)]
    pub fn broadcast_recoverable(
        &self,
        mut msg: Broadcast<T>,
        mut ticket: Option<NetworkBroadcastAdmissionTicket>,
    ) -> Result<(), NetworkBroadcastAdmissionError<Broadcast<T>>> {
        let requested_priority = msg.priority;
        if !msg.data.is_outbound_allowed() {
            return Err(NetworkBroadcastAdmissionError::Rejected {
                message: msg,
                ticket,
                reason: NetworkActorAdmissionRejection::OutboundDisallowed,
            });
        }
        let topic = msg.data.topic();
        let route = msg.data.subscriber_route();
        if !is_reliable_progress_route(topic, route) {
            return Err(NetworkBroadcastAdmissionError::Rejected {
                message: msg,
                ticket,
                reason: NetworkActorAdmissionRejection::NotReliableProgress,
            });
        }
        if matches!(
            msg.data.progress_reconstruction(),
            message::ProgressReconstruction::Exact
        ) {
            return Err(NetworkBroadcastAdmissionError::Rejected {
                message: msg,
                ticket,
                reason: NetworkActorAdmissionRejection::MissingReconstruction,
            });
        }
        msg.priority = canonical_outbound_priority(topic, route, msg.priority);
        let canonical = NetworkMessage::Broadcast(msg.clone());
        if let Err(reason) = self.outbound_actor_wire_bytes_recoverable(&canonical, topic) {
            msg.priority = requested_priority;
            return Err(NetworkBroadcastAdmissionError::Rejected {
                message: msg,
                ticket,
                reason,
            });
        }
        let request_digest = progress_ticket_request_digest(&canonical);
        let mut ticket = match ticket.take() {
            Some(ticket)
                if ticket.request_digest == request_digest
                    && Arc::ptr_eq(&ticket.budget, &self.network_actor_progress_budget)
                    && Arc::ptr_eq(&ticket.topology, &self.reliable_broadcast_topology) =>
            {
                ticket
            }
            Some(ticket) => {
                msg.priority = requested_priority;
                return Err(NetworkBroadcastAdmissionError::Rejected {
                    message: msg,
                    ticket: Some(ticket),
                    reason: NetworkActorAdmissionRejection::InvalidTicket,
                });
            }
            None => NetworkBroadcastAdmissionTicket::fresh(
                request_digest,
                Arc::clone(&self.network_actor_progress_budget),
                Arc::clone(&self.reliable_broadcast_topology),
            ),
        };
        if ticket.needs_topology_snapshot {
            let targets = self
                .reliable_broadcast_topology
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .snapshot();
            if !targets.is_empty() {
                ticket.targets.extend(targets.into_iter().map(|membership| {
                    NetworkBroadcastTargetTicket {
                        membership,
                        actor_ticket: None,
                    }
                }));
                ticket.needs_topology_snapshot = false;
            }
        }
        let actor_closed = if matches!(topic, message::Topic::ConsensusSafety) {
            self.network_message_safety_sender.is_closed()
        } else {
            self.network_message_progress_sender.is_closed()
        };
        if actor_closed {
            msg.priority = requested_priority;
            return Err(NetworkBroadcastAdmissionError::Closed {
                message: msg,
                ticket,
            });
        }
        if ticket.needs_topology_snapshot {
            msg.priority = requested_priority;
            return Err(NetworkBroadcastAdmissionError::Backpressured {
                message: msg,
                ticket,
                rank: 1,
            });
        }
        let class = ActorProgressClass::for_payload(&msg.data)
            .expect("a reliable typed progress message must have one actor class");
        let attempts = ticket.targets.len();
        let mut minimum_rank = usize::MAX;
        for _ in 0..attempts {
            let Some(mut target) = ticket.targets.pop_front() else {
                break;
            };
            if !target.membership.is_active() {
                // Dropping a target ticket cancels only this removed topology
                // membership's actor-waiter rank.
                continue;
            }
            let source = ActorProgressSource {
                target: Some(target.membership.peer_id.clone()),
                class,
            };
            let target_message = NetworkMessage::Broadcast(msg.clone());
            match self.submit_progress_message_to_source(
                target_message,
                topic,
                true,
                source,
                ProgressDeliveryAuthority::Topology(Arc::clone(&target.membership)),
                target.actor_ticket.take(),
                None,
                None,
            ) {
                Ok(_new_owner) => {}
                Err(NetworkActorAdmissionError::Backpressured {
                    message: _,
                    ticket: actor_ticket,
                    rank,
                }) => {
                    target.actor_ticket = actor_ticket;
                    minimum_rank = minimum_rank.min(rank.max(1));
                    ticket.targets.push_back(target);
                }
                Err(NetworkActorAdmissionError::Closed { message: _ }) => {
                    target.actor_ticket = None;
                    ticket.targets.push_front(target);
                    msg.priority = requested_priority;
                    return Err(NetworkBroadcastAdmissionError::Closed {
                        message: msg,
                        ticket,
                    });
                }
                Err(NetworkActorAdmissionError::Rejected { message: _, reason }) => {
                    target.actor_ticket = None;
                    ticket.targets.push_front(target);
                    msg.priority = requested_priority;
                    return Err(NetworkBroadcastAdmissionError::Rejected {
                        message: msg,
                        ticket: Some(ticket),
                        reason,
                    });
                }
            }
        }
        if ticket.targets.is_empty() {
            Ok(())
        } else {
            msg.priority = requested_priority;
            Err(NetworkBroadcastAdmissionError::Backpressured {
                message: msg,
                ticket,
                rank: if minimum_rank == usize::MAX {
                    1
                } else {
                    minimum_rank
                },
            })
        }
    }
    /// Send a best-effort [`Post<T>`] message on the network actor.
    ///
    /// Reliable routes must use [`Self::post_recoverable`], because a void API
    /// cannot return the exact source item when bounded admission applies.
    /// Calling this developer convenience boundary with a reliable route is a
    /// programming error and panics before ownership is transferred.
    #[track_caller]
    #[allow(clippy::needless_pass_by_value)]
    pub fn post(&self, msg: Post<T>) {
        use tokio::sync::mpsc::error::TrySendError;
        let topic = msg.data.topic();
        let route = msg.data.subscriber_route();
        let priority = canonical_outbound_priority(topic, route, msg.priority);
        assert!(
            !is_reliable_progress_route(topic, route),
            "reliable P2P route {topic:?} requires post_recoverable so backpressure preserves source ownership"
        );
        if !msg.data.is_outbound_allowed() {
            iroha_logger::warn!(
                topic = ?msg.data.topic(),
                "Rejected an outbound message at the P2P admission boundary"
            );
            return;
        }
        let message = NetworkMessage::Post(msg);
        if matches!(priority, Priority::Low) {
            let Some(message) = self.admit_low_actor_message(message, topic) else {
                record_network_actor_queue_drop(priority, false);
                return;
            };
            if let Err(e) = self.network_message_low_sender.try_send(message) {
                match e {
                    TrySendError::Full(_) => {
                        iroha_logger::warn!(
                            ?priority,
                            ?topic,
                            "Network message queue is full, dropping post"
                        );
                        record_network_actor_queue_drop(priority, false);
                    }
                    TrySendError::Closed(_) => {
                        iroha_logger::debug!("Network actor is closed, dropping post");
                    }
                }
            }
            return;
        }
        let Some(message) = self.admit_high_actor_message(message, topic, false) else {
            record_network_actor_queue_drop(priority, false);
            return;
        };
        let sender = &self.network_message_high_sender;
        if let Err(e) = sender.try_send(message) {
            match e {
                TrySendError::Full(message) => {
                    if defer_high_priority_network_message(
                        sender.clone(),
                        message,
                        false,
                        topic,
                        &self.network_message_high_deferred_permits,
                    )
                    .is_ok()
                    {
                        return;
                    }
                    iroha_logger::warn!(
                        ?priority,
                        ?topic,
                        "Network message queue is full, dropping post"
                    );
                    record_network_actor_queue_drop(priority, false);
                }
                TrySendError::Closed(_) => {
                    iroha_logger::debug!("Network actor is closed, dropping post");
                }
            }
        }
    }
    /// Send a best-effort [`Broadcast<T>`] message on the network actor.
    ///
    /// Reliable routes must use [`Self::broadcast_recoverable`]. This method
    /// panics at the developer boundary before accepting a reliable payload.
    #[track_caller]
    #[allow(clippy::needless_pass_by_value)]
    pub fn broadcast(&self, msg: Broadcast<T>) {
        use tokio::sync::mpsc::error::TrySendError;
        let topic = msg.data.topic();
        let route = msg.data.subscriber_route();
        let priority = canonical_outbound_priority(topic, route, msg.priority);
        assert!(
            !is_reliable_progress_route(topic, route),
            "reliable P2P route {topic:?} requires broadcast_recoverable so backpressure preserves source ownership"
        );
        if !msg.data.is_outbound_allowed() {
            iroha_logger::warn!(
                topic = ?msg.data.topic(),
                "Rejected an outbound broadcast at the P2P admission boundary"
            );
            return;
        }
        let message = NetworkMessage::Broadcast(msg);
        if matches!(priority, Priority::Low) {
            let Some(message) = self.admit_low_actor_message(message, topic) else {
                record_network_actor_queue_drop(priority, true);
                return;
            };
            if let Err(e) = self.network_message_low_sender.try_send(message) {
                match e {
                    TrySendError::Full(_) => {
                        iroha_logger::warn!(
                            ?priority,
                            ?topic,
                            "Network message queue is full, dropping broadcast"
                        );
                        record_network_actor_queue_drop(priority, true);
                    }
                    TrySendError::Closed(_) => {
                        iroha_logger::debug!("Network actor is closed, dropping broadcast");
                    }
                }
            }
            return;
        }
        let Some(message) = self.admit_high_actor_message(message, topic, false) else {
            record_network_actor_queue_drop(priority, true);
            return;
        };
        let sender = &self.network_message_high_sender;
        if let Err(e) = sender.try_send(message) {
            match e {
                TrySendError::Full(message) => {
                    if defer_high_priority_network_message(
                        sender.clone(),
                        message,
                        true,
                        topic,
                        &self.network_message_high_deferred_permits,
                    )
                    .is_ok()
                    {
                        return;
                    }
                    iroha_logger::warn!(
                        ?priority,
                        ?topic,
                        "Network message queue is full, dropping broadcast"
                    );
                    record_network_actor_queue_drop(priority, true);
                }
                TrySendError::Closed(_) => {
                    iroha_logger::debug!("Network actor is closed, dropping broadcast");
                }
            }
        }
    }
    /// Send [`UpdateTopology`] message on network actor.
    ///
    /// The update is asynchronous. If the resulting relay-aware topology would
    /// exceed the configured reliable-target geometry, the actor logs the
    /// rejection and keeps its previous topology and relay-hub selection.
    pub fn update_topology(&self, topology: UpdateTopology) {
        send_control_update(&self.update_topology_sender, "topology", topology);
    }
    /// Send [`UpdatePeers`] message on network actor.
    pub fn update_peers_addresses(&self, peers: UpdatePeers) {
        send_control_update(&self.update_peers_sender, "peers", peers);
    }
    /// Replace the configured-validator subset governed by deterministic
    /// pairwise dial ownership.
    ///
    /// Relay hubs, observers, dynamically discovered peers, and ordinary P2P
    /// test callers remain on the existing eager dial policy unless explicitly
    /// included in this authenticated local roster.
    pub fn update_validator_dial_roster(&self, roster: message::UpdateValidatorDialRoster) {
        send_control_update(
            &self.update_validator_dial_roster_sender,
            "validator dial roster",
            ValidatorDialControlUpdate::Roster(roster),
        );
    }
    /// Atomically replace the consensus topology and the configured-validator
    /// subset governed by deterministic pairwise dial ownership.
    ///
    /// Publishing the two snapshots as one retained actor update prevents a
    /// newly admitted validator from briefly entering the eager dynamic-peer
    /// dial path before its ownership role is installed.
    pub fn update_validator_topology(&self, update: message::UpdateValidatorTopology) {
        send_control_update(
            &self.update_validator_dial_roster_sender,
            "validator topology",
            ValidatorDialControlUpdate::Topology(update),
        );
    }
    /// Send [`UpdatePeerCapabilities`] message on network actor.
    pub fn update_peer_capabilities(&self, capabilities: message::UpdatePeerCapabilities) {
        send_control_update(
            &self.update_peer_capabilities_sender,
            "peer capability",
            capabilities,
        );
    }
    /// Update trusted peer list for reputation tracking.
    pub fn update_trusted_peers(&self, trusted: UpdateTrustedPeers) {
        send_control_update(&self.update_trusted_peers_sender, "trusted peers", trusted);
    }
    /// Update ACL configuration at runtime.
    pub fn update_acl(&self, acl: message::UpdateAcl) {
        send_control_update(&self.update_acl_sender, "ACL", acl);
    }
    /// Update `SoraNet` handshake configuration at runtime.
    ///
    /// # Errors
    /// Returns an error if the network actor is unavailable or rejects the
    /// proposed runtime configuration.
    pub async fn update_soranet_handshake(
        &self,
        handshake: ActualSoranetHandshake,
    ) -> Result<(), Error> {
        let (respond_to, response) = oneshot::channel();
        self.update_handshake_sender
            .send(message::UpdateHandshake {
                handshake,
                respond_to,
            })
            .await
            .map_err(|_| {
                Error::HandshakeSoranet(
                    "network actor closed before accepting SoraNet handshake update".to_owned(),
                )
            })?;
        response.await.map_err(|_| {
            Error::HandshakeSoranet(
                "network actor closed before acknowledging SoraNet handshake update".to_owned(),
            )
        })?
    }
    /// Receive latest update of [`OnlinePeers`]
    pub fn online_peers<P>(&self, f: impl FnOnce(&OnlinePeers) -> P) -> P {
        f(&self.online_peers_receiver.borrow())
    }
    /// Receive latest update of online peer transport capabilities.
    pub fn online_peer_capabilities<P>(
        &self,
        f: impl FnOnce(&message::OnlinePeerCapabilities) -> P,
    ) -> P {
        f(&self.online_peer_capabilities_receiver.borrow())
    }
    /// Return the current configured-peer generation and cardinality.
    ///
    /// The generation changes whenever the fail-closed effective sampling set
    /// changes. Consumers can invalidate in-flight work and retained samples
    /// without cloning the complete topology.
    pub fn configured_peer_generation_and_count(&self) -> (u64, usize) {
        let state = self
            .configured_peer_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.generation, state.peer_ids.len())
    }

    /// Run `f` while the configured-peer generation is held stable.
    ///
    /// This provides a linearization point for consumers that must invalidate
    /// generation-bound state and use it in one operation. The closure should
    /// remain short and must not call back into configured-peer snapshot APIs.
    pub fn with_configured_peer_generation_and_count<R>(
        &self,
        f: impl FnOnce(u64, usize) -> R,
    ) -> R {
        let state = self
            .configured_peer_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(state.generation, state.peer_ids.len())
    }

    /// Return a bounded rotating batch of configured semantic peer ids.
    ///
    /// Unlike [`Self::online_peers`], this relay-aware snapshot retains logical
    /// targets reachable through a hub in Spoke deployments. The actor publishes
    /// it only after topology and key-ACL admission; authenticated peers outside the
    /// configured topology are deliberately excluded.
    /// Results begin at `start_index`, wrap once, and clone no more than
    /// `limit` identifiers. A complete-cycle batch advances by one position so
    /// bounded low-priority admission cannot permanently favor the canonical
    /// prefix when the peer count is less than or equal to the round cap.
    pub fn configured_peer_ids_bounded(
        &self,
        start_index: usize,
        limit: usize,
    ) -> ConfiguredPeerBatch {
        let state = self
            .configured_peer_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let total_peer_count = state.peer_ids.len();
        if limit == 0 || total_peer_count == 0 {
            return ConfiguredPeerBatch {
                generation: state.generation,
                total_peer_count,
                peer_ids: Vec::new(),
                next_start_index: 0,
            };
        }
        let start = start_index % total_peer_count;
        let take = limit.min(total_peer_count);
        let peer_ids = state.peer_ids[start..]
            .iter()
            .chain(state.peer_ids[..start].iter())
            .take(take)
            .cloned()
            .collect();
        let advance = if take == total_peer_count { 1 } else { take };
        ConfiguredPeerBatch {
            generation: state.generation,
            total_peer_count,
            peer_ids,
            next_start_index: (start + advance) % total_peer_count,
        }
    }
    /// Get a receiver of [`OnlinePeers`]
    pub fn online_peers_receiver(&self) -> watch::Receiver<OnlinePeers> {
        self.online_peers_receiver.clone()
    }
    /// Wait for update of [`OnlinePeers`].
    ///
    /// # Errors
    /// Returns an error if the network actor has shut down and the watch channel is closed.
    pub async fn wait_online_peers_update<P>(
        &mut self,
        f: impl FnOnce(&OnlinePeers) -> P + Send,
    ) -> Result<P, watch::error::RecvError> {
        self.online_peers_receiver.changed().await?;
        Ok(self.online_peers(f))
    }
}
fn send_control_update<T>(sender: &ControlUpdateSender<T>, label: &'static str, update: T) {
    if sender.send(Some(Arc::new(update))).is_err() {
        debug!(
            label = label,
            "Network actor is closed, dropping P2P control update"
        );
    }
}
async fn receive_control_update<T: Clone + Send + Sync>(
    receiver: &mut ControlUpdateReceiver<T>,
) -> Option<T> {
    receiver.changed().await.ok()?;
    let update = {
        let current = receiver.borrow_and_update();
        current.as_ref().cloned()?
    };
    Some(Arc::unwrap_or_clone(update))
}
#[cfg(test)]
fn test_network_actor_progress_budget() -> Arc<NetworkActorProgressBudget> {
    NetworkActorProgressBudget::new(usize::MAX / 8, 8, 8)
        .expect("bounded multi-source test progress budget must fit")
}
#[cfg(test)]
include!("network/handle_update_tests.rs");
#[cfg(test)]
mod accept_stream_tests {
    use super::*;
    use crate::peer::test_support::{SpawnPath, snapshot};
    use iroha_config::parameters::actual::{
        LaneProfile, Network as NetCfg, RelayMode, SoranetPrivacy as ActualSoranetPrivacy,
    };
    use iroha_crypto::{KeyPair, encryption::ChaCha20Poly1305};
    use iroha_data_model::peer::Peer;
    use iroha_model_base::peer::PeerId;
    use iroha_primitives::addr::socket_addr;
    use norito::codec::{Decode, DecodeAll, Encode};
    use std::time::Duration;
    #[test]
    fn captured_original_test_payload_identities() {
        crate::frame_identity_tests::test_payload_identity::<Dummy>(
            "iroha_p2p::network::accept_stream_tests::Dummy",
        );
        crate::frame_identity_tests::test_payload_identity::<DummyConsensus>(
            "iroha_p2p::network::accept_stream_tests::DummyConsensus",
        );
        crate::frame_identity_tests::test_payload_identity::<DummyConsensusPayload>(
            "iroha_p2p::network::accept_stream_tests::DummyConsensusPayload",
        );
        crate::frame_identity_tests::test_payload_identity::<DummyConsensusChunk>(
            "iroha_p2p::network::accept_stream_tests::DummyConsensusChunk",
        );
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_p2p::network::accept_stream_tests::Dummy")]
    #[derive(Clone, Debug, Decode, Encode)]
    struct Dummy;
    fn test_node_key_pair() -> KeyPair {
        KeyPair::try_from_seed(vec![0x71; 32], Algorithm::BlsNormal)
            .expect("test BLS-normal node key")
    }
    fn test_transport_key_pair() -> KeyPair {
        KeyPair::try_from_seed(vec![0x72; 32], Algorithm::Ed25519)
            .expect("test Ed25519 transport key")
    }
    fn test_relay_authentication_key_pair() -> KeyPair {
        KeyPair::try_from_seed(vec![0x73; 32], Algorithm::MlDsa)
            .expect("test ML-DSA-65 relay-authentication key")
    }
    fn test_p2p_identity_keys(node: KeyPair) -> P2pIdentityKeys {
        P2pIdentityKeys::new(node, test_transport_key_pair()).expect("test P2P identity roles")
    }
    impl crate::network::message::ClassifyTopic for Dummy {
        fn inbound_topic(
            payload: &[u8],
            flags: u8,
        ) -> Result<Option<message::Topic>, norito::core::Error> {
            // Unit fixture decode is fixed and performs no dynamic allocation.
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let (value, used) = norito::core::decode_field_canonical::<Self>(payload)?;
            if used != payload.len() {
                return Err(norito::core::Error::LengthMismatch);
            }
            Ok(Some(value.topic()))
        }
    }
    type TestNetworkHandle = super::NetworkBaseHandle<Dummy, ChaCha20Poly1305>;
    async fn start_test_network(
        key_pair: KeyPair,
        cfg: NetCfg,
        shutdown: iroha_futures::supervisor::ShutdownSignal,
    ) -> Result<(TestNetworkHandle, Child), Error> {
        TestNetworkHandle::start(
            test_p2p_identity_keys(key_pair),
            cfg,
            test_network_id("test-chain"),
            None,
            None,
            shutdown,
        )
        .await
    }
    async fn assert_start_invalid_input(key_pair: KeyPair, cfg: NetCfg) {
        let started = start_test_network(
            key_pair,
            cfg,
            iroha_futures::supervisor::ShutdownSignal::new(),
        )
        .await;
        assert!(matches!(
            started,
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput
        ));
    }
    macro_rules! impl_decode_from_slice_via_codec {
        ($($ty:ty),+ $(,)?) => {
            $(
                impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
                    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                        let mut slice = bytes;
                        let value = <Self as DecodeAll>::decode_all(&mut slice).map_err(|error| {
                            norito::core::Error::Message(format!("codec decode error: {error}"))
                        })?;
                        Ok((value, bytes.len() - slice.len()))
                    }
                }
            )+
        };
    }
    impl_decode_from_slice_via_codec!(Dummy);
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_p2p::network::accept_stream_tests::DummyConsensus")]
    #[derive(Clone, Debug, Decode, Encode)]
    struct DummyConsensus;
    impl message::ClassifyTopic for DummyConsensus {
        fn topic(&self) -> message::Topic {
            message::Topic::Consensus
        }
        fn progress_reconstruction(&self) -> message::ProgressReconstruction {
            message::ProgressReconstruction::Retransmit
        }
    }
    impl_decode_from_slice_via_codec!(DummyConsensus);
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_p2p::network::accept_stream_tests::DummyConsensusPayload")]
    #[derive(Clone, Debug, Decode, Encode)]
    struct DummyConsensusPayload;
    impl message::ClassifyTopic for DummyConsensusPayload {
        fn topic(&self) -> message::Topic {
            message::Topic::ConsensusPayload
        }
        fn progress_reconstruction(&self) -> message::ProgressReconstruction {
            message::ProgressReconstruction::Retransmit
        }
    }
    impl_decode_from_slice_via_codec!(DummyConsensusPayload);
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_p2p::network::accept_stream_tests::DummyConsensusChunk")]
    #[derive(Clone, Debug, Decode, Encode)]
    struct DummyConsensusChunk;
    impl message::ClassifyTopic for DummyConsensusChunk {
        fn topic(&self) -> message::Topic {
            message::Topic::ConsensusChunk
        }
        fn progress_reconstruction(&self) -> message::ProgressReconstruction {
            message::ProgressReconstruction::Retransmit
        }
    }
    impl_decode_from_slice_via_codec!(DummyConsensusChunk);
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
    #[derive(Debug)]
    struct AcceptAllVerifier;
    impl ServerCertVerifier for AcceptAllVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }
    fn base_cfg() -> NetCfg {
        let soranet_handshake = test_soranet_handshake_config();
        NetCfg {
            address: iroha_config_base::WithOrigin::inline(socket_addr!(127.0.0.1:0)),
            public_address: iroha_config_base::WithOrigin::inline(socket_addr!(127.0.0.1:0)),
            relay_mode: RelayMode::Disabled,
            relay_hub_addresses: Vec::new(),
            relay_ttl: iroha_config::parameters::defaults::network::RELAY_TTL,
            soranet_handshake,
            soranet_privacy: ActualSoranetPrivacy::default(),
            soranet_vpn: iroha_config::parameters::actual::SoranetVpn::default(),
            lane_profile: LaneProfile::Core,
            require_sm_handshake_match: true,
            require_sm_openssl_preview_match: true,
            idle_timeout: std::time::Duration::from_millis(200),
            preauth_timeout: iroha_config::parameters::defaults::network::PREAUTH_TIMEOUT,
            reply_writer_flush_timeout:
                iroha_config::parameters::defaults::network::REPLY_WRITER_FLUSH_TIMEOUT,
            connect_startup_delay: iroha_config::parameters::defaults::network::CONNECT_STARTUP_DELAY,
            dial_timeout: iroha_config::parameters::defaults::network::DIAL_TIMEOUT,
            deferred_send_ttl: std::time::Duration::from_millis(
                iroha_config::parameters::defaults::network::DEFERRED_SEND_TTL_MS,
            ),
            deferred_send_max_per_peer:
                iroha_config::parameters::defaults::network::DEFERRED_SEND_MAX_PER_PEER,
            deferred_send_max_bytes_per_peer:
                iroha_config::parameters::defaults::network::DEFERRED_SEND_MAX_BYTES_PER_PEER,
            deferred_send_max_bytes_total: iroha_config::parameters::defaults::network::DEFERRED_SEND_MAX_BYTES_TOTAL,
            peer_gossip_period: iroha_config::parameters::defaults::network::PEER_GOSSIP_PERIOD,
            peer_gossip_max_period: iroha_config::parameters::defaults::network::PEER_GOSSIP_PERIOD,
            trust_decay_half_life:
                iroha_config::parameters::defaults::network::TRUST_DECAY_HALF_LIFE,
            trust_penalty_bad_gossip:
                iroha_config::parameters::defaults::network::TRUST_PENALTY_BAD_GOSSIP,
            trust_penalty_unknown_peer:
                iroha_config::parameters::defaults::network::TRUST_PENALTY_UNKNOWN_PEER,
            trust_min_score: iroha_config::parameters::defaults::network::TRUST_MIN_SCORE,
            trust_gossip: iroha_config::parameters::defaults::network::TRUST_GOSSIP,
            dns_refresh_interval: None,
            dns_refresh_ttl: None,
            quic_enabled: false,
            quic_datagrams_enabled:
                iroha_config::parameters::defaults::network::QUIC_DATAGRAMS_ENABLED,
            quic_datagram_max_payload_bytes: iroha_config::parameters::defaults::network::QUIC_DATAGRAM_MAX_PAYLOAD_BYTES.get(),
            quic_datagram_receive_buffer_bytes: iroha_config::parameters::defaults::network::QUIC_DATAGRAM_RECEIVE_BUFFER_BYTES.get(),
            quic_datagram_send_buffer_bytes: iroha_config::parameters::defaults::network::QUIC_DATAGRAM_SEND_BUFFER_BYTES.get(),
            p2p_proxy: None,
            p2p_proxy_required: false,
            p2p_no_proxy: vec![],
            outbound_dial_allow_cidrs: vec![],
            outbound_dial_deny_cidrs: vec![],
            outbound_dial_allow_dns_suffixes: vec![],
            outbound_dial_deny_dns_suffixes: vec![],
            p2p_proxy_tls_verify: true,
            p2p_proxy_tls_pinned_cert_der_base64: None,
            p2p_queue_cap_high: core::num::NonZeroUsize::new(128).unwrap(),
            p2p_queue_cap_low: core::num::NonZeroUsize::new(128).unwrap(),
            p2p_post_queue_cap: core::num::NonZeroUsize::new(64).unwrap(),
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
            happy_eyeballs_stagger: std::time::Duration::from_millis(50),
            addr_ipv6_first: false,
            max_incoming: None,
            max_total_connections: None,
            preauth_max_connections_per_ip:
                iroha_config::parameters::defaults::network::PREAUTH_MAX_CONNECTIONS_PER_IP,
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
            allow_keys: vec![],
            deny_keys: vec![],
            allow_cidrs: vec![],
            deny_cidrs: vec![],
            disconnect_on_post_overflow: true,
            max_frame_bytes: 1_048_576 + iroha_config::parameters::defaults::network::DEFAULT_AEAD_FRAME_OVERHEAD_BYTES,
            tcp_nodelay: true,
            tcp_keepalive: None,
            max_frame_bytes_consensus: 262_144,
            max_frame_bytes_control: 262_144,
            max_frame_bytes_block_sync: 1_048_576,
            max_frame_bytes_tx_gossip: 262_144,
            max_frame_bytes_peer_gossip: 131_072,
            max_frame_bytes_health: 65_536,
            max_frame_bytes_connect: iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONNECT.get(),
            max_frame_bytes_other: 262_144,
            quic_max_idle_timeout: None,
        }
    }
    #[test]
    fn encrypted_frame_cap_accepts_exact_runtime_limit_and_rejects_next_byte() {
        assert!(
            super::validate_encrypted_frame_cap(crate::MAX_ENCRYPTED_FRAME_BYTES).is_ok(),
            "the exact deterministic runtime cap must remain admissible"
        );
        assert!(matches!(
            super::validate_encrypted_frame_cap(crate::MAX_ENCRYPTED_FRAME_BYTES + 1),
            Err(Error::FrameTooLarge)
        ));
    }
    #[test]
    fn shipped_quic_datagram_policy_is_disabled_and_rejects_enablement() {
        const {
            assert!(
                !iroha_config::parameters::defaults::network::QUIC_DATAGRAMS_ENABLED,
                "the shipping configuration must not advertise a Quinn DATAGRAM receive queue"
            );
        }
        assert!(!validate_shipping_quic_datagram_policy(false).unwrap());
        let error = validate_shipping_quic_datagram_policy(true)
            .expect_err("explicit DATAGRAM enablement must fail before binding sockets");
        let Error::Io(error) = error else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        let reason = error.to_string();
        assert!(reason.contains("quinn-proto 0.11.18"));
        assert!(reason.contains("zero-length frames"));
        assert!(reason.contains("requalification"));
    }
    #[test]
    fn shipped_quic_policy_rejects_unqualified_locked_dependency() {
        let error = validate_shipping_quic_policy(true)
            .expect_err("unqualified Quinn must fail before binding sockets");
        let Error::Io(error) = error else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        let reason = error.to_string();
        assert!(reason.contains("quinn-proto 0.11.18"));
        assert!(reason.contains("transport requalification"));
        assert!(reason.contains("requalification"));
        assert!(!validate_shipping_quic_policy(false).unwrap());
    }
    #[test]
    fn dormant_quic_datagram_geometry_is_bounded() {
        let payload = 1_200;
        let minimum_buffer = payload + core::mem::size_of::<bytes::Bytes>();
        validate_quic_configuration(false, false, payload, 0, 0).expect("TCP-only configuration");
        validate_quic_configuration(true, false, payload, 0, 0)
            .expect("stream-only QUIC configuration");
        validate_quic_configuration(true, true, payload, minimum_buffer, minimum_buffer)
            .expect("bounded QUIC DATAGRAM configuration");
        let error =
            validate_quic_configuration(false, true, payload, minimum_buffer, minimum_buffer)
                .expect_err("DATAGRAM without QUIC must fail before binding sockets");
        let Error::Io(error) = error else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("requires network.quic_enabled=true")
        );

        for (receive, send) in [
            (minimum_buffer - 1, minimum_buffer),
            (minimum_buffer, minimum_buffer - 1),
        ] {
            let error = validate_quic_configuration(true, true, payload, receive, send)
                .expect_err("a buffer smaller than payload plus fixed entry overhead must fail");
            let Error::Io(error) = error else {
                panic!("unexpected error: {error:?}");
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains(&minimum_buffer.to_string()));
        }
    }
    #[test]
    fn network_actor_budget_uses_exact_encrypted_stream_geometry() {
        let control_plaintext = 4096;
        let safety_charge = crate::frame_queue_charge(control_plaintext)
            .expect("small control frame must have a stream charge");
        let budget = super::network_actor_byte_budget(safety_charge, safety_charge)
            .expect("exact one-frame ordinary budget must be valid");
        assert_eq!(budget.max_bytes, safety_charge * 2);
        assert_eq!(budget.safety_reserve_bytes, safety_charge);
        let too_small = super::network_actor_byte_budget(safety_charge - 1, safety_charge);
        assert!(
            matches!(too_small, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput)
        );
        let overflowing = super::network_actor_byte_budget(usize::MAX, safety_charge);
        assert!(
            matches!(overflowing, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput)
        );
    }
    #[test]
    fn deferred_total_geometry_accepts_exact_dual_progress_boundary_and_rejects_one_less() {
        let topic_caps = TopicFrameCaps {
            consensus: 2_048,
            control: 1_024,
            block_sync: 4_096,
            tx_gossip: 512,
            peer_gossip: 256,
            health: 128,
            connect: 512,
            other: 512,
        };
        let max_ordinary = crate::frame_queue_charge_for::<ChaCha20Poly1305>(4_096)
            .expect("small ordinary progress charge");
        let safety =
            crate::frame_queue_charge_for::<ChaCha20Poly1305>(1_024).expect("small safety charge");
        let lane = crate::frame_queue_charge_for::<ChaCha20Poly1305>(2_048)
            .expect("small lane progress charge");
        let exact_total = max_ordinary
            .checked_add(safety)
            .expect("small dual-progress geometry");
        let exact = validate_transport_queue_geometry::<ChaCha20Poly1305>(
            8_192,
            topic_caps,
            max_ordinary,
            max_ordinary,
            exact_total,
            exact_total,
            3,
            6,
            2,
            1,
            2,
        );
        assert_eq!(
            exact.expect("exact boundary must be valid"),
            TransportQueueGeometry {
                safety_reserve_bytes: safety,
                progress_reserve_bytes: max_ordinary,
                actor_progress_bytes: ActorProgressByteLimits {
                    safety,
                    lane,
                    bulk: max_ordinary,
                },
            }
        );
        let below = validate_transport_queue_geometry::<ChaCha20Poly1305>(
            8_192,
            topic_caps,
            max_ordinary,
            max_ordinary,
            exact_total - 1,
            exact_total,
            3,
            6,
            2,
            1,
            2,
        );
        assert!(
            matches!(below, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput),
            "one byte below safety plus ordinary progress geometry must fail closed"
        );
        let per_peer_below = validate_transport_queue_geometry::<ChaCha20Poly1305>(
            8_192,
            topic_caps,
            max_ordinary,
            max_ordinary,
            exact_total,
            exact_total - 1,
            3,
            6,
            2,
            1,
            2,
        );
        assert!(
            matches!(per_peer_below, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput),
            "a per-peer byte owner below the dual-progress boundary must fail closed"
        );
        let one_slot = validate_transport_queue_geometry::<ChaCha20Poly1305>(
            8_192,
            topic_caps,
            max_ordinary,
            max_ordinary,
            exact_total,
            exact_total,
            1,
            1,
            1,
            1,
            1,
        );
        assert!(
            matches!(one_slot, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput),
            "a one-frame per-peer queue cannot preserve simultaneous safety and ordinary progress"
        );
    }
    #[test]
    fn connect_frame_cap_requires_matching_low_stream_capacity() {
        let mut caps = TopicFrameCaps::uniform(32_768);
        caps.connect = 8 * 1024 * 1024;
        let required = crate::frame_queue_charge_for::<ChaCha20Poly1305>(caps.connect)
            .expect("bounded Connect stream charge");
        let validate = |low_bytes| {
            validate_transport_queue_geometry::<ChaCha20Poly1305>(
                16 * 1024 * 1024,
                caps,
                16 * 1024 * 1024,
                low_bytes,
                32 * 1024 * 1024,
                32 * 1024 * 1024,
                3,
                message::TransportAdmissionClass::ORDINARY_HIGH.len(),
                message::TransportAdmissionClass::LOW.len(),
                1,
                2,
            )
        };
        validate(required).expect("exact low-stream Connect frame capacity");
        assert!(
            matches!(validate(required - 1), Err(Error::Io(error))
            if error.to_string().contains("maximum eligible low-topic frame")),
            "dedicated Connect frames must not bypass the low-stream byte geometry"
        );
    }

    #[test]
    fn shipped_defaults_form_valid_chacha_transport_geometry() {
        use iroha_config::parameters::defaults::network as defaults;
        let topic_caps = TopicFrameCaps {
            consensus: defaults::MAX_FRAME_BYTES_CONSENSUS.get(),
            control: defaults::MAX_FRAME_BYTES_CONTROL.get(),
            block_sync: defaults::MAX_FRAME_BYTES_BLOCK_SYNC.get(),
            tx_gossip: defaults::MAX_FRAME_BYTES_TX_GOSSIP.get(),
            peer_gossip: defaults::MAX_FRAME_BYTES_PEER_GOSSIP.get(),
            health: defaults::MAX_FRAME_BYTES_HEALTH.get(),
            connect: defaults::MAX_FRAME_BYTES_CONNECT.get(),
            other: defaults::MAX_FRAME_BYTES_OTHER.get(),
        };
        let geometry = validate_transport_queue_geometry::<ChaCha20Poly1305>(
            defaults::MAX_FRAME_BYTES.get(),
            topic_caps,
            defaults::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_BYTES.get(),
            defaults::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_BYTES.get(),
            defaults::DEFERRED_SEND_MAX_BYTES_TOTAL,
            defaults::DEFERRED_SEND_MAX_BYTES_PER_PEER,
            defaults::DEFERRED_SEND_MAX_PER_PEER,
            defaults::P2P_QUEUE_CAP_HIGH.get(),
            defaults::P2P_QUEUE_CAP_LOW.get(),
            defaults::P2P_POST_QUEUE_CAP.get(),
            defaults::P2P_SUBSCRIBER_QUEUE_CAP.get(),
        )
        .expect("the shipped network configuration must pass pre-bind transport validation");
        assert_eq!(
            geometry.safety_reserve_bytes,
            crate::frame_queue_charge_for::<ChaCha20Poly1305>(
                defaults::MAX_FRAME_BYTES_CONTROL.get()
            )
            .expect("default control charge")
        );
        assert_eq!(
            geometry.progress_reserve_bytes,
            crate::frame_queue_charge_for::<ChaCha20Poly1305>(
                defaults::MAX_PLAINTEXT_FRAME_BYTES.get()
            )
            .expect("default progress charge")
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_frame_cap_above_runtime_limit_before_binding() {
        let mut cfg = base_cfg();
        cfg.max_frame_bytes = crate::MAX_ENCRYPTED_FRAME_BYTES + 1;
        let shutdown = iroha_futures::supervisor::ShutdownSignal::new();
        let started = start_test_network(test_node_key_pair(), cfg, shutdown).await;
        assert!(matches!(started, Err(Error::FrameTooLarge)));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_deferred_total_below_dual_progress_geometry_before_binding() {
        let mut cfg = base_cfg();
        cfg.deferred_send_max_bytes_total = 1;
        let shutdown = iroha_futures::supervisor::ShutdownSignal::new();
        let started = start_test_network(test_node_key_pair(), cfg, shutdown).await;
        assert!(
            matches!(started, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput),
            "invalid deferred aggregate geometry must fail before listener binding"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_low_byte_burst_below_one_plaintext_frame_before_binding() {
        let mut cfg = base_cfg();
        // Occupy the requested address: a bind attempt would return AddrInUse, proving
        // that the exact InvalidInput below comes from the mandatory startup check.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        cfg.address = iroha_config_base::WithOrigin::inline(listener.local_addr().unwrap().into());
        cfg.low_priority_bytes_per_sec = core::num::NonZeroU32::new(1);
        cfg.low_priority_bytes_burst =
            core::num::NonZeroU32::new(u32::try_from(cfg.max_frame_bytes_block_sync - 1).unwrap());
        let started = start_test_network(
            test_node_key_pair(),
            cfg,
            iroha_futures::supervisor::ShutdownSignal::new(),
        )
        .await;
        assert!(matches!(
            started, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput
                && error.to_string().contains("network.low_priority_bytes_burst")
                && error.to_string().contains("1048576 canonical plaintext bytes")
        ));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_low_writer_budget_below_independent_gossip_and_sync_reservations() {
        use iroha_config::parameters::defaults::network as defaults;
        let mut cfg = base_cfg();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        cfg.address = iroha_config_base::WithOrigin::inline(listener.local_addr().unwrap().into());
        cfg.max_frame_bytes = defaults::MAX_FRAME_BYTES.get();
        cfg.max_frame_bytes_tx_gossip = defaults::MAX_FRAME_BYTES_TX_GOSSIP.get();
        cfg.max_frame_bytes_block_sync = defaults::MAX_FRAME_BYTES_BLOCK_SYNC.get();
        cfg.p2p_outbound_frame_queue_max_low_bytes =
            core::num::NonZeroUsize::new(64 * 1024 * 1024).unwrap();
        let started = start_test_network(
            test_node_key_pair(),
            cfg,
            iroha_futures::supervisor::ShutdownSignal::new(),
        )
        .await;
        assert!(matches!(
            started, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput
                && error.to_string().contains("network.p2p_outbound_frame_queue_max_low_bytes (67108864)")
                && error.to_string().contains("separate plaintext/encryption copies")
        ));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_proxy_required_without_proxy() {
        let key_pair = test_node_key_pair();
        let mut cfg = base_cfg();
        cfg.p2p_proxy_required = true;
        cfg.p2p_proxy = None;
        assert_start_invalid_input(key_pair, cfg).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_proxy_required_with_no_proxy_exemptions() {
        let key_pair = test_node_key_pair();
        let mut cfg = base_cfg();
        cfg.p2p_proxy_required = true;
        cfg.p2p_proxy = Some("http://proxy.invalid:8080".to_string());
        cfg.p2p_no_proxy = vec!["localhost".to_string()];
        assert_start_invalid_input(key_pair, cfg).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_malformed_outbound_dial_cidr_before_binding() {
        let key_pair = test_node_key_pair();
        let mut cfg = base_cfg();
        cfg.outbound_dial_deny_cidrs = vec!["192.0.2.0/33".to_owned()];
        assert_start_invalid_input(key_pair, cfg).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_malformed_inbound_acl_before_listener_binding() {
        let blocker = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("TCP blocker bind failed: {error:?}"),
        };
        let blocked_addr: iroha_primitives::addr::SocketAddr =
            blocker.local_addr().expect("blocked TCP address").into();
        let mut cfg = base_cfg();
        cfg.address = iroha_config_base::WithOrigin::inline(blocked_addr.clone());
        cfg.public_address = iroha_config_base::WithOrigin::inline(blocked_addr);
        cfg.deny_cidrs = vec!["192.0.2.0/33".to_owned()];

        let started = start_test_network(
            test_node_key_pair(),
            cfg,
            iroha_futures::supervisor::ShutdownSignal::new(),
        )
        .await;
        assert!(
            matches!(started, Err(Error::Io(error))
                if error.kind() == std::io::ErrorKind::InvalidInput
                    && error.to_string().contains("network.deny_cidrs")),
            "malformed inbound ACL must fail closed before reaching the occupied listener"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_accept_cap_below_enabled_dimensions() {
        let mut cfg = base_cfg();
        cfg.accept_rate_per_prefix_per_sec = core::num::NonZeroU32::new(1);
        cfg.accept_rate_per_ip_per_sec = core::num::NonZeroU32::new(1);
        cfg.max_accept_buckets = core::num::NonZeroUsize::new(1).unwrap();
        assert_start_invalid_input(test_node_key_pair(), cfg).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_malformed_outbound_dial_dns_suffix_before_binding() {
        let key_pair = test_node_key_pair();
        let mut cfg = base_cfg();
        cfg.outbound_dial_allow_dns_suffixes = vec!["bad..example".to_owned()];
        assert_start_invalid_input(key_pair, cfg).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_https_proxy_without_pin() {
        let key_pair = test_node_key_pair();
        let mut cfg = base_cfg();
        cfg.p2p_proxy = Some("https://proxy.invalid:443".to_string());
        cfg.p2p_proxy_tls_verify = true;
        cfg.p2p_proxy_tls_pinned_cert_der_base64 = None;
        assert_start_invalid_input(key_pair, cfg).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_disabled_https_proxy_verification() {
        let key_pair = test_node_key_pair();
        let mut cfg = base_cfg();
        cfg.p2p_proxy = Some("https://proxy.invalid:443".to_string());
        cfg.p2p_proxy_tls_verify = false;
        cfg.p2p_proxy_tls_pinned_cert_der_base64 = Some(BASE64_STANDARD.encode(b"test pin"));
        assert_start_invalid_input(key_pair, cfg).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_accepts_mandatory_tls_transport() {
        let key_pair = test_node_key_pair();
        let shutdown = iroha_futures::supervisor::ShutdownSignal::new();
        let started = start_test_network(key_pair, base_cfg(), shutdown.clone()).await;
        let (_handle, _child) = match started {
            Ok(ok) => ok,
            Err(Error::Io(_) | Error::BindListener { .. }) => {
                // Likely running in a sandbox that forbids sockets; skip.
                return;
            }
            Err(e) => panic!("network start: {e:?}"),
        };
        shutdown.send();
    }
    #[cfg(not(feature = "quic"))]
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_requested_quic_without_feature() {
        let key_pair = test_node_key_pair();
        let mut cfg = base_cfg();
        cfg.quic_enabled = true;
        assert_start_invalid_input(key_pair, cfg).await;
    }
    #[cfg(feature = "quic")]
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_proxy_required_with_quic_enabled() {
        let key_pair = test_node_key_pair();
        let mut cfg = base_cfg();
        cfg.p2p_proxy_required = true;
        cfg.p2p_proxy = Some("http://proxy.invalid:8080".to_string());
        cfg.quic_enabled = true;
        assert_start_invalid_input(key_pair, cfg).await;
    }
    #[cfg(feature = "quic")]
    #[tokio::test(flavor = "current_thread")]
    async fn start_rejects_vulnerable_quic_before_listener_binding() {
        let blocker = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(socket) => socket,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("UDP blocker bind failed: {error:?}"),
        };
        let blocked_addr: iroha_primitives::addr::SocketAddr =
            blocker.local_addr().expect("blocked UDP address").into();
        let mut cfg = base_cfg();
        cfg.address = iroha_config_base::WithOrigin::inline(blocked_addr.clone());
        cfg.public_address = iroha_config_base::WithOrigin::inline(blocked_addr);
        cfg.quic_enabled = true;
        let shutdown = iroha_futures::supervisor::ShutdownSignal::new();

        let started = start_test_network(test_node_key_pair(), cfg, shutdown).await;
        assert!(
            matches!(started, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput),
            "unqualified Quinn must be rejected before reaching the occupied UDP listener"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn connect_peer_propagates_frame_cap() {
        use iroha_primitives::addr::socket_addr;
        use std::collections::HashSet;
        let baseline = snapshot().len();
        let key_pair = test_node_key_pair();
        let mut cfg = base_cfg();
        cfg.max_frame_bytes = 37_777;
        let shutdown = iroha_futures::supervisor::ShutdownSignal::new();
        let started = start_test_network(key_pair, cfg, shutdown.clone()).await;
        let (handle, _child) = match started {
            Ok(ok) => ok,
            Err(Error::Io(_) | Error::BindListener { .. }) => {
                return;
            }
            Err(e) => panic!("network start: {e:?}"),
        };
        let peer_key = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let peer_id = iroha_model_base::peer::PeerId::from(peer_key.public_key().clone());
        let addr = socket_addr!(127.0.0.1:9);
        handle.update_peers_addresses(UpdatePeers(vec![(peer_id.clone(), addr)]));
        let mut topology = HashSet::new();
        topology.insert(peer_id);
        handle.update_topology(UpdateTopology(topology));
        let mut observed = false;
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let records = snapshot();
            if records
                .iter()
                .skip(baseline)
                .any(|(path, cap)| *path == SpawnPath::Connecting && *cap == 37_777)
            {
                observed = true;
                break;
            }
        }
        shutdown.send();
        assert!(
            observed,
            "expected connecting spawn to record configured cap"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn tls_listener_closes_silent_transport_at_absolute_preauth_deadline() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use tokio::{io::AsyncReadExt as _, sync::mpsc};

        let key_pair = test_node_key_pair();
        let network_id = test_network_id("preauth-deadline-test-chain");
        let soranet_transport_key_pair = Arc::new(test_transport_key_pair());
        let soranet_transport_certificate = crate::peer::create_soranet_transport_certificate_v5(
            &key_pair,
            Arc::clone(&soranet_transport_key_pair),
            Arc::new(test_relay_authentication_key_pair()),
            &network_id,
        )
        .expect("test transport certificate");
        let cancellations = Arc::new(AtomicUsize::new(0));
        let observed_cancellations = Arc::clone(&cancellations);
        let (service_tx, mut service_rx) =
            mpsc::channel::<super::ServiceMessage<super::WireMessage<Dummy>>>(8);
        tokio::spawn(async move {
            while let Some(message) = service_rx.recv().await {
                match message {
                    super::ServiceMessage::InboundAsk { reply, .. } => {
                        let _ = reply.send(true);
                    }
                    super::ServiceMessage::InboundCancelled(_) => {
                        observed_cancellations.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
        });
        let std_listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(e) => panic!("tcp bind failed: {e:?}"),
        };
        let addr = std_listener.local_addr().unwrap();
        drop(std_listener);
        let shutdown = ShutdownSignal::new();
        let listener_task = start_tls_listener::<super::WireMessage<Dummy>, ChaCha20Poly1305>(
            addr,
            Arc::new(key_pair),
            soranet_transport_key_pair,
            soranet_transport_certificate,
            socket_addr!(127.0.0.1:1_337),
            service_tx,
            Duration::from_secs(5),
            Duration::from_millis(150),
            network_id,
            None,
            None,
            None,
            8,
            OutboundFrameQueueLimits::default(),
            OutboundPostByteBudgets::default(),
            crate::peer::InboundFrameByteBudgets::default(),
            TlsListenerOptions {
                peer_capabilities: TlsPeerCapabilities {
                    trust_gossip: true,
                    quic_datagrams_enabled: false,
                    quic_datagram_max_payload_bytes: 0,
                    local_scion_supported: true,
                },
                tcp_nodelay: true,
                tcp_keepalive: None,
            },
            59_999,
            test_soranet_handshake_runtime(),
            RelayRole::Disabled,
            Arc::new(PreauthSourceGate::new(
                iroha_config::parameters::defaults::network::PREAUTH_MAX_CONNECTIONS_PER_IP,
            )),
            Arc::new(Semaphore::new(1)),
            shutdown.clone(),
        )
        .await
        .expect("start TLS listener");

        let mut raw = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect silent client");
        let mut byte = [0_u8; 1];
        match tokio::time::timeout(Duration::from_secs(2), raw.read(&mut byte)).await {
            Ok(Ok(0) | Err(_)) => {}
            other => panic!("silent transport outlived its absolute pre-auth deadline: {other:?}"),
        }
        for _ in 0..20 {
            if cancellations.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            cancellations.load(Ordering::Relaxed),
            1,
            "the expired transport must release exactly one inbound reservation"
        );
        shutdown.send();
        tokio::time::timeout(Duration::from_secs(2), listener_task.join())
            .await
            .expect("TLS listener must stop after shutdown");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tls_source_gate_precedes_global_capacity_and_deadline_releases_it() {
        use std::{net::Ipv4Addr, num::NonZeroUsize, sync::Arc};
        use tokio::{io::AsyncReadExt as _, sync::mpsc};

        let key_pair = test_node_key_pair();
        let network_id = test_network_id("preauth-source-gate-test-chain");
        let soranet_transport_key_pair = Arc::new(test_transport_key_pair());
        let soranet_transport_certificate = crate::peer::create_soranet_transport_certificate_v5(
            &key_pair,
            Arc::clone(&soranet_transport_key_pair),
            Arc::new(test_relay_authentication_key_pair()),
            &network_id,
        )
        .expect("test transport certificate");
        let (service_tx, mut service_rx) =
            mpsc::channel::<super::ServiceMessage<super::WireMessage<Dummy>>>(1);
        let std_listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(e) => panic!("tcp bind failed: {e:?}"),
        };
        let addr = std_listener.local_addr().expect("listener address");
        drop(std_listener);
        let source_gate = Arc::new(PreauthSourceGate::new(NonZeroUsize::new(1).unwrap()));
        let held_source = source_gate
            .try_acquire(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect("pre-existing source reservation");
        let global_capacity = Arc::new(Semaphore::new(1));
        let shutdown = ShutdownSignal::new();
        let listener_task = start_tls_listener::<super::WireMessage<Dummy>, ChaCha20Poly1305>(
            addr,
            Arc::new(key_pair),
            soranet_transport_key_pair,
            soranet_transport_certificate,
            socket_addr!(127.0.0.1:1_337),
            service_tx,
            Duration::from_secs(5),
            Duration::from_millis(150),
            network_id,
            None,
            None,
            None,
            8,
            OutboundFrameQueueLimits::default(),
            OutboundPostByteBudgets::default(),
            crate::peer::InboundFrameByteBudgets::default(),
            TlsListenerOptions {
                peer_capabilities: TlsPeerCapabilities {
                    trust_gossip: true,
                    quic_datagrams_enabled: false,
                    quic_datagram_max_payload_bytes: 0,
                    local_scion_supported: true,
                },
                tcp_nodelay: true,
                tcp_keepalive: None,
            },
            59_999,
            test_soranet_handshake_runtime(),
            RelayRole::Disabled,
            Arc::clone(&source_gate),
            Arc::clone(&global_capacity),
            shutdown.clone(),
        )
        .await
        .expect("start TLS listener");

        let mut rejected = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect source-capped client");
        let mut byte = [0_u8; 1];
        match tokio::time::timeout(Duration::from_secs(2), rejected.read(&mut byte)).await {
            Ok(Ok(0) | Err(_)) => {}
            other => panic!("source-capped transport was not closed: {other:?}"),
        }
        assert_eq!(
            global_capacity.available_permits(),
            1,
            "source rejection must happen before global capacity acquisition"
        );
        assert!(service_rx.try_recv().is_err());

        drop(held_source);
        let global_owner = Arc::clone(&global_capacity)
            .acquire_owned()
            .await
            .expect("global capacity");
        let mut capacity_waiter = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect capacity waiter");
        for _ in 0..20 {
            if source_gate.active_for(IpAddr::V4(Ipv4Addr::LOCALHOST)) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            source_gate.active_for(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            1,
            "accepted transport must own the source gate while waiting for global capacity"
        );
        match tokio::time::timeout(Duration::from_secs(2), capacity_waiter.read(&mut byte)).await {
            Ok(Ok(0) | Err(_)) => {}
            other => panic!("capacity waiter outlived its absolute deadline: {other:?}"),
        }
        assert_eq!(
            source_gate.active_for(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            0,
            "deadline teardown must release the source reservation"
        );
        assert!(service_rx.try_recv().is_err());

        drop(global_owner);
        shutdown.send();
        tokio::time::timeout(Duration::from_secs(2), listener_task.join())
            .await
            .expect("TLS listener must stop after shutdown");
    }

    #[cfg(feature = "quic")]
    #[tokio::test(flavor = "current_thread")]
    async fn tls_and_quic_share_source_gate_and_release_deadline_ownership() {
        use std::{
            net::{IpAddr, Ipv4Addr},
            num::NonZeroUsize,
            sync::{
                Arc, Mutex,
                atomic::{AtomicUsize, Ordering},
            },
        };
        use tokio::{
            io::AsyncReadExt as _,
            sync::{Notify, mpsc},
        };

        let key_pair = test_node_key_pair();
        let network_id = test_network_id("shared-preauth-source-gate-test-chain");
        let soranet_transport_key_pair = Arc::new(test_transport_key_pair());
        let soranet_transport_certificate = crate::peer::create_soranet_transport_certificate_v5(
            &key_pair,
            Arc::clone(&soranet_transport_key_pair),
            Arc::new(test_relay_authentication_key_pair()),
            &network_id,
        )
        .expect("test transport certificate");
        let inbound_asks = Arc::new(AtomicUsize::new(0));
        let observed_inbound_asks = Arc::clone(&inbound_asks);
        let admitted_conn_ids = Arc::new(Mutex::new(Vec::new()));
        let observed_admitted_conn_ids = Arc::clone(&admitted_conn_ids);
        let cancelled_conn_ids = Arc::new(Mutex::new(Vec::new()));
        let observed_cancelled_conn_ids = Arc::clone(&cancelled_conn_ids);
        let release_first_admission = Arc::new(Notify::new());
        let observed_release_first_admission = Arc::clone(&release_first_admission);
        let (service_tx, mut service_rx) =
            mpsc::channel::<super::ServiceMessage<super::WireMessage<Dummy>>>(8);
        tokio::spawn(async move {
            let mut first_admission = true;
            while let Some(message) = service_rx.recv().await {
                match message {
                    super::ServiceMessage::InboundAsk { conn_id, reply, .. } => {
                        observed_inbound_asks.fetch_add(1, Ordering::Relaxed);
                        observed_admitted_conn_ids
                            .lock()
                            .expect("admitted connection record")
                            .push(conn_id);
                        if first_admission {
                            first_admission = false;
                            observed_release_first_admission.notified().await;
                        }
                        let _ = reply.send(true);
                    }
                    super::ServiceMessage::InboundCancelled(conn_id) => {
                        observed_cancelled_conn_ids
                            .lock()
                            .expect("cancelled connection record")
                            .push(conn_id);
                    }
                    _ => {}
                }
            }
        });

        let tcp = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("tcp bind failed: {error:?}"),
        };
        let tls_addr = tcp.local_addr().expect("TLS listener address");
        drop(tcp);
        let udp = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(socket) => socket,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("udp bind failed: {error:?}"),
        };
        let quic_addr = udp.local_addr().expect("QUIC listener address");
        drop(udp);

        let preauth_timeout = Duration::from_secs(3);
        let source_gate = Arc::new(PreauthSourceGate::new(NonZeroUsize::new(1).unwrap()));
        let global_capacity = Arc::new(Semaphore::new(1));
        let shutdown = ShutdownSignal::new();
        let tls_listener = start_tls_listener::<super::WireMessage<Dummy>, ChaCha20Poly1305>(
            tls_addr,
            Arc::new(key_pair.clone()),
            Arc::clone(&soranet_transport_key_pair),
            Arc::clone(&soranet_transport_certificate),
            socket_addr!(127.0.0.1:1_337),
            service_tx.clone(),
            Duration::from_secs(5),
            preauth_timeout,
            network_id.clone(),
            None,
            None,
            None,
            8,
            OutboundFrameQueueLimits::default(),
            OutboundPostByteBudgets::default(),
            crate::peer::InboundFrameByteBudgets::default(),
            TlsListenerOptions {
                peer_capabilities: TlsPeerCapabilities {
                    trust_gossip: true,
                    quic_datagrams_enabled: false,
                    quic_datagram_max_payload_bytes: 0,
                    local_scion_supported: true,
                },
                tcp_nodelay: true,
                tcp_keepalive: None,
            },
            59_999,
            test_soranet_handshake_runtime(),
            RelayRole::Disabled,
            Arc::clone(&source_gate),
            Arc::clone(&global_capacity),
            shutdown.clone(),
        )
        .await
        .expect("start TLS listener");
        let quic_listener = start_quic_listener::<super::WireMessage<Dummy>, ChaCha20Poly1305>(
            &quic_addr,
            Arc::new(key_pair),
            soranet_transport_key_pair,
            soranet_transport_certificate,
            socket_addr!(127.0.0.1:4_321),
            service_tx,
            Duration::from_secs(5),
            preauth_timeout,
            None,
            false,
            0,
            0,
            0,
            network_id,
            None,
            None,
            None,
            8,
            OutboundFrameQueueLimits::default(),
            OutboundPostByteBudgets::default(),
            crate::peer::InboundFrameByteBudgets::default(),
            true,
            59_999,
            test_soranet_handshake_runtime(),
            true,
            RelayRole::Disabled,
            crate::transport::quic::FlowControlConfig {
                max_encrypted_frame_bytes: 59_999,
                max_total_connections: 1,
                process_budget_bytes: 4 * crate::transport::quic::FLOW_CONTROL_GRANULE_BYTES,
            },
            1,
            Arc::clone(&source_gate),
            Arc::clone(&global_capacity),
            shutdown.clone(),
        )
        .await
        .expect("start QUIC listener");

        let mut silent_tls = tokio::net::TcpStream::connect(tls_addr)
            .await
            .expect("connect silent TLS client");
        let localhost = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..40 {
            if source_gate.active_for(localhost) == 1 && inbound_asks.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            source_gate.active_for(localhost),
            1,
            "silent TLS transport must retain the shared source reservation"
        );
        assert_eq!(
            inbound_asks.load(Ordering::Relaxed),
            1,
            "the TLS transport must reach actor admission before stalling"
        );

        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
            .expect("create QUIC client endpoint");
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
            .with_no_client_auth();
        crypto.alpn_protocols = vec![crate::transport::quic::P2P_ALPN.to_vec()];
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .expect("configure rustls for quinn"),
        ));
        client_config.transport_config(Arc::new(quinn::TransportConfig::default()));
        endpoint.set_default_client_config(client_config);

        assert_eq!(
            global_capacity.available_permits(),
            0,
            "the admitted TLS transport must already own global pre-auth capacity",
        );
        let rejected = endpoint
            .connect(quic_addr, "iroha-quic")
            .expect("start source-capped QUIC connection");
        assert!(
            matches!(
                tokio::time::timeout(Duration::from_secs(1), rejected).await,
                Ok(Err(_))
            ),
            "QUIC source rejection must precede the unavailable global capacity"
        );
        assert_eq!(
            inbound_asks.load(Ordering::Relaxed),
            1,
            "a source-capped QUIC attempt must not consume actor admission"
        );
        assert_eq!(
            source_gate.active_for(localhost),
            1,
            "rejecting QUIC must not release the TLS owner's reservation"
        );
        assert!(
            cancelled_conn_ids
                .lock()
                .expect("cancelled connection record")
                .is_empty(),
            "source rejection must not cancel the admitted TLS reservation"
        );
        release_first_admission.notify_one();
        let mut byte = [0_u8; 1];
        match tokio::time::timeout(Duration::from_secs(4), silent_tls.read(&mut byte)).await {
            Ok(Ok(0) | Err(_)) => {}
            other => panic!("silent TLS transport outlived its pre-auth deadline: {other:?}"),
        }
        for _ in 0..40 {
            if source_gate.active_for(localhost) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            source_gate.active_for(localhost),
            0,
            "TLS deadline teardown must release shared source ownership"
        );
        for _ in 0..40 {
            if cancelled_conn_ids
                .lock()
                .expect("cancelled connection record")
                .len()
                == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let tls_conn_id = admitted_conn_ids
            .lock()
            .expect("admitted connection record")[0];
        assert_eq!(
            cancelled_conn_ids
                .lock()
                .expect("cancelled connection record")
                .as_slice(),
            &[tls_conn_id],
            "TLS deadline must cancel exactly its admitted reservation"
        );

        let admitted = endpoint
            .connect(quic_addr, "iroha-quic")
            .expect("start QUIC connection after TLS timeout");
        let connection = tokio::time::timeout(Duration::from_secs(2), admitted)
            .await
            .expect("QUIC admission must complete before the pre-auth deadline")
            .expect("QUIC source must be admitted after TLS releases it");
        let (mut send, _recv) = connection
            .open_bi()
            .await
            .expect("open required QUIC stream");
        send.write_all(b"I")
            .await
            .expect("send incomplete application preface");
        for _ in 0..40 {
            if inbound_asks.load(Ordering::Relaxed) == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            inbound_asks.load(Ordering::Relaxed),
            2,
            "released ownership must admit the next QUIC transport"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            source_gate.active_for(localhost),
            1,
            "silent QUIC application authentication must retain source ownership"
        );
        assert_eq!(
            cancelled_conn_ids
                .lock()
                .expect("cancelled connection record")
                .len(),
            1,
            "admitted QUIC ownership must not cancel before its deadline"
        );
        for _ in 0..100 {
            if source_gate.active_for(localhost) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            source_gate.active_for(localhost),
            0,
            "QUIC pre-auth deadline must release source ownership"
        );
        for _ in 0..40 {
            if cancelled_conn_ids
                .lock()
                .expect("cancelled connection record")
                .len()
                == 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let cancelled = cancelled_conn_ids
            .lock()
            .expect("cancelled connection record")
            .clone();
        let admitted = admitted_conn_ids
            .lock()
            .expect("admitted connection record")
            .clone();
        assert_eq!(
            cancelled, admitted,
            "each admitted deadline path must cancel its exact reservation once"
        );

        connection.close(0u32.into(), b"done");
        endpoint.close(0u32.into(), b"done");
        shutdown.send();
        tokio::time::timeout(Duration::from_secs(2), tls_listener.join())
            .await
            .expect("TLS listener must stop after shutdown");
        tokio::time::timeout(Duration::from_secs(2), quic_listener.join())
            .await
            .expect("QUIC listener must stop after shutdown");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tls_listener_requires_exact_p2p_alpn_and_propagates_frame_cap() {
        async fn connect_with_alpn(
            addr: std::net::SocketAddr,
            alpn_protocols: Vec<Vec<u8>>,
        ) -> std::io::Result<()> {
            let tcp = tokio::net::TcpStream::connect(addr).await?;
            let mut client_cfg =
                ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
                    .with_no_client_auth();
            client_cfg.alpn_protocols = alpn_protocols;
            let connector = TlsConnector::from(Arc::new(client_cfg));
            let server_name = rustls::pki_types::ServerName::try_from("iroha-tls")
                .unwrap()
                .to_owned();
            connector.connect(server_name, tcp).await.map(|_| ())
        }
        use std::sync::Arc;
        use tokio::sync::mpsc;
        use tokio_rustls::{
            TlsConnector,
            rustls::{self, ClientConfig},
        };
        let baseline = snapshot().len();
        let key_pair = test_node_key_pair();
        let network_id = test_network_id("test-chain");
        let soranet_transport_key_pair = Arc::new(test_transport_key_pair());
        let soranet_transport_certificate = crate::peer::create_soranet_transport_certificate_v5(
            &key_pair,
            Arc::clone(&soranet_transport_key_pair),
            Arc::new(test_relay_authentication_key_pair()),
            &network_id,
        )
        .expect("test transport certificate");
        let max_frame_bytes = 59_999usize;
        let (service_tx, mut service_rx) =
            mpsc::channel::<super::ServiceMessage<super::WireMessage<Dummy>>>(8);
        tokio::spawn(async move {
            while let Some(message) = service_rx.recv().await {
                if let super::ServiceMessage::InboundAsk { reply, .. } = message {
                    let _ = reply.send(true);
                }
            }
        });
        let std_listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(e) => panic!("tcp bind failed: {e:?}"),
        };
        let addr = std_listener.local_addr().unwrap();
        drop(std_listener);
        let soranet = test_soranet_handshake_runtime();
        let shutdown = ShutdownSignal::new();
        let _listener_task = start_tls_listener::<super::WireMessage<Dummy>, ChaCha20Poly1305>(
            addr,
            Arc::new(key_pair),
            soranet_transport_key_pair,
            soranet_transport_certificate,
            socket_addr!(127.0.0.1:1_337),
            service_tx,
            Duration::from_secs(1),
            Duration::from_secs(1),
            network_id,
            None,
            None,
            None,
            8,
            OutboundFrameQueueLimits::default(),
            OutboundPostByteBudgets::default(),
            crate::peer::InboundFrameByteBudgets::default(),
            TlsListenerOptions {
                peer_capabilities: TlsPeerCapabilities {
                    trust_gossip: true,
                    quic_datagrams_enabled: false,
                    quic_datagram_max_payload_bytes: 0,
                    local_scion_supported: true,
                },
                tcp_nodelay: true,
                tcp_keepalive: None,
            },
            max_frame_bytes,
            soranet.clone(),
            RelayRole::Disabled,
            Arc::new(PreauthSourceGate::new(
                iroha_config::parameters::defaults::network::PREAUTH_MAX_CONNECTIONS_PER_IP,
            )),
            Arc::new(Semaphore::new(1)),
            shutdown,
        )
        .await
        .expect("start_tls_listener");

        if let Ok(mut raw) = tokio::net::TcpStream::connect(addr).await {
            use tokio::io::AsyncWriteExt as _;
            let mut v5_preface = b"I2P2\x05".to_vec();
            v5_preface.extend_from_slice(&[7_u8; 32]);
            v5_preface.push(0);
            let _ = raw.write_all(&v5_preface).await;
            drop(raw);
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                !snapshot().iter().skip(baseline).any(|(path, cap)| {
                    *path == SpawnPath::ConnectedFrom && *cap == max_frame_bytes
                }),
                "the configured P2P socket must not expose a raw plaintext listener"
            );
        }

        for invalid_alpn in [Vec::new(), vec![b"http/1.1".to_vec()]] {
            let _ = connect_with_alpn(addr, invalid_alpn).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                !snapshot().iter().skip(baseline).any(|(path, cap)| {
                    *path == SpawnPath::ConnectedFrom && *cap == max_frame_bytes
                }),
                "raw TLS listener must reject missing or wrong ALPN"
            );
        }
        if connect_with_alpn(addr, vec![crate::transport::P2P_ALPN.to_vec()])
            .await
            .is_err()
        {
            return;
        }
        let mut observed = false;
        for _ in 0..20 {
            if snapshot()
                .iter()
                .skip(baseline)
                .any(|(path, cap)| *path == SpawnPath::ConnectedFrom && *cap == max_frame_bytes)
            {
                observed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            observed,
            "expected tls listener to propagate configured frame cap"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn start_provides_bind_listener_context_on_failure() {
        use iroha_primitives::addr::socket_addr;
        let key_pair = test_node_key_pair();
        let mut cfg = base_cfg();
        cfg.address = iroha_config_base::WithOrigin::inline(socket_addr!(127.0.0.1:1));
        cfg.public_address = iroha_config_base::WithOrigin::inline(socket_addr!(127.0.0.1:1));
        let shutdown = iroha_futures::supervisor::ShutdownSignal::new();
        let result = start_test_network(key_pair, cfg, shutdown).await;
        match result {
            Err(Error::BindListener {
                listen_addr,
                public_address,
                ..
            }) => {
                assert!(
                    listen_addr.contains("127.0.0.1:1"),
                    "listen address should mention configured endpoint; got {listen_addr}"
                );
                assert!(
                    public_address.contains("127.0.0.1:1"),
                    "public address should mention configured endpoint; got {public_address}"
                );
            }
            Err(Error::Io(_)) => {
                // Likely running in a sandbox that forbids sockets; skip.
            }
            Ok(_) => panic!("expected bind failure due to privileged port"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
    async fn assert_peer_message_cap<T, F>(
        payload: T,
        block_sync_cap: usize,
        within_cap_wire_len: Option<usize>,
        oversized_wire_len: usize,
        cap_violations: F,
        oversized_diagnostic: &'static str,
    ) where
        T: Pload + message::ClassifyTopic + Sync,
        F: Fn() -> u64 + Send,
    {
        let key_pair = test_node_key_pair();
        let Some((mut network, std_listener)) =
            super::tests::network_fixture_with_listener::<T>(key_pair.clone())
        else {
            return;
        };
        let listen_addr_std = std_listener.local_addr().unwrap();
        network.max_frame_bytes = 4096;
        network.cap_consensus = 128;
        network.cap_control = 128;
        network.cap_block_sync = block_sync_cap;
        network.cap_tx_gossip = 128;
        network.cap_peer_gossip = 128;
        network.cap_health = 128;
        network.cap_other = 128;
        network.disconnect_on_post_overflow = false;
        let peer = Peer::new(
            listen_addr_std.into(),
            PeerId::from(key_pair.public_key().clone()),
        );
        let mut before_oversized = cap_violations();
        if let Some(within_cap_wire_len) = within_cap_wire_len {
            let within_cap = super::PeerMessage::new(
                peer.clone(),
                RelayMessage::new(
                    peer.id().clone(),
                    RelayTarget::Direct(network.self_id.clone()),
                    DEFAULT_RELAY_TTL,
                    payload.clone(),
                ),
                within_cap_wire_len,
            );
            network.peer_message(within_cap).await;
            let after_within = cap_violations();
            assert!(
                after_within >= before_oversized,
                "cap violation counter should not decrease"
            );
            before_oversized = after_within;
        }
        let oversized = super::PeerMessage::new(
            peer.clone(),
            RelayMessage::new(
                peer.id().clone(),
                RelayTarget::Direct(network.self_id.clone()),
                DEFAULT_RELAY_TTL,
                payload,
            ),
            oversized_wire_len,
        );
        network.peer_message(oversized).await;
        let after_oversized = cap_violations();
        assert!(after_oversized > before_oversized, "{oversized_diagnostic}");
        assert!(
            !network.retry_backoff.contains_key(peer.id()),
            "a synthetic/inbound identity must not create outbound retry state"
        );
    }
    #[cfg(feature = "quic")]
    #[tokio::test(flavor = "current_thread")]
    async fn dormant_quic_listener_disables_datagram_transport() {
        use std::sync::Arc;
        use tokio::sync::mpsc;
        let baseline = snapshot().len();
        let key_pair = test_node_key_pair();
        let network_id = test_network_id("test-chain");
        let soranet_transport_key_pair = Arc::new(test_transport_key_pair());
        let soranet_transport_certificate = crate::peer::create_soranet_transport_certificate_v5(
            &key_pair,
            Arc::clone(&soranet_transport_key_pair),
            Arc::new(test_relay_authentication_key_pair()),
            &network_id,
        )
        .expect("test transport certificate");
        let max_frame_bytes = 61_111usize;
        let datagram_max_payload_bytes = 1_200usize;
        let datagram_buffer_bytes = 64 * 1024;
        let inbound_asks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_inbound_asks = Arc::clone(&inbound_asks);
        let (service_tx, mut service_rx) =
            mpsc::channel::<super::ServiceMessage<super::WireMessage<Dummy>>>(8);
        tokio::spawn(async move {
            while let Some(message) = service_rx.recv().await {
                if let super::ServiceMessage::InboundAsk { reply, .. } = message {
                    observed_inbound_asks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let _ = reply.send(true);
                }
            }
        });
        let udp = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(sock) => sock,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(e) => panic!("udp bind failed: {e:?}"),
        };
        let addr = udp.local_addr().unwrap();
        drop(udp);
        let soranet = test_soranet_handshake_runtime();
        let _listener_task = start_quic_listener::<super::WireMessage<Dummy>, ChaCha20Poly1305>(
            &addr,
            Arc::new(key_pair),
            soranet_transport_key_pair,
            soranet_transport_certificate,
            socket_addr!(127.0.0.1:4_321),
            service_tx,
            Duration::from_secs(5),
            Duration::from_secs(5),
            None,
            false,
            datagram_max_payload_bytes,
            datagram_buffer_bytes,
            datagram_buffer_bytes,
            network_id,
            None,
            None,
            None,
            8,
            OutboundFrameQueueLimits::default(),
            OutboundPostByteBudgets::default(),
            crate::peer::InboundFrameByteBudgets::default(),
            true,
            max_frame_bytes,
            soranet.clone(),
            false,
            RelayRole::Disabled,
            crate::transport::quic::FlowControlConfig {
                max_encrypted_frame_bytes: max_frame_bytes,
                max_total_connections: 1,
                process_budget_bytes: 4 * crate::transport::quic::FLOW_CONTROL_GRANULE_BYTES,
            },
            1,
            Arc::new(PreauthSourceGate::new(
                iroha_config::parameters::defaults::network::PREAUTH_MAX_CONNECTIONS_PER_IP,
            )),
            Arc::new(Semaphore::new(1)),
            ShutdownSignal::new(),
        )
        .await
        .expect("start_quic_listener");
        let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut endpoint = match quinn::Endpoint::client(bind_addr) {
            Ok(ep) => ep,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::PermissionDenied {
                    return;
                }
                panic!("quic endpoint failed: {err:?}");
            }
        };
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
            .with_no_client_auth();
        crypto.alpn_protocols = vec![crate::transport::quic::P2P_ALPN.to_vec()];
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .expect("failed to configure rustls for quinn"),
        ));
        let mut transport = quinn::TransportConfig::default();
        transport
            .datagram_receive_buffer_size(Some(datagram_buffer_bytes))
            .datagram_send_buffer_size(datagram_buffer_bytes);
        client_config.transport_config(Arc::new(transport));
        endpoint.set_default_client_config(client_config);
        let connecting = match endpoint.connect(addr, "iroha-quic") {
            Ok(conn) => conn,
            Err(e) => {
                iroha_logger::warn!(%e, "quic connect failed; skipping test");
                return;
            }
        };
        let connection = match connecting.await {
            Ok(conn) => conn,
            Err(e) => {
                iroha_logger::warn!(%e, "quic handshake failed; skipping test");
                return;
            }
        };
        let (mut send_hi, _recv_hi) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(_) => return,
        };
        send_hi
            .write_all(b"I")
            .await
            .expect("open the server's required high-priority stream");
        let mut observed = false;
        for _ in 0..20 {
            if snapshot()
                .iter()
                .skip(baseline)
                .any(|(path, cap)| *path == SpawnPath::ConnectedFrom && *cap == max_frame_bytes)
            {
                observed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            connection.max_datagram_size(),
            None,
            "the listener must not negotiate DATAGRAM support"
        );
        let error = connection
            .send_datagram(bytes::Bytes::from_static(b"probe"))
            .expect_err("the dormant listener must advertise no DATAGRAM receive support");
        assert!(
            matches!(error, quinn::SendDatagramError::UnsupportedByPeer),
            "unexpected disabled-DATAGRAM error: {error:?}"
        );
        endpoint.close(0u32.into(), b"done");
        assert!(
            observed,
            "expected quic listener to propagate configured frame cap"
        );
        assert_eq!(
            inbound_asks.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "QUIC Retry address validation must precede the sole InboundAsk"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn peer_message_over_cap_increments_violation_counter() {
        use crate::network::cap_violations_consensus;
        let _guard = cap_violation_test_guard().await;
        assert_peer_message_cap(
            DummyConsensus,
            128,
            None,
            512,
            cap_violations_consensus,
            "expected cap violation counter to increase",
        )
        .await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn peer_message_consensus_payload_uses_block_sync_cap() {
        use crate::network::cap_violations_consensus;
        let _guard = cap_violation_test_guard().await;
        assert_peer_message_cap(
            DummyConsensusPayload,
            512,
            Some(256),
            1024,
            cap_violations_consensus,
            "oversized consensus payload should be dropped",
        )
        .await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn peer_message_consensus_chunk_uses_block_sync_cap() {
        use crate::network::cap_violations_block_sync;
        let _guard = cap_violation_test_guard().await;
        assert_peer_message_cap(
            DummyConsensusChunk,
            512,
            Some(256),
            1024,
            cap_violations_block_sync,
            "oversized consensus chunk should be dropped",
        )
        .await;
    }
    #[test]
    fn overflow_counters_high_low_per_topic() {
        use super::message::Topic::*;
        // Capture base totals
        let base_total = super::post_overflow_count();
        let base_hi_cons = super::post_overflow_consensus_high_count();
        let base_lo_cons = super::post_overflow_consensus_low_count();
        // Simulate two overflows: one High/Consensus, one Low/Consensus
        super::POST_OVERFLOWS.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        super::inc_post_overflow_for_prio(Consensus, true);
        super::inc_post_overflow_for_prio(Consensus, false);
        assert!(
            super::post_overflow_count() >= base_total + 2,
            "global overflow counter should reflect at least this test's increments"
        );
        assert!(
            super::post_overflow_consensus_high_count() > base_hi_cons,
            "high-priority consensus overflow counter should reflect this test's increment"
        );
        assert!(
            super::post_overflow_consensus_low_count() > base_lo_cons,
            "low-priority consensus overflow counter should reflect this test's increment"
        );
    }
    #[test]
    fn tx_gossip_overflow_count_sums_both_priorities() {
        use super::message::Topic::*;
        let base = super::post_overflow_tx_gossip_count();
        super::inc_post_overflow_for_prio(TxGossip, true);
        super::inc_post_overflow_for_prio(TxGossipRestricted, false);
        assert!(
            super::post_overflow_tx_gossip_count() >= base + 2,
            "tx-gossip overflow total must include high and low priority overflows"
        );
    }
    #[test]
    fn overflow_counters_full_matrix() {
        use super::message::Topic::*;
        use std::sync::atomic::Ordering::Relaxed;
        // Snapshot bases
        let base_total = super::post_overflow_count();
        let b_hi = (
            super::post_overflow_consensus_high_count(),
            super::post_overflow_control_high_count(),
            super::post_overflow_block_sync_high_count(),
            super::post_overflow_tx_gossip_high_count(),
            super::post_overflow_peer_gossip_high_count(),
            super::post_overflow_health_high_count(),
            super::post_overflow_other_high_count(),
        );
        let b_lo = (
            super::post_overflow_consensus_low_count(),
            super::post_overflow_control_low_count(),
            super::post_overflow_block_sync_low_count(),
            super::post_overflow_tx_gossip_low_count(),
            super::post_overflow_peer_gossip_low_count(),
            super::post_overflow_health_low_count(),
            super::post_overflow_other_low_count(),
        );
        let topics = [
            Consensus,
            ConsensusChunk,
            Control,
            BlockSync,
            TxGossip,
            TxGossipRestricted,
            PeerGossip,
            TrustGossip,
            Health,
            Other,
        ];
        for &t in &topics {
            // High increment
            super::POST_OVERFLOWS.fetch_add(1, Relaxed);
            super::inc_post_overflow_for_prio(t, true);
            // Low increment
            super::POST_OVERFLOWS.fetch_add(1, Relaxed);
            super::inc_post_overflow_for_prio(t, false);
        }
        // Assert total grew by at least 16 (allowing for concurrent increments in other tests)
        assert!(super::post_overflow_count() >= base_total + 16);
        // Read back highs and lows
        let a_hi = (
            super::post_overflow_consensus_high_count(),
            super::post_overflow_control_high_count(),
            super::post_overflow_block_sync_high_count(),
            super::post_overflow_tx_gossip_high_count(),
            super::post_overflow_peer_gossip_high_count(),
            super::post_overflow_health_high_count(),
            super::post_overflow_other_high_count(),
        );
        let a_lo = (
            super::post_overflow_consensus_low_count(),
            super::post_overflow_control_low_count(),
            super::post_overflow_block_sync_low_count(),
            super::post_overflow_tx_gossip_low_count(),
            super::post_overflow_peer_gossip_low_count(),
            super::post_overflow_health_low_count(),
            super::post_overflow_other_low_count(),
        );
        // Each topic should have increased by at least 1 in both High and Low buckets
        assert!(a_hi.0 > b_hi.0);
        assert!(a_hi.1 > b_hi.1);
        assert!(a_hi.2 > b_hi.2);
        assert!(a_hi.3 > b_hi.3);
        assert!(a_hi.4 > b_hi.4);
        assert!(a_hi.5 > b_hi.5);
        assert!(a_hi.6 > b_hi.6);
        assert!(a_lo.0 > b_lo.0);
        assert!(a_lo.1 > b_lo.1);
        assert!(a_lo.2 > b_lo.2);
        assert!(a_lo.3 > b_lo.3);
        assert!(a_lo.4 > b_lo.4);
        assert!(a_lo.5 > b_lo.5);
        assert!(a_lo.6 > b_lo.6);
    }
}
#[cfg(test)]
mod reputation_tests {
    use super::*;
    use iroha_crypto::KeyPair;
    use std::collections::HashSet;
    #[test]
    fn trust_and_scores_update() {
        let id1 = PeerId::from(
            KeyPair::random_with_algorithm(Algorithm::BlsNormal)
                .public_key()
                .clone(),
        );
        let id2 = PeerId::from(
            KeyPair::random_with_algorithm(Algorithm::BlsNormal)
                .public_key()
                .clone(),
        );
        let mut rep = PeerReputationBook::default();
        rep.record_connected(&id1);
        rep.record_disconnected(&id2);
        let mut trusted = HashSet::new();
        trusted.insert(id1.clone());
        rep.set_trusted(&trusted);
        let trusted_ids: HashSet<_> = rep.trusted_peers().into_iter().collect();
        assert!(trusted_ids.contains(&id1));
        assert!(!trusted_ids.contains(&id2));
        let snap = rep.snapshot();
        let r1 = snap.get(&id1).expect("id1 present");
        assert!(r1.trusted);
        assert!(r1.score > 0);
        assert!(!snap.contains_key(&id2));
        assert_eq!(rep.score(&id2), 0);
    }
}
#[cfg(feature = "quic")]
#[allow(clippy::too_many_arguments)]
async fn start_quic_listener<T, E>(
    addr: &std::net::SocketAddr,
    key_pair: Arc<iroha_crypto::KeyPair>,
    soranet_transport_key_pair: Arc<iroha_crypto::KeyPair>,
    soranet_transport_certificate: Arc<crate::peer::LocalSoranetTransportCertificateV5>,
    public_address: iroha_primitives::addr::SocketAddr,
    service_message_sender: tokio::sync::mpsc::Sender<crate::peer::message::ServiceMessage<T>>,
    idle_timeout: std::time::Duration,
    preauth_timeout: std::time::Duration,
    quic_max_idle_timeout: Option<std::time::Duration>,
    quic_datagrams_enabled: bool,
    quic_datagram_max_payload_bytes: usize,
    quic_datagram_receive_buffer_bytes: usize,
    quic_datagram_send_buffer_bytes: usize,
    network_id: iroha_data_model::NetworkId,
    consensus_caps: Option<crate::ConsensusHandshakeCaps>,
    confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
    crypto_caps: Option<crate::CryptoHandshakeCaps>,
    post_capacity: usize,
    outbound_frame_queue_limits: OutboundFrameQueueLimits,
    outbound_post_byte_budgets: OutboundPostByteBudgets,
    inbound_frame_byte_budgets: crate::peer::InboundFrameByteBudgets,
    trust_gossip_config: bool,
    max_frame_bytes: usize,
    soranet_handshake: Arc<SoranetHandshakeRuntime>,
    local_scion_supported: bool,
    relay_role: RelayRole,
    flow_control: crate::transport::quic::FlowControlConfig,
    endpoint_max_incoming: usize,
    preauth_source_gate: Arc<PreauthSourceGate>,
    preauth_capacity: Arc<Semaphore>,
    shutdown_signal: ShutdownSignal,
) -> Result<AbortOnDropTask, Error>
where
    T: Pload + message::ClassifyTopic,
    E: Enc,
{
    use quinn::{
        IdleTimeout, TransportConfig, crypto::rustls::QuicServerConfig as QuinnRustlsServerConfig,
    };
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use std::sync::Arc;
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(["iroha-quic".to_owned()])
            .map_err(|e| Error::from(std::io::Error::other(format!("rcgen: {e}"))))?;
    let cert_der = cert.der().clone().into_owned();
    let transport_binding = crate::transport::certificate_fingerprint(cert_der.as_ref());
    let priv_key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], priv_key.into())
        .map_err(|e| Error::from(std::io::Error::other(format!("rustls server config: {e}"))))?;
    // Signed application authentication runs after QUIC setup, so replayable
    // 0-RTT data is never accepted on the P2P transport.
    tls.max_early_data_size = 0;
    tls.alpn_protocols = vec![crate::transport::quic::P2P_ALPN.to_vec()];
    let crypto = QuinnRustlsServerConfig::try_from(Arc::new(tls))
        .map_err(|e| Error::from(std::io::Error::other(format!("quic rustls: {e}"))))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint_geometry = crate::transport::quic::endpoint_buffer_geometry(
        flow_control,
        endpoint_max_incoming,
        quic_datagrams_enabled.then_some(quic_datagram_receive_buffer_bytes),
        if quic_datagrams_enabled {
            quic_datagram_send_buffer_bytes
        } else {
            0
        },
    )
    .map_err(|error| {
        Error::from(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("QUIC endpoint geometry: {error}"),
        ))
    })?;
    server_config
        .max_incoming(endpoint_geometry.max_incoming)
        .incoming_buffer_size(endpoint_geometry.incoming_buffer_size_bytes)
        .incoming_buffer_size_total(endpoint_geometry.incoming_buffer_size_total_bytes);
    // Align transport tuning with the outbound dialer defaults.
    let mut transport = TransportConfig::default();
    if let Some(timeout) = quic_max_idle_timeout {
        let idle = IdleTimeout::try_from(timeout)
            .map_err(|e| Error::from(std::io::Error::other(format!("quic idle timeout: {e}"))))?;
        transport.max_idle_timeout(Some(idle));
    }
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    if quic_datagrams_enabled {
        transport.datagram_receive_buffer_size(Some(quic_datagram_receive_buffer_bytes));
        transport.datagram_send_buffer_size(quic_datagram_send_buffer_bytes);
    } else {
        // Quinn enables DATAGRAM buffers by default. Match the disabled
        // application policy and the endpoint's zero-DATAGRAM byte budget.
        transport.datagram_receive_buffer_size(None);
        transport.datagram_send_buffer_size(0);
    }
    crate::transport::quic::configure_flow_control(&mut transport, flow_control).map_err(
        |error| {
            Error::from(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("QUIC flow-control geometry: {error}"),
            ))
        },
    )?;
    server_config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(server_config, *addr)
        .map_err(|e| Error::from(std::io::Error::other(format!("endpoint: {e}"))))?;
    // Allocate unique connection ids for QUIC streams starting from a high range
    // to minimize collision with TCP-generated ids.
    let id_alloc = NEXT_QUIC_CONN_ID.get_or_init(|| AtomicU64::new(1 << 60));
    let listen_addr = *addr;
    let task = tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        iroha_logger::info!(addr=%listen_addr, "QUIC listener started");
        loop {
            while children.try_join_next().is_some() {}
            let incoming = tokio::select! {
                () = shutdown_signal.receive() => break,
                () = service_message_sender.closed() => break,
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    incoming
                }
            };
            if !incoming.remote_address_validated() {
                let remote = incoming.remote_address();
                if let Err(error) = incoming.retry() {
                    iroha_logger::debug!(%error, %remote, "Failed to issue QUIC Retry");
                }
                continue;
            }
            let remote = incoming.remote_address();
            let Some(preauth_deadline) = PreauthDeadline::from_now(preauth_timeout) else {
                iroha_logger::error!(
                    %remote,
                    "Configured pre-authentication timeout is not representable"
                );
                continue;
            };
            let Some(source_permit) = preauth_source_gate.try_acquire(remote.ip()) else {
                PREAUTH_SOURCE_CAP_REJECTS.fetch_add(1, Ordering::Relaxed);
                iroha_logger::debug!(
                    %remote,
                    source_ip = %canonical_remote_ip(remote.ip()),
                    cap = preauth_source_gate.max_per_ip(),
                    "Dropping unauthenticated QUIC connection due to concurrent source cap"
                );
                continue;
            };
            // Address validation must precede both actor admission and any
            // reservation/cryptographic capacity ownership.
            let permit = tokio::select! {
                () = shutdown_signal.receive() => break,
                () = service_message_sender.closed() => break,
                permit = preauth_deadline.run(
                    None,
                    Arc::clone(&preauth_capacity).acquire_owned(),
                ) => {
                    match permit {
                        Ok(Ok(permit)) => permit,
                        Ok(Err(_)) => break,
                        Err(_) => {
                            iroha_logger::warn!(
                                %remote,
                                timeout = ?preauth_timeout,
                                "QUIC connection exhausted its pre-authentication deadline while waiting for capacity"
                            );
                            continue;
                        }
                    }
                }
            };
            let service_message_sender = service_message_sender.clone();
            let key_pair = Arc::clone(&key_pair);
            let soranet_transport_key_pair = Arc::clone(&soranet_transport_key_pair);
            let soranet_transport_certificate = Arc::clone(&soranet_transport_certificate);
            let public_address = public_address.clone();
            let network_id = network_id.clone();
            let consensus_caps = consensus_caps.clone();
            let confidential_caps = confidential_caps.clone();
            let crypto_caps = crypto_caps.clone();
            let idle_timeout = idle_timeout;
            let post_capacity = post_capacity;
            let outbound_frame_queue_limits = outbound_frame_queue_limits;
            let outbound_post_byte_budgets = outbound_post_byte_budgets.clone();
            let inbound_frame_byte_budgets = inbound_frame_byte_budgets.clone();
            let soranet_handshake = soranet_handshake.clone();
            let relay_role = relay_role;
            let trust_gossip_config = trust_gossip_config;
            let transport_binding = transport_binding;
            children.spawn(async move {
                let conn_id = id_alloc.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut reservation =
                    InboundReservationGuard::new(conn_id, service_message_sender.clone());
                let (tx, rx) = tokio::sync::oneshot::channel();
                let ask = ServiceMessage::InboundAsk {
                    conn_id,
                    remote_addr: remote,
                    reply: tx,
                };
                if !matches!(
                    preauth_deadline
                        .run(Some(idle_timeout), service_message_sender.send(ask))
                        .await,
                    Ok(Ok(()))
                ) {
                    iroha_logger::debug!(%remote, "Network did not accept QUIC InboundAsk in time");
                    return;
                }
                let allow = match preauth_deadline.run(Some(idle_timeout), rx).await {
                    Ok(Ok(allow)) => allow,
                    _ => return,
                };
                if !allow {
                    reservation.disarm();
                    iroha_logger::debug!(%remote, "Dropping QUIC connection due to caps/throttle");
                    return;
                }
                // The actor's exact `incoming_pending` reservation now owns
                // this connection, so the pre-crypto semaphore can be reused.
                drop(permit);
                let connecting = match incoming.accept() {
                    Ok(connecting) => connecting,
                    Err(e) => {
                        iroha_logger::warn!(%e, %remote, "Failed to accept QUIC connection");
                        return;
                    }
                };
                let new_conn = match preauth_deadline
                    .run(Some(idle_timeout), connecting)
                    .await
                {
                    Ok(Ok(conn)) => conn,
                    Ok(Err(e)) => {
                        iroha_logger::warn!(%e, %remote, "QUIC handshake failed");
                        return;
                    }
                    Err(_) => {
                        iroha_logger::warn!(%remote, timeout=?idle_timeout, "QUIC handshake timed out");
                        return;
                    }
                };
                let datagram_ingress = quic_datagrams_enabled.then(|| {
                    crate::peer::QuicDatagramIngress::spawn(
                        &new_conn,
                        quic_datagram_max_payload_bytes
                            .min(max_frame_bytes)
                            .min(crate::MAX_ENCRYPTED_FRAME_BYTES),
                    )
                });
                let (send_hi, recv_hi) = match preauth_deadline
                    .run(Some(idle_timeout), new_conn.accept_bi())
                    .await
                {
                    Ok(Ok((send, recv))) => (send, recv),
                    Ok(Err(e)) => {
                        iroha_logger::warn!(%e, %remote, "Failed to accept QUIC bi-stream");
                        return;
                    }
                    Err(_) => {
                        iroha_logger::warn!(
                            %remote,
                            timeout = ?idle_timeout,
                            "Timed out waiting for the required QUIC bi-stream"
                        );
                        return;
                    }
                };
                let low = preauth_deadline
                    .run(
                        Some(std::time::Duration::from_millis(200)),
                        new_conn.accept_bi(),
                    )
                    .await;
                let (send_low, recv_low) = match low {
                    Ok(Ok((s, r))) => (Some(s), Some(r)),
                    Ok(Err(e)) => {
                        iroha_logger::debug!(%e, %remote, "Failed to accept low-priority QUIC stream; continuing with single stream");
                        (None, None)
                    }
                    Err(DeadlineElapsed::Stage) => (None, None),
                    Err(DeadlineElapsed::Absolute) => {
                        iroha_logger::warn!(
                            %remote,
                            timeout = ?preauth_timeout,
                            "QUIC connection exhausted its pre-authentication deadline while waiting for the optional stream"
                        );
                        return;
                    }
                };
                let soranet_policy = match soranet_handshake.snapshot() {
                    Ok(policy) => policy,
                    Err(error) => {
                        iroha_logger::error!(
                            %error,
                            %remote,
                            "Refusing QUIC handshake without a SoraNet policy snapshot"
                        );
                        return;
                    }
                };
                let trust_gossip = trust_gossip_config && soranet_policy.trust_gossip();
                let (auth_completion, auth_receiver) = preauth_deadline.completion_channel();
                let peer_task = connected_from::<T, E>(
                    public_address,
                    key_pair,
                    soranet_transport_key_pair,
                    soranet_transport_certificate,
                    Connection::from_quic(
                        conn_id,
                        new_conn.clone(),
                        send_hi,
                        recv_hi,
                        send_low,
                        recv_low,
                        datagram_ingress,
                        Some(remote),
                        transport_binding,
                    ),
                    service_message_sender,
                    idle_timeout,
                    auth_completion,
                    network_id,
                    consensus_caps,
                    confidential_caps,
                    crypto_caps,
                    soranet_policy,
                    local_scion_supported,
                    post_capacity,
                    outbound_frame_queue_limits,
                    outbound_post_byte_budgets,
                    inbound_frame_byte_budgets,
                    relay_role,
                    trust_gossip,
                    max_frame_bytes,
                    quic_datagrams_enabled,
                    quic_datagram_max_payload_bytes,
                );
                let peer_task = AbortOnDropTask::new(peer_task);
                match preauth_deadline.wait_for_authentication(auth_receiver).await {
                    crate::preauth::AuthenticationWaitOutcome::Authenticated => {}
                    crate::preauth::AuthenticationWaitOutcome::PeerEnded => {
                        iroha_logger::debug!(%remote, "QUIC peer ended before completing authentication");
                        return;
                    }
                    crate::preauth::AuthenticationWaitOutcome::DeadlineElapsed => {
                        iroha_logger::warn!(
                            %remote,
                            timeout = ?preauth_timeout,
                            "QUIC peer did not authenticate before its pre-authentication deadline"
                        );
                        return;
                    }
                }
                drop(source_permit);
                reservation.disarm();
                peer_task.join().await;
            });
        }
        endpoint.close(0u32.into(), b"listener shutdown");
        children.abort_all();
        while children.join_next().await.is_some() {}
    });
    Ok(AbortOnDropTask::new(task))
}
#[cfg(all(test, feature = "quic"))]
mod quic_tests {
    use super::*;
    use iroha_crypto::{KeyPair, encryption::ChaCha20Poly1305};
    use iroha_primitives::addr::socket_addr;
    use norito::codec::{Decode, Encode};
    use std::sync::Arc;
    #[test]
    fn captured_original_test_payload_identities() {
        crate::frame_identity_tests::test_payload_identity::<Dummy>(
            "iroha_p2p::network::quic_tests::Dummy",
        );
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_p2p::network::quic_tests::Dummy")]
    #[derive(Clone, Debug, Decode, Encode)]
    struct Dummy;
    impl<'a> ncore::DecodeFromSlice<'a> for Dummy {
        fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
            ncore::decode_field_canonical::<Self>(bytes)
        }
    }
    impl crate::network::message::ClassifyTopic for Dummy {}
    #[tokio::test(flavor = "current_thread")]
    async fn quic_listener_shutdown_releases_udp_port_for_rebind() {
        let reserved = std::net::UdpSocket::bind("127.0.0.1:0").expect("reserve UDP port");
        let addr = reserved.local_addr().expect("reserved UDP address");
        drop(reserved);
        let kp = KeyPair::try_from_seed(vec![0x73; 32], Algorithm::BlsNormal)
            .expect("test BLS-normal node key");
        let transport = Arc::new(
            KeyPair::try_from_seed(vec![0x74; 32], Algorithm::Ed25519)
                .expect("test Ed25519 transport key"),
        );
        let relay_authentication = Arc::new(
            KeyPair::try_from_seed(vec![0x75; 32], Algorithm::MlDsa)
                .expect("test ML-DSA-65 relay-authentication key"),
        );
        let network_id = test_network_id("test-chain");
        let certificate = crate::peer::create_soranet_transport_certificate_v5(
            &kp,
            Arc::clone(&transport),
            relay_authentication,
            &network_id,
        )
        .expect("test transport certificate");
        let (tx, _rx) = tokio::sync::mpsc::channel::<
            crate::peer::message::ServiceMessage<WireMessage<Dummy>>,
        >(1);
        let soranet = test_soranet_handshake_runtime();
        let shutdown = ShutdownSignal::new();
        let task = match start_quic_listener::<WireMessage<Dummy>, ChaCha20Poly1305>(
            &addr,
            Arc::new(kp),
            transport,
            certificate,
            socket_addr!(127.0.0.1:1337),
            tx,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
            None,
            false,
            0,
            0,
            0,
            network_id,
            None,
            None,
            None,
            1,
            OutboundFrameQueueLimits::default(),
            OutboundPostByteBudgets::default(),
            crate::peer::InboundFrameByteBudgets::default(),
            true,
            1_048_576,
            soranet,
            true,
            RelayRole::Disabled,
            crate::transport::quic::FlowControlConfig {
                max_encrypted_frame_bytes: 1_048_576,
                max_total_connections: 1,
                process_budget_bytes: 4 * crate::transport::quic::FLOW_CONTROL_GRANULE_BYTES,
            },
            1,
            Arc::new(PreauthSourceGate::new(
                iroha_config::parameters::defaults::network::PREAUTH_MAX_CONNECTIONS_PER_IP,
            )),
            Arc::new(Semaphore::new(1)),
            shutdown.clone(),
        )
        .await
        {
            Ok(task) => task,
            Err(err) => {
                if let Error::Io(io_err) = &err {
                    if io_err.kind() == std::io::ErrorKind::PermissionDenied
                        || io_err.to_string().contains("Operation not permitted")
                    {
                        return;
                    }
                }
                panic!("scaffold should start without error: {err:?}");
            }
        };
        shutdown.send();
        tokio::time::timeout(std::time::Duration::from_secs(2), task.join())
            .await
            .expect("QUIC listener must terminate promptly after shutdown");
        std::net::UdpSocket::bind(addr)
            .expect("QUIC listener shutdown must release its UDP socket for immediate rebind");
    }
}
#[derive(Clone, Copy)]
struct TlsPeerCapabilities {
    trust_gossip: bool,
    quic_datagrams_enabled: bool,
    quic_datagram_max_payload_bytes: usize,
    local_scion_supported: bool,
}
#[derive(Clone, Copy)]
struct TlsListenerOptions {
    peer_capabilities: TlsPeerCapabilities,
    tcp_nodelay: bool,
    tcp_keepalive: Option<std::time::Duration>,
}
#[allow(clippy::too_many_arguments)]
async fn start_tls_listener<T, E>(
    addr: std::net::SocketAddr,
    key_pair: Arc<iroha_crypto::KeyPair>,
    soranet_transport_key_pair: Arc<iroha_crypto::KeyPair>,
    soranet_transport_certificate: Arc<crate::peer::LocalSoranetTransportCertificateV5>,
    public_address: iroha_primitives::addr::SocketAddr,
    service_message_sender: tokio::sync::mpsc::Sender<crate::peer::message::ServiceMessage<T>>,
    idle_timeout: std::time::Duration,
    preauth_timeout: std::time::Duration,
    network_id: iroha_data_model::NetworkId,
    consensus_caps: Option<crate::ConsensusHandshakeCaps>,
    confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
    crypto_caps: Option<crate::CryptoHandshakeCaps>,
    post_capacity: usize,
    outbound_frame_queue_limits: OutboundFrameQueueLimits,
    outbound_post_byte_budgets: OutboundPostByteBudgets,
    inbound_frame_byte_budgets: crate::peer::InboundFrameByteBudgets,
    options: TlsListenerOptions,
    max_frame_bytes: usize,
    soranet_handshake: Arc<SoranetHandshakeRuntime>,
    relay_role: RelayRole,
    preauth_source_gate: Arc<PreauthSourceGate>,
    preauth_capacity: Arc<Semaphore>,
    shutdown_signal: ShutdownSignal,
) -> Result<AbortOnDropTask, Error>
where
    T: boilerplate::Pload + message::ClassifyTopic,
    E: boilerplate::Enc,
{
    let TlsListenerOptions {
        peer_capabilities:
            TlsPeerCapabilities {
                trust_gossip: trust_gossip_config,
                quic_datagrams_enabled,
                quic_datagram_max_payload_bytes,
                local_scion_supported,
            },
        tcp_nodelay,
        tcp_keepalive,
    } = options;
    // Generate a self-signed certificate for the TLS server.
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(["iroha-tls".to_owned()])
            .map_err(|e| std::io::Error::other(format!("rcgen: {e}")))?;
    let cert_der = cert.der().clone();
    let transport_binding = crate::transport::certificate_fingerprint(cert_der.as_ref());
    let cert_chain = vec![cert_der.into_owned()];
    let priv_key = rustls::pki_types::PrivateKeyDer::from(
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
    )
    .clone_key();
    let mut server_cfg =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(cert_chain, priv_key)
            .map_err(|e| std::io::Error::other(format!("tls config: {e}")))?;
    server_cfg.alpn_protocols = vec![crate::transport::P2P_ALPN.to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let id_alloc = NEXT_TLS_CONN_ID.get_or_init(|| std::sync::atomic::AtomicU64::new(1 << 59));
    let task = tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        iroha_logger::info!(addr=%addr, "TLS listener started");
        loop {
            while children.try_join_next().is_some() {}
            let (tcp, remote) = tokio::select! {
                () = shutdown_signal.receive() => break,
                () = service_message_sender.closed() => break,
                accepted = listener.accept() => {
                    let Ok(accepted) = accepted else { break };
                    accepted
                }
            };
            let Some(preauth_deadline) = PreauthDeadline::from_now(preauth_timeout) else {
                iroha_logger::error!(
                    %remote,
                    "Configured pre-authentication timeout is not representable"
                );
                continue;
            };
            let Some(source_permit) = preauth_source_gate.try_acquire(remote.ip()) else {
                PREAUTH_SOURCE_CAP_REJECTS.fetch_add(1, Ordering::Relaxed);
                iroha_logger::debug!(
                    %remote,
                    source_ip = %canonical_remote_ip(remote.ip()),
                    cap = preauth_source_gate.max_per_ip(),
                    "Dropping unauthenticated TLS connection due to concurrent source cap"
                );
                continue;
            };
            let permit = tokio::select! {
                () = shutdown_signal.receive() => break,
                () = service_message_sender.closed() => break,
                permit = preauth_deadline.run(
                    None,
                    Arc::clone(&preauth_capacity).acquire_owned(),
                ) => {
                    match permit {
                        Ok(Ok(permit)) => permit,
                        Ok(Err(_)) => break,
                        Err(_) => {
                            iroha_logger::warn!(
                                %remote,
                                timeout = ?preauth_timeout,
                                "TLS connection exhausted its pre-authentication deadline while waiting for capacity"
                            );
                            continue;
                        }
                    }
                }
            };
            let service_message_sender = service_message_sender.clone();
            let key_pair = Arc::clone(&key_pair);
            let soranet_transport_key_pair = Arc::clone(&soranet_transport_key_pair);
            let soranet_transport_certificate = Arc::clone(&soranet_transport_certificate);
            let public_address = public_address.clone();
            let confidential_caps = confidential_caps.clone();
            let acceptor = acceptor.clone();
            let idle_timeout = idle_timeout;
            let post_capacity = post_capacity;
            let outbound_frame_queue_limits = outbound_frame_queue_limits;
            let outbound_post_byte_budgets = outbound_post_byte_budgets.clone();
            let inbound_frame_byte_budgets = inbound_frame_byte_budgets.clone();
            let soranet_handshake = Arc::clone(&soranet_handshake);
            let relay_role = relay_role;
            let tcp_nodelay = tcp_nodelay;
            let tcp_keepalive = tcp_keepalive;
            let quic_datagrams_enabled = quic_datagrams_enabled;
            let quic_datagram_max_payload_bytes = quic_datagram_max_payload_bytes;
            let transport_binding = transport_binding;
            children.spawn(async move {
                let conn_id = id_alloc.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut reservation =
                    InboundReservationGuard::new(conn_id, service_message_sender.clone());
                let (tx, rx) = tokio::sync::oneshot::channel();
                let ask = ServiceMessage::InboundAsk {
                    conn_id,
                    remote_addr: remote,
                    reply: tx,
                };
                if !matches!(
                    preauth_deadline
                        .run(Some(idle_timeout), service_message_sender.send(ask))
                        .await,
                    Ok(Ok(()))
                ) {
                    iroha_logger::debug!(%remote, "Network did not accept TLS InboundAsk in time");
                    return;
                }
                let allow = match preauth_deadline.run(Some(idle_timeout), rx).await {
                    Ok(Ok(allow)) => allow,
                    _ => return,
                };
                if !allow {
                    reservation.disarm();
                    iroha_logger::debug!(%remote, "Dropping TLS connection due to caps/throttle");
                    return;
                }
                // `incoming_pending` is now the exact max-total owner.
                drop(permit);
                crate::transport::apply_tcp_socket_options(&tcp, tcp_nodelay, tcp_keepalive);
                match preauth_deadline
                    .run(Some(idle_timeout), acceptor.accept(tcp))
                    .await
                {
                    Ok(Ok(tls_stream)) => {
                        if tls_stream.get_ref().1.alpn_protocol()
                            != Some(crate::transport::P2P_ALPN)
                        {
                            iroha_logger::warn!(
                                %remote,
                                "TLS peer did not negotiate the required raw P2P ALPN"
                            );
                            return;
                        }
                        let soranet_policy = match soranet_handshake.snapshot() {
                            Ok(policy) => policy,
                            Err(error) => {
                                iroha_logger::error!(
                                    %error,
                                    %remote,
                                    "Refusing TLS handshake without a SoraNet policy snapshot"
                                );
                                return;
                            }
                        };
                        let trust_gossip = trust_gossip_config && soranet_policy.trust_gossip();
                        let (read_half, write_half) = tokio::io::split(tls_stream);
                        let (auth_completion, auth_receiver) =
                            preauth_deadline.completion_channel();
                        let peer_task = connected_from::<T, E>(
                            public_address,
                            key_pair,
                            soranet_transport_key_pair,
                            soranet_transport_certificate,
                            Connection::from_split_with_binding(
                                conn_id,
                                read_half,
                                write_half,
                                transport_binding,
                            ),
                            service_message_sender,
                            idle_timeout,
                            auth_completion,
                            network_id,
                            consensus_caps,
                            confidential_caps.clone(),
                            crypto_caps,
                            soranet_policy,
                            local_scion_supported,
                            post_capacity,
                            outbound_frame_queue_limits,
                            outbound_post_byte_budgets,
                            inbound_frame_byte_budgets,
                            relay_role,
                            trust_gossip,
                            max_frame_bytes,
                            quic_datagrams_enabled,
                            quic_datagram_max_payload_bytes,
                        );
                        let peer_task = AbortOnDropTask::new(peer_task);
                        match preauth_deadline.wait_for_authentication(auth_receiver).await {
                            crate::preauth::AuthenticationWaitOutcome::Authenticated => {}
                            crate::preauth::AuthenticationWaitOutcome::PeerEnded => {
                                iroha_logger::debug!(%remote, "TLS peer ended before completing authentication");
                                return;
                            }
                            crate::preauth::AuthenticationWaitOutcome::DeadlineElapsed => {
                                iroha_logger::warn!(
                                    %remote,
                                    timeout = ?preauth_timeout,
                                    "TLS peer did not authenticate before its pre-authentication deadline"
                                );
                                return;
                            }
                        }
                        drop(source_permit);
                        reservation.disarm();
                        peer_task.join().await;
                    }
                    Ok(Err(e)) => {
                        iroha_logger::warn!(%e, %remote, "TLS accept failed");
                    }
                    Err(_) => {
                        iroha_logger::warn!(
                            %remote,
                            timeout = ?idle_timeout,
                            "TLS accept timed out"
                        );
                    }
                }
            });
        }
        children.abort_all();
        while children.join_next().await.is_some() {}
    });
    Ok(AbortOnDropTask::new(task))
}
/// Base network layer structure, holding connections interacting with peers.
#[allow(clippy::struct_excessive_bools)]
struct NetworkBase<T: Pload, E: Enc> {
    /// Listening address for incoming connections. Must parse into [`std::net::SocketAddr`]
    listen_addr: SocketAddr,
    /// TLS/QUIC accept loops owned by this actor and joined at shutdown.
    listener_tasks: Vec<AbortOnDropTask>,
    /// Peer tasks, including pre-authentication application handshakes, owned by this actor.
    peer_tasks: Vec<AbortOnDropTask>,
    /// External address of the peer (as seen by other peers)
    public_address: SocketAddr,
    /// Local relay role advertised during handshake.
    relay_role: RelayRole,
    /// Relay mode configured for this node.
    relay_mode: iroha_config::parameters::actual::RelayMode,
    /// Relay hub addresses to dial when in `spoke` / `assist` mode (priority order).
    ///
    /// When multiple hubs are provided, the network may rotate through them to
    /// maintain reachability in the presence of firewalls/censorship.
    relay_hub_addresses: Vec<SocketAddr>,
    /// Hub peer id resolved from topology/address book (spoke mode).
    relay_hub_peer: Option<PeerId>,
    /// Dial candidates whose advertised address matches `relay_hub_addresses`.
    ///
    /// Address gossip is sufficient to schedule an exact-id dial, but is not
    /// authority to relay traffic until that dial authenticates the expected
    /// identity.
    relay_hub_candidates: HashSet<PeerId>,
    /// Authenticated relay hub identities proven by an exact outbound dial.
    ///
    /// Peers in this set are allowed to send frames where `origin != incoming_peer_id`
    /// (i.e., forwarded/relayed frames).
    relay_trusted_peers: HashSet<PeerId>,
    /// Hop limit for forwarded frames.
    relay_ttl: u8,
    /// Configured trust-gossip capability for this node.
    trust_gossip_config: bool,
    /// Whether this node advertises trust-gossip support.
    trust_gossip: bool,
    /// Local peer identifier (derived from key pair).
    self_id: PeerId,
    /// Known peer addresses keyed by peer id.
    address_book: HashMap<PeerId, SocketAddr>,
    /// Local view of peer trust/score.
    peer_reputations: PeerReputationBook,
    /// `SoraNet` handshake runtime configuration shared across peers.
    soranet_handshake: Arc<SoranetHandshakeRuntime>,
    /// Current [`Peer`]s in [`Peer::Ready`] state.
    peers: HashMap<PeerId, RefPeer<WireMessage<T>>>,
    /// Exclusive pre-credit reader selection for registered authenticated connections.
    reader_arbitration: connection_arbitration::Arbitration,
    /// [`Peer`]s in process of being connected.
    connecting_peers: HashMap<ConnectionId, Peer>,
    /// Exact outbound generations retained until their termination witness.
    ///
    /// Inbound identities must never create reconnect state; keeping direction
    /// by connection id makes that decision independent of peer-id churn.
    outbound_connections: HashSet<ConnectionId>,
    /// Our app-level key pair
    key_pair: Arc<KeyPair>,
    /// Recipients of messages received from other peers in the network.
    subscribers_to_peers_messages: Vec<Subscriber<T>>,
    /// Byte/source-credit-owned reliable deliveries waiting for their unique
    /// route subscriber to register or be replaced.
    unrouted_reliable_deliveries: VecDeque<UnroutedReliableDelivery<T>>,
    /// Receiver to subscribe for messages received from other peers in the network.
    subscribe_to_peers_messages_receiver: mpsc::Receiver<Subscriber<T>>,
    /// Sender of `OnlinePeer` message
    online_peers_sender: watch::Sender<OnlinePeers>,
    /// Sender of online peer transport capabilities.
    online_peer_capabilities_sender: watch::Sender<message::OnlinePeerCapabilities>,
    /// Relay-aware topology publication used by targetized broadcast callers.
    reliable_broadcast_topology: Arc<Mutex<ReliableProgressTopology>>,
    /// Actor-published authority for direct reliable posts. This contains the
    /// accepted logical topology plus currently authenticated peer identities.
    reliable_direct_topology: Arc<Mutex<ReliableProgressTopology>>,
    /// Actor-published configured logical peers after topology and key-ACL admission.
    configured_peer_ids: Arc<Mutex<ConfiguredPeerState>>,
    /// Actor-instance identity and exact current connection tenures used to
    /// mint unforgeable reply routes for inbound semantic origins.
    reply_route_owner: Arc<()>,
    reply_route_tenures: HashMap<ConnectionId, Arc<ReliableReplyRouteTenure>>,
    next_reply_connection_ordinal: u128,
    next_reply_delivery_ordinal: u128,
    /// Latest coherent control transition whose protected delivery sources
    /// are installed but whose obsolete live owners have not all drained.
    pending_reply_source_authority: PendingReplySourceAuthority,
    /// Resolved configured hub waiting for its authenticated handoff.
    pending_configured_hub_source: Option<PeerId>,
    /// Shared reliable-progress owner used to cancel waiters whose exact
    /// broadcast membership was removed by an accepted topology transition.
    network_actor_progress_budget: Arc<NetworkActorProgressBudget>,
    /// Latest [`UpdateTopology`] snapshot receiver.
    update_topology_receiver: ControlUpdateReceiver<UpdateTopology>,
    /// Latest [`UpdatePeers`] snapshot receiver.
    update_peers_receiver: ControlUpdateReceiver<UpdatePeers>,
    /// Latest configured-validator dial-roster snapshot receiver.
    update_validator_dial_roster_receiver: ControlUpdateReceiver<ValidatorDialControlUpdate>,
    /// Latest [`UpdatePeerCapabilities`] snapshot receiver.
    update_peer_capabilities_receiver: ControlUpdateReceiver<message::UpdatePeerCapabilities>,
    /// Latest trusted-peers snapshot receiver.
    update_trusted_peers_receiver: ControlUpdateReceiver<UpdateTrustedPeers>,
    /// Receiver of high priority [`NetworkMessage`]
    network_message_high_receiver: net_channel::Receiver<AdmittedNetworkMessage<T>>,
    /// Receiver of authoritative-consensus safety [`NetworkMessage`]s.
    network_message_safety_receiver: net_channel::Receiver<AdmittedNetworkMessage<T>>,
    /// Receiver of reliable semantic-progress [`NetworkMessage`]s.
    network_message_progress_receiver: net_channel::Receiver<AdmittedNetworkMessage<T>>,
    /// Receiver of low priority [`NetworkMessage`]
    network_message_low_receiver: net_channel::Receiver<AdmittedNetworkMessage<T>>,
    /// High-priority inbound peer messages (consensus/control).
    peer_message_high_receiver: mpsc::Receiver<PeerMessage<WireMessage<T>>>,
    /// Dedicated semantic bulk delivery owner.
    peer_message_payload_receiver: mpsc::Receiver<PeerMessage<WireMessage<T>>>,
    peer_message_payload_sender: mpsc::Sender<PeerMessage<WireMessage<T>>>,
    peer_message_block_sync_receiver: mpsc::Receiver<PeerMessage<WireMessage<T>>>,
    peer_message_block_sync_sender: mpsc::Sender<PeerMessage<WireMessage<T>>>,
    /// Dedicated semantic control delivery owner.
    peer_message_control_receiver: mpsc::Receiver<PeerMessage<WireMessage<T>>>,
    peer_message_control_sender: mpsc::Sender<PeerMessage<WireMessage<T>>>,

    /// Authoritative-consensus safety messages from peers.
    peer_message_safety_receiver: mpsc::Receiver<PeerMessage<WireMessage<T>>>,
    /// Low-priority inbound peer messages (gossip/sync).
    peer_message_low_receiver: mpsc::Receiver<PeerMessage<WireMessage<T>>>,
    /// Sender for high-priority peer messages to provide clone inside peer.
    peer_message_high_sender: mpsc::Sender<PeerMessage<WireMessage<T>>>,
    /// Sender for authoritative-consensus safety messages provided to peers.
    peer_message_safety_sender: mpsc::Sender<PeerMessage<WireMessage<T>>>,
    /// Sender for low-priority peer messages to provide clone inside peer.
    peer_message_low_sender: mpsc::Sender<PeerMessage<WireMessage<T>>>,
    /// Channel to gather service messages from all peers
    service_message_receiver: mpsc::Receiver<ServiceMessage<WireMessage<T>>>,
    /// Sender for service peer messages to provide clone of sender inside peer
    service_message_sender: mpsc::Sender<ServiceMessage<WireMessage<T>>>,
    /// Latest ACL snapshot receiver.
    update_acl_receiver: ControlUpdateReceiver<message::UpdateAcl>,
    /// Exact handshake update request receiver.
    update_handshake_receiver: mpsc::Receiver<message::UpdateHandshake>,
    /// Current available connection id
    current_conn_id: ConnectionId,
    /// Last accepted logical topology before relay-route projection.
    requested_topology: HashSet<PeerId>,
    /// Current topology
    current_topology: HashSet<PeerId>,
    /// Pairwise preferred-owner and bounded standby takeover state for the
    /// configured validator subset only.
    validator_dial_scheduler: ValidatorDialScheduler,
    /// Peers which are not yet connected, but should.
    ///
    /// Can have two addresses for same `PeerId`.
    /// * One initially provided via config
    /// * Second received from other peers via gossiping
    ///
    /// Will try to establish connection via both addresses.
    current_peers_addresses: Vec<(PeerId, SocketAddr)>,
    /// Canonical `NetworkId` included in every handshake signature binding.
    network_id: NetworkId,
    /// Optional consensus handshake capabilities for gating connections.
    consensus_caps: Option<crate::ConsensusHandshakeCaps>,
    /// Optional confidential handshake capabilities for gating connections.
    confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
    /// Optional crypto handshake capabilities for gating connections.
    crypto_caps: Option<crate::CryptoHandshakeCaps>,
    /// Known peer transport capabilities keyed by peer id.
    peer_capabilities: HashMap<PeerId, message::PeerTransportCapabilities>,
    /// Per-peer post channel capacity (bounded mode).
    post_queue_cap: usize,
    /// Per-peer encrypted outbound frame backlog limits.
    outbound_frame_queue_limits: OutboundFrameQueueLimits,
    /// Process-wide owner retained across every connected outbound session.
    outbound_post_byte_budgets: OutboundPostByteBudgets,
    /// Aggregate pre-authentication frame owners shared by every connected reader.
    inbound_frame_byte_budgets: crate::peer::InboundFrameByteBudgets,
    /// Owns the one validated class partition across all live and draining tenures.
    _receive_credit_pool: Arc<crate::peer::receive_credit::Pool>,
    _semantic_post_pool: Option<Arc<crate::peer::post_admission::Pool>>,
    /// Classified byte owners spanning actor, subscriber, and application queues.
    inbound_dispatch_byte_budgets: crate::peer::InboundDispatchByteBudgets,
    /// Per-lane message credits reserved for each authenticated connection.
    authenticated_source_credit_capacity: usize,
    /// Optional interval to refresh hostname-based peers.
    dns_refresh_interval: Option<Duration>,
    /// Optional TTL to refresh hostname-based peers individually.
    dns_refresh_ttl: Option<Duration>,
    /// Last refresh time per peer for TTL logic.
    dns_last_refresh: HashMap<PeerId, tokio::time::Instant>,
    /// Interval between topology refresh ticks.
    topology_update_interval: Duration,
    /// Enable QUIC transport based on config at runtime.
    quic_enabled: bool,
    /// Enable QUIC DATAGRAM support for best-effort topics when using QUIC.
    quic_datagrams_enabled: bool,
    /// Upper bound (bytes) for QUIC datagram payloads.
    quic_datagram_max_payload_bytes: usize,
    /// Shared outbound QUIC dialer endpoint (feature-gated).
    quic_dialer: Option<crate::transport::QuicDialer>,
    /// Whether this node can advertise/use SCION-preferred transport.
    local_scion_supported: bool,
    /// Proxy policy applied to outbound TCP dials.
    proxy_policy: crate::transport::ProxyPolicy,
    /// Operator admission policy applied to every outbound logical and resolved target.
    outbound_dial_policy: Arc<crate::dial_policy::OutboundDialPolicy>,
    /// Whether to verify TLS certificates when dialing an `https://` proxy.
    proxy_tls_verify: bool,
    /// Optional pinned end-entity certificate for `https://` proxies (DER).
    proxy_tls_pinned_cert_der: Option<std::sync::Arc<[u8]>>,
    /// ACL: Allowlist-only switch and lists of keys and networks
    allowlist_only: bool,
    allow_keys: std::collections::HashSet<iroha_crypto::PublicKey>,
    deny_keys: std::collections::HashSet<iroha_crypto::PublicKey>,
    allow_nets: Vec<IpNet>,
    deny_nets: Vec<IpNet>,
    /// Peers pending reconnect after a DNS refresh.
    dns_pending_refresh: HashSet<PeerId>,
    /// Duration after which terminate connection with idle peer
    idle_timeout: Duration,
    /// Base deadline for an exact reply occurrence inside one peer writer.
    reply_writer_flush_timeout: Duration,
    /// Timeout applied to an individual outbound dial attempt.
    dial_timeout: Duration,
    /// Total dial-and-authentication tenure, also used for validator standby takeover.
    outbound_authentication_timeout: Duration,
    /// Whether to enable `TCP_NODELAY` on TCP connections (best-effort).
    tcp_nodelay: bool,
    /// Optional TCP keepalive idle timeout (best-effort, platform-specific).
    tcp_keepalive: Option<Duration>,
    /// Outbound dial delay applied once at startup.
    connect_startup_delay_until: tokio::time::Instant,
    /// Per-address exponential backoff schedule per peer: next allowed retry time and current base delay.
    /// Keyed by peer id, then by address string.
    retry_backoff: HashMap<PeerId, HashMap<String, (tokio::time::Instant, Duration)>>,
    /// Pending scheduled connect attempts with staggers
    pending_connects: Vec<(tokio::time::Instant, Peer)>,
    /// Deferred outbound frames queued while peer session is unavailable.
    deferred_send_queue: DeferredPeerFrameQueue<T>,
    /// Stagger delay between parallel address attempts for the same peer
    happy_eyeballs_stagger: Duration,
    /// Prefer IPv6 addresses first when ordering parallel dials
    addr_ipv6_first: bool,
    /// Track last-activity time per connected peer (updated on inbound peer messages)
    last_active: HashMap<PeerId, tokio::time::Instant>,
    /// Pending incoming accepts awaiting handshake (connection ids)
    incoming_pending: HashSet<ConnectionId>,
    /// Active incoming connections (connection ids)
    incoming_active: HashSet<ConnectionId>,
    /// Proactively removed peer actors which have not reported termination yet.
    ///
    /// These remain part of total-cap accounting because their authenticated
    /// source-reserve ownership can still be alive until task teardown finishes.
    terminating_connections: HashSet<ConnectionId>,
    /// Exact authenticated connection tenures rejected for a protocol violation.
    ///
    /// Entries remain until the tenure's delivery-drain fence completes so
    /// already queued frames cannot repeat expensive validation work.
    protocol_rejected_connections: HashSet<ConnectionId>,
    /// Optional cap on number of incoming connections
    max_incoming: Option<usize>,
    /// Optional cap on total number of connections
    max_total_connections: Option<usize>,
    /// Accept throttle parameters (prefix + per-IP).
    accept_params: AcceptThrottleParams,
    /// Prefix-level accept throttle buckets.
    accept_prefix_buckets: HashMap<IpBucketKey, AcceptBucket>,
    /// Per-IP accept throttle buckets.
    accept_ip_buckets: HashMap<IpBucketKey, AcceptBucket>,
    /// Log sampling helpers to avoid repeated warnings flooding logs
    sampler_high_queue_warn: LogSampler,
    sampler_low_queue_warn: LogSampler,
    /// Per-peer token buckets for low-priority messages
    low_rate_per_sec: Option<f64>,
    low_burst: Option<f64>,
    low_buckets: HashMap<PeerId, TokenBucket>,
    /// Optional bytes/sec limiter for Low-priority messages
    low_bytes_per_sec: Option<f64>,
    /// Resolved finite plaintext byte burst, large enough for one eligible low-topic frame.
    low_bytes_burst: f64,
    /// Per-peer bytes token buckets
    low_bytes_buckets: HashMap<PeerId, TokenBucket>,
    /// Maximum allowed frame size (bytes)
    max_frame_bytes: usize,
    /// Per-topic frame caps
    cap_consensus: usize,
    cap_control: usize,
    cap_block_sync: usize,
    cap_tx_gossip: usize,
    cap_peer_gossip: usize,
    cap_health: usize,
    cap_connect: usize,
    cap_other: usize,
    /// Whether to disconnect on per-peer post overflow (bounded channels)
    disconnect_on_post_overflow: bool,
    /// Encryptor used by the network
    _encryptor: core::marker::PhantomData<E>,
}
impl<T: Pload, E: Enc> NetworkBase<T, E> {
    fn reserve_incoming_pending(&mut self, conn_id: ConnectionId) -> bool {
        self.incoming_pending.insert(conn_id)
    }

    fn release_incoming_pending(&mut self, conn_id: ConnectionId) -> bool {
        self.incoming_pending.remove(&conn_id)
    }

    /// Revoke every actor-owned reply tenure and every caller-held waiter
    /// authorized by those tenures.
    ///
    /// Taking the map first makes the operation idempotent and lets normal
    /// shutdown share the exact path used by `Drop` after task abort or panic.
    fn cancel_all_reply_route_tenures(&mut self) -> usize {
        let tenures = core::mem::take(&mut self.reply_route_tenures);
        tenures.into_values().fold(0usize, |cancelled, tenure| {
            tenure.cancel();
            cancelled.saturating_add(
                self.network_actor_progress_budget
                    .cancel_reply_route(&tenure),
            )
        })
    }
}
impl<T: Pload, E: Enc> Drop for NetworkBase<T, E> {
    fn drop(&mut self) {
        let _ = self.cancel_all_reply_route_tenures();
    }
}
impl<T: Pload + message::ClassifyTopic + Sync, E: Enc> NetworkBase<T, E> {
    fn update_soranet_handshake_config(
        &mut self,
        handshake: ActualSoranetHandshake,
    ) -> Result<(), Error> {
        let updated = self.soranet_handshake.reload(handshake)?;
        self.trust_gossip = self.trust_gossip_config && updated.trust_gossip();
        Ok(())
    }
    fn handle_soranet_handshake_update(&mut self, update: message::UpdateHandshake) {
        let result = self.update_soranet_handshake_config(update.handshake);
        if let Err(err) = &result {
            iroha_logger::error!(
                error = %err,
                "Failed to update SoraNet handshake configuration"
            );
        }
        let _ = update.respond_to.send(result);
    }
    fn peer_authenticated(&mut self, candidate: Authenticated) {
        let connection_id = candidate.connection_id;
        // Only a real listener/dial reservation can create a provisional entry.
        // Authentication supplies identity; it does not mint another connection slot.
        let registered = self.incoming_pending.contains(&connection_id)
            || self
                .connecting_peers
                .get(&connection_id)
                .is_some_and(|target| target.id() == candidate.peer.id());
        if !registered {
            candidate.cancel.send_replace(true);
            return;
        }
        // Preserve exact configured-address hub proof at the moved identity
        // boundary, independently of which simultaneous session wins. The
        // losing transport grants no online or application authority.
        if matches!(candidate.relay_role, RelayRole::Hub)
            && self.outbound_connections.contains(&connection_id)
            && self
                .connecting_peers
                .get(&connection_id)
                .is_some_and(|target| {
                    target.id() == candidate.peer.id()
                        && self.configured_hub_matches(target.address())
                })
        {
            self.relay_trusted_peers.insert(candidate.peer.id().clone());
        }
        self.drain_reader_releases(SERVICE_MESSAGE_BUDGET);
        let admission = self.reader_arbitration.admit(candidate);
        if let Some(retired) = admission.retired {
            self.mark_connection_terminating(retired);
        }
        if !admission.accepted {
            self.mark_connection_terminating(connection_id);
        }
    }
    fn drain_reader_releases(&mut self, budget: usize) {
        for _ in 0..budget {
            let Some(id) = self.reader_arbitration.ready_release() else {
                break;
            };
            self.reader_arbitration.released(id);
        }
    }
    fn handle_service_message(&mut self, service_message: ServiceMessage<WireMessage<T>>) {
        match service_message {
            ServiceMessage::Authenticated(candidate) => {
                self.peer_authenticated(candidate);
            }
            ServiceMessage::Terminated(terminated) => {
                self.peer_terminated(terminated);
            }
            ServiceMessage::ReplyRouteDeliveryDrained(conn_id) => {
                self.finish_reply_route_tenure(conn_id);
            }
            ServiceMessage::Connected(connected) => {
                self.peer_connected(connected);
            }
            ServiceMessage::InboundAsk {
                conn_id,
                remote_addr,
                reply,
            } => {
                let remote_ip = canonical_remote_ip(remote_addr.ip());
                // Apply the same caps and per-IP throttle to TLS and QUIC accepts.
                let allow = if self.exceeds_ordinary_connection_cap() {
                    TOTAL_CAP_REJECTS.fetch_add(1, Ordering::Relaxed);
                    iroha_logger::warn!(addr=%remote_addr, "Dropping unauthenticated connection due to total connections cap");
                    false
                } else if self.exceeds_incoming_cap() {
                    INCOMING_CAP_REJECTS.fetch_add(1, Ordering::Relaxed);
                    iroha_logger::warn!(addr=%remote_addr, "Dropping unauthenticated connection due to max_incoming cap");
                    false
                } else if !self.allow_ip(remote_ip) {
                    // Token-bucket rejection is counted inside `allow_ip_with_policy` exactly
                    // once; ACL rejection is policy enforcement, not throttling telemetry.
                    iroha_logger::debug!(addr=%remote_addr, "Dropping unauthenticated connection due to IP policy or accept throttle");
                    false
                } else {
                    self.reserve_incoming_pending(conn_id)
                };
                if reply.send(allow).is_err() && allow {
                    // The request future was cancelled after admission but
                    // before it could construct its cancellation guard.
                    self.release_incoming_pending(conn_id);
                }
            }
            ServiceMessage::InboundCancelled(conn_id) => {
                // Idempotent and deliberately limited to pre-authentication
                // state: a delayed duplicate must not de-account a live peer.
                self.release_incoming_pending(conn_id);
            }
        }
    }
    fn drain_service_messages(&mut self, budget: usize) -> usize {
        let mut drained = 0;
        while drained < budget {
            match self.service_message_receiver.try_recv() {
                Ok(service_message) => {
                    self.handle_service_message(service_message);
                    drained = drained.saturating_add(1);
                }
                Err(
                    tokio::sync::mpsc::error::TryRecvError::Empty
                    | tokio::sync::mpsc::error::TryRecvError::Disconnected,
                ) => break,
            }
        }
        drained
    }
    #[expect(
        clippy::result_large_err,
        reason = "refused dispatch preserves the original admitted owner, byte lease and pending writer acknowledgements without allocating"
    )]
    fn dispatch_reliable_actor_message(
        &mut self,
        admitted: AdmittedNetworkMessage<T>,
    ) -> Result<(), AdmittedNetworkMessage<T>> {
        self.dispatch_reliable_actor_message_inner(admitted, || {})
    }
    /// Dispatch one admitted reliable item.
    ///
    /// The generic hook is monomorphized to an empty closure in production.
    /// Tests use it to publish a writer flush deterministically after the
    /// optimistic poll and before any terminal close-and-poll fence.
    #[expect(
        clippy::result_large_err,
        reason = "refused dispatch preserves the original admitted owner, byte lease and pending writer acknowledgements without allocating"
    )]
    fn dispatch_reliable_actor_message_inner<AfterInitialFlushPoll>(
        &mut self,
        admitted: AdmittedNetworkMessage<T>,
        after_initial_flush_poll: AfterInitialFlushPoll,
    ) -> Result<(), AdmittedNetworkMessage<T>>
    where
        AfterInitialFlushPoll: FnOnce(),
    {
        let NetworkDispatchParts {
            message,
            byte_lease: actor_lease,
            mut remaining_broadcast_targets,
            mut pending_flush_acks,
            progress_authority,
            reply_writer_timeout_attempt,
            mut reply_writer_deadline,
            reply_flush_ack,
        } = admitted.into_dispatch_parts();
        if let Some(attempt) = reply_writer_timeout_attempt {
            debug_assert!(matches!(
                progress_authority.as_ref(),
                Some(ProgressDeliveryAuthority::Reply(_))
            ));
            reply_writer_deadline.get_or_insert_with(|| ExactReplyWriterDeadline {
                admitted_at: tokio::time::Instant::now(),
                timeout: scaled_reply_writer_flush_timeout(
                    self.reply_writer_flush_timeout,
                    attempt,
                ),
            });
        }
        let (topic, route) = match &message {
            AdmittedNetworkPayload::Unsigned(NetworkMessage::Post(post)) => {
                (post.data.topic(), post.data.subscriber_route())
            }
            AdmittedNetworkPayload::Unsigned(NetworkMessage::Broadcast(broadcast)) => {
                (broadcast.data.topic(), broadcast.data.subscriber_route())
            }
            AdmittedNetworkPayload::Signed(frame) => {
                (frame.payload.topic(), frame.payload.subscriber_route())
            }
        };
        let reliable_progress = is_reliable_progress_route(topic, route);
        // Poll already-admitted peer-writer occurrences before observing route
        // retirement or connection replacement. The receiver is their
        // linearization point: a successful full flush published by that exact
        // writer occurrence remains successful even if actor-side teardown
        // wins the race immediately afterwards. A never-admitted occurrence
        // has no receiver in this map and therefore cannot take this path.
        //
        // Poll in stable peer-id order so a HashMap's randomized iteration
        // cannot affect the reducer-visible retry order or test traces.
        let mut ack_targets: Vec<_> = pending_flush_acks.keys().cloned().collect();
        ack_targets.sort();
        let mut completed_targets = HashSet::new();
        let mut retry_targets = Vec::new();
        let reply_route = progress_authority.as_ref().and_then(|authority| {
            let ProgressDeliveryAuthority::Reply(route) = authority else {
                return None;
            };
            Some(route.clone())
        });
        for target in ack_targets {
            let pending = pending_flush_acks
                .get_mut(&target)
                .expect("ack target snapshot must still be present");
            // The receiver is the linearization point: a flush already
            // published by the peer writer wins even at the deadline.
            let outcome = pending.receiver.try_recv();
            match outcome {
                Ok(()) => {
                    pending_flush_acks.remove(&target);
                    completed_targets.insert(target);
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    pending_flush_acks.remove(&target);
                    retry_targets.push(target);
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
            }
        }
        after_initial_flush_poll();
        let exact_reply_flushed = reply_route
            .as_ref()
            .is_some_and(|route| completed_targets.contains(route.semantic_target()));
        if exact_reply_flushed {
            debug_assert!(reliable_progress);
            debug_assert!(match &message {
                AdmittedNetworkPayload::Unsigned(NetworkMessage::Post(_)) => true,
                AdmittedNetworkPayload::Signed(frame) => {
                    matches!(&frame.target, RelayTarget::Direct(_))
                }
                AdmittedNetworkPayload::Unsigned(NetworkMessage::Broadcast(_)) => false,
            });
            if let Some(reply_flush_ack) = reply_flush_ack {
                let _ = reply_flush_ack.send(NetworkReplyFlushCompletion::Flushed);
            }
            drop(actor_lease);
            return Ok(());
        }
        if progress_authority
            .as_ref()
            .is_some_and(|authority| !authority.is_active())
        {
            if exact_reply_flush_wins_terminal_fence(
                &mut pending_flush_acks,
                reply_route.as_ref().map(NetworkReplyRoute::semantic_target),
            ) {
                if let Some(reply_flush_ack) = reply_flush_ack {
                    let _ = reply_flush_ack.send(NetworkReplyFlushCompletion::Flushed);
                }
                drop(actor_lease);
                return Ok(());
            }
            // An accepted topology removal is the exact cancellation witness
            // for this reliable target tenure. An empty or closed writer
            // receiver cannot keep the cancelled tenure alive.
            drop(actor_lease);
            return Ok(());
        }
        if let Some(ProgressDeliveryAuthority::Reply(route)) = progress_authority.as_ref() {
            let current_writer = self
                .peers
                .get(&route.tenure.delivery_peer)
                .is_some_and(|peer| peer.conn_id == route.tenure.connection_id);
            let current_tenure = self
                .reply_route_tenures
                .get(&route.tenure.connection_id)
                .is_some_and(|current| Arc::ptr_eq(current, &route.tenure));
            if !current_writer || !current_tenure {
                if exact_reply_flush_wins_terminal_fence(
                    &mut pending_flush_acks,
                    reply_route.as_ref().map(NetworkReplyRoute::semantic_target),
                ) {
                    if let Some(reply_flush_ack) = reply_flush_ack {
                        let _ = reply_flush_ack.send(NetworkReplyFlushCompletion::Flushed);
                    }
                    drop(actor_lease);
                    return Ok(());
                }
                // The actor may process replacement between handle admission
                // and this dispatch. Close this exact writer occurrence, but
                // keep delivery authority alive until the receiver-completion
                // fence so other already-dispatched inbound messages retain a
                // route.
                route.tenure.mark_draining();
                let _ = self
                    .network_actor_progress_budget
                    .cancel_reply_route(&route.tenure);
                drop(actor_lease);
                return Ok(());
            }
        }
        if !reliable_progress {
            match message.into_network() {
                NetworkMessage::Post(post) => self.post(post),
                NetworkMessage::Broadcast(broadcast) => self.broadcast(broadcast),
            }
            drop(actor_lease);
            return Ok(());
        }
        let timed_out_reply_writer = reply_route.is_some()
            && reply_writer_deadline
                .is_some_and(|deadline| deadline.expired_at(tokio::time::Instant::now()));
        if timed_out_reply_writer {
            let route = reply_route.expect("only an exact reply writer carries a deadline");
            let semantic_target = route.semantic_target();
            let connection_id = route.tenure.connection_id;
            if exact_reply_flush_wins_terminal_fence(&mut pending_flush_acks, Some(semantic_target))
            {
                if let Some(reply_flush_ack) = reply_flush_ack {
                    let _ = reply_flush_ack.send(NetworkReplyFlushCompletion::Flushed);
                }
                drop(actor_lease);
                return Ok(());
            }
            let terminated_current_writer =
                self.expire_reply_writer_occurrence(&route, connection_id);
            iroha_logger::warn!(
                semantic_target = %semantic_target,
                delivery_peer = %route.tenure.delivery_peer,
                connection_id,
                terminated_current_writer,
                timeout = ?reply_writer_deadline.map(|deadline| deadline.timeout),
                attempt = ?reply_writer_timeout_attempt,
                "Exact reply peer writer exceeded its flush deadline"
            );
            // Draining and exact-connection retirement publish before the
            // timeout result, so the caller can safely retry on a replacement.
            if let Some(reply_flush_ack) = reply_flush_ack {
                let _ = reply_flush_ack.send(NetworkReplyFlushCompletion::TimedOut);
            }
            drop(actor_lease);
            return Ok(());
        }
        let message = message.materialize(&self.key_pair, self.relay_ttl);
        let frame = Arc::clone(message.signed_frame());
        let transferred = match &frame.target {
            RelayTarget::Direct(peer_id) => {
                debug_assert!(
                    retry_targets.is_empty() || retry_targets == [peer_id.clone()],
                    "a direct actor post owns exactly one writer acknowledgement"
                );
                if completed_targets.contains(peer_id) {
                    true
                } else if pending_flush_acks.contains_key(peer_id) {
                    false
                } else {
                    let delivery_peer = match progress_authority.as_ref() {
                        Some(ProgressDeliveryAuthority::Reply(route)) => {
                            debug_assert_eq!(route.semantic_target(), peer_id);
                            route.tenure.delivery_peer.clone()
                        }
                        Some(ProgressDeliveryAuthority::Topology(_)) | None => self
                            .relay_route_for_unconnected_post_target(peer_id)
                            .unwrap_or_else(|| peer_id.clone()),
                    };
                    let exact_reply = matches!(
                        progress_authority.as_ref(),
                        Some(ProgressDeliveryAuthority::Reply(_))
                    );
                    match self.post_reliable_actor_frame_to_writer(
                        &delivery_peer,
                        frame.as_ref(),
                        topic,
                        exact_reply,
                    ) {
                        ReliableWriterAttempt::Awaiting(receiver) => {
                            let replaced = pending_flush_acks.insert(peer_id.clone(), receiver);
                            debug_assert!(replaced.is_none());
                            false
                        }
                        ReliableWriterAttempt::Retry => false,
                    }
                }
            }
            RelayTarget::Broadcast => {
                if !retry_targets.is_empty() {
                    let remaining = remaining_broadcast_targets.get_or_insert_with(VecDeque::new);
                    for target in retry_targets {
                        if !remaining.contains(&target) {
                            remaining.push_back(target);
                        }
                    }
                }
                if remaining_broadcast_targets.is_none() {
                    remaining_broadcast_targets = self.reliable_broadcast_targets();
                }
                if let Some(remaining) = remaining_broadcast_targets.as_mut() {
                    let attempts = remaining.len();
                    for _ in 0..attempts {
                        let target = remaining
                            .pop_front()
                            .expect("broadcast attempts are bounded by its target cursor");
                        if pending_flush_acks.contains_key(&target) {
                            continue;
                        }
                        match self.post_reliable_actor_frame_to_writer(
                            &target,
                            frame.as_ref(),
                            topic,
                            false,
                        ) {
                            ReliableWriterAttempt::Awaiting(receiver) => {
                                let replaced = pending_flush_acks.insert(target, receiver);
                                debug_assert!(replaced.is_none());
                            }
                            ReliableWriterAttempt::Retry => remaining.push_back(target),
                        }
                    }
                }
                remaining_broadcast_targets
                    .as_ref()
                    .is_some_and(VecDeque::is_empty)
                    && pending_flush_acks.is_empty()
            }
        };
        if transferred {
            // The actor lease retires only after every target's peer writer
            // confirms a complete write and flush.
            if let Some(reply_flush_ack) = reply_flush_ack {
                let _ = reply_flush_ack.send(NetworkReplyFlushCompletion::Flushed);
            }
            drop(actor_lease);
            Ok(())
        } else {
            Err(AdmittedNetworkMessage::retain_after_dispatch_attempt(
                NetworkDispatchParts {
                    message,
                    byte_lease: actor_lease,
                    remaining_broadcast_targets,
                    pending_flush_acks,
                    progress_authority,
                    reply_writer_timeout_attempt,
                    reply_writer_deadline,
                    reply_flush_ack,
                },
            ))
        }
    }
    fn retry_reliable_actor_messages(
        &mut self,
        pending: &mut ReliableActorPending<T>,
        budget: usize,
    ) -> usize {
        let attempts = pending.len().min(budget);
        let mut completed = 0usize;
        for _ in 0..attempts {
            let Some((source, message)) = pending.pop_front() else {
                break;
            };
            match self.dispatch_reliable_actor_message(message) {
                Ok(()) => completed = completed.saturating_add(1),
                Err(message) => pending.retry_back(source, message),
            }
        }
        completed
    }
    fn accept_reliable_actor_message(
        &mut self,
        pending: &mut ReliableActorPending<T>,
        mut message: AdmittedNetworkMessage<T>,
    ) {
        if message.cancelled_progress_authority() {
            message.publish_ready_exact_reply_before_terminal_drop();
            return;
        }
        pending.push_back(message);
        // A fresh source may run only after the prior head receives another
        // attempt. Two attempts make a cap-one blocked -> live sequence
        // immediately useful without letting the arrival barge ahead.
        self.retry_reliable_actor_messages(pending, 2);
    }
    /// [`Self`] task.
    #[allow(clippy::too_many_lines)]
    #[log(skip(self, shutdown_signal), fields(listen_addr=%self.listen_addr, public_key=%self.key_pair.public_key()))]
    async fn run(mut self, shutdown_signal: ShutdownSignal) {
        let mut update_topology_interval =
            tokio::time::interval(topology_tick_interval(self.topology_update_interval));
        update_topology_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Process pending staggered connects frequently to honor small staggers
        let mut pending_connects_interval = tokio::time::interval(Duration::from_millis(50));
        pending_connects_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut deferred_retry_interval = tokio::time::interval(DEFERRED_RETRY_INTERVAL);
        deferred_retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let reliable_actor_source_capacity = network_actor_progress_source_capacity(
            self.max_total_connections.unwrap_or(
                iroha_config::parameters::defaults::network::lane_profile::CORE_MAX_TOTAL_CONNECTIONS,
            ),
        )
        .expect("reliable actor source geometry was validated before listener startup");
        let mut safety_dispatch_pending = ReliableActorPending::new(reliable_actor_source_capacity);
        let mut progress_dispatch_pending =
            ReliableActorPending::new(reliable_actor_source_capacity);
        let mut dns_refresh_interval =
            self.dns_refresh_interval
                .map(tokio::time::interval)
                .map(|mut int| {
                    // Schedule first tick in the future to avoid immediate churn on startup
                    int.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    int
                });
        // TTL check timer: coarse periodic check
        let mut dns_ttl_check = if self.dns_refresh_ttl.is_some() {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            Some(interval)
        } else {
            None
        };
        loop {
            self.peer_tasks.retain(|task| !task.is_finished());
            if shutdown_signal.is_sent() {
                iroha_logger::debug!("Shutting down due to signal");
                break;
            }
            self.drain_reader_releases(SERVICE_MESSAGE_BUDGET);
            self.flush_safety_subscribers();
            let mut outbound_safety_drained = 0usize;
            while outbound_safety_drained < CONSENSUS_SAFETY_DRAIN_BUDGET
                && !shutdown_signal.is_sent()
            {
                match self.network_message_safety_receiver.try_recv() {
                    Ok(message) => {
                        self.accept_reliable_actor_message(&mut safety_dispatch_pending, message);
                    }
                    Err(
                        tokio::sync::mpsc::error::TryRecvError::Empty
                        | tokio::sync::mpsc::error::TryRecvError::Disconnected,
                    ) => break,
                }
                outbound_safety_drained = outbound_safety_drained.saturating_add(1);
            }
            update_network_queue_depth_safety(
                self.network_message_safety_receiver
                    .len()
                    .saturating_add(safety_dispatch_pending.len()),
            );
            let mut inbound_safety_drained = 0usize;
            while inbound_safety_drained < CONSENSUS_SAFETY_DRAIN_BUDGET
                && !shutdown_signal.is_sent()
            {
                match self.peer_message_safety_receiver.try_recv() {
                    Ok(peer_message) => {
                        self.peer_message(peer_message).await;
                        inbound_safety_drained = inbound_safety_drained.saturating_add(1);
                    }
                    Err(
                        tokio::sync::mpsc::error::TryRecvError::Empty
                        | tokio::sync::mpsc::error::TryRecvError::Disconnected,
                    ) => break,
                }
            }
            // Peer lifecycle and admission replies must stay ahead of bulk
            // outbound work, but the budget prevents a service producer from
            // monopolizing the actor.
            self.drain_service_messages(SERVICE_MESSAGE_BUDGET);
            let mut progress_drained = 0usize;
            while progress_drained < NETWORK_PROGRESS_ACTOR_DRAIN_BUDGET
                && !shutdown_signal.is_sent()
            {
                match self.network_message_progress_receiver.try_recv() {
                    Ok(message) => {
                        self.accept_reliable_actor_message(&mut progress_dispatch_pending, message);
                        progress_drained = progress_drained.saturating_add(1);
                    }
                    Err(
                        tokio::sync::mpsc::error::TryRecvError::Empty
                        | tokio::sync::mpsc::error::TryRecvError::Disconnected,
                    ) => break,
                }
            }
            update_network_queue_depth_progress(
                self.network_message_progress_receiver
                    .len()
                    .saturating_add(progress_dispatch_pending.len()),
            );
            let mut high_drained = 0usize;
            while high_drained < INBOUND_PEER_HIGH_BUDGET && !shutdown_signal.is_sent() {
                match self.peer_message_high_receiver.try_recv() {
                    Ok(peer_message) => {
                        self.peer_message(peer_message).await;
                        high_drained = high_drained.saturating_add(1);
                    }
                    Err(
                        tokio::sync::mpsc::error::TryRecvError::Empty
                        | tokio::sync::mpsc::error::TryRecvError::Disconnected,
                    ) => break,
                }
            }
            if shutdown_signal.is_sent() {
                iroha_logger::debug!("Shutting down due to signal");
                break;
            }
            // The bounded pre-drains above give safety, service, and
            // high-priority peer traffic predictable budgets. Keep the main
            // selection fair so a continuously ready queue or retained
            // control snapshot cannot starve other work or shutdown.
            tokio::select! {
                // Authoritative consensus safety has independent admission and is
                // always serviced before auxiliary control/high traffic.
                Some(network_message) = self.network_message_safety_receiver.recv() => {
                    self.accept_reliable_actor_message(
                        &mut safety_dispatch_pending,
                        network_message,
                    );
                    update_network_queue_depth_safety(
                        self.network_message_safety_receiver
                            .len()
                            .saturating_add(safety_dispatch_pending.len()),
                    );
                }
                Some(peer_message) = self.peer_message_safety_receiver.recv() => {
                    self.peer_message(peer_message).await;
                }
                // Subscribe messages is expected to exhaust at some point after starting network actor
                subscriber = self.subscribe_to_peers_messages_receiver.recv() => {
                    if let Some(subscriber) = subscriber {
                        self.subscribe_to_peers_messages(subscriber);
                    } else {
                        iroha_logger::warn!("unsubscribe channel closed; network actor shutting down");
                        break;
                    }
                }
                // Periodically refresh connections for hostname-based peers to re-resolve DNS
                _ = async {
                    match &mut dns_refresh_interval {
                        Some(int) => { int.tick().await; true }
                        None => false,
                    }
                }, if self.dns_refresh_interval.is_some() => {
                    self.refresh_hostnames();
                }
                // TTL-based selective refresh
                _ = async {
                    match &mut dns_ttl_check { Some(int) => { int.tick().await; true }, None => false }
                }, if self.dns_refresh_ttl.is_some() => {
                    self.refresh_hostnames_ttl();
                }
                // Update topology is relative low rate message (at most once every block)
                Some(update_topology) = receive_control_update(&mut self.update_topology_receiver) => {
                    self.set_current_topology(update_topology);
                }
                Some(update_peers) = receive_control_update(&mut self.update_peers_receiver) => {
                    self.set_current_peers_addresses(update_peers);
                }
                Some(update_validator_dial_control) = receive_control_update(
                    &mut self.update_validator_dial_roster_receiver,
                ) => {
                    match update_validator_dial_control {
                        ValidatorDialControlUpdate::Roster(roster) => {
                            self.set_validator_dial_roster(roster);
                        }
                        ValidatorDialControlUpdate::Topology(topology) => {
                            self.set_validator_topology(topology);
                        }
                    }
                }
                Some(update_capabilities) = receive_control_update(
                    &mut self.update_peer_capabilities_receiver,
                ) => {
                    self.set_peer_capabilities(update_capabilities);
                }
                // Apply ACL updates (hot reload)
                Some(acl) = receive_control_update(&mut self.update_acl_receiver) => {
                    self.set_reply_source_acl(acl);
                }
                Some(handshake) = self.update_handshake_receiver.recv() => {
                    self.handle_soranet_handshake_update(handshake);
                }
                // Frequency of update is relatively low, so it won't block other tasks from execution
                _ = update_topology_interval.tick() => {
                    if self.retry_pending_reply_source_authority() {
                        self.update_topology();
                    }
                }
                Some(trusted_update) = receive_control_update(
                    &mut self.update_trusted_peers_receiver,
                ) => {
                    self.set_reply_source_trusted(trusted_update);
                }
                // Process staggered connect attempts
                _ = pending_connects_interval.tick() => {
                    self.process_pending_connects();
                }
                // A retained frame must resume when peer-channel capacity opens;
                // it must not depend on an unrelated future outbound message.
                _ = deferred_retry_interval.tick() => {
                    let _ = self.retry_pending_reply_source_authority();
                    self.retry_deferred_frames();
                    self.retry_reliable_actor_messages(
                        &mut safety_dispatch_pending,
                        CONSENSUS_SAFETY_DRAIN_BUDGET,
                    );
                    self.retry_reliable_actor_messages(
                        &mut progress_dispatch_pending,
                        NETWORK_PROGRESS_ACTOR_DRAIN_BUDGET,
                    );
                    update_network_queue_depth_safety(
                        self.network_message_safety_receiver
                            .len()
                            .saturating_add(safety_dispatch_pending.len()),
                    );
                    update_network_queue_depth_progress(
                        self.network_message_progress_receiver
                            .len()
                            .saturating_add(progress_dispatch_pending.len()),
                    );
                }
                // The pre-drain above preserves service-before-data priority;
                // this branch handles arrivals that race with selection.
                released = std::future::poll_fn(|cx| self.reader_arbitration.poll_released(cx)) => {
                    if shutdown_signal.is_sent() { break; }
                    self.reader_arbitration.released(released);
                }
                Some(service_message) = self.service_message_receiver.recv() => {
                    self.handle_service_message(service_message);
                }
                // Reliable progress has an additive byte owner and a bounded
                // pre-drain above. This branch handles arrivals that race with
                // selection without allowing an unbounded progress burst.
                Some(network_message) = self.network_message_progress_receiver.recv() => {
                    self.accept_reliable_actor_message(
                        &mut progress_dispatch_pending,
                        network_message,
                    );
                    update_network_queue_depth_progress(
                        self.network_message_progress_receiver
                            .len()
                            .saturating_add(progress_dispatch_pending.len()),
                    );
                }
                // High-priority network messages (consensus/control)
                network_message = self.network_message_high_receiver.recv() => {
                    let Some(network_message) = network_message else {
                        iroha_logger::debug!("All handles to network actor are dropped. Shutting down...");
                        break;
                    };
                    let queued_after_first_recv = self.network_message_high_receiver.len();
                    let drain_limit = high_actor_drain_limit(queued_after_first_recv.saturating_add(1));
                    let mut drained = 0usize;
                    let mut network_message = Some(network_message);
                    while let Some(message) = network_message {
                        let (message, _actor_lease) = message.into_parts();
                        match message {
                            NetworkMessage::Post(post) => self.post(post),
                            NetworkMessage::Broadcast(broadcast) => self.broadcast(broadcast),
                        }
                        drained = drained.saturating_add(1);
                        if should_stop_high_actor_drain(
                            drained,
                            drain_limit,
                            !self.service_message_receiver.is_empty(),
                            shutdown_signal.is_sent(),
                        ) {
                            break;
                        }
                        network_message = self.network_message_high_receiver.try_recv().ok();
                    }
                    let len = self.network_message_high_receiver.len();
                    update_network_queue_depth_high(len);
                    if len > 100
                        && let Some(supp) = self.sampler_high_queue_warn.should_log(tokio::time::Duration::from_secs(1)) {
                            iroha_logger::warn!(size=len, drained, drain_limit, suppressed=supp, "High-priority messages are piling up in the queue");
                        }
                }
                // High-priority inbound peer messages (consensus/control)
                Some(peer_message) = self.peer_message_high_receiver.recv() => {
                    self.peer_message(peer_message).await;
                }
                Some(peer_message) = self.peer_message_payload_receiver.recv() => {
                    self.peer_message(peer_message).await;
                }
                Some(peer_message) = self.peer_message_block_sync_receiver.recv() => {
                    self.peer_message(peer_message).await;
                }
                Some(peer_message) = self.peer_message_control_receiver.recv() => {
                    self.peer_message(peer_message).await;
                }

                // Low-priority network messages (gossip)
                network_message = self.network_message_low_receiver.recv() => {
                    let Some(network_message) = network_message else {
                        iroha_logger::debug!("All handles to network actor are dropped. Shutting down...");
                        break;
                    };
                    let len = self.network_message_low_receiver.len();
                    update_network_queue_depth_low(len);
                    if len > 100
                        && let Some(supp) = self.sampler_low_queue_warn.should_log(tokio::time::Duration::from_secs(1)) {
                            iroha_logger::warn!(size=len, suppressed=supp, "Low-priority messages are piling up in the queue");
                        }
                    let (network_message, _actor_lease) = network_message.into_parts();
                    match network_message {
                        NetworkMessage::Post(post) => self.post_low(post),
                        NetworkMessage::Broadcast(broadcast) => self.broadcast_low(broadcast),
                    }
                }
                // Low-priority inbound peer messages (gossip/sync)
                Some(peer_message) = self.peer_message_low_receiver.recv() => {
                    self.peer_message(peer_message).await;
                }
                () = shutdown_signal.receive() => {
                    iroha_logger::debug!("Shutting down due to signal");
                    break
                }
                else => {
                    iroha_logger::debug!("All receivers are dropped, shutting down");
                    break
                },
            }
            let (removed_memberships, cancelled_waiters) =
                self.reconcile_reliable_progress_topologies();
            let released = safety_dispatch_pending
                .release_cancelled_targets()
                .saturating_add(progress_dispatch_pending.release_cancelled_targets());
            if removed_memberships > 0 || cancelled_waiters > 0 || released > 0 {
                iroha_logger::debug!(
                    removed_memberships,
                    cancelled_waiters,
                    released,
                    "Cancelled exact reliable-progress ownership for removed topology memberships"
                );
            }
            tokio::task::yield_now().await;
        }
        let released_on_shutdown = safety_dispatch_pending
            .release_all_with_terminal_fence()
            .saturating_add(progress_dispatch_pending.release_all_with_terminal_fence());
        if released_on_shutdown > 0 {
            iroha_logger::debug!(
                released_on_shutdown,
                "Released reliable actor ownership through terminal fences at shutdown"
            );
        }
        // Publish route and waiter cancellation before stopping peer writers.
        // `Drop` repeats this same idempotent operation if shutdown is aborted
        // or unwinds before reaching this point. Pending-queue `Drop` likewise
        // fences exact writer receivers if the actor future is aborted.
        let _ = self.cancel_all_reply_route_tenures();
        // Explicitly cancel authenticated peer tasks at actor shutdown.  Dropping
        // their handles alone intentionally permits admitted frames to drain and
        // therefore cannot unblock a writer whose remote has stopped reading.
        for ref_peer in self.peers.values() {
            ref_peer.handle.request_termination();
        }
        for task in &self.listener_tasks {
            task.abort();
        }
        for task in &self.peer_tasks {
            task.abort();
        }
        for task in self.listener_tasks.drain(..) {
            task.join().await;
        }
        for task in self.peer_tasks.drain(..) {
            task.join().await;
        }
    }
    /// Disconnect and re-dial peers whose address is hostname-based to re-resolve DNS.
    fn refresh_hostnames(&mut self) {
        let ids_to_refresh: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(peer_id, ref_peer)| match &ref_peer.p2p_addr {
                SocketAddr::Host(_) => Some(peer_id.clone()),
                _ => None,
            })
            .collect();
        for peer_id in ids_to_refresh {
            iroha_logger::debug!(%peer_id, "Refreshing DNS for hostname-based peer");
            self.dns_pending_refresh.insert(peer_id.clone());
            self.disconnect_peer(&peer_id);
        }
        DNS_REFRESHES.fetch_add(1, Ordering::Relaxed);
        // Connections will be re-established via the regular topology update path
        self.update_topology();
    }
    /// TTL-based selective refresh for hostname-based peers.
    fn refresh_hostnames_ttl(&mut self) {
        let Some(ttl) = self.dns_refresh_ttl else {
            return;
        };
        let now = tokio::time::Instant::now();
        let mut refreshed = Vec::new();
        for (peer_id, ref_peer) in &self.peers {
            if !matches!(ref_peer.p2p_addr, SocketAddr::Host(_)) {
                continue;
            }
            let last = self
                .dns_last_refresh
                .get(peer_id)
                .copied()
                .unwrap_or(now - ttl - Duration::from_secs(1));
            if now.duration_since(last) >= ttl {
                refreshed.push(peer_id.clone());
            }
        }
        for peer_id in &refreshed {
            iroha_logger::debug!(%peer_id, "TTL refresh of hostname-based peer");
            self.dns_last_refresh.insert(peer_id.clone(), now);
            self.disconnect_peer(peer_id);
        }
        if !refreshed.is_empty() {
            DNS_TTL_REFRESHES.fetch_add(1, Ordering::Relaxed);
        }
        self.update_topology();
    }
    fn accept_staged_reply_source_authority(
        &mut self,
        prior: PendingReplySourceAuthority,
        transition: &'static str,
    ) -> bool {
        let projection = self.desired_reply_source_authority();
        let source_capacity = self.reply_source_capacity();
        if projection.protected_sources.len() > source_capacity {
            iroha_logger::error!(
                transition,
                desired_sources = projection.protected_sources.len(),
                source_capacity,
                "Rejected reply-source authority larger than configured source-count geometry"
            );
            self.pending_reply_source_authority = prior;
            return false;
        }
        let installed = self
            .inbound_frame_byte_budgets
            .install_protected_sources(projection.protected_sources.clone());
        debug_assert!(installed, "representable source projection must install");
        if self
            .inbound_frame_byte_budgets
            .protected_source_geometry_fits()
        {
            self.commit_pending_reply_source_authority();
        } else {
            self.retire_obsolete_reply_sources(&projection.reconciliation_topology);
            iroha_logger::warn!(
                transition,
                desired_sources = projection.protected_sources.len(),
                source_capacity,
                "Deferred reply-source authority until obsolete source owners drain"
            );
        }
        true
    }
    fn retry_pending_reply_source_authority(&mut self) -> bool {
        if self.pending_reply_source_authority.is_empty() {
            return true;
        }
        let projection = self.desired_reply_source_authority();
        if projection.protected_sources.len() > self.reply_source_capacity() {
            iroha_logger::error!(
                desired_sources = projection.protected_sources.len(),
                source_capacity = self.reply_source_capacity(),
                "Pending reply-source authority is not representable; retaining applied state"
            );
            return false;
        }
        let installed = self
            .inbound_frame_byte_budgets
            .install_protected_sources(projection.protected_sources.clone());
        debug_assert!(
            installed,
            "representable pending source projection must install"
        );
        if !self
            .inbound_frame_byte_budgets
            .protected_source_geometry_fits()
        {
            self.retire_obsolete_reply_sources(&projection.reconciliation_topology);
            return false;
        }
        self.commit_pending_reply_source_authority();
        true
    }
    fn retire_obsolete_reply_sources(&mut self, desired: &HashSet<PeerId>) {
        self.pending_connects
            .retain(|(_, peer)| desired.contains(peer.id()));
        self.retry_backoff
            .retain(|peer_id, _| desired.contains(peer_id));
        self.dns_pending_refresh
            .retain(|peer_id| desired.contains(peer_id));
        let obsolete: Vec<_> = self
            .peers
            .keys()
            .filter(|peer_id| !desired.contains(*peer_id))
            .cloned()
            .collect();
        for peer_id in obsolete {
            self.disconnect_peer(&peer_id);
        }
    }
    fn commit_pending_reply_source_authority(&mut self) {
        let pending = core::mem::take(&mut self.pending_reply_source_authority);
        if let Some(acl) = pending.acl {
            self.apply_reply_source_acl(acl);
        }
        if let Some(trusted) = pending.trusted {
            self.apply_reply_source_trusted(trusted);
        }
        if let Some(message::UpdateValidatorDialRoster(roster)) = pending.validator_dial_roster {
            self.validator_dial_scheduler
                .replace_roster(roster, &self.self_id);
        }
        if let Some(topology) = pending.topology {
            self.apply_current_topology(topology);
        } else {
            self.update_topology();
        }
        let applied = self.desired_reply_source_authority();
        let installed = self
            .inbound_frame_byte_budgets
            .install_protected_sources(applied.protected_sources);
        debug_assert!(
            installed,
            "committed source projection must remain representable"
        );
    }
    fn set_reply_source_acl(&mut self, acl: message::UpdateAcl) -> bool {
        let acl = match ValidatedAclUpdate::parse(acl) {
            Ok(acl) => acl,
            Err(error) => {
                iroha_logger::error!(%error, "Rejected invalid runtime network ACL");
                return false;
            }
        };
        let prior = self.pending_reply_source_authority.clone();
        self.pending_reply_source_authority.acl = Some(acl);
        self.accept_staged_reply_source_authority(prior, "ACL update")
    }
    fn set_reply_source_trusted(&mut self, trusted: UpdateTrustedPeers) {
        let prior = self.pending_reply_source_authority.clone();
        self.pending_reply_source_authority.trusted = Some(trusted);
        self.accept_staged_reply_source_authority(prior, "trusted-peer update");
    }
    fn set_current_topology(&mut self, update: UpdateTopology) {
        self.stage_current_topology(update, None, "topology update");
    }
    fn set_validator_topology(
        &mut self,
        message::UpdateValidatorTopology {
            topology,
            mut validator_dial_roster,
        }: message::UpdateValidatorTopology,
    ) {
        validator_dial_roster.retain(|peer_id| topology.contains(peer_id));
        self.stage_current_topology(
            UpdateTopology(topology),
            Some(message::UpdateValidatorDialRoster(validator_dial_roster)),
            "validator topology update",
        );
    }
    fn stage_current_topology(
        &mut self,
        update: UpdateTopology,
        validator_dial_roster: Option<message::UpdateValidatorDialRoster>,
        transition: &'static str,
    ) {
        let logical_topology: HashSet<_> = update
            .0
            .iter()
            .filter(|peer_id| *peer_id != &self.self_id)
            .filter(|peer_id| self.projected_reply_source_acl_allows(peer_id))
            .cloned()
            .collect();
        if !self.reliable_topology_candidate_fits(&logical_topology, "logical topology update") {
            return;
        }
        let prior = self.pending_reply_source_authority.clone();
        self.pending_reply_source_authority.topology = Some(update);
        if let Some(validator_dial_roster) = validator_dial_roster {
            self.pending_reply_source_authority.validator_dial_roster = Some(validator_dial_roster);
        }
        self.accept_staged_reply_source_authority(prior, transition);
    }
    fn apply_reply_source_acl(&mut self, acl: ValidatedAclUpdate) {
        let ValidatedAclUpdate {
            allowlist_only,
            allow_keys,
            deny_keys,
            allow_nets,
            deny_nets,
        } = acl;
        self.allowlist_only = allowlist_only;
        self.allow_keys = allow_keys.into_iter().collect();
        self.deny_keys = deny_keys.into_iter().collect();
        self.allow_nets = allow_nets;
        self.deny_nets = deny_nets;
        self.requested_topology.retain(|peer_id| {
            let key = peer_id.public_key();
            !self.deny_keys.contains(key) && (!self.allowlist_only || self.allow_keys.contains(key))
        });
        self.current_topology.retain(|peer_id| {
            let key = peer_id.public_key();
            !self.deny_keys.contains(key) && (!self.allowlist_only || self.allow_keys.contains(key))
        });
        let deny_keys = &self.deny_keys;
        let allow_keys = &self.allow_keys;
        let allowlist_only = self.allowlist_only;
        let identity_allowed = |peer_id: &PeerId| {
            let key = peer_id.public_key();
            !deny_keys.contains(key) && (!allowlist_only || allow_keys.contains(key))
        };
        self.relay_trusted_peers.retain(identity_allowed);
        self.refresh_relay_hub_candidates();
        if self
            .relay_hub_peer
            .as_ref()
            .is_some_and(|peer_id| !self.relay_trusted_peers.contains(peer_id))
        {
            self.relay_hub_peer = None;
        }
    }
    fn apply_reply_source_trusted(&mut self, UpdateTrustedPeers(trusted): UpdateTrustedPeers) {
        self.peer_reputations.set_trusted(&trusted);
        let relay_hub_peer = self.verified_relay_hub_peer();
        self.current_topology =
            self.relay_topology_candidate(self.requested_topology.clone(), relay_hub_peer.as_ref());
        self.relay_hub_peer = relay_hub_peer;
        self.apply_trusted_observers();
    }
    fn apply_current_topology(&mut self, UpdateTopology(topology): UpdateTopology) {
        iroha_logger::debug!(?topology, "Network receive new topology");
        let logical_topology: HashSet<_> = topology
            .into_iter()
            .filter(|peer_id| peer_id.public_key() != self.key_pair.public_key())
            .filter(|peer_id| {
                let pk = peer_id.public_key();
                if self.deny_keys.contains(pk) {
                    return false;
                }
                if self.allowlist_only && !self.allow_keys.contains(pk) {
                    return false;
                }
                true
            })
            .collect();
        if !self.reliable_topology_candidate_fits(&logical_topology, "logical topology update") {
            return;
        }
        let relay_hub_peer = self.verified_relay_hub_peer();
        if relay_hub_peer.is_none()
            && matches!(
                self.relay_mode,
                iroha_config::parameters::actual::RelayMode::Spoke
                    | iroha_config::parameters::actual::RelayMode::Assist
            )
        {
            iroha_logger::warn!(
                relay_mode = ?self.relay_mode,
                relay_hub_addresses = ?self.relay_hub_addresses,
                "Relay mode has no reachable hub peer id"
            );
        }
        let topology =
            self.relay_topology_candidate(logical_topology.clone(), relay_hub_peer.as_ref());
        if !self.reliable_topology_candidate_fits(&topology, "topology update") {
            return;
        }
        // Commit the coupled topology/hub snapshot only after validating its
        // final relay-aware geometry. A rejected public update therefore cannot
        // partially rotate the assist route while leaving the old topology.
        self.relay_hub_peer = relay_hub_peer;
        self.requested_topology = logical_topology;
        self.current_topology = topology;
        self.apply_trusted_observers();
        self.update_topology()
    }
    fn allow_trusted_observers(&self) -> bool {
        self.is_permissioned_consensus()
            && !matches!(
                self.relay_mode,
                iroha_config::parameters::actual::RelayMode::Spoke
            )
    }
    fn apply_trusted_observers(&mut self) -> bool {
        if !self.allow_trusted_observers() {
            return false;
        }
        if self.current_topology.is_empty() {
            return false;
        }
        let mut updated = self.current_topology.clone();
        updated.retain(|peer_id| {
            let pk = peer_id.public_key();
            !self.deny_keys.contains(pk) && (!self.allowlist_only || self.allow_keys.contains(pk))
        });
        for peer_id in self.peer_reputations.trusted_peers() {
            if peer_id.public_key() == self.key_pair.public_key() {
                continue;
            }
            let pk = peer_id.public_key();
            if self.deny_keys.contains(pk) {
                continue;
            }
            if self.allowlist_only && !self.allow_keys.contains(pk) {
                continue;
            }
            updated.insert(peer_id);
        }
        let target_capacity = self.reliable_actor_target_capacity();
        if updated.len() > target_capacity {
            iroha_logger::warn!(
                topology_len = self.current_topology.len(),
                trusted_topology_len = updated.len(),
                target_capacity,
                "Skipping trusted observers which exceed reliable fanout geometry"
            );
            return false;
        }
        if updated != self.current_topology {
            self.current_topology = updated;
            return true;
        }
        false
    }
    fn set_current_peers_addresses(&mut self, UpdatePeers(peers): UpdatePeers) {
        debug!(
            total = peers.len(),
            local_known = self.peers.len(),
            relay_mode = ?self.relay_mode,
            relay_hub_addresses = ?self.relay_hub_addresses,
            "Network receive new peers addresses",
        );
        let preserved_hub = if matches!(
            self.relay_mode,
            iroha_config::parameters::actual::RelayMode::Spoke
                | iroha_config::parameters::actual::RelayMode::Assist
        ) {
            self.relay_hub_peer.as_ref().and_then(|hub| {
                self.address_book
                    .get(hub)
                    .cloned()
                    .map(|addr| (hub.clone(), addr))
            })
        } else {
            None
        };
        self.address_book.clear();
        for (pid, addr) in &peers {
            self.address_book.insert(pid.clone(), addr.clone());
        }
        self.current_peers_addresses = peers;
        if let Some((hub_id, hub_addr)) = preserved_hub {
            self.address_book
                .entry(hub_id.clone())
                .or_insert_with(|| hub_addr.clone());
            if !self
                .current_peers_addresses
                .iter()
                .any(|(id, _)| id == &hub_id)
            {
                self.current_peers_addresses.push((hub_id, hub_addr));
            }
        }
        // Address publication is a replacing authority snapshot. Revoke stale
        // pending and backoff owners before scheduling the new endpoints so a
        // retry retained across the update cannot dial a superseded address.
        let configured_targets: HashSet<_> = self
            .current_peers_addresses
            .iter()
            .map(|(peer_id, address)| (peer_id.clone(), address.to_string()))
            .collect();
        self.pending_connects.retain(|(_, peer)| {
            configured_targets.contains(&(peer.id().clone(), peer.address().to_string()))
        });
        self.retry_backoff.retain(|peer_id, by_address| {
            by_address.retain(|address, _| {
                configured_targets.contains(&(peer_id.clone(), address.clone()))
            });
            !by_address.is_empty()
        });
        // Address publication grants dial capability only. Relay authority is
        // retained solely for identities previously proven by an exact
        // outbound configured-hub dial.
        self.refresh_relay_hub_candidates();
        // Apply address updates immediately to reduce startup latency and
        // speed up recovery after gossip/DNS refresh. This keeps connection
        // attempts responsive instead of waiting for the periodic tick.
        self.update_topology();
    }
    fn set_peer_capabilities(
        &mut self,
        message::UpdatePeerCapabilities(capabilities): message::UpdatePeerCapabilities,
    ) {
        self.peer_capabilities = capabilities
            .into_iter()
            .filter(|(peer_id, _)| peer_id.public_key() != self.key_pair.public_key())
            .collect();
    }
    fn set_validator_dial_roster(&mut self, roster: message::UpdateValidatorDialRoster) {
        let prior = self.pending_reply_source_authority.clone();
        self.pending_reply_source_authority.validator_dial_roster = Some(roster);
        // Existing authenticated sessions are deliberately retained. The
        // roster commits through the same authority transaction as topology so
        // pending membership changes cannot expose an unmanaged validator.
        self.accept_staged_reply_source_authority(prior, "validator dial roster update");
    }
    fn update_topology(&mut self) {
        if !self.pending_reply_source_authority.is_empty()
            && !self.retry_pending_reply_source_authority()
        {
            return;
        }
        let now = tokio::time::Instant::now();
        // Hub selection and topology membership are one checked transition.
        // Computing both candidates first prevents an assist failover from
        // transiently exceeding the reliable-target geometry.
        let relay_hub_peer = self.verified_relay_hub_peer();
        let topology =
            self.relay_topology_candidate(self.current_topology.clone(), relay_hub_peer.as_ref());
        if self.reliable_topology_candidate_fits(&topology, "relay topology refresh") {
            self.relay_hub_peer = relay_hub_peer;
            self.current_topology = topology;
        }
        // Even when relay rotation is rejected, continue reconciling the prior
        // valid topology. ACL disconnects, deferred cancellation, and scheduled
        // dials must not depend on accepting an optional assist transition.
        let restrict_topology = self.is_permissioned_consensus()
            || matches!(
                self.relay_mode,
                iroha_config::parameters::actual::RelayMode::Spoke
            );
        let mut deferred_allowed = self.current_topology.clone();
        if !restrict_topology {
            deferred_allowed.extend(self.peers.keys().cloned());
        }
        let deferred_dropped = self.deferred_send_queue.retain_peers(&deferred_allowed);
        if deferred_dropped > 0 {
            DEFERRED_SEND_DROPPED.fetch_add(deferred_dropped as u64, Ordering::Relaxed);
            iroha_logger::debug!(
                deferred_dropped,
                "Dropped deferred frames for peers removed from the active topology"
            );
        }
        // Group candidate addresses by peer id for staggered parallel attempts
        let mut by_peer: HashMap<PeerId, Vec<SocketAddr>> = HashMap::new();
        for (id, address) in &self.current_peers_addresses {
            if !self.pending_reply_source_allows(id) {
                continue;
            }
            if !self.current_topology.contains(id) && !self.is_relay_hub_dial_identity(id) {
                continue;
            }
            // Skip already connected or already connecting for the same address
            if (self.peers.contains_key(id) && !self.requires_relay_hub_proof(id))
                || self
                    .connecting_peers
                    .values()
                    .any(|peer| (peer.id(), peer.address()) == (id, address))
            {
                continue;
            }
            if !self.ready_to_retry_addr(id, address, now) {
                continue;
            }
            by_peer.entry(id.clone()).or_default().push(address.clone());
        }
        // Order addresses by preference and schedule staggered attempts
        for (peer_id, mut addrs) in by_peer {
            let validator_not_before = self.validator_dial_scheduler.not_before(
                &self.self_id,
                &peer_id,
                now,
                self.connect_startup_delay_until,
            );
            addrs.sort_by_key(|a| self.addr_preference(a));
            for (i, addr) in addrs.into_iter().enumerate() {
                if self.is_scheduled(&peer_id, &addr) {
                    continue;
                }
                // Add small jitter to spread attempts in very large clusters
                let base = self
                    .happy_eyeballs_stagger
                    .saturating_mul(u32::try_from(i).unwrap_or(u32::MAX));
                let jitter_cap_ms =
                    u64::try_from(self.happy_eyeballs_stagger.as_millis() / 2).unwrap_or(u64::MAX);
                let jitter_ms = connect_attempt_jitter_ms(
                    &self.self_id,
                    &peer_id,
                    &addr,
                    i,
                    self.happy_eyeballs_stagger,
                    jitter_cap_ms,
                );
                let mut when = now + base + Duration::from_millis(jitter_ms);
                if let Some(validator_not_before) = validator_not_before {
                    when = core::cmp::max(when, validator_not_before);
                }
                let when = apply_connect_startup_delay(when, self.connect_startup_delay_until);
                self.pending_connects
                    .push((when, Peer::new(addr, peer_id.clone())));
            }
        }
        let to_disconnect = if restrict_topology {
            self.peers
                .keys()
                // Peer is connected but shouldn't
                .filter(|&peer_id| !self.current_topology.contains(peer_id))
                .cloned()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        // actual dialing is handled in process_pending_connects()
        for public_key in to_disconnect {
            self.disconnect_peer(&public_key)
        }
    }
    fn ensure_hub_peer(&mut self) -> Option<PeerId> {
        self.refresh_relay_hub_peer(tokio::time::Instant::now());
        self.relay_hub_peer.clone()
    }
    fn configured_hub_matches(&self, addr: &SocketAddr) -> bool {
        self.relay_hub_addresses.iter().any(|hub_addr| {
            addr == hub_addr
                || (addr.port() == hub_addr.port() && addr.host_str() == hub_addr.host_str())
        })
    }
    fn refresh_relay_hub_candidates(&mut self) {
        let candidates = if self.relay_hub_addresses.is_empty() {
            HashSet::new()
        } else {
            self.current_peers_addresses
                .iter()
                .filter(|(peer_id, address)| {
                    self.configured_hub_matches(address)
                        && self.projected_reply_source_acl_allows(peer_id)
                })
                .map(|(peer_id, _)| peer_id.clone())
                .collect()
        };
        self.relay_hub_candidates = candidates;
    }
    fn refresh_relay_hub_peer(&mut self, _now: tokio::time::Instant) {
        let relay_hub_peer = self.verified_relay_hub_peer();
        let topology =
            self.relay_topology_candidate(self.current_topology.clone(), relay_hub_peer.as_ref());
        if !self.reliable_topology_candidate_fits(&topology, "relay hub selection") {
            return;
        }
        self.relay_hub_peer = relay_hub_peer;
    }
    fn is_configured_hub_peer(&self, peer: &Peer, relay_role: RelayRole) -> bool {
        matches!(relay_role, RelayRole::Hub) && self.relay_trusted_peers.contains(peer.id())
    }
    fn is_relay_hub_dial_identity(&self, peer_id: &PeerId) -> bool {
        self.relay_hub_candidates.contains(peer_id) || self.relay_trusted_peers.contains(peer_id)
    }
    fn requires_relay_hub_proof(&self, peer_id: &PeerId) -> bool {
        self.relay_hub_candidates.contains(peer_id) && !self.relay_trusted_peers.contains(peer_id)
    }
    fn is_exact_relay_hub_dial_target(&self, peer: &Peer) -> bool {
        matches!(
            self.relay_mode,
            iroha_config::parameters::actual::RelayMode::Spoke
                | iroha_config::parameters::actual::RelayMode::Assist
        ) && self.is_relay_hub_dial_identity(peer.id())
            && self.configured_hub_matches(peer.address())
            && self.is_configured_dial_target(peer)
    }
    fn reserves_relay_hub_slot(&self) -> bool {
        if !matches!(
            self.relay_mode,
            iroha_config::parameters::actual::RelayMode::Spoke
                | iroha_config::parameters::actual::RelayMode::Assist
        ) || self.relay_hub_addresses.is_empty()
        {
            return false;
        }
        let authenticated_hub = self.peers.iter().any(|(peer_id, peer)| {
            matches!(peer.relay_role, RelayRole::Hub) && self.relay_trusted_peers.contains(peer_id)
        });
        let exact_hub_dial_inflight = self.connecting_peers.iter().any(|(conn_id, peer)| {
            self.outbound_connections.contains(conn_id) && self.is_exact_relay_hub_dial_target(peer)
        });
        !authenticated_hub && !exact_hub_dial_inflight
    }
    fn hub_handle(&mut self) -> Option<(&PeerId, &RefPeer<WireMessage<T>>)> {
        self.refresh_relay_hub_peer(tokio::time::Instant::now());
        let hub = self.relay_hub_peer.as_ref()?;
        self.peers.get_key_value(hub)
    }
    fn relay_route_for_unconnected_post_target(&mut self, target: &PeerId) -> Option<PeerId> {
        if !matches!(
            self.relay_mode,
            iroha_config::parameters::actual::RelayMode::Spoke
                | iroha_config::parameters::actual::RelayMode::Assist
        ) {
            return None;
        }
        if self.peers.contains_key(target) {
            return None;
        }
        let hub_id = self.ensure_hub_peer()?;
        if &hub_id == target {
            return None;
        }
        Some(hub_id)
    }
    fn resolve_origin_peer(&self, origin: &PeerId, via: &Peer) -> Peer {
        self.address_book.get(origin).map_or_else(
            || Peer::new(via.address().clone(), origin.clone()),
            |addr| Peer::new(addr.clone(), origin.clone()),
        )
    }
    fn record_trust_gossip_skip(peer_id: &PeerId, direction: TrustDirection, reason: &'static str) {
        inc_trust_gossip_skipped(direction.as_label(), reason);
        iroha_logger::debug!(
            peer=%peer_id,
            ?direction,
            reason,
            "trust gossip skipped: capability off"
        );
    }
    fn trigger_reconnect_for_peer(&mut self, peer_id: &PeerId) -> bool {
        if !self.current_topology.contains(peer_id) || !self.pending_reply_source_allows(peer_id) {
            return false;
        }
        if self.peers.contains_key(peer_id)
            || self
                .connecting_peers
                .values()
                .any(|peer| peer.id() == peer_id)
        {
            return false;
        }
        let now = tokio::time::Instant::now();
        let Some(addr) = self
            .current_peers_addresses
            .iter()
            .find_map(|(id, addr)| (id == peer_id).then_some(addr.clone()))
        else {
            return false;
        };
        if self.is_scheduled(peer_id, &addr) {
            return false;
        }
        let peer = Peer::new(addr.clone(), peer_id.clone());
        let validator_not_before = self.validator_dial_scheduler.not_before(
            &self.self_id,
            peer_id,
            now,
            self.connect_startup_delay_until,
        );
        let backoff_not_before = self
            .retry_backoff
            .get(peer_id)
            .and_then(|inner| inner.get(&addr.to_string()).map(|(when, _)| *when));
        let not_before = validator_not_before
            .into_iter()
            .chain(backoff_not_before)
            .fold(self.connect_startup_delay_until, core::cmp::max);
        if now >= not_before {
            if !self.connect_peer(&peer) {
                let when = apply_connect_startup_delay(
                    now + Duration::from_millis(50),
                    self.connect_startup_delay_until,
                );
                self.pending_connects.push((when, peer));
            }
        } else {
            self.pending_connects.push((not_before, peer));
        }
        SESSION_RECONNECT_TOTAL.fetch_add(1, Ordering::Relaxed);
        true
    }
    fn defer_frame(
        &mut self,
        peer_id: &PeerId,
        frame: RelayMessage<T>,
        topic: message::Topic,
        bound_connection_id: Option<ConnectionId>,
        trigger_reconnect: bool,
        reason: &'static str,
    ) -> bool {
        let now = tokio::time::Instant::now();
        let DeferredEnqueueOutcome {
            expired,
            overflow,
            enqueued,
        } = self.deferred_send_queue.enqueue(
            peer_id.clone(),
            frame,
            topic,
            bound_connection_id,
            now,
        );
        if enqueued {
            DEFERRED_SEND_ENQUEUED.fetch_add(1, Ordering::Relaxed);
            if self.peers.contains_key(peer_id) {
                self.deferred_send_queue.schedule_retry(peer_id);
            }
        }
        let dropped = expired.saturating_add(overflow);
        if dropped > 0 {
            DEFERRED_SEND_DROPPED.fetch_add(dropped as u64, Ordering::Relaxed);
        }
        if enqueued && trigger_reconnect {
            let _ = self.trigger_reconnect_for_peer(peer_id);
        }
        debug!(
            peer = %peer_id,
            ?bound_connection_id,
            trigger_reconnect,
            enqueued,
            expired_dropped = expired,
            overflow_dropped = overflow,
            reason,
            "deferred outbound frame while peer session unavailable"
        );
        enqueued
    }
    fn defer_missing_session_frame(
        &mut self,
        peer_id: &PeerId,
        frame: RelayMessage<T>,
        topic: message::Topic,
        is_progress: bool,
        reason: &'static str,
    ) -> bool {
        if matches!(topic, message::Topic::Control) && !is_progress {
            iroha_logger::warn!(
                peer = %peer_id,
                "Peer session is missing; dropping non-progress control frame"
            );
            return false;
        }
        let enqueued = self.defer_frame(peer_id, frame, topic, None, !is_progress, reason);
        if is_progress {
            // Reconnect scheduling is independent from bounded admission.  A
            // full deferred owner must report failure to the caller, but must
            // not suppress the coalesced attempt to restore a live session.
            let scheduled_reconnect = self.trigger_reconnect_for_peer(peer_id);
            iroha_logger::debug!(
                peer = %peer_id,
                ?topic,
                enqueued,
                scheduled_reconnect,
                reason,
                "Retained topic-qualified progress for a missing peer session"
            );
        }
        enqueued
    }
    fn flush_deferred_frames_for_peer_once(&mut self, peer_id: &PeerId) -> DeferredFlushOutcome {
        let now = tokio::time::Instant::now();
        let (mut queued, expired) = self.deferred_send_queue.take_peer(peer_id, now);
        if expired > 0 {
            DEFERRED_SEND_DROPPED.fetch_add(expired as u64, Ordering::Relaxed);
        }
        if queued.is_empty() {
            return DeferredFlushOutcome::Flushed;
        }
        // A full safety transport lane must not prevent an independent progress
        // lane from being attempted forever.  Hold at most one blocked safety
        // frame while probing the first queued ordinary progress witness.  The
        // blocked frame is always restored ahead of the remaining work, so the
        // probe cannot reorder two safety frames or lose their exact ownership.
        let mut blocked_safety = None;
        while let Some(mut entry) = queued.pop_front() {
            let Some(ref_peer) = self.peers.get(peer_id) else {
                queued.push_front(entry);
                if let Some(blocked) = blocked_safety.take() {
                    queued.push_front(blocked);
                }
                self.deferred_send_queue
                    .restore_peer(peer_id.clone(), queued);
                return DeferredFlushOutcome::PeerMissing;
            };
            let conn_id = ref_peer.conn_id;
            let peer_addr = ref_peer.p2p_addr.clone();
            if entry
                .bound_connection_id
                .is_some_and(|bound_connection_id| bound_connection_id != ref_peer.conn_id)
            {
                if entry.is_progress() {
                    // A reconnect changes only the bound transport connection. The
                    // durable semantic intent is retagged to the authenticated
                    // replacement session and keeps its exact queue position.
                    let prior_connection_id = entry.bound_connection_id.take();
                    iroha_logger::debug!(
                        peer = %peer_id,
                        prior_connection_id = ?prior_connection_id,
                        replacement_connection_id = ?ref_peer.conn_id,
                        topic = ?entry.topic,
                        "Retagging reliable deferred frame across peer connection replacement"
                    );
                } else {
                    DEFERRED_SEND_DROPPED.fetch_add(1, Ordering::Relaxed);
                    self.deferred_send_queue.note_served(peer_id, entry.topic);
                    if let Some(blocked) = blocked_safety.take() {
                        queued.push_front(blocked);
                        self.deferred_send_queue
                            .restore_peer(peer_id.clone(), queued);
                        return DeferredFlushOutcome::Backpressured(conn_id);
                    }
                    continue;
                }
            }
            if !trust_gossip_allowed(entry.topic, ref_peer.trust_gossip && self.trust_gossip) {
                let reason = if self.trust_gossip {
                    "peer_capability_off"
                } else {
                    "local_capability_off"
                };
                Self::record_trust_gossip_skip(peer_id, TrustDirection::Outbound, reason);
                self.deferred_send_queue.note_served(peer_id, entry.topic);
                if let Some(blocked) = blocked_safety.take() {
                    queued.push_front(blocked);
                    self.deferred_send_queue
                        .restore_peer(peer_id.clone(), queued);
                    return DeferredFlushOutcome::Backpressured(conn_id);
                }
                continue;
            }
            let DeferredPeerFrame {
                frame,
                topic,
                enqueued_at,
                bound_connection_id,
                wire_bytes,
                sequence,
                _aggregate_lease: aggregate_lease,
            } = entry;
            match ref_peer.handle.post_recover(frame) {
                Ok(()) => {
                    self.deferred_send_queue.note_served(peer_id, topic);
                    if let Some(blocked) = blocked_safety.take() {
                        queued.push_front(blocked);
                        self.deferred_send_queue
                            .restore_peer(peer_id.clone(), queued);
                        return DeferredFlushOutcome::Backpressured(conn_id);
                    }
                }
                Err(error @ RecoverPostError::Full(_)) => {
                    let retry_entry = DeferredPeerFrame {
                        frame: error.into_message(),
                        topic,
                        enqueued_at,
                        bound_connection_id,
                        wire_bytes,
                        sequence,
                        _aggregate_lease: aggregate_lease,
                    };
                    if matches!(topic, message::Topic::ConsensusSafety)
                        && blocked_safety.is_none()
                        && let Some(progress_index) = queued.iter().position(|entry| {
                            !matches!(entry.topic, message::Topic::ConsensusSafety)
                                && entry.is_progress()
                        })
                    {
                        blocked_safety = Some(retry_entry);
                        let progress = queued
                            .remove(progress_index)
                            .expect("located deferred progress entry must still exist");
                        queued.push_front(progress);
                        continue;
                    }
                    queued.push_front(retry_entry);
                    if let Some(blocked) = blocked_safety.take() {
                        queued.push_front(blocked);
                    }
                    self.deferred_send_queue
                        .restore_peer(peer_id.clone(), queued);
                    return DeferredFlushOutcome::Backpressured(conn_id);
                }
                Err(error @ RecoverPostError::Closed(_)) => {
                    let retry_entry = DeferredPeerFrame {
                        frame: error.into_message(),
                        topic,
                        enqueued_at,
                        bound_connection_id: None,
                        wire_bytes,
                        sequence,
                        _aggregate_lease: aggregate_lease,
                    };
                    let peer = Peer::new(peer_addr, peer_id.clone());
                    iroha_logger::warn!(
                        peer=%peer,
                        "Peer channel closed while flushing deferred frames; retaining unsent frame"
                    );
                    if let Some(ref_peer) = self.peers.remove(peer_id) {
                        ref_peer.handle.request_termination();
                        self.mark_connection_terminating(conn_id);
                        self.peer_reputations.record_disconnected(peer_id);
                    }
                    Self::remove_online_peer(
                        &self.online_peers_sender,
                        &self.online_peer_capabilities_sender,
                        peer_id,
                    );
                    self.last_active.remove(peer_id);
                    self.clear_low_buckets(peer_id);
                    for deferred in &mut queued {
                        deferred.bound_connection_id = None;
                    }
                    queued.push_front(retry_entry);
                    if let Some(mut blocked) = blocked_safety.take() {
                        blocked.bound_connection_id = None;
                        queued.push_front(blocked);
                    }
                    self.deferred_send_queue
                        .restore_peer(peer_id.clone(), queued);
                    return DeferredFlushOutcome::PeerMissing;
                }
            }
        }
        self.deferred_send_queue.reset_service_rank(peer_id);
        DeferredFlushOutcome::Flushed
    }
    fn flush_deferred_frames_for_peer(&mut self, peer_id: &PeerId) -> DeferredFlushOutcome {
        let outcome = self.flush_deferred_frames_for_peer_once(peer_id);
        if matches!(outcome, DeferredFlushOutcome::Backpressured(_)) {
            self.deferred_send_queue.schedule_retry(peer_id);
        } else {
            self.deferred_send_queue.cancel_retry(peer_id);
        }
        outcome
    }
    fn retry_deferred_frames(&mut self) {
        let peers = self
            .deferred_send_queue
            .take_retry_batch(DEFERRED_RETRY_PEER_BUDGET);
        for peer_id in peers {
            if matches!(
                self.flush_deferred_frames_for_peer(&peer_id),
                DeferredFlushOutcome::PeerMissing
            ) {
                let _ = self.trigger_reconnect_for_peer(&peer_id);
            }
        }
    }
    /// Attempt one actor-owned reliable frame directly against the current
    /// peer-writer connection.
    ///
    /// This corridor intentionally bypasses `DeferredPeerFrameQueue`: the
    /// opaque actor item remains the sole semantic owner until the returned
    /// receiver observes a successful full write and flush.  Missing, closed,
    /// or replaced sessions therefore yield `Retry` and trigger the ordinary
    /// reconnect machinery without manufacturing a second durable owner.
    /// Exact replies retain their actor occurrence when the queue is full even
    /// if best-effort overflow policy requests disconnection; their immutable
    /// actor deadline owns that retirement decision.
    fn post_reliable_actor_frame_to_writer(
        &mut self,
        peer_id: &PeerId,
        frame: &RelayMessage<T>,
        topic: message::Topic,
        exact_reply: bool,
    ) -> ReliableWriterAttempt {
        if !message::ClassifyTopic::is_outbound_allowed(frame) {
            iroha_logger::error!(
                peer = %peer_id,
                ?topic,
                "Reliable actor admitted a frame forbidden by the outbound boundary"
            );
            return ReliableWriterAttempt::Retry;
        }
        if peer_id.public_key() == self.key_pair.public_key() {
            return ReliableWriterAttempt::Retry;
        }
        let Some(ref_peer) = self.peers.get(peer_id) else {
            let _ = self.trigger_reconnect_for_peer(peer_id);
            return ReliableWriterAttempt::Retry;
        };
        if !trust_gossip_allowed(topic, ref_peer.trust_gossip && self.trust_gossip) {
            let reason = if self.trust_gossip {
                "peer_capability_off"
            } else {
                "local_capability_off"
            };
            Self::record_trust_gossip_skip(peer_id, TrustDirection::Outbound, reason);
            return ReliableWriterAttempt::Retry;
        }
        let is_high = matches!(message::ClassifyTopic::priority(frame), Priority::High);
        let is_consensus = is_consensus_topic(topic);
        let conn_id = ref_peer.conn_id;
        let p2p_addr = ref_peer.p2p_addr.clone();
        // Clone only after every route/session/capability preflight passes.
        // Missing-session retries therefore touch only the actor's `Arc` and
        // never allocate another relay envelope.
        match ref_peer.handle.post_recover_with_flush_ack(frame.clone()) {
            Ok(receiver) => {
                if is_consensus {
                    iroha_logger::debug!(
                        peer = %peer_id,
                        high = is_high,
                        conn_id,
                        "reliable consensus frame is awaiting peer-writer flush"
                    );
                }
                ReliableWriterAttempt::Awaiting(PendingWriterFlush { receiver })
            }
            Err(error) => {
                let closed = matches!(&error, RecoverPostError::Closed(_));
                if !closed {
                    POST_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
                    inc_post_overflow_for_prio(topic, is_high);
                }
                drop(error.into_message());
                if closed || (self.disconnect_on_post_overflow && !exact_reply) {
                    let peer = Peer::new(p2p_addr, peer_id.clone());
                    iroha_logger::warn!(
                        peer = %peer,
                        conn_id,
                        closed,
                        "Reliable peer writer unavailable; retaining actor ownership"
                    );
                    if self
                        .peers
                        .get(peer_id)
                        .is_some_and(|current| current.conn_id == conn_id)
                    {
                        let removed = self
                            .peers
                            .remove(peer_id)
                            .expect("checked peer connection must still exist");
                        removed.handle.request_termination();
                        self.deferred_send_queue
                            .release_retired_tenure_binding(peer_id, conn_id);
                        self.mark_connection_terminating(conn_id);
                        self.peer_reputations.record_disconnected(peer_id);
                        Self::remove_online_peer(
                            &self.online_peers_sender,
                            &self.online_peer_capabilities_sender,
                            peer_id,
                        );
                        self.last_active.remove(peer_id);
                        self.clear_low_buckets(peer_id);
                    }
                    let _ = self.trigger_reconnect_for_peer(peer_id);
                }
                ReliableWriterAttempt::Retry
            }
        }
    }
    fn send_frame_to_peer(
        &mut self,
        peer_id: &PeerId,
        frame: RelayMessage<T>,
        topic: message::Topic,
    ) -> bool {
        if !message::ClassifyTopic::is_outbound_allowed(&frame) {
            iroha_logger::warn!(
                peer = %peer_id,
                ?topic,
                "Rejected an outbound relay frame at the P2P admission boundary"
            );
            return false;
        }
        let is_high = matches!(message::ClassifyTopic::priority(&frame), Priority::High);
        let is_consensus = is_consensus_topic(topic);
        let is_progress = is_reliable_progress_route(
            topic,
            message::ClassifyTopic::subscriber_route(&frame.payload),
        );
        if is_progress
            && matches!(
                frame.payload.progress_reconstruction(),
                message::ProgressReconstruction::Exact
            )
        {
            iroha_logger::error!(
                peer = %peer_id,
                ?topic,
                "Rejected reliable progress without a durable reconstruction contract"
            );
            return false;
        }
        if matches!(topic, message::Topic::BlockSync) {
            iroha_logger::debug!(
                peer=%peer_id,
                high=is_high,
                "enqueueing block sync frame to peer"
            );
        }
        let Some(_) = self.peers.get(peer_id) else {
            if peer_id.public_key() == self.key_pair.public_key() {
                #[cfg(debug_assertions)]
                iroha_logger::trace!("Not sending message to myself");
                return false;
            }
            if !self.current_topology.contains(peer_id) {
                if is_progress {
                    let reconstruction = frame.payload.progress_reconstruction();
                    iroha_logger::warn!(
                        peer = %peer_id,
                        ?topic,
                        ?reconstruction,
                        "Reliable target outside current topology has no exact downstream owner"
                    );
                    return false;
                }
                iroha_logger::warn!(
                    peer=%peer_id,
                    "Peer is outside the current topology; dropping outbound frame"
                );
                return false;
            }
            return self.defer_missing_session_frame(
                peer_id,
                frame,
                topic,
                is_progress,
                "peer session missing",
            );
        };
        match self.flush_deferred_frames_for_peer(peer_id) {
            DeferredFlushOutcome::Flushed => {}
            DeferredFlushOutcome::PeerMissing => {
                return self.defer_missing_session_frame(
                    peer_id,
                    frame,
                    topic,
                    is_progress,
                    "peer session missing after deferred flush",
                );
            }
            DeferredFlushOutcome::Backpressured(conn_id) => {
                return self.defer_frame(
                    peer_id,
                    frame,
                    topic,
                    Some(conn_id),
                    false,
                    "peer backpressured while flushing deferred frames",
                );
            }
        }
        let Some(ref_peer) = self.peers.get(peer_id) else {
            return self.defer_missing_session_frame(
                peer_id,
                frame,
                topic,
                is_progress,
                "peer session disappeared before post",
            );
        };
        if !trust_gossip_allowed(topic, ref_peer.trust_gossip && self.trust_gossip) {
            let reason = if self.trust_gossip {
                "peer_capability_off"
            } else {
                "local_capability_off"
            };
            Self::record_trust_gossip_skip(peer_id, TrustDirection::Outbound, reason);
            return false;
        }
        let (conn_id, p2p_addr) = (ref_peer.conn_id, ref_peer.p2p_addr.clone());
        let (retry_frame, outcome) = match ref_peer.handle.post_recover(frame) {
            Ok(()) => {
                if is_consensus {
                    iroha_logger::debug!(
                        peer=%peer_id,
                        high=is_high,
                        "consensus frame enqueued to peer"
                    );
                }
                return true;
            }
            Err(RecoverPostError::Closed(frame)) => {
                let peer = Peer::new(p2p_addr.clone(), peer_id.clone());
                iroha_logger::error!(peer=%peer, "Peer channel closed; dropping peer");
                (frame, Some(peer))
            }
            Err(RecoverPostError::Full(frame)) => {
                POST_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
                inc_post_overflow_for_prio(topic, is_high);
                if self.disconnect_on_post_overflow {
                    let peer = Peer::new(p2p_addr.clone(), peer_id.clone());
                    iroha_logger::warn!(
                        peer=%peer,
                        consensus=is_consensus,
                        high=is_high,
                        "Per-peer post channel overflow; disconnecting per policy"
                    );
                    (frame, Some(peer))
                } else {
                    iroha_logger::warn!(
                        peer=%peer_id,
                        consensus=is_consensus,
                        high=is_high,
                        "Per-peer post channel overflow; dropping message per policy"
                    );
                    return self.defer_frame(
                        peer_id,
                        frame,
                        topic,
                        Some(conn_id),
                        false,
                        "peer post queue full",
                    );
                }
            }
        };
        if outcome.is_some() {
            if let Some(ref_peer) = self.peers.remove(peer_id) {
                ref_peer.handle.request_termination();
                self.deferred_send_queue
                    .release_retired_tenure_binding(peer_id, conn_id);
                self.mark_connection_terminating(conn_id);
                self.peer_reputations.record_disconnected(peer_id);
            }
            Self::remove_online_peer(
                &self.online_peers_sender,
                &self.online_peer_capabilities_sender,
                peer_id,
            );
            self.last_active.remove(peer_id);
            self.clear_low_buckets(peer_id);
            return self.defer_missing_session_frame(
                peer_id,
                retry_frame,
                topic,
                is_progress,
                "peer disconnected while posting frame",
            );
        }
        false
    }
    fn ready_to_retry_addr(
        &self,
        id: &PeerId,
        addr: &SocketAddr,
        now: tokio::time::Instant,
    ) -> bool {
        let key = addr.to_string();
        self.retry_backoff
            .get(id)
            .and_then(|m| m.get(&key))
            .is_none_or(|(when, _)| now >= *when)
    }
    fn schedule_backoff_addr(&mut self, id: &PeerId, addr: &SocketAddr) {
        let now = tokio::time::Instant::now();
        let key = addr.to_string();
        let base = self
            .retry_backoff
            .get(id)
            .and_then(|m| m.get(&key).map(|(_, b)| *b))
            .unwrap_or(BACKOFF_INITIAL);
        let next_base = core::cmp::min(BACKOFF_MAX, base.saturating_mul(2));
        let upper_ms = u64::try_from(next_base.as_millis()).unwrap_or(u64::MAX);
        let jitter_ms =
            reconnect_backoff_jitter_ms(&self.self_id, id, addr, base, next_base, upper_ms);
        CONNECT_RETRY_MILLIS_TOTAL.fetch_add(jitter_ms, Ordering::Relaxed);
        let when = now + Duration::from_millis(jitter_ms);
        self.retry_backoff
            .entry(id.clone())
            .or_default()
            .insert(key, (when, next_base));
        // The backoff entry is only an admission deadline; it does not wake the
        // connection actor by itself.  Retain one exact pending dial owner so a
        // failed configured-peer attempt resumes at that deadline even when no
        // later topology update or outbound frame happens to arrive.
        if let Some((pending_when, _)) = self
            .pending_connects
            .iter_mut()
            .find(|(_, pending)| pending.id() == id && pending.address() == addr)
        {
            *pending_when = core::cmp::max(*pending_when, when);
        } else {
            self.pending_connects
                .push((when, Peer::new(addr.clone(), id.clone())));
        }
        BACKOFF_SCHEDULED.fetch_add(1, Ordering::Relaxed);
        iroha_logger::debug!(peer=%id, addr=%addr, delay=?next_base, until=?when, "Scheduled reconnect backoff");
    }
    fn reset_backoff_addr(&mut self, id: &PeerId, addr: &SocketAddr) {
        let key = addr.to_string();
        if let Some(inner) = self.retry_backoff.get_mut(id) {
            inner.remove(&key);
            if inner.is_empty() {
                self.retry_backoff.remove(id);
            }
        }
    }
    fn is_configured_dial_target(&self, peer: &Peer) -> bool {
        self.current_peers_addresses
            .iter()
            .any(|(peer_id, address)| peer_id == peer.id() && address == peer.address())
    }
    fn has_configured_dial_identity(&self, id: &PeerId) -> bool {
        self.current_peers_addresses
            .iter()
            .any(|(peer_id, _)| peer_id == id)
    }
    fn schedule_retry_for_terminated_peer(&mut self, failed: &Peer) {
        let id = failed.id();
        if !self.has_configured_dial_identity(id)
            || !self.pending_reply_source_allows(id)
            || (!self.current_topology.contains(id) && !self.is_relay_hub_dial_identity(id))
            || self.peers.contains_key(id)
            || self
                .connecting_peers
                .values()
                .any(|candidate| candidate.id() == id && candidate.address() == failed.address())
        {
            return;
        }
        if self.is_configured_dial_target(failed) {
            self.schedule_backoff_addr(id, failed.address());
        } else {
            // The failed connection belonged to a configured identity but its
            // endpoint has since been replaced (or it advertised a different
            // public address). Reconcile the current snapshot immediately;
            // the replacement endpoint has not failed and must not inherit the
            // obsolete endpoint's exponential backoff.
            self.update_topology();
        }
    }
    fn is_permissioned_consensus(&self) -> bool {
        self.consensus_caps
            .as_ref()
            .is_none_or(|caps| matches!(caps.mode, crate::ConsensusMode::Permissioned))
    }
    fn reply_source_capacity(&self) -> usize {
        self.max_total_connections.unwrap_or(
            iroha_config::parameters::defaults::network::lane_profile::CORE_MAX_TOTAL_CONNECTIONS,
        )
    }
    fn verified_relay_hub_peer(&self) -> Option<PeerId> {
        if !matches!(
            self.relay_mode,
            iroha_config::parameters::actual::RelayMode::Spoke
                | iroha_config::parameters::actual::RelayMode::Assist
        ) {
            return None;
        }
        let selected = self.relay_hub_peer.as_ref()?;
        self.peers
            .get(selected)
            .filter(|peer| {
                matches!(peer.relay_role, RelayRole::Hub)
                    && self.relay_trusted_peers.contains(selected)
            })
            .map(|_| selected.clone())
    }
    fn projected_reply_source_acl_allows(&self, peer_id: &PeerId) -> bool {
        let pending_acl = self.pending_reply_source_authority.acl.as_ref();
        let key = peer_id.public_key();
        let denied = pending_acl.map_or_else(
            || self.deny_keys.contains(key),
            |acl| acl.deny_keys.contains(key),
        );
        let allowlist_only = pending_acl.map_or(self.allowlist_only, |acl| acl.allowlist_only);
        let allowlisted = pending_acl.map_or_else(
            || self.allow_keys.contains(key),
            |acl| acl.allow_keys.contains(key),
        );
        !denied && (!allowlist_only || allowlisted)
    }
    fn desired_reply_source_authority(&self) -> ReplySourceAuthorityProjection {
        let pending = &self.pending_reply_source_authority;
        let requested = pending
            .topology
            .as_ref()
            .map_or(&self.requested_topology, |update| &update.0);
        let mut direct: HashSet<_> = requested
            .iter()
            .filter(|peer_id| {
                *peer_id != &self.self_id && self.projected_reply_source_acl_allows(peer_id)
            })
            .cloned()
            .collect();
        let verified_hub = self
            .pending_configured_hub_source
            .clone()
            .or_else(|| self.verified_relay_hub_peer())
            .filter(|peer_id| self.projected_reply_source_acl_allows(peer_id));
        let protected_sources = match self.relay_mode {
            iroha_config::parameters::actual::RelayMode::Spoke => {
                verified_hub.into_iter().collect()
            }
            iroha_config::parameters::actual::RelayMode::Assist => {
                direct.extend(verified_hub);
                direct
            }
            iroha_config::parameters::actual::RelayMode::Disabled
            | iroha_config::parameters::actual::RelayMode::Hub => direct,
        };
        ReplySourceAuthorityProjection {
            reconciliation_topology: protected_sources.clone(),
            protected_sources,
        }
    }
    fn pending_reply_source_allows(&self, peer_id: &PeerId) -> bool {
        (self.pending_reply_source_authority.is_empty()
            && self.pending_configured_hub_source.is_none())
            || self
                .desired_reply_source_authority()
                .reconciliation_topology
                .contains(peer_id)
    }
    fn process_pending_connects(&mut self) {
        let now = tokio::time::Instant::now();
        let delay_until = self.connect_startup_delay_until;
        let mut rest = Vec::with_capacity(self.pending_connects.len());
        let mut due_peers = Vec::new();
        for (when, peer) in self.pending_connects.drain(..) {
            let when = apply_connect_startup_delay(when, delay_until);
            if when > now {
                rest.push((when, peer));
            } else {
                due_peers.push(peer);
            }
        }
        due_peers.sort_by(|a, b| {
            let ta = self.peer_reputations.is_trusted(a.id());
            let tb = self.peer_reputations.is_trusted(b.id());
            match tb.cmp(&ta) {
                std::cmp::Ordering::Equal => self
                    .peer_reputations
                    .score(b.id())
                    .cmp(&self.peer_reputations.score(a.id())),
                ord => ord,
            }
        });
        self.pending_connects = rest;
        for peer in due_peers {
            let id = peer.id().clone();
            let addr = peer.address().clone();
            if !self.pending_reply_source_allows(&id) {
                continue;
            }
            if !self.current_topology.contains(&id) && !self.is_relay_hub_dial_identity(&id) {
                continue;
            }
            if !self.is_configured_dial_target(&peer) {
                // Pending attempts are capabilities minted by an exact address
                // snapshot. Revalidate at execution time as a final fence
                // against a concurrent or directly staged replacement.
                self.reset_backoff_addr(&id, &addr);
                continue;
            }
            if self.peers.contains_key(&id) && !self.requires_relay_hub_proof(&id) {
                // A pending standby or Happy-Eyeballs attempt became obsolete
                // when either direction authenticated. Dropping it here avoids
                // a permanent 50 ms reschedule loop and leaves future reconnects
                // to the existing termination/backoff path.
                continue;
            }
            if let Some(not_before) = self.validator_dial_scheduler.not_before(
                &self.self_id,
                &id,
                now,
                self.connect_startup_delay_until,
            ) && not_before > now
            {
                self.pending_connects.push((not_before, peer));
                continue;
            }
            if self.exceeds_outbound_connection_cap(&peer) {
                // Outbound handshakes consume the same finite process slot as
                // accepted inbound and established connections. Keep the due
                // peer scheduled instead of spawning pre-authentication work
                // beyond the H + L + N*R transport geometry.
                let when = apply_connect_startup_delay(
                    now + Duration::from_millis(50),
                    self.connect_startup_delay_until,
                );
                self.pending_connects.push((when, peer));
                continue;
            }
            if !self
                .connecting_peers
                .values()
                .any(|p| (p.id(), p.address()) == (&id, &addr))
                && self.ready_to_retry_addr(&id, &addr, now)
            {
                if !self.connect_peer(&peer) {
                    let when = apply_connect_startup_delay(
                        now + Duration::from_millis(50),
                        self.connect_startup_delay_until,
                    );
                    self.pending_connects.push((when, peer));
                }
            } else {
                // Not ready; reschedule shortly to avoid starvation
                let when = apply_connect_startup_delay(
                    now + Duration::from_millis(50),
                    self.connect_startup_delay_until,
                );
                self.pending_connects.push((when, peer));
            }
        }
    }
    fn is_scheduled(&self, id: &PeerId, addr: &SocketAddr) -> bool {
        self.pending_connects
            .iter()
            .any(|(_, p)| p.id() == id && p.address() == addr)
    }
    fn addr_preference(&self, addr: &SocketAddr) -> u8 {
        if self.addr_ipv6_first {
            return match addr {
                SocketAddr::Ipv6(_) => 0,
                SocketAddr::Host(_) => 1,
                SocketAddr::Ipv4(_) => 2,
            };
        }
        match addr {
            SocketAddr::Host(_) => 0,
            SocketAddr::Ipv6(_) => 1,
            SocketAddr::Ipv4(_) => 2,
        }
    }
    fn connect_peer(&mut self, peer: &Peer) -> bool {
        if self.exceeds_outbound_connection_cap(peer) {
            return false;
        }
        let Some(authentication_deadline) =
            PreauthDeadline::from_now(self.outbound_authentication_timeout)
        else {
            iroha_logger::error!(
                "Refusing outbound handshake with an unrepresentable authentication deadline"
            );
            return false;
        };
        let soranet_policy = match self.soranet_handshake.snapshot() {
            Ok(policy) => policy,
            Err(error) => {
                iroha_logger::error!(
                    %error,
                    peer = %peer.id(),
                    "Refusing outbound handshake without a SoraNet policy snapshot"
                );
                return false;
            }
        };
        let trust_gossip = self.trust_gossip_config && soranet_policy.trust_gossip();
        iroha_logger::trace!(
            listen_addr = %self.listen_addr, peer.id.address = %peer.address(),
            "Creating new peer actor",
        );
        let conn_id = self.get_conn_id();
        let prefer_scion = self.local_scion_supported
            && self
                .peer_capabilities
                .get(peer.id())
                .is_some_and(|caps| caps.scion_supported);
        self.connecting_peers.insert(conn_id, peer.clone());
        self.outbound_connections.insert(conn_id);
        let service_message_sender = self.service_message_sender.clone();
        // The enabled transport retains its endpoint; the disabled handle is unit.
        #[cfg(feature = "quic")]
        let quic_dialer = self.quic_dialer.clone();
        #[cfg(not(feature = "quic"))]
        let quic_dialer = self.quic_dialer;
        let task = connecting::<WireMessage<T>, E>(
            // NOTE: we intentionally use peer's address and our public key, it's used during handshake
            peer.address().clone(),
            peer.id().clone(),
            self.public_address.clone(),
            Arc::clone(&self.key_pair),
            conn_id,
            service_message_sender,
            self.idle_timeout,
            self.dial_timeout,
            authentication_deadline,
            self.network_id,
            self.consensus_caps,
            self.confidential_caps.clone(),
            self.crypto_caps,
            soranet_policy,
            self.post_queue_cap,
            self.outbound_frame_queue_limits,
            self.outbound_post_byte_budgets.clone(),
            self.inbound_frame_byte_budgets.clone(),
            self.quic_enabled,
            prefer_scion,
            self.local_scion_supported,
            trust_gossip,
            self.max_frame_bytes,
            self.relay_role,
            self.happy_eyeballs_stagger,
            self.tcp_nodelay,
            self.tcp_keepalive,
            self.proxy_tls_verify,
            self.proxy_tls_pinned_cert_der.clone(),
            self.proxy_policy.clone(),
            Arc::clone(&self.outbound_dial_policy),
            quic_dialer,
            self.quic_datagrams_enabled,
            self.quic_datagram_max_payload_bytes,
        );
        self.peer_tasks.push(AbortOnDropTask::new(task));
        true
    }
    fn mark_connection_terminating(&mut self, conn_id: ConnectionId) {
        self.release_incoming_pending(conn_id);
        self.incoming_active.remove(&conn_id);
        if let Some(tenure) = self.reply_route_tenures.get(&conn_id) {
            tenure.mark_draining();
            let _ = self
                .network_actor_progress_budget
                .cancel_reply_route(tenure);
        }
        self.terminating_connections.insert(conn_id);
    }
    /// Drain one exact reply tenure whose peer writer exceeded its fixed deadline.
    ///
    /// Returns `true` only when this call removed and cancelled the same
    /// connection which originally accepted writer ownership. A delayed
    /// timeout can therefore never terminate a replacement connection.
    fn expire_reply_writer_occurrence(
        &mut self,
        route: &NetworkReplyRoute,
        connection_id: ConnectionId,
    ) -> bool {
        route.tenure.mark_draining();
        let _ = self
            .network_actor_progress_budget
            .cancel_reply_route(&route.tenure);
        if route.tenure.connection_id != connection_id {
            iroha_logger::error!(
                expected_connection_id = route.tenure.connection_id,
                connection_id,
                "Exact reply writer deadline carried a foreign connection"
            );
            return false;
        }
        let delivery_peer = route.tenure.delivery_peer.clone();
        if self
            .peers
            .get(&delivery_peer)
            .is_none_or(|current| current.conn_id != connection_id)
        {
            return false;
        }
        self.disconnect_peer(&delivery_peer);
        let _ = self.trigger_reconnect_for_peer(&delivery_peer);
        true
    }
    fn finish_reply_route_tenure(&mut self, conn_id: ConnectionId) -> usize {
        let Some(tenure) = self.reply_route_tenures.remove(&conn_id) else {
            self.terminating_connections.remove(&conn_id);
            self.protocol_rejected_connections.remove(&conn_id);
            return 0;
        };
        tenure.cancel();
        self.terminating_connections.remove(&conn_id);
        self.protocol_rejected_connections.remove(&conn_id);
        self.network_actor_progress_budget
            .cancel_reply_route(&tenure)
    }
    fn reject_protocol_tenure(
        &mut self,
        peer_id: &PeerId,
        connection_id: Option<ConnectionId>,
        reason: &'static str,
    ) {
        let Some(connection_id) = connection_id else {
            iroha_logger::warn!(peer = %peer_id, reason, "Dropping protocol violation without an exact tenure");
            return;
        };
        let owns_tenure = self
            .reply_route_tenures
            .get(&connection_id)
            .is_some_and(|tenure| &tenure.delivery_peer == peer_id)
            || self
                .peers
                .get(peer_id)
                .is_some_and(|current| current.conn_id == connection_id);
        if !owns_tenure {
            iroha_logger::warn!(peer = %peer_id, connection_id, reason, "Dropping protocol violation with mismatched tenure ownership");
            return;
        }
        self.protocol_rejected_connections.insert(connection_id);
        if self
            .peers
            .get(peer_id)
            .is_some_and(|current| current.conn_id == connection_id)
        {
            iroha_logger::warn!(peer = %peer_id, connection_id, reason, "Disconnecting exact peer tenure after protocol violation");
            self.disconnect_peer(peer_id);
        }
    }
    fn disconnect_peer(&mut self, peer_id: &PeerId) {
        let peer = match self.peers.remove(peer_id) {
            Some(peer) => peer,
            _ => return iroha_logger::warn!(?peer_id, "Not found peer to disconnect"),
        };
        iroha_logger::debug!(listen_addr = %self.listen_addr, %peer.conn_id, "Disconnecting peer");
        peer.handle.request_termination();
        self.deferred_send_queue
            .release_retired_tenure_binding(peer_id, peer.conn_id);
        self.mark_connection_terminating(peer.conn_id);
        self.peer_reputations.record_disconnected(peer_id);
        self.last_active.remove(peer_id);
        Self::remove_online_peer(
            &self.online_peers_sender,
            &self.online_peer_capabilities_sender,
            peer_id,
        );
        self.clear_low_buckets(peer_id);
        if !self.current_topology.contains(peer_id) {
            let deferred_dropped = self.deferred_send_queue.remove_peer(peer_id);
            if deferred_dropped > 0 {
                DEFERRED_SEND_DROPPED.fetch_add(deferred_dropped as u64, Ordering::Relaxed);
                iroha_logger::debug!(
                    peer=%peer_id,
                    deferred_dropped,
                    "Dropped deferred frames for a disconnected peer outside the active topology"
                );
            }
        }
    }
    fn reject_authenticated_tenure(
        &mut self,
        connection_id: ConnectionId,
        ready_peer_handle: PeerHandle<WireMessage<T>>,
        peer_message_sender: tokio::sync::oneshot::Sender<
            crate::peer::message::PeerMessageSenders<WireMessage<T>>,
        >,
    ) {
        self.reader_arbitration.cancel(connection_id);
        ready_peer_handle.request_termination();
        drop(peer_message_sender);
        // Keep this authenticated tenure charged against the total cap
        // until its exact `Terminated` witness arrives.
        self.mark_connection_terminating(connection_id);
    }
    #[log(skip_all, fields(peer=%peer, conn_id=connection_id, disambiguator=disambiguator))]
    fn peer_connected(
        &mut self,
        Connected {
            peer,
            connection_id,
            ready_peer_handle,
            peer_message_sender,
            delivery_drain,
            disambiguator,
            relay_role,
            scion_supported,
            trust_gossip,
        }: Connected<WireMessage<T>>,
    ) {
        if !self
            .reader_arbitration
            .claim_connected(connection_id, peer.id(), disambiguator)
        {
            self.reject_authenticated_tenure(connection_id, ready_peer_handle, peer_message_sender);
            return;
        }
        let dial_target = self.connecting_peers.remove(&connection_id);
        let proven_outbound_hub = matches!(relay_role, RelayRole::Hub)
            && self.outbound_connections.contains(&connection_id)
            && dial_target.as_ref().is_some_and(|target| {
                target.id() == peer.id() && self.configured_hub_matches(target.address())
            });
        let _ = self.retry_pending_reply_source_authority();
        let configured_hub = self.is_configured_hub_peer(&peer, relay_role) || proven_outbound_hub;
        if configured_hub
            && self
                .pending_configured_hub_source
                .as_ref()
                .is_some_and(|pending| pending != peer.id())
        {
            iroha_logger::warn!(
                peer = %peer.id(),
                connection_id,
                pending_hub = ?self.pending_configured_hub_source,
                "Rejecting obsolete configured hub while a newer hub handoff is staged"
            );
            self.reject_authenticated_tenure(connection_id, ready_peer_handle, peer_message_sender);
            return;
        }
        let configured_hub_candidate = configured_hub
            && matches!(
                self.relay_mode,
                iroha_config::parameters::actual::RelayMode::Spoke
                    | iroha_config::parameters::actual::RelayMode::Assist
            )
            && self
                .relay_hub_peer
                .as_ref()
                .is_none_or(|selected| selected == peer.id() || !self.peers.contains_key(selected));
        let pending_transition = !self.pending_reply_source_authority.is_empty()
            || self.pending_configured_hub_source.is_some();
        let pending_desired_source = pending_transition
            && self
                .desired_reply_source_authority()
                .reconciliation_topology
                .contains(peer.id());
        if pending_transition && !pending_desired_source && !configured_hub {
            iroha_logger::warn!(
                peer = %peer.id(),
                connection_id,
                "Rejecting source outside pending reply-authority reconciliation"
            );
            self.reject_authenticated_tenure(connection_id, ready_peer_handle, peer_message_sender);
            return;
        }
        let outside_topology = !self.current_topology.contains(peer.id());
        if outside_topology
            && matches!(
                self.relay_mode,
                iroha_config::parameters::actual::RelayMode::Spoke
            )
            && !configured_hub
        {
            iroha_logger::warn!(
                peer=%peer.id(),
                role=?relay_role,
                "Spoke mode only accepts configured hub peers; dropping peer"
            );
            self.reject_authenticated_tenure(connection_id, ready_peer_handle, peer_message_sender);
            return;
        }
        if outside_topology
            && self.is_permissioned_consensus()
            && !self.peer_reputations.is_trusted(peer.id())
            && !pending_desired_source
            && !configured_hub
        {
            iroha_logger::warn!(peer=%peer.id(), "Dropping untrusted observer in permissioned network");
            self.reject_authenticated_tenure(connection_id, ready_peer_handle, peer_message_sender);
            return;
        }
        if outside_topology && !self.is_permissioned_consensus() && !configured_hub {
            // Public observers are live transport peers, not consensus-topology
            // members. Promoting arbitrary authenticated identities here makes
            // sequential churn an unbounded topology/subscriber-memory input.
            iroha_logger::debug!(peer=%peer.id(), "Accepting ephemeral observer outside public consensus topology");
        }
        // Enforce the staged ACL while a coupled authority transition waits
        // for obsolete source owners to drain. The previously applied ACL
        // must neither re-admit an obsolete source nor reject its replacement.
        if !self.projected_reply_source_acl_allows(peer.id()) {
            iroha_logger::warn!(peer=%peer.id(), "Peer rejected by projected key ACL; dropping connection");
            self.reject_authenticated_tenure(connection_id, ready_peer_handle, peer_message_sender);
            return;
        }
        if proven_outbound_hub {
            // Authentication of the exact locally configured dial target pins
            // hub identity for this process/config generation. Mutable address
            // gossip cannot revoke or grant this authority.
            self.relay_trusted_peers.insert(peer.id().clone());
        }
        if matches!(
            self.relay_mode,
            iroha_config::parameters::actual::RelayMode::Spoke
        ) && !configured_hub
        {
            iroha_logger::warn!(
                peer=%peer.id(),
                role=?relay_role,
                "Spoke mode only accepts configured hub connections; dropping peer"
            );
            self.reject_authenticated_tenure(connection_id, ready_peer_handle, peer_message_sender);
            return;
        }
        // The full authenticated session order was settled before reader
        // binding. No second compact/direction/hub arbitration may disagree.
        if configured_hub_candidate {
            let prior_hub = self.pending_configured_hub_source.clone();
            self.pending_configured_hub_source = Some(peer.id().clone());
            let projection = self.desired_reply_source_authority();
            if projection.protected_sources.len() > self.reply_source_capacity()
                || !self
                    .inbound_frame_byte_budgets
                    .install_protected_sources(projection.protected_sources)
            {
                self.pending_configured_hub_source = prior_hub;
                iroha_logger::error!(
                    peer = %peer.id(),
                    connection_id,
                    "Resolved configured hub exceeds reply-source authority geometry"
                );
                self.reject_authenticated_tenure(
                    connection_id,
                    ready_peer_handle,
                    peer_message_sender,
                );
                return;
            }
            if !self
                .inbound_frame_byte_budgets
                .protected_source_geometry_fits()
            {
                self.retire_obsolete_reply_sources(&projection.reconciliation_topology);
                iroha_logger::warn!(
                    peer = %peer.id(),
                    connection_id,
                    "Deferring configured hub handoff until obsolete source owners drain"
                );
                self.reject_authenticated_tenure(
                    connection_id,
                    ready_peer_handle,
                    peer_message_sender,
                );
                return;
            }
        }
        if self
            .inbound_frame_byte_budgets
            .protected_sources()
            .is_none()
        {
            iroha_logger::warn!(
                peer = %peer.id(),
                connection_id,
                "Reply-source authority is not initialized; rejecting authenticated source"
            );
            self.reject_authenticated_tenure(connection_id, ready_peer_handle, peer_message_sender);
            return;
        }
        let Some(source_credits) = self
            .inbound_frame_byte_budgets
            .source_credits(peer.id(), self.authenticated_source_credit_capacity)
        else {
            iroha_logger::warn!(
                peer = %peer.id(),
                connection_id,
                source_credit_capacity = self.authenticated_source_credit_capacity,
                "Authenticated PeerId count-owner geometry is exhausted; rejecting tenure"
            );
            self.reject_authenticated_tenure(connection_id, ready_peer_handle, peer_message_sender);
            return;
        };
        let transport_capabilities = message::PeerTransportCapabilities { scion_supported };
        let route_source_credits = source_credits.clone();
        let ref_peer = RefPeer {
            handle: ready_peer_handle,
            conn_id: connection_id,
            p2p_addr: peer.address().clone(),
            relay_role,
            trust_gossip,
        };
        if peer_message_sender
            .send(crate::peer::message::PeerMessageSenders {
                safety: self.peer_message_safety_sender.clone(),
                payload: self.peer_message_payload_sender.clone(),
                block_sync: self.peer_message_block_sync_sender.clone(),
                control: self.peer_message_control_sender.clone(),

                high: self.peer_message_high_sender.clone(),
                low: self.peer_message_low_sender.clone(),
                dispatch_budgets: self.inbound_dispatch_byte_budgets.clone(),
                source_credits,
                topic_frame_caps: TopicFrameCaps {
                    consensus: self.cap_consensus,
                    control: self.cap_control,
                    block_sync: self.cap_block_sync,
                    tx_gossip: self.cap_tx_gossip,
                    peer_gossip: self.cap_peer_gossip,
                    health: self.cap_health,
                    connect: self.cap_connect,
                    other: self.cap_other,
                },
                delivery_drain: Arc::clone(&delivery_drain),
            })
            .is_err()
        {
            iroha_logger::warn!(
                peer = %peer.id(),
                connection_id,
                "Authenticated peer task closed before network handoff"
            );
            ref_peer.handle.request_termination();
            self.mark_connection_terminating(connection_id);
            return;
        }
        // Register externally visible state only after the peer task accepts
        // its actor handoff; a closed oneshot must not leave a zombie session.
        self.validator_dial_scheduler.note_session_established(
            &self.self_id,
            peer.id(),
            tokio::time::Instant::now(),
            self.connect_startup_delay_until,
        );
        self.reset_backoff_addr(peer.id(), peer.address());
        self.last_active
            .insert(peer.id().clone(), tokio::time::Instant::now());
        if self.release_incoming_pending(connection_id) {
            self.incoming_active.insert(connection_id);
        }
        if configured_hub_candidate {
            let relay_hub_peer = Some(peer.id().clone());
            let topology = self
                .relay_topology_candidate(self.current_topology.clone(), relay_hub_peer.as_ref());
            if self.reliable_topology_candidate_fits(&topology, "configured hub connection") {
                self.relay_hub_peer = relay_hub_peer;
                self.current_topology = topology;
            }
        }
        let persist_peer_metadata = self.current_topology.contains(peer.id())
            || configured_hub
            || self.is_configured_dial_target(&peer);
        if persist_peer_metadata {
            self.address_book
                .insert(peer.id().clone(), peer.address().clone());
            self.peer_capabilities
                .insert(peer.id().clone(), transport_capabilities);
        }
        self.peer_reputations.record_connected(peer.id());
        if let Some(replaced) = self.peers.insert(peer.id().clone(), ref_peer)
            && replaced.conn_id != connection_id
        {
            replaced.handle.request_termination();
            self.deferred_send_queue
                .release_retired_tenure_binding(peer.id(), replaced.conn_id);
            self.mark_connection_terminating(replaced.conn_id);
            self.peer_reputations.record_disconnected(peer.id());
        }
        let connection_ordinal = self.next_reply_connection_ordinal;
        self.next_reply_connection_ordinal = connection_ordinal
            .checked_add(1)
            .expect("reply-route connection ordinal cannot wrap while the actor is live");
        let source_capacity = self
            .max_total_connections
            .unwrap_or(
                iroha_config::parameters::defaults::network::lane_profile::CORE_MAX_TOTAL_CONNECTIONS,
            )
            .max(1);
        let prior = self.reply_route_tenures.insert(
            connection_id,
            Arc::new(ReliableReplyRouteTenure {
                owner: Arc::clone(&self.reply_route_owner),
                _source_credits: route_source_credits,
                delivery_peer: peer.id().clone(),
                connection_id,
                connection_ordinal,
                source_capacity,
                delivery_active: AtomicBool::new(true),
                reply_writable: AtomicBool::new(true),
                delivery_drain,
                termination_seen: AtomicBool::new(false),
            }),
        );
        assert!(prior.is_none(), "accepted connection ids cannot be reused");
        if configured_hub_candidate
            && self.relay_hub_peer.as_ref() == Some(peer.id())
            && self.pending_configured_hub_source.as_ref() == Some(peer.id())
        {
            self.pending_configured_hub_source = None;
            let applied = self.desired_reply_source_authority();
            let installed = self
                .inbound_frame_byte_budgets
                .install_protected_sources(applied.protected_sources);
            debug_assert!(
                installed,
                "accepted hub source projection must remain representable"
            );
        }
        match self.flush_deferred_frames_for_peer(peer.id()) {
            DeferredFlushOutcome::Flushed | DeferredFlushOutcome::Backpressured(_) => {}
            DeferredFlushOutcome::PeerMissing => {
                let _ = self.trigger_reconnect_for_peer(peer.id());
            }
        }
        if self.dns_refresh_interval.is_some() || self.dns_refresh_ttl.is_some() {
            if self.dns_pending_refresh.remove(peer.id()) {
                DNS_RECONNECT_SUCCESSES.fetch_add(1, Ordering::Relaxed);
            }
            self.dns_last_refresh
                .insert(peer.id().clone(), tokio::time::Instant::now());
        }
        Self::add_online_peer(
            &self.online_peers_sender,
            &self.online_peer_capabilities_sender,
            peer,
            transport_capabilities,
        );
    }
    fn peer_terminated(&mut self, Terminated { peer, conn_id }: Terminated) {
        self.reader_arbitration.cancel(conn_id);
        let known_connection = self.outbound_connections.contains(&conn_id)
            || self.reply_route_tenures.contains_key(&conn_id)
            || self.terminating_connections.contains(&conn_id)
            || self.incoming_pending.contains(&conn_id)
            || self.incoming_active.contains(&conn_id)
            || self.connecting_peers.contains_key(&conn_id)
            || peer.as_ref().is_some_and(|peer| {
                self.peers
                    .get(peer.id())
                    .is_some_and(|current| current.conn_id == conn_id)
            });
        if !known_connection {
            // A completed connection has no remaining actor-side ownership.
            // In particular, a duplicate notice for a configured dial target
            // must not advance its exponential backoff or reconnect metrics.
            iroha_logger::debug!(
                conn_id,
                peer = ?peer,
                "Ignoring duplicate or foreign peer termination notice"
            );
            return;
        }
        let was_outbound = self.outbound_connections.remove(&conn_id);
        // This is idempotent for natural termination and duplicate notices.
        // A reply tenure remains charged until its dispatch producer is closed
        // and every delivery which already crossed an actor lane has left its
        // final local receiver. The service notice is on a different channel
        // and may otherwise overtake those deliveries.
        if let Some(tenure) = self.reply_route_tenures.get(&conn_id).cloned() {
            if !tenure.mark_termination_seen() {
                // The first notice owns all teardown side effects, including
                // disconnect accounting and redial scheduling. The tenure may
                // remain present while receiver guards drain, so gate here as
                // well as at the actor-state boundary above.
                iroha_logger::debug!(
                    conn_id,
                    "Ignoring duplicate peer termination while delivery ownership drains"
                );
                return;
            }
            tenure.mark_draining();
            let _ = self
                .network_actor_progress_budget
                .cancel_reply_route(&tenure);
            self.terminating_connections.insert(conn_id);
            if tenure.delivery_drain.is_complete() {
                let _ = self.finish_reply_route_tenure(conn_id);
            } else {
                let delivery_drain = Arc::clone(&tenure.delivery_drain);
                let service_message_sender = self.service_message_sender.clone();
                tokio::spawn(async move {
                    delivery_drain.wait_complete().await;
                    let _ = service_message_sender
                        .send(ServiceMessage::ReplyRouteDeliveryDrained(conn_id))
                        .await;
                });
            }
        } else {
            self.terminating_connections.remove(&conn_id);
            self.protocol_rejected_connections.remove(&conn_id);
        }
        // An inbound handshake is still recorded in `incoming_pending` until
        // `peer_connected` accepts it into the active set.  Rejections after
        // authentication report `Some(peer)`, so clean both inbound sets
        // independently of how far the connection progressed.
        self.release_incoming_pending(conn_id);
        self.incoming_active.remove(&conn_id);
        // Remove the terminating attempt before retry reconciliation so the
        // shared replacement check only observes other in-flight owners.
        let pending_connect_peer = self.connecting_peers.remove(&conn_id);
        // Writer tickets were cancelled above. Delivery capability retirement
        // is deferred to the receiver-completion fence, so a stale predecessor
        // notice cannot strip reply authority from queued local work.
        // If termination happened before handshake, the `peer` is None.
        // In that case use the pending `connecting_peers` map to find which peer failed.
        if let Some(peer) = peer {
            if let Some(ref_peer) = self.peers.get(peer.id())
                && ref_peer.conn_id == conn_id
            {
                iroha_logger::debug!(conn_id, peer=%peer, "Peer terminated");
                self.peer_reputations.record_disconnected(peer.id());
                self.deferred_send_queue
                    .release_retired_tenure_binding(peer.id(), conn_id);
                self.peers.remove(peer.id());
                self.last_active.remove(peer.id());
                Self::remove_online_peer(
                    &self.online_peers_sender,
                    &self.online_peer_capabilities_sender,
                    peer.id(),
                );
                self.clear_low_buckets(peer.id());
            }
            // A current configured identity remains eligible even when the
            // terminated tenure was inbound. Arbitrary inbound identities are
            // excluded by the current address-authority snapshot.
            self.schedule_retry_for_terminated_peer(&peer);
        } else if let Some(pending_peer) = pending_connect_peer {
            // Pre-handshake failures are retryable only for locally initiated
            // attempts. The shared helper then revalidates current identity,
            // topology, ACL, and exact address authority.
            if was_outbound {
                self.schedule_retry_for_terminated_peer(&pending_peer);
            }
        }
    }
    fn try_post(
        &mut self,
        Post {
            data,
            peer_id,
            priority,
        }: Post<T>,
    ) -> bool {
        iroha_logger::trace!(peer=%peer_id, "Post message");
        let topic = data.topic();
        if matches!(
            topic,
            message::Topic::ConsensusSafety
                | message::Topic::Consensus
                | message::Topic::ConsensusPayload
                | message::Topic::ConsensusChunk
        ) {
            iroha_logger::debug!(
                peer = %peer_id,
                high = matches!(priority, Priority::High),
                "sending consensus frame to peer"
            );
        }
        if matches!(topic, message::Topic::TrustGossip) && !self.trust_gossip {
            iroha_logger::debug!(
                peer=%peer_id,
                "Skipping trust gossip post because local capability is disabled"
            );
            inc_trust_gossip_skipped("send", "local_capability_off");
            return false;
        }
        let relay_ttl = self.relay_ttl;
        if let Some(hub_id) = self.relay_route_for_unconnected_post_target(&peer_id) {
            let frame = RelayMessage::new_signed(
                &self.key_pair,
                RelayTarget::Direct(peer_id),
                relay_ttl,
                data,
            );
            return self.send_frame_to_peer(&hub_id, frame, topic);
        }
        let relay_fallback_enabled = matches!(
            self.relay_mode,
            iroha_config::parameters::actual::RelayMode::Spoke
                | iroha_config::parameters::actual::RelayMode::Assist
        );
        let fallback_hub = if relay_fallback_enabled {
            self.hub_handle().map(|(id, _)| id.clone())
        } else {
            None
        };
        // Retain a payload copy only when a live hub could be needed after a
        // failed direct enqueue. The signed direct frame owns the caller's
        // original payload.
        let fallback_payload = fallback_hub.as_ref().map(|_| data.clone());
        let frame = RelayMessage::new_signed(
            &self.key_pair,
            RelayTarget::Direct(peer_id.clone()),
            relay_ttl,
            data,
        );
        let relay_fallback = fallback_hub.zip(fallback_payload).map(|(hub_id, payload)| {
            (
                hub_id,
                frame.origin.clone(),
                frame.target.clone(),
                frame.origin_signature.clone(),
                payload,
            )
        });
        if self.send_frame_to_peer(&peer_id, frame, topic) {
            return true;
        }
        if relay_fallback_enabled {
            if let Some((hub_id, origin, target, origin_signature, payload)) = relay_fallback {
                let fallback = RelayMessage {
                    origin,
                    target,
                    ttl: relay_ttl,
                    origin_signature,
                    payload,
                };
                return self.send_frame_to_peer(&hub_id, fallback, topic);
            }
            iroha_logger::warn!(
                peer=%peer_id,
                "Relay mode could not route post because hub is unavailable"
            );
        }
        false
    }
    fn post(&mut self, post: Post<T>) {
        let _ = self.try_post(post);
    }
    fn reliable_actor_target_capacity(&self) -> usize {
        self.max_total_connections.unwrap_or(
            iroha_config::parameters::defaults::network::lane_profile::CORE_MAX_TOTAL_CONNECTIONS,
        )
    }
    fn relay_topology_candidate(
        &self,
        mut topology: HashSet<PeerId>,
        relay_hub_peer: Option<&PeerId>,
    ) -> HashSet<PeerId> {
        match self.relay_mode {
            iroha_config::parameters::actual::RelayMode::Spoke => {
                // A spoke owns exactly one relay route and no direct validator
                // fanout. Replacing the whole set also removes a prior hub
                // atomically during failover.
                topology.clear();
                topology.extend(relay_hub_peer.cloned());
            }
            iroha_config::parameters::actual::RelayMode::Assist => {
                // Keep at most the selected configured hub. Consensus peers are
                // preserved; only identities proven to be configured relay hubs
                // may be removed during hub rotation.
                if !self.relay_trusted_peers.is_empty() {
                    topology.retain(|id| {
                        !self.relay_trusted_peers.contains(id)
                            || relay_hub_peer.is_some_and(|selected| id == selected)
                    });
                }
                topology.extend(relay_hub_peer.cloned());
            }
            iroha_config::parameters::actual::RelayMode::Disabled
            | iroha_config::parameters::actual::RelayMode::Hub => {}
        }
        topology
    }
    fn reliable_topology_candidate_fits(
        &self,
        topology: &HashSet<PeerId>,
        transition: &'static str,
    ) -> bool {
        let target_capacity = self.reliable_actor_target_capacity();
        if topology.len() <= target_capacity {
            return true;
        }
        iroha_logger::error!(
            topology_len = topology.len(),
            target_capacity,
            transition,
            "Rejected topology transition larger than the checked reliable fanout geometry; retaining the previous topology and relay hub"
        );
        false
    }
    fn reconcile_reliable_topology(
        &self,
        published: &Arc<Mutex<ReliableProgressTopology>>,
        expected: &HashSet<PeerId>,
        broadcast: bool,
    ) -> (usize, usize) {
        let removed = published
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reconcile(expected, &self.self_id);
        // `reconcile` marks every removed token inactive before this budget
        // lock is acquired. A concurrent reservation therefore either sees
        // the inactive token or is included in this exact removed-membership sweep.
        let mut cancelled_waiters = 0usize;
        for membership in &removed {
            cancelled_waiters = cancelled_waiters
                .checked_add(
                    self.network_actor_progress_budget
                        .cancel_membership(membership, broadcast),
                )
                .expect("bounded reliable-progress waiter count cannot overflow");
        }
        (removed.len(), cancelled_waiters)
    }
    fn reconcile_reliable_progress_topologies(&mut self) -> (usize, usize) {
        let mut configured_peer_ids = self
            .requested_topology
            .iter()
            .filter(|peer_id| *peer_id != &self.self_id)
            // A pending revocation must stop being a sampling authority before
            // obsolete connection owners finish draining. Pending additions,
            // however, are not exposed until the topology commits.
            .filter(|peer_id| {
                self.pending_reply_source_authority
                    .topology
                    .as_ref()
                    .is_none_or(|pending| pending.0.contains(peer_id))
            })
            .filter(|peer_id| self.projected_reply_source_acl_allows(peer_id))
            .cloned()
            .collect::<Vec<_>>();
        configured_peer_ids.sort();
        let mut state = self
            .configured_peer_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.peer_ids != configured_peer_ids {
            state.generation = state
                .generation
                .checked_add(1)
                .expect("configured-peer generation space exhausted");
            state.peer_ids = configured_peer_ids;
        }
        drop(state);

        let (removed_broadcast, cancelled_broadcast_waiters) = self.reconcile_reliable_topology(
            &self.reliable_broadcast_topology,
            &self.current_topology,
            true,
        );
        let mut direct_targets = self.requested_topology.clone();
        direct_targets.extend(self.peers.keys().cloned());
        debug_assert!(
            direct_targets.len()
                <= network_actor_progress_target_capacity(self.reliable_actor_target_capacity())
                    .expect("validated reliable direct target geometry")
        );
        let (removed_direct, cancelled_direct_waiters) = self.reconcile_reliable_topology(
            &self.reliable_direct_topology,
            &direct_targets,
            false,
        );
        (
            removed_broadcast.saturating_add(removed_direct),
            cancelled_broadcast_waiters.saturating_add(cancelled_direct_waiters),
        )
    }
    fn reliable_broadcast_targets(&self) -> Option<VecDeque<PeerId>> {
        let mut peers: Vec<_> = self
            .current_topology
            .iter()
            .filter(|peer_id| *peer_id != &self.self_id)
            .cloned()
            .collect();
        peers.sort();
        let target_capacity = self.reliable_actor_target_capacity();
        if peers.len() > target_capacity {
            iroha_logger::error!(
                topology_len = peers.len(),
                target_capacity,
                "Reliable broadcast refused an unbounded topology snapshot"
            );
            return None;
        }
        if peers.is_empty() {
            None
        } else {
            Some(peers.into())
        }
    }
    /// Transfer one broadcast intent to each target that does not already own
    /// it. Failed targets rotate to the tail so one unavailable peer cannot
    /// starve the rest of the snapshot, while successful targets are removed
    /// permanently and are never duplicated by a later retry.
    fn try_broadcast_remaining(&mut self, data: &T, remaining: &mut VecDeque<PeerId>) -> bool {
        let topic = data.topic();
        let attempts = remaining.len();
        if attempts == 0 {
            return true;
        }
        let mut frame = Some(RelayMessage::new_signed(
            &self.key_pair,
            RelayTarget::Broadcast,
            self.relay_ttl,
            data.clone(),
        ));
        for attempt in 0..attempts {
            let pid = remaining
                .pop_front()
                .expect("broadcast retry attempts are bounded by the target queue");
            let outgoing = if attempt + 1 == attempts {
                frame
                    .take()
                    .expect("the final broadcast target owns the signed frame")
            } else {
                frame
                    .as_ref()
                    .expect("the signed broadcast frame remains available")
                    .clone()
            };
            if !self.send_frame_to_peer(&pid, outgoing, topic) {
                match topic {
                    message::Topic::TxGossip | message::Topic::TxGossipRestricted => {
                        iroha_logger::warn!(
                            peer=%pid,
                            "Failed to enqueue tx gossip broadcast frame"
                        );
                    }
                    message::Topic::ConsensusSafety
                    | message::Topic::Consensus
                    | message::Topic::ConsensusPayload
                    | message::Topic::ConsensusChunk => {
                        iroha_logger::warn!(peer=%pid, "Failed to enqueue consensus broadcast frame");
                    }
                    _ => {}
                }
                remaining.push_back(pid);
            }
        }
        remaining.is_empty()
    }
    fn try_broadcast(&mut self, Broadcast { data, priority }: &Broadcast<T>) -> bool {
        iroha_logger::trace!("Broadcast message");
        let topic = data.topic();
        let route = data.subscriber_route();
        let reliable_progress = is_reliable_progress_route(topic, route);
        if matches!(
            topic,
            message::Topic::ConsensusSafety
                | message::Topic::Consensus
                | message::Topic::ConsensusPayload
                | message::Topic::ConsensusChunk
        ) {
            iroha_logger::debug!(
                high = matches!(priority, Priority::High),
                "broadcasting consensus frame to all peers"
            );
        }
        if matches!(topic, message::Topic::TrustGossip) && !self.trust_gossip {
            iroha_logger::debug!(
                "Skipping trust gossip broadcast because local capability is disabled"
            );
            inc_trust_gossip_skipped("send", "local_capability_off");
            return false;
        }
        let peers: VecDeque<PeerId> = if reliable_progress {
            let Some(peers) = self.reliable_broadcast_targets() else {
                return false;
            };
            peers
        } else {
            self.peers.keys().cloned().collect()
        };
        let mut remaining = peers;
        self.try_broadcast_remaining(data, &mut remaining)
    }
    fn broadcast(&mut self, broadcast: Broadcast<T>) {
        let _ = self.try_broadcast(&broadcast);
    }
    async fn peer_message(&mut self, msg: PeerMessage<WireMessage<T>>) {
        iroha_logger::trace!(peer=%msg.peer, "Received peer message");
        if msg.connection_id().is_some_and(|connection_id| {
            self.protocol_rejected_connections.contains(&connection_id)
        }) {
            iroha_logger::debug!(
                peer = %msg.peer,
                connection_id = ?msg.connection_id(),
                "Dropping frame queued by a protocol-rejected connection tenure"
            );
            return;
        }
        let topic = msg.payload.payload.topic();
        let route = msg.payload.payload.subscriber_route();
        let size_bytes = msg.payload_bytes;
        let peer_id = msg.peer.id().clone();
        let replaced_connection = msg.connection_id().is_some_and(|connection_id| {
            self.peers
                .get(&peer_id)
                .is_none_or(|peer| peer.conn_id != connection_id)
        });
        if replaced_connection && !is_reliable_progress_route(topic, route) {
            let connection_id = msg
                .connection_id()
                .expect("replaced connection has an exact connection id");
            iroha_logger::debug!(
                peer = %peer_id,
                connection_id,
                current_connection_id = ?self.peers.get(&peer_id).map(|peer| peer.conn_id),
                "Dropping best-effort message queued by a replaced peer connection"
            );
            return;
        }
        if replaced_connection {
            iroha_logger::debug!(
                peer = %peer_id,
                connection_id = ?msg.connection_id(),
                current_connection_id = ?self.peers.get(&peer_id).map(|peer| peer.conn_id),
                ?topic,
                "Accepting authenticated reliable progress from a draining transport tenure"
            );
        }
        if matches!(topic, message::Topic::TrustGossip) {
            if !self.trust_gossip {
                Self::record_trust_gossip_skip(
                    &peer_id,
                    TrustDirection::Inbound,
                    "local_capability_off",
                );
                return;
            }
            if !self.peers.get(&peer_id).is_some_and(|p| p.trust_gossip) {
                Self::record_trust_gossip_skip(
                    &peer_id,
                    TrustDirection::Inbound,
                    "peer_capability_off",
                );
                return;
            }
        }
        let cap = match topic {
            message::Topic::ConsensusSafety | message::Topic::Control => self.cap_control,
            message::Topic::Consensus => self.cap_consensus,
            // Payload-heavy consensus frames share the block-sync cap.
            message::Topic::ConsensusPayload
            | message::Topic::ConsensusChunk
            | message::Topic::BlockSync => self.cap_block_sync,
            message::Topic::TxGossip | message::Topic::TxGossipRestricted => self.cap_tx_gossip,
            message::Topic::PeerGossip | message::Topic::TrustGossip => self.cap_peer_gossip,
            message::Topic::Health => self.cap_health,
            message::Topic::Connect => self.cap_connect,
            message::Topic::Other => self.cap_other,
        };
        if size_bytes > cap {
            iroha_logger::warn!(peer=%msg.peer, topic=?topic, size=size_bytes, cap=cap, "Dropping inbound message exceeding topic cap");
            record_inbound_cap_violation(topic);
            self.reject_protocol_tenure(&peer_id, msg.connection_id(), "topic frame cap exceeded");
            return;
        }
        let incoming_peer = msg.peer.clone();
        let origin = msg.payload.origin.clone();
        let target = msg.payload.target.clone();
        let ttl = msg.payload.ttl.min(self.relay_ttl);
        let priority = topic.scheduling_priority();
        // Most peers must send frames where `origin` matches their peer id. We only accept
        // relayed frames (origin mismatch) from explicitly trusted relay peers.
        let allow_origin_mismatch = match self.relay_mode {
            iroha_config::parameters::actual::RelayMode::Spoke
            | iroha_config::parameters::actual::RelayMode::Assist => self
                .relay_hub_peer
                .as_ref()
                .is_some_and(|hub| hub == incoming_peer.id()),
            iroha_config::parameters::actual::RelayMode::Hub => {
                self.relay_trusted_peers.contains(incoming_peer.id())
            }
            iroha_config::parameters::actual::RelayMode::Disabled => false,
        };
        if origin != *incoming_peer.id() && !allow_origin_mismatch {
            iroha_logger::warn!(
                peer = %incoming_peer,
                origin = %origin,
                "dropping relay frame with mismatched origin"
            );
            self.reject_protocol_tenure(
                &peer_id,
                msg.connection_id(),
                "unauthorized relay origin mismatch",
            );
            return;
        }
        if let Err(error) = msg.payload.verify_origin_signature() {
            iroha_logger::warn!(
                peer = %incoming_peer,
                origin = %origin,
                %error,
                "dropping relay frame with invalid end-to-end origin signature"
            );
            self.reject_protocol_tenure(
                &peer_id,
                msg.connection_id(),
                "invalid relay origin signature",
            );
            return;
        }
        if matches!(
            topic,
            message::Topic::ConsensusSafety
                | message::Topic::Consensus
                | message::Topic::ConsensusPayload
                | message::Topic::ConsensusChunk
        ) {
            iroha_logger::debug!(
                from=%incoming_peer,
                origin=%origin,
                ?target,
                high=matches!(priority, Priority::High),
                size=size_bytes,
                topic=?topic,
                "received consensus frame"
            );
        }
        if matches!(topic, message::Topic::BlockSync) {
            iroha_logger::debug!(
                from=%incoming_peer,
                origin=%origin,
                ?target,
                high=matches!(priority, Priority::High),
                size=size_bytes,
                "received block sync frame"
            );
        }
        if ttl == 0
            && !matches!(&target, RelayTarget::Direct(id) if id == &self.self_id)
            && !matches!(target, RelayTarget::Broadcast)
        {
            iroha_logger::debug!(peer=%incoming_peer, "Dropping relay frame with expired ttl");
            return;
        }
        self.last_active
            .insert(peer_id.clone(), tokio::time::Instant::now());
        let deliver_local = matches!(&target, RelayTarget::Broadcast)
            || matches!(&target, RelayTarget::Direct(id) if id == &self.self_id);
        // Forward first (only borrows `payload`) so we can move it into the local-delivery
        // message without cloning when hub-mode relay is enabled.
        if matches!(self.relay_role, RelayRole::Hub)
            && let Some(next_ttl) = ttl.checked_sub(1)
        {
            match &target {
                RelayTarget::Broadcast => {
                    self.forward_broadcast(&incoming_peer, &msg.payload, next_ttl, topic);
                }
                RelayTarget::Direct(target_id) => {
                    if target_id != &self.self_id {
                        self.forward_direct(
                            &incoming_peer,
                            &msg.payload,
                            target_id,
                            next_ttl,
                            topic,
                        );
                    }
                }
            }
        }
        if deliver_local {
            let origin_peer = self.resolve_origin_peer(&origin, &incoming_peer);
            let reply_tenure = msg
                .connection_id()
                .and_then(|connection_id| self.reply_route_tenures.get(&connection_id))
                .filter(|tenure| tenure.is_active() && tenure.delivery_peer == *incoming_peer.id())
                .cloned();
            let reply_route = reply_tenure.map(|tenure| {
                let delivery_ordinal = self.next_reply_delivery_ordinal;
                self.next_reply_delivery_ordinal = delivery_ordinal
                    .checked_add(1)
                    .expect("reply-route delivery ordinal cannot wrap while the actor is live");
                NetworkReplyRoute::new(origin.clone(), tenure, delivery_ordinal)
            });
            let mut deliver = msg.map_payload(origin_peer, |relay| relay.payload);
            if let Some(reply_route) = reply_route {
                deliver.set_reply_route(reply_route);
            }
            if matches!(
                topic,
                message::Topic::TxGossip | message::Topic::TxGossipRestricted
            ) {
                iroha_logger::debug!(
                    peer=%deliver.peer,
                    size_bytes,
                    "delivering tx gossip frame to subscribers"
                );
            } else if matches!(
                topic,
                message::Topic::ConsensusSafety
                    | message::Topic::Consensus
                    | message::Topic::ConsensusPayload
                    | message::Topic::ConsensusChunk
            ) {
                iroha_logger::debug!(
                    peer=%deliver.peer,
                    topic=?topic,
                    size_bytes,
                    "delivering consensus frame to subscribers"
                );
            }
            let admission_peer_id = incoming_peer.id().clone();
            self.dispatch_to_subscribers_from(deliver, admission_peer_id);
        }
    }
    fn subscribe_to_peers_messages(&mut self, subscriber: Subscriber<T>) {
        let mut registered_open = Vec::with_capacity(self.subscribers_to_peers_messages.len());
        let mut recovered = VecDeque::new();
        for mut registered in self.subscribers_to_peers_messages.drain(..) {
            if registered.sender.is_closed() {
                iroha_logger::debug!(
                    filter = ?registered.filter,
                    "Recovering a closed subscriber's reliable backlog before replacement"
                );
                recovered.extend(registered.drain_reliable_pending());
            } else {
                registered_open.push(registered);
            }
        }
        self.subscribers_to_peers_messages = registered_open;
        self.unrouted_reliable_deliveries.extend(recovered);
        if self
            .subscribers_to_peers_messages
            .iter()
            .any(|registered| registered.filter.overlaps_reliable(&subscriber.filter))
        {
            iroha_logger::error!(
                filter = ?subscriber.filter,
                "Rejected a subscriber whose filter overlaps an existing reliable single-consumer route"
            );
            return;
        }
        self.subscribers_to_peers_messages.push(subscriber);
        iroha_logger::info!(
            subscribers = self.subscribers_to_peers_messages.len(),
            "registered peer message subscriber"
        );
        let pending = core::mem::take(&mut self.unrouted_reliable_deliveries);
        for UnroutedReliableDelivery {
            message,
            admission_peer_id,
        } in pending
        {
            self.dispatch_to_subscribers_from(message, admission_peer_id);
        }
    }
    fn flush_safety_subscribers(&mut self) {
        let mut next = Vec::with_capacity(self.subscribers_to_peers_messages.len());
        let mut recovered = VecDeque::new();
        for mut subscriber in self.subscribers_to_peers_messages.drain(..) {
            if subscriber.sender.is_closed() {
                iroha_logger::debug!("subscriber channel closed; recovering its reliable backlog");
                recovered.extend(subscriber.drain_reliable_pending());
                continue;
            }
            if subscriber
                .flush_reliable(CONSENSUS_SAFETY_DRAIN_BUDGET)
                .is_ok()
            {
                next.push(subscriber);
            } else {
                iroha_logger::debug!(
                    "subscriber channel closed during service; recovering its reliable backlog"
                );
                recovered.extend(subscriber.drain_reliable_pending());
            }
        }
        self.subscribers_to_peers_messages = next;
        self.unrouted_reliable_deliveries.extend(recovered);
    }
    #[cfg(test)]
    fn dispatch_to_subscribers(&mut self, msg: PeerMessage<T>) {
        let admission_peer_id = msg.peer.id().clone();
        self.dispatch_to_subscribers_from(msg, admission_peer_id);
    }
    fn dispatch_to_subscribers_from(&mut self, msg: PeerMessage<T>, admission_peer_id: PeerId) {
        use tokio::sync::mpsc::error::TrySendError;
        let topic = msg.payload.topic();
        let route = msg.payload.subscriber_route();
        let admission_class = msg.payload.admission_class();
        let progress_class = subscriber_progress_class(topic, route);
        let reliable_single_consumer = is_reliable_progress_route(topic, route);
        let logging_peer = msg.peer.clone();
        if self.subscribers_to_peers_messages.is_empty() {
            if reliable_single_consumer {
                self.unrouted_reliable_deliveries
                    .push_back(UnroutedReliableDelivery {
                        message: msg,
                        admission_peer_id,
                    });
                iroha_logger::debug!(
                    peer = %logging_peer,
                    ?topic,
                    ?route,
                    "Retained reliable delivery until its route subscriber registers"
                );
                return;
            }
            if matches!(
                topic,
                message::Topic::ConsensusSafety
                    | message::Topic::Consensus
                    | message::Topic::ConsensusPayload
                    | message::Topic::ConsensusChunk
            ) {
                iroha_logger::warn!(
                    peer = %msg.peer,
                    "dropping best-effort consensus-shaped frame because no subscribers are registered yet"
                );
            } else {
                iroha_logger::warn!("No subscribers to send message to");
            }
            return;
        }
        if matches!(topic, message::Topic::BlockSync) {
            iroha_logger::debug!(
                peer = %msg.peer,
                size_bytes = msg.payload_bytes,
                "dispatching block sync message to subscribers"
            );
        }
        let matched_count = self
            .subscribers_to_peers_messages
            .iter()
            .filter(|subscriber| subscriber.filter.matches(topic, route, admission_class))
            .count();
        let mut next = Vec::with_capacity(self.subscribers_to_peers_messages.len());
        let mut recovered = VecDeque::new();
        let mut matched_index = 0_usize;
        let mut original = Some(msg);
        for mut subscriber in self.subscribers_to_peers_messages.drain(..) {
            if !subscriber.filter.matches(topic, route, admission_class) {
                next.push(subscriber);
                continue;
            }
            if reliable_single_consumer && matched_index > 0 {
                // Registration rejects this state. Keep dispatch fail-closed if
                // an invalid subscriber was injected by a test or future API:
                // the first stable owner receives the original, while the
                // overlapping subscriber is removed before it can turn clone
                // pressure into partial reliable fan-out.
                iroha_logger::error!(
                    topic = ?topic,
                    route = ?route,
                    "Removing overlapping reliable subscriber to preserve the single-consumer invariant"
                );
                recovered.extend(subscriber.drain_reliable_pending());
                continue;
            }
            matched_index += 1;
            let delivery = if reliable_single_consumer || matched_index == matched_count {
                original.take()
            } else {
                original.as_ref().and_then(PeerMessage::try_clone_retained)
            };
            let Some(delivery) = delivery else {
                let drops = inc_subscriber_queue_full_for(topic);
                if drops == 1 || drops.is_multiple_of(1024) {
                    iroha_logger::warn!(
                        peer = %logging_peer,
                        topic = ?topic,
                        drops,
                        "subscriber fan-out byte budget is full; dropping duplicate delivery"
                    );
                }
                next.push(subscriber);
                continue;
            };
            if matches!(topic, message::Topic::ConsensusSafety) {
                if subscriber
                    .flush_reliable(CONSENSUS_SAFETY_DRAIN_BUDGET)
                    .is_err()
                {
                    subscriber.enqueue_safety(delivery, admission_peer_id.clone());
                    recovered.extend(subscriber.drain_reliable_pending());
                    iroha_logger::debug!("subscriber channel closed; recovering safety deliveries");
                    continue;
                }
                subscriber.enqueue_safety(delivery, admission_peer_id.clone());
                if subscriber
                    .flush_reliable(CONSENSUS_SAFETY_DRAIN_BUDGET)
                    .is_ok()
                {
                    next.push(subscriber);
                } else {
                    recovered.extend(subscriber.drain_reliable_pending());
                    iroha_logger::debug!("subscriber channel closed; recovering safety deliveries");
                }
                continue;
            }
            if let Some(progress_class) = progress_class {
                if subscriber
                    .flush_reliable(NETWORK_PROGRESS_ACTOR_DRAIN_BUDGET)
                    .is_err()
                {
                    subscriber.enqueue_progress(
                        delivery,
                        admission_peer_id.clone(),
                        progress_class,
                    );
                    recovered.extend(subscriber.drain_reliable_pending());
                    iroha_logger::debug!(
                        "subscriber channel closed; recovering progress deliveries"
                    );
                    continue;
                }
                subscriber.enqueue_progress(delivery, admission_peer_id.clone(), progress_class);
                if subscriber
                    .flush_reliable(NETWORK_PROGRESS_ACTOR_DRAIN_BUDGET)
                    .is_ok()
                {
                    next.push(subscriber);
                } else {
                    recovered.extend(subscriber.drain_reliable_pending());
                    iroha_logger::debug!(
                        "subscriber channel closed; recovering progress deliveries"
                    );
                }
                continue;
            }
            match subscriber.sender.try_send(delivery) {
                Ok(()) => next.push(subscriber),
                Err(TrySendError::Full(_)) => {
                    let drops = inc_subscriber_queue_full_for(topic);
                    if drops == 1 || drops.is_multiple_of(1024) {
                        iroha_logger::warn!(
                            peer = %logging_peer,
                            topic = ?topic,
                            drops,
                            "subscriber queue full; dropping inbound message"
                        );
                    }
                    next.push(subscriber);
                }
                Err(TrySendError::Closed(_)) => {
                    iroha_logger::debug!("subscriber channel closed; dropping subscriber");
                }
            }
        }
        let unrouted_reliable = if matched_count == 0 && reliable_single_consumer {
            original.take().map(|message| UnroutedReliableDelivery {
                message,
                admission_peer_id,
            })
        } else {
            None
        };
        if matched_count == 0 {
            let misses = inc_subscriber_unrouted_for(topic);
            if misses == 1 || misses.is_multiple_of(1024) {
                iroha_logger::warn!(
                    peer = %logging_peer,
                    topic = ?topic,
                    misses,
                    "no subscribers registered for topic"
                );
            }
        }
        self.subscribers_to_peers_messages = next;
        self.unrouted_reliable_deliveries.extend(recovered);
        if let Some(unrouted) = unrouted_reliable {
            self.unrouted_reliable_deliveries.push_back(unrouted);
        }
    }
    fn forward_broadcast(
        &mut self,
        incoming_peer: &Peer,
        relay: &RelayMessage<T>,
        ttl: u8,
        topic: message::Topic,
    ) {
        let targets: Vec<PeerId> = self.peers.keys().cloned().collect();
        for pid in targets {
            if pid == *incoming_peer.id() {
                continue;
            }
            let frame = relay.forwarded_with_ttl(ttl);
            self.send_frame_to_peer(&pid, frame, topic);
        }
    }
    fn forward_direct(
        &mut self,
        incoming_peer: &Peer,
        relay: &RelayMessage<T>,
        target: &PeerId,
        ttl: u8,
        topic: message::Topic,
    ) {
        if target == incoming_peer.id() {
            iroha_logger::debug!(%target, "Dropping relay frame targeted at sender");
            return;
        }
        let frame = relay.forwarded_with_ttl(ttl);
        let _ = self.send_frame_to_peer(target, frame, topic);
    }
    fn add_online_peer(
        online_peers_sender: &watch::Sender<OnlinePeers>,
        online_peer_capabilities_sender: &watch::Sender<message::OnlinePeerCapabilities>,
        peer: Peer,
        capabilities: message::PeerTransportCapabilities,
    ) {
        online_peers_sender.send_if_modified(|online_peers| {
            let inserted = online_peers.insert(peer.clone());
            if inserted {
                iroha_logger::info!(
                    peer=%peer.id(),
                    online_peers = online_peers.len(),
                    "peer connected"
                );
            }
            inserted
        });
        let peer_id = peer.id().clone();
        online_peer_capabilities_sender.send_if_modified(|online_caps| {
            online_caps.insert(peer_id.clone(), capabilities) != Some(capabilities)
        });
    }
    fn remove_online_peer(
        online_peers_sender: &watch::Sender<OnlinePeers>,
        online_peer_capabilities_sender: &watch::Sender<message::OnlinePeerCapabilities>,
        peer_id: &PeerId,
    ) {
        online_peers_sender.send_if_modified(|online_peers| online_peers.remove(peer_id));
        online_peer_capabilities_sender
            .send_if_modified(|online_caps| online_caps.remove(peer_id).is_some());
    }
    fn get_conn_id(&mut self) -> ConnectionId {
        let conn_id = self.current_conn_id;
        self.current_conn_id = conn_id
            .checked_add(1)
            .expect("P2P connection identifiers cannot wrap while the actor is live");
        conn_id
    }
    /// Whether total connection cap is exceeded.
    fn exceeds_caps(&self) -> bool {
        let Some(max_total) = self.max_total_connections else {
            return false;
        };
        // A proactively removed actor can retain authenticated source ownership
        // until its termination notice arrives, so it remains part of the hard
        // connection/source-reserve bound during teardown.
        let total = self
            .peers
            .len()
            .saturating_add(self.connecting_peers.len())
            .saturating_add(self.incoming_pending.len())
            .saturating_add(self.terminating_connections.len());
        total >= max_total
    }
    /// Whether an ordinary connection would consume the relay-hub proof slot.
    fn exceeds_ordinary_connection_cap(&self) -> bool {
        let Some(max_total) = self.max_total_connections else {
            return false;
        };
        let ordinary_limit = max_total.saturating_sub(usize::from(self.reserves_relay_hub_slot()));
        let total = self
            .peers
            .len()
            .saturating_add(self.connecting_peers.len())
            .saturating_add(self.incoming_pending.len())
            .saturating_add(self.terminating_connections.len());
        total >= ordinary_limit
    }
    /// Whether an outbound target has exhausted the capacity available to it.
    fn exceeds_outbound_connection_cap(&self, peer: &Peer) -> bool {
        if self.is_exact_relay_hub_dial_target(peer) {
            self.exceeds_caps()
        } else {
            self.exceeds_ordinary_connection_cap()
        }
    }
    /// Whether incoming cap is exceeded.
    fn exceeds_incoming_cap(&self) -> bool {
        let Some(max_in) = self.max_incoming else {
            return false;
        };
        let incoming = self.incoming_active.len() + self.incoming_pending.len();
        incoming >= max_in
    }
    /// Check and update per-IP accept throttle.
    fn allow_ip(&mut self, ip: std::net::IpAddr) -> bool {
        allow_ip_with_policy(
            &self.allow_nets,
            &self.deny_nets,
            self.allowlist_only,
            self.accept_params,
            &mut self.accept_prefix_buckets,
            &mut self.accept_ip_buckets,
            ip,
        )
    }
    fn clear_low_buckets(&mut self, peer_id: &PeerId) {
        self.low_buckets.remove(peer_id);
        self.low_bytes_buckets.remove(peer_id);
    }
}
fn topology_tick_interval(configured: Duration) -> Duration {
    configured
}
#[cfg(test)]
async fn cap_violation_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    // Keep the counter isolated across awaits without blocking an executor thread.
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}
fn apply_connect_startup_delay(
    when: tokio::time::Instant,
    delay_until: tokio::time::Instant,
) -> tokio::time::Instant {
    if when < delay_until {
        delay_until
    } else {
        when
    }
}
fn connect_attempt_jitter_ms(
    self_id: &PeerId,
    peer_id: &PeerId,
    addr: &SocketAddr,
    stagger_index: usize,
    stagger: Duration,
    upper_ms: u64,
) -> u64 {
    let material = format!(
        "iroha:p2p-connect-attempt-jitter:v1\nself={self_id}\npeer={peer_id}\naddr={addr}\nindex={stagger_index}\nstagger_ms={}\nupper_ms={upper_ms}",
        stagger.as_millis()
    );
    bounded_hash_jitter_ms(&material, upper_ms)
}
fn reconnect_backoff_jitter_ms(
    self_id: &PeerId,
    peer_id: &PeerId,
    addr: &SocketAddr,
    base: Duration,
    next_base: Duration,
    upper_ms: u64,
) -> u64 {
    let material = format!(
        "iroha:p2p-reconnect-backoff-jitter:v1\nself={self_id}\npeer={peer_id}\naddr={addr}\nbase_ms={}\nnext_base_ms={}\nupper_ms={upper_ms}",
        base.as_millis(),
        next_base.as_millis()
    );
    // Keep jitter inside the current exponential-backoff window.  Hashing
    // into `0..=next_base` lets one peer pair deterministically select the
    // same near-zero delay forever once `base == next_base`, turning an
    // unavailable validator into a reconnect storm.  The lower bound still
    // spreads peers throughout `[base, next_base]` while preserving the
    // configured maximum retry cadence.
    let lower_ms = u64::try_from(base.as_millis())
        .unwrap_or(u64::MAX)
        .min(upper_ms);
    lower_ms.saturating_add(bounded_hash_jitter_ms(
        &material,
        upper_ms.saturating_sub(lower_ms),
    ))
}
fn bounded_hash_jitter_ms(material: &str, upper_ms: u64) -> u64 {
    if upper_ms == 0 {
        return 0;
    }
    let digest = Hash::new(material.as_bytes());
    let digest: [u8; Hash::LENGTH] = digest.into();
    let mut word = [0_u8; 8];
    word.copy_from_slice(&digest[..8]);
    let raw = u64::from_le_bytes(word);
    u64::try_from(u128::from(raw) % (u128::from(upper_ms) + 1))
        .expect("bounded jitter value fits in u64")
}
#[cfg(test)]
#[path = "network/admission_class_tests.rs"]
pub(crate) mod admission_class_tests;
#[cfg(test)]
#[path = "network/tests.rs"]
mod tests;
pub mod message {
    //! Module for network messages
    use super::*;
    use iroha_data_model::peer::Peer;
    use norito::codec::{Decode, Encode};
    /// Priority for network messages.
    #[derive(Clone, Copy, Debug, Encode, Decode, PartialEq, Eq)]
    pub enum Priority {
        /// Critical messages (consensus/control) that should be serviced first.
        High,
        /// Best-effort messages (gossip/sync) that can yield to high-priority ones.
        Low,
    }
    /// Variant-disjoint application route for subscriber fan-out.
    ///
    /// Topics remain transport scheduling classes. Routes prevent a generic
    /// topic consumer from competing for the only owned delivery of a message
    /// that belongs to a specialized application protocol.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum SubscriberRoute {
        /// Ordinary daemon/core message processing.
        General,
        /// Torii and `SoraCloud` request/response proxy protocol.
        ToriiProxy,
        /// Torii websocket Connect relay protocol.
        Connect,
        /// Sumeragi consensus frames: the consensus driver owns these FIFOs, one per traffic
        /// class, and never competes with the generic relay workers for them.
        Sumeragi,
    }
    /// Durable reconstruction available after a reliable progress delivery gap.
    ///
    /// Transport queues may use this contract only to isolate an unavailable
    /// target from responsive peers. `Retransmit` also asserts that retrying
    /// the same canonical request is idempotent; it never authorizes a distinct
    /// request digest to be retired under an older owner. This does not turn
    /// best-effort traffic into reliable traffic and does not promise progress
    /// without a responsive quorum and terminating reconstruction work.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub enum ProgressReconstruction {
        /// No compact reconstruction exists; the exact payload must retain an owner.
        #[default]
        Exact,
        /// The protocol retains a durable intent, fairly retransmits it, and
        /// treats a byte-identical canonical request as an idempotent retry.
        Retransmit,
    }
    /// Logical topic for scheduling per-topic substreams.
    ///
    /// Topics are advisory tags used by the peer to route messages into
    /// separate internal queues. This avoids head-of-line blocking between
    /// unrelated flows (e.g., consensus vs. block sync vs. gossip) and allows
    /// basic prioritization.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Topic {
        /// Authoritative consensus safety plane (proposals, votes, and certificates).
        ///
        /// This is a local scheduling tag and is not encoded on the wire. Keeping it
        /// distinct prevents unrelated control and auxiliary consensus traffic from
        /// consuming the queues needed to make global consensus progress.
        ConsensusSafety,
        /// Consensus data plane (votes, hints, and critical block-payload control signals).
        Consensus,
        /// Consensus payload chunks (RBC chunk data).
        ConsensusChunk,
        /// Consensus payload plane (block sync updates and proposal payloads).
        ConsensusPayload,
        /// Consensus control plane (view changes, coordination).
        Control,
        /// Block synchronization stream.
        BlockSync,
        /// Transaction gossip stream (public dataspaces).
        TxGossip,
        /// Transaction gossip stream for restricted dataspaces.
        TxGossipRestricted,
        /// Peer discovery gossip stream.
        PeerGossip,
        /// Signed trust gossip stream.
        TrustGossip,
        /// Health and diagnostics.
        Health,
        /// Authenticated Connect wallet-session relay traffic; never shares the health cap.
        Connect,
        /// Any other traffic not classified explicitly.
        Other,
    }
    impl Topic {
        /// Return the local scheduler class for this semantic topic.
        ///
        /// This mapping is the sole scheduler authority for relayed payloads, so
        /// authenticated peers cannot promote gossip or other bulk traffic into
        /// the consensus/control queues.
        pub(crate) const fn scheduling_priority(self) -> Priority {
            match self {
                Topic::ConsensusSafety
                | Topic::Consensus
                | Topic::ConsensusChunk
                | Topic::ConsensusPayload
                | Topic::Control => Priority::High,
                Topic::BlockSync
                | Topic::TxGossip
                | Topic::TxGossipRestricted
                | Topic::PeerGossip
                | Topic::TrustGossip
                | Topic::Health
                | Topic::Connect
                | Topic::Other => Priority::Low,
            }
        }

        /// Whether this topic may be delivered as best-effort traffic.
        ///
        /// Best-effort topics may use QUIC DATAGRAM when available; reliable topics
        /// always stay on streams.
        pub const fn is_best_effort(self) -> bool {
            matches!(
                self,
                Topic::TxGossip
                    | Topic::TxGossipRestricted
                    | Topic::PeerGossip
                    | Topic::TrustGossip
                    | Topic::Health
            )
        }
    }
    /// Semantic application admission class, independent of unchanged Topic caps.
    ///
    /// Safety, lane control, large bodies, application control, low-priority `BlockSync` and
    /// other low-priority traffic each have their own owner. These classes do not grant origin,
    /// committee, finality or execution authority. Fixed credit records use their independently
    /// precharged parser, never an application class.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum TransportAdmissionClass {
        /// Authoritative consensus safety messages.
        Safety,
        /// Ordinary consensus lane control.
        Lane,
        /// Large ordinary consensus bodies and chunks.
        Payload,
        /// Non-consensus application control, with no progress authority.
        Control,
        /// Reliable block synchronization in the existing low-priority lane.
        BlockSync,
        /// Other low-priority application traffic.
        Low,
    }
    impl TransportAdmissionClass {
        /// Exact first-release application-class cardinality.
        pub const COUNT: usize = 6;
        /// Complete class order bound by mandatory geometry and record framing.
        pub const ALL: [Self; Self::COUNT] = [
            Self::Safety,
            Self::Lane,
            Self::Payload,
            Self::Control,
            Self::BlockSync,
            Self::Low,
        ];
        /// Classes sharing the existing high byte ceiling.
        pub const HIGH: [Self; 4] = [Self::Safety, Self::Lane, Self::Payload, Self::Control];
        /// Non-safety classes partitioning the existing high occurrence ceiling.
        pub const ORDINARY_HIGH: [Self; 3] = [Self::Lane, Self::Payload, Self::Control];
        /// Classes partitioning the existing low byte and occurrence ceilings.
        pub const LOW: [Self; 2] = [Self::BlockSync, Self::Low];
        /// Deterministic weighted service cycle. High classes each receive two
        /// ranks, low classes one; every eligible low class retains finite service.
        /// A rank is one complete record, never a permission to skip missing TCP bytes.
        pub const SCHEDULE: [Self; 10] = [
            Self::Safety,
            Self::Lane,
            Self::Payload,
            Self::Control,
            Self::Safety,
            Self::Lane,
            Self::Payload,
            Self::Control,
            Self::BlockSync,
            Self::Low,
        ];
        /// Total local ownership index, independent of Topic and caller priority.
        #[must_use]
        pub const fn index(self) -> usize {
            self.wire_code() as usize
        }
        /// Exact one-byte class code shared by geometry offers and credit records.
        #[must_use]
        pub(crate) const fn wire_code(self) -> u8 {
            match self {
                Self::Safety => 0,
                Self::Lane => 1,
                Self::Payload => 2,
                Self::Control => 3,
                Self::BlockSync => 4,
                Self::Low => 5,
            }
        }
        /// Whether this class belongs to the existing low scheduling/resource lane.
        #[must_use]
        pub const fn is_low(self) -> bool {
            matches!(self, Self::BlockSync | Self::Low)
        }
        /// Map an ordinary topic to its admission class.
        #[must_use]
        pub const fn ordinary_for_topic(topic: Topic) -> Self {
            match topic {
                Topic::ConsensusSafety => Self::Safety,
                Topic::Consensus => Self::Lane,
                Topic::ConsensusPayload | Topic::ConsensusChunk => Self::Payload,
                Topic::BlockSync => Self::BlockSync,
                Topic::Control => Self::Control,
                Topic::TxGossip
                | Topic::TxGossipRestricted
                | Topic::PeerGossip
                | Topic::TrustGossip
                | Topic::Health
                | Topic::Connect
                | Topic::Other => Self::Low,
            }
        }
    }
    /// Classification hook for payload types to indicate their logical topic.
    ///
    /// By default, all messages are classified as `Topic::Other`. Crates that
    /// define concrete network payloads (e.g., `iroha_core::NetworkMessage`)
    /// should implement this trait to provide useful classification.
    pub trait ClassifyTopic {
        /// Whether this payload type installs an inbound resource policy before
        /// Norito materializes an attacker-controlled archive.
        ///
        /// The default keeps the historical decode path for payload types that
        /// do not need a variant-specific bound. Envelope types must propagate
        /// this value from their nested payload.
        const HAS_INBOUND_DECODE_LIMITS: bool = false;
        /// Return the logical topic of the message for scheduling.
        fn topic(&self) -> Topic {
            Topic::Other
        }
        /// Return the semantic application admission class.
        fn admission_class(&self) -> TransportAdmissionClass {
            TransportAdmissionClass::ordinary_for_topic(self.topic())
        }
        /// Classify a bare inbound application payload without materializing it.
        ///
        /// Envelopes must validate their own framing and delegate the exact
        /// nested field. A receive-credit consumer must compare the declared,
        /// raw and decoded classes; this hook does not validate signatures or
        /// every payload field. Unknown raw classification is an error, with
        /// no decoded-value or caller-priority fallback.
        ///
        /// # Errors
        ///
        /// Reject malformed or unknown discriminants and payload owners which
        /// provide no bounded raw classifier.
        fn inbound_admission_class(
            payload: &[u8],
            flags: u8,
        ) -> Result<TransportAdmissionClass, norito::core::Error> {
            let topic = Self::inbound_topic(payload, flags)?.ok_or_else(|| {
                norito::core::Error::Message(
                    "application payload has no raw admission classifier".to_owned(),
                )
            })?;
            Ok(TransportAdmissionClass::ordinary_for_topic(topic))
        }
        /// Return the locally trusted delivery priority for scheduling.
        ///
        /// Envelope implementations must derive this from their nested payload
        /// semantics.
        fn priority(&self) -> Priority {
            Priority::Low
        }
        /// Return the variant-disjoint application subscriber route.
        fn subscriber_route(&self) -> SubscriberRoute {
            SubscriberRoute::General
        }
        /// Describe the durable source which reconstructs a missed reliable
        /// progress payload for an isolated target.
        ///
        /// The default is exact ownership: generic payloads are never assumed
        /// to be durably retransmittable.
        fn progress_reconstruction(&self) -> ProgressReconstruction {
            ProgressReconstruction::Exact
        }
        /// Classify an inbound bare Norito payload before materializing it.
        ///
        /// `payload` excludes the Norito header and root-alignment padding, and
        /// `flags` carries the authenticated layout flags from that header.
        /// Envelope implementations must validate their own length-delimited
        /// layout and delegate the exact nested field. Returning `Some` lets the
        /// transport enforce the selected topic's frame cap before typed decode;
        /// returning `None` retains the decoded-value fallback for payload types
        /// without a raw classifier.
        ///
        /// # Errors
        ///
        /// Return an error when the bounded envelope prefix is malformed, has an
        /// unknown discriminant, or cannot be classified without guessing.
        fn inbound_topic(
            _payload: &[u8],
            _flags: u8,
        ) -> Result<Option<Topic>, norito::core::Error> {
            Ok(None)
        }
        /// Select resource limits for an inbound bare Norito payload.
        ///
        /// `payload` excludes the Norito header and any root-alignment padding.
        /// `framed_len` is the byte length of the complete outer P2P Norito
        /// frame and remains unchanged when an envelope delegates to its nested
        /// payload. `flags` carries the authenticated layout flags from that
        /// outer header.
        ///
        /// Implementations should inspect only bounded fixed-width prefixes and
        /// return limits before deserializing dynamic fields. Returning `None`
        /// preserves the ordinary decode path for the selected variant.
        ///
        /// # Errors
        ///
        /// Implementations may return an error when the bounded payload prefix
        /// is malformed or cannot yield a valid resource policy.
        fn inbound_decode_limits(
            _payload: &[u8],
            _framed_len: usize,
            _flags: u8,
        ) -> Result<Option<norito::DecodeLimits>, norito::core::Error> {
            Ok(None)
        }
        /// Return whether the payload may cross the live outbound network boundary.
        ///
        /// Implementations use this fail-closed hook to keep decode-only archival
        /// envelopes off the live peer network. Ordinary payloads are admitted by
        /// default.
        fn is_outbound_allowed(&self) -> bool {
            true
        }
    }
    /// Current online network peers
    pub type OnlinePeers = HashSet<Peer>;
    /// Transport capabilities observed/advertised for a peer.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
    pub struct PeerTransportCapabilities {
        /// Whether the peer advertises SCION-preferred transport support.
        pub scion_supported: bool,
    }
    /// Current transport capabilities for online peers keyed by peer id.
    pub type OnlinePeerCapabilities = HashMap<PeerId, PeerTransportCapabilities>;
    /// The message that is sent to `NetworkBase` to update p2p topology of the network.
    #[derive(Clone, Debug)]
    pub struct UpdateTopology(pub HashSet<PeerId>);
    /// The message that is sent to `NetworkBase` to update peers addresses of the network.
    #[derive(Clone, Debug)]
    pub struct UpdatePeers(pub Vec<(PeerId, SocketAddr)>);
    /// Configured validators eligible for deterministic pairwise dial ownership.
    ///
    /// This is local scheduling authority, never peer-gossip input. The set
    /// includes the local validator when it participates in the roster.
    #[derive(Clone, Debug)]
    pub struct UpdateValidatorDialRoster(pub HashSet<PeerId>);
    /// One atomic consensus-topology and validator-dial-ownership snapshot.
    ///
    /// `validator_dial_roster` must be the locally authenticated configured
    /// validator subset of `topology`; the network actor also intersects it
    /// with the immutable startup authority before applying it.
    #[derive(Clone, Debug)]
    pub struct UpdateValidatorTopology {
        /// Logical consensus topology, including the local peer when active.
        pub topology: HashSet<PeerId>,
        /// Configured validators governed by deterministic pairwise ownership.
        pub validator_dial_roster: HashSet<PeerId>,
    }
    /// Full latest-state snapshot of transport capabilities for peers.
    #[derive(Clone, Debug)]
    pub struct UpdatePeerCapabilities(pub Vec<(PeerId, PeerTransportCapabilities)>);
    /// Update ACL configuration at runtime (hot reload).
    #[derive(Clone, Debug, Default)]
    pub struct UpdateAcl {
        /// When true, only peers whose public keys appear in `allow_keys` are permitted.
        pub allowlist_only: bool,
        /// Allowlist of peer public keys.
        pub allow_keys: Vec<iroha_crypto::PublicKey>,
        /// Denylist of peer public keys.
        pub deny_keys: Vec<iroha_crypto::PublicKey>,
        /// CIDR allowlist (IPv4/IPv6), e.g., "192.168.1.0/24", `2001:db8::/32`.
        pub allow_cidrs: Vec<String>,
        /// CIDR denylist (checked before throttles).
        pub deny_cidrs: Vec<String>,
    }
    /// Update trusted peer list for lightweight reputation tracking.
    #[derive(Clone, Debug, Default)]
    pub struct UpdateTrustedPeers(pub HashSet<PeerId>);
    /// Update `SoraNet` handshake runtime configuration.
    #[derive(Debug)]
    pub struct UpdateHandshake {
        /// New handshake parameters to install.
        pub handshake: ActualSoranetHandshake,
        /// Exact response for this proposed runtime update.
        pub(crate) respond_to: oneshot::Sender<Result<(), Error>>,
    }
    /// The message to be sent to the other [`Peer`].
    #[derive(Clone, Debug)]
    pub struct Post<T> {
        /// Data to be sent
        pub data: T,
        /// Destination peer
        pub peer_id: PeerId,
        /// Delivery priority
        pub priority: Priority,
    }
    /// The message to be send to the all connected [`Peer`]s.
    #[derive(Clone, Debug)]
    pub struct Broadcast<T> {
        /// Data to be send
        pub data: T,
        /// Delivery priority
        pub priority: Priority,
    }
    /// Message send to network by other actors.
    pub(crate) enum NetworkMessage<T> {
        Post(Post<T>),
        Broadcast(Broadcast<T>),
    }
}
/// Reference as a means of communication with a [`Peer`]
struct RefPeer<T: Pload> {
    handle: PeerHandle<T>,
    conn_id: ConnectionId,
    p2p_addr: SocketAddr,
    relay_role: RelayRole,
    trust_gossip: bool,
}
#[derive(Clone, Copy, Debug)]
enum TrustDirection {
    Inbound,
    Outbound,
}
impl TrustDirection {
    fn as_label(self) -> &'static str {
        match self {
            Self::Inbound => "recv",
            Self::Outbound => "send",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeferredFlushOutcome {
    Flushed,
    PeerMissing,
    Backpressured(ConnectionId),
}
enum ReliableWriterAttempt {
    Awaiting(PendingWriterFlush),
    Retry,
}
#[derive(Clone, Debug, Default)]
struct PeerReputation {
    trusted: bool,
    score: i32,
}
#[derive(Default)]
struct PeerReputationBook {
    inner: HashMap<PeerId, PeerReputation>,
}
impl PeerReputationBook {
    fn trusted_peers(&self) -> Vec<PeerId> {
        self.inner
            .iter()
            .filter_map(|(peer, rep)| rep.trusted.then_some(peer.clone()))
            .collect()
    }
    fn set_trusted(&mut self, trusted: &HashSet<PeerId>) {
        for id in trusted {
            self.inner.entry(id.clone()).or_default().trusted = true;
        }
        // Clear trust flag for peers not present in the new set.
        for (peer_id, rep) in &mut self.inner {
            rep.trusted = trusted.contains(peer_id);
            if !rep.trusted {
                rep.score = 0;
            }
        }
        self.inner
            .retain(|_, reputation| reputation.trusted || reputation.score != 0);
    }
    fn record_connected(&mut self, peer: &PeerId) {
        let rep = self.inner.entry(peer.clone()).or_default();
        rep.score = rep.score.saturating_add(1);
    }
    fn record_disconnected(&mut self, peer: &PeerId) {
        let remove = self.inner.get_mut(peer).is_some_and(|rep| {
            rep.score = rep.score.saturating_sub(1);
            rep.score == 0 && !rep.trusted
        });
        if remove {
            self.inner.remove(peer);
        }
    }
    fn is_trusted(&self, peer: &PeerId) -> bool {
        self.inner
            .get(peer)
            .is_some_and(|rep| rep.trusted || rep.score > 0)
    }
    fn score(&self, peer: &PeerId) -> i32 {
        self.inner.get(peer).map_or(0, |rep| rep.score)
    }
    #[cfg(test)]
    fn snapshot(&self) -> HashMap<PeerId, PeerReputation> {
        self.inner.clone()
    }
}
// Low-priority helpers were accidentally emitted outside of the impl, which
// causes free functions with a `self` parameter (invalid) and missing generics.
// Wrap them into the NetworkBase impl where they belong.
impl<T: Pload + message::ClassifyTopic + Sync, E: Enc> NetworkBase<T, E> {
    fn low_allow(&mut self, id: &PeerId) -> bool {
        let Some(rate) = self.low_rate_per_sec else {
            return true;
        };
        let burst = self.low_burst.unwrap_or_else(|| rate.max(1.0));
        self.low_buckets
            .entry(id.clone())
            .or_insert_with(|| TokenBucket::new(rate, burst))
            .allow()
    }
    #[allow(clippy::cast_precision_loss)]
    fn low_allow_bytes(&mut self, id: &PeerId, bytes: usize) -> bool {
        let Some(rate) = self.low_bytes_per_sec else {
            return true;
        };
        let burst = self.low_bytes_burst;
        self.low_bytes_buckets
            .entry(id.clone())
            .or_insert_with(|| TokenBucket::new(rate, burst))
            .allow_n(bytes as f64)
    }
    fn post_low(&mut self, Post { data, peer_id, .. }: Post<T>) {
        iroha_logger::trace!(peer=%peer_id, "Post message (low)");
        let topic = data.topic();
        let relay_ttl = self.relay_ttl;
        let key_pair = Arc::clone(&self.key_pair);
        let frame_for = |target: RelayTarget| {
            RelayMessage::new_signed(&key_pair, target, relay_ttl, data.clone())
        };
        let send_with_throttle = |this: &mut Self, target_id: &PeerId, frame: RelayMessage<T>| {
            if !this.low_allow(target_id) {
                iroha_logger::debug!(peer=%target_id, "Low-priority post throttled by token bucket");
                LOW_THROTTLED_POSTS.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            let Ok(size_bytes) = crate::peer::checked_data_message_wire_len(&frame) else {
                iroha_logger::warn!(peer=%target_id, "Low-priority post frame size is not representable");
                return false;
            };
            if !this.low_allow_bytes(target_id, size_bytes) {
                iroha_logger::debug!(peer=%target_id, size=size_bytes, "Low-priority post throttled by bytes token bucket");
                LOW_THROTTLED_POSTS.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            this.send_frame_to_peer(target_id, frame, topic)
        };
        if let Some(hub_id) = self.relay_route_for_unconnected_post_target(&peer_id) {
            let _ = send_with_throttle(self, &hub_id, frame_for(RelayTarget::Direct(peer_id)));
            return;
        }
        if send_with_throttle(
            self,
            &peer_id,
            frame_for(RelayTarget::Direct(peer_id.clone())),
        ) {
            return;
        }
        if matches!(
            self.relay_mode,
            iroha_config::parameters::actual::RelayMode::Spoke
                | iroha_config::parameters::actual::RelayMode::Assist
        ) {
            if let Some(hub_id) = self.hub_handle().map(|(id, _)| id.clone()) {
                let _ = send_with_throttle(self, &hub_id, frame_for(RelayTarget::Direct(peer_id)));
            } else {
                iroha_logger::warn!(
                    peer=%peer_id,
                    "Relay mode could not route low post because hub is unavailable"
                );
            }
        }
    }
    fn broadcast_low(&mut self, Broadcast { data, .. }: Broadcast<T>) {
        iroha_logger::trace!("Broadcast message (low)");
        let topic = data.topic();
        let peers: Vec<PeerId> = self.peers.keys().cloned().collect();
        for pid in peers {
            let frame = RelayMessage::new_signed(
                &self.key_pair,
                RelayTarget::Broadcast,
                self.relay_ttl,
                data.clone(),
            );
            let Ok(size_bytes) = crate::peer::checked_data_message_wire_len(&frame) else {
                iroha_logger::warn!(peer=%pid, "Low-priority broadcast frame size is not representable");
                continue;
            };
            if !self.low_allow(&pid) || !self.low_allow_bytes(&pid, size_bytes) {
                LOW_THROTTLED_BROADCASTS.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            self.send_frame_to_peer(&pid, frame, topic);
        }
    }
}

#[cfg(test)]
mod frame_identity_tests;
