//! The Sumeragi driver's transport over Iroha P2P (`specs/sumeragi.md` §12.2, §12.3 O5–O10;
//! integration map §5).
//!
//! - **Envelope.** [`NetworkMessage::Sumeragi`] carries one [`SumeragiFrame`]: the exact
//!   canonical bytes of a core `WireMessage`, including source-bound application control,
//!   signed payload manifests, row chunks and requests, plus the 32-byte instance id.
//!   The driver enforces canonical, size-limited decoding with `WireMessage::decode`;
//!   the network codec sees an opaque byte string.
//! - **Classes.** [`frame_class`] uses the core's single `traffic_class_of_frame` helper
//!   over the exact bytes. Both the decoded path ([`SumeragiFrame::topic`], hence
//!   `NetworkMessage::topic`/`admission_class`) and raw pre-decode path
//!   ([`inbound_frame_topic`], [`inbound_decode_limits`]) use that helper, so the P2P
//!   reader's raw/decoded comparison agrees. Signed row chunks are Bulk and requests
//!   are Control. Control → `ConsensusSafety` (the reserved safety FIFO), Proposal →
//!   `ConsensusPayload`, Bulk → `BlockSync` ([`topic_of_class`]).
//! - **Egress.** [`P2pNet`] implements the driver's [`Net`] with one `post_recoverable` per
//!   recipient ([`SumeragiTransport`]); backpressure returns an owned retry containing the
//!   exact original post and its admission ticket. Payload streams retain that owner until
//!   admission; protocol-timer sends may explicitly cancel it. It never uses `post()` (which
//!   asserts on reliable routes) or `broadcast_recoverable` (which targets the P2P topology, not
//!   the core's explicit recipients). The envelope is built once per frame and shared by every
//!   recipient.
//! - **Ingress.** The frames arrive on the driver's own P2P FIFOs — one per class on
//!   `SubscriberRoute::Sumeragi` ([`P2pNet::subscribe`]) — and [`SumeragiIngress`] hands each to the
//!   driver of its instance (the driver's ingress is bounded per peer and class, O6), dropping
//!   the P2P retention at once so credits never stall.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread::JoinHandle,
};

use iroha_config::parameters::defaults::network::{
    MAX_FRAME_BYTES_CONTROL, MAX_PLAINTEXT_FRAME_BYTES,
};
use iroha_model_base::peer::PeerId;
use iroha_p2p::{
    Priority,
    network::{
        NetworkActorAdmissionError, NetworkActorAdmissionTicket, SubscriberFilter,
        message::{Post, SubscriberRoute, Topic, TransportAdmissionClass},
    },
    peer::message::PeerMessage,
};
use iroha_sumeragi::{
    message::{TrafficClass, traffic_class_of_frame},
    pacemaker::FRAME_OVERHEAD,
    types::{Hash32, PublicKey},
};
use norito::codec::{Decode, Encode};
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;

use super::{
    crypto::{core_key, iroha_key},
    driver::{
        DriverHandle,
        traits::{Frame, Net, PendingSend, SendOutcome},
    },
};
use crate::{IrohaNetwork, NetworkMessage};

/// One Sumeragi wire frame in the P2P envelope: the exact canonical encoding of a core
/// `WireMessage`, and the instance it belongs to.
/// The bytes are never decoded by the network codec.
#[derive(Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::sumeragi::net::SumeragiFrame")]
pub struct SumeragiFrame {
    instance: [u8; 32],
    frame: Vec<u8>,
}

impl core::fmt::Debug for SumeragiFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SumeragiFrame")
            .field("instance", &Hash32(self.instance))
            .field("len", &self.frame.len())
            .field("class", &self.class())
            .finish()
    }
}

impl SumeragiFrame {
    /// A frame of `instance` with the exact encoded bytes `frame`.
    pub fn new(instance: Hash32, frame: Vec<u8>) -> Self {
        Self {
            instance: instance.0,
            frame,
        }
    }

    /// The envelope of a driver frame.
    pub fn from_frame(frame: &Frame) -> Self {
        Self::new(frame.instance, frame.bytes.to_vec())
    }

    /// The instance the frame is routed to.
    pub fn instance(&self) -> Hash32 {
        Hash32(self.instance)
    }

    /// The exact encoded `WireMessage`.
    pub fn bytes(&self) -> &[u8] {
        &self.frame
    }

    /// The frame's traffic class ([`frame_class`]); `None` if it is not a classifiable frame.
    pub fn class(&self) -> Option<TrafficClass> {
        frame_class(&self.frame)
    }

    /// The P2P topic of the frame; `Topic::Other` if it is not classifiable (such a frame is
    /// never sent and is rejected by the raw classifier on receipt).
    pub fn topic(&self) -> Topic {
        self.class().map_or(Topic::Other, topic_of_class)
    }
}

/// The traffic class of a canonical Sumeragi frame (§12.3 O8): a core `WireMessage` frame by
/// the core's table, a payload-availability frame (§12.8) by its own (a chunk is proposal
/// traffic, a chunk request control traffic); `None` for anything else. The single classifier
/// of both the decoded and the raw P2P paths.
pub fn frame_class(frame: &[u8]) -> Option<TrafficClass> {
    traffic_class_of_frame(frame)
}

/// The P2P topic of a traffic class: control → `ConsensusSafety` (reserved safety FIFO),
/// proposal → `ConsensusPayload`, bulk → `BlockSync` (integration map §5).
pub const fn topic_of_class(class: TrafficClass) -> Topic {
    match class {
        TrafficClass::Control => Topic::ConsensusSafety,
        TrafficClass::Proposal => Topic::ConsensusPayload,
        TrafficClass::Bulk => Topic::BlockSync,
    }
}

/// The P2P admission class of a traffic class (`Safety`, `Payload`, `BlockSync`).
pub const fn admission_of_class(class: TrafficClass) -> TransportAdmissionClass {
    TransportAdmissionClass::ordinary_for_topic(topic_of_class(class))
}

/// The P2P send priority of a traffic class (the actor re-derives it from the topic).
pub const fn priority_of_class(class: TrafficClass) -> Priority {
    match class {
        TrafficClass::Control | TrafficClass::Proposal => Priority::High,
        TrafficClass::Bulk => Priority::Low,
    }
}

/// Frame caps per traffic class, in bytes of the encoded `WireMessage` (integration map §5,
/// spec §12.3 O10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameCaps {
    /// Control frames.
    pub control: usize,
    /// Proposal frames (`max_block_bytes + FRAME_OVERHEAD`).
    pub proposal: usize,
    /// Bulk frames (`sync_max_bytes + FRAME_OVERHEAD`).
    pub bulk: usize,
}

impl FrameCaps {
    /// The transport's static caps (its topic frame caps): control 2 MiB, proposal and bulk
    /// the payload/block-sync cap. The chain parameters are validated against them (O10).
    pub const TRANSPORT: Self = Self {
        control: MAX_FRAME_BYTES_CONTROL.get(),
        proposal: MAX_PLAINTEXT_FRAME_BYTES.get(),
        bulk: MAX_PLAINTEXT_FRAME_BYTES.get(),
    };

    /// The caps for `max_block_bytes` and `sync_max_bytes`: control 2 MiB, proposal
    /// `max_block_bytes + FRAME_OVERHEAD`, bulk `sync_max_bytes + FRAME_OVERHEAD`, each at most
    /// the transport's.
    pub fn for_params(max_block_bytes: u32, sync_max_bytes: u32) -> Self {
        let with_overhead = |bytes: u32| {
            usize::try_from(u64::from(bytes) + u64::from(FRAME_OVERHEAD)).unwrap_or(usize::MAX)
        };
        Self {
            control: Self::TRANSPORT.control,
            proposal: with_overhead(max_block_bytes).min(Self::TRANSPORT.proposal),
            bulk: with_overhead(sync_max_bytes).min(Self::TRANSPORT.bulk),
        }
    }

    /// The cap of `class`.
    pub const fn of(&self, class: TrafficClass) -> usize {
        match class {
            TrafficClass::Control => self.control,
            TrafficClass::Proposal => self.proposal,
            TrafficClass::Bulk => self.bulk,
        }
    }
}

/// The exact `WireMessage` bytes inside the bare `SumeragiFrame` payload `field` (the value
/// after the `NetworkMessage` variant and `Arc` boundaries), without copying or decoding.
fn raw_frame(field: &[u8], flags: u8) -> Result<&[u8], norito::core::Error> {
    use norito::core::Error;
    // The sole native envelope has exactly two length-prefixed fields. Parse
    // both boundaries before exposing the byte sequence; no retired envelope
    // decoder or heuristic layout selection participates in admission.
    let mut remaining = field;
    let mut frame = None;
    for index in 0..2 {
        let (length, prefix) = norito::core::read_len_from_slice_with_flags(remaining, flags)?;
        let end = prefix.checked_add(length).ok_or(Error::LengthMismatch)?;
        let value = remaining.get(prefix..end).ok_or(Error::LengthMismatch)?;
        remaining = remaining.get(end..).ok_or(Error::LengthMismatch)?;
        if index == 1 {
            frame = Some(value);
        }
    }
    if !remaining.is_empty() {
        return Err(Error::LengthMismatch);
    }
    let frame = frame.ok_or(Error::LengthMismatch)?;
    let count: [u8; 8] = frame
        .get(..8)
        .ok_or(Error::LengthMismatch)?
        .try_into()
        .map_err(|_| Error::LengthMismatch)?;
    let count = usize::try_from(u64::from_le_bytes(count)).map_err(|_| Error::LengthMismatch)?;
    if count.checked_add(8) != Some(frame.len()) {
        return Err(Error::LengthMismatch);
    }
    frame.get(8..).ok_or(Error::LengthMismatch)
}

/// Raw (pre-decode) P2P topic of a bare `SumeragiFrame` payload: [`frame_class`] of the exact
/// bytes, as for the decoded value. An unclassifiable frame is an error (rejected unread).
///
/// # Errors
/// A malformed envelope or an unclassifiable frame.
pub fn inbound_frame_topic(field: &[u8], flags: u8) -> Result<Topic, norito::core::Error> {
    frame_class(raw_frame(field, flags)?)
        .map(topic_of_class)
        .ok_or_else(|| norito::core::Error::Message("unclassifiable Sumeragi frame".to_owned()))
}

/// Decode limits of a `NetworkMessage::Sumeragi` P2P frame of `framed_len` bytes whose bare
/// `SumeragiFrame` payload is `field`: the class's transport cap bounds the frame, its one
/// byte string and the total allocation.
///
/// # Errors
/// A malformed envelope, an unclassifiable frame, or a frame above its class cap.
pub fn inbound_decode_limits(
    field: &[u8],
    framed_len: usize,
    flags: u8,
) -> Result<norito::DecodeLimits, norito::core::Error> {
    let class = frame_class(raw_frame(field, flags)?)
        .ok_or_else(|| norito::core::Error::Message("unclassifiable Sumeragi frame".to_owned()))?;
    let cap = FrameCaps::TRANSPORT.of(class);
    if framed_len > cap {
        return Err(norito::core::Error::ArchiveLengthExceeded {
            length: u64::try_from(framed_len).unwrap_or(u64::MAX),
            limit: u64::try_from(cap).unwrap_or(u64::MAX),
        });
    }
    Ok(norito::DecodeLimits::new(
        cap,
        cap,
        cap.saturating_add(64),
        cap.saturating_mul(12),
        64,
    ))
}

/// The non-blocking reliable post the driver needs from the P2P network (a test seam).
pub trait SumeragiTransport: Send + Sync + 'static {
    /// Attempt the exact owned post without blocking. Refusal returns the original post
    /// and its FIFO ticket so the caller can retry without losing occurrence identity.
    ///
    /// # Errors
    /// Backpressure retains admission ownership; closure and rejection are terminal.
    fn post_frame(
        &self,
        post: Post<NetworkMessage>,
        ticket: Option<NetworkActorAdmissionTicket>,
    ) -> Result<(), NetworkActorAdmissionError<Post<NetworkMessage>>>;
}

impl SumeragiTransport for IrohaNetwork {
    fn post_frame(
        &self,
        post: Post<NetworkMessage>,
        ticket: Option<NetworkActorAdmissionTicket>,
    ) -> Result<(), NetworkActorAdmissionError<Post<NetworkMessage>>> {
        self.post_recoverable(post, ticket)
    }
}

/// Egress counters of a [`P2pNet`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetStats {
    /// Posts admitted.
    pub sent: u64,
    /// Attempts refused under backpressure, including retries of retained posts.
    pub backpressured: u64,
    /// Posts dropped because the network is closed.
    pub closed: u64,
    /// Posts refused.
    pub rejected: u64,
    /// Recipients that are not valid BLS-normal keys.
    pub bad_recipient: u64,
}

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    backpressured: AtomicU64,
    closed: AtomicU64,
    rejected: AtomicU64,
    bad_recipient: AtomicU64,
}

impl Counters {
    fn record(&self, result: &Result<(), NetworkActorAdmissionError<Post<NetworkMessage>>>) {
        let counter = match result {
            Ok(()) => &self.sent,
            Err(NetworkActorAdmissionError::Backpressured { .. }) => &self.backpressured,
            Err(NetworkActorAdmissionError::Closed { .. }) => &self.closed,
            Err(NetworkActorAdmissionError::Rejected { reason, .. }) => {
                iroha_logger::debug!(?reason, "sumeragi frame refused by the P2P actor");
                &self.rejected
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// One caller-owned refusal, never a hidden adapter queue. The returned P2P ticket
/// owns its exact per-recipient/class FIFO position and topology generation.
struct PendingP2pSend<T> {
    transport: Arc<T>,
    counters: Arc<Counters>,
    post: Option<Post<NetworkMessage>>,
    ticket: Option<NetworkActorAdmissionTicket>,
}

impl<T: SumeragiTransport> PendingSend for PendingP2pSend<T> {
    fn retry(mut self: Box<Self>) -> SendOutcome {
        // Only this consuming method takes the post. A refused attempt reinstalls
        // the exact value before returning this same owner to its caller.
        let post = self
            .post
            .take()
            .expect("pending send owns its original post");
        let result = self.transport.post_frame(post, self.ticket.take());
        self.counters.record(&result);
        match result {
            Ok(()) => SendOutcome::Admitted,
            Err(NetworkActorAdmissionError::Backpressured {
                message, ticket, ..
            }) => {
                self.post = Some(message);
                self.ticket = ticket;
                SendOutcome::Backpressured(self)
            }
            Err(NetworkActorAdmissionError::Closed { .. }) => SendOutcome::Closed,
            Err(NetworkActorAdmissionError::Rejected { .. }) => SendOutcome::Rejected,
        }
    }
}

/// Largest number of recipient `PeerId`s cached by a [`P2pNet`].
const PEER_CACHE: usize = 4096;

/// The driver's [`Net`] over the P2P network (see the module documentation).
pub struct P2pNet<T> {
    transport: Arc<T>,
    /// The envelope of the frame sent last (one per frame, shared by its recipients).
    envelope: Mutex<Option<(Arc<[u8]>, Arc<SumeragiFrame>)>>,
    /// Recipient keys already converted to `PeerId`s.
    peers: Mutex<HashMap<PublicKey, PeerId>>,
    counters: Arc<Counters>,
}

impl<T> core::fmt::Debug for P2pNet<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("P2pNet")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl<T> P2pNet<T> {
    /// A transport over `transport` (the node's `IrohaNetwork`).
    pub fn new(transport: T) -> Self {
        Self {
            transport: Arc::new(transport),
            envelope: Mutex::new(None),
            peers: Mutex::new(HashMap::new()),
            counters: Arc::default(),
        }
    }

    /// The egress counters.
    pub fn stats(&self) -> NetStats {
        let c = &self.counters;
        NetStats {
            sent: c.sent.load(Ordering::Relaxed),
            backpressured: c.backpressured.load(Ordering::Relaxed),
            closed: c.closed.load(Ordering::Relaxed),
            rejected: c.rejected.load(Ordering::Relaxed),
            bad_recipient: c.bad_recipient.load(Ordering::Relaxed),
        }
    }

    /// The envelope of `frame`: built once and shared (`Arc`) by every recipient.
    fn envelope(&self, frame: &Frame) -> Arc<SumeragiFrame> {
        let mut cached = self.envelope.lock();
        if let Some((bytes, envelope)) = cached.as_ref()
            && Arc::ptr_eq(bytes, &frame.bytes)
            && envelope.instance() == frame.instance
        {
            return Arc::clone(envelope);
        }
        let envelope = Arc::new(SumeragiFrame::from_frame(frame));
        *cached = Some((Arc::clone(&frame.bytes), Arc::clone(&envelope)));
        envelope
    }

    /// The `PeerId` of a recipient key; `None` if the key is not a valid BLS-normal key.
    fn peer(&self, key: &PublicKey) -> Option<PeerId> {
        if let Some(peer) = self.peers.lock().get(key) {
            return Some(peer.clone());
        }
        let peer = PeerId::new(iroha_key(key).ok()?);
        let mut peers = self.peers.lock();
        if peers.len() >= PEER_CACHE {
            peers.clear();
        }
        peers.insert(key.clone(), peer.clone());
        Some(peer)
    }
}

impl<T: SumeragiTransport> Net for P2pNet<T> {
    fn send(&self, to: &PublicKey, frame: &Frame) -> SendOutcome {
        let Some(peer) = self.peer(to) else {
            self.counters.bad_recipient.fetch_add(1, Ordering::Relaxed);
            return SendOutcome::Rejected;
        };
        let post = Post {
            data: NetworkMessage::Sumeragi(self.envelope(frame)),
            peer_id: peer,
            priority: priority_of_class(frame.class),
        };
        let result = self.transport.post_frame(post, None);
        self.counters.record(&result);
        match result {
            Ok(()) => SendOutcome::Admitted,
            Err(NetworkActorAdmissionError::Backpressured {
                message, ticket, ..
            }) => SendOutcome::Backpressured(Box::new(PendingP2pSend {
                transport: Arc::clone(&self.transport),
                counters: Arc::clone(&self.counters),
                post: Some(message),
                ticket,
            })),
            Err(NetworkActorAdmissionError::Closed { .. }) => SendOutcome::Closed,
            Err(NetworkActorAdmissionError::Rejected { .. }) => SendOutcome::Rejected,
        }
    }
}

/// Where the ingress hands a frame: the driver of one instance (a test seam).
pub trait FrameSink: Send + Sync {
    /// Deliver the encoded frame `frame` from the authenticated peer `from`; returns whether it
    /// was queued (never blocks; the driver decodes and bounds it).
    fn deliver(&self, from: &PublicKey, frame: &[u8]) -> bool;
}

impl FrameSink for DriverHandle {
    fn deliver(&self, from: &PublicKey, frame: &[u8]) -> bool {
        DriverHandle::deliver(self, from, frame)
    }
}

/// What the ingress did with one inbound message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Routed {
    /// Queued by the instance's driver.
    Delivered,
    /// The driver refused it (undecodable, another instance inside, the node's own, ...).
    Refused,
    /// Not a Sumeragi frame.
    NotSumeragi,
    /// Relayed (origin differs from the authenticated connection): not accepted, so the ingress
    /// stays bounded by the authenticated peers.
    Relayed,
    /// The sender's key is not a BLS-normal consensus key.
    BadSender,
    /// No driver runs the frame's instance.
    UnknownInstance,
    /// Unclassifiable, or above its class cap.
    Oversize,
}

/// Ingress counters of a [`SumeragiIngress`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IngressStats {
    /// Frames delivered.
    pub delivered: u64,
    /// Frames not delivered.
    pub dropped: u64,
}

/// Routes inbound Sumeragi frames to the driver of their instance (O9).
pub struct SumeragiIngress {
    routes: RwLock<HashMap<Hash32, Arc<dyn FrameSink>>>,
    caps: FrameCaps,
    delivered: AtomicU64,
    dropped: AtomicU64,
}

impl core::fmt::Debug for SumeragiIngress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SumeragiIngress")
            .field("instances", &self.routes.read().len())
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

impl SumeragiIngress {
    /// An ingress with no instance, dropping frames above `caps`.
    pub fn new(caps: FrameCaps) -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
            caps,
            delivered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    /// Route the frames of `instance` to `sink` (its driver).
    pub fn register(&self, instance: Hash32, sink: Arc<dyn FrameSink>) {
        self.routes.write().insert(instance, sink);
    }

    /// Stop routing `instance`; returns whether it was routed.
    pub fn unregister(&self, instance: &Hash32) -> bool {
        self.routes.write().remove(instance).is_some()
    }

    /// The ingress counters.
    pub fn stats(&self) -> IngressStats {
        IngressStats {
            delivered: self.delivered.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }

    /// Route one message from the P2P subscription. Its retention (P2P credit) is released
    /// before this returns.
    ///
    /// Only a [`PeerMessage`] reaches a driver, so every routed frame carries the peer of the
    /// authenticated connection it arrived on (and is dropped as [`Routed::Relayed`] when its
    /// origin differs). A decoded [`SumeragiFrame`] carries no sender and cannot be routed:
    ///
    /// ```compile_fail
    /// use iroha_core::sumeragi::net::{SumeragiFrame, SumeragiIngress};
    ///
    /// fn route_senderless_frame(ingress: &SumeragiIngress, frame: SumeragiFrame) {
    ///     ingress.route(frame);
    /// }
    /// ```
    ///
    /// ```no_run
    /// use iroha_core::{NetworkMessage, sumeragi::net::SumeragiIngress};
    /// use iroha_p2p::peer::message::PeerMessage;
    ///
    /// fn route_authenticated(ingress: &SumeragiIngress, message: PeerMessage<NetworkMessage>) {
    ///     ingress.route(message);
    /// }
    /// ```
    pub fn route(&self, message: PeerMessage<NetworkMessage>) -> Routed {
        let (origin, authenticated_via, payload, _bytes, retention) = message.into_parts();
        drop(retention);
        let routed = self.route_parts(origin.id(), &authenticated_via, &payload);
        let counter = if routed == Routed::Delivered {
            &self.delivered
        } else {
            &self.dropped
        };
        counter.fetch_add(1, Ordering::Relaxed);
        routed
    }

    /// Route a frame an in-process transport carries from the authenticated consensus key
    /// `from` (the same instance routing and class caps as [`Self::route`]).
    pub fn deliver(&self, from: &PublicKey, frame: &super::driver::traits::Frame) -> Routed {
        let routed = if frame.bytes.len() > self.caps.of(frame.class) {
            Routed::Oversize
        } else {
            match self.routes.read().get(&frame.instance).cloned() {
                None => Routed::UnknownInstance,
                Some(sink) if sink.deliver(from, &frame.bytes) => Routed::Delivered,
                Some(_) => Routed::Refused,
            }
        };
        let counter = if routed == Routed::Delivered {
            &self.delivered
        } else {
            &self.dropped
        };
        counter.fetch_add(1, Ordering::Relaxed);
        routed
    }

    /// [`SumeragiIngress::route`] of a message from `origin`, received over the
    /// authenticated connection of `via`.
    fn route_parts(&self, origin: &PeerId, via: &PeerId, payload: &NetworkMessage) -> Routed {
        let NetworkMessage::Sumeragi(frame) = payload else {
            return Routed::NotSumeragi;
        };
        if origin != via {
            return Routed::Relayed;
        }
        let Ok(from) = core_key(&via.public_key) else {
            return Routed::BadSender;
        };
        match frame.class() {
            Some(class) if frame.bytes().len() <= self.caps.of(class) => {}
            _ => return Routed::Oversize,
        }
        let Some(sink) = self.routes.read().get(&frame.instance()).cloned() else {
            return Routed::UnknownInstance;
        };
        if sink.deliver(&from, frame.bytes()) {
            Routed::Delivered
        } else {
            Routed::Refused
        }
    }
}

/// The driver's P2P FIFOs: one per traffic class on `SubscriberRoute::Sumeragi`.
#[derive(Debug)]
pub struct SumeragiSubscription {
    /// Control class (`Safety` admission, the reserved FIFO).
    pub control: mpsc::Receiver<PeerMessage<NetworkMessage>>,
    /// Proposal class (`Payload` admission).
    pub proposal: mpsc::Receiver<PeerMessage<NetworkMessage>>,
    /// Bulk class (`BlockSync` admission).
    pub bulk: mpsc::Receiver<PeerMessage<NetworkMessage>>,
}

/// The subscription filter of each traffic class's FIFO.
pub fn subscription_filters() -> [(TrafficClass, SubscriberFilter); 3] {
    [
        TrafficClass::Control,
        TrafficClass::Proposal,
        TrafficClass::Bulk,
    ]
    .map(|class| {
        (
            class,
            SubscriberFilter::SemanticClass {
                class: admission_of_class(class),
                route: SubscriberRoute::Sumeragi,
            },
        )
    })
}

/// Why the driver could not subscribe to its FIFOs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the P2P network refused the sumeragi subscription (shut down or queue full)")]
pub struct SubscribeError;

impl P2pNet<IrohaNetwork> {
    /// Subscribe the driver to its three FIFOs on this transport's retained actor,
    /// each holding up to `capacity` messages. P2P further bounds bytes and credits.
    ///
    /// Send and receive custody always belong to the same actor. No independent
    /// network handle can replace the inbound owner at node startup.
    ///
    /// # Errors
    /// The retained actor is shut down or its registration queue is full.
    pub fn subscribe(&self, capacity: usize) -> Result<SumeragiSubscription, SubscribeError> {
        let [control, proposal, bulk] = subscription_filters().map(|(_, filter)| {
            let (tx, rx) = mpsc::channel(capacity.max(1));
            let result = self
                .transport
                .subscribe_to_peers_messages_with_filter(tx, filter);
            if result.is_ok() || cfg!(all(test, sumeragi_core_mutation = "HC23")) {
                Ok(rx)
            } else {
                Err(SubscribeError)
            }
        });
        Ok(SumeragiSubscription {
            control: control?,
            proposal: proposal?,
            bulk: bulk?,
        })
    }
}

/// Drain `subscription` into `ingress` on a dedicated thread (decoding stays off the async
/// runtime), control first, then proposal, then bulk. The thread ends when every FIFO closes.
///
/// # Errors
/// The thread could not be spawned.
pub fn spawn_ingress(
    subscription: SumeragiSubscription,
    ingress: Arc<SumeragiIngress>,
) -> std::io::Result<JoinHandle<()>> {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    std::thread::Builder::new()
        .name("sumeragi-ingress".to_owned())
        .spawn(move || {
            let SumeragiSubscription {
                mut control,
                mut proposal,
                mut bulk,
            } = subscription;
            runtime.block_on(async move {
                loop {
                    let message = tokio::select! {
                        biased;
                        Some(message) = control.recv() => message,
                        Some(message) = proposal.recv() => message,
                        Some(message) = bulk.recv() => message,
                        else => break,
                    };
                    ingress.route(message);
                }
            });
        })
}

#[cfg(test)]
mod tests {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::peer::Peer;
    use iroha_p2p::network::message::ClassifyTopic;
    use iroha_sumeragi::availability::{AvailabilityFrame, RowBytes};
    use iroha_sumeragi::{
        message::{
            BlockHeader, PayloadChunk, PayloadManifest, PayloadRequest, Proposal, ProposalMessage,
            Qc, Status, SyncEntry, SyncRequest, SyncResponse, TcEntry, TimeoutCert, TimeoutVote,
            Vote, VoteKind, WireMessage,
        },
        types::{AggregateSignature, Bitmap, EpochId, SIGNATURE_LEN, Signature},
    };
    use norito::core as ncore;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use super::*;

    fn h(rng: &mut StdRng) -> Hash32 {
        Hash32(rng.random())
    }

    fn epoch(rng: &mut StdRng) -> EpochId {
        EpochId {
            epoch: rng.random_range(0..100),
            context: h(rng),
        }
    }

    fn sig(rng: &mut StdRng) -> Signature {
        Signature([rng.random(); SIGNATURE_LEN])
    }

    fn qc(rng: &mut StdRng, instance: Hash32) -> Qc {
        Qc {
            kind: if rng.random() {
                VoteKind::Prepare
            } else {
                VoteKind::Commit
            },
            instance,
            epoch: epoch(rng),
            height: rng.random_range(1..1_000),
            view: rng.random_range(0..10),
            block_hash: h(rng),
            result: h(rng),
            signers: Bitmap::new(rng.random_range(1..20)),
            agg_sig: AggregateSignature([rng.random(); SIGNATURE_LEN]),
        }
    }

    /// Structurally bounded untrusted wire metadata for classifier tests, not body custody.
    fn manifest(rng: &mut StdRng, instance: Hash32) -> PayloadManifest {
        PayloadManifest {
            header: BlockHeader {
                instance,
                epoch: epoch(rng),
                height: rng.random_range(1..1_000),
                origin_view: 0,
                parent_hash: h(rng),
                parent_result: h(rng),
                payload_hash: h(rng),
                availability_digest: h(rng),
                payload_len: rng.random_range(1..300),
                proposer: 0,
                skipped_leaders: Vec::new(),
                control_witness: Default::default(),
            },
            availability: AvailabilityFrame::from_untrusted(vec![rng.random(); 100]).unwrap(),
        }
    }

    /// A random message across round, sync, manifest, request and row carriers.
    fn message(rng: &mut StdRng) -> WireMessage {
        let instance = h(rng);
        let height = rng.random_range(1..1_000);
        let view = rng.random_range(0..10);
        match rng.random_range(0..11) {
            0 => {
                let manifest = manifest(rng, instance);
                WireMessage::Proposal(Box::new(ProposalMessage {
                    proposal: Proposal {
                        instance,
                        height,
                        view,
                        header: manifest.header,
                        justify: None,
                        parent_qc: rng.random::<bool>().then(|| qc(rng, instance)),
                        sig: sig(rng),
                    },
                    availability: manifest.availability,
                }))
            }
            1 => WireMessage::Vote(Vote {
                kind: VoteKind::Prepare,
                instance,
                epoch: epoch(rng),
                height,
                view,
                block_hash: h(rng),
                result: h(rng),
                signer: rng.random_range(0..10),
                sig: sig(rng),
            }),
            2 => WireMessage::Qc(qc(rng, instance)),
            3 => WireMessage::Timeout(Box::new(TimeoutVote {
                instance,
                epoch: epoch(rng),
                height,
                view,
                high_pqc: None,
                signer: 1,
                sig: sig(rng),
            })),
            4 => WireMessage::Tc(Box::new(TimeoutCert {
                instance,
                epoch: epoch(rng),
                height,
                view,
                entries: vec![TcEntry {
                    signer: 0,
                    hq: None,
                }],
                agg_sig: AggregateSignature([7; SIGNATURE_LEN]),
                high_pqc: None,
            })),
            5 => WireMessage::Status(Box::new(Status {
                instance,
                height,
                view,
                committed_qc: None,
                high_pqc: rng.random::<bool>().then(|| qc(rng, instance)),
                high_tc: None,
                proposal_hash: Some(h(rng)),
                want_proposal: rng.random(),
                probe: None,
                echo: None,
            })),
            6 => WireMessage::SyncRequest(SyncRequest {
                instance,
                from_height: height,
                max_count: 8,
                max_bytes: 1 << 20,
            }),
            7 => WireMessage::SyncResponse(SyncResponse {
                instance,
                blocks: (0..rng.random_range(0..3))
                    .map(|_| SyncEntry {
                        manifest: manifest(rng, instance),
                        commit_qc: qc(rng, instance),
                    })
                    .collect(),
            }),
            8 => WireMessage::PayloadRequest(PayloadRequest {
                instance,
                height,
                block_hash: h(rng),
            }),
            9 => WireMessage::PayloadManifest(manifest(rng, instance)),
            _ => WireMessage::PayloadChunk(PayloadChunk {
                instance,
                height,
                block_hash: h(rng),
                index: rng.random_range(0..10),
                bytes: RowBytes::from_untrusted(vec![rng.random(); 128]).unwrap(),
            }),
        }
    }

    const LAYOUTS: [u8; 2] = [0, ncore::header_flags::COMPACT_LEN];

    /// The raw (pre-decode) topic, admission class and decode limits of a network message
    /// encoded under `layout`, and the message decoded back.
    fn raw_and_decoded(
        message: &NetworkMessage,
        layout: u8,
    ) -> (
        Result<Option<Topic>, ncore::Error>,
        Result<TransportAdmissionClass, ncore::Error>,
        NetworkMessage,
    ) {
        let encoded = {
            let _layout = ncore::DecodeFlagsGuard::enter(layout);
            ncore::to_bytes(message).unwrap()
        };
        let view = ncore::from_bytes_view(&encoded).unwrap();
        let topic = NetworkMessage::inbound_topic(view.as_bytes(), view.flags());
        let class = NetworkMessage::inbound_admission_class(view.as_bytes(), view.flags());
        if topic.is_ok() {
            let limits =
                NetworkMessage::inbound_decode_limits(view.as_bytes(), encoded.len(), view.flags())
                    .unwrap()
                    .expect("a classified Sumeragi frame installs decode limits");
            let bounded = ncore::decode_from_bytes_with_limits::<NetworkMessage>(&encoded, limits)
                .expect("the limits admit the frame");
            assert!(matches!(bounded, NetworkMessage::Sumeragi(_)));
        }
        let decoded = ncore::decode_from_bytes::<NetworkMessage>(&encoded).unwrap();
        (topic, class, decoded)
    }

    /// Property: for random frames of every kind, and for random corruptions of them, the raw
    /// classification agrees with the decoded one under every layout (one shared helper), and a
    /// valid frame's class is the core's `traffic_class` mapped by `topic_of_class`.
    #[test]
    fn raw_and_decoded_classes_agree() {
        let mut rng = StdRng::seed_from_u64(0x5eed_5eed);
        for round in 0..400 {
            let msg = message(&mut rng);
            let mut bytes = msg.encode().unwrap();
            let valid = round % 4 != 3;
            if !valid {
                for _ in 0..rng.random_range(1..4) {
                    let at = rng.random_range(0..bytes.len());
                    bytes[at] = rng.random();
                }
            }
            let frame = SumeragiFrame::new(*msg.instance(), bytes);
            let network = NetworkMessage::Sumeragi(Arc::new(frame.clone()));
            for layout in LAYOUTS {
                let (raw_topic, raw_class, decoded) = raw_and_decoded(&network, layout);
                assert_eq!(decoded.subscriber_route(), SubscriberRoute::Sumeragi);
                match raw_topic {
                    Ok(topic) => {
                        assert_eq!(topic, Some(decoded.topic()), "round {round} {layout:#x}");
                        assert_eq!(raw_class.unwrap(), decoded.admission_class());
                        assert!(decoded.is_outbound_allowed());
                    }
                    Err(_) => {
                        assert!(raw_class.is_err());
                        assert_eq!(decoded.topic(), Topic::Other);
                        assert!(!decoded.is_outbound_allowed(), "never sent");
                    }
                }
                if valid {
                    let expected = topic_of_class(msg.traffic_class());
                    assert_eq!(decoded.topic(), expected);
                    assert_eq!(raw_topic.unwrap(), Some(expected));
                    assert_eq!(
                        decoded.admission_class(),
                        admission_of_class(msg.traffic_class())
                    );
                }
            }
        }
    }

    #[test]
    fn class_table() {
        use TrafficClass as C;
        assert_eq!(topic_of_class(C::Control), Topic::ConsensusSafety);
        assert_eq!(topic_of_class(C::Proposal), Topic::ConsensusPayload);
        assert_eq!(topic_of_class(C::Bulk), Topic::BlockSync);
        assert_eq!(
            admission_of_class(C::Control),
            TransportAdmissionClass::Safety
        );
        assert_eq!(
            admission_of_class(C::Proposal),
            TransportAdmissionClass::Payload
        );
        assert_eq!(
            admission_of_class(C::Bulk),
            TransportAdmissionClass::BlockSync
        );
        assert_eq!(priority_of_class(C::Control), Priority::High);
        assert_eq!(priority_of_class(C::Proposal), Priority::High);
        assert_eq!(priority_of_class(C::Bulk), Priority::Low);
        for (class, filter) in subscription_filters() {
            assert_eq!(
                filter,
                SubscriberFilter::SemanticClass {
                    class: admission_of_class(class),
                    route: SubscriberRoute::Sumeragi,
                }
            );
        }
        let network = NetworkMessage::Sumeragi(Arc::new(SumeragiFrame::new(Hash32::ZERO, vec![])));
        assert_eq!(
            network.progress_reconstruction(),
            iroha_p2p::network::message::ProgressReconstruction::Retransmit
        );
        assert!(
            iroha_p2p::network::reliable_progress_class(
                Topic::ConsensusSafety,
                SubscriberRoute::Sumeragi
            )
            .is_some()
        );
    }

    /// §12.8: payload-availability frames share the envelope and the one classifier: a chunk is
    /// bulk traffic, a chunk request control traffic, on the raw and the decoded paths under
    /// every layout, and a frame of neither schema is unclassifiable.
    #[test]
    fn availability_frames_are_classified_on_both_paths() {
        use iroha_sumeragi::{
            availability::RowBytes,
            message::{PayloadChunk, PayloadRequest},
        };
        let instance = Hash32([4; 32]);
        let chunk = WireMessage::PayloadChunk(PayloadChunk {
            instance,
            height: 3,
            block_hash: Hash32([5; 32]),
            index: 2,
            bytes: RowBytes::from_untrusted(vec![7; 1000]).unwrap(),
        });
        let request = WireMessage::PayloadRequest(PayloadRequest {
            instance,
            height: 3,
            block_hash: Hash32([5; 32]),
        });
        for (msg, topic) in [
            (&chunk, Topic::BlockSync),
            (&request, Topic::ConsensusSafety),
        ] {
            let bytes = msg.encode().unwrap();
            assert_eq!(frame_class(&bytes), Some(msg.traffic_class()));
            let network =
                NetworkMessage::Sumeragi(Arc::new(SumeragiFrame::new(instance, bytes.clone())));
            for layout in LAYOUTS {
                let (raw_topic, raw_class, decoded) = raw_and_decoded(&network, layout);
                assert_eq!(raw_topic.unwrap(), Some(topic));
                assert_eq!(decoded.topic(), topic);
                assert_eq!(raw_class.unwrap(), admission_of_class(msg.traffic_class()));
            }
            // A corrupted schema hash is not a canonical consensus frame.
            let mut corrupted = bytes;
            corrupted[10] ^= 0xff;
            assert_eq!(frame_class(&corrupted), None);
        }
    }

    #[test]
    fn frame_caps() {
        let caps = FrameCaps::for_params(4 << 20, 16 << 20);
        assert_eq!(caps.control, 2 << 20);
        assert_eq!(
            caps.proposal,
            (4 << 20) + usize::try_from(FRAME_OVERHEAD).unwrap()
        );
        assert_eq!(
            caps.bulk,
            (16 << 20) + usize::try_from(FRAME_OVERHEAD).unwrap()
        );
        assert_eq!(caps.of(TrafficClass::Bulk), caps.bulk);
        let huge = FrameCaps::for_params(u32::MAX, u32::MAX);
        assert_eq!(huge.proposal, FrameCaps::TRANSPORT.proposal);
        assert_eq!(huge.bulk, FrameCaps::TRANSPORT.bulk);
        // A frame above its class's transport cap is refused before decode.
        let msg = WireMessage::PayloadRequest(PayloadRequest {
            instance: Hash32::ZERO,
            height: 1,
            block_hash: Hash32::ZERO,
        });
        let network = NetworkMessage::Sumeragi(Arc::new(SumeragiFrame::new(
            Hash32::ZERO,
            msg.encode().unwrap(),
        )));
        let encoded = ncore::to_bytes(&network).unwrap();
        let view = ncore::from_bytes_view(&encoded).unwrap();
        let (_, remaining) = crate::inbound_enum_parts(view.as_bytes()).unwrap();
        let field = crate::inbound_owned_enum_field(remaining, view.flags()).unwrap();
        assert!(
            inbound_decode_limits(field, FrameCaps::TRANSPORT.control + 1, view.flags()).is_err()
        );
        assert!(inbound_decode_limits(field, 100, view.flags()).is_ok());
        assert_eq!(
            inbound_frame_topic(field, view.flags()).unwrap(),
            Topic::ConsensusSafety
        );
        assert!(raw_frame(&field[..field.len() - 1], view.flags()).is_err());
    }

    #[test]
    fn raw_native_envelope_rejects_suffix_and_byte_count_substitution() {
        let network = NetworkMessage::Sumeragi(Arc::new(SumeragiFrame::new(
            Hash32::ZERO,
            WireMessage::PayloadRequest(PayloadRequest {
                instance: Hash32::ZERO,
                height: 1,
                block_hash: Hash32::ZERO,
            })
            .encode()
            .unwrap(),
        )));
        let encoded = ncore::to_bytes(&network).unwrap();
        let view = ncore::from_bytes_view(&encoded).unwrap();
        let (_, remaining) = crate::inbound_enum_parts(view.as_bytes()).unwrap();
        let field = crate::inbound_owned_enum_field(remaining, view.flags()).unwrap();
        let mut suffixed = field.to_vec();
        suffixed.push(0);
        assert!(raw_frame(&suffixed, view.flags()).is_err());
        let (instance_len, prefix_len) =
            ncore::read_len_from_slice_with_flags(field, view.flags()).unwrap();
        let frame_field_offset = prefix_len + instance_len;
        let (_, frame_prefix_len) =
            ncore::read_len_from_slice_with_flags(&field[frame_field_offset..], view.flags())
                .unwrap();
        let count_offset = frame_field_offset + frame_prefix_len;
        for count in [0_u64, u64::MAX] {
            let mut changed = field.to_vec();
            changed[count_offset..count_offset + 8].copy_from_slice(&count.to_le_bytes());
            assert!(raw_frame(&changed, view.flags()).is_err());
        }
        for end in 0..field.len() {
            assert!(raw_frame(&field[..end], view.flags()).is_err());
        }
    }

    #[test]
    fn frame_accessors() {
        let msg = WireMessage::SyncRequest(SyncRequest {
            instance: Hash32([3; 32]),
            from_height: 1,
            max_count: 1,
            max_bytes: 1,
        });
        let bytes: Arc<[u8]> = msg.encode().unwrap().into();
        let frame = Frame {
            instance: Hash32([3; 32]),
            class: msg.traffic_class(),
            bytes: Arc::clone(&bytes),
        };
        let envelope = SumeragiFrame::from_frame(&frame);
        assert_eq!(envelope.instance(), Hash32([3; 32]));
        assert_eq!(envelope.bytes(), &bytes[..]);
        assert_eq!(envelope.class(), Some(TrafficClass::Control));
        assert_eq!(envelope.topic(), Topic::ConsensusSafety);
        assert!(format!("{envelope:?}").contains("SumeragiFrame"));
        assert_eq!(
            SumeragiFrame::new(Hash32::ZERO, vec![1, 2]).topic(),
            Topic::Other
        );
        assert_eq!(frame_class(&bytes), Some(TrafficClass::Control));
    }

    #[derive(Clone, Copy)]
    enum FakeOutcome {
        Admitted,
        Backpressured,
        Closed,
        Rejected,
    }

    /// Records exact occurrences while returning the scripted transport result.
    #[derive(Default)]
    struct FakeTransport {
        posts: Mutex<Vec<(PeerId, NetworkMessage, Priority)>>,
        outcome: Mutex<Option<FakeOutcome>>,
    }

    impl SumeragiTransport for FakeTransport {
        fn post_frame(
            &self,
            post: Post<NetworkMessage>,
            ticket: Option<NetworkActorAdmissionTicket>,
        ) -> Result<(), NetworkActorAdmissionError<Post<NetworkMessage>>> {
            self.posts
                .lock()
                .push((post.peer_id.clone(), post.data.clone(), post.priority));
            match self.outcome.lock().unwrap_or(FakeOutcome::Admitted) {
                FakeOutcome::Admitted => Ok(()),
                FakeOutcome::Backpressured => Err(NetworkActorAdmissionError::Backpressured {
                    message: post,
                    ticket,
                    rank: 1,
                }),
                FakeOutcome::Closed => Err(NetworkActorAdmissionError::Closed { message: post }),
                FakeOutcome::Rejected => Err(NetworkActorAdmissionError::Rejected {
                    message: post,
                    reason: iroha_p2p::network::NetworkActorAdmissionRejection::OutboundDisallowed,
                }),
            }
        }
    }

    fn bls(seed: u8) -> KeyPair {
        KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal)
    }

    fn frame_of(msg: &WireMessage) -> Frame {
        Frame {
            instance: *msg.instance(),
            class: msg.traffic_class(),
            bytes: msg.encode().unwrap().into(),
        }
    }

    fn pending(outcome: SendOutcome) -> Box<dyn PendingSend> {
        match outcome {
            SendOutcome::Backpressured(owner) => owner,
            _ => panic!("expected caller-owned backpressure"),
        }
    }

    fn row_frame(index: u32) -> Frame {
        frame_of(&WireMessage::PayloadChunk(
            iroha_sumeragi::message::PayloadChunk {
                instance: Hash32([9; 32]),
                height: 3,
                block_hash: Hash32([8; 32]),
                index,
                bytes: iroha_sumeragi::availability::RowBytes::from_untrusted(vec![7; 2]).unwrap(),
            },
        ))
    }

    /// Every retry keeps the original encoded envelope and target; admitted posts need no owner.
    #[test]
    fn egress_retains_original_frame_on_backpressure_and_counts_retries() {
        let net = P2pNet::new(FakeTransport::default());
        let (a, b) = (bls(1), bls(2));
        let (ka, kb) = (
            core_key(a.public_key()).unwrap(),
            core_key(b.public_key()).unwrap(),
        );
        let frame = row_frame(2);
        assert!(matches!(net.send(&ka, &frame), SendOutcome::Admitted));
        assert!(matches!(net.send(&kb, &frame), SendOutcome::Admitted));
        *net.transport.outcome.lock() = Some(FakeOutcome::Backpressured);
        let owner = pending(net.send(&ka, &frame));
        let original = net.envelope(&frame);
        let replacement = net.envelope(&row_frame(99));
        assert!(!Arc::ptr_eq(&original, &replacement));
        let owner_ptr = std::ptr::from_ref::<dyn PendingSend>(&*owner) as *const ();
        let owner = pending(owner.retry());
        assert_eq!(
            std::ptr::from_ref::<dyn PendingSend>(&*owner) as *const (),
            owner_ptr,
            "retry must return the same owner"
        );
        *net.transport.outcome.lock() = Some(FakeOutcome::Admitted);
        assert!(matches!(owner.retry(), SendOutcome::Admitted));
        assert_eq!(net.stats().sent, 3);
        assert_eq!(net.stats().backpressured, 2);
        let posts = net.transport.posts.lock();
        assert_eq!(posts.len(), 5);
        let NetworkMessage::Sumeragi(original) = &posts[0].1 else {
            panic!("not a frame")
        };
        for (index, (to, message, priority)) in posts.iter().enumerate() {
            assert_eq!(
                *to,
                PeerId::new(
                    if index == 1 {
                        b.public_key()
                    } else {
                        a.public_key()
                    }
                    .clone()
                )
            );
            assert_eq!(*priority, Priority::Low);
            let NetworkMessage::Sumeragi(envelope) = message else {
                panic!("not a frame")
            };
            assert!(Arc::ptr_eq(original, envelope));
            assert_eq!(envelope.bytes(), &*frame.bytes);
        }
    }

    /// Closure/rejection are terminal even after a refusal; malformed recipients never post.
    #[test]
    fn egress_terminal_outcomes_release_the_owned_attempt() {
        for terminal in [FakeOutcome::Closed, FakeOutcome::Rejected] {
            let net = P2pNet::new(FakeTransport::default());
            let to = core_key(bls(2).public_key()).unwrap();
            *net.transport.outcome.lock() = Some(FakeOutcome::Backpressured);
            let owner = pending(net.send(&to, &row_frame(0)));
            *net.transport.outcome.lock() = Some(terminal);
            let result = owner.retry();
            match terminal {
                FakeOutcome::Closed => assert!(matches!(result, SendOutcome::Closed)),
                FakeOutcome::Rejected => assert!(matches!(result, SendOutcome::Rejected)),
                _ => unreachable!(),
            }
            assert_eq!(net.stats().sent, 0);
            assert_eq!(net.stats().backpressured, 1);
            assert_eq!(net.stats().closed + net.stats().rejected, 1);
            assert!(matches!(
                net.send(&PublicKey::new(vec![1; 48]).unwrap(), &row_frame(1)),
                SendOutcome::Rejected
            ));
            assert_eq!(net.stats().bad_recipient, 1);
            assert_eq!(net.transport.posts.lock().len(), 2);
        }
    }

    /// Real P2P admission permits only one retained frame per target/class. A later caller
    /// cannot overtake the original refused row after capacity becomes available.
    #[test]
    fn egress_real_actor_retains_row_ticket_and_fifo_until_admitted() {
        let target = bls(4);
        let target_peer = PeerId::new(target.public_key().clone());
        let (network, mut actor) = IrohaNetwork::actor_admission_for_tests(
            PeerId::new(bls(3).public_key().clone()),
            std::collections::HashSet::from([target_peer.clone()]),
            std::num::NonZeroUsize::new(4).unwrap(),
        );
        let net = P2pNet::new(network);
        let to = core_key(target.public_key()).unwrap();
        let frames = [row_frame(0), row_frame(1), row_frame(2)];
        assert!(matches!(net.send(&to, &frames[0]), SendOutcome::Admitted));
        let original = net.envelope(&frames[1]);
        let first = pending(net.send(&to, &frames[1]));
        let second = pending(net.send(&to, &frames[2]));
        let mut delivered = Vec::new();
        let mut capture = |post: &Post<NetworkMessage>| {
            assert_eq!(post.peer_id, target_peer);
            let NetworkMessage::Sumeragi(frame) = &post.data else {
                panic!("not a frame")
            };
            // Reliable BlockSync posts are promoted by the actual P2P actor boundary.
            assert_eq!(post.priority, Priority::High);
            if frame.bytes() == &*frames[1].bytes {
                assert!(
                    Arc::ptr_eq(&original, frame),
                    "retry recreated its encoded envelope"
                );
            }
            delivered.push(frame.bytes().to_vec());
        };
        assert_eq!(actor.drain_posts(&mut capture), 1);
        // Retrying the later ticket first must not silently acquire a fresh queue position.
        let second = pending(second.retry());
        assert!(matches!(first.retry(), SendOutcome::Admitted));
        assert_eq!(actor.drain_posts(&mut capture), 1);
        // The pending attempt owns its transport lifetime, not a borrow of the adapter.
        drop(net);
        assert!(matches!(second.retry(), SendOutcome::Admitted));
        assert_eq!(actor.drain_posts(&mut capture), 1);
        assert_eq!(
            delivered,
            frames
                .iter()
                .map(|frame| frame.bytes.to_vec())
                .collect::<Vec<_>>()
        );
    }

    /// An occupied stream cannot block another target, and explicit cancellation releases
    /// the original rank so the next retained attempt can progress.
    #[test]
    fn egress_real_actor_isolates_recipients_and_cancels_only_dropped_owner() {
        let (a, b) = (bls(4), bls(5));
        let targets = [
            PeerId::new(a.public_key().clone()),
            PeerId::new(b.public_key().clone()),
        ];
        let (network, mut actor) = IrohaNetwork::actor_admission_for_tests(
            PeerId::new(bls(3).public_key().clone()),
            targets.iter().cloned().collect(),
            std::num::NonZeroUsize::new(4).unwrap(),
        );
        let net = P2pNet::new(network);
        let (ka, kb) = (
            core_key(a.public_key()).unwrap(),
            core_key(b.public_key()).unwrap(),
        );
        assert!(matches!(
            net.send(&ka, &row_frame(0)),
            SendOutcome::Admitted
        ));
        let cancelled = pending(net.send(&ka, &row_frame(1)));
        let next = pending(net.send(&ka, &row_frame(2)));
        assert!(matches!(
            net.send(&kb, &row_frame(0)),
            SendOutcome::Admitted
        ));
        assert_eq!(actor.drain_posts(|_| {}), 2);
        drop(cancelled);
        assert!(matches!(next.retry(), SendOutcome::Admitted));
        assert_eq!(
            actor.drain_posts(|post| assert_eq!(post.peer_id, targets[0])),
            1
        );
    }

    /// The actual actor must see a live FIFO owner for the row refused by Net::send.
    /// This same test fails against the old void/dropping adapter and passes when the
    /// returned outcome owns the original post and rank until explicitly cancelled.
    #[test]
    fn actor_rank_one_refusal_preserves_the_returned_row_owner() {
        let target = bls(4);
        let target_peer = PeerId::new(target.public_key().clone());
        let (network, mut actor) = IrohaNetwork::actor_admission_for_tests(
            PeerId::new(bls(3).public_key().clone()),
            std::collections::HashSet::from([target_peer.clone()]),
            std::num::NonZeroUsize::new(4).unwrap(),
        );
        let net = P2pNet::new(network);
        let to = core_key(target.public_key()).unwrap();
        let row = |index| {
            frame_of(&WireMessage::PayloadChunk(
                iroha_sumeragi::message::PayloadChunk {
                    instance: Hash32([9; 32]),
                    height: 3,
                    block_hash: Hash32([8; 32]),
                    index,
                    bytes: iroha_sumeragi::availability::RowBytes::from_untrusted(vec![7; 2])
                        .unwrap(),
                },
            ))
        };
        let _initial = net.send(&to, &row(0));
        let retained = net.send(&to, &row(1));
        let later = Post {
            data: NetworkMessage::Sumeragi(net.envelope(&row(2))),
            peer_id: target_peer,
            priority: Priority::Low,
        };
        let (later, ticket) = match net.transport.post_recoverable(later, None) {
            Err(NetworkActorAdmissionError::Backpressured {
                message,
                ticket: Some(ticket),
                rank,
            }) => {
                assert_eq!(
                    rank, 2,
                    "the refused row lost its original per-recipient queue rank"
                );
                (message, ticket)
            }
            _ => panic!("later row must retain the second admission rank"),
        };
        assert_eq!(ticket.rank(), Some(2));
        drop(retained);
        assert_eq!(
            ticket.rank(),
            Some(1),
            "only explicit cancellation releases the older owner"
        );
        assert_eq!(actor.drain_posts(|_| {}), 1);
        assert!(net.transport.post_recoverable(later, Some(ticket)).is_ok());
        assert_eq!(actor.drain_posts(|_| {}), 1);
    }

    #[test]
    fn egress_real_actor_closure_is_terminal_for_a_retained_row() {
        let target = bls(4);
        let (network, actor) = IrohaNetwork::actor_admission_for_tests(
            PeerId::new(bls(3).public_key().clone()),
            std::collections::HashSet::from([PeerId::new(target.public_key().clone())]),
            std::num::NonZeroUsize::new(4).unwrap(),
        );
        let net = P2pNet::new(network);
        let to = core_key(target.public_key()).unwrap();
        assert!(matches!(
            net.send(&to, &row_frame(0)),
            SendOutcome::Admitted
        ));
        let owner = pending(net.send(&to, &row_frame(1)));
        drop(actor);
        assert!(matches!(owner.retry(), SendOutcome::Closed));
        assert_eq!(net.stats().closed, 1);
        assert_eq!(net.stats().backpressured, 1);
    }

    #[test]
    fn egress_missing_membership_returns_ownership_without_actor_admission() {
        let target = bls(4);
        let (network, mut actor) = IrohaNetwork::actor_admission_for_tests(
            PeerId::new(bls(3).public_key().clone()),
            std::collections::HashSet::new(),
            std::num::NonZeroUsize::new(1).unwrap(),
        );
        let net = P2pNet::new(network);
        let to = core_key(target.public_key()).unwrap();
        let owner = pending(net.send(&to, &row_frame(0)));
        let owner = pending(owner.retry());
        assert_eq!(actor.drain_posts(|_| {}), 0);
        assert_eq!(net.stats().sent, 0);
        assert_eq!(net.stats().backpressured, 2);
        drop(owner);
    }

    /// A sink that records deliveries.
    #[derive(Default)]
    struct Sink {
        frames: Mutex<Vec<(PublicKey, Vec<u8>)>>,
        refuse: bool,
    }

    impl FrameSink for Sink {
        fn deliver(&self, from: &PublicKey, frame: &[u8]) -> bool {
            self.frames.lock().push((from.clone(), frame.to_vec()));
            !self.refuse
        }
    }

    fn peer_message(kp: &KeyPair, payload: NetworkMessage) -> PeerMessage<NetworkMessage> {
        let peer = Peer::new("127.0.0.1:1337".parse().unwrap(), kp.public_key().clone());
        PeerMessage::new(peer, payload, 0)
    }

    /// Ingress routing: frames go to their instance's driver as `(from, exact bytes)`; other
    /// instances, other messages, non-BLS senders, relayed and oversize frames are dropped.
    #[test]
    fn ingress_routes_by_instance() {
        // Exercise a local refusal below the protocol's maximum row size. The
        // default bulk cap also accommodates manifests and is larger than a row.
        let caps = FrameCaps {
            bulk: 1024,
            ..FrameCaps::for_params(1024, 1024)
        };
        let ingress = SumeragiIngress::new(caps);
        let (i, j) = (Hash32([1; 32]), Hash32([2; 32]));
        let sink = Arc::new(Sink::default());
        ingress.register(i, sink.clone());
        let sender = bls(5);
        let msg = WireMessage::PayloadRequest(PayloadRequest {
            instance: i,
            height: 3,
            block_hash: Hash32::ZERO,
        });
        let bytes = msg.encode().unwrap();
        let frame = |instance| {
            NetworkMessage::Sumeragi(Arc::new(SumeragiFrame::new(instance, bytes.clone())))
        };
        assert_eq!(
            ingress.route(peer_message(&sender, frame(i))),
            Routed::Delivered
        );
        {
            let frames = sink.frames.lock();
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0].0, core_key(sender.public_key()).unwrap());
            assert_eq!(frames[0].1, bytes);
        }
        assert_eq!(
            ingress.route(peer_message(&sender, frame(j))),
            Routed::UnknownInstance
        );
        assert_eq!(
            ingress.route(peer_message(&sender, NetworkMessage::Health)),
            Routed::NotSumeragi
        );
        let ed = KeyPair::from_seed(vec![1; 32], Algorithm::Ed25519);
        assert_eq!(
            ingress.route(peer_message(&ed, frame(i))),
            Routed::BadSender
        );
        let big = WireMessage::PayloadChunk(PayloadChunk {
            instance: i,
            height: 1,
            block_hash: Hash32::ZERO,
            index: 0,
            // A bounded valid row frame can exceed this instance's smaller bulk cap.
            bytes: RowBytes::from_untrusted(vec![0; caps.bulk]).unwrap(),
        });
        let oversize =
            NetworkMessage::Sumeragi(Arc::new(SumeragiFrame::new(i, big.encode().unwrap())));
        assert_eq!(
            ingress.route(peer_message(&sender, oversize)),
            Routed::Oversize
        );
        let junk = NetworkMessage::Sumeragi(Arc::new(SumeragiFrame::new(i, vec![1, 2, 3])));
        assert_eq!(ingress.route(peer_message(&sender, junk)), Routed::Oversize);
        let other = PeerId::new(bls(6).public_key().clone());
        let via = PeerId::new(sender.public_key().clone());
        assert_eq!(
            ingress.route_parts(&other, &via, &frame(i)),
            Routed::Relayed
        );
        assert_eq!(
            ingress.stats(),
            IngressStats {
                delivered: 1,
                dropped: 5
            }
        );
        let refusing = Arc::new(Sink {
            refuse: true,
            ..Sink::default()
        });
        ingress.register(i, refusing);
        assert_eq!(
            ingress.route(peer_message(&sender, frame(i))),
            Routed::Refused
        );
        assert!(ingress.unregister(&i));
        assert!(!ingress.unregister(&i));
        assert!(format!("{ingress:?}").contains("SumeragiIngress"));
    }

    /// The ingress thread drains the three FIFOs into the router and ends when they close.
    #[test]
    fn ingress_thread_drains_fifos() {
        let ingress = Arc::new(SumeragiIngress::new(FrameCaps::TRANSPORT));
        let i = Hash32([1; 32]);
        let sink = Arc::new(Sink::default());
        ingress.register(i, sink.clone());
        let (ctx, crx) = mpsc::channel(4);
        let (ptx, prx) = mpsc::channel(4);
        let (btx, brx) = mpsc::channel(4);
        let thread = spawn_ingress(
            SumeragiSubscription {
                control: crx,
                proposal: prx,
                bulk: brx,
            },
            Arc::clone(&ingress),
        )
        .unwrap();
        let sender = bls(7);
        let msg = WireMessage::PayloadRequest(PayloadRequest {
            instance: i,
            height: 3,
            block_hash: Hash32::ZERO,
        });
        let frame =
            || NetworkMessage::Sumeragi(Arc::new(SumeragiFrame::new(i, msg.encode().unwrap())));
        for tx in [&ctx, &ptx, &btx] {
            tx.blocking_send(peer_message(&sender, frame())).unwrap();
        }
        drop((ctx, ptx, btx));
        thread.join().unwrap();
        assert_eq!(sink.frames.lock().len(), 3);
        assert_eq!(ingress.stats().delivered, 3);
    }
}

#[cfg(test)]
#[test]
fn retired_beacon_sideframes_have_no_transport_classifier() {
    let mut retired = b"IROHA-BEACON\x01".to_vec();
    retired.extend_from_slice(&[0; 256]);
    assert_eq!(frame_class(&retired), None);
    assert_eq!(SumeragiFrame::new(Hash32([1; 32]), retired).class(), None);
}
