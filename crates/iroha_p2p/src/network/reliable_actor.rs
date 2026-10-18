//! Process-local ownership for bounded reliable network-actor retries.
//!
//! Encoded relay targets and envelopes deliberately remain in the parent
//! module so this source split cannot alter their wire identity or layout.

use super::*;

pub(super) enum NetworkActorLease {
    Ordinary(NetworkActorByteLease),
    Progress(NetworkActorProgressLease),
}
impl NetworkActorLease {
    pub(super) fn bytes(&self) -> usize {
        match self {
            Self::Ordinary(lease) => lease.bytes,
            Self::Progress(lease) => lease.bytes,
        }
    }
    pub(super) fn progress_source(&self) -> Option<&ActorProgressSource> {
        match self {
            Self::Ordinary(_) => None,
            Self::Progress(lease) => Some(&lease.source),
        }
    }
}
impl From<NetworkActorByteLease> for NetworkActorLease {
    fn from(lease: NetworkActorByteLease) -> Self {
        Self::Ordinary(lease)
    }
}
impl From<NetworkActorProgressLease> for NetworkActorLease {
    fn from(lease: NetworkActorProgressLease) -> Self {
        Self::Progress(lease)
    }
}
/// One peer-writer occurrence retained by the network actor until flush.
pub(super) struct PendingWriterFlush {
    pub(super) receiver: tokio::sync::oneshot::Receiver<()>,
}
/// Linearize an exact reply's pending writer flush before a destructive exit.
///
/// Closing the receiver and polling it immediately gives the peer writer and
/// network actor one deterministic boundary: a flush published before the
/// close remains observable, while a writer which loses the close race cannot
/// publish success afterwards. Topology traffic has no exact target and never
/// enters this fence.
pub(super) fn exact_reply_flush_wins_terminal_fence(
    pending_flush_acks: &mut HashMap<PeerId, PendingWriterFlush>,
    exact_target: Option<&PeerId>,
) -> bool {
    let Some(exact_target) = exact_target else {
        return false;
    };
    let Some(mut pending) = pending_flush_acks.remove(exact_target) else {
        return false;
    };
    pending.receiver.close();
    matches!(pending.receiver.try_recv(), Ok(()))
}
/// Immutable lifetime of one exact actor-owned reply occurrence.
#[derive(Clone, Copy, Debug)]
pub(super) struct ExactReplyWriterDeadline {
    pub(super) admitted_at: tokio::time::Instant,
    pub(super) timeout: Duration,
}
impl ExactReplyWriterDeadline {
    pub(super) fn expired_at(self, now: tokio::time::Instant) -> bool {
        now.checked_duration_since(self.admitted_at)
            .is_some_and(|elapsed| elapsed >= self.timeout)
    }
}
pub(super) fn scaled_reply_writer_flush_timeout(base: Duration, attempt: u8) -> Duration {
    let mut timeout = base;
    for _ in 0..attempt {
        let Some(doubled) = timeout.checked_mul(2) else {
            return Duration::MAX;
        };
        timeout = doubled;
    }
    timeout
}
pub(super) enum AdmittedNetworkPayload<T> {
    Unsigned(NetworkMessage<T>),
    Signed(Arc<RelayMessage<T>>),
}
impl<T> AdmittedNetworkPayload<T> {
    pub(super) fn from_network(message: NetworkMessage<T>) -> Self {
        Self::Unsigned(message)
    }

    pub(super) fn into_network(self) -> NetworkMessage<T> {
        let Self::Unsigned(message) = self else {
            unreachable!("a signed reliable envelope cannot return to best-effort admission")
        };
        message
    }

    pub(super) fn signed_frame(&self) -> &Arc<RelayMessage<T>> {
        let Self::Signed(frame) = self else {
            unreachable!("reliable dispatch must materialize its relay envelope once")
        };
        frame
    }
}
impl<T: Encode> AdmittedNetworkPayload<T> {
    pub(super) fn materialize(self, key_pair: &KeyPair, relay_ttl: u8) -> Self {
        match self {
            Self::Signed(frame) => Self::Signed(frame),
            Self::Unsigned(NetworkMessage::Post(post)) => {
                Self::Signed(Arc::new(RelayMessage::new_signed(
                    key_pair,
                    RelayTarget::Direct(post.peer_id),
                    relay_ttl,
                    post.data,
                )))
            }
            Self::Unsigned(NetworkMessage::Broadcast(broadcast)) => {
                Self::Signed(Arc::new(RelayMessage::new_signed(
                    key_pair,
                    RelayTarget::Broadcast,
                    relay_ttl,
                    broadcast.data,
                )))
            }
        }
    }
}
/// The original dispatch owner temporarily unpacked by one actor attempt.
///
/// The payload and its byte lease precede retained routing and flush state.
/// This moves an admitted item without allocation or new authority.
pub(super) struct NetworkDispatchParts<T> {
    pub(super) message: AdmittedNetworkPayload<T>,
    pub(super) byte_lease: NetworkActorLease,
    pub(super) remaining_broadcast_targets: Option<VecDeque<PeerId>>,
    pub(super) pending_flush_acks: HashMap<PeerId, PendingWriterFlush>,
    pub(super) progress_authority: Option<ProgressDeliveryAuthority>,
    pub(super) reply_writer_timeout_attempt: Option<u8>,
    pub(super) reply_writer_deadline: Option<ExactReplyWriterDeadline>,
    pub(super) reply_flush_ack: Option<tokio::sync::oneshot::Sender<NetworkReplyFlushCompletion>>,
}

pub(super) struct AdmittedNetworkMessage<T> {
    /// One signed relay envelope retained across every actor retry.
    ///
    /// Actor turns reuse this `Arc` and its signature allocation without
    /// repeating BLS signing. A live peer writer still receives its bounded
    /// owned frame clone after all connection preflights pass.
    pub(super) message: Option<AdmittedNetworkPayload<T>>,
    /// Exact actor queue ownership for this one retained payload.
    pub(super) byte_lease: NetworkActorLease,
    /// Exact actor-published topology tenure for a reliable target delivery.
    /// Best-effort traffic and budget-only test fixtures carry no membership.
    pub(super) progress_authority: Option<ProgressDeliveryAuthority>,
    /// Snapshot of broadcast targets that have not yet acquired downstream
    /// ownership. `None` means the first dispatch has not observed topology;
    /// `Some(empty)` is a completed fanout.
    pub(super) remaining_broadcast_targets: Option<VecDeque<PeerId>>,
    /// Per-target peer-writer completions that have not yet observed a
    /// successful full write and flush.
    ///
    /// Receivers stay inside the same opaque actor item as the original
    /// message and actor lease.  A closed receiver moves its target back to
    /// the retry cursor; a pending receiver cannot be mistaken for delivery.
    /// An exact reply also retains its immutable writer deadline and
    /// connection so timeout retirement cannot affect a replacement.
    pub(super) pending_flush_acks: HashMap<PeerId, PendingWriterFlush>,
    /// Adaptive timeout generation for an exact reply; topology traffic has none.
    pub(super) reply_writer_timeout_attempt: Option<u8>,
    /// Fixed on first actor dispatch, before any peer-writer admission attempt.
    pub(super) reply_writer_deadline: Option<ExactReplyWriterDeadline>,
    /// Process-local completion owned by the caller which admitted this exact
    /// reply occurrence. Only a fully observed peer-writer flush consumes it
    /// successfully. A ready writer flush wins each terminal close-and-poll
    /// fence; cancellation or drop otherwise closes the caller's receiver.
    pub(super) reply_flush_ack: Option<tokio::sync::oneshot::Sender<NetworkReplyFlushCompletion>>,
}
impl<T> AdmittedNetworkMessage<T> {
    pub(super) fn new(
        message: NetworkMessage<T>,
        byte_lease: impl Into<NetworkActorLease>,
    ) -> Self {
        let byte_lease = byte_lease.into();
        let _ = byte_lease.bytes();
        Self {
            message: Some(AdmittedNetworkPayload::from_network(message)),
            byte_lease,
            progress_authority: None,
            remaining_broadcast_targets: None,
            pending_flush_acks: HashMap::new(),
            reply_writer_timeout_attempt: None,
            reply_writer_deadline: None,
            reply_flush_ack: None,
        }
    }
    pub(super) fn new_targeted_broadcast(
        message: NetworkMessage<T>,
        byte_lease: NetworkActorProgressLease,
        authority: ProgressDeliveryAuthority,
    ) -> Self {
        debug_assert!(matches!(message, NetworkMessage::Broadcast(_)));
        let ProgressDeliveryAuthority::Topology(membership) = &authority else {
            unreachable!("reliable broadcasts require topology authority")
        };
        debug_assert_eq!(byte_lease.source.target.as_ref(), Some(&membership.peer_id));
        Self {
            message: Some(AdmittedNetworkPayload::from_network(message)),
            byte_lease: byte_lease.into(),
            remaining_broadcast_targets: Some(VecDeque::from([membership.peer_id.clone()])),
            progress_authority: Some(authority),
            pending_flush_acks: HashMap::new(),
            reply_writer_timeout_attempt: None,
            reply_writer_deadline: None,
            reply_flush_ack: None,
        }
    }
    pub(super) fn new_targeted_post(
        message: NetworkMessage<T>,
        byte_lease: NetworkActorProgressLease,
        authority: ProgressDeliveryAuthority,
        reply_writer_timeout_attempt: Option<u8>,
        reply_flush_ack: Option<tokio::sync::oneshot::Sender<NetworkReplyFlushCompletion>>,
    ) -> Self {
        debug_assert!(matches!(message, NetworkMessage::Post(_)));
        debug_assert_eq!(
            byte_lease.source.target.as_ref(),
            Some(authority.source_target())
        );
        debug_assert_eq!(
            reply_writer_timeout_attempt.is_some(),
            matches!(&authority, ProgressDeliveryAuthority::Reply(_))
        );
        Self {
            message: Some(AdmittedNetworkPayload::from_network(message)),
            byte_lease: byte_lease.into(),
            progress_authority: Some(authority),
            remaining_broadcast_targets: None,
            pending_flush_acks: HashMap::new(),
            reply_writer_timeout_attempt,
            reply_writer_deadline: None,
            reply_flush_ack,
        }
    }
    pub(super) fn cancelled_progress_authority(&self) -> bool {
        self.progress_authority
            .as_ref()
            .is_some_and(|authority| !authority.is_active())
    }
    /// Publish a ready exact-reply flush before this actor item is dropped.
    ///
    /// This is the terminal-drop counterpart of dispatch's destructive-exit
    /// fence. It is intentionally a no-op for topology-authorized traffic.
    pub(super) fn publish_ready_exact_reply_before_terminal_drop(&mut self) -> bool {
        let Self {
            progress_authority,
            pending_flush_acks,
            reply_flush_ack,
            ..
        } = self;
        let exact_target = progress_authority.as_ref().and_then(|authority| {
            let ProgressDeliveryAuthority::Reply(route) = authority else {
                return None;
            };
            Some(route.semantic_target())
        });
        if !exact_reply_flush_wins_terminal_fence(pending_flush_acks, exact_target) {
            return false;
        }
        if let Some(reply_flush_ack) = reply_flush_ack.take() {
            let _ = reply_flush_ack.send(NetworkReplyFlushCompletion::Flushed);
        }
        true
    }
    pub(super) fn progress_source(&self) -> Option<&ActorProgressSource> {
        self.byte_lease.progress_source()
    }
    pub(super) fn into_parts(self) -> (NetworkMessage<T>, NetworkActorLease) {
        let Self {
            mut message,
            byte_lease,
            ..
        } = self;
        (
            message
                .take()
                .expect("admitted network message must be consumed exactly once")
                .into_network(),
            byte_lease,
        )
    }
    pub(super) fn into_dispatch_parts(self) -> NetworkDispatchParts<T> {
        let Self {
            mut message,
            byte_lease,
            remaining_broadcast_targets,
            pending_flush_acks,
            progress_authority,
            reply_writer_timeout_attempt,
            reply_writer_deadline,
            reply_flush_ack,
        } = self;
        NetworkDispatchParts {
            message: message
                .take()
                .expect("admitted network message must be consumed exactly once"),
            byte_lease,
            remaining_broadcast_targets,
            pending_flush_acks,
            progress_authority,
            reply_writer_timeout_attempt,
            reply_writer_deadline,
            reply_flush_ack,
        }
    }
    /// Retain the same admitted owner after an incomplete writer-dispatch attempt.
    ///
    /// This is not a capability reconstruction boundary: every tenure-bound
    /// authority and reply completion sender is moved out by
    /// [`Self::into_dispatch_parts`] and returned here unchanged.
    pub(super) fn retain_after_dispatch_attempt(parts: NetworkDispatchParts<T>) -> Self {
        let NetworkDispatchParts {
            message,
            byte_lease,
            remaining_broadcast_targets,
            pending_flush_acks,
            progress_authority,
            reply_writer_timeout_attempt,
            reply_writer_deadline,
            reply_flush_ack,
        } = parts;
        Self {
            message: Some(message),
            byte_lease,
            progress_authority,
            remaining_broadcast_targets,
            pending_flush_acks,
            reply_writer_timeout_attempt,
            reply_writer_deadline,
            reply_flush_ack,
        }
    }
    #[cfg(test)]
    pub(super) fn into_inner(self) -> NetworkMessage<T> {
        self.into_parts().0
    }
}
/// Source-isolated reliable actor backlog.
///
/// The scheduler deliberately stores the admitted owner as one opaque item.
/// Target cursors (and, once the peer writer exposes them, flush
/// acknowledgements) therefore remain part of the same retryable ownership
/// record rather than being duplicated into another queue.
pub(super) struct ReliableActorPending<T> {
    by_source: HashMap<ActorProgressSource, VecDeque<AdmittedNetworkMessage<T>>>,
    ready_sources: VecDeque<ActorProgressSource>,
    ready_members: HashSet<ActorProgressSource>,
    len: usize,
    max_items: usize,
}
impl<T> ReliableActorPending<T> {
    /// Release every retained item through the exact-reply terminal fence.
    pub(super) fn release_all_with_terminal_fence(&mut self) -> usize {
        let released = self.len;
        for entries in self.by_source.values_mut() {
            for entry in entries {
                entry.publish_ready_exact_reply_before_terminal_drop();
            }
        }
        self.by_source.clear();
        self.ready_sources.clear();
        self.ready_members.clear();
        self.len = 0;
        released
    }
}
impl<T> Drop for ReliableActorPending<T> {
    fn drop(&mut self) {
        let _ = self.release_all_with_terminal_fence();
    }
}
impl<T: message::ClassifyTopic> ReliableActorPending<T> {
    pub(super) fn new(max_items: usize) -> Self {
        Self {
            by_source: HashMap::new(),
            ready_sources: VecDeque::new(),
            ready_members: HashSet::new(),
            len: 0,
            max_items,
        }
    }
    pub(super) fn source(message: &AdmittedNetworkMessage<T>) -> ActorProgressSource {
        message
            .progress_source()
            .cloned()
            .or_else(|| {
                message
                    .message
                    .as_ref()
                    .and_then(ActorProgressSource::for_admitted_payload)
            })
            .expect("reliable actor backlog accepts only semantic-progress messages")
    }
    pub(super) fn push_back(&mut self, message: AdmittedNetworkMessage<T>) {
        assert!(
            self.len < self.max_items,
            "reliable actor backlog exceeded its checked admission geometry"
        );
        let source = Self::source(&message);
        let entries = self.by_source.entry(source.clone()).or_default();
        entries.push_back(message);
        self.len = self
            .len
            .checked_add(1)
            .expect("bounded reliable actor item count cannot overflow");
        if self.ready_members.insert(source.clone()) {
            self.ready_sources.push_back(source);
        }
    }
    pub(super) fn pop_front(&mut self) -> Option<(ActorProgressSource, AdmittedNetworkMessage<T>)> {
        while let Some(source) = self.ready_sources.pop_front() {
            self.ready_members.remove(&source);
            let Some(mut entries) = self.by_source.remove(&source) else {
                continue;
            };
            let Some(message) = entries.pop_front() else {
                continue;
            };
            self.len = self
                .len
                .checked_sub(1)
                .expect("reliable actor backlog count must match its queues");
            if !entries.is_empty() {
                self.by_source.insert(source.clone(), entries);
                self.ready_members.insert(source.clone());
                self.ready_sources.push_back(source.clone());
            }
            return Some((source, message));
        }
        None
    }
    pub(super) fn retry_back(
        &mut self,
        source: ActorProgressSource,
        message: AdmittedNetworkMessage<T>,
    ) {
        assert_eq!(
            source,
            Self::source(&message),
            "reliable actor retry must preserve its admission source"
        );
        self.push_back(message);
    }
    pub(super) fn len(&self) -> usize {
        self.len
    }
    /// Release reliable target deliveries whose exact topology tenure was cancelled.
    pub(super) fn release_cancelled_targets(&mut self) -> usize {
        let mut released = 0usize;
        self.by_source.retain(|_source, entries| {
            entries.retain_mut(|entry| {
                if !entry.cancelled_progress_authority() {
                    return true;
                }
                entry.publish_ready_exact_reply_before_terminal_drop();
                released = released.saturating_add(1);
                false
            });
            !entries.is_empty()
        });
        self.len = self
            .len
            .checked_sub(released)
            .expect("released target deliveries must match reliable backlog ownership");
        self.ready_sources
            .retain(|source| self.by_source.contains_key(source));
        self.ready_members
            .retain(|source| self.by_source.contains_key(source));
        released
    }
}
