//! Bounded serving and retained signed-payload work, off the consensus event loop.
//! Payload phases keep their original owners across resource refusal. Every storage error
//! stays distinct from absence. A worker failure stops the instance instead of inventing data.

use super::{
    payload_worker::{PayloadWork, PayloadWorker},
    traits::{BlockStore, BodyStore, Frame, Net, PendingSend, SendOutcome},
};
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use iroha_sumeragi::{
    api::{Action, Event},
    message::{SyncEntry, SyncResponse, WireMessage},
    types::{Hash32, Millis, PublicKey},
};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
};
const ENTRY_FRAMING: usize = 16;

/// One bounded worker turn selected by the instance scheduler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeRequest {
    /// Consecutive signed manifests and CommitQCs from the committed store.
    Blocks {
        /// Authenticated requesting peer.
        to: PublicKey,
        /// First requested committed height.
        from_height: u64,
        /// Maximum number of consecutive metadata entries.
        max_count: u16,
        /// Response byte bound; one oversized first entry is permitted.
        max_bytes: u32,
    },
    /// Retained author, acquisition, restoration or row-dissemination work.
    Payload(Box<PayloadWork>),
}
impl ServeRequest {
    /// Convert a released Core action, returning unrelated actions unchanged.
    pub fn from_action(action: Action) -> Result<Self, Action> {
        match action {
            Action::ServeBlocks {
                to,
                from_height,
                max_count,
                max_bytes,
            } => Ok(Self::Blocks {
                to,
                from_height,
                max_count,
                max_bytes,
            }),
            other => PayloadWork::from_action(other).map(|work| Self::Payload(Box::new(work))),
        }
    }
}

/// Per-peer response limits and finite retained job/command count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServeLimits {
    /// Response bytes permitted per second.
    pub bytes_per_sec: u64,
    /// Initial and maximum response credit.
    pub burst_bytes: u64,
    /// Bound per purpose: proactive streams, historical responses, local fetches, and metadata.
    /// These classes share the allocation budget; queued commands have the same finite bound.
    pub max_peers: usize,
}
impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            bytes_per_sec: 32 << 20,
            burst_bytes: 64 << 20,
            max_peers: 1_024,
        }
    }
}
#[derive(Debug)]
struct PeerServe {
    body: Option<ServeRequest>,
    blocks: Option<ServeRequest>,
    tokens: i64,
    at: Millis,
    queued: bool,
}
fn burst(l: ServeLimits) -> i64 {
    i64::try_from(l.burst_bytes).unwrap_or(i64::MAX)
}
impl PeerServe {
    fn refill(&mut self, l: ServeLimits, now: Millis) {
        let elapsed = now.saturating_sub(self.at);
        self.at = self.at.max(now);
        let gain = i64::try_from(u128::from(elapsed) * u128::from(l.bytes_per_sec) / 1_000)
            .unwrap_or(i64::MAX);
        self.tokens = self.tokens.saturating_add(gain).min(burst(l));
    }
    fn pending(&self) -> usize {
        usize::from(self.body.is_some()) + usize::from(self.blocks.is_some())
    }
}

/// Pure scheduler. Waiting for remote rows creates no polling work; temporary local refusal
/// uses backoff, and ready output rows get another immediate bounded turn.
#[derive(Debug)]
pub struct ServeSched {
    limits: ServeLimits,
    work: VecDeque<PayloadWork>,
    author: Option<PayloadWork>,
    applied: Option<u64>,
    retain: Option<(u64, Vec<Hash32>)>,
    peers: BTreeMap<PublicKey, PeerServe>,
    order: VecDeque<PublicKey>,
    in_flight: bool,
    in_flight_refusal: Option<crate::execution_attempt::ExecutionDeferred>,
    retry_at: Option<Millis>,
    failed: Option<(
        Millis,
        ServeRequest,
        Option<crate::execution_attempt::ExecutionDeferred>,
    )>,
    dropped: u64,
}
impl ServeSched {
    /// Empty scheduler with independent per-instance bounds.
    pub fn new(limits: ServeLimits) -> Self {
        Self {
            limits,
            work: VecDeque::new(),
            author: None,
            applied: None,
            retain: None,
            peers: BTreeMap::new(),
            order: VecDeque::new(),
            in_flight: false,
            in_flight_refusal: None,
            retry_at: None,
            failed: None,
            dropped: 0,
        }
    }
    /// Queue local work or one request of each kind per remote peer.
    pub fn push(&mut self, request: ServeRequest, now: Millis) -> bool {
        let to = match &request {
            ServeRequest::Blocks { to, .. } => to.clone(),
            ServeRequest::Payload(work) => match &**work {
                PayloadWork::Serve { to, .. } => to.clone(),
                _ => {
                    let ServeRequest::Payload(work) = request else {
                        unreachable!()
                    };
                    if matches!(&*work, PayloadWork::Poll) {
                        self.retry_at = Some(now);
                        return true;
                    }
                    // These local commands cannot be lost to peer-controlled queue
                    // pressure. Each has one bounded slot; a newer round/application supersedes
                    // the previous one without retaining another payload owner.
                    if matches!(&*work, PayloadWork::Author { .. }) {
                        self.author = Some(*work);
                        return true;
                    }
                    if let PayloadWork::Retain { height, keep } = &*work {
                        if self.retain.as_ref().is_none_or(|(old, _)| *old <= *height) {
                            self.retain = Some((*height, keep.clone()));
                            self.work.retain(|work| !matches!(work, PayloadWork::Disseminate { body, .. }
                                if body.source().height() == *height && !keep.contains(&body.source().block_hash())));
                        }
                        return true;
                    }
                    if let PayloadWork::Applied(height) = &*work {
                        self.applied = Some(self.applied.map_or(*height, |old| old.max(*height)));
                        return true;
                    }
                    if self.work.contains(&work) {
                        return true;
                    }
                    if self.work.len() >= self.limits.max_peers.max(1) {
                        // Fetch/acquisition/dissemination requests are retried by Core's
                        // existing body and proposal timers. Refuse only this new command.
                        self.dropped += 1;
                        return false;
                    }
                    self.work.push_back(*work);
                    return true;
                }
            },
        };
        if !self.peers.contains_key(&to) && self.peers.len() >= self.limits.max_peers {
            let limits = self.limits;
            self.peers.retain(|_, p| {
                p.refill(limits, now);
                p.queued || p.tokens < burst(limits)
            });
            if self.peers.len() >= self.limits.max_peers {
                self.dropped += 1;
                return false;
            }
        }
        let p = self.peers.entry(to.clone()).or_insert(PeerServe {
            body: None,
            blocks: None,
            tokens: burst(self.limits),
            at: now,
            queued: false,
        });
        p.refill(self.limits, now);
        if p.tokens <= 0 {
            self.dropped += 1;
            return false;
        }
        let slot = if matches!(request, ServeRequest::Blocks { .. }) {
            &mut p.blocks
        } else {
            &mut p.body
        };
        if slot.replace(request).is_some() {
            self.dropped += 1;
        }
        if !p.queued {
            p.queued = true;
            self.order.push_back(to);
        }
        true
    }
    /// One operation, never another while the worker owns the previous turn.
    pub fn next(&mut self, now: Millis) -> Option<ServeRequest> {
        if self.in_flight {
            return None;
        }
        let work = self
            .applied
            .take()
            .map(PayloadWork::Applied)
            .or_else(|| {
                self.retain
                    .take()
                    .map(|(height, keep)| PayloadWork::Retain { height, keep })
            })
            .or_else(|| self.author.take())
            .or_else(|| self.work.pop_front());
        if let Some(work) = work {
            self.in_flight = true;
            return Some(ServeRequest::Payload(Box::new(work)));
        }
        if self.failed.as_ref().is_some_and(|(at, _, _)| *at <= now) {
            let (_, request, refusal) = self
                .failed
                .take()
                .expect("retained refused metadata request");
            self.in_flight = true;
            self.in_flight_refusal = refusal;
            return Some(request);
        }
        if self.retry_at.is_some_and(|at| at <= now) {
            self.retry_at = None;
            self.in_flight = true;
            return Some(ServeRequest::Payload(Box::new(PayloadWork::Poll)));
        }
        // The sole failed metadata slot must survive until its original request completes.
        // Still serve payload requests and local row progress while metadata backs off.
        let queued = self.order.len();
        for _ in 0..queued {
            let key = self.order.pop_front().expect("bounded queued peers");
            let Some(p) = self.peers.get_mut(&key) else {
                continue;
            };
            p.refill(self.limits, now);
            if p.tokens <= 0 {
                self.dropped += p.pending() as u64;
                p.body = None;
                p.blocks = None;
                p.queued = false;
                continue;
            }
            let request = p.body.take().or_else(|| {
                (self.failed.is_none() || cfg!(all(test, sumeragi_core_mutation = "HC47")))
                    .then(|| p.blocks.take())
                    .flatten()
            });
            let Some(request) = request else {
                if p.pending() > 0 {
                    self.order.push_back(key);
                } else {
                    p.queued = false;
                }
                continue;
            };
            if p.pending() > 0 {
                self.order.push_back(key);
            } else {
                p.queued = false;
            }
            self.in_flight = true;
            return Some(request);
        }
        None
    }
    /// Release this turn, charge actual responses and schedule only actual retained work.
    pub fn done(&mut self, now: Millis, served: Served) -> Vec<Event> {
        self.in_flight = false;
        self.in_flight_refusal = None;
        for (key, bytes) in &served.charges {
            if let Some(p) = self.peers.get_mut(key) {
                p.refill(self.limits, now);
                p.tokens = p
                    .tokens
                    .saturating_sub(i64::try_from(*bytes).unwrap_or(i64::MAX));
            }
        }
        if served.payload {
            self.retry_at = served
                .retry
                .then_some(now.saturating_add(if served.refused { 10 } else { 0 }));
        }
        if let Some(request) = served.retry_request {
            self.failed = Some((now.saturating_add(10), request, served.deferred));
        }
        served.events
    }
    /// Earliest retained-job retry; no timer for jobs awaiting remote rows.
    pub fn wakeup(&self) -> Millis {
        self.retry_at
            .unwrap_or(Millis::MAX)
            .min(self.failed.as_ref().map_or(Millis::MAX, |(at, _, _)| *at))
    }
    /// Pending commands, excluding worker-owned retained jobs.
    pub fn len(&self) -> usize {
        usize::from(self.author.is_some())
            + usize::from(self.applied.is_some())
            + usize::from(self.retain.is_some())
            + self.work.len()
            + self.peers.values().map(PeerServe::pending).sum::<usize>()
    }
    /// No pending commands.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The worker owns a turn.
    pub fn busy(&self) -> bool {
        self.in_flight
    }
    /// Requests dropped by queue or per-peer bounds.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// Consecutive metadata entries, including an oversized first entry as the protocol permits.
/// Read errors are propagated; they never produce an empty successful response.
pub fn entries(
    blocks: &(impl BlockStore + ?Sized),
    from_height: u64,
    max_count: u16,
    max_bytes: u32,
) -> Result<Vec<SyncEntry>, Attempt<io::Error>> {
    let (mut out, mut bytes) = (Vec::new(), 0usize);
    for offset in 0..u64::from(max_count) {
        let Some(height) = from_height.checked_add(offset) else {
            break;
        };
        let Some(entry) = blocks.entry(height)? else {
            break;
        };
        let size = norito::codec::Encode::encoded_len(&entry).saturating_add(ENTRY_FRAMING);
        if !out.is_empty() && bytes.saturating_add(size) > max_bytes as usize {
            break;
        }
        bytes = bytes.saturating_add(size);
        out.push(entry);
    }
    Ok(out)
}
/// Encode once for all recipients. Encoding failure is reported to the caller.
pub fn frame(msg: &WireMessage) -> Option<Frame> {
    match msg.encode() {
        Ok(bytes) => Some(Frame {
            instance: *msg.instance(),
            class: msg.traffic_class(),
            bytes: bytes.into(),
        }),
        Err(error) => {
            iroha_logger::error!(%error,"sumeragi message does not encode");
            None
        }
    }
}
/// Actual worker completion; no successful default is substituted on panic or corruption.
#[derive(Debug, Default)]
pub struct Served {
    /// This turn progressed the retained payload worker.
    pub payload: bool,
    /// Exact metadata request retained after local resource refusal.
    pub retry_request: Option<ServeRequest>,
    /// Original local storage refusal, retained with the exact metadata retry request.
    pub deferred: Option<crate::execution_attempt::ExecutionDeferred>,
    /// Verified events in order.
    pub events: Vec<Event>,
    /// Actual bytes sent per requesting peer, including continued rows from later turns.
    pub charges: Vec<(PublicKey, u64)>,
    /// Another retained phase can make progress.
    pub retry: bool,
    /// Resource refusal needs backoff.
    pub refused: bool,
}
/// One bounded encoded output batch. Each peer retains its own original admission receipt;
/// a refused peer does not prevent the other peers from admitting this same batch.
pub(super) struct DeliveryBatch {
    frames: Vec<Frame>,
    recipients: Vec<Recipient>,
}
struct Recipient {
    peer: PublicKey,
    frames: Vec<usize>,
    next: usize,
    pending: Option<Box<dyn PendingSend>>,
    metered: bool,
}
impl DeliveryBatch {
    pub(super) fn new(
        outputs: Vec<(Vec<PublicKey>, Frame)>,
        metered: &[PublicKey],
    ) -> io::Result<Self> {
        // A worker turn emits at most a fetch request, a manifest and one row.
        if outputs.len() > 3 {
            return Err(io::Error::other(
                "availability output batch exceeds turn bound",
            ));
        }
        let mut frames = Vec::with_capacity(outputs.len());
        let mut recipients = BTreeMap::<PublicKey, Vec<usize>>::new();
        for (peers, frame) in outputs {
            let index = frames.len();
            frames.push(frame);
            for peer in peers {
                let indices = recipients.entry(peer).or_default();
                if indices.last() != Some(&index) {
                    indices.push(index);
                }
            }
        }
        Ok(Self {
            frames,
            recipients: recipients
                .into_iter()
                .map(|(peer, frames)| Recipient {
                    metered: metered.contains(&peer),
                    peer,
                    frames,
                    next: 0,
                    pending: None,
                })
                .collect(),
        })
    }
    /// Core may rotate the destinations of the same source-bound fetch. Intersection peers
    /// keep their exact original occurrence; removed peers explicitly cancel their receipt.
    pub(super) fn retarget(&mut self, peers: &[PublicKey]) {
        self.recipients
            .retain(|recipient| peers.contains(&recipient.peer));
        for peer in peers {
            if !self
                .recipients
                .iter()
                .any(|recipient| &recipient.peer == peer)
            {
                self.recipients.push(Recipient {
                    peer: peer.clone(),
                    frames: (0..self.frames.len()).collect(),
                    next: 0,
                    pending: None,
                    metered: false,
                });
            }
        }
    }
    pub(super) fn poll(&mut self, net: &dyn Net) -> io::Result<Vec<(PublicKey, u64)>> {
        let mut charges = Vec::new();
        for recipient in &mut self.recipients {
            let mut bytes = 0u64;
            while let Some(&index) = recipient.frames.get(recipient.next) {
                let outcome = match recipient.pending.take() {
                    Some(pending) => pending.retry(),
                    None => net.send(&recipient.peer, &self.frames[index]),
                };
                match outcome {
                    SendOutcome::Admitted => {
                        recipient.next += 1;
                        if recipient.metered {
                            bytes += self.frames[index].bytes.len() as u64;
                        }
                    }
                    SendOutcome::Backpressured(pending) => {
                        recipient.pending = Some(pending);
                        break;
                    }
                    SendOutcome::Closed => {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "availability transport closed",
                        ));
                    }
                    SendOutcome::Rejected => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "availability transport rejected exact frame",
                        ));
                    }
                }
            }
            if bytes != 0 {
                charges.push((recipient.peer.clone(), bytes));
            }
        }
        Ok(charges)
    }
    pub(super) fn complete(&self) -> bool {
        self.recipients
            .iter()
            .all(|peer| peer.next == peer.frames.len())
    }
}
fn deliver(worker: &mut PayloadWorker, net: &dyn Net, served: &mut Served) -> io::Result<()> {
    // Every retained metadata recipient gets one bounded attempt; none gates row streams.
    let count = worker.metadata.len();
    for _ in 0..count {
        let (peer, mut batch) = worker.metadata.pop_front().expect("bounded metadata slot");
        served.charges.extend(batch.poll(net)?);
        if !batch.complete() {
            worker.metadata.push_back((peer, batch));
            served.retry = true;
            served.refused = true;
        }
    }
    Ok(())
}
/// Run one bounded serving turn with the same retained worker across requests.
/// Exact encoded frames and recoverable post receipts survive every pressure retry.
pub fn serve(
    request: ServeRequest,
    instance: Hash32,
    bodies: &dyn BodyStore,
    blocks: &dyn BlockStore,
    net: &dyn Net,
    worker: &mut PayloadWorker,
) -> io::Result<Served> {
    let result = (|| {
        let mut served = Served {
            payload: true,
            ..Served::default()
        };
        deliver(worker, net, &mut served)?;
        match request {
            ServeRequest::Blocks {
                to,
                from_height,
                max_count,
                max_bytes,
            } => {
                let original = ServeRequest::Blocks {
                    to: to.clone(),
                    from_height,
                    max_count,
                    max_bytes,
                };
                let entries = match entries(blocks, from_height, max_count, max_bytes) {
                    Ok(entries) => entries,
                    Err(Attempt::Deferred(reason)) => {
                        served.retry_request = Some(original);
                        served.deferred = Some(reason);
                        return Ok(served);
                    }
                    Err(Attempt::Rejected(error))
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        served.retry_request = Some(original);
                        return Ok(served);
                    }
                    Err(Attempt::Rejected(error)) => return Err(error),
                };
                let msg = WireMessage::SyncResponse(SyncResponse {
                    instance,
                    blocks: entries,
                });
                let frame = frame(&msg).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "sync metadata encoding")
                })?;
                worker.retain_metadata(
                    to.clone(),
                    DeliveryBatch::new(vec![(vec![to.clone()], frame)], &[to])?,
                );
            }
            ServeRequest::Payload(work) => {
                let progress = worker.step(*work, bodies, blocks, net)?;
                served.events = progress.events;
                served.charges.extend(progress.charges);
                served.retry |= progress.retry;
                served.refused |= progress.refused;
            }
        }
        // Newly queued metadata waits for the next bounded turn when another recipient
        // already refused above; no transport occurrence is attempted twice in one turn.
        if !served.refused {
            deliver(worker, net, &mut served)?;
        }
        Ok(served)
    })();
    result.map(|mut served| {
        served.retry |= worker.has_runnable();
        served
    })
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "delivery_tests.rs"]
mod delivery_tests;
