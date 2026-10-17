//! Bounded ingress of network messages (`specs/sumeragi.md` §12.3 O5, O6, O8): one queue per
//! `(peer, class)` that drops its oldest message when full, a latest-`Status` slot per peer,
//! round-robin service of the peers within a class, and strict priority control > proposal >
//! bulk with a guaranteed share for bulk so sync always progresses.

use std::{
    collections::{BTreeMap, VecDeque},
    ops::Bound,
};

use iroha_sumeragi::{
    message::{TrafficClass, WireMessage},
    types::PublicKey,
};

/// Ingress bounds and the bulk share (§12.3 O6, O8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngressLimits {
    /// Messages kept per peer in the control, proposal and bulk classes.
    pub per_peer: [usize; 3],
    /// While bulk messages wait, at least one pop in every `bulk_every` serves bulk (10: a
    /// 10 % share).
    pub bulk_every: u32,
}

impl Default for IngressLimits {
    fn default() -> Self {
        Self {
            per_peer: [256, 16, 8],
            bulk_every: 10,
        }
    }
}

/// Priority index of a class: control 0, proposal 1, bulk 2.
pub fn lane(class: TrafficClass) -> usize {
    match class {
        TrafficClass::Control => 0,
        TrafficClass::Proposal => 1,
        TrafficClass::Bulk => 2,
    }
}

fn is_status(msg: &WireMessage) -> bool {
    matches!(msg, WireMessage::Status(_))
}

/// One class: a bounded queue per peer, served round-robin.
#[derive(Debug, Default)]
struct Lane {
    peers: BTreeMap<PublicKey, VecDeque<WireMessage>>,
    /// The peer served last.
    cursor: Option<PublicKey>,
    len: usize,
}

impl Lane {
    /// Queue `msg` from `from`; returns whether a message was dropped. A `Status` replaces the
    /// peer's queued `Status` in place; otherwise a full queue drops its oldest message that is
    /// not the peer's latest `Status`.
    fn push(&mut self, from: PublicKey, msg: WireMessage, cap: usize) -> bool {
        let queue = self.peers.entry(from).or_default();
        if is_status(&msg)
            && let Some(slot) = queue.iter_mut().find(|m| is_status(m))
        {
            *slot = msg;
            return false;
        }
        let mut dropped = false;
        if queue.len() >= cap.max(1)
            && let Some(oldest) = queue.iter().position(|m| !is_status(m))
        {
            queue.remove(oldest);
            self.len -= 1;
            dropped = true;
        }
        queue.push_back(msg);
        self.len += 1;
        dropped
    }

    /// The next message: the next peer after the one served last that has one.
    fn pop(&mut self) -> Option<(PublicKey, WireMessage)> {
        if self.len == 0 {
            return None;
        }
        let after = match &self.cursor {
            Some(last) => self
                .peers
                .range::<PublicKey, _>((Bound::Excluded(last), Bound::Unbounded))
                .next(),
            None => None,
        };
        let peer = after
            .or_else(|| self.peers.iter().next())
            .map(|(k, _)| k.clone())?;
        let queue = self.peers.get_mut(&peer)?;
        let msg = queue.pop_front()?;
        if queue.is_empty() {
            self.peers.remove(&peer);
        }
        self.len -= 1;
        self.cursor = Some(peer.clone());
        Some((peer, msg))
    }
}

/// The ingress queues of one instance.
#[derive(Debug)]
pub struct Ingress {
    limits: IngressLimits,
    lanes: [Lane; 3],
    /// Pops since bulk was last served.
    since_bulk: u32,
    dropped: u64,
}

impl Ingress {
    /// Empty queues with `limits`.
    pub fn new(limits: IngressLimits) -> Self {
        Self {
            limits,
            lanes: Default::default(),
            since_bulk: 0,
            dropped: 0,
        }
    }

    /// Release every retained frame when its instance stops, preserving drop diagnostics.
    pub(super) fn clear(&mut self) {
        self.lanes = Default::default();
        self.since_bulk = 0;
    }

    /// Queue a message of class `class` from the authenticated peer `from` (O6: the oldest
    /// message of that peer and class is dropped when its queue is full).
    pub fn push(&mut self, from: PublicKey, msg: WireMessage, class: TrafficClass) {
        let lane = lane(class);
        let cap = self.limits.per_peer[lane];
        if self.lanes[lane].push(from, msg, cap) {
            self.dropped += 1;
        }
    }

    /// The next message by priority: control, proposal, bulk, except that bulk is served first
    /// when it waited for `bulk_every − 1` pops (O8).
    pub fn pop(&mut self) -> Option<(PublicKey, WireMessage)> {
        let bulk_turn =
            self.since_bulk + 1 >= self.limits.bulk_every.max(1) && self.lanes[2].len > 0;
        let order: [usize; 3] = if bulk_turn { [2, 0, 1] } else { [0, 1, 2] };
        for lane in order {
            if let Some(next) = self.lanes[lane].pop() {
                self.since_bulk = if lane == 2 { 0 } else { self.since_bulk + 1 };
                return Some(next);
            }
        }
        None
    }

    /// Messages queued.
    pub fn len(&self) -> usize {
        self.lanes.iter().map(|l| l.len).sum()
    }

    /// Whether nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Messages dropped by the bounds so far.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use iroha_sumeragi::{
        message::{PayloadRequest, Status, SyncResponse},
        types::Hash32,
    };

    use super::*;

    fn peer(byte: u8) -> PublicKey {
        PublicKey::new(vec![byte; 32]).unwrap()
    }

    fn request(height: u64) -> WireMessage {
        WireMessage::PayloadRequest(PayloadRequest {
            instance: Hash32::ZERO,
            height,
            block_hash: Hash32::ZERO,
        })
    }

    fn status(height: u64) -> WireMessage {
        WireMessage::Status(Box::new(Status {
            instance: Hash32::ZERO,
            height,
            view: 0,
            committed_qc: None,
            high_pqc: None,
            high_tc: None,
            proposal_hash: None,
            want_proposal: false,
            probe: None,
            echo: None,
        }))
    }

    fn bulk() -> WireMessage {
        WireMessage::SyncResponse(SyncResponse {
            instance: Hash32::ZERO,
            blocks: Vec::new(),
        })
    }

    fn height_of(msg: &WireMessage) -> u64 {
        match msg {
            WireMessage::PayloadRequest(r) => r.height,
            WireMessage::Status(s) => s.height,
            _ => u64::MAX,
        }
    }

    #[test]
    fn lane_indices() {
        assert_eq!(lane(TrafficClass::Control), 0);
        assert_eq!(lane(TrafficClass::Proposal), 1);
        assert_eq!(lane(TrafficClass::Bulk), 2);
    }

    /// O6: a flooding peer's queue is bounded and loses its oldest messages.
    #[test]
    fn bounded_drop_oldest() {
        let mut ingress = Ingress::new(IngressLimits::default());
        for h in 0..300 {
            ingress.push(peer(1), request(h), TrafficClass::Control);
        }
        assert_eq!(ingress.len(), 256);
        assert_eq!(ingress.dropped(), 44);
        let (_, first) = ingress.pop().unwrap();
        assert_eq!(height_of(&first), 44, "the 44 oldest were dropped");
        assert!(!ingress.is_empty());
    }

    /// O6: the latest `Status` of a peer replaces the previous one in place and is never the
    /// message a full queue drops.
    #[test]
    fn latest_status_slot() {
        let limits = IngressLimits {
            per_peer: [3, 1, 1],
            bulk_every: 10,
        };
        let mut ingress = Ingress::new(limits);
        ingress.push(peer(1), status(1), TrafficClass::Control);
        ingress.push(peer(1), request(10), TrafficClass::Control);
        ingress.push(peer(1), status(2), TrafficClass::Control);
        assert_eq!(ingress.len(), 2, "one Status slot");
        for h in 11..20 {
            ingress.push(peer(1), request(h), TrafficClass::Control);
        }
        assert_eq!(ingress.len(), 3);
        let order: Vec<u64> = std::iter::from_fn(|| ingress.pop())
            .map(|(_, m)| height_of(&m))
            .collect();
        assert_eq!(
            order,
            vec![2, 18, 19],
            "the latest Status survived at its place"
        );
    }

    /// Within a class, peers are served round-robin: a flooding peer does not starve another.
    #[test]
    fn round_robin_between_peers() {
        let mut ingress = Ingress::new(IngressLimits::default());
        for h in 0..5 {
            ingress.push(peer(1), request(h), TrafficClass::Control);
        }
        ingress.push(peer(2), request(100), TrafficClass::Control);
        ingress.push(peer(2), request(101), TrafficClass::Control);
        let order: Vec<(u8, u64)> = std::iter::from_fn(|| ingress.pop())
            .map(|(p, m)| (p.as_bytes()[0], height_of(&m)))
            .collect();
        assert_eq!(
            order,
            vec![(1, 0), (2, 100), (1, 1), (2, 101), (1, 2), (1, 3), (1, 4)]
        );
    }

    /// O8: strict priority control > proposal > bulk, with a guaranteed share for bulk.
    #[test]
    fn class_priority_and_bulk_share() {
        let mut ingress = Ingress::new(IngressLimits::default());
        ingress.push(peer(1), bulk(), TrafficClass::Bulk);
        ingress.push(peer(1), request(1), TrafficClass::Proposal);
        ingress.push(peer(1), request(0), TrafficClass::Control);
        let classes: Vec<u64> = std::iter::from_fn(|| ingress.pop())
            .map(|(_, m)| height_of(&m))
            .collect();
        assert_eq!(classes, vec![0, 1, u64::MAX]);
        // A control flood: bulk still gets every tenth pop.
        for h in 0..30 {
            ingress.push(
                peer(u8::try_from(h).unwrap()),
                request(h),
                TrafficClass::Control,
            );
        }
        ingress.push(peer(99), bulk(), TrafficClass::Bulk);
        ingress.push(peer(98), bulk(), TrafficClass::Bulk);
        let positions: Vec<usize> = std::iter::from_fn(|| ingress.pop())
            .enumerate()
            .filter(|(_, (_, m))| matches!(m, WireMessage::SyncResponse(_)))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(positions, vec![9, 19]);
    }
}
