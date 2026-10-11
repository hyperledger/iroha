//! Network model (§13.1): traffic classes and sizes (O8, O10), per-link delay distributions
//! with heavy tails, loss, duplication, reordering, delay spikes, directed (asymmetric)
//! partitions and a heal time (GST), and a per-replica NIC with strict-priority egress and a
//! guaranteed minimum share for bulk traffic.

use std::collections::{BTreeSet, VecDeque};

use super::rng::Rng;
use crate::{
    message::{BlockHeader, PayloadManifest, Qc, TimeoutCert, TrafficClass, WireMessage},
    types::Millis,
};

/// Traffic class of a message (O8): the core's table (§3.5, Appendix E, E44).
pub type Class = TrafficClass;

/// The O8 class of `msg` (`WireMessage::traffic_class`, the table the transport uses).
pub fn class_of(msg: &WireMessage) -> Class {
    msg.traffic_class()
}

/// Lane index of a class (priority order: control, proposal, bulk).
pub fn lane(class: Class) -> usize {
    match class {
        Class::Control => 0,
        Class::Proposal => 1,
        Class::Bulk => 2,
    }
}

fn qc_size(qc: &Qc) -> u64 {
    1 + 32 + 8 + 8 + 32 + 32 + 8 + len64(qc.signers.as_bytes().len()) + 96
}

fn opt_qc_size(qc: Option<&Qc>) -> u64 {
    1 + qc.map_or(0, qc_size)
}

fn tc_size(tc: &TimeoutCert) -> u64 {
    32 + 8 + 8 + 8 + 13 * len64(tc.entries.len()) + 96 + opt_qc_size(tc.high_pqc.as_ref())
}

fn header_size(header: &BlockHeader) -> u64 {
    32 + 40
        + 32
        + 8
        + 8
        + 32
        + 32
        + 32
        + 4
        + 4
        + 8
        + 40 * len64(header.skipped_leaders.len())
        + 8
        + len64(header.control_witness.len())
}

fn manifest_size(manifest: &PayloadManifest) -> u64 {
    header_size(&manifest.header) + 8 + len64(manifest.availability.as_slice().len())
}

fn len64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Approximate encoded size of a message (framing overhead included), without encoding it.
pub fn approx_size(msg: &WireMessage) -> u64 {
    let body = match msg {
        WireMessage::Proposal(p) => {
            32 + 8
                + 8
                + header_size(&p.proposal.header)
                + 1
                + p.proposal.justify.as_ref().map_or(0, tc_size)
                + opt_qc_size(p.proposal.parent_qc.as_ref())
                + 1
                + 8
                + len64(p.availability.as_slice().len())
                + 96
        }
        WireMessage::Vote(_) => 1 + 32 + 8 + 8 + 32 + 32 + 4 + 96,
        WireMessage::Qc(qc) => qc_size(qc),
        WireMessage::Timeout(t) => 32 + 8 + 8 + opt_qc_size(t.high_pqc.as_ref()) + 4 + 96,
        WireMessage::Tc(tc) => tc_size(tc),
        WireMessage::Status(s) => {
            32 + 8
                + 8
                + opt_qc_size(s.committed_qc.as_ref())
                + opt_qc_size(s.high_pqc.as_ref())
                + 1
                + s.high_tc.as_ref().map_or(0, tc_size)
                + 33
        }
        WireMessage::SyncRequest(_) => 32 + 8 + 2 + 4,
        WireMessage::SyncResponse(r) => {
            32 + 8
                + r.blocks
                    .iter()
                    .map(|e| manifest_size(&e.manifest) + qc_size(&e.commit_qc))
                    .sum::<u64>()
        }
        WireMessage::PayloadRequest(_) => 32 + 8 + 32,
        WireMessage::PayloadManifest(r) => manifest_size(r),
        WireMessage::PayloadChunk(r) => 32 + 8 + 32 + 4 + 8 + len64(r.bytes.as_slice().len()),
        WireMessage::ApplicationControl(message) => {
            32 + 40 + 8 + 64 + 8 + len64(message.bytes.len())
        }
    };
    body + 16
}

/// A directed partition: messages from `a` to `b` for `(a, b) ∈ blocked` are dropped while it
/// is active.
#[derive(Clone, Debug)]
pub struct Partition {
    /// Start (inclusive).
    pub from: Millis,
    /// End (exclusive).
    pub until: Millis,
    /// Blocked directed machine pairs.
    pub blocked: BTreeSet<(usize, usize)>,
}

impl Partition {
    /// Isolate `group` from everyone else in both directions.
    pub fn isolate(from: Millis, until: Millis, group: &[usize], n: usize) -> Self {
        let mut blocked = BTreeSet::new();
        for &a in group {
            for b in 0..n {
                if !group.contains(&b) {
                    blocked.insert((a, b));
                    blocked.insert((b, a));
                }
            }
        }
        Self {
            from,
            until,
            blocked,
        }
    }

    /// Block only the direction `from_group → to_group` (asymmetric).
    pub fn one_way(from: Millis, until: Millis, from_group: &[usize], to_group: &[usize]) -> Self {
        let blocked = from_group
            .iter()
            .flat_map(|a| to_group.iter().map(move |b| (*a, *b)))
            .filter(|(a, b)| a != b)
            .collect();
        Self {
            from,
            until,
            blocked,
        }
    }

    fn blocks(&self, t: Millis, a: usize, b: usize) -> bool {
        (self.from..self.until).contains(&t) && self.blocked.contains(&(a, b))
    }
}

/// A delay spike: delays are multiplied by `factor` in `[from, until)`.
#[derive(Clone, Copy, Debug)]
pub struct Spike {
    /// Start.
    pub from: Millis,
    /// End.
    pub until: Millis,
    /// Delay multiplier.
    pub factor: u64,
}

/// Network parameters of a scenario.
#[derive(Clone, Debug)]
pub struct NetConfig {
    /// Minimum one-way delay.
    pub delay_min: Millis,
    /// Maximum one-way delay (after heal, `Δ` = this plus serialization).
    pub delay_max: Millis,
    /// Probability (ppm) of a heavy-tail delay before heal.
    pub tail_ppm: u32,
    /// Heavy-tail multiplier.
    pub tail_factor: u64,
    /// Loss probability (ppm) before heal.
    pub loss_ppm: u32,
    /// Loss probability (ppm) after heal.
    pub post_heal_loss_ppm: u32,
    /// Duplication probability (ppm).
    pub dup_ppm: u32,
    /// Probability (ppm) of an extra reordering delay.
    pub reorder_ppm: u32,
    /// Extra delay of a reordered message (uniform up to this).
    pub reorder_extra: Millis,
    /// NIC bandwidth in bytes per millisecond (`0` = unlimited).
    pub bandwidth: u64,
    /// Transport frame limit (O10); larger messages are dropped by the transport.
    pub frame_limit: u64,
    /// Directed partitions.
    pub partitions: Vec<Partition>,
    /// Delay spikes.
    pub spikes: Vec<Spike>,
    /// Per-machine extra delay on every link touching it (a "slow" node).
    pub slow_links: Vec<(usize, Millis)>,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            delay_min: 5,
            delay_max: 50,
            tail_ppm: 0,
            tail_factor: 10,
            loss_ppm: 0,
            post_heal_loss_ppm: 0,
            dup_ppm: 0,
            reorder_ppm: 0,
            reorder_extra: 100,
            bandwidth: 1_000_000,
            frame_limit: u64::MAX,
            partitions: Vec::new(),
            spikes: Vec::new(),
            slow_links: Vec::new(),
        }
    }
}

/// What the link does with one packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fate {
    /// Dropped (loss, partition or frame limit).
    Drop,
    /// Delivered after these delays (one entry per copy; duplication gives two).
    Deliver(Millis, Option<Millis>),
}

impl NetConfig {
    /// Decide the fate of a packet from machine `a` to machine `b` departing at `t`.
    pub fn fate(&self, rng: &mut Rng, t: Millis, heal_at: Millis, a: usize, b: usize) -> Fate {
        if self.partitions.iter().any(|p| p.blocks(t, a, b)) {
            return Fate::Drop;
        }
        let healed = t >= heal_at;
        let loss = if healed {
            self.post_heal_loss_ppm
        } else {
            self.loss_ppm
        };
        if rng.chance(loss) {
            return Fate::Drop;
        }
        let first = self.delay(rng, t, healed, a, b);
        let second = rng
            .chance(self.dup_ppm)
            .then(|| self.delay(rng, t, healed, a, b));
        Fate::Deliver(first, second)
    }

    fn delay(&self, rng: &mut Rng, t: Millis, healed: bool, a: usize, b: usize) -> Millis {
        let mut d = rng.range(self.delay_min, self.delay_max);
        if !healed && rng.chance(self.tail_ppm) {
            d = d.saturating_mul(self.tail_factor);
        }
        if rng.chance(self.reorder_ppm) {
            d = d.saturating_add(rng.range(0, self.reorder_extra));
        }
        for spike in &self.spikes {
            if (spike.from..spike.until).contains(&t) {
                d = d.saturating_mul(spike.factor);
            }
        }
        for (m, extra) in &self.slow_links {
            if *m == a || *m == b {
                d = d.saturating_add(*extra);
            }
        }
        d
    }

    /// `Δ` after heal: the largest delay plus slow links (no tails, spikes or reordering after
    /// heal are assumed by the scenarios that check performance bounds).
    pub fn delta(&self) -> Millis {
        let slow = self.slow_links.iter().map(|(_, d)| *d).max().unwrap_or(0);
        self.delay_max
            .saturating_add(slow.saturating_mul(2))
            .saturating_add(if self.reorder_ppm > 0 {
                self.reorder_extra
            } else {
                0
            })
    }
}

/// A packet waiting in a NIC queue.
#[derive(Clone, Debug)]
pub struct Packet<T> {
    /// Payload (message and addressing).
    pub item: T,
    /// Size in bytes.
    pub size: u64,
}

/// A replica's NIC: one transmission at a time, strict priority control > proposal > bulk,
/// with every tenth transmission reserved for bulk when bulk is waiting (O8).
#[derive(Clone, Debug)]
pub struct Nic<T> {
    free_us: u64,
    queues: [VecDeque<Packet<T>>; 3],
    since_bulk: u32,
    /// A `NicFree` wakeup is scheduled.
    pub wakeup_pending: bool,
}

impl<T> Default for Nic<T> {
    fn default() -> Self {
        Self {
            free_us: 0,
            queues: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
            since_bulk: 0,
            wakeup_pending: false,
        }
    }
}

impl<T> Nic<T> {
    /// Queue a packet at time `now_us`.
    pub fn push(&mut self, class: Class, packet: Packet<T>) {
        if let Some(queue) = self.queues.get_mut(lane(class)) {
            queue.push_back(packet);
        }
    }

    /// Whether packets are waiting.
    pub fn is_empty(&self) -> bool {
        self.queues.iter().all(VecDeque::is_empty)
    }

    /// Packets waiting.
    pub fn len(&self) -> usize {
        self.queues.iter().map(VecDeque::len).sum()
    }

    /// Transmit every packet that can start before the end of millisecond `now` (µs clock),
    /// in priority order. Returns `(departure_ms, item)` pairs and, if packets remain, the
    /// millisecond at which the NIC frees up.
    pub fn drain(&mut self, now: Millis, bandwidth: u64) -> (Vec<(Millis, T)>, Option<Millis>) {
        let now_us = now.saturating_mul(1_000);
        let horizon = now_us.saturating_add(1_000);
        self.free_us = self.free_us.max(now_us);
        let mut out = Vec::new();
        while self.free_us < horizon {
            let Some(packet) = self.pop() else {
                break;
            };
            let tx_us = if bandwidth == 0 {
                0
            } else {
                packet.size.saturating_mul(1_000) / bandwidth
            };
            self.free_us = self.free_us.saturating_add(tx_us);
            out.push((self.free_us.div_ceil(1_000), packet.item));
        }
        let next = (!self.is_empty()).then(|| self.free_us.div_ceil(1_000));
        (out, next)
    }

    fn pop(&mut self) -> Option<Packet<T>> {
        let bulk_turn = self.since_bulk >= 9 && !self.queues[2].is_empty();
        if bulk_turn {
            self.since_bulk = 0;
            return self.queues[2].pop_front();
        }
        for lane in 0..3 {
            if let Some(packet) = self.queues[lane].pop_front() {
                self.since_bulk = if lane == 2 { 0 } else { self.since_bulk + 1 };
                return Some(packet);
            }
        }
        None
    }

    /// Drop everything (crash).
    pub fn clear(&mut self) {
        for queue in &mut self.queues {
            queue.clear();
        }
        self.wakeup_pending = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nic_priority_and_bandwidth() {
        let mut nic: Nic<u32> = Nic::default();
        nic.push(
            Class::Proposal,
            Packet {
                item: 1,
                size: 10_000,
            },
        );
        nic.push(
            Class::Proposal,
            Packet {
                item: 2,
                size: 10_000,
            },
        );
        nic.push(Class::Control, Packet { item: 3, size: 100 });
        // 1000 B/ms: the control packet goes first, then one proposal (10 ms).
        let (out, next) = nic.drain(0, 1_000);
        assert_eq!(out, vec![(1, 3), (11, 1)]);
        assert_eq!(next, Some(11));
        let (out, next) = nic.drain(11, 1_000);
        assert_eq!(out, vec![(21, 2)]);
        assert_eq!(next, None);
        assert!(nic.is_empty());
        // Bulk gets every tenth slot.
        for i in 0..12 {
            nic.push(Class::Control, Packet { item: i, size: 0 });
        }
        nic.push(Class::Bulk, Packet { item: 99, size: 0 });
        let (out, _) = nic.drain(30, 0);
        let pos = out.iter().position(|(_, item)| *item == 99).unwrap();
        assert!(pos <= 10, "bulk served at {pos}");
        assert_eq!(nic.len(), 0);
    }

    #[test]
    fn link_fates() {
        let mut rng = Rng::new(1);
        let mut cfg = NetConfig {
            partitions: vec![Partition::one_way(0, 100, &[0], &[1])],
            ..NetConfig::default()
        };
        assert_eq!(cfg.fate(&mut rng, 10, 0, 0, 1), Fate::Drop);
        assert!(matches!(cfg.fate(&mut rng, 10, 0, 1, 0), Fate::Deliver(..)));
        assert!(matches!(
            cfg.fate(&mut rng, 100, 0, 0, 1),
            Fate::Deliver(..)
        ));
        cfg.loss_ppm = super::super::rng::PPM;
        assert_eq!(cfg.fate(&mut rng, 200, 1_000, 1, 0), Fate::Drop);
        assert!(matches!(
            cfg.fate(&mut rng, 200, 100, 1, 0),
            Fate::Deliver(..)
        ));
        let iso = Partition::isolate(0, 10, &[2], 4);
        assert!(iso.blocks(5, 2, 0) && iso.blocks(5, 0, 2) && !iso.blocks(5, 0, 1));
        assert_eq!(cfg.delta(), 50);
    }
}
