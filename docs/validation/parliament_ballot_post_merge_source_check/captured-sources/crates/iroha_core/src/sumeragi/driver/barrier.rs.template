//! The persist-before-effect barrier (`specs/sumeragi.md` §12.3 O2, §7.4).
//!
//! After a `PersistSafety`, every later externally visible action — `Send`, `Broadcast`,
//! `CommitBlock` (and anything later served from the block store), `ServeBlocks`, `ServePayload`,
//! `FetchPayload`, `ReportEvidence`, and `Halt` — takes effect only once that record is durable,
//! in the order the core emitted them (O1). The exempt actions (`Execute`, `DiscardExecution`,
//! `BuildPayload`, `RecoverProposalAdmission`, `PayloadRejected`, `LocalFault`, `StoreBody`) never wait. Records are
//! identified by the sequence numbers of the ordered persistence queue, so "durable up to `s`"
//! also covers every earlier `StoreBody` (§7.4 body durability).
//!
//! While a write keeps failing the core keeps rebroadcasting, so the held effects are bounded
//! ([`HeldLimits`]): beyond the bounds the oldest held network messages and serving requests
//! are dropped (O6: the core rebroadcasts its state and requesters retry), and a newer
//! `FetchPayload` of a body replaces a held one. `CommitBlock`, evidence and `Halt` are never
//! dropped (the core emits a bounded number of them).

use std::collections::VecDeque;

use iroha_sumeragi::{api::Action, message::WireMessage};

/// Whether `action` waits behind a pending safety record (O2). `PersistSafety` itself is the
/// barrier and is not gated.
pub fn gated(action: &Action) -> bool {
    !matches!(
        action,
        Action::PersistSafety(_)
            | Action::StoreBody { .. }
            | Action::Execute { .. }
            | Action::DiscardExecution { .. }
            | Action::BuildPayload { .. }
            | Action::RecoverProposalAdmission { .. }
            | Action::AuthorPayload { .. }
            | Action::AcquirePayload { .. }
            | Action::ReceivePayloadChunk { .. }
            | Action::BuildControlWitness { .. }
            | Action::DriveApplicationControl { .. }
            | Action::ReceiveApplicationControl { .. }
            | Action::PayloadRejected { .. }
            | Action::LocalFault(_)
    )
}

/// Whether a held `action` may be dropped under the [`HeldLimits`] (O6): network messages and
/// serving requests.
pub fn droppable(action: &Action) -> bool {
    matches!(
        action,
        Action::Send { .. }
            | Action::Broadcast { .. }
            | Action::DisseminatePayload { .. }
            | Action::ServeBlocks { .. }
            | Action::ServePayload { .. }
    )
}

/// Block payload bytes a message carries (what dominates its size).
pub fn message_payload_bytes(msg: &WireMessage) -> u64 {
    let len = |bytes: usize| u64::try_from(bytes).unwrap_or(u64::MAX);
    let manifest = |m: &iroha_sumeragi::message::PayloadManifest| {
        len(m.availability.as_slice().len())
            .saturating_add(len(iroha_sumeragi::types::MAX_CONTROL_WITNESS_BYTES))
    };
    match msg {
        WireMessage::Proposal(p) => len(p.availability.as_slice().len())
            .saturating_add(len(iroha_sumeragi::types::MAX_CONTROL_WITNESS_BYTES)),
        WireMessage::PayloadManifest(m) => manifest(m),
        WireMessage::PayloadChunk(chunk) => len(chunk.bytes.as_slice().len()),
        WireMessage::ApplicationControl(_) => len(iroha_sumeragi::types::MAX_CONTROL_WITNESS_BYTES),
        WireMessage::SyncResponse(r) => r
            .blocks
            .iter()
            .map(|entry| manifest(&entry.manifest))
            .fold(0, u64::saturating_add),
        _ => 0,
    }
}

/// Exact retained bulk bytes plus the bounded header witness of a held action.
fn payload_bytes(action: &Action) -> u64 {
    match action {
        Action::Send { msg, .. } | Action::Broadcast { msg, .. } => message_payload_bytes(msg),
        Action::CommitBlock { block, .. } | Action::DisseminatePayload { body: block, .. } => {
            (block.payload().as_slice().len() as u64)
                .saturating_add(block.availability().as_slice().len() as u64)
                .saturating_add(iroha_sumeragi::types::MAX_CONTROL_WITNESS_BYTES as u64)
        }
        _ => 0,
    }
}

/// Bounds of the effects held behind a pending record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldLimits {
    /// Held effects.
    pub effects: usize,
    /// Block payload bytes of the held effects.
    pub payload_bytes: u64,
}

impl Default for HeldLimits {
    fn default() -> Self {
        Self {
            effects: 1_024,
            payload_bytes: 32 << 20,
        }
    }
}

/// Effects held behind the latest pending safety record.
#[derive(Debug, Default)]
pub struct Barrier {
    /// Sequence number of the latest record not yet durable.
    pending: Option<u64>,
    /// Held effects with the record they wait for, in emission order.
    held: VecDeque<(u64, Action)>,
    limits: HeldLimits,
    /// Payload bytes of `held`.
    bytes: u64,
    dropped: u64,
}

impl Barrier {
    /// An empty barrier with `limits`.
    pub fn new(limits: HeldLimits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    /// The record with sequence number `seq` was queued: later gated effects wait for it.
    pub fn persisting(&mut self, seq: u64) {
        self.pending = Some(seq);
    }

    /// The record `old` was superseded by the newer record `new` of the same key (and will
    /// never be written): whatever was emitted after `old` now waits for `new` at least.
    pub fn superseded(&mut self, old: u64, new: u64) {
        let later = |seq: u64| if seq >= old { seq.max(new) } else { seq };
        for (seq, _) in &mut self.held {
            *seq = later(*seq);
        }
        self.pending = self.pending.map(later);
    }

    /// An action the core emitted: returned to be performed now if it is exempt or no record is
    /// pending, otherwise held (within the limits).
    pub fn admit(&mut self, action: Action) -> Option<Action> {
        match self.pending {
            Some(seq) if gated(&action) => {
                self.hold(seq, action);
                None
            }
            _ => Some(action),
        }
    }

    fn hold(&mut self, seq: u64, action: Action) {
        if let Action::FetchPayload { source, .. } = &action {
            // The newer fetch waits for a record at least as late as the one it replaces.
            let wanted = source;
            self.held.retain(
                |(_, held)| !matches!(held, Action::FetchPayload { source, .. } if source == wanted),
            );
        }
        self.bytes = self.bytes.saturating_add(payload_bytes(&action));
        self.held.push_back((seq, action));
        while self.held.len() > self.limits.effects || self.bytes > self.limits.payload_bytes {
            let Some(index) = self.held.iter().position(|(_, held)| droppable(held)) else {
                break;
            };
            if let Some((_, dropped)) = self.held.remove(index) {
                self.bytes = self.bytes.saturating_sub(payload_bytes(&dropped));
                self.dropped += 1;
            }
        }
    }

    /// The writes up to sequence number `durable` are durable: the held effects that waited
    /// for them, in order.
    pub fn release(&mut self, durable: u64) -> Vec<Action> {
        if self.pending.is_some_and(|seq| seq <= durable) {
            self.pending = None;
        }
        let mut released = Vec::new();
        while self.held.front().is_some_and(|(seq, _)| *seq <= durable) {
            if let Some((_, action)) = self.held.pop_front() {
                self.bytes = self.bytes.saturating_sub(payload_bytes(&action));
                released.push(action);
            }
        }
        released
    }

    /// The held effects in order (an observation for tests and diagnostics).
    pub fn held(&self) -> impl Iterator<Item = &Action> {
        self.held.iter().map(|(_, action)| action)
    }

    /// Number of held effects and their payload bytes.
    pub fn size(&self) -> (usize, u64) {
        (self.held.len(), self.bytes)
    }

    /// Held effects dropped by the limits so far.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use iroha_sumeragi::{
        api::{HaltReason, LocalFault},
        message::{PayloadRequest, WireMessage},
        types::{Hash32, PublicKey},
    };

    use super::{
        super::tests::{block, commit_qc},
        *,
    };

    fn send(height: u64) -> Action {
        Action::Send {
            to: PublicKey::new(vec![1; 32]).unwrap(),
            msg: WireMessage::PayloadRequest(PayloadRequest {
                instance: Hash32::ZERO,
                height,
                block_hash: Hash32::ZERO,
            }),
        }
    }

    /// The O2 table: which actions wait for a pending record.
    #[test]
    fn gated_versus_exempt() {
        let key = PublicKey::new(vec![1; 32]).unwrap();
        let exempt = [
            Action::DiscardExecution {
                height: 1,
                keep: Vec::new(),
            },
            Action::BuildPayload {
                req: 1,
                height: 1,
                view: 0,
                max_bytes: 1,
                exec_budget_ms: 1,
            },
            Action::RecoverProposalAdmission {
                req: 2,
                body: block(1, Hash32::ZERO, Hash32::ZERO, vec![1]),
            },
            Action::PayloadRejected {
                height: 1,
                view: 0,
                block_hash: Hash32::ZERO,
            },
            Action::LocalFault(LocalFault::RecordMissing),
        ];
        for action in &exempt {
            assert!(!gated(action), "{action:?}");
        }
        let effects = [
            send(1),
            Action::Broadcast {
                to: vec![key.clone()],
                msg: WireMessage::PayloadRequest(PayloadRequest {
                    instance: Hash32::ZERO,
                    height: 1,
                    block_hash: Hash32::ZERO,
                }),
            },
            Action::FetchPayload {
                source: super::super::tests::source(1, Hash32::ZERO),
                peers: Vec::new(),
            },
            Action::ServePayload {
                to: key.clone(),
                height: 1,
                block_hash: Hash32::ZERO,
            },
            Action::ServeBlocks {
                to: key,
                from_height: 1,
                max_count: 1,
                max_bytes: 1,
            },
            Action::Halt(HaltReason::DriverAnomaly),
        ];
        for action in &effects {
            assert!(gated(action), "{action:?}");
        }
    }

    /// Held effects leave in emission order, each once its record is durable; exempt actions
    /// never wait; without a pending record nothing is held.
    #[test]
    fn hold_and_release_in_order() {
        let mut barrier = Barrier::default();
        assert_eq!(barrier.admit(send(1)), Some(send(1)), "no pending record");
        barrier.persisting(3);
        assert_eq!(barrier.admit(send(2)), None);
        assert_eq!(barrier.admit(send(3)), None);
        let fault = Action::LocalFault(LocalFault::RecordMissing);
        assert_eq!(barrier.admit(fault.clone()), Some(fault), "exempt");
        barrier.persisting(5);
        assert_eq!(barrier.admit(send(4)), None);
        assert_eq!(barrier.held().count(), 3);
        assert!(barrier.release(2).is_empty(), "record 3 is not durable yet");
        assert_eq!(barrier.release(4), vec![send(2), send(3)]);
        assert_eq!(barrier.admit(send(5)), None, "record 5 still pending");
        assert_eq!(barrier.release(5), vec![send(4), send(5)]);
        assert_eq!(barrier.admit(send(6)), Some(send(6)));
        assert_eq!(barrier.held().count(), 0);
    }

    fn fetch(tag: u8, peer: u8) -> Action {
        Action::FetchPayload {
            source: super::super::tests::source(1, Hash32([tag; 32])),
            peers: vec![PublicKey::new(vec![peer; 32]).unwrap()],
        }
    }

    /// Under a record that stays pending, the held effects stay within their limits: the
    /// oldest network messages go first, `CommitBlock`, evidence and `Halt` are never dropped,
    /// and a newer fetch of a body replaces the held one.
    #[test]
    fn held_effects_are_bounded() {
        let b1 = block(1, Hash32::ZERO, Hash32::ZERO, vec![0; 1_000]);
        // Retained original payload and signed table both count, together with the
        // bounded control witness allowance. Two bodies fit; three must not.
        let retained_bytes = b1.payload().as_slice().len() as u64
            + b1.availability().as_slice().len() as u64
            + iroha_sumeragi::types::MAX_CONTROL_WITNESS_BYTES as u64;
        let limits = HeldLimits {
            effects: 4,
            payload_bytes: 2 * retained_bytes + 500,
        };
        let mut barrier = Barrier::new(limits);
        barrier.persisting(1);
        let commit = Action::CommitBlock {
            block: b1.clone(),
            commit_qc: commit_qc(&b1, Hash32::ZERO),
        };
        let halt = Action::Halt(HaltReason::DriverAnomaly);
        assert_eq!(barrier.admit(commit.clone()), None);
        for h in 0..100 {
            assert_eq!(barrier.admit(send(h)), None);
        }
        assert_eq!(barrier.admit(fetch(7, 1)), None);
        assert_eq!(barrier.admit(fetch(7, 2)), None);
        assert_eq!(barrier.admit(halt.clone()), None);
        assert_eq!(barrier.size(), (4, retained_bytes));
        assert_eq!(
            barrier.held().cloned().collect::<Vec<_>>(),
            vec![commit.clone(), send(99), fetch(7, 2), halt.clone()]
        );
        assert_eq!(barrier.dropped(), 99);
        assert_eq!(barrier.release(1).len(), 4);
        assert_eq!(barrier.size(), (0, 0));
        // Payload bytes: a response of a large block makes the older one go.
        let mut barrier = Barrier::new(HeldLimits {
            effects: 100,
            payload_bytes: 2 * retained_bytes + 500,
        });
        barrier.persisting(1);
        let response = |h: u64| Action::DisseminatePayload {
            peers: vec![PublicKey::new(vec![1; 32]).unwrap()],
            body: block(h, Hash32::ZERO, Hash32::ZERO, vec![0; 1_000]),
        };
        barrier.admit(commit.clone());
        barrier.admit(response(2));
        barrier.admit(response(3));
        assert_eq!(barrier.size(), (2, 2 * retained_bytes));
        assert_eq!(
            barrier.held().cloned().collect::<Vec<_>>(),
            vec![commit, response(3)]
        );
    }

    /// A superseded record: everything emitted after it waits for the newer record, even what
    /// waited for a later record of another key; earlier effects keep their record.
    #[test]
    fn superseded_record_moves_its_waiters() {
        let mut barrier = Barrier::default();
        barrier.persisting(1);
        barrier.admit(send(1));
        barrier.persisting(3);
        barrier.admit(send(2));
        barrier.persisting(4);
        barrier.admit(send(3));
        barrier.superseded(3, 6);
        barrier.persisting(6);
        barrier.admit(send(4));
        assert_eq!(barrier.release(1), vec![send(1)]);
        assert!(barrier.release(5).is_empty(), "record 3 moved to 6");
        assert_eq!(barrier.release(6), vec![send(2), send(3), send(4)]);
        assert_eq!(barrier.admit(send(5)), Some(send(5)));
        // A failed record superseded by an older queued one than the latest pending record.
        barrier.persisting(7);
        barrier.admit(send(6));
        barrier.persisting(9);
        barrier.admit(send(7));
        barrier.superseded(7, 8);
        assert!(barrier.release(7).is_empty());
        assert_eq!(barrier.release(8), vec![send(6)]);
        assert_eq!(barrier.admit(send(8)), None, "record 9 still pending");
        assert_eq!(barrier.release(9), vec![send(7), send(8)]);
    }
}
