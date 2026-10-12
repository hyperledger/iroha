//! Regression tests for core issues found by the deterministic simulator (`crate::sim`); each
//! names the scenario and seed that exposed it.

use super::manifest;
use super::{G_HASH, G_RESULT, H, I, pick, result_of};
use crate::preimage;
use crate::{
    api::{Action, Event, HaltReason},
    crypto::Signer,
    message::{Status, SyncEntry, SyncResponse, VoteKind, WireMessage},
    safety::RecordState,
    types::Hash32,
};

fn status(height: u64, committed_qc: Option<crate::message::Qc>) -> WireMessage {
    WireMessage::Status(Box::new(Status {
        instance: I,
        height,
        committed_qc,
        ..Status::default()
    }))
}

/// F3 seed 12 (withholding proxy tail): a peer's periodic `Status` (old `CommitQC`) is followed
/// within the per-peer rate limit by its reply carrying the `CommitQC` of the current height.
/// The reply must still commit the height; other rate-limited content stays dropped.
#[test]
fn rate_limited_status_still_delivers_a_fresh_commit_qc() {
    let mut h = H::new(4, pick::set_a(0));
    h.commit_heights(1);
    let peer = h.others(1, &[])[0];
    let height = h.height();
    let parent = h.core.tip.commit_qc.clone();
    // The periodic Status of the peer, still at our height.
    h.deliver(peer, status(height, parent.clone()));
    // 3 ms later its reply: it committed our height meanwhile.
    h.now += 3;
    let block = h.block(0, b"B");
    h.bodies.insert(h.bh(&block), block.clone());
    let cqc = h.qc_q(VoteKind::Commit, 0, &block);
    let out = h.deliver(peer, status(height + 1, Some(cqc)));
    assert_eq!(
        h.core.tip.height, height,
        "committed from the rate-limited Status"
    );
    assert!(
        out.iter()
            .any(|a| matches!(a, Action::DiscardExecution { .. })),
        "commit path ran"
    );
    // The same (no longer fresh) content within the window is dropped again.
    h.now += 3;
    let before = h.core.tip.height;
    let out = h.deliver(peer, status(height + 1, parent));
    assert!(out.is_empty());
    assert_eq!(h.core.tip.height, before);
}

/// F24 with a forged record parent (the R4 case): a checksum-valid record whose parent
/// `CommitQC` contradicts the block-store tip halts the instance instead of re-sending the
/// recorded proposal with that parent (which would be a second proposal for the round).
#[test]
fn resume_rejects_a_record_inconsistent_with_the_store() {
    let mut h = H::new(4, pick::leader(0));
    h.commit_heights(2);
    let height = h.height();
    // Time out at the current height: a record with the parent CommitQC becomes durable.
    let until = h.now + 30_000;
    h.run_until(until);
    assert!(h.core.status().halted.is_none());
    let mut record = h.durable().expect("a durable record");
    assert_eq!(record.height, height);
    // Forge the parent CommitQC (same shape, another block) and re-encode with a valid
    // checksum.
    let mut forged = record.parent_commit_qc.clone().expect("parent CommitQC");
    forged.block_hash = Hash32([0x66; 32]);
    record.parent_commit_qc = Some(forged);
    let bytes = record.encode(&h.v.crypto).unwrap();
    let key = h.signers[0].public_key().clone();
    let out = h.start(vec![(key.clone(), RecordState::Present(bytes))]);
    assert!(
        out.contains(&Action::Halt(HaltReason::SafetyRecordInconsistent)),
        "{out:?}"
    );
    assert!(
        !out.iter()
            .any(|a| matches!(a, Action::Broadcast { .. } | Action::Send { .. })),
        "nothing is sent"
    );
    // The unmodified record resumes normally.
    let good = h.records.get(&key).cloned().unwrap();
    let out = h.start(vec![(key, RecordState::Present(good))]);
    assert!(!out.iter().any(|a| matches!(a, Action::Halt(_))));
}

/// The `from_height` of the core's outstanding `SyncRequest`, if any.
fn sync_from(actions: &[Action]) -> Option<u64> {
    actions.iter().rev().find_map(|a| match a {
        Action::Send {
            msg: WireMessage::SyncRequest(r),
            ..
        } => Some(r.from_height),
        _ => None,
    })
}

/// F17 seed 106 (Byzantine sync responder): an entry with a forged `CommitQC` (rewritten
/// result, well-formed) is dropped at its turn after the request for the following range went
/// out; the honest answer to that request lands above the gap. Catch-up must request the gap
/// again instead of stopping.
#[test]
fn sync_refetches_a_gap_left_by_a_dropped_forged_prefix() {
    let mut h = H::new(4, pick::set_a(0));
    h.auto_apply = false;
    let mut chain = Vec::new();
    let mut parent = (G_HASH, G_RESULT);
    for height in 1..=6u64 {
        let block = h.block_at(height, parent, 0, &height.to_be_bytes());
        let qc = h.cqc_for(&block, 0);
        parent = (h.bh(&block), result_of(&block));
        chain.push(SyncEntry {
            manifest: manifest(&block),
            commit_qc: qc,
        });
    }
    let source = h.others(1, &[])[0];
    // A member reports CommitQC(6): a hint (C_6 is unknown); a request from height 1.
    let out = h.deliver(source, WireMessage::Qc(chain[5].commit_qc.clone()));
    assert_eq!(sync_from(&out), Some(1));
    // The answer: valid 1, 2 and forged 3, 4 (well formed, invalid certificates).
    let mut entries = chain[..2].to_vec();
    for entry in &chain[2..4] {
        let mut forged = entry.clone();
        forged.commit_qc.result = Hash32([0x31; 32]);
        entries.push(forged);
    }
    let response = |blocks: Vec<SyncEntry>| {
        WireMessage::SyncResponse(SyncResponse {
            instance: I,
            blocks,
        })
    };
    let out = h.deliver(source, response(entries));
    assert_eq!(
        h.core.tip.height, 2,
        "1 and 2 committed; 3 needs C_3 (apply of 1)"
    );
    assert_eq!(sync_from(&out), Some(5), "the next range is requested");
    // Apply of 1 makes C_3 known: the forged entry 3 fails at its turn and is dropped.
    h.apply_height(1);
    assert_eq!(h.core.tip.height, 2);
    // The honest answer for 5, 6 arrives: the gap 3, 4 must be requested again.
    let out = h.deliver(source, response(chain[4..].to_vec()));
    assert_eq!(sync_from(&out), Some(3), "the gap is requested again");
    h.auto_apply = true;
    h.apply_height(2);
    h.deliver(source, response(chain[2..].to_vec()));
    assert_eq!(h.core.tip.height, 6, "catch-up completes");
}

/// F2 seed 115: the driver answers the view-0 build `EMPTY` and a transaction arrives right
/// after, so its `PayloadReady{req}` reaches the core before the `EMPTY` answer. The leader must
/// build again at once instead of idling until `payload_retry_interval` (members would time the
/// view out and record the honest leader as skipped).
#[test]
fn payload_ready_during_an_outstanding_build_ends_the_idle_wait() {
    let mut h = H::new(4, pick::leader(0));
    let built = |actions: &[Action]| {
        actions.iter().any(|a| {
            matches!(
                a,
                Action::BuildPayload {
                    height: 1,
                    view: 0,
                    ..
                }
            )
        })
    };
    // The build is requested at `t_enter + pace` (1 s) and times out 200 ms later.
    let all = h.run_until(h.now + 1_100);
    assert!(built(&all), "the view-0 build is requested");
    h.payload_ready();
    let out = h.built(b"");
    assert!(
        built(&out),
        "an empty answer after PayloadReady is requested again at once"
    );
    let out = h.built(b"tx");
    assert!(
        out.iter().any(|a| matches!(
            a,
            Action::Broadcast {
                msg: WireMessage::Proposal(p),
                ..
            } if p.proposal.header.payload_hash == preimage::payload_hash(&h.v.crypto, b"tx")
        )),
        "the transaction is proposed"
    );
    // Without a PayloadReady, an empty answer still waits for real work.
    let mut h = H::new(4, pick::leader(0));
    h.run_until(h.now + 1_100);
    let out = h.built(b"");
    assert!(!built(&out) && !out.iter().any(|a| matches!(a, Action::Broadcast { .. })));
    // A PayloadReady of another request id changes nothing.
    let other = h.last_build.unwrap() + 7;
    let out = h.fire(Event::PayloadReady { req: other });
    assert!(out.is_empty());
}

/// F3 seed 4 (a withholding proxy tail delivering its certificates to half of the members):
/// the `PrepareQC` reached one honest member only; at stage 2 that member no longer re-sends its
/// Prepare (its phase QC is held), so the others cannot assemble `q` Prepares. A node at
/// stage 2 is unsettled: its `Status`, which carries its lock, goes out every
/// `rebroadcast_interval` instead of every `status_keepalive`.
#[test]
fn stage_two_makes_a_node_unsettled() {
    let mut h = H::new(4, pick::at(2, 0, 1));
    h.commit_with(0, b"1");
    assert!(!h.core.late_entry, "entered from a Qc message: settled");
    h.run_until(h.now + 1);
    let b = h.block(0, b"B");
    let p = h.proposal(0, &b, None);
    h.deliver(h.leader(0), WireMessage::Proposal(Box::new(p)));
    h.exec_all();
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    h.deliver(h.others(1, &[])[0], WireMessage::Qc(pqc.clone()));
    assert!(h.core.mine.commit.is_some());
    let last = h.core.last_status.unwrap();
    let keepalive = |h: &H| {
        h.core
            .deadlines()
            .into_iter()
            .find_map(|(n, at)| (n == "status").then_some(at).flatten())
    };
    assert_eq!(keepalive(&h), Some(last + h.local.status_keepalive));
    // The CommitQC never comes: stage 2 at t_lastvote + 2·t_retx.
    let stage2 = h.core.stage2_deadline().unwrap();
    h.run_until(stage2);
    assert_eq!(h.core.stage, 2);
    let out = h.run_until(h.now + h.local.rebroadcast_interval);
    let carried = out.iter().any(|a| {
        matches!(a, Action::Broadcast { msg: WireMessage::Status(s), .. } if s.high_pqc == Some(pqc.clone()))
    });
    assert!(carried, "the lock goes out at the unsettled cadence");
}

/// F24 seed 10 (record and Kura tail lost): the echoes of all members were recorded while the
/// node was far behind (heights above `t' + 1`); later replies report higher heights and never
/// lower an entry, and at a height entry `C_{t'+2}` is not known yet. Anchoring must be checked
/// when `BlockApplied` makes `C_{tip.height+2}` known.
#[test]
fn anchoring_is_checked_when_the_next_configuration_is_known() {
    use crate::message::Echo;
    let mut h = H::new(4, pick::set_a(0));
    h.records.clear();
    let key = h.signers[0].public_key().clone();
    h.start(vec![(key, RecordState::Absent)]);
    for o in h.others(3, &[]) {
        let k = h.key_at(o);
        let sig = h.signer_of(&k).sign(&crate::preimage::echo_preimage(
            &I,
            &crate::testing::TEST_EPOCH.id,
            h.nonce,
            3,
        )).expect("fixture signing succeeds");
        let msg = WireMessage::Status(Box::new(Status {
            instance: I,
            height: 3,
            echo: Some(Echo {
                epoch: crate::testing::TEST_EPOCH.id,
                nonce: h.nonce,
                key: k,
                sig,
            }),
            ..Status::default()
        }));
        h.deliver(o, msg);
    }
    assert_eq!(h.core.probe.len(), 3);
    assert!(h.core.status().unanchored, "3 > t' + 1 = 1");
    h.commit_with(0, b"1");
    assert!(h.core.status().unanchored, "3 > t' + 1 = 2");
    h.commit_with(0, b"2");
    // BlockApplied(2) makes C_4 known: 3 ≤ t' + 1 = 3 for all three.
    assert!(!h.core.status().unanchored);
    assert_eq!(h.core.keys[0].abstain_below, 5);
}
