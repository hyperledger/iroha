//! Named deterministic safety tests (§13.4, MS1–MS38), one core driven by scripted inputs.
//!
//! Role layout used throughout (n = 4, height 1, no demotion): `order_{1,0} = [L0, a, P0, b]`,
//! `L(1,1) = a`, `order_{1,1} = [a, P0, b, L0]`, `L(1,2) = P0`, `order_{1,2} = [P0, b, L0, a]`.

use super::*;
use crate::{
    message::{Defect, Echo, Status, SyncEntry, SyncResponse},
    preimage::{KIND_COMMIT, KIND_PREPARE, KIND_PROPOSAL, KIND_TIMEOUT},
    types::{AggregateSignature, SIGNATURE_LEN},
};

fn prop(h: &mut H, view: u64, block: &AvailableBody, justify: Option<TimeoutCert>) -> Vec<Action> {
    let p = h.proposal(view, block, justify);
    h.deliver(h.leader(view), WireMessage::Proposal(Box::new(p)))
}

fn qc_msg(h: &mut H, qc: Qc) -> Vec<Action> {
    let from = h.others(1, &[])[0];
    h.deliver(from, WireMessage::Qc(qc))
}

/// Run to the current view's deadline (the core times out).
fn time_out(h: &mut H) -> Vec<Action> {
    let deadline = h.core.view_deadline().expect("a view deadline");
    h.run_until(deadline)
}

fn is_persist(a: &Action) -> bool {
    matches!(a, Action::PersistSafety(_))
}

/// Actions that would leave the node under O2 if no record of this list became durable
/// (everything before the first `PersistSafety`) and could carry the node's signature: signed
/// messages, certificates, committed or served blocks, evidence.
fn released_without_durability(actions: &[Action]) -> Vec<Action> {
    actions
        .iter()
        .take_while(|a| !is_persist(a))
        .filter(|a| match a {
            Action::Send { msg, .. } | Action::Broadcast { msg, .. } => !matches!(
                msg,
                WireMessage::Status(_)
                    | WireMessage::SyncRequest(_)
                    | WireMessage::PayloadRequest(_)
            ),
            Action::CommitBlock { .. }
            | Action::ServeBlocks { .. }
            | Action::ServePayload { .. }
            | Action::ReportEvidence(_) => true,
            _ => false,
        })
        .cloned()
        .collect()
}

// ---- SR1, SR29: proposals ------------------------------------------------------------------

#[test]
fn det_s1_leader_restart_no_second_proposal() {
    let mut h = H::new(4, pick::leader(0));
    let out = h.run_until(1_000);
    assert!(out.iter().any(|a| matches!(
        a,
        Action::BuildPayload {
            height: 1,
            view: 0,
            ..
        }
    )));
    let out = h.built(b"B");
    let sent_b = proposals(&out);
    assert_eq!(sent_b.len(), 1);
    let bh_b = sent_b[0].block_hash(&h.v.crypto);
    // Crash before the broadcast left: the record and the stored body survive.
    let out = h.restart();
    assert!(!out.iter().any(|a| matches!(a, Action::BuildPayload { .. })));
    let resent = proposals(&out);
    assert_eq!(resent.len(), 1, "the recorded proposal is re-sent");
    assert_eq!(resent[0].block_hash(&h.v.crypto), bh_b);
    assert_eq!(
        h.bodies[&resent[0].block_hash(&h.v.crypto)]
            .payload()
            .as_slice(),
        &b"B"[..]
    );
    // The builder now returns C: nothing else is ever proposed at (1, 0).
    for _ in 0..100 {
        let out = h.tick(100);
        if out
            .iter()
            .any(|a| matches!(a, Action::BuildPayload { view: 0, .. }))
        {
            h.built(b"C");
        }
    }
    assert!(
        proposals(&h.all)
            .iter()
            .all(|p| p.view != 0 || p.block_hash(&h.v.crypto) == bh_b)
    );
    assert_eq!(h.my_sigs(KIND_PROPOSAL, 1, 0).len(), 1);
}

#[test]
fn det_s1_leader_restart_without_body_stays_silent() {
    let mut h = H::new(4, pick::leader(0));
    h.run_until(1_000);
    h.built(b"B");
    h.bodies.clear();
    h.restart();
    for _ in 0..100 {
        let out = h.tick(100);
        assert!(
            !out.iter()
                .any(|a| matches!(a, Action::BuildPayload { view: 0, .. }))
        );
    }
    assert!(proposals(&h.all).is_empty());
    assert_eq!(h.my_sigs(KIND_PROPOSAL, 1, 0).len(), 1);
}

#[test]
fn det_s29_forget_proposal() {
    let mut h = H::new(4, pick::leader(0));
    h.run_until(1_000);
    let out = h.built(b"B");
    let bh = proposals(&out)[0].block_hash(&h.v.crypto);
    // The record written before the broadcast holds (view, bh, justify).
    let record_at = out
        .iter()
        .position(|a| {
            matches!(a, Action::PersistSafety(r)
                if r.proposal.as_ref().is_some_and(|p| p.view == 0 && p.block_hash == bh && p.justify.is_none()))
        })
        .expect("the proposal is recorded");
    let send_at = out
        .iter()
        .position(|a| {
            matches!(
                a,
                Action::Broadcast {
                    msg: WireMessage::Proposal(_),
                    ..
                }
            )
        })
        .unwrap();
    assert!(record_at < send_at);
    h.restart();
    let restored = h.core.safety.as_ref().and_then(|r| r.proposal.clone());
    assert_eq!(restored.map(|p| (p.view, p.block_hash)), Some((0, bh)));
    assert_eq!(h.core.build, super::super::Build::Idle);
}

// ---- SR2, SR3, SR27: Prepare -----------------------------------------------------------------

/// In-process twins: the held proposal is the only one executed and the only one ever
/// Prepared (§6.2 step 2); the twin also ends the view (early timeout), so the held proposal is
/// Prepared only if its execution finished before the twin arrived.
#[test]
fn twin_proposals_one_prepare_in_process() {
    for (reversed, executed_first) in [(false, false), (true, false), (false, true)] {
        let mut h = H::new(4, pick::set_a(0));
        let b = h.block(0, b"B");
        let b2 = h.block(0, b"B2");
        let (first, second) = if reversed { (&b2, &b) } else { (&b, &b2) };
        prop(&mut h, 0, first, None);
        if executed_first {
            h.exec_all();
        }
        let out = prop(&mut h, 0, second, None);
        assert!(
            matches!(evidence(&out)[..], [Evidence::ProposalEquivocation(..)]),
            "{out:#?}"
        );
        assert_eq!(timeouts(&out).len(), 1, "early timeout");
        assert_eq!(
            h.pending_exec.len(),
            usize::from(!executed_first),
            "only the held proposal is executed"
        );
        h.exec_all();
        let prepares = votes_of(&h.all, VoteKind::Prepare);
        assert_eq!(prepares.len(), usize::from(executed_first));
        assert!(prepares.iter().all(|p| p.block_hash == h.bh(first)));
        assert_eq!(
            h.my_sigs(KIND_PREPARE, 1, 0).len(),
            usize::from(executed_first)
        );
    }
}

/// MS2 and MS27: harness-signed twins B, B′ of `L(h, v)`; X Prepares B and its record becomes
/// durable; X crashes and restarts with the record intact (R4); B′ is delivered and executes
/// `Valid` → no Prepare for B′. In-process the mutations are masked by §6.2 step 2 (only the
/// first twin is ever held), hence the restart.
#[test]
fn det_s2_s27_prepare_once_across_restart() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    let b2 = h.block(0, b"B2");
    prop(&mut h, 0, &b, None);
    h.exec_all();
    assert_eq!(h.my_sigs(KIND_PREPARE, 1, 0).len(), 1);
    let recorded = h.durable().and_then(|r| r.prepare);
    assert_eq!(
        recorded.map(|v| (v.view, v.block_hash)),
        Some((0, h.bh(&b))),
        "the Prepare is recorded (SR27)"
    );
    let out = h.restart();
    assert!(
        votes(&out).is_empty(),
        "votes are re-sent on the retransmit schedule"
    );
    let out = h.tick(h.core.pm.t_retx(0));
    assert_eq!(
        votes_of(&out, VoteKind::Prepare),
        votes_of(&h.all, VoteKind::Prepare)[..1].to_vec(),
        "the recorded Prepare is re-sent unchanged"
    );
    let out = prop(&mut h, 0, &b2, None);
    assert_eq!(executes(&out).len(), 1, "B′ is accepted after the restart");
    h.exec_all();
    assert_eq!(
        h.my_sigs(KIND_PREPARE, 1, 0).len(),
        1,
        "no Prepare for the twin (SR2)"
    );
    assert!(
        votes_of(&h.all, VoteKind::Prepare)
            .iter()
            .all(|v| v.block_hash == h.bh(&b))
    );
}

/// MS3: X accepts proposal(B, v) with `Execute{B, r1}` pending; `TC(v)` with
/// `high_pqc = PQC(B, v)` keeps B's execution entry across the view change; the answer to
/// `r1` arrives in `v + 1` → no Prepare until a proposal of `v + 1` is accepted, then exactly
/// one Prepare `(h, v + 1, B, R)`.
#[test]
fn det_s3_no_prepare_for_old_view_proposal() {
    // P0 is set A of (1, 1) and not its leader.
    let mut h = H::new(4, pick::proxy_tail(0));
    assert!(h.round(1).in_set_a(h.my_idx()) && h.leader(1) != h.my_idx());
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    let (bh, r1, _) = h.pending_exec.pop().expect("Execute r1");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    let o = h.others(3, &[]);
    let tc = h.tc(0, &[(o[0], Some(pqc.clone())), (o[1], None), (o[2], None)]);
    let out = h.deliver(o[1], WireMessage::Tc(Box::new(tc.clone())));
    assert_eq!(h.core.view, 1);
    assert!(
        out.iter().any(
            |a| matches!(a, Action::DiscardExecution { height: 1, keep } if keep.contains(&bh))
        ),
        "B's execution survives the discard"
    );
    let out = h.fire(Event::Executed {
        block_hash: bh,
        req: r1,
        outcome: ExecOutcome::Valid(result_of(&b)),
    });
    assert!(
        votes(&out).is_empty(),
        "no Prepare for the old view's proposal"
    );
    assert!(h.my_sigs(KIND_PREPARE, 1, 0).is_empty());
    assert!(h.my_sigs(KIND_PREPARE, 1, 1).is_empty());
    // The re-proposal of B in view 1: exactly one Prepare (h, 1, B, R), from the kept result.
    let out = prop(&mut h, 1, &b, Some(tc));
    assert!(executes(&out).is_empty(), "the kept result is reused");
    let prepares = votes_of(&out, VoteKind::Prepare);
    assert_eq!(prepares.len(), 1);
    assert_eq!(
        (prepares[0].view, prepares[0].block_hash, prepares[0].result),
        (1, bh, pqc.result)
    );
    assert_eq!(h.my_sigs(KIND_PREPARE, 1, 1).len(), 1);
}

#[test]
fn det_s23_crash_between_persist_and_durable() {
    let mut h = H::new(4, pick::set_a(0));
    let durable_before = h.records.clone();
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    let out = h.exec_all();
    let persist = out.iter().position(is_persist).expect("persist");
    let send = out
        .iter()
        .position(|a| {
            matches!(
                a,
                Action::Send {
                    msg: WireMessage::Vote(_),
                    ..
                }
            )
        })
        .expect("vote");
    assert!(
        persist < send,
        "the record precedes the vote (O2 holds the vote)"
    );
    // Crash before the record was durable: the held vote never left and the record is lost.
    assert!(votes(&released_without_durability(&out)).is_empty());
    h.records = durable_before;
    h.restart();
    let b2 = h.block(0, b"B2");
    prop(&mut h, 0, &b2, None);
    let out = h.exec_all();
    let prepares = votes_of(&out, VoteKind::Prepare);
    assert_eq!(prepares.len(), 1);
    assert_eq!(prepares[0].block_hash, h.bh(&b2));
    // O-PBS: the durable record now covers the only Prepare that left the node.
    let record = h.durable().unwrap();
    assert_eq!(record.prepare.map(|v| v.block_hash), Some(h.bh(&b2)));
}

// ---- SR4, SR5, SR25, SR26: fence and Commit ---------------------------------------------------

#[test]
fn det_s4_fence_across_restart() {
    let mut h = H::new(4, pick::set_a(0));
    let out = time_out(&mut h);
    assert_eq!(timeouts(&out).len(), 1);
    assert_eq!(h.durable().unwrap().timeout.map(|t| t.view), Some(0));
    h.restart();
    assert_eq!(h.core.timeout_view, Some(0));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    h.exec_all();
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    qc_msg(&mut h, pqc);
    for _ in 0..20 {
        h.tick(250);
    }
    assert!(h.my_sigs(KIND_PREPARE, 1, 0).is_empty());
    assert!(h.my_sigs(KIND_COMMIT, 1, 0).is_empty());
}

#[test]
fn det_s26_forget_timeout() {
    let mut h = H::new(4, pick::set_a(0));
    time_out(&mut h);
    let record = h.durable().unwrap();
    assert_eq!(
        record.timeout.as_ref().map(|t| (t.view, t.hq())),
        Some((0, None))
    );
    h.restart();
    assert_eq!(h.core.timeout_view, Some(0));
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    let out = qc_msg(&mut h, pqc);
    assert!(votes(&out).is_empty());
    assert!(h.my_sigs(KIND_COMMIT, 1, 0).is_empty());
}

/// MS5: X is in `(h, v + 1)` via `TC(v)` with no `PrepareQC` and no proposal of `v + 1`; a
/// `PrepareQC` of `v` raises the lock (§6.5 2e does not fire); stage 2 is then entered at
/// `anchor + φ·T` and runs `try_commit()` → no Commit (the lock is not of the current view).
#[test]
fn det_s5_no_commit_stale_qc() {
    let mut h = H::new(4, pick::proxy_tail(0));
    h.enter_view(1);
    assert_ne!(h.leader(1), h.my_idx());
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    let out = qc_msg(&mut h, pqc.clone());
    assert!(votes(&out).is_empty());
    assert_eq!(h.core.high_pqc, Some(pqc), "the lock still rises");
    let backstop = h.core.anchor() + h.core.pm.view_timeout(1) / 2;
    assert!(backstop < h.core.view_deadline().unwrap());
    h.run_until(backstop);
    assert_eq!(h.core.stage, 2, "stage entry ran try_commit()");
    assert!(h.core.timeout_view.is_none());
    assert!(h.my_sigs(KIND_COMMIT, 1, 0).is_empty());
    assert!(h.my_sigs(KIND_COMMIT, 1, 1).is_empty());
}

/// MS25: X Commits at `(h, v)`; the `CommitQC` reaches others only; X crashes before timing
/// out; after the restart its timeout carries `hq = v` (the lock is the record of the Commit).
#[test]
fn det_s25_lock_persisted_with_commit() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    let out = qc_msg(&mut h, pqc.clone());
    assert_eq!(votes_of(&out, VoteKind::Commit).len(), 1);
    let persist = out
        .iter()
        .position(|a| matches!(a, Action::PersistSafety(r) if r.lock == Some(pqc.clone())))
        .expect("the lock is written before the Commit");
    let vote = out
        .iter()
        .position(|a| {
            matches!(
                a,
                Action::Send {
                    msg: WireMessage::Vote(_),
                    ..
                }
            )
        })
        .unwrap();
    assert!(persist < vote);
    h.restart();
    let out = time_out(&mut h);
    let sent = timeouts(&out);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].hq(), Some(0), "the restored lock is carried");
}

// ---- SR7, SR8, SR9, SR30: lock and timeouts ---------------------------------------------------

/// MS7: X locks `PQC(B1, v1)`; W's timeout at `v1` carries the older `PQC(B0, v0)` (a nested
/// certificate: a top-level `Qc` would be cheap-rejected, §6.1 rule 5); X's timeout still
/// carries `hq = v1`.
#[test]
fn det_s7_lock_monotone() {
    let mut h = H::new(4, pick::set_b(0));
    let b0 = h.block(0, b"B0");
    let b1 = h.block(0, b"B1");
    let q1 = h.qc_q(VoteKind::Prepare, 2, &b1);
    qc_msg(&mut h, q1.clone());
    assert_eq!(h.core.view, 2);
    let q0 = h.qc_q(VoteKind::Prepare, 1, &b0);
    let w = h.others(1, &[])[0];
    let t = h.timeout(w, 2, Some(q0));
    h.deliver(w, WireMessage::Timeout(Box::new(t)));
    assert!(
        h.core.timeouts[usize::try_from(w).unwrap()].is_some(),
        "a timeout carrying an older PrepareQC is still stored"
    );
    assert_eq!(h.core.high_pqc, Some(q1));
    let out = time_out(&mut h);
    let sent = timeouts(&out);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].hq(), Some(2));
}

#[test]
fn det_s8_timeout_carries_lock() {
    let mut h = H::new(4, pick::set_b(0));
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    qc_msg(&mut h, pqc.clone());
    let out = time_out(&mut h);
    let sent = timeouts(&out);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].high_pqc, Some(pqc.clone()));
    let record = h.durable().unwrap();
    assert_eq!(record.timeout.and_then(|t| t.high_pqc), Some(pqc.clone()));
    assert_eq!(record.lock, Some(pqc));
}

#[test]
fn det_s9_timeout_resend_exact() {
    let mut h = H::new(4, pick::leader(0));
    h.enter_view(1);
    let out = time_out(&mut h);
    let first = timeouts(&out);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].hq(), None);
    // A PrepareQC of view 0 raises the lock after the timeout was signed.
    let b = h.block(0, b"B");
    {
        let qc = h.qc_q(VoteKind::Prepare, 0, &b);
        qc_msg(&mut h, qc)
    };
    assert_eq!(h.core.high_pqc.as_ref().map(|q| q.view), Some(0));
    let out = h.tick(h.local.rebroadcast_interval);
    let resent = timeouts(&out);
    assert_eq!(resent, first, "the stored timeout is re-sent unchanged");
    // TC formation uses the stored timeout as the own entry.
    let others = h.others(2, &[]);
    for o in &others {
        let t = h.timeout(*o, 1, None);
        h.deliver(*o, WireMessage::Timeout(Box::new(t)));
    }
    let tc = h.core.high_tc.clone().expect("TC formed");
    assert_eq!(tc.view, 1);
    let mine = tc
        .entries
        .iter()
        .find(|e| e.signer == h.my_idx())
        .expect("own entry");
    assert_eq!(mine.hq, None);
    assert_eq!(h.my_sigs(KIND_TIMEOUT, 1, 1).len(), 1);
}

#[test]
fn det_s30_lock_restored() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    qc_msg(&mut h, pqc.clone());
    h.restart();
    assert_eq!(h.core.high_pqc, Some(pqc));
    let out = time_out(&mut h);
    assert_eq!(timeouts(&out)[0].hq(), Some(0));
}

// ---- SR10, SR11, SR12: TC rule and TCs ---------------------------------------------------------

#[test]
fn det_s10a_tc_rule_forces_reproposal() {
    // Leader side: L(1,1) re-proposes the TC's highest PrepareQC block, from memory or the
    // local store.
    for body_in_memory in [true, false] {
        let mut h = H::new(4, pick::set_a(0));
        let b = h.block(0, b"B");
        if body_in_memory {
            prop(&mut h, 0, &b, None);
        } else {
            h.bodies.insert(h.bh(&b), b.clone());
        }
        let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
        let o = h.others(3, &[]);
        let tc = h.tc(0, &[(o[0], Some(pqc.clone())), (o[1], None), (o[2], None)]);
        h.deliver(o[1], WireMessage::Tc(Box::new(tc)));
        let sent = proposals(&h.all);
        assert_eq!(sent.len(), 1, "body in memory: {body_in_memory}");
        assert_eq!(sent[0].view, 1);
        assert_eq!(
            sent[0].header,
            b.header().clone(),
            "the block is re-proposed unchanged"
        );
        assert_eq!(
            sent[0].justify.as_ref().and_then(|tc| tc.high_pqc.clone()),
            Some(pqc)
        );
    }
    // Voter side: a fresh block against a TC naming Q is rejected.
    let mut h = H::new(4, pick::proxy_tail(0));
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    let o = h.others(3, &[]);
    let tc = h.tc(0, &[(o[0], Some(pqc)), (o[1], None), (o[2], None)]);
    let c = h.block(1, b"C");
    let out = prop(&mut h, 1, &c, Some(tc));
    assert!(matches!(
        &evidence(&out)[..],
        [Evidence::InvalidProposal {
            defect: Defect::TcRule,
            ..
        }]
    ));
    assert_eq!(timeouts(&out).len(), 1, "early timeout of the view");
    assert!(executes(&out).is_empty());
    assert!(h.my_sigs(KIND_PREPARE, 1, 1).is_empty());
}

#[test]
fn det_s10b_voter_rejects_tc_violation() {
    // n = 7: a set-A member of (1, 1) that is not its leader.
    let mut h = H::new(7, pick::at(1, 1, 2));
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    let o = h.others(5, &[]);
    let entries: Vec<_> = o
        .iter()
        .enumerate()
        .map(|(i, m)| (*m, (i == 0).then(|| pqc.clone())))
        .collect();
    let tc = h.tc(0, &entries);
    let other = h.block(0, b"B-other");
    // A re-proposal of a different block (a header-valid view-0 block of the same parent).
    let out = prop(&mut h, 1, &other, Some(tc));
    assert!(matches!(
        &evidence(&out)[..],
        [Evidence::InvalidProposal {
            defect: Defect::TcRule,
            ..
        }]
    ));
    assert!(h.my_sigs(KIND_PREPARE, 1, 1).is_empty());
}

#[test]
fn det_s11_tc_max_hq_core() {
    let mut h = H::new(4, pick::leader(0));
    h.enter_view(2);
    time_out(&mut h);
    let o = h.others(2, &[]);
    let b0 = h.block(0, b"B0");
    let b1 = h.block(0, b"B1");
    let q0 = h.qc_q(VoteKind::Prepare, 0, &b0);
    let q1 = h.qc_q(VoteKind::Prepare, 1, &b1);
    let t0 = h.timeout(o[0], 2, Some(q0));
    h.deliver(o[0], WireMessage::Timeout(Box::new(t0)));
    let t1 = h.timeout(o[1], 2, Some(q1.clone()));
    h.deliver(o[1], WireMessage::Timeout(Box::new(t1)));
    let tc = h.core.high_tc.clone().expect("TC formed");
    assert_eq!(tc.view, 2);
    let mut hqs: Vec<_> = tc.entries.iter().map(|e| e.hq).collect();
    hqs.sort();
    assert_eq!(hqs, vec![None, Some(0), Some(1)]);
    assert_eq!(tc.high_pqc, Some(q1));
    assert_eq!(h.core.view, 3);
}

#[test]
fn det_s12_tc_verify_rejects_low_high_pqc_core() {
    let mut h = H::new(4, pick::set_b(0));
    let o = h.others(3, &[]);
    let b0 = h.block(0, b"B0");
    let b1 = h.block(0, b"B1");
    let q0 = h.qc_q(VoteKind::Prepare, 0, &b0);
    let q1 = h.qc_q(VoteKind::Prepare, 1, &b1);
    let mut tc = h.tc(
        2,
        &[(o[0], Some(q1)), (o[1], Some(q0.clone())), (o[2], None)],
    );
    tc.high_pqc = Some(q0);
    h.deliver(o[0], WireMessage::Tc(Box::new(tc.clone())));
    assert_eq!(h.core.view, 0);
    assert!(h.core.high_tc.is_none());
    // As a proposal's justification it is a signed defect of the proposer.
    let c = h.block(3, b"C");
    let out = prop(&mut h, 3, &c, Some(tc));
    assert!(matches!(
        &evidence(&out)[..],
        [Evidence::InvalidProposal {
            defect: Defect::InvalidJustify,
            ..
        }]
    ));
    assert_eq!(h.core.view, 0);
}

// ---- SR13–SR17: certificates ------------------------------------------------------------------

#[test]
fn det_s13_quorum_n5_core() {
    let mut h = H::new(5, pick::set_a(0));
    let b = h.block(0, b"B");
    h.bodies.insert(h.bh(&b), b.clone());
    let three = h.others(3, &[]);
    {
        let qc = h.qc(VoteKind::Commit, 0, &b, &three);
        qc_msg(&mut h, qc)
    };
    assert_eq!(
        h.core.tip.height, 0,
        "2f + 1 = 3 signers are not a quorum at n = 5"
    );
    let four = h.others(4, &[]);
    {
        let qc = h.qc(VoteKind::Commit, 0, &b, &four);
        qc_msg(&mut h, qc)
    };
    assert_eq!(h.core.tip.height, 1);
}

#[test]
fn det_s14_qc_popcount_core() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    let two = h.others(2, &[]);
    {
        let qc = h.qc(VoteKind::Commit, 0, &b, &two);
        qc_msg(&mut h, qc)
    };
    {
        let qc = h.qc(VoteKind::Prepare, 0, &b, &two);
        qc_msg(&mut h, qc)
    };
    assert_eq!(h.core.tip.height, 0);
    assert!(h.core.high_pqc.is_none());
}

#[test]
fn det_s15_committee_of_height() {
    // Keys k0..k4; C_old = {k0..k3} below height 4, C_new = {k0, k1, k2, k4} from height 4.
    let mut h = H::new(5, |_| 0);
    let keys: Vec<PublicKey> = (0..5).map(|i| h.v.key(i)).collect();
    let old = Committee::new(keys[..4].to_vec()).unwrap();
    let new = Committee::new(vec![
        keys[0].clone(),
        keys[1].clone(),
        keys[2].clone(),
        keys[4].clone(),
    ])
    .unwrap();
    h.committees.insert(0, old.clone());
    h.committees.insert(4, new);
    h.restart();
    h.commit_heights(3);
    assert_eq!(h.height(), 4);
    let b = h.block(0, b"B4");
    h.bodies.insert(h.bh(&b), b.clone());
    let value = (h.bh(&b), result_of(&b));
    // Signed by q members of the old committee including the removed k3, old bitmap.
    let forged = h.qc_keys(&old, VoteKind::Commit, 4, 0, value, &keys[1..4]);
    h.deliver_key(keys[3].clone(), WireMessage::Qc(forged));
    assert_eq!(h.core.tip.height, 3, "certificates verify only under C_4");
    let genuine = h.cqc_for(&b, 0);
    h.deliver_key(keys[1].clone(), WireMessage::Qc(genuine));
    assert_eq!(h.core.tip.height, 4);
}

#[test]
fn det_s16_cross_instance_replay_core() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    h.bodies.insert(h.bh(&b), b.clone());
    // A certificate genuinely signed for another instance, relabelled with this instance.
    let other = Hash32([0x22; 32]);
    let value = (h.bh(&b), result_of(&b));
    let msg = preimage::vote_preimage(
        VoteKind::Commit,
        &other,
        &crate::testing::TEST_EPOCH.id,
        1,
        0,
        &value.0,
        &value.1,
    );
    let signers = h.others(3, &[]);
    let sigs: Vec<Signature> = signers
        .iter()
        .map(|i| h.signer_of(&h.key_at(*i)).sign(&msg))
        .collect();
    let mut qc = h.qc(VoteKind::Commit, 0, &b, &signers);
    qc.agg_sig = h.v.crypto.aggregate(&sigs);
    qc_msg(&mut h, qc.clone());
    assert_eq!(h.core.tip.height, 0);
    // The unmodified foreign certificate is dropped at intake.
    qc.instance = other;
    qc_msg(&mut h, qc);
    assert_eq!(h.core.tip.height, 0);
}

#[test]
fn det_s17_result_bound_core() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    h.bodies.insert(h.bh(&b), b.clone());
    let mut qc = h.qc_q(VoteKind::Commit, 0, &b);
    qc.result = Hash32([0x99; 32]);
    qc_msg(&mut h, qc);
    assert_eq!(h.core.tip.height, 0, "a rewritten result does not verify");
    // Votes for different results never aggregate together.
    let mut h = H::new(4, pick::proxy_tail(0));
    let b = h.block(0, b"B");
    let o = h.others(3, &[]);
    for (i, signer) in o.iter().enumerate() {
        let result = if i == 0 {
            result_of(&b)
        } else {
            Hash32([u8::try_from(i).unwrap(); 32])
        };
        let vote = h.vote_value(VoteKind::Prepare, *signer, 0, (h.bh(&b), result));
        h.deliver(*signer, WireMessage::Vote(vote));
    }
    assert!(h.core.high_pqc.is_none());
}

// ---- SR18, SR19, SR20, SR35: proposals and bodies ---------------------------------------------

#[test]
fn det_s18_non_leader_proposal_dropped() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    let intruder = h.proxy_tail(0);
    let p = h.proposal_by(intruder, 0, &b, None);
    let out = h.deliver(intruder, WireMessage::Proposal(Box::new(p)));
    assert!(out.is_empty(), "{out:#?}");
    assert!(h.core.proposal.is_none());
    // The genuine leader's proposal is then accepted normally.
    let out = prop(&mut h, 0, &b, None);
    assert!(evidence(&out).is_empty());
    assert_eq!(executes(&out).len(), 1);
}

#[test]
fn det_s19_wrong_parent_rejected() {
    let mut h = H::new(4, pick::at(2, 0, 1));
    h.commit_heights(1);
    assert_eq!(h.height(), 2);
    assert!(h.round(0).in_set_a(h.my_idx()));
    let stale = h.block(0, b"B");
    let mut header = stale.header().clone();
    header.parent_hash = G_HASH;
    header.parent_result = G_RESULT;
    let stale = h.author(header, stale.payload().as_slice());
    let out = prop(&mut h, 0, &stale, None);
    assert!(matches!(
        &evidence(&out)[..],
        [Evidence::InvalidProposal {
            defect: Defect::ParentHash,
            ..
        }]
    ));
    assert_eq!(timeouts(&out).len(), 1);
    assert!(executes(&out).is_empty());
    // A parent_qc for another value of the parent height is a defect as well.
    let mut h = H::new(4, pick::at(2, 0, 1));
    h.commit_heights(1);
    let b = h.block(0, b"B");
    let mut p = h.proposal(0, &b, None);
    let fake_parent = h.block_at(1, (G_HASH, G_RESULT), 0, b"other");
    p.proposal.parent_qc = Some(h.cqc_for(&fake_parent, 0));
    let leader = h.leader(0);
    let bh = h.bh(&b);
    let ad = preimage::att_digest(&h.v.crypto, None, p.proposal.parent_qc.as_ref());
    p.proposal.sig = h
        .signer_of(&h.key_at(leader))
        .sign(&preimage::prop_preimage(
            &I,
            &crate::testing::TEST_EPOCH.id,
            2,
            0,
            &bh,
            &ad,
        ));
    let out = h.deliver(leader, WireMessage::Proposal(Box::new(p)));
    assert!(matches!(
        &evidence(&out)[..],
        [Evidence::InvalidProposal {
            defect: Defect::InvalidParentQc,
            ..
        }]
    ));
    assert!(h.my_sigs(KIND_PREPARE, 2, 0).is_empty());
}

#[test]
#[allow(clippy::many_single_char_names)] // W and the others as in the spec
fn det_s20_forged_body_under_real_header() {
    let mut h = H::new(4, pick::proxy_tail(0));
    h.auto_fetch = false;
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    let o = h.others(3, &[]);
    let tc = h.tc(0, &[(o[0], Some(pqc.clone())), (o[1], None), (o[2], None)]);
    let p = h.proposal(1, &b, Some(tc));
    h.withheld_rows.insert(h.bh(&b));
    let out = h.deliver(h.leader(1), WireMessage::Proposal(Box::new(p)));
    assert!(out.iter().any(
        |a| matches!(a, Action::FetchPayload { source, .. } if source.block_hash() == h.bh(&b))
    ));
    let mut forged = h.chunks(&b)[0].clone();
    let mut bytes = forged.bytes.as_slice().to_vec();
    bytes[0] ^= 1;
    forged.bytes = RowBytes::from_untrusted(bytes).unwrap();
    let w = o[2];
    let out = h.deliver(w, WireMessage::PayloadChunk(forged));
    assert!(evidence(&out).is_empty() && timeouts(&out).is_empty());
    assert!(
        h.pending_exec.is_empty(),
        "forged relay rows cannot construct an AvailableBody"
    );
    let out = h.deliver_rows(o[1], &b);
    assert!(out.iter().any(|a| matches!(a, Action::StoreBody { .. })));
    assert_eq!(h.pending_exec.len(), 1);
    let out = h.exec_all();
    let prepares = votes_of(&out, VoteKind::Prepare);
    assert_eq!(prepares.len(), 1);
    assert_eq!((prepares[0].view, prepares[0].result), (1, pqc.result));
}

#[test]
fn det_s35_relay_tamper_no_evidence() {
    let mut h = H::new(4, pick::set_a(0));
    h.auto_fetch = false;
    let b = h.block(0, b"B");
    let genuine = h.proposal(0, &b, None);
    let leader = h.leader(0);
    let mut tampered = genuine.clone();
    let mut bytes = tampered.availability.as_slice().to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    tampered.availability = crate::availability::AvailabilityFrame::from_untrusted(bytes).unwrap();
    let mut stripped = genuine.clone();
    stripped.availability =
        crate::availability::AvailabilityFrame::from_untrusted(Vec::new()).unwrap();
    let mut bad_attach = genuine.clone();
    bad_attach.proposal.justify = Some(h.tc_q(0));
    for p in [tampered.clone(), bad_attach.clone()] {
        let out = h.deliver(leader, WireMessage::Proposal(Box::new(p)));
        assert!(
            evidence(&out).is_empty() && timeouts(&out).is_empty(),
            "unsigned carrier corruption cannot accuse or time out the original author"
        );
    }
    assert!(h.pending_exec.is_empty());
    h.deliver(leader, WireMessage::Proposal(Box::new(genuine)));
    assert_eq!(h.pending_exec.len(), 1);
    for p in [tampered, stripped, bad_attach] {
        h.deliver(leader, WireMessage::Proposal(Box::new(p)));
    }
    h.exec_all();
    assert!(evidence(&h.all).is_empty());
    assert!(timeouts(&h.all).is_empty());
    assert_eq!(votes_of(&h.all, VoteKind::Prepare).len(), 1);
}

// ---- SR21, SR22: commit paths -----------------------------------------------------------------

fn forged(mut qc: Qc) -> Qc {
    qc.agg_sig = AggregateSignature([7; SIGNATURE_LEN]);
    qc
}

#[test]
fn det_s21_forged_commitqc_via_status() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    h.bodies.insert(h.bh(&b), b.clone());
    let status = |qc: Qc| Status {
        instance: I,
        height: 2,
        committed_qc: Some(qc),
        ..Status::default()
    };
    let o = h.others(2, &[]);
    let bad = forged(h.qc_q(VoteKind::Commit, 0, &b));
    h.deliver(o[0], WireMessage::Status(Box::new(status(bad))));
    assert_eq!(h.core.tip.height, 0);
    let good = h.qc_q(VoteKind::Commit, 0, &b);
    h.deliver(o[1], WireMessage::Status(Box::new(status(good))));
    assert_eq!(h.core.tip.height, 1);
}

#[test]
fn det_s21_forged_commitqc_via_parent_qc() {
    let mut h = H::new(4, pick::set_a(0));
    let b1 = h.block(0, b"B1");
    h.bodies.insert(h.bh(&b1), b1.clone());
    let topo2 = Topology::from_parts(h.core.topo.permutation().to_vec(), &[], 2).unwrap();
    let leader2 = topo2.leader(0);
    let b2 = h.block_at(2, (h.bh(&b1), result_of(&b1)), leader2, b"B2");
    let make = |h: &H, parent_qc: Qc| {
        let bh = h.bh(&b2);
        let ad = preimage::att_digest(&h.v.crypto, None, Some(&parent_qc));
        ProposalMessage {
            availability: b2.availability().clone(),
            proposal: Proposal {
                instance: I,
                height: 2,
                view: 0,
                header: b2.header().clone(),
                justify: None,
                parent_qc: Some(parent_qc),
                sig: h
                    .signer_of(&h.key_at(leader2))
                    .sign(&preimage::prop_preimage(
                        &I,
                        &crate::testing::TEST_EPOCH.id,
                        2,
                        0,
                        &bh,
                        &ad,
                    )),
            },
        }
    };
    let bad = make(&h, forged(h.qc_q(VoteKind::Commit, 0, &b1)));
    let out = h.deliver(leader2, WireMessage::Proposal(Box::new(bad)));
    assert_eq!(h.core.tip.height, 0);
    assert!(evidence(&out).is_empty());
    let good = make(&h, h.qc_q(VoteKind::Commit, 0, &b1));
    let out = h.deliver(leader2, WireMessage::Proposal(Box::new(good)));
    assert_eq!(h.core.tip.height, 1);
    assert_eq!(h.height(), 2);
    assert_eq!(
        executes(&out).len(),
        1,
        "the height-2 proposal is then accepted"
    );
}

#[test]
fn det_s22_sync_forged_block() {
    let mut h = H::new(4, pick::set_a(0));
    let b1 = h.block(0, b"B1");
    let c1 = h.cqc_for(&b1, 0);
    let b2 = h.block_at(2, (h.bh(&b1), result_of(&b1)), 0, b"B2");
    let c2 = h.cqc_for(&b2, 0);
    let peer = h.others(1, &[])[0];
    let status = Status {
        instance: I,
        height: 3,
        committed_qc: Some(c2.clone()),
        ..Status::default()
    };
    let out = h.deliver(peer, WireMessage::Status(Box::new(status)));
    assert!(
        sent(&out)
            .iter()
            .any(|(_, m)| matches!(m, WireMessage::SyncRequest(r) if r.from_height == 1))
    );
    let respond = |h: &mut H, blocks: Vec<SyncEntry>| {
        // Rejected availability completes asynchronously. A request for a later height may
        // already be in flight; let its bounded retry request the missing prefix again.
        let out = h.run_until(h.now + h.local.sync_retry);
        assert!(
            sent(&out).iter().any(|(_, message)| {
                matches!(message, WireMessage::SyncRequest(request) if request.from_height == 1)
            }),
            "each response answers a new request for the missing prefix"
        );
        h.deliver(
            peer,
            WireMessage::SyncResponse(SyncResponse {
                instance: I,
                blocks,
            }),
        )
    };
    // A forged original authorization table and a header that does not match its QC.
    let mut forged_manifest = manifest(&b1);
    let mut bytes = forged_manifest.availability.as_slice().to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    forged_manifest.availability =
        crate::availability::AvailabilityFrame::from_untrusted(bytes).unwrap();
    let mut wrong_header = manifest(&b1);
    wrong_header.header.origin_view = 5;
    for bad in [forged_manifest, wrong_header] {
        respond(
            &mut h,
            vec![SyncEntry {
                manifest: bad,
                commit_qc: c1.clone(),
            }],
        );
        assert_eq!(h.core.tip.height, 0);
    }
    // A certified block that does not extend the tip (wrong parent link).
    let stray = h.block_at(1, (Hash32([5; 32]), G_RESULT), 0, b"stray");
    let stray_qc = h.cqc_for(&stray, 0);
    respond(
        &mut h,
        vec![SyncEntry {
            manifest: manifest(&stray),
            commit_qc: stray_qc,
        }],
    );
    assert_eq!(h.core.tip.height, 0);
    // Genuine entries commit in order.
    respond(
        &mut h,
        vec![
            SyncEntry {
                manifest: manifest(&b1),
                commit_qc: c1,
            },
            SyncEntry {
                manifest: manifest(&b2),
                commit_qc: c2,
            },
        ],
    );
    assert_eq!(h.core.tip.height, 2);
    assert!(halts(&h.all).is_empty());
}

// ---- SR24: the O2 barrier for locally formed certificates -------------------------------------

#[test]
fn det_s24_local_cqc_not_exposed_before_durable() {
    let mut h = H::new(4, pick::proxy_tail(0));
    let b = h.block(0, b"B");
    h.bodies.insert(h.bh(&b), b.clone());
    let o = h.others(2, &[]);
    for signer in &o {
        let vote = h.vote(VoteKind::Commit, *signer, 0, &b);
        h.deliver(*signer, WireMessage::Vote(vote));
    }
    assert_eq!(h.core.tip.height, 0);
    // The PrepareQC makes X Commit; its own vote completes the CommitQC in the same call.
    let out = {
        let qc = h.qc_q(VoteKind::Prepare, 0, &b);
        qc_msg(&mut h, qc)
    };
    let persist = out
        .iter()
        .position(|a| matches!(a, Action::PersistSafety(r) if r.lock.as_ref().is_some_and(|q| q.view == 0)))
        .expect("the Commit is recorded through the lock");
    let broadcast = out
        .iter()
        .position(|a| matches!(a, Action::Broadcast { msg: WireMessage::Qc(q), .. } if q.kind == VoteKind::Commit))
        .expect("the proxy tail broadcasts the CommitQC");
    let commit = out
        .iter()
        .position(|a| matches!(a, Action::CommitBlock { .. }))
        .expect("committed");
    assert!(persist < broadcast && persist < commit);
    assert!(
        released_without_durability(&out).is_empty(),
        "nothing escapes before durability"
    );
    // A sync request served afterwards is also behind the barrier (a later action).
    let w = h.others(1, &[])[0];
    let out = h.deliver(
        w,
        WireMessage::SyncRequest(crate::message::SyncRequest {
            instance: I,
            from_height: 1,
            max_count: 8,
            max_bytes: 1 << 20,
        }),
    );
    assert!(out.iter().any(|a| matches!(a, Action::ServeBlocks { .. })));
}

// ---- SR31, SR32, SR33: restart rules -----------------------------------------------------------

/// A `Status` carrying an echo for `key`, signed by the holder of `signer` over
/// `echo_preimage(h.nonce, height)` (a forgery when `signer ≠ key`).
fn echo_status(h: &H, key: &PublicKey, signer: &PublicKey, height: u64) -> WireMessage {
    let msg = preimage::echo_preimage(&I, &crate::testing::TEST_EPOCH.id, h.nonce, height);
    let sig = h.signer_of(signer).sign(&msg);
    WireMessage::Status(Box::new(Status {
        instance: I,
        height,
        echo: Some(Echo {
            epoch: crate::testing::TEST_EPOCH.id,
            nonce: h.nonce,
            key: key.clone(),
            sig,
        }),
        ..Status::default()
    }))
}

/// A valid echo of member `index` reporting `height`, delivered by that member.
fn echo(h: &mut H, index: ValidatorIndex, height: u64) -> Vec<Action> {
    let key = h.key_at(index);
    let msg = echo_status(h, &key, &key, height);
    h.deliver(index, msg)
}

fn signatures_of(h: &H, key: &PublicKey) -> usize {
    h.log.signatures_by(key).len()
}

fn key_state(h: &H) -> (bool, u64) {
    let key = &h.core.keys[0];
    (key.unanchored, key.abstain_below)
}

/// MS31: X Commits at `(t+1, 0)`, its record is deleted, the block store is intact; after the
/// restart X signs nothing at `t+1` or `t+2`; once W, Y, Z (`2f + 1 = 3`) report heights
/// `≤ t'+1` in signed echoes it signs again from `t'+3`.
#[test]
fn det_s31_deleted_record_abstains() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    {
        let qc = h.qc_q(VoteKind::Prepare, 0, &b);
        qc_msg(&mut h, qc)
    };
    assert_eq!(h.my_sigs(KIND_COMMIT, 1, 0).len(), 1);
    h.records.clear();
    let key = h.signers[0].public_key().clone();
    let out = h.start(vec![(key.clone(), RecordState::Absent)]);
    assert!(faults(&out).contains(&LocalFault::RecordMissing));
    assert!(h.core.status().unanchored);
    assert!(h.core.status().signer.is_none());
    let signed = signatures_of(&h, &key);
    // Probes go to the other members of C_{t'+2}, and every Status carries the nonce.
    let out = h.run_until(h.now + h.local.rebroadcast_interval);
    let probes: Vec<_> = sent(&out)
        .into_iter()
        .filter_map(|(to, m)| match m {
            WireMessage::Status(s) => Some((to, s.probe)),
            _ => None,
        })
        .collect();
    assert!(!probes.is_empty());
    assert!(probes.iter().all(|(_, p)| *p == Some(h.nonce)));
    assert!(
        probes
            .iter()
            .any(|(to, _)| to.len() == 3 && !to.contains(&key)),
        "{probes:?}"
    );
    // Unanchored: X signs nothing at t + 1 whatever it sees.
    let twin = h.block(0, b"B-twin");
    if h.leader(0) != h.my_idx() {
        prop(&mut h, 0, &twin, None);
        h.exec_all();
    }
    {
        let qc = h.qc_q(VoteKind::Prepare, 0, &twin);
        qc_msg(&mut h, qc)
    };
    h.run_until(h.now + 20_000);
    assert_eq!(signatures_of(&h, &key), signed);
    // Two echoes are not enough (2f + 1 = 3); the third anchors: abstain through t' + 2 = 2.
    let others = h.others(3, &[]);
    echo(&mut h, others[0], 1);
    echo(&mut h, others[1], 1);
    assert_eq!(key_state(&h), (true, 0));
    echo(&mut h, others[2], 1);
    assert_eq!(key_state(&h), (false, 3));
    assert!(h.core.probe.is_empty());
    // Heights t + 1 = 1 and t + 2 = 2: still nothing is signed.
    for height in 1..=2 {
        assert_eq!(h.height(), height);
        assert!(h.core.status().signer.is_none());
        let blk = h.block(0, b"X");
        if h.leader(0) != h.my_idx() {
            prop(&mut h, 0, &blk, None);
            h.exec_all();
        }
        h.run_until(h.now + 20_000);
        assert_eq!(signatures_of(&h, &key), signed, "height {height}");
        h.commit_with(0, b"X");
    }
    // Height 3 = t' + 3: the key signs again.
    assert_eq!(h.height(), 3);
    assert_eq!(h.core.status().signer, Some(key.clone()));
    h.run_until(h.now + 30_000);
    assert!(signatures_of(&h, &key) > signed);
}

/// `MS31b`: the record and the block-store tail are lost together. X Prepared and Committed B at
/// `(10, 0)`; its record is deleted and its Kura truncated to 6; after the restart X syncs 7–9
/// and enters 10. W's fresh echo (height 10) and Byzantine Z's count; Y committed 10 and its
/// echo reports 11 > t' + 1, so X stays unanchored and never Prepares the twin B′ at `(10, 0)`.
/// (The revision-3 rule anchored at once from the local tip: `abstain_below = 6 + 3 = 9`.)
#[test]
#[allow(clippy::many_single_char_names)] // replicas named as in the spec
fn det_s31b_record_and_store_lost() {
    let mut h = H::new(4, pick::at(10, 0, 1));
    h.commit_heights(9);
    assert_eq!(h.height(), 10);
    assert!(h.round(0).in_set_a(h.my_idx()) && h.leader(0) != h.my_idx());
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    h.exec_all();
    {
        let qc = h.qc_q(VoteKind::Prepare, 0, &b);
        qc_msg(&mut h, qc)
    };
    assert_eq!(h.my_sigs(KIND_PREPARE, 10, 0).len(), 1);
    assert_eq!(h.my_sigs(KIND_COMMIT, 10, 0).len(), 1);
    let full = h.store.clone();
    h.records.clear();
    h.store.truncate(6);
    let key = h.signers[0].public_key().clone();
    h.start(vec![(key, RecordState::Absent)]);
    assert_eq!(h.height(), 7);
    let o = h.others(3, &[]);
    let (w, y, z) = (o[0], o[1], o[2]);
    // X syncs 7..9 from W and enters 10.
    let status = Status {
        instance: I,
        height: 10,
        committed_qc: Some(full[8].1.clone()),
        ..Status::default()
    };
    h.deliver(w, WireMessage::Status(Box::new(status)));
    let entries: Vec<SyncEntry> = full[6..9]
        .iter()
        .map(|(block, qc)| SyncEntry {
            manifest: manifest(block),
            commit_qc: qc.clone(),
        })
        .collect();
    h.deliver(
        w,
        WireMessage::SyncResponse(SyncResponse {
            instance: I,
            blocks: entries,
        }),
    );
    assert_eq!(h.height(), 10);
    echo(&mut h, w, 10);
    echo(&mut h, z, 1);
    echo(&mut h, y, 11);
    assert!(
        h.core.status().unanchored,
        "Y's reply shows height 11 > t' + 1"
    );
    let twin = h.block(0, b"B-twin");
    prop(&mut h, 0, &twin, None);
    h.exec_all();
    h.run_until(h.now + 20_000);
    assert_eq!(h.my_sigs(KIND_PREPARE, 10, 0).len(), 1, "no Prepare for B′");
    assert_eq!(h.my_sigs(KIND_COMMIT, 10, 0).len(), 1);
}

/// `MS31c`: a node with an unanchored or abstaining key answers no probe; once anchored and past
/// `abstain_below` it answers with a signed echo of its current height.
#[test]
fn det_s31c_abstaining_node_does_not_answer() {
    let mut h = H::new(4, pick::set_a(0));
    h.records.clear();
    let key = h.signers[0].public_key().clone();
    h.start(vec![(key.clone(), RecordState::Absent)]);
    let prober = h.others(1, &[])[0];
    let probe = |height: u64| {
        WireMessage::Status(Box::new(Status {
            instance: I,
            height,
            probe: Some(0x77),
            ..Status::default()
        }))
    };
    let echoes = |actions: &[Action]| -> Vec<Echo> {
        sent(actions)
            .into_iter()
            .filter_map(|(_, m)| match m {
                WireMessage::Status(s) => s.echo,
                _ => None,
            })
            .collect()
    };
    let out = h.deliver(prober, probe(1));
    assert!(echoes(&out).is_empty(), "unanchored: no answer");
    for o in h.others(3, &[]) {
        echo(&mut h, o, 1);
    }
    assert_eq!(key_state(&h), (false, 3));
    h.now += h.local.rebroadcast_interval;
    let out = h.deliver(prober, probe(1));
    assert!(echoes(&out).is_empty(), "abstaining at height 1: no answer");
    h.commit_heights(2);
    assert_eq!(h.height(), 3);
    h.now += h.local.rebroadcast_interval;
    let out = h.deliver(prober, probe(3));
    let answered = echoes(&out);
    assert_eq!(answered.len(), 1);
    let e = &answered[0];
    assert_eq!((e.nonce, &e.key), (0x77, &key));
    let msg = preimage::echo_preimage(&I, &crate::testing::TEST_EPOCH.id, 0x77, 3);
    assert!(h.v.crypto.verify(&key, &msg, &e.sig));
    // At most once per peer per rebroadcast_interval.
    h.now += h.local.rebroadcast_interval / 2;
    let out = h.deliver(prober, probe(3));
    assert!(echoes(&out).is_empty());
}

/// `MS31d`: only a fresh signed echo counts. A `Status` Y sent before X's crash (height `≤ t'+1`,
/// no echo) arrives late and Y's fresh echo reports `t' + 2` → X stays unanchored.
#[test]
#[allow(clippy::many_single_char_names)] // replicas named as in the spec
fn det_s31d_stale_status_is_not_a_reply() {
    let mut h = H::new(4, pick::set_a(0));
    h.records.clear();
    let key = h.signers[0].public_key().clone();
    h.start(vec![(key, RecordState::Absent)]);
    let o = h.others(3, &[]);
    let (w, y, z) = (o[0], o[1], o[2]);
    echo(&mut h, w, 1);
    echo(&mut h, z, 1);
    let stale = Status {
        instance: I,
        height: 1,
        ..Status::default()
    };
    h.deliver(y, WireMessage::Status(Box::new(stale)));
    assert!(h.core.status().unanchored);
    echo(&mut h, y, 2);
    assert!(h.core.status().unanchored, "t' + 2 does not count");
    // A replayed echo of another nonce, and an echo under the node's own key, never count.
    let mut replay = echo_status(&h, &h.key_at(y), &h.key_at(y), 1);
    if let WireMessage::Status(s) = &mut replay
        && let Some(e) = s.echo.as_mut()
    {
        e.nonce ^= 1;
    }
    h.deliver(y, replay);
    let mine = h.key_at(h.my_idx());
    let own = echo_status(&h, &mine, &mine, 1);
    h.deliver(y, own);
    assert!(h.core.status().unanchored);
}

/// `MS31e`: echoes are signed. Z (harness-Byzantine, leader of `(t+3, 0)`) sends X echoes that
/// name W and Y but carry Z's signature, plus its own valid echo → X stays unanchored. X syncs
/// to `t+2`; Y's valid echo reaches X only relayed by Z, W's directly → X anchors at
/// `t' = t + 2` (a relayed signed echo counts) and never Prepares Z's twin B′ at `(t+3, 0)`.
#[test]
#[allow(clippy::many_single_char_names)] // W, X, Y, Z as in the spec
fn det_s31e_echo_signature() {
    let t = 3;
    let mut h = H::new(4, pick::at(t + 3, 0, 1));
    h.commit_heights(t + 2);
    assert_eq!(h.height(), t + 3);
    let z = h.leader(0);
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    h.exec_all();
    assert_eq!(h.my_sigs(KIND_PREPARE, t + 3, 0).len(), 1);
    let full = h.store.clone();
    h.records.clear();
    h.store.truncate(usize::try_from(t).unwrap());
    let key = h.signers[0].public_key().clone();
    h.start(vec![(key, RecordState::Absent)]);
    assert_eq!(h.height(), t + 1);
    let others = h.others(3, &[z]);
    let (w, y) = (others[0], others[1]);
    let (wk, yk, zk) = (h.key_at(w), h.key_at(y), h.key_at(z));
    // Forged echoes naming W and Y (Z's signatures), and Z's own valid echo.
    let forged_w = echo_status(&h, &wk, &zk, t + 1);
    let forged_y = echo_status(&h, &yk, &zk, t + 1);
    let own_z = echo_status(&h, &zk, &zk, t + 1);
    for msg in [forged_w, forged_y, own_z] {
        h.deliver(z, msg);
    }
    assert!(h.core.status().unanchored);
    assert_eq!(h.core.probe.len(), 1, "only Z's own echo counts");
    // X syncs to t + 2.
    let status = Status {
        instance: I,
        height: t + 3,
        committed_qc: Some(full[usize::try_from(t + 1).unwrap()].1.clone()),
        ..Status::default()
    };
    h.deliver(w, WireMessage::Status(Box::new(status)));
    let entries: Vec<SyncEntry> = full
        [usize::try_from(t).unwrap()..usize::try_from(t + 2).unwrap()]
        .iter()
        .map(|(block, qc)| SyncEntry {
            manifest: manifest(block),
            commit_qc: qc.clone(),
        })
        .collect();
    h.deliver(
        w,
        WireMessage::SyncResponse(SyncResponse {
            instance: I,
            blocks: entries,
        }),
    );
    assert_eq!((h.core.tip.height, h.height()), (t + 2, t + 3));
    // Y's valid echo relayed by Z, W's directly.
    let relayed = echo_status(&h, &yk, &yk, t + 3);
    h.deliver(z, relayed);
    assert!(h.core.status().unanchored);
    echo(&mut h, w, t + 3);
    assert_eq!(key_state(&h), (false, t + 5), "anchored at t' = t + 2");
    // Z's twin B′ at (t + 3, 0): never Prepared.
    let twin = h.block(0, b"B-twin");
    prop(&mut h, 0, &twin, None);
    h.exec_all();
    h.run_until(h.now + 20_000);
    assert_eq!(h.my_sigs(KIND_PREPARE, t + 3, 0).len(), 1);
}

/// `MS32a`: R5 with a record at `t + 2` (valid checksum) whose `parent_commit_qc` does not verify
/// under `C_{t+1}` → `Halt(SafetyRecordInconsistent)`, no commit.
#[test]
fn det_s32a_r5_forged_parent_qc() {
    let mut h = H::new(4, |_| 0);
    h.commit_heights(2);
    time_out(&mut h);
    let mut record = h.durable().unwrap();
    assert_eq!(record.height, 3);
    record.parent_commit_qc = record.parent_commit_qc.map(forged);
    let key = h.signers[0].public_key().clone();
    h.records.insert(key, record.encode(&h.v.crypto).unwrap());
    h.store.truncate(1);
    let out = h.restart();
    assert_eq!(halts(&out), vec![HaltReason::SafetyRecordInconsistent]);
    assert_eq!(h.core.tip.height, 1, "nothing is committed");
    assert!(!out.iter().any(|a| matches!(a, Action::CommitBlock { .. })));

    // The genuine record: R5 commits t + 1 from the local body store and resumes at t + 2.
    let mut h = H::new(4, |_| 0);
    h.commit_heights(2);
    time_out(&mut h);
    h.store.truncate(1);
    let out = h.restart();
    assert!(halts(&out).is_empty());
    assert_eq!((h.core.tip.height, h.height()), (2, 3));
    assert_eq!(h.core.timeout_view, Some(0));
    assert_eq!(
        h.store.len(),
        2,
        "the recommitted block is applied from the local body store"
    );
}

/// `MS32b`: R6. The record describes `t + 5` with a Commit (the lock) at `(t + 5, 0)`; the block
/// store is at `t` → X signs nothing below `t + 5` and resumes there with the lock.
#[test]
fn det_s32b_store_behind_record() {
    let mut h = H::new(4, pick::at(7, 0, 1));
    h.commit_heights(6);
    assert_eq!(h.height(), 7);
    let b = h.block(0, b"B7");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    qc_msg(&mut h, pqc.clone());
    assert_eq!(h.my_sigs(KIND_COMMIT, 7, 0).len(), 1);
    let record = h.durable().unwrap();
    assert_eq!((record.height, record.lock.clone()), (7, Some(pqc.clone())));
    let key = h.signers[0].public_key().clone();
    let full = h.store.clone();
    h.store.truncate(2);
    let out = h.restart();
    assert!(faults(&out).contains(&LocalFault::StoreBehindRecord { record_height: 7 }));
    assert_eq!(h.height(), 3);
    assert!(
        h.core.status().signer.is_none(),
        "abstains below the record's height"
    );
    let signed = signatures_of(&h, &key);
    // Round 3 runs as an observer.
    let b3 = h.block(0, b"B3");
    if h.leader(0) != h.my_idx() {
        prop(&mut h, 0, &b3, None);
        h.exec_all();
    }
    h.run_until(h.now + 20_000);
    assert_eq!(signatures_of(&h, &key), signed, "nothing below t + 5");
    // Sync from a peer that has heights 3..6.
    let peer = h.others(1, &[])[0];
    let status = Status {
        instance: I,
        height: 7,
        committed_qc: Some(full[5].1.clone()),
        ..Status::default()
    };
    h.deliver(peer, WireMessage::Status(Box::new(status)));
    let entries = full[2..6]
        .iter()
        .map(|(block, qc)| SyncEntry {
            manifest: manifest(block),
            commit_qc: qc.clone(),
        })
        .collect();
    h.deliver(
        peer,
        WireMessage::SyncResponse(SyncResponse {
            instance: I,
            blocks: entries,
        }),
    );
    assert_eq!((h.core.tip.height, h.height()), (6, 7));
    assert_eq!(h.core.high_pqc, Some(pqc), "resumed with the lock");
    assert_eq!(h.core.status().signer, Some(key));
    assert_eq!(
        h.my_sigs(KIND_COMMIT, 7, 0).len(),
        1,
        "the identical Commit at most"
    );
    let out = time_out(&mut h);
    assert_eq!(timeouts(&out)[0].hq(), Some(0));
}

/// `MS32c`: R5 with a valid `CommitQC(t + 1)` whose block does not extend the local tip
/// (simulated block-store corruption) → `Halt(SafetyRecordInconsistent)` when the body arrives,
/// no `CommitBlock`.
#[test]
fn det_s32c_r5_block_not_extending_tip() {
    let mut h = H::new(4, |_| 0);
    h.commit_heights(2);
    time_out(&mut h);
    assert_eq!(h.durable().unwrap().height, 3);
    let b2 = h.store[1].0.clone();
    assert!(h.bodies.contains_key(&h.bh(&b2)), "B2 is in the body store");
    // The block store's tip is replaced by another certified block of height 1; B2 is lost.
    let other = h.block_at(1, (G_HASH, G_RESULT), 0, b"C1");
    let c1 = h.cqc_for(&other, 0);
    h.store = vec![(other, c1)];
    let out = h.restart();
    assert!(
        !h.all
            .iter()
            .any(|a| matches!(a, Action::CommitBlock { .. })),
        "{out:#?}"
    );
    assert_eq!(halts(&h.all), vec![HaltReason::SafetyRecordInconsistent]);
}

#[test]
fn det_s33_key_rotation_restart() {
    // Keys k0..k4; the node rotates from k3 (C_old = {k0..k3}, heights < 4) to k4
    // (C_new = {k0, k1, k2, k4}, heights ≥ 4) and holds both keys throughout.
    let setup = |order: [u32; 2]| {
        let mut h = H::new(5, |_| 3);
        let keys: Vec<PublicKey> = (0..5).map(|i| h.v.key(i)).collect();
        h.committees
            .insert(0, Committee::new(keys[..4].to_vec()).unwrap());
        h.committees.insert(
            4,
            Committee::new(vec![
                keys[0].clone(),
                keys[1].clone(),
                keys[2].clone(),
                keys[4].clone(),
            ])
            .unwrap(),
        );
        h.signers = order.iter().map(|i| h.v.signer(*i).clone()).collect();
        h.records.clear();
        h.install_keys();
        h.restart();
        (h, keys)
    };
    // (a) MS33a, MS33b: each key keeps its own record; the signer is chosen by membership.
    let (mut h, keys) = setup([3, 4]);
    h.commit_heights(2);
    assert_eq!(h.core.status().signer, Some(keys[3].clone()));
    time_out(&mut h);
    // Restart before the change: k3 resumes (R4), k4 is at its initial record (R3).
    h.restart();
    assert_eq!(h.core.status().signer, Some(keys[3].clone()));
    assert_eq!(h.core.timeout_view, Some(0));
    h.commit_with(0, b"3");
    assert_eq!(h.height(), 4);
    assert_eq!(h.core.status().signer, Some(keys[4].clone()));
    time_out(&mut h);
    let k3_record = SafetyRecord::decode(&h.v.crypto, &h.records[&keys[3]]).unwrap();
    let k4_record = SafetyRecord::decode(&h.v.crypto, &h.records[&keys[4]]).unwrap();
    assert_eq!((k3_record.height, k4_record.height), (3, 4));
    // Restart after the change: k3's record is old (R3), k4 resumes (R4); nothing halts.
    let out = h.restart();
    assert!(halts(&out).is_empty());
    assert_eq!(h.core.status().signer, Some(keys[4].clone()));
    assert_eq!(h.core.timeout_view, Some(0));
    // No key ever signed at a height where it is not a member.
    for record in h.log.signatures_by(&keys[3]) {
        let height = u64::from_be_bytes(
            record.preimage
                [preimage::TAG_SIG.len() + 1 + 32 + 40..preimage::TAG_SIG.len() + 1 + 32 + 48]
                .try_into()
                .unwrap(),
        );
        assert!(height < 4);
    }
    for record in h.log.signatures_by(&keys[4]) {
        let height = u64::from_be_bytes(
            record.preimage
                [preimage::TAG_SIG.len() + 1 + 32 + 40..preimage::TAG_SIG.len() + 1 + 32 + 48]
                .try_into()
                .unwrap(),
        );
        assert!(height >= 4);
    }

    // (b) MS33c: restart composition. Store tip t = 2; K2 = k4 (listed first) has a record at
    // t + 2 = 4, K1 = k3 one at t + 1 = 3 → R5 commits 3 once, the round starts at 4 from K2's
    // record, K1's record is classified against the new tip (R3); the tip never moves back.
    let (mut h, keys) = setup([4, 3]);
    h.commit_heights(2);
    time_out(&mut h);
    h.commit_with(0, b"3");
    assert_eq!(h.height(), 4);
    time_out(&mut h);
    h.store.truncate(2);
    let out = h.restart();
    assert!(halts(&out).is_empty(), "{out:#?}");
    let commits: Vec<u64> = h
        .all
        .iter()
        .filter_map(|a| match a {
            Action::CommitBlock { block, .. } => Some(block.header().height),
            _ => None,
        })
        .collect();
    assert_eq!(commits, vec![3], "exactly one CommitBlock for t + 1");
    assert_eq!((h.core.tip.height, h.height()), (3, 4));
    assert_eq!(h.core.status().signer, Some(keys[4].clone()));
    assert_eq!(
        h.core.timeout_view,
        Some(0),
        "the round comes from K2's record"
    );
}

/// `MS33d`: the fake driver's record store with its installation log and store id (§7.4 record
/// provenance rules 2–4). Key K is generated on X; the dataspace instance I is created later
/// (initial record, `(I, K)` entry, new store id); X Prepares B at `(t+1, 0)`, block store at
/// `t`; X's key store is restored from a snapshot taken before I existed and X's record for I is
/// deleted; at restart the driver marks K imported, `Init` carries `Absent` for `(I, K)`, and X
/// never Prepares the twin B′ at `(t+1, 0)`. Variant: the same old key store onto a new, empty
/// record store → `Absent` likewise.
#[test]
fn det_s33d_installation_log_rollback() {
    use crate::sim::records::{KeyStore, StoreId};
    for new_record_store in [false, true] {
        let mut next: StoreId = 0x5eed;
        let mut fresh = || {
            next += 1;
            next
        };
        let mut h = H::new(4, pick::set_a(0));
        let key = h.signers[0].public_key().clone();
        // Installation: K generated on X; a snapshot of the key store is taken; then the
        // dataspace instance I starts (initial record, `(I, K)` entry, fresh store id).
        let mut store_id = None;
        let mut keystore = KeyStore::default();
        keystore.install_key(&mut store_id, &key, true, fresh());
        let snapshot = keystore.clone();
        assert!(!keystore.check_store_id(&mut store_id, &mut fresh));
        h.records.clear();
        let write = keystore.install_instance(&mut store_id, &I, &key, false, false, fresh());
        assert!(write, "a key generated on the node gets its initial record");
        h.records.insert(key.clone(), initial_record(&h.v, &key));
        h.restart();
        // X Prepares B at (1, 0); the block store is at 0.
        let b = h.block(0, b"B");
        prop(&mut h, 0, &b, None);
        h.exec_all();
        assert_eq!(h.my_sigs(KIND_PREPARE, 1, 0).len(), 1);
        // The key store is rolled back and X's record for I is deleted (or the record store is
        // replaced by a new, empty one).
        let mut keystore = snapshot;
        h.records.clear();
        if new_record_store {
            store_id = None;
        }
        let marked = keystore.check_store_id(&mut store_id, &mut fresh);
        assert!(marked, "the log does not describe these record files");
        assert!(!keystore.generated(&key), "every key is imported");
        let write = keystore.install_instance(
            &mut store_id,
            &I,
            &key,
            h.records.contains_key(&key),
            false,
            fresh(),
        );
        assert!(
            !write,
            "never an initial record without an operator assertion"
        );
        let state = h.records.get(&key).map_or(RecordState::Absent, |bytes| {
            RecordState::Present(bytes.clone())
        });
        assert_eq!(state, RecordState::Absent, "Init carries Absent for (I, K)");
        h.start(vec![(key.clone(), state)]);
        assert!(h.core.status().unanchored);
        // The twin B′ at (1, 0) is never Prepared.
        let twin = h.block(0, b"B-twin");
        prop(&mut h, 0, &twin, None);
        h.exec_all();
        h.run_until(h.now + 20_000);
        assert_eq!(
            h.my_sigs(KIND_PREPARE, 1, 0).len(),
            1,
            "new record store: {new_record_store}"
        );
    }
}

#[test]
fn det_s33_key_conflict_signs_neither() {
    let mut h = H::new(4, |_| 2);
    h.signers = vec![h.v.signer(2).clone(), h.v.signer(3).clone()];
    h.records.clear();
    h.install_keys();
    let out = h.restart();
    assert!(faults(&out).contains(&LocalFault::KeyConflict { height: 1 }));
    h.run_until(30_000);
    assert!(h.log.signatures_by(&h.v.key(2)).is_empty());
    assert!(h.log.signatures_by(&h.v.key(3)).is_empty());
}

/// A retired key is restored like the others (R1–R6, the probe-answer rule) but never signs.
#[test]
fn det_r4_retired_keys_never_sign() {
    let mut h = H::new(5, |_| 3);
    let keys: Vec<PublicKey> = (0..5).map(|i| h.v.key(i)).collect();
    h.committees
        .insert(0, Committee::new(keys[..4].to_vec()).unwrap());
    // k4 is retired (it was the node's old key); k3 signs.
    h.retired = vec![keys[4].clone()];
    h.records.clear();
    h.install_keys();
    let out = h.restart();
    assert!(
        faults(&out).contains(&LocalFault::RecordMissing),
        "k4 lost its record"
    );
    assert_eq!(h.core.status().signer, Some(keys[3].clone()));
    assert!(h.core.status().unanchored);
    // The node signs with k3, never with the retired k4 …
    h.commit_heights(1);
    h.run_until(h.now + 20_000);
    assert!(!h.log.signatures_by(&keys[3]).is_empty());
    assert!(h.log.signatures_by(&keys[4]).is_empty());
    // … and answers no probe while the retired key is unanchored.
    let probe = Status {
        instance: I,
        height: 2,
        probe: Some(5),
        ..Status::default()
    };
    let out = h.deliver(0, WireMessage::Status(Box::new(probe)));
    assert!(sent(&out).iter().all(|(_, m)| !matches!(
        m,
        WireMessage::Status(s) if s.echo.is_some()
    )));
}

// ---- SR34, SR36, SR37, SR38 --------------------------------------------------------------------

#[test]
fn det_s34_apply_divergence_halts() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    let bh = h.bh(&b);
    // A local result that differs from the certified one: the driver re-executes at apply.
    h.exec(bh, ExecOutcome::Valid(Hash32([0x42; 32])));
    let out = {
        let qc = h.qc_q(VoteKind::Commit, 0, &b);
        qc_msg(&mut h, qc)
    };
    assert!(out.iter().any(|a| matches!(a, Action::CommitBlock { .. })));
    assert!(!h.core.tip.exec_ok, "the cached post-state does not match");
    let out = h.fire(Event::ApplyDiverged {
        height: 1,
        block_hash: bh,
        local_result: Hash32([0x42; 32]),
    });
    assert_eq!(halts(&out), vec![HaltReason::ApplyDiverged { height: 1 }]);
    assert_eq!(h.core.next_wakeup(), Millis::MAX);
    // With the matching result the driver may apply the cached post-state.
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    h.exec_all();
    let out = {
        let qc = h.qc_q(VoteKind::Commit, 0, &b);
        qc_msg(&mut h, qc)
    };
    assert!(out.iter().any(|a| matches!(a, Action::CommitBlock { .. })));
    assert!(h.core.tip.exec_ok);
}

#[test]
fn det_s36_certified_mismatch_is_local() {
    let setup = || {
        let mut h = H::new(4, pick::proxy_tail(0));
        let b = h.block(0, b"B");
        let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
        let o = h.others(3, &[]);
        let tc = h.tc(0, &[(o[0], Some(pqc)), (o[1], None), (o[2], None)]);
        prop(&mut h, 1, &b, Some(tc));
        let bh = h.bh(&b);
        (h, bh)
    };
    for outcome in [ExecOutcome::Valid(Hash32([0x42; 32])), ExecOutcome::Invalid] {
        let (mut h, bh) = setup();
        let out = h.exec(bh, outcome);
        assert!(matches!(
            faults(&out)[..],
            [LocalFault::ExecutionMismatch { height: 1, view: 1 }]
        ));
        assert!(evidence(&out).is_empty());
        assert!(timeouts(&out).is_empty());
        assert!(
            !out.iter()
                .any(|a| matches!(a, Action::PayloadRejected { .. }))
        );
        assert!(h.my_sigs(KIND_PREPARE, 1, 1).is_empty());
    }
    // Failed: a local fault and a retry after the backoff, then the vote.
    let (mut h, bh) = setup();
    let out = h.exec(bh, ExecOutcome::Failed("disk".into()));
    assert!(matches!(
        faults(&out)[..],
        [LocalFault::ExecutorFailed { height: 1 }]
    ));
    assert!(evidence(&out).is_empty() && timeouts(&out).is_empty());
    let out = h.tick(99);
    assert!(executes(&out).is_empty());
    let out = h.tick(1);
    assert_eq!(executes(&out).len(), 1, "retried after 100 ms");
    h.exec_all();
    assert_eq!(h.my_sigs(KIND_PREPARE, 1, 1).len(), 1);
}

#[test]
fn det_s37_conflicting_commitqc_halts() {
    let mut h = H::new(4, pick::set_a(0));
    h.commit_with(0, b"B");
    let other = h.block_at(1, (G_HASH, G_RESULT), 0, b"B-conflict");
    let conflicting = h.cqc_for(&other, 3);
    let out = qc_msg(&mut h, conflicting);
    assert!(matches!(
        evidence(&out)[..],
        [Evidence::ConflictingCertificates(..)]
    ));
    assert_eq!(halts(&out), vec![HaltReason::SafetyViolation { height: 1 }]);
    // Halted: only serving continues.
    let out = h.tick(10_000);
    assert!(out.is_empty());
    let o = h.others(1, &[])[0];
    let out = h.deliver(
        o,
        WireMessage::PayloadRequest(crate::message::PayloadRequest {
            instance: I,
            height: 1,
            block_hash: Hash32([1; 32]),
        }),
    );
    assert!(matches!(out[..], [Action::ServePayload { .. }]));
    // An equal CommitQC of a committed height is ignored.
    let mut h = H::new(4, pick::set_a(0));
    let b = h.commit_with(0, b"B");
    let same = h.cqc_for(&b, 0);
    let out = qc_msg(&mut h, same);
    assert!(halts(&out).is_empty());
}

#[test]
fn det_s38_forged_votes_never_pooled() {
    let mut h = H::new(4, pick::proxy_tail(0));
    let b = h.block(0, b"B");
    h.bodies.insert(h.bh(&b), b.clone());
    {
        let qc = h.qc_q(VoteKind::Prepare, 0, &b);
        qc_msg(&mut h, qc)
    };
    let stage = h.core.stage;
    let o = h.others(3, &[]);
    // q − 1 = 2 forged Commit votes under honest indices, plus one genuine vote.
    for signer in &o[..2] {
        let mut vote = h.vote(VoteKind::Commit, *signer, 0, &b);
        vote.sig = Signature([9; SIGNATURE_LEN]);
        h.deliver(*signer, WireMessage::Vote(vote));
    }
    let genuine = h.vote(VoteKind::Commit, o[2], 0, &b);
    h.deliver(o[2], WireMessage::Vote(genuine));
    assert_eq!(h.core.tip.height, 0, "no CommitQC from forged votes");
    assert_eq!(h.core.stage, stage);
    assert_eq!(h.core.votes.len(), 2, "own vote and the genuine one");
    // The genuine votes of the same signers still form the certificate.
    let genuine = h.vote(VoteKind::Commit, o[0], 0, &b);
    h.deliver(o[0], WireMessage::Vote(genuine));
    assert_eq!(h.core.tip.height, 1);

    // Contagion never counts forged votes.
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    for signer in h.others(2, &[h.proxy_tail(0)]) {
        let mut vote = h.vote(VoteKind::Prepare, signer, 0, &b);
        vote.sig = Signature([9; SIGNATURE_LEN]);
        h.deliver(signer, WireMessage::Vote(vote));
    }
    assert_eq!(h.core.stage, 0);
}

/// MS42: a consumed original publication is a local recovery halt, never a retry or invalid block.
#[test]
fn det_s42_original_publication_recovery_halts() {
    let mut h = H::new(4, pick::set_a(0));
    let out = h.fire(Event::PublicationRecoveryRequired { height: 1 });
    let reason = HaltReason::PublicationRecoveryRequired { height: 1 };
    assert_eq!(halts(&out), vec![reason]);
    assert_eq!(h.core.status().halted, Some(reason));
    assert_eq!(h.core.next_wakeup(), Millis::MAX);
    for event in [
        Event::Tick,
        Event::PayloadReady { req: 0 },
        Event::PublicationRecoveryRequired { height: 1 },
    ] {
        assert!(
            h.fire(event).is_empty(),
            "halted instance signs and schedules nothing"
        );
    }
    // The existing halt state still serves peers; it does not become another execution owner.
    let out = h.deliver(
        1,
        WireMessage::SyncRequest(crate::message::SyncRequest {
            instance: I,
            from_height: 1,
            max_count: 1,
            max_bytes: 1024,
        }),
    );
    assert!(
        out.iter()
            .any(|action| matches!(action, Action::ServeBlocks { .. }))
    );
    assert!(
        out.iter()
            .all(|action| matches!(action, Action::ServeBlocks { .. }))
    );
}
