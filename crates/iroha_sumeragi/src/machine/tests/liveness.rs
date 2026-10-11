//! Named deterministic liveness tests (§13.4, ML1–ML26, and MS51's `det_s51`) that one core can
//! express.
//! `det_l9` and `det_l10` need several live cores and are in `cluster`; `det_l12` (driver
//! scheduling) and the randomized scenarios belong to the simulator stage.

use super::*;
use crate::{
    pacemaker::exec_retry_delay,
    preimage::{KIND_COMMIT, KIND_PREPARE},
};

fn prop(h: &mut H, view: u64, block: &AvailableBody, justify: Option<TimeoutCert>) -> Vec<Action> {
    let p = h.proposal(view, block, justify);
    h.deliver(h.leader(view), WireMessage::Proposal(Box::new(p)))
}

fn qc_msg(h: &mut H, qc: Qc) -> Vec<Action> {
    let from = h.others(1, &[])[0];
    h.deliver(from, WireMessage::Qc(qc))
}

fn statuses(actions: &[Action]) -> usize {
    sent(actions)
        .iter()
        .filter(|(_, m)| matches!(m, WireMessage::Status(_)))
        .count()
}

#[test]
fn det_l1_levels_grow() {
    let mut h = H::new(4, pick::set_b(0));
    let t_base = h.local.t_base;
    // View 0: anchor = t_enter + payload_retry_interval + build_timeout.
    let expected0 = h.params.payload_retry_interval + h.local.build_timeout + t_base;
    assert_eq!(h.core.view_deadline(), Some(expected0));
    let mut timeouts_at = Vec::new();
    for view in 0..4u64 {
        let deadline = h.core.view_deadline().unwrap();
        assert_eq!(h.core.status().level, u32::try_from(view).unwrap());
        let out = h.run_until(deadline - 1);
        assert!(timeouts(&out).is_empty());
        let out = h.run_until(deadline);
        assert_eq!(timeouts(&out).len(), 1, "view {view}");
        timeouts_at.push(deadline);
        let t_enter = h.now;
        h.enter_view(view + 1);
        let next = h.core.view_deadline().unwrap();
        // T(L) = t_base · 1.5^L; every fresh later view allows one build timeout.
        // Leading a view without work does not manufacture an immediate proposal.
        let anchor = t_enter + h.local.build_timeout;
        let level = u32::try_from(view + 1).unwrap();
        let expected = anchor + t_base * 3u64.pow(level) / 2u64.pow(level);
        assert_eq!(next, expected, "view {}", view + 1);
    }
    assert_eq!(timeouts_at.len(), 4);
}

#[test]
fn det_l2_lost_timeout_resent() {
    let mut h = H::new(4, pick::set_b(0));
    let deadline = h.core.view_deadline().unwrap();
    let out = h.run_until(deadline);
    let first = timeouts(&out);
    assert_eq!(first.len(), 1);
    let interval = h.local.rebroadcast_interval;
    for _ in 0..3 {
        let out = h.run_until(h.now + interval);
        assert_eq!(
            timeouts(&out),
            first,
            "re-sent unchanged at every rebroadcast"
        );
    }
}

#[test]
fn det_l3_setb_joins_stage1() {
    // (a) ML3: a silent non-P set-A member; set B votes at t_ready + t_retx.
    let mut h = H::new(4, pick::set_b(0));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    h.now = 10;
    let out = h.exec_all();
    assert!(votes(&out).is_empty(), "set B does not vote at stage 0");
    let t_retx = h.core.pm.t_retx(0);
    let out = h.run_until(10 + t_retx - 1);
    assert!(votes(&out).is_empty());
    let out = h.run_until(10 + t_retx);
    let prepares = votes_of(&out, VoteKind::Prepare);
    assert_eq!(prepares.len(), 1, "stage 1: set B votes");
    assert_eq!(h.core.stage, 1);
    let to_p = sent(&out)
        .into_iter()
        .any(|(to, m)| matches!(m, WireMessage::Vote(_)) && to == vec![h.key_at(h.proxy_tail(0))]);
    assert!(to_p, "stage-1 votes go to the proxy tail only");

    // (b) ML22: a set-A member Prepares but withholds its Commit (hint off). The PrepareQC of
    // set A arrives before t_ready + t_retx; the overdue CommitQC (t_pqc + t_retx) moves set B
    // to stage 1, whose Commit reaches P long before the stage-2 backstop.
    let mut h = H::new(4, pick::set_b(0));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    h.now = 10;
    h.exec_all();
    h.now = 20;
    let set_a = h.round(0).set_a().to_vec();
    let pqc = h.qc(VoteKind::Prepare, 0, &b, &set_a);
    let out = qc_msg(&mut h, pqc);
    assert!(votes(&out).is_empty(), "set B does not Commit at stage 0");
    assert_eq!(h.core.stage, 0);
    let t_retx = h.core.pm.t_retx(0);
    let out = h.run_until(20 + t_retx - 1);
    assert!(votes(&out).is_empty());
    let out = h.run_until(20 + t_retx);
    let commits = votes_of(&out, VoteKind::Commit);
    assert_eq!(commits.len(), 1, "stage 1 on the overdue CommitQC");
    assert_eq!(h.core.stage, 1);
    let backstop = h.core.anchor() + h.core.pm.view_timeout(0) / 2;
    assert!(20 + t_retx < backstop, "well before stage 2");
    let to_p = sent(&out).into_iter().any(|(to, m)| {
        matches!(m, WireMessage::Vote(v) if v.kind == VoteKind::Commit)
            && to == vec![h.key_at(h.proxy_tail(0))]
    });
    assert!(to_p, "the Commit goes to the proxy tail");
    assert_eq!(h.my_sigs(KIND_COMMIT, 1, 0).len(), 1);
}

#[test]
fn det_l4_stage2_timing() {
    // (a) t_lastvote + 2·t_retx without the phase's QC (a long T keeps the backstop later).
    let local = LocalParams {
        t_base: 8_000,
        ..LocalParams::default()
    };
    let mut h = H::with(4, local, ChainParams::default(), pick::set_a(0));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    h.now = 10;
    h.exec_all();
    let t_retx = h.core.pm.t_retx(0);
    h.run_until(10 + 2 * t_retx - 1);
    assert!(h.core.stage < 2);
    let out = h.run_until(10 + 2 * t_retx);
    assert_eq!(h.core.stage, 2);
    let broadcast = sent(&out)
        .into_iter()
        .any(|(to, m)| matches!(m, WireMessage::Vote(_)) && to.len() == 3);
    assert!(broadcast, "stage 2 broadcasts the own votes");

    // (c) contagion: verified votes of the view from f + 1 distinct non-self signers.
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    let senders = h.others(2, &[h.proxy_tail(0)]);
    let v0 = h.vote(VoteKind::Prepare, senders[0], 0, &b);
    h.deliver(senders[0], WireMessage::Vote(v0));
    assert_eq!(h.core.stage, 0, "f senders are not enough");
    let v1 = h.vote(VoteKind::Prepare, senders[1], 0, &b);
    h.deliver(senders[1], WireMessage::Vote(v1));
    assert_eq!(h.core.stage, 2);
    // The proxy tail itself is never escalated by contagion.
    let mut h = H::new(4, pick::proxy_tail(0));
    let b = h.block(0, b"B");
    for s in h.others(2, &[]) {
        let v = h.vote(VoteKind::Prepare, s, 0, &b);
        h.deliver(s, WireMessage::Vote(v));
    }
    assert_eq!(h.core.stage, 0);

    // (b) backstop anchor + φ·T for a node that never became ready.
    let mut h = H::new(4, pick::set_a(0));
    let backstop = h.params.payload_retry_interval + h.local.build_timeout + h.local.t_base / 2;
    h.run_until(backstop - 1);
    assert!(h.core.stage < 2);
    h.run_until(backstop);
    assert_eq!(h.core.stage, 2);
}

#[test]
fn det_l5_lost_vote_retransmitted() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    let out = h.exec_all();
    let first = votes_of(&out, VoteKind::Prepare);
    assert_eq!(first.len(), 1);
    let t_retx = h.core.pm.t_retx(0);
    let out = h.run_until(t_retx);
    assert!(
        votes_of(&out, VoteKind::Prepare).contains(&first[0]),
        "re-sent at t_retx"
    );
    let out = h.run_until(h.now + h.local.rebroadcast_interval);
    assert!(
        votes_of(&out, VoteKind::Prepare).contains(&first[0]),
        "and again"
    );
    // The phase's QC stops the retransmissions of the Prepare.
    {
        let qc = h.qc_q(VoteKind::Prepare, 0, &b);
        qc_msg(&mut h, qc)
    };
    let out = h.run_until(h.now + 3 * h.local.rebroadcast_interval);
    assert!(votes_of(&out, VoteKind::Prepare).is_empty());

    // The proxy tail answers a voter that evidently lacks the QC, once per voter and view.
    let mut h = H::new(4, pick::proxy_tail(0));
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    qc_msg(&mut h, pqc.clone());
    let voter = h.others(1, &[])[0];
    let vote = h.vote(VoteKind::Prepare, voter, 0, &b);
    let out = h.deliver(voter, WireMessage::Vote(vote));
    let answers = sent(&out)
        .into_iter()
        .filter(|(to, m)| {
            matches!(m, WireMessage::Qc(q) if *q == pqc) && *to == vec![h.key_at(voter)]
        })
        .count();
    assert_eq!(answers, 1);
    let out = h.deliver(voter, WireMessage::Vote(vote));
    assert!(qcs(&out).is_empty(), "once per voter");
}

#[test]
fn det_l6_level_decays() {
    let mut h = H::new(4, pick::set_b(0));
    // The committing view of height 1 takes longer than T(0)/2 here: the start level rises.
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    h.now += h.local.t_base / 2 + 1;
    let cqc = h.qc_q(VoteKind::Commit, 0, &b);
    qc_msg(&mut h, cqc);
    assert_eq!(h.core.tip.height, 1);
    assert_eq!(h.core.status().start_level, 1);
    // decay_after fast (view-0) commits lower it again.
    for i in 0..h.local.decay_after {
        assert_eq!(h.core.status().start_level, 1, "after {i} fast commits");
        let payload = [u8::try_from(i).unwrap()];
        h.commit_with(0, &payload);
    }
    assert_eq!(h.core.status().start_level, 0);
    // A slow height (execution and view > T(start) / 2) raises it again.
    let b = h.block(0, b"slow");
    prop(&mut h, 0, &b, None);
    h.now += h.local.t_base;
    h.exec_all();
    h.commit_with(0, b"slow");
    assert_eq!(h.core.status().start_level, 1);
}

#[test]
fn det_l7_demotion_golden() {
    let mut h = H::new(4, pick::set_b(0));
    let silent = h.leader(0);
    h.enter_view(1);
    let block = h.commit_with(1, b"B1");
    assert_eq!(block.header().skipped_leaders, vec![h.key_at(silent)]);
    h.commit_heights(1);
    let perm = h.core.topo.permutation().to_vec();
    let n = perm.len();
    // From height 3 = 1 + 2 the skipped leader is demoted for W heights.
    for _ in 0..(2 * n) {
        let height = h.height();
        assert_eq!(h.core.topo.demoted(), &[silent], "height {height}");
        let slot_owner = perm[usize::try_from(height).unwrap() % n];
        let leader = h.leader(0);
        if slot_owner == silent {
            let pos = perm.iter().position(|m| *m == silent).unwrap();
            assert_eq!(
                leader,
                perm[(pos + 1) % n],
                "its slot passes to its successor"
            );
        } else {
            assert_eq!(leader, slot_owner, "other heights keep their leaders");
        }
        assert!(
            !h.round(0).in_set_a(silent),
            "demoted members never in set A"
        );
        h.commit_heights(1);
    }
}

#[test]
fn det_l8_join_f_plus_1() {
    let mut h = H::new(4, pick::set_b(0));
    let o = h.others(2, &[]);
    let t = h.timeout(o[0], 3, None);
    let out = h.deliver(o[0], WireMessage::Timeout(Box::new(t)));
    assert!(timeouts(&out).is_empty(), "f timeouts cannot force a join");
    assert_eq!(h.core.view, 0);
    let t = h.timeout(o[1], 3, None);
    let out = h.deliver(o[1], WireMessage::Timeout(Box::new(t)));
    let joined = timeouts(&out);
    assert_eq!(joined.len(), 1);
    assert_eq!(joined[0].view, 3);
    assert_eq!(h.core.timeout_view, Some(3));
    // With n = 4 the joined timeout completes a quorum: TC(3) forms and the view is 4.
    assert_eq!(h.core.high_tc.as_ref().map(|tc| tc.view), Some(3));
    assert_eq!(h.core.view, 4);
}

#[test]
fn det_l11_pending_apply_after_peers_moved_on() {
    let mut h = H::new(4, pick::set_b(0));
    h.auto_fetch = false;
    let b1 = h.block(0, b"B1");
    {
        let qc = h.qc_q(VoteKind::Commit, 0, &b1);
        qc_msg(&mut h, qc)
    };
    assert_eq!((h.core.tip.height, h.height()), (1, 2));
    let fetch = h
        .out
        .iter()
        .find_map(|a| match a {
            Action::FetchPayload { source, peers } if source.height() == 1 => {
                Some((source.block_hash(), peers.clone()))
            }
            _ => None,
        })
        .expect("the committed body is fetched");
    assert_eq!(fetch.0, h.bh(&b1));
    assert!(!fetch.1.is_empty(), "from the CommitQC's signers");
    // Height 2 commits too; its configuration successor waits for apply.
    let b2 = h.block(0, b"B2");
    {
        let qc = h.qc_q(VoteKind::Commit, 0, &b2);
        qc_msg(&mut h, qc)
    };
    assert!(h.core.awaiting);
    // Bodies answered by peers that moved on, in any order; CommitBlock stays in height order.
    let peer = h.others(1, &[])[0];
    let out = h.deliver(peer, WireMessage::PayloadManifest(manifest(&b2)));
    assert!(!out.iter().any(|a| matches!(a, Action::CommitBlock { .. })));
    let out = h.deliver(peer, WireMessage::PayloadManifest(manifest(&b1)));
    let heights: Vec<u64> = out
        .iter()
        .filter_map(|a| match a {
            Action::CommitBlock { block, .. } => Some(block.header().height),
            _ => None,
        })
        .collect();
    assert_eq!(heights, vec![1, 2]);
    assert!(!h.core.awaiting);
    assert_eq!(h.height(), 3);
    // Serving: a PayloadRequest for a committed height is answered from the stores.
    let out = h.deliver(
        peer,
        WireMessage::PayloadRequest(crate::message::PayloadRequest {
            instance: I,
            height: 1,
            block_hash: h.bh(&b1),
        }),
    );
    assert!(matches!(out[..], [Action::ServePayload { height: 1, .. }]));
}

#[test]
fn det_l13_late_views_build_nonempty_work() {
    let mut h = H::new(4, pick::proxy_tail(0));
    assert_eq!(h.leader(2), h.my_idx());
    h.enter_view(1);
    let tc = h.tc_q(1);
    let out = h.deliver(h.others(1, &[])[0], WireMessage::Tc(Box::new(tc)));
    assert!(
        out.iter()
            .any(|a| matches!(a, Action::BuildPayload { view: 2, .. }))
    );
    assert!(proposals(&out).is_empty());
    let out = h.built(b"");
    assert!(proposals(&out).is_empty());
    assert!(
        h.payload_ready()
            .iter()
            .any(|a| matches!(a, Action::BuildPayload { .. }))
    );
    let out = h.built(b"pending transaction");
    assert_eq!(
        h.bodies[&proposals(&out)[0].block_hash(&h.v.crypto)]
            .payload()
            .as_slice(),
        &b"pending transaction"[..]
    );
    let mut h = H::new(4, pick::set_b(0));
    h.enter_view(1);
    let tc = h.tc_q(1);
    let block = h.block(2, b"pending transaction");
    let out = prop(&mut h, 2, &block, Some(tc));
    assert!(evidence(&out).is_empty());
    assert_eq!(h.pending_exec.len(), 1, "late-view nonempty work executes");
}

#[test]
fn det_l14_poison_quarantined() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"poison");
    prop(&mut h, 0, &b, None);
    let bh = h.bh(&b);
    let out = h.exec(bh, ExecOutcome::Invalid);
    assert!(out.iter().any(|a| matches!(
        a,
        Action::PayloadRejected { height: 1, view: 0, block_hash } if *block_hash == bh
    )));
    assert!(
        evidence(&out).is_empty(),
        "an Invalid execution never produces evidence (§3.6)"
    );
    assert_eq!(timeouts(&out).len(), 1, "early timeout");
    assert!(h.my_sigs(KIND_PREPARE, 1, 0).is_empty());
    // No timeout raises the start level, an early one included (§9.2).
    h.enter_view(1);
    h.commit_with(1, b"B1");
    assert_eq!(h.core.status().start_level, 0);
}

#[test]
fn det_l15_unsettled_status_rate() {
    let mut h = H::new(4, pick::set_b(0));
    let interval = h.local.rebroadcast_interval;
    // No commit yet: unsettled, one Status per rebroadcast_interval.
    let out = h.run_until(4 * interval);
    assert_eq!(statuses(&out), 5);
    // Committing every 400 ms: settled, keepalive cadence.
    let start = h.now;
    let mut settled = Vec::new();
    for i in 0..12u8 {
        h.now += 400;
        settled.extend(h.fire(Event::Tick));
        h.commit_with(0, &[i]);
        settled.extend(h.out.clone());
    }
    let elapsed = h.now - start;
    assert!(elapsed >= 4_800);
    assert!(statuses(&settled) <= 2, "{}", statuses(&settled));
    // Timed out in the view: unsettled again.
    let deadline = h.core.view_deadline().unwrap();
    h.run_until(deadline);
    let out = h.run_until(deadline + 4 * interval);
    assert!(statuses(&out) >= 4);
}

#[test]
fn det_l16_hint_from_parent_commitqc() {
    for set_b_signed in [true, false] {
        // n = 7, a set-B member of (2, 0).
        let mut h = H::new(7, pick::at(2, 0, 5));
        let round1 = h.round(0);
        let mut signers: Vec<ValidatorIndex> = round1.set_a().to_vec();
        if set_b_signed {
            signers.pop();
            signers.push(round1.set_b()[0]);
        }
        let b1 = h.block(0, b"B1");
        h.bodies.insert(h.bh(&b1), b1.clone());
        {
            let qc = h.qc(VoteKind::Commit, 0, &b1, &signers);
            qc_msg(&mut h, qc)
        };
        assert_eq!(h.height(), 2);
        assert!(h.round(0).in_set_b(h.my_idx()));
        assert_eq!(h.core.stage, u8::from(set_b_signed), "the hint");
        let b2 = h.block(0, b"B2");
        if h.leader(0) != h.my_idx() {
            prop(&mut h, 0, &b2, None);
        }
        let out = h.exec_all();
        let prepared = votes_of(&out, VoteKind::Prepare);
        if set_b_signed {
            assert_eq!(prepared.len(), 1, "votes as soon as it is ready");
        } else {
            assert!(prepared.is_empty(), "waits for t_ready + t_retx");
        }
    }
}

#[test]
#[allow(clippy::many_single_char_names)] // W, X, Y, Z as in the spec
fn det_l17_hidden_pqc_reexecutes() {
    // n = 4; X (the core) is set B at (1, 0) and set A at (1, 2); W, Y, Z are harness keys.
    for variant in ['a', 'b', 'c'] {
        let mut h = H::new(4, pick::set_b(0));
        let x = h.my_idx();
        assert!(h.round(2).in_set_a(x) && h.leader(1) != x && h.leader(2) != x);
        let others = h.others(3, &[]);
        let (w, y, z) = (others[0], others[1], others[2]);
        // (1) X accepts B of (1, 0); the answer to r1 is withheld.
        let b = h.block(0, b"B");
        prop(&mut h, 0, &b, None);
        let (bh, r1, _) = h.pending_exec.pop().expect("Execute r1");
        // (2) PQC(B, 0) exists (W, Y, Z) but is hidden from X; X, W, Y time out, X forms TC(0).
        let pqc = h.qc(VoteKind::Prepare, 0, &b, &[w, y, z]);
        let deadline = h.core.view_deadline().unwrap();
        h.run_until(deadline);
        for s in [w, y] {
            let t = h.timeout(s, 0, None);
            h.deliver(s, WireMessage::Timeout(Box::new(t)));
        }
        assert_eq!(h.core.view, 1);
        assert!(h.all.iter().any(
            |a| matches!(a, Action::DiscardExecution { height: 1, keep } if !keep.contains(&bh))
        ));
        // (3) The stale answer to r1 is ignored.
        let stale = |h: &mut H| {
            let outcome = if variant == 'a' {
                ExecOutcome::Cancelled
            } else {
                ExecOutcome::Valid(result_of(&b))
            };
            h.fire(Event::Executed {
                block_hash: bh,
                req: r1,
                outcome,
            })
        };
        if variant != 'c' {
            let out = stale(&mut h);
            assert!(votes(&out).is_empty() && faults(&out).is_empty());
        }
        // (4) View 1 fails; TC(1) includes Z's timeout carrying PQC(B, 0).
        let deadline = h.core.view_deadline().unwrap();
        h.run_until(deadline);
        let tw = h.timeout(w, 1, None);
        h.deliver(w, WireMessage::Timeout(Box::new(tw)));
        let tz = h.timeout(z, 1, Some(pqc.clone()));
        h.deliver(z, WireMessage::Timeout(Box::new(tz)));
        assert_eq!(h.core.view, 2);
        let tc = h.core.high_tc.clone().unwrap();
        assert_eq!(tc.high_pqc, Some(pqc.clone()));
        // L(1, 2) re-proposes B; X executes it again with a fresh request id.
        let out = prop(&mut h, 2, &b, Some(tc));
        let reexec: Vec<u64> = out
            .iter()
            .filter_map(|a| match a {
                Action::Execute { req, .. } => Some(*req),
                _ => None,
            })
            .collect();
        assert_eq!(reexec.len(), 1, "variant {variant}");
        assert_ne!(reexec[0], r1);
        if variant == 'c' {
            let out = stale(&mut h);
            assert!(votes(&out).is_empty() && faults(&out).is_empty());
        }
        let out = h.exec_all();
        let prepared = votes_of(&out, VoteKind::Prepare);
        assert_eq!(prepared.len(), 1, "variant {variant}");
        assert_eq!((prepared[0].view, prepared[0].result), (2, pqc.result));
        assert!(faults(&h.all).is_empty(), "variant {variant}");
    }
}

/// `det_s51_execute_certified_flag` (MS51; §4.5 "Certified re-proposals", §6.2 step 9): n = 4,
/// X is set B at (1, 0) and set A at (1, 2). A fresh block is executed with
/// `certified = false`, and so is its retry after the application guard answers
/// `Failed(ClockAhead)`. Its `PrepareQC` (W, Y, Z) is hidden from X until `TC(1)` carries it;
/// the re-proposal is executed with `certified = true`, and so is its retry after
/// `Failed(StaleDueWork)`, re-evaluated at the `RetryAt` emission; the certified execution then
/// Prepares `Q`'s result. A second core covers the node's own lock: a `PrepareQC` that others
/// formed arrives while the guard refuses the uncertified execution, and the retry is certified.
#[test]
#[allow(clippy::many_single_char_names)] // W, X, Y, Z as in the spec
fn det_s51_execute_certified_flag() {
    let mut h = H::new(4, pick::set_b(0));
    let x = h.my_idx();
    assert!(h.round(2).in_set_a(x) && h.leader(1) != x && h.leader(2) != x);
    let others = h.others(3, &[]);
    let (w, y, z) = (others[0], others[1], others[2]);
    let latest = |h: &H| {
        let (_, req, _) = h.pending_exec.last().expect("an outstanding Execute");
        (*req, h.exec_certified[req])
    };
    // (1) Fresh: uncertified, also on the retry after a guard's `Failed`.
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    let (bh, r1, _) = h.pending_exec.pop().expect("Execute r1");
    assert_eq!(h.exec_certified.get(&r1), Some(&false));
    let out = h.fire(Event::Executed {
        block_hash: bh,
        req: r1,
        outcome: ExecOutcome::Failed("ClockAhead".to_owned()),
    });
    assert!(votes(&out).is_empty() && h.pending_exec.is_empty());
    let retry = h.now + exec_retry_delay(0, h.local.rebroadcast_interval);
    h.run_until(retry);
    let (r1b, certified) = latest(&h);
    assert!(
        r1b > r1 && !certified,
        "the retry of a fresh block stays uncertified"
    );
    // (2) PQC(B, 0) is hidden from X; views 0 and 1 fail; TC(1) carries it.
    let pqc = h.qc(VoteKind::Prepare, 0, &b, &[w, y, z]);
    let deadline = h.core.view_deadline().unwrap();
    h.run_until(deadline);
    for s in [w, y] {
        let t = h.timeout(s, 0, None);
        h.deliver(s, WireMessage::Timeout(Box::new(t)));
    }
    assert_eq!(h.core.view, 1);
    let deadline = h.core.view_deadline().unwrap();
    h.run_until(deadline);
    let tw = h.timeout(w, 1, None);
    h.deliver(w, WireMessage::Timeout(Box::new(tw)));
    let tz = h.timeout(z, 1, Some(pqc.clone()));
    h.deliver(z, WireMessage::Timeout(Box::new(tz)));
    assert_eq!(h.core.view, 2);
    let tc = h.core.high_tc.clone().unwrap();
    assert_eq!(tc.high_pqc, Some(pqc.clone()));
    // (3) The re-proposal is certified, and so is its retry after `Failed(StaleDueWork)`.
    prop(&mut h, 2, &b, Some(tc));
    let (r2, certified) = latest(&h);
    assert!(
        r2 > r1b && certified,
        "the re-proposal of a certified block"
    );
    h.pending_exec.clear();
    let out = h.fire(Event::Executed {
        block_hash: bh,
        req: r2,
        outcome: ExecOutcome::Failed("StaleDueWork".to_owned()),
    });
    assert!(votes(&out).is_empty());
    h.run_until(h.now + exec_retry_delay(0, h.local.rebroadcast_interval));
    let (r3, certified) = latest(&h);
    assert!(r3 > r2 && certified, "re-evaluated at the RetryAt emission");
    let out = h.exec_all();
    let prepared = votes_of(&out, VoteKind::Prepare);
    assert_eq!(prepared.len(), 1);
    assert_eq!((prepared[0].view, prepared[0].result), (2, pqc.result));

    // (4) The node's own lock: PQC(C, 0), formed by W, Y and Z, reaches X while the guard
    // refuses X's uncertified execution of C; the retry at the `RetryAt` emission is certified.
    let mut h = H::new(4, pick::set_b(0));
    let others = h.others(3, &[]);
    let c = h.block(0, b"C");
    prop(&mut h, 0, &c, None);
    let (ch, r1, _) = h.pending_exec.pop().expect("Execute r1");
    assert_eq!(h.exec_certified.get(&r1), Some(&false));
    h.fire(Event::Executed {
        block_hash: ch,
        req: r1,
        outcome: ExecOutcome::Failed("ClockAhead".to_owned()),
    });
    let lock = h.qc(VoteKind::Prepare, 0, &c, &others);
    qc_msg(&mut h, lock.clone());
    assert_eq!(h.core.high_pqc, Some(lock.clone()), "X holds the lock");
    h.run_until(h.now + exec_retry_delay(0, h.local.rebroadcast_interval));
    let (r2, certified) = latest(&h);
    assert!(
        r2 > r1 && certified,
        "the node's own lock certifies the retry"
    );
    let out = h.exec_all();
    assert!(
        faults(&out).is_empty(),
        "the certified execution agrees with the lock: {out:?}"
    );
}

#[test]
fn det_l18_f_plus_1_distinct_leaders_core() {
    // With D = {L0} at a height anchored at L0's slot, the leaders of views 0 and 1 differ.
    let mut h = H::new(4, pick::set_b(0));
    let silent = h.leader(0);
    h.enter_view(1);
    h.commit_with(1, b"B1");
    let perm = h.core.topo.permutation().to_vec();
    let n = perm.len();
    let pos = perm.iter().position(|m| *m == silent).unwrap();
    // Advance to the first height ≥ 3 anchored at the demoted slot.
    h.commit_heights(1);
    while usize::try_from(h.height()).unwrap() % n != pos {
        h.commit_heights(1);
    }
    assert_eq!(h.core.topo.demoted(), &[silent]);
    let leaders: Vec<_> = (0..=u64::try_from(h.f()).unwrap())
        .map(|v| h.leader(v))
        .collect();
    let mut distinct = leaders.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), leaders.len(), "{leaders:?}");
    assert!(!leaders.contains(&silent));
}

/// `det_l20_p_broadcasts_commitqc` (ML20): n = 4, P forms `CommitQC(h)` → in the same `handle`
/// call it broadcasts to every incumbent before `CommitBlock`. A boundary does not route
/// to unactivated candidates; the next committee becomes available only after application.
#[test]
fn det_l20_p_broadcasts_commitqc() {
    let mut h = H::new(4, pick::proxy_tail(0));
    let joiner = crate::testing::FakeSigner::from_seed(b"det_l20 joiner", None)
        .public_key()
        .clone();
    let mut keys = h.committee().members().to_vec();
    keys.push(joiner.clone());
    h.committees.insert(2, Committee::new(keys).unwrap());
    let current = h.config(1);
    let topo = Topology::compute(
        &h.v.crypto,
        &I,
        &current.epoch,
        &current.committee,
        1,
        0,
        W,
        &[],
    );
    h.signers = vec![h.v.signer(topo.round(0).proxy_tail()).clone()];
    h.records.clear();
    h.install_keys();
    h.restart();
    let own = h.key_at(h.my_idx());
    let members: Vec<_> = h
        .committee()
        .members()
        .iter()
        .filter(|key| **key != own)
        .cloned()
        .collect();
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    h.exec_all();
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    let out = qc_msg(&mut h, pqc);
    assert_eq!(
        votes_of(&out, VoteKind::Commit).len(),
        0,
        "P pools its own Commit"
    );
    assert!(h.core.mine.commit.is_some());
    let others = h.others(2, &[]);
    let v0 = h.vote(VoteKind::Commit, others[0], 0, &b);
    h.deliver(others[0], WireMessage::Vote(v0));
    let v1 = h.vote(VoteKind::Commit, others[1], 0, &b);
    let out = h.deliver(others[1], WireMessage::Vote(v1));
    let broadcast = out
        .iter()
        .position(|a| matches!(a, Action::Broadcast { msg: WireMessage::Qc(q), .. } if q.kind == VoteKind::Commit))
        .expect("P broadcasts the CommitQC it formed");
    let commit = out
        .iter()
        .position(|a| matches!(a, Action::CommitBlock { .. }))
        .expect("committed");
    assert!(broadcast < commit, "before CommitBlock");
    let Action::Broadcast { to, .. } = &out[broadcast] else {
        unreachable!()
    };
    assert!(members.iter().all(|k| to.contains(k)), "every other member");
    assert!(
        !to.contains(&joiner),
        "unactivated membership cannot route consensus"
    );
    assert_eq!(h.height(), 2);
    assert!(
        h.core.cfg.committee.contains(&joiner),
        "the applied boundary installs C_2"
    );
}

/// `det_l23_commit_before_own_execution` (ML23): X commits `h` while `Execute{B_h}` is still
/// pending; proposal `(h + 1)` arrives; `Executed(Valid(R_h))` arrives before `BlockApplied(h)` →
/// X emits `Execute{B_{h+1}}` at once (the committed block's pending execution is kept,
/// `tip.exec_req`, §6.3 step 0).
#[test]
fn det_l23_commit_before_own_execution() {
    let mut h = H::new(4, pick::at(2, 0, 1));
    h.auto_apply = false;
    let b1 = h.block(0, b"B1");
    prop(&mut h, 0, &b1, None);
    let (bh1, r1, _) = h.pending_exec.pop().expect("Execute{B1} pending");
    let cqc = h.qc_q(VoteKind::Commit, 0, &b1);
    qc_msg(&mut h, cqc);
    assert_eq!((h.core.tip.height, h.height()), (1, 2));
    assert_eq!(
        h.core.tip.exec_req,
        Some(r1),
        "the pending execution is kept"
    );
    assert!(!h.core.tip.exec_ok);
    let b2 = h.block(0, b"B2");
    let out = prop(&mut h, 0, &b2, None);
    assert!(
        executes(&out).is_empty(),
        "the parent state is not available yet"
    );
    let out = h.fire(Event::Executed {
        block_hash: bh1,
        req: r1,
        outcome: ExecOutcome::Valid(result_of(&b1)),
    });
    assert_eq!(executes(&out).len(), 1, "B2 is executed at once");
    assert!(h.core.tip.exec_ok);
    assert_eq!(h.core.tip.exec_req, None);
    // A mismatching answer for the committed block is a local fault, never evidence.
    let mut h = H::new(4, pick::at(2, 0, 1));
    h.auto_apply = false;
    let b1 = h.block(0, b"B1");
    prop(&mut h, 0, &b1, None);
    let (bh1, r1, _) = h.pending_exec.pop().unwrap();
    let cqc = h.qc_q(VoteKind::Commit, 0, &b1);
    qc_msg(&mut h, cqc);
    let out = h.fire(Event::Executed {
        block_hash: bh1,
        req: r1,
        outcome: ExecOutcome::Valid(Hash32([0x42; 32])),
    });
    assert!(matches!(
        faults(&out)[..],
        [LocalFault::ExecutionMismatch { height: 1, .. }]
    ));
    assert!(evidence(&out).is_empty() && executes(&out).is_empty());
}

/// §6.2 step 2, §6.6 caller 1 (ML26): two differently-valued proposals for the current
/// `(h, view)`, both validly signed by `L(h, view)`, are evidence **and** an early timeout —
/// whether or not this node already Prepared the first twin — so the view ends one TC later
/// instead of at its deadline. An honest leader cannot be framed: a copy that differs only in
/// unsigned bytes, a second proposal without the leader's signature, and twins of a view this
/// node already left cause neither.
#[test]
fn det_l25_equivocating_leader_early_timeout() {
    for prepared_first in [false, true] {
        let mut h = H::new(4, pick::set_a(0));
        let a = h.block(0, b"A");
        let b = h.block(0, b"B");
        prop(&mut h, 0, &a, None);
        if prepared_first {
            h.exec_all();
            assert_eq!(h.my_sigs(KIND_PREPARE, 1, 0).len(), 1);
        }
        let out = prop(&mut h, 0, &b, None);
        assert!(
            matches!(evidence(&out)[..], [Evidence::ProposalEquivocation(..)]),
            "{out:#?}"
        );
        let sent = timeouts(&out);
        assert_eq!(sent.len(), 1, "early timeout ({prepared_first})");
        assert_eq!((sent[0].view, sent[0].hq()), (0, None));
        assert_eq!(h.core.timeout_view, Some(0));
        // The fence closes the view: no further vote at view 0, even with its PrepareQC.
        h.exec_all();
        let pqc = h.qc_q(VoteKind::Prepare, 0, &a);
        qc_msg(&mut h, pqc);
        assert_eq!(
            h.my_sigs(KIND_PREPARE, 1, 0).len(),
            usize::from(prepared_first)
        );
        assert!(h.my_sigs(KIND_COMMIT, 1, 0).is_empty());
        // One timeout per view: the twin again changes nothing.
        let out = prop(&mut h, 0, &b, None);
        assert!(timeouts(&out).is_empty() && evidence(&out).is_empty());
        // The other members saw the twins too: TC(0) forms now, not at the view deadline.
        let t = h.now;
        for o in h.others(h.q() - 1, &[]) {
            let timeout = h.timeout(o, 0, None);
            h.deliver(o, WireMessage::Timeout(Box::new(timeout)));
        }
        assert_eq!((h.core.view, h.now), (1, t));
    }

    // Not equivocation.
    let mut h = H::new(4, pick::set_a(0));
    let a = h.block(0, b"A");
    let b = h.block(0, b"B");
    prop(&mut h, 0, &a, None);
    // (1) A relayed copy without its payload (unsigned bytes): same `(bh, ad)`.
    let stripped = h.proposal(0, &a, None);
    // Replaying metadata alone supplies no new rows.
    let other = h.others(1, &[h.leader(0)])[0];
    let out = h.deliver(other, WireMessage::Proposal(Box::new(stripped)));
    assert!(timeouts(&out).is_empty() && evidence(&out).is_empty());
    // (2) A different proposal signed by another member, and one carrying the leader's
    // signature of `A`: step 1 drops both silently.
    let forged = h.proposal_by(other, 0, &b, None);
    let out = h.deliver(other, WireMessage::Proposal(Box::new(forged)));
    assert!(timeouts(&out).is_empty() && evidence(&out).is_empty());
    let mut reused = h.proposal(0, &b, None);
    reused.proposal.sig = h.proposal(0, &a, None).proposal.sig;
    let out = h.deliver(other, WireMessage::Proposal(Box::new(reused)));
    assert!(timeouts(&out).is_empty() && evidence(&out).is_empty());
    assert_eq!(h.core.timeout_view, None);
    // (3) Twins of a view this node already left do not end its current view.
    h.enter_view(1);
    let c = h.block(1, b"C");
    let tc = h.tc_q(0);
    prop(&mut h, 1, &c, Some(tc));
    let mut out = prop(&mut h, 0, &a, None);
    out.extend(prop(&mut h, 0, &b, None));
    assert!(timeouts(&out).is_empty() && evidence(&out).is_empty());
    assert_eq!((h.core.view, h.core.timeout_view), (1, None));
}

/// §9.2 (ML25, ML28): the start level rises only when an execution at this height, or its
/// committing view measured here from when this node held its proposal and body, took more
/// than `T(start)/2`. Views that a Byzantine leader makes fail never raise it — by
/// equivocating (early timeout), or by sending its valid proposal to too few members so that
/// the view ends on its deadline or by a join while this node holds that proposal; nor does a
/// committing view this node had already left. A slow honest view does raise it, at view 0
/// and above; the view-0 wait for the proposal (pace or payload retry) does not count.
#[test]
fn det_l26_raise_only_on_slow_commit_or_exec() {
    let half = LocalParams::default().t_base / 2; // T(0)/2
    let start = |h: &H| h.core.status().start_level;

    // (a) Equivocating leader: early timeout, a fast view-1 commit → unchanged.
    let mut h = H::new(4, pick::set_a(0));
    let a = h.block(0, b"A");
    let b = h.block(0, b"B");
    prop(&mut h, 0, &a, None);
    h.exec_all();
    prop(&mut h, 0, &b, None);
    assert_eq!(h.core.timeout_view, Some(0));
    h.now += 4 * half; // the failed view's length never counts
    h.enter_view(1);
    h.commit_with(1, b"B1");
    assert_eq!(start(&h), 0, "equivocating leader");

    // (b) A valid proposal that only 2f members get: this node holds and Prepares it, no
    // PrepareQC forms, the view times out on its deadline → unchanged.
    let mut h = H::new(4, pick::set_a(0));
    let a = h.block(0, b"A");
    prop(&mut h, 0, &a, None);
    h.exec_all();
    let deadline = h.core.view_deadline().unwrap();
    h.run_until(deadline);
    assert_eq!(h.core.timeout_view, Some(0));
    assert!(h.core.proposal.is_some(), "timed out holding the proposal");
    h.enter_view(1);
    h.commit_with(1, b"B1");
    assert_eq!(start(&h), 0, "deadline with a held proposal");

    // (c) The same view ended by the f + 1 join (n = 7: the join alone forms no TC).
    let mut h = H::new(7, pick::set_a(0));
    let a = h.block(0, b"A");
    prop(&mut h, 0, &a, None);
    h.exec_all();
    for o in h.others(h.f() + 1, &[]) {
        let t = h.timeout(o, 0, None);
        h.deliver(o, WireMessage::Timeout(Box::new(t)));
    }
    assert_eq!(h.core.timeout_view, Some(0), "joined");
    assert!(h.core.proposal.is_some());
    h.enter_view(1);
    h.commit_with(1, b"B1");
    assert_eq!(start(&h), 0, "join with a held proposal");

    // (d) The CommitQC of a view this node already left (its first twin committed through
    // members that voted before the second arrived) → this node never measured that view.
    let mut h = H::new(4, pick::set_a(0));
    let a = h.block(0, b"A");
    let b = h.block(0, b"B");
    prop(&mut h, 0, &a, None);
    prop(&mut h, 0, &b, None);
    h.enter_view(1);
    h.now += 4 * half;
    let cqc = h.qc_q(VoteKind::Commit, 0, &a);
    qc_msg(&mut h, cqc);
    assert_eq!((h.core.tip.height, start(&h)), (1, 0), "left view");

    // (e) A slow honest view-0 commit raises; exactly T(0)/2 does not.
    let mut h = H::new(4, pick::set_b(0));
    for (payload, extra, expected) in [(b"A", 0, 0), (b"B", 1, 1)] {
        let blk = h.block(0, payload);
        prop(&mut h, 0, &blk, None);
        h.now += half + extra;
        let cqc = h.qc_q(VoteKind::Commit, 0, &blk);
        qc_msg(&mut h, cqc);
        assert_eq!(
            start(&h),
            expected,
            "view-0 commit after {} ms",
            half + extra
        );
    }

    // (f) So does a slow view > 0, measured from that view's anchor.
    let mut h = H::new(4, pick::set_b(0));
    h.now += 4 * half;
    h.enter_view(1);
    let blk = h.block(1, b"C");
    let tc = h.tc_q(0);
    prop(&mut h, 1, &blk, Some(tc));
    h.now += half + 1;
    let cqc = h.qc_q(VoteKind::Commit, 1, &blk);
    qc_msg(&mut h, cqc);
    assert_eq!(start(&h), 1, "slow view 1");

    // (g) Work arriving after an idle wait: the view-0 proposal arrives after the entry
    // and commits at once → unchanged (the anchor is the proposal, not the entry).
    let mut h = H::new(4, pick::set_b(0));
    h.now += h.params.payload_retry_interval;
    let blk = h.block(0, b"work after idle");
    prop(&mut h, 0, &blk, None);
    h.now += 100;
    let cqc = h.qc_q(VoteKind::Commit, 0, &blk);
    qc_msg(&mut h, cqc);
    assert_eq!((h.core.tip.height, start(&h)), (1, 0), "work after idle");

    // (h) A slow execution raises even when the committing view is fast (the slow block's
    // view failed; view 1's block is executed at once and commits at once): the height's
    // longest execution counts, not its last (ML28).
    let mut h = H::new(4, pick::set_a(0));
    let a = h.block(0, b"A");
    prop(&mut h, 0, &a, None);
    h.now += half + 1;
    h.exec_all();
    h.enter_view(1);
    let b1 = h.block(1, b"B1");
    let tc = h.tc_q(0);
    prop(&mut h, 1, &b1, Some(tc));
    assert_eq!(h.pending_exec.len(), 1, "B1 is executed before the commit");
    h.exec_all();
    let cqc = h.qc_q(VoteKind::Commit, 1, &b1);
    qc_msg(&mut h, cqc);
    assert_eq!((h.core.tip.height, start(&h)), (1, 1), "slow execution");
}

/// §9.2, §6.2 `discard_exec`, §6.8 step 4 (ML27, ML28): an execution that outlasts its view
/// counts with its elapsed time. (a) Every executor takes longer than `T(1)` for a non-empty
/// block: views 0 and 1 time out while their executions are pending (the driver cancels the
/// work), view 2 commits valid retry work at once → the start level rises so later heights
/// budget for the slow execution already observed. (b) The committed
/// block's own execution, kept across a view change (it is the lock's block) and still
/// pending when its `CommitQC` of the view this node left arrives → the start level rises.
/// (c) A view that fails after its execution finished records only the real duration.
#[test]
fn det_l27_pending_execution_counts() {
    let half = LocalParams::default().t_base / 2; // T(0)/2
    let start = |h: &H| h.core.status().start_level;

    // (a) Views 0 and 1 time out executing; view 2 commits EMPTY.
    let mut h = H::new(4, pick::set_a(0));
    let a = h.block(0, b"A");
    prop(&mut h, 0, &a, None);
    assert_eq!(h.pending_exec.len(), 1, "Execute{{A}}");
    let deadline = h.core.view_deadline().unwrap();
    h.run_until(deadline);
    assert_eq!(h.core.timeout_view, Some(0));
    h.enter_view(1);
    assert!(
        h.core.pm.last_exec_ms() >= Some(2 * half),
        "A counts with T(0)"
    );
    let b1 = h.block(1, b"B1");
    let tc = h.tc_q(0);
    prop(&mut h, 1, &b1, Some(tc));
    let deadline = h.core.view_deadline().unwrap();
    h.run_until(deadline);
    assert_eq!(h.core.timeout_view, Some(1));
    h.enter_view(2);
    let e = h.block(2, b"retry work");
    let bh_e = h.bh(&e);
    let tc = h.tc_q(1);
    // The driver answers the discarded requests `Cancelled` (ignored, stale).
    h.pending_exec.retain(|(bh, _, _)| *bh == bh_e);
    prop(&mut h, 2, &e, Some(tc));
    assert_eq!(h.pending_exec.len(), 1, "Execute{{retry work}}");
    h.exec_all();
    h.now += 50;
    let cqc = h.qc_q(VoteKind::Commit, 2, &e);
    qc_msg(&mut h, cqc);
    assert_eq!(
        (h.core.tip.height, start(&h)),
        (1, 1),
        "nonempty work after two slow views"
    );

    // (b) The committed block's execution, pending since view 0, at a CommitQC of view 0
    // that arrives after this node entered view 1 through a TC carrying PrepareQC(A).
    let mut h = H::new(4, pick::set_a(0));
    let a = h.block(0, b"A");
    let bh_a = h.bh(&a);
    prop(&mut h, 0, &a, None);
    let pqc = h.qc_q(VoteKind::Prepare, 0, &a);
    let entries: Vec<_> = h
        .others(h.q(), &[])
        .into_iter()
        .enumerate()
        .map(|(i, o)| (o, (i == 0).then(|| pqc.clone())))
        .collect();
    let tc = h.tc(0, &entries);
    let from = h.others(1, &[])[0];
    h.deliver(from, WireMessage::Tc(Box::new(tc)));
    assert_eq!(h.core.view, 1);
    assert!(
        matches!(
            h.core.exec.get(&bh_a),
            Some(crate::machine::ExecState::Pending { .. })
        ),
        "the lock's execution is kept"
    );
    h.now += half + 1;
    let cqc = h.qc_q(VoteKind::Commit, 0, &a);
    qc_msg(&mut h, cqc);
    assert_eq!(h.core.tip.height, 1);
    assert!(h.core.tip.exec_req.is_some(), "still pending at the commit");
    assert_eq!(
        start(&h),
        1,
        "the committed block's pending execution counts"
    );

    // (c) Control: the execution finished at once; the failed view's length does not count.
    let mut h = H::new(4, pick::set_a(0));
    let a = h.block(0, b"A");
    prop(&mut h, 0, &a, None);
    h.exec_all();
    let deadline = h.core.view_deadline().unwrap();
    h.run_until(deadline);
    h.enter_view(1);
    h.commit_with(1, b"B1");
    assert_eq!(start(&h), 0, "finished execution, failed view");
}

/// §9.2 (ML29, ML30): the committing view is measured from when this node first held its
/// proposal together with its body, so a leader that sends a valid proposal, or its body,
/// late — but early enough for the view to commit — never raises the start level: (a) a
/// view-0 proposal `T(0)/2 + 100 ms` after `t_enter + P(0)`; (b) the same at view 1; (c) a
/// payload-less proposal at once and its body `T(0)/2 + 100 ms` later; (d) a `CommitQC` of the
/// twin of the proposal this node holds. (e) Control: a committing view slower than `T(0)/2`
/// after the body arrived still raises.
#[test]
fn det_l29_late_leader_does_not_raise() {
    let half = LocalParams::default().t_base / 2; // T(0)/2
    let start = |h: &H| h.core.status().start_level;
    let commit_after = |h: &mut H, view: u64, block: &AvailableBody, ms: Millis| {
        h.exec_all();
        h.now += ms;
        let cqc = h.qc_q(VoteKind::Commit, view, block);
        qc_msg(h, cqc);
        assert_eq!(h.core.tip.height, 1, "committed");
    };

    // (a) View 0: the proposal arrives after the anchor `t_enter + P(0)`.
    let mut h = H::new(4, pick::set_b(0));
    let p0 = h.params.payload_retry_interval + h.local.build_timeout;
    let late = h.core.t_enter + p0 + half + 100;
    h.run_until(late);
    assert_eq!(h.core.timeout_view, None, "the view is still open");
    let blk = h.block(0, b"A");
    prop(&mut h, 0, &blk, None);
    commit_after(&mut h, 0, &blk, 50);
    assert_eq!(start(&h), 0, "late view-0 proposal");

    // (b) View 1: the proposal arrives after `t_enter + P(1)`.
    let mut h = H::new(4, pick::set_b(1));
    h.now += 4 * half;
    h.enter_view(1);
    let t1 = h.core.pm.view_timeout(1);
    let late = h.core.t_enter + h.local.build_timeout + t1 / 2 + 100;
    h.run_until(late);
    assert_eq!(h.core.timeout_view, None, "the view is still open");
    let blk = h.block(1, b"C");
    let tc = h.tc_q(0);
    prop(&mut h, 1, &blk, Some(tc));
    commit_after(&mut h, 1, &blk, 50);
    assert_eq!(start(&h), 0, "late view-1 proposal");

    // (c) A payload-less proposal at once, its body late (from the leader's re-push).
    let mut h = H::new(4, pick::set_b(0));
    h.auto_fetch = false;
    let blk = h.block(0, b"A");
    let bare = h.proposal(0, &blk, None);
    h.withheld_rows.insert(h.bh(&blk));
    h.now += 100;
    h.deliver(h.leader(0), WireMessage::Proposal(Box::new(bare)));
    assert!(h.core.proposal.is_some() && h.core.t_body.is_none());
    let late = h.now + half + 100;
    h.run_until(late);
    h.deliver_rows(h.leader(0), &blk);
    assert_eq!(h.core.t_body, Some(late), "body held now");
    commit_after(&mut h, 0, &blk, 50);
    assert_eq!(start(&h), 0, "late body");

    // (d) This node holds A from early on; the others commit the twin B late.
    let mut h = H::new(4, pick::set_b(0));
    let a = h.block(0, b"A");
    let b = h.block(0, b"B");
    h.now += 100;
    prop(&mut h, 0, &a, None);
    h.exec_all();
    let late = h.now + half + 100;
    h.run_until(late);
    let cqc = h.qc_q(VoteKind::Commit, 0, &b);
    qc_msg(&mut h, cqc);
    assert_eq!((h.core.tip.height, start(&h)), (1, 0), "twin committed");

    // (e) Control: body at once, commit `T(0)/2 + 1` later → raised.
    let mut h = H::new(4, pick::set_b(0));
    h.now += 100;
    let blk = h.block(0, b"A");
    prop(&mut h, 0, &blk, None);
    commit_after(&mut h, 0, &blk, half + 1);
    assert_eq!(start(&h), 1, "slow committing view");
}
