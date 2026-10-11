//! Tests of individual handler branches (§6.1–§6.13).

use super::*;

#[test]
fn smoke_voter_prepares_and_commits() {
    let mut h = H::new(4, pick::set_a(0));
    let block = h.block(0, b"tx");
    let p = h.proposal(0, &block, None);
    let leader = h.leader(0);
    let out = h.deliver(leader, WireMessage::Proposal(Box::new(p)));
    assert_eq!(executes(&out).len(), 1, "{out:#?}");
    let out = h.exec_all();
    let prepares = votes_of(&out, VoteKind::Prepare);
    assert_eq!(prepares.len(), 1, "{out:#?}");
    // The record precedes the vote.
    let persist = out
        .iter()
        .position(|a| matches!(a, Action::PersistSafety(_)))
        .unwrap();
    let send = out
        .iter()
        .position(|a| matches!(a, Action::Send { .. }))
        .unwrap();
    assert!(persist < send);
    let pqc = h.qc_q(VoteKind::Prepare, 0, &block);
    let out = h.deliver(h.proxy_tail(0), WireMessage::Qc(pqc));
    assert_eq!(votes_of(&out, VoteKind::Commit).len(), 1, "{out:#?}");
    let cqc = h.qc_q(VoteKind::Commit, 0, &block);
    let out = h.deliver(h.proxy_tail(0), WireMessage::Qc(cqc));
    assert!(
        out.iter().any(|a| matches!(a, Action::CommitBlock { .. })),
        "{out:#?}"
    );
    assert!(
        h.core.tip.exec_ok,
        "executed with exactly the certified result"
    );
    assert_eq!(h.core.height, 2);
    assert_eq!(h.core.tip.height, 1);
}

#[test]
fn smoke_leader_proposes_after_pace() {
    let mut h = H::new(4, pick::leader(0));
    let out = h.run_until(999);
    assert!(
        !out.iter().any(|a| matches!(a, Action::BuildPayload { .. })),
        "{out:#?}"
    );
    let out = h.run_until(1_000);
    assert!(
        out.iter().any(|a| matches!(
            a,
            Action::BuildPayload {
                height: 1,
                view: 0,
                ..
            }
        )),
        "{out:#?}"
    );
    let out = h.built(b"abc");
    let ps = proposals(&out);
    assert_eq!(ps.len(), 1, "{out:#?}");
    assert_eq!(
        h.bodies[&ps[0].block_hash(&h.v.crypto)]
            .payload()
            .as_slice(),
        &b"abc"[..]
    );
    assert_eq!(executes(&out).len(), 1);
}

use crate::{
    api::ConfigError,
    message::{PayloadRequest, Status, SyncRequest, SyncResponse},
};

fn prop(h: &mut H, view: u64, block: &AvailableBody, justify: Option<TimeoutCert>) -> Vec<Action> {
    let p = h.proposal(view, block, justify);
    h.deliver(h.leader(view), WireMessage::Proposal(Box::new(p)))
}

fn qc_msg(h: &mut H, qc: Qc) -> Vec<Action> {
    let from = h.others(1, &[])[0];
    h.deliver(from, WireMessage::Qc(qc))
}

fn status_to(actions: &[Action]) -> Vec<Vec<PublicKey>> {
    sent(actions)
        .into_iter()
        .filter(|(_, m)| matches!(m, WireMessage::Status(_)))
        .map(|(to, _)| to)
        .collect()
}

fn empty_status(height: u64, view: u64) -> Status {
    Status {
        instance: I,
        height,
        view,
        ..Status::default()
    }
}

// ---- §6.1 intake ------------------------------------------------------------------------------

#[test]
fn intake_drops_other_instances_and_oversized_structures() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    let mut p = h.proposal(0, &b, None);
    p.proposal.instance = Hash32([0x22; 32]);
    let out = h.deliver(h.leader(0), WireMessage::Proposal(Box::new(p)));
    assert!(out.is_empty());
    let mut p = h.proposal(0, &b, None);
    p.proposal.header.skipped_leaders = vec![h.key_at(0); crate::types::MAX_COMMITTEE_SIZE + 1];
    let out = h.deliver(h.leader(0), WireMessage::Proposal(Box::new(p)));
    assert!(out.is_empty());
}

#[test]
fn intake_rule3_status_reply_to_members_behind() {
    let mut h = H::new(4, pick::set_a(0));
    let old = h.block(0, b"old");
    h.commit_heights(1);
    let behind = h.others(1, &[])[0];
    let vote = h.v.vote(
        VoteKind::Prepare,
        behind,
        &I,
        1,
        0,
        &h.bh(&old),
        &result_of(&old),
    );
    let out = h.deliver(behind, WireMessage::Vote(vote));
    assert_eq!(status_to(&out), vec![vec![h.key_at(behind)]]);
    let out = h.deliver(behind, WireMessage::Vote(vote));
    assert!(status_to(&out).is_empty(), "rate-limited per peer");
    h.now += h.local.rebroadcast_interval;
    let out = h.deliver(behind, WireMessage::Vote(vote));
    assert_eq!(status_to(&out).len(), 1);
    // Not from a non-member.
    let stranger = PublicKey::new(vec![0x77; 32]).unwrap();
    let out = h.deliver_key(stranger, WireMessage::Vote(vote));
    assert!(out.is_empty());
}

#[test]
fn intake_rule4_next_height_messages() {
    let mut h = H::new(4, pick::set_a(0));
    let ahead = h.others(1, &[])[0];
    let mut vote = h.vote(VoteKind::Prepare, ahead, 0, &h.block(0, b"x"));
    vote.height = 2;
    let out = h.deliver(ahead, WireMessage::Vote(vote));
    assert_eq!(status_to(&out), vec![vec![h.key_at(ahead)]]);
    // A far-height CommitQC from a member is a sync hint even if unverifiable (config unknown).
    let mut qc = h.qc_q(VoteKind::Commit, 0, &h.block(0, b"x"));
    qc.height = 9;
    let stranger = PublicKey::new(vec![0x77; 32]).unwrap();
    let out = h.deliver_key(stranger, WireMessage::Qc(qc.clone()));
    assert!(
        sent(&out).is_empty(),
        "hints are accepted only from members"
    );
    let out = h.deliver(ahead, WireMessage::Qc(qc));
    assert!(sent(&out).iter().any(
        |(to, m)| matches!(m, WireMessage::SyncRequest(r) if r.from_height == 1)
            && *to == vec![h.key_at(ahead)]
    ));
    assert_eq!(h.core.sync.target(), 9);
}

#[test]
fn awaiting_configuration_freezes_the_round() {
    let mut h = H::new(4, pick::set_b(0));
    h.auto_apply = false;
    let b1 = h.commit_with(0, b"1");
    h.commit_with(0, b"2");
    assert!(h.core.awaiting, "C_3 is unknown until BlockApplied(1)");
    assert_eq!((h.height(), h.core.tip.height), (2, 2));
    assert_eq!(
        h.core.next_wakeup(),
        h.core.next_wakeup().min(h.now + 5_000)
    );
    let status = h.core.status_message();
    assert_eq!((status.height, status.view), (3, 0));
    assert_eq!(status.committed_qc, h.core.tip.commit_qc);
    // A proposal for height 3 cannot be verified yet and is dropped.
    let b3 = h.block_at(3, (h.core.tip.block_hash, h.core.tip.result), 0, b"3");
    let p = h.v.proposal(
        0,
        &I,
        3,
        0,
        b3.header().clone(),
        None,
        h.core.tip.commit_qc.clone(),
    );
    let out = h.deliver(
        0,
        WireMessage::Proposal(Box::new(ProposalMessage {
            proposal: p,
            availability: b3.availability().clone(),
        })),
    );
    assert!(executes(&out).is_empty());
    // No round timers fire while awaiting.
    let out = h.run_until(h.now + 20_000);
    assert!(timeouts(&out).is_empty() && votes(&out).is_empty());
    let event = h.applied_event(&b1);
    let out = h.fire(event);
    assert!(!h.core.awaiting);
    assert_eq!(h.height(), 3);
    assert!(halts(&out).is_empty());
}

// ---- §6.11 Status ------------------------------------------------------------------------------

#[test]
fn status_certificates_and_rate_limit() {
    let mut h = H::new(4, pick::set_b(0));
    let peer = h.others(1, &[])[0];
    let tc = h.tc_q(2);
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 1, &b);
    let status = Status {
        high_tc: Some(tc),
        high_pqc: Some(pqc.clone()),
        proposal_hash: Some(h.bh(&b)),
        ..empty_status(1, 3)
    };
    h.deliver(peer, WireMessage::Status(Box::new(status.clone())));
    assert_eq!(h.core.view, 3, "TC(2) from a Status advances the view");
    assert_eq!(h.core.high_pqc, Some(pqc));
    assert_eq!(h.core.peers.get(&h.key_at(peer)).map(|p| p.view), Some(3));
    // A second Status within rebroadcast_interval / 2 is ignored.
    let later = empty_status(1, 5);
    h.deliver(peer, WireMessage::Status(Box::new(later.clone())));
    assert_eq!(h.core.peers.get(&h.key_at(peer)).map(|p| p.view), Some(3));
    h.now += h.local.rebroadcast_interval / 2;
    h.deliver(peer, WireMessage::Status(Box::new(later)));
    assert_eq!(h.core.peers.get(&h.key_at(peer)).map(|p| p.view), Some(5));
}

#[test]
fn status_from_a_member_behind_is_answered_and_sources_wants() {
    let mut h = H::new(4, pick::set_a(0));
    h.auto_fetch = false;
    h.commit_heights(1);
    let peer = h.others(1, &[])[0];
    let out = h.deliver(peer, WireMessage::Status(Box::new(empty_status(1, 0))));
    assert_eq!(status_to(&out), vec![vec![h.key_at(peer)]]);
    // A peer reporting a wanted proposal hash becomes a fetch source.
    let b = h.block(0, b"B");
    let p = h.proposal(0, &b, None);
    h.withheld_rows.insert(h.bh(&b));
    h.deliver(h.leader(0), WireMessage::Proposal(Box::new(p)));
    let reporter = h.others(3, &[h.leader(0)])[0];
    h.now += h.local.rebroadcast_interval;
    let status = Status {
        proposal_hash: Some(h.bh(&b)),
        ..empty_status(2, 0)
    };
    h.deliver(reporter, WireMessage::Status(Box::new(status)));
    let want = h.core.wants.get(&h.bh(&b)).expect("wanted");
    assert!(want.sources.contains(&h.key_at(reporter)));
}

// ---- §6.4 votes --------------------------------------------------------------------------------

#[test]
fn votes_window_equivocation_and_formation_broadcast() {
    let mut h = H::new(4, pick::proxy_tail(0));
    let b = h.block(0, b"B");
    let o = h.others(3, &[]);
    // Outside {view − 1, view, view + 1}: dropped.
    let far = h.vote(VoteKind::Prepare, o[0], 2, &b);
    h.deliver(o[0], WireMessage::Vote(far));
    assert_eq!(h.core.votes.len(), 0);
    let next = h.vote(VoteKind::Prepare, o[0], 1, &b);
    h.deliver(o[0], WireMessage::Vote(next));
    assert_eq!(h.core.votes.len(), 1);
    // Equivocation: evidence once.
    let v1 = h.vote(VoteKind::Prepare, o[1], 0, &b);
    let v2 = h.vote(VoteKind::Prepare, o[1], 0, &h.block(0, b"B2"));
    h.deliver(o[1], WireMessage::Vote(v1));
    let out = h.deliver(o[1], WireMessage::Vote(v2));
    assert!(matches!(
        evidence(&out)[..],
        [Evidence::VoteEquivocation(..)]
    ));
    let out = h.deliver(o[1], WireMessage::Vote(v2));
    assert!(evidence(&out).is_empty(), "evidence once per key");
    // P forms the PrepareQC from q matching votes and broadcasts it, set A first.
    let v3 = h.vote(VoteKind::Prepare, o[2], 0, &b);
    let v0 = h.vote(VoteKind::Prepare, o[0], 0, &b);
    h.deliver(o[2], WireMessage::Vote(v3));
    let out = h.deliver(o[0], WireMessage::Vote(v0));
    let formed = sent(&out)
        .into_iter()
        .find(|(_, m)| matches!(m, WireMessage::Qc(q) if q.kind == VoteKind::Prepare))
        .expect("PrepareQC broadcast");
    let expected: Vec<PublicKey> = h
        .round(0)
        .order()
        .iter()
        .filter(|i| **i != h.my_idx())
        .map(|i| h.key_at(*i))
        .collect();
    assert_eq!(formed.0, expected);
    assert_eq!(h.core.high_pqc.as_ref().map(|q| q.view), Some(0));
    // P (set A) Commits on it.
    assert_eq!(
        votes_of(&out, VoteKind::Commit).len(),
        0,
        "local delivery to itself"
    );
    assert!(h.core.mine.commit.is_some());
}

#[test]
fn pqc_with_set_b_signer_raises_stage_1() {
    for with_b in [false, true] {
        let mut h = H::new(4, pick::set_a(0));
        let b = h.block(0, b"B");
        let r = h.round(0);
        let mut signers: Vec<ValidatorIndex> = r.set_a().to_vec();
        if with_b {
            signers.retain(|m| *m != h.my_idx());
            signers.push(r.set_b()[0]);
        }
        let qc = h.qc(VoteKind::Prepare, 0, &b, &signers);
        qc_msg(&mut h, qc);
        assert_eq!(h.core.stage, u8::from(with_b));
    }
}

// ---- §6.6–§6.7, §6.12 timeouts and view changes -------------------------------------------------

#[test]
fn timeout_equivocation_and_tc_unicast_to_next_leader() {
    let mut h = H::new(4, pick::set_b(0));
    let o = h.others(1, &[h.leader(1)])[0];
    let b = h.block(0, b"B");
    let t1 = h.timeout(o, 0, None);
    let t2 = h.timeout(o, 0, Some(h.qc_q(VoteKind::Prepare, 0, &b)));
    h.deliver(o, WireMessage::Timeout(Box::new(t1)));
    let out = h.deliver(o, WireMessage::Timeout(Box::new(t2)));
    assert!(matches!(
        evidence(&out)[..],
        [Evidence::TimeoutEquivocation(..)]
    ));
    // A TC from the wire: unicast to L(h, view + 1) (not this node).
    let tc = h.tc_q(0);
    let out = h.deliver(o, WireMessage::Tc(Box::new(tc.clone())));
    let unicast: Vec<_> = sent(&out)
        .into_iter()
        .filter(|(_, m)| matches!(m, WireMessage::Tc(_)))
        .collect();
    assert_eq!(unicast.len(), 1);
    assert_eq!(unicast[0].0, vec![h.key_at(h.leader(1))]);
    // The same TC again is a cheap reject.
    let out = h.deliver(o, WireMessage::Tc(Box::new(tc)));
    assert!(out.is_empty());
}

/// §6.7 rule 3 (revision 4, Appendix C #37): a TC's `high_pqc` only updates the lock and the
/// want (§6.5 2a, 2c); `q` members timed out of the view, so no Commit forms there.
#[test]
fn det_r4_tc_high_pqc_locks_only() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    let o = h.others(3, &[]);
    let tc = h.tc(0, &[(o[0], Some(pqc.clone())), (o[1], None), (o[2], None)]);
    let out = h.deliver(o[0], WireMessage::Tc(Box::new(tc)));
    assert!(votes(&out).is_empty(), "no Commit from a TC's high_pqc");
    assert_eq!(h.core.high_pqc, Some(pqc));
    assert_eq!(h.core.view, 1);
    assert!(
        h.core.wants.contains_key(&h.bh(&b)),
        "the locked body is wanted"
    );
}

#[test]
fn view_change_keeps_the_locked_execution() {
    let mut h = H::new(4, pick::set_b(0));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    let qc = h.qc_q(VoteKind::Prepare, 0, &b);
    qc_msg(&mut h, qc);
    let tc = h.tc_q(0);
    let out = h.deliver(h.others(1, &[])[0], WireMessage::Tc(Box::new(tc)));
    assert!(
        out.iter()
            .any(|a| matches!(a, Action::DiscardExecution { keep, .. } if *keep == vec![h.bh(&b)]))
    );
    assert!(h.core.exec.contains_key(&h.bh(&b)));
    assert!(h.core.blocks.contains_key(&h.bh(&b)));
}

// ---- §6.3 execution ------------------------------------------------------------------------------

#[test]
fn execution_retries_back_off_and_cancelled_is_retried() {
    // A long view timeout so that the retries finish within the view.
    let local = LocalParams {
        t_base: 20_000,
        ..LocalParams::default()
    };
    let mut h = H::with(4, local, ChainParams::default(), pick::set_a(0));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    let bh = h.bh(&b);
    let mut delays = Vec::new();
    for _ in 0..5 {
        let out = h.exec(bh, ExecOutcome::Failed("io".into()));
        assert_eq!(faults(&out), vec![LocalFault::ExecutorFailed { height: 1 }]);
        let start = h.now;
        let wake = h
            .core
            .deadlines()
            .into_iter()
            .find_map(|(name, at)| (name == "exec").then_some(at).flatten())
            .expect("an execution retry is scheduled");
        h.run_until(wake);
        assert_eq!(h.pending_exec.len(), 1);
        delays.push(wake - start);
    }
    assert_eq!(
        delays,
        vec![100, 200, 400, 500, 500],
        "doubling, capped at rebroadcast_interval"
    );
    let out = h.exec(bh, ExecOutcome::Cancelled);
    assert!(
        faults(&out).is_empty(),
        "a Cancelled answer is retried without a fault"
    );
    h.run_until(h.now + 500);
    let (_, req, _) = h.pending_exec[0].clone();
    // Unknown or stale answers are ignored.
    let out = h.fire(Event::Executed {
        block_hash: bh,
        req: req + 100,
        outcome: ExecOutcome::Invalid,
    });
    assert!(out.is_empty());
    h.exec_all();
    assert_eq!(votes_of(&h.all, VoteKind::Prepare).len(), 1);
}

/// Resource contract (`specs/zk_resource_contract.json`, class `local_defer`): an executor
/// that lacks a local resource defers. The validator signs no Prepare vote and no timeout
/// vote, rejects no payload and reports no evidence; the same block is then executed and
/// voted. Only a deterministic invalid outcome rejects, and validators at different committee
/// positions with different node-local settings reach the same verdict on the same block.
#[test]
fn local_resource_failure_defers_without_vote_and_invalid_rejects_deterministically() {
    fn start(position: impl Fn(&Topology) -> ValidatorIndex, t_base: u64) -> (H, Hash32) {
        // A long view timeout so that the retries finish within the view.
        let local = LocalParams {
            t_base,
            ..LocalParams::default()
        };
        let mut h = H::with(4, local, ChainParams::default(), position);
        let b = h.block(0, b"B");
        prop(&mut h, 0, &b, None);
        let bh = h.bh(&b);
        (h, bh)
    }
    let rejected = |actions: &[Action]| {
        actions
            .iter()
            .filter(|a| matches!(a, Action::PayloadRejected { .. }))
            .count()
    };
    // Deferred: a local fault, a scheduled retry and nothing signed.
    let (mut h, bh) = start(pick::set_a(0), 20_000);
    for _ in 0..3 {
        let out = h.exec(bh, ExecOutcome::Failed("execution pool exhausted".into()));
        assert_eq!(faults(&out), vec![LocalFault::ExecutorFailed { height: 1 }]);
        assert!(votes_of(&out, VoteKind::Prepare).is_empty());
        assert!(timeouts(&out).is_empty() && evidence(&out).is_empty());
        assert_eq!(rejected(&out), 0);
        assert!(h.my_sigs(crate::preimage::KIND_PREPARE, 1, 0).is_empty());
        assert!(h.my_sigs(crate::preimage::KIND_TIMEOUT, 1, 0).is_empty());
        let wake = h
            .core
            .deadlines()
            .into_iter()
            .find_map(|(name, at)| (name == "exec").then_some(at).flatten())
            .expect("the deferred execution is retried");
        h.run_until(wake);
        assert_eq!(h.pending_exec.len(), 1, "the same block is executed again");
    }
    // The resource returns: the unchanged block is executed and voted.
    h.exec_all();
    assert_eq!(h.my_sigs(crate::preimage::KIND_PREPARE, 1, 0).len(), 1);
    assert_eq!(rejected(&h.all), 0);
    assert!(h.my_sigs(crate::preimage::KIND_TIMEOUT, 1, 0).is_empty());

    // Invalid: one rejection and one timeout vote, no Prepare vote and no local fault. The
    // verdict is taken on three different validators of the committee, each with its own
    // node-local view timeout: local position and local settings change nothing.
    let verdict = |position: &dyn Fn(&Topology) -> ValidatorIndex, t_base: u64| {
        let (mut h, bh) = start(position, t_base);
        let me = h.me;
        let out = h.exec(bh, ExecOutcome::Invalid);
        (
            me,
            (
                rejected(&out),
                timeouts(&out).len(),
                votes_of(&out, VoteKind::Prepare).len(),
                faults(&out),
                h.my_sigs(crate::preimage::KIND_PREPARE, 1, 0).len(),
            ),
        )
    };
    let (first, first_verdict) = verdict(&pick::set_a(0), 20_000);
    let (second, second_verdict) = verdict(&pick::proxy_tail(0), 35_000);
    let (third, third_verdict) = verdict(&pick::set_b(0), 50_000);
    assert!(
        first != second && second != third && first != third,
        "three different validators"
    );
    assert_eq!(first_verdict, (1, 1, 0, Vec::new(), 0));
    assert_eq!(second_verdict, first_verdict, "the proxy tail agrees");
    assert_eq!(third_verdict, first_verdict, "a set-B validator agrees");
}

#[test]
fn bodies_only_when_wanted() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    let out = h.fire(Event::BodyAvailable { block: b.clone() });
    assert!(out.is_empty());
    let out = h.deliver(
        h.others(1, &[])[0],
        WireMessage::PayloadManifest(manifest(&b)),
    );
    assert!(out.is_empty());
    assert!(h.core.blocks.is_empty());
}

// ---- §6.10 work-driven proposing ----------------------------------------------------------------

#[test]
fn idle_payload_wait_and_payload_ready() {
    let mut h = H::new(4, pick::leader(0));
    h.run_until(1_000);
    let first = h.last_build.expect("the view-0 build");
    let out = h.built(b"");
    assert!(
        proposals(&out).is_empty(),
        "an empty payload waits for the idle interval"
    );
    let out = h.run_until(2_000);
    assert!(!out.iter().any(|a| matches!(a, Action::BuildPayload { .. })));
    // A PayloadReady for another request changes nothing.
    let out = h.fire(Event::PayloadReady { req: first + 100 });
    assert!(out.is_empty());
    let out = h.payload_ready();
    assert!(out.iter().any(|a| matches!(a, Action::BuildPayload { .. })));
    let second = h.last_build.unwrap();
    assert_ne!(second, first, "a new request id");
    // A stale answer to the first request is ignored.
    let out = h.fire(Event::PayloadBuilt {
        req: first,
        payload: h.payload(b"stale"),
    });
    assert!(proposals(&out).is_empty());
    let out = h.built(b"tx");
    assert_eq!(
        h.bodies[&proposals(&out)[0].block_hash(&h.v.crypto)]
            .payload()
            .as_slice(),
        &b"tx"[..]
    );

    // Empty answers and build deadlines never manufacture a block.
    let mut h = H::new(4, pick::leader(0));
    let out = h.run_until(20_000);
    assert!(proposals(&out).is_empty());
    assert_eq!(h.core.tip.height, 0);
}

#[test]
fn oversized_payload_waits_for_bounded_rebuild() {
    let params = ChainParams {
        max_block_bytes: 8,
        ..ChainParams::default()
    };
    let local = LocalParams {
        sync_max_bytes: 1 << 20,
        ..LocalParams::default()
    };
    let mut h = H::with(4, local, params, pick::leader(0));
    h.run_until(1_000);
    h.built(&[1; 9]);
    let out = h.run_until(h.params.payload_retry_interval + h.local.build_timeout);
    assert!(proposals(&out).is_empty());
    assert_eq!(h.core.tip.height, 0);
}

/// Proposer stage of the resource contract (`specs/zk_resource_contract.json`,
/// `block.max_block_bytes`): the committed payload limit is inclusive for the leader, as it
/// is for the follower's signed-header check.
#[test]
fn payload_at_the_committed_limit_is_proposed_and_one_byte_over_is_not() {
    let params = ChainParams {
        max_block_bytes: 8,
        ..ChainParams::default()
    };
    let local = LocalParams {
        sync_max_bytes: 1 << 20,
        ..LocalParams::default()
    };
    let mut h = H::with(4, local, params, pick::leader(0));
    h.run_until(1_000);
    let out = h.built(&[1; 8]);
    let proposed = proposals(&out);
    assert_eq!(
        proposed.len(),
        1,
        "a payload of exactly the limit is proposed"
    );
    assert_eq!(proposed[0].header.payload_len, 8);

    let mut h = H::with(4, local, params, pick::leader(0));
    h.run_until(1_000);
    let out = h.built(&[1; 9]);
    assert!(
        proposals(&out).is_empty(),
        "one byte over is never proposed"
    );
}

#[test]
fn det_r4_payload_ready_moves_no_timer() {
    // A non-leader's queue never moves its view timer (§9.1): the view-0 deadline stays at
    // t_enter + P(0) + T.
    let mut h = H::new(4, pick::set_b(0));
    let before = h.core.view_deadline();
    h.now = 100;
    h.fire(Event::PayloadReady { req: 0 });
    let expected = h.params.payload_retry_interval + h.local.build_timeout + h.local.t_base;
    assert_eq!(before, Some(expected));
    assert_eq!(h.core.view_deadline(), Some(expected));
}

#[test]
fn leader_repushes_to_members_lacking_the_proposal() {
    let mut h = H::new(4, pick::leader(0));
    h.run_until(1_000);
    h.built(b"tx");
    let lagging = h.others(1, &[])[0];
    h.now += h.local.rebroadcast_interval + 1;
    h.deliver(lagging, WireMessage::Status(Box::new(empty_status(1, 0))));
    let out = h.run_until(h.now + h.local.rebroadcast_interval);
    let pushed: Vec<_> = sent(&out)
        .into_iter()
        .filter(|(_, m)| matches!(m, WireMessage::Proposal(_)))
        .collect();
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0].0, vec![h.key_at(lagging)]);
    let out = h.run_until(h.now + 3 * h.local.rebroadcast_interval);
    assert!(proposals(&out).is_empty(), "once per member per view");
}

#[test]
fn boundary_proposals_use_only_the_applied_committee() {
    let mut h = H::new(5, |_| 0);
    let keys: Vec<PublicKey> = (0..5).map(|i| h.v.key(i)).collect();
    h.committees
        .insert(0, Committee::new(keys[..4].to_vec()).unwrap());
    h.committees
        .insert(2, Committee::new(keys[1..].to_vec()).unwrap());
    h.restart();
    // Force this node to lead by entering views until it is the leader.
    let mut view = 0;
    while h.leader(view) != h.my_idx() {
        view += 1;
    }
    if view > 0 {
        h.enter_view(view);
    } else {
        h.run_until(h.now + h.params.block_time);
    }
    h.built(b"committee transition transaction");
    let broadcast = sent(&h.all)
        .into_iter()
        .find(|(_, m)| matches!(m, WireMessage::Proposal(_)))
        .expect("proposal");
    assert!(
        h.core.config(2).is_none(),
        "successor authority awaits the applied boundary"
    );
    assert!(
        !broadcast.0.contains(&keys[4]),
        "an unapplied successor cannot become an authenticated proposal recipient"
    );
    h.commit_with(view, b"authenticated committee boundary");
    assert_eq!(h.core.cfg.committee, h.config(2).committee);
    assert!(h.core.cfg.committee.contains(&keys[4]));
}

// ---- §6.9 sync and serving ------------------------------------------------------------------------

#[test]
fn sync_ignores_unsolicited_and_drops_empty_hints() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    let entry = crate::message::SyncEntry {
        manifest: manifest(&b),
        commit_qc: h.qc_q(VoteKind::Commit, 0, &b),
    };
    let o = h.others(2, &[]);
    h.deliver(
        o[0],
        WireMessage::SyncResponse(SyncResponse {
            instance: I,
            blocks: vec![entry],
        }),
    );
    assert_eq!(h.core.tip.height, 0, "unsolicited responses are dropped");
    // Two members hint at height 9 (unverifiable); both answer with nothing.
    let mut qc = h.qc_q(VoteKind::Commit, 0, &b);
    qc.height = 9;
    for peer in &o {
        h.deliver(*peer, WireMessage::Qc(qc.clone()));
    }
    for _ in 0..2 {
        let target = h
            .core
            .sync
            .outstanding_peer()
            .expect("a request is outstanding");
        let from = h.committee().index_of(&target).unwrap();
        h.deliver(
            from,
            WireMessage::SyncResponse(SyncResponse {
                instance: I,
                blocks: Vec::new(),
            }),
        );
    }
    assert_eq!(h.core.sync.target(), 0, "the hint is dropped");
}

#[test]
fn serving_requests() {
    let mut h = H::new(4, pick::set_a(0));
    let o = h.others(1, &[])[0];
    let out = h.deliver(
        o,
        WireMessage::SyncRequest(SyncRequest {
            instance: I,
            from_height: 3,
            max_count: u16::MAX,
            max_bytes: u32::MAX,
        }),
    );
    assert!(matches!(
        out[..],
        [Action::ServeBlocks { from_height: 3, max_count, max_bytes, .. }]
            if max_count == h.local.sync_batch && max_bytes == h.local.sync_max_bytes
    ));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    let out = h.deliver(
        o,
        WireMessage::PayloadRequest(PayloadRequest {
            instance: I,
            height: 1,
            block_hash: h.bh(&b),
        }),
    );
    assert!(out.iter().any(|action| matches!(action,
        Action::ServePayload { to, height: 1, block_hash }
            if *to == h.v.key(o) && *block_hash == h.bh(&b)
    )));
    assert!(
        !out.iter()
            .any(|action| matches!(action, Action::DisseminatePayload { .. })),
        "a cached requested body must still use the per-requester serving path"
    );
    let expected: Vec<_> = out
        .into_iter()
        .filter(|action| matches!(action, Action::ServePayload { .. }))
        .collect();
    let hash = h.bh(&b);
    assert!(
        h.core.blocks.remove(&hash).is_some(),
        "exercise cached-body case first"
    );
    let uncached = h.deliver(
        o,
        WireMessage::PayloadRequest(PayloadRequest {
            instance: I,
            height: 1,
            block_hash: hash,
        }),
    );
    let actual: Vec<_> = uncached
        .into_iter()
        .filter(|action| matches!(action, Action::ServePayload { .. }))
        .collect();
    assert_eq!(
        actual, expected,
        "cache residency does not change request ownership or quota"
    );
}

// ---- §9.4, §12.1 configuration and startup -----------------------------------------------------------

#[test]
fn config_too_tight_is_a_local_fault() {
    let mut h = H::new(4, pick::set_b(0));
    h.params.e_max = 20_000;
    h.commit_heights(2);
    let t_req = crate::pacemaker::t_req_nominal(&h.local, &h.params, 4);
    assert!(t_req > h.local.t_max);
    assert!(faults(&h.all).contains(&LocalFault::ConfigTooTight { t_req }));
    assert_eq!(h.core.pm.t_max_eff(), t_req);
}

#[test]
fn startup_rejects_bad_input() {
    let h = H::new(4, pick::set_a(0));
    let signers =
        || -> Vec<std::sync::Arc<dyn Signer>> { vec![std::sync::Arc::new(h.signers[0].clone())] };
    let key = h.signers[0].public_key().clone();
    let fresh = vec![(
        key.clone(),
        RecordState::Present(initial_record(&h.v, &key)),
        false,
    )];
    let new = |init: Init, local: LocalParams, signers: Vec<std::sync::Arc<dyn Signer>>| {
        Core::new(
            local,
            init,
            signers,
            Box::new(h.v.crypto.clone()),
            h.budget.clone(),
            0,
        )
        .map(|_| ())
    };
    assert_eq!(new(h.init(fresh.clone()), h.local, signers()), Ok(()));
    let mut init = h.init(fresh.clone());
    init.configs.retain(|(height, _)| *height != 2);
    assert_eq!(
        new(init, h.local, signers()),
        Err(ConfigError::InvalidInit(
            "next epoch must await its applied boundary"
        ))
    );
    let mut init = h.init(fresh.clone());
    init.tip.block_hash = Hash32([1; 32]);
    init.tip.header = Some(h.block(0, b"x").header().clone());
    assert!(matches!(
        new(init, h.local, signers()),
        Err(ConfigError::InvalidInit(_))
    ));
    let init = h.init(Vec::new());
    assert!(matches!(
        new(init, h.local, signers()),
        Err(ConfigError::InvalidInit(_))
    ));
    // A retired key has no signer; a configured one needs one; no key twice.
    let mut retired = fresh.clone();
    retired[0].2 = true;
    assert!(matches!(
        new(h.init(retired.clone()), h.local, signers()),
        Err(ConfigError::InvalidInit(_))
    ));
    assert_eq!(new(h.init(retired), h.local, Vec::new()), Ok(()));
    assert!(matches!(
        new(h.init(fresh.clone()), h.local, Vec::new()),
        Err(ConfigError::InvalidInit(_))
    ));
    let twice = [fresh.clone(), fresh.clone()].concat();
    assert!(matches!(
        new(h.init(twice), h.local, signers()),
        Err(ConfigError::InvalidInit(_))
    ));
    // `W` is a genesis constant and must be at least 1 (§9.4).
    let mut init = h.init(fresh.clone());
    init.demotion_window = 0;
    assert_eq!(
        new(init, h.local, signers()),
        Err(ConfigError::DemotionWindowZero)
    );
    let local = LocalParams {
        rebroadcast_interval: 5_000,
        ..h.local
    };
    assert_eq!(
        new(h.init(fresh), local, signers()),
        Err(ConfigError::RebroadcastTooLong)
    );
}

/// `check_init` at a committed tip: a hash-consistent tip header of an epoch other than `C_t`'s,
/// and a tip whose `t + 2` overflows, are refused.
#[test]
fn startup_rejects_foreign_tip_epoch_and_height_overflow() {
    let mut h = H::new(4, pick::set_a(0));
    h.commit_heights(2);
    let key = h.signers[0].public_key().clone();
    let state = RecordState::Present(h.records[&key].clone());
    let new = |init: Init| {
        let signers: Vec<std::sync::Arc<dyn Signer>> =
            vec![std::sync::Arc::new(h.signers[0].clone())];
        Core::new(
            h.local,
            init,
            signers,
            Box::new(h.v.crypto.clone()),
            h.budget.clone(),
            0,
        )
        .map(|_| ())
    };
    let valid = h.init(vec![(key, state, false)]);
    assert!(valid.tip.height > valid.genesis_height);
    assert_eq!(new(valid.clone()), Ok(()));
    let mut foreign = valid.clone();
    let header = foreign.tip.header.as_mut().unwrap();
    header.epoch.epoch += 1;
    foreign.tip.block_hash = header.hash(&h.v.crypto);
    assert_eq!(
        new(foreign),
        Err(ConfigError::InvalidInit(
            "noncontiguous authenticated epoch window"
        ))
    );
    let mut overflow = valid;
    overflow.tip.height = u64::MAX - 1;
    let header = overflow.tip.header.as_mut().unwrap();
    header.height = u64::MAX - 1;
    overflow.tip.block_hash = header.hash(&h.v.crypto);
    overflow.configs.clear();
    assert_eq!(
        new(overflow),
        Err(ConfigError::InvalidInit("height overflow"))
    );
}

#[test]
fn corrupt_record_halts_and_only_serves() {
    let mut h = H::new(4, pick::set_a(0));
    let key = h.signers[0].public_key().clone();
    let out = h.start(vec![(key, RecordState::Present(vec![1, 2, 3]))]);
    assert_eq!(halts(&out), vec![HaltReason::SafetyRecordCorrupt]);
    assert_eq!(h.core.next_wakeup(), Millis::MAX);
    assert_eq!(
        h.core.status().halted,
        Some(HaltReason::SafetyRecordCorrupt)
    );
    let b = h.block(0, b"B");
    let out = prop(&mut h, 0, &b, None);
    assert!(out.is_empty());
    let out = h.deliver(
        h.others(1, &[])[0],
        WireMessage::PayloadRequest(PayloadRequest {
            instance: I,
            height: 1,
            block_hash: h.bh(&b),
        }),
    );
    assert!(matches!(out[..], [Action::ServePayload { .. }]));
}

#[test]
fn observer_follows_without_signing() {
    // The core's key is not in the committee.
    let mut h = H::new(5, |_| 4);
    let keys: Vec<PublicKey> = (0..5).map(|i| h.v.key(i)).collect();
    h.committees
        .insert(0, Committee::new(keys[..4].to_vec()).unwrap());
    h.restart();
    assert!(h.core.status().signer.is_none());
    h.commit_heights(3);
    h.run_until(h.now + 30_000);
    assert_eq!(h.core.tip.height, 3);
    assert!(h.log.signatures_by(&keys[4]).is_empty());
    assert!(
        !status_to(&h.all).is_empty(),
        "observers still send Status to the members"
    );
}

#[test]
fn tick_consumes_every_deadline() {
    let mut h = H::new(4, pick::leader(0));
    let mut last = 0;
    for _ in 0..2_000 {
        let wake = h.core.next_wakeup();
        assert!(wake >= last, "deadlines never move backwards past a tick");
        h.now = wake;
        h.fire(Event::Tick);
        assert!(h.core.next_wakeup() > h.now);
        last = h.now;
        if h.now > 600_000 {
            break;
        }
    }
    assert!(h.now > 100_000, "time advances");
}

/// Actual received row provenance survives Core dispatch independently of original authorship.
#[test]
fn wanted_row_preserves_authenticated_relay_and_intake_filters() {
    let mut h = H::new(4, pick::set_a(0));
    let body = h.block(0, b"original availability bytes");
    let bh = body.hash(&h.v.crypto);
    let shape = body
        .source()
        .config()
        .epoch
        .da_layout
        .shape(body.header().payload_len.into())
        .unwrap();
    let encoded = iroha_primitives::erasure::rs16::compact::encode_funded(
        shape,
        body.payload().as_slice(),
        &h.budget,
    )
    .unwrap();
    let bytes = encoded.codeword()[shape.chunk_range(0).unwrap()].to_vec();
    let mut chunk = PayloadChunk {
        instance: I,
        height: 1,
        block_hash: bh,
        index: 0,
        bytes: RowBytes::from_untrusted(bytes).unwrap(),
    };
    chunk.bytes.admit(&h.budget).unwrap();
    h.core.want(bh, 1, Vec::new());
    assert!(
        matches!(h.core.out.as_slice(), [Action::FetchPayload { source, .. }] if source.block_hash() == bh)
    );
    h.core.out.clear(); // The fixture has dispatched the initial acquisition request.
    let relays = [h.v.key(1), PublicKey::new(vec![0xfa; 32]).unwrap()];
    for relay in relays {
        let actions = h.core.handle(
            h.now,
            Event::Message {
                from: relay.clone(),
                msg: WireMessage::PayloadChunk(chunk.clone()),
            },
        );
        assert_eq!(
            actions,
            vec![Action::ReceivePayloadChunk {
                from: relay,
                chunk: chunk.clone()
            }]
        );
        assert!(
            h.core.blocks.is_empty(),
            "forwarding is not row authentication or body custody"
        );
    }
    let from = h.v.key(2);
    let mut rejects = Vec::new();
    let mut wrong_height = chunk.clone();
    wrong_height.height += 1;
    rejects.push(wrong_height);
    let mut wrong_hash = chunk.clone();
    wrong_hash.block_hash = Hash32::ZERO;
    rejects.push(wrong_hash);
    let mut wrong_instance = chunk.clone();
    wrong_instance.instance = Hash32::ZERO;
    rejects.push(wrong_instance);
    let mut foreign = chunk.clone();
    foreign.bytes = RowBytes::from_untrusted(chunk.bytes.as_slice().to_vec()).unwrap();
    foreign
        .bytes
        .admit(&iroha_allocation::AllocationBudget::new(1 << 20))
        .unwrap();
    rejects.push(foreign);
    for rejected in rejects {
        assert!(
            h.core
                .handle(
                    h.now,
                    Event::Message {
                        from: from.clone(),
                        msg: WireMessage::PayloadChunk(rejected),
                    }
                )
                .is_empty()
        );
    }
}
