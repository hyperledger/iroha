//! Regression tests for issues found by code review: each fails on the code before its fix.

use super::*;
use crate::{
    api::ConfigError,
    message::{Status, SyncEntry, SyncResponse},
    types::{AggregateSignature, SIGNATURE_LEN},
};

fn prop(h: &mut H, view: u64, block: &AvailableBody, justify: Option<TimeoutCert>) -> Vec<Action> {
    let p = h.proposal(view, block, justify);
    h.deliver(h.leader(view), WireMessage::Proposal(Box::new(p)))
}

fn status(height: u64, committed_qc: Option<Qc>) -> WireMessage {
    WireMessage::Status(Box::new(Status {
        instance: I,
        height,
        committed_qc,
        ..Status::default()
    }))
}

fn response(blocks: Vec<SyncEntry>) -> WireMessage {
    WireMessage::SyncResponse(SyncResponse {
        instance: I,
        blocks,
    })
}

/// The committed chain `1..=k` from genesis, as a driver serves it.
fn chain(h: &H, k: u64) -> Vec<SyncEntry> {
    let mut chain = Vec::new();
    let mut parent = (G_HASH, G_RESULT);
    for height in 1..=k {
        let block = h.block_at(height, parent, 0, &height.to_be_bytes());
        let commit_qc = h.cqc_for(&block, 0);
        parent = (h.bh(&block), result_of(&block));
        chain.push(SyncEntry {
            manifest: manifest(&block),
            commit_qc,
        });
    }
    chain
}

/// Well-formed entries for `from..from + count` (block hash, heights and bodies check out)
/// whose `CommitQC`s carry a bogus aggregate signature.
fn junk(h: &H, from: u64, count: u64) -> Vec<SyncEntry> {
    let mut out = Vec::new();
    let mut parent = (Hash32([0x55; 32]), Hash32([0x66; 32]));
    for height in from..from + count {
        let block = h.block_at(height, parent, 0, b"junk");
        let mut commit_qc = h.cqc_for(&block, 0);
        commit_qc.agg_sig = AggregateSignature([7; SIGNATURE_LEN]);
        parent = (h.bh(&block), result_of(&block));
        out.push(SyncEntry {
            manifest: manifest(&block),
            commit_qc,
        });
    }
    out
}

/// The latest `SyncRequest` the core sent: `(peer, from_height)`.
fn last_request(actions: &[Action]) -> Option<(PublicKey, u64)> {
    actions.iter().rev().find_map(|a| match a {
        Action::Send {
            to,
            msg: WireMessage::SyncRequest(r),
        } => Some((to.clone(), r.from_height)),
        _ => None,
    })
}

/// Catch-up of 20 heights from three sources, one of them Byzantine. Before every honest
/// answer the Byzantine source sends well-formed entries with forged `CommitQC`s for the
/// heights above `h` and from `h`, and replays its unanswered requests with forged entries.
/// It answers its own requests with forged entries (`answers_own`) or stays silent.
fn catch_up_against_junk(answers_own: bool) -> H {
    let mut h = H::new(4, pick::set_a(0));
    let good = chain(&h, 20);
    let o = h.others(3, &[]);
    let byz = o[0];
    let byz_key = h.key_at(byz);
    // All three report CommitQC(20): a hint (C_20 is unknown), the Byzantine one first.
    for peer in &o {
        h.deliver(*peer, status(21, Some(good[19].commit_qc.clone())));
    }
    let mut unanswered: Vec<u64> = Vec::new();
    for _ in 0..60 {
        if h.core.tip.height == 20 {
            break;
        }
        let Some((to, from_height)) = last_request(&h.all)
            .filter(|(to, _)| h.core.sync.outstanding_peer().as_ref() == Some(to))
        else {
            h.tick(h.local.sync_retry);
            continue;
        };
        let next = h.core.tip.height + 1;
        if to == byz_key {
            if answers_own {
                h.deliver(byz, response(junk(&h, from_height, 128)));
            } else {
                unanswered.push(from_height);
                h.tick(h.local.sync_retry);
            }
            continue;
        }
        h.deliver(byz, response(junk(&h, next + 1, 128)));
        h.deliver(byz, response(junk(&h, next, 128)));
        for from in std::mem::take(&mut unanswered) {
            h.deliver(byz, response(junk(&h, from, 128)));
        }
        let honest = h.committee().index_of(&to).unwrap();
        let start = usize::try_from(from_height - 1).unwrap();
        let end = (start + 64).min(good.len());
        h.deliver(honest, response(good[start..end].to_vec()));
    }
    h
}

/// §6.9 rule 3 as written: a source asked once was heard for good and a buffered entry was
/// never replaced, so forged entries above `h` filled the buffer, never reached their turn,
/// and every honest answer was dropped; catch-up stopped for good. It must complete.
#[test]
fn review_sync_junk_from_an_asked_source_cannot_block_catch_up() {
    for answers_own in [true, false] {
        let h = catch_up_against_junk(answers_own);
        assert_eq!(h.core.tip.height, 20, "catch-up completes ({answers_own})");
        assert!(halts(&h.all).is_empty());
    }
}

/// §6.9 rule 3: a response answers one unanswered request to its peer and starts at that
/// request's `from_height`; a second response of the same peer, or one from another height,
/// is dropped.
#[test]
fn review_sync_response_answers_one_request_only() {
    let mut h = H::new(4, pick::set_a(0));
    let good = chain(&h, 3);
    let o = h.others(2, &[]);
    let (byz, honest) = (o[0], o[1]);
    h.deliver(byz, status(4, Some(good[2].commit_qc.clone())));
    h.deliver(honest, status(4, Some(good[2].commit_qc.clone())));
    assert_eq!(
        last_request(&h.all),
        Some((h.key_at(byz), 1)),
        "the first source is asked from 1"
    );
    // A response starting at another height answers nothing.
    h.deliver(byz, response(good[1..].to_vec()));
    assert_eq!(h.core.tip.height, 0, "not from the requested height");
    // The answer: forged entries from 1, dropped at their turn; the next source is asked.
    h.deliver(byz, response(junk(&h, 1, 3)));
    assert_eq!(h.core.tip.height, 0);
    assert_eq!(last_request(&h.all), Some((h.key_at(honest), 1)));
    // The same peer again (its request is answered): dropped, whatever it carries.
    h.deliver(byz, response(good.clone()));
    assert_eq!(
        h.core.tip.height, 0,
        "a second response of the same request"
    );
    // The honest answer commits.
    h.deliver(honest, response(good.clone()));
    assert_eq!(h.core.tip.height, 3);
    assert!(halts(&h.all).is_empty());
}

/// §6.9 rule 2: sources are the senders of target `CommitQC`s and *members* whose `Status`
/// shows a higher height; an observer's `Status` never makes it a sync source.
#[test]
fn review_sync_observer_is_never_a_candidate() {
    let mut h = H::new(4, pick::set_a(0));
    let good = chain(&h, 20);
    let observer = FakeSigner::from_seed(b"review observer", None)
        .public_key()
        .clone();
    assert!(!h.committee().contains(&observer));
    h.deliver_key(observer.clone(), status(21, None));
    let member = h.others(1, &[])[0];
    h.deliver(member, status(21, Some(good[19].commit_qc.clone())));
    // The member stays silent: the request is retried, never to the observer.
    for _ in 0..4 {
        h.tick(h.local.sync_retry);
    }
    let asked: Vec<PublicKey> = sent(&h.all)
        .into_iter()
        .filter(|(_, m)| matches!(m, WireMessage::SyncRequest(_)))
        .flat_map(|(to, _)| to)
        .collect();
    assert!(!asked.is_empty(), "the member is asked");
    assert!(!asked.contains(&observer), "the observer is never asked");
}

/// §12.1: `Init.configs` holds the configurations of `t` (unless `t = g`), `t + 1` and `t + 2`
/// only. One for `t + 3` let commits run ahead of apply by more than two heights (§10.2), and
/// the next in-order `BlockApplied` halted the core as a driver anomaly.
#[test]
fn review_init_configs_beyond_t_plus_2_are_refused() {
    let h = H::new(4, pick::set_a(0));
    let key = h.signers[0].public_key().clone();
    let records = vec![(
        key.clone(),
        RecordState::Present(initial_record(&h.v, &key)),
        false,
    )];
    let start = |init: Init| {
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
    assert!(start(h.init(records.clone())).is_ok(), "t + 1 and t + 2");
    let mut extra = h.init(records.clone());
    extra
        .configs
        .push((3, crate::types::ConfigSlot::Ready(h.config(3))));
    assert!(matches!(start(extra), Err(ConfigError::InvalidInit(_))));
    let mut twice = h.init(records.clone());
    twice
        .configs
        .push((2, crate::types::ConfigSlot::Ready(h.config(2))));
    assert!(matches!(start(twice), Err(ConfigError::InvalidInit(_))));
}

/// With the extra configurations passed anyway by a driver that knows a static committee, the
/// old core committed three heights ahead of apply and then halted on the honest in-order
/// `BlockApplied(1)` (`DriverAnomaly`). The refusal above prevents that; the invariant
/// `tip ≤ applied + 2` holds through a catch-up with immediate applies.
#[test]
fn review_catch_up_keeps_commits_within_two_of_apply() {
    let mut h = H::new(4, pick::set_a(0));
    let good = chain(&h, 10);
    let peer = h.others(1, &[])[0];
    h.deliver(peer, status(11, Some(good[9].commit_qc.clone())));
    h.deliver(peer, response(good.clone()));
    assert_eq!(h.core.tip.height, 10);
    assert!(h.core.tip.height <= h.core.applied + 2);
    assert!(halts(&h.all).is_empty());
}

/// §7.4 step 4 (E2) for every key: a retired key's record at `t + 1` whose parent `CommitQC`
/// names another block at `t` contradicts the block store and halts the instance, although
/// that key never signs.
#[test]
fn review_retired_key_record_inconsistent_with_the_store_halts() {
    let mut h = H::new(4, pick::leader(0));
    h.commit_heights(2);
    let height = h.height();
    // Time out at the current height: a record with the parent CommitQC becomes durable.
    let until = h.now + 30_000;
    h.run_until(until);
    let mut record = h.durable().expect("a durable record");
    assert_eq!(record.height, height);
    let key = h.signers[0].public_key().clone();
    // The key is retired before the restart (the node keeps running as an observer).
    h.retired = vec![key.clone()];
    h.signers.clear();
    let out = h.start(Vec::new());
    assert!(
        halts(&out).is_empty(),
        "the unmodified record is consistent"
    );
    let mut forged = record.parent_commit_qc.clone().expect("parent CommitQC");
    forged.block_hash = Hash32([0x66; 32]);
    record.parent_commit_qc = Some(forged);
    h.records
        .insert(key, record.encode(&h.v.crypto).expect("encode"));
    let out = h.start(Vec::new());
    assert_eq!(halts(&out), vec![HaltReason::SafetyRecordInconsistent]);
}

/// §6.3 / §4.3 condition 3: only the proposal of the current view is acted on. With a held
/// proposal of an older view (the invariant "a view change clears it" broken), neither a
/// `Valid` outcome signs a Prepare nor an `Invalid` one times the current view out.
#[test]
fn review_stale_view_proposal_outcome_is_ignored() {
    let mut h = H::new(4, pick::proxy_tail(0));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    let (bh, req, _) = h.pending_exec.pop().expect("Execute");
    // Break the invariant: view 1 without clearing the held proposal of view 0.
    h.core.view = 1;
    h.core.rnd = h.core.topo.round(1);
    let out = h.fire(Event::Executed {
        block_hash: bh,
        req,
        outcome: ExecOutcome::Invalid,
    });
    assert!(timeouts(&out).is_empty(), "no early timeout of view 1");
    assert!(
        !out.iter()
            .any(|a| matches!(a, Action::PayloadRejected { .. })),
        "{out:?}"
    );
    h.core
        .exec
        .insert(bh, super::super::ExecState::Valid(result_of(&b)));
    h.core.maybe_execute();
    assert!(votes(&h.core.out).is_empty(), "no Prepare for view 1");
}

/// §7.4 R4 with §5.2 (b): a set-B member restored with the lock `PrepareQC(v)` of the current
/// view that includes a set-B signer is at stage 1, so the final `try_commit()` of the restore
/// re-signs its Commit at once (not only at stage 2).
#[test]
fn review_restored_set_b_lock_re_signs_the_commit() {
    let mut h = H::new(4, pick::set_b(0));
    let me = h.my_idx();
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    let leader = h.leader(0);
    let other = h.others(1, &[leader])[0];
    let pqc = h.qc(VoteKind::Prepare, 0, &b, &[leader, other, me]);
    let out = h.deliver(other, WireMessage::Qc(pqc.clone()));
    let first = votes_of(&out, VoteKind::Commit);
    assert_eq!(first.len(), 1, "stage 1 by the set-B signer: Commit");
    assert_eq!(h.durable().unwrap().lock, Some(pqc));
    // Crash before the Commit left the node; restart with the durable record.
    let out = h.restart();
    assert_eq!(
        votes_of(&out, VoteKind::Commit),
        first,
        "the identical Commit is re-signed at restore"
    );
}

/// §7.4 R4 with §5.2 (a): a set-B member restored with a lock of the current view signed by
/// set A only holds that `PrepareQC` from the restart on, so its stage-1 timer
/// `t_pqc + t_retx` runs and the Commit is re-signed then (not only at stage 2).
#[test]
fn review_restored_lock_arms_the_stage_one_timer() {
    let mut h = H::new(4, pick::set_b(0));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    h.deliver(h.others(1, &[])[0], WireMessage::Qc(pqc));
    let t_retx = h.core.status().t_retx;
    let signed = h.run_until(h.now + t_retx);
    let first = votes_of(&signed, VoteKind::Commit);
    assert_eq!(first.len(), 1, "stage 1 at t_pqc + t_retx: Commit");
    let out = h.restart();
    assert!(
        votes_of(&out, VoteKind::Commit).is_empty(),
        "no set-B signer"
    );
    let t_retx = h.core.status().t_retx;
    let out = h.run_until(h.now + t_retx);
    assert_eq!(
        votes_of(&out, VoteKind::Commit),
        first,
        "re-signed at restart + t_retx"
    );
}

/// E28: one Byzantine member signing defective proposals for far-future views (a signed
/// defect needs no TC) filled the whole evidence cap with keys that are never pruned within
/// the height; evidence of another member's equivocation was then dropped.
#[test]
fn review_far_future_evidence_cannot_crowd_out_other_evidence() {
    let mut h = H::new(4, pick::set_a(0));
    let me = h.my_idx();
    let byz = h.others(1, &[])[0];
    let mut defects = 0;
    for view in 2..2_000 {
        if h.leader(view) != byz {
            continue;
        }
        let block = h.block(view, b"x");
        let p = h.proposal_by(byz, view, &block, None);
        let out = h.deliver(byz, WireMessage::Proposal(Box::new(p)));
        defects += evidence(&out).len();
        if defects >= 60 {
            break;
        }
    }
    assert!(defects >= 1, "far-future signed defects are evidence");
    // A genuine Prepare equivocation of another member at the current view.
    let x = h.others(1, &[byz])[0];
    assert_ne!(x, me);
    let b = h.block(0, b"B");
    let c = h.block(0, b"C");
    h.deliver(x, WireMessage::Vote(h.vote(VoteKind::Prepare, x, 0, &b)));
    let out = h.deliver(x, WireMessage::Vote(h.vote(VoteKind::Prepare, x, 0, &c)));
    assert!(
        matches!(&evidence(&out)[..], [Evidence::VoteEquivocation(..)]),
        "{:?}",
        evidence(&out)
    );
}

/// Rebuild polling cannot use a zero interval.
#[test]
fn review_zero_payload_retry_refused_at_start() {
    let h = H::new(4, pick::leader(0));
    let key = h.signers[0].public_key().clone();
    let records = vec![(
        key.clone(),
        RecordState::Present(initial_record(&h.v, &key)),
        false,
    )];
    let mut init = h.init(records);
    for (_, config) in &mut init.configs {
        if let crate::types::ConfigSlot::Ready(config) = config {
            config.params.payload_retry_interval = 0;
            config.params.block_time = 0;
        }
    }
    let signers: Vec<std::sync::Arc<dyn Signer>> = vec![std::sync::Arc::new(h.signers[0].clone())];
    let started = Core::new(
        h.local,
        init,
        signers,
        Box::new(h.v.crypto.clone()),
        h.budget.clone(),
        0,
    );
    assert!(matches!(
        started,
        Err(ConfigError::PayloadRetryIntervalZero)
    ));
}

/// Every view retains real work and no application setting can force an empty fallback.
#[test]
fn review_leader_preserves_nonempty_payload_at_view_0() {
    let mut h = H::new(4, pick::leader(0));
    h.run_until(h.now + 1_100);
    let out = h.built(b"tx");
    let sent = proposals(&out);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        h.bodies[&sent[0].block_hash(&h.v.crypto)]
            .payload()
            .as_slice(),
        &b"tx"[..]
    );
}

/// E22: a zero `build_timeout` is refused (it answered every build with `EMPTY` before the
/// builder could, so the leader never proposed a transaction).
#[test]
fn review_zero_build_timeout_refused() {
    let h = H::new(4, pick::leader(0));
    let key = h.signers[0].public_key().clone();
    let records = vec![(
        key.clone(),
        RecordState::Present(initial_record(&h.v, &key)),
        false,
    )];
    let local = LocalParams {
        build_timeout: 0,
        ..h.local
    };
    let signers: Vec<std::sync::Arc<dyn Signer>> = vec![std::sync::Arc::new(h.signers[0].clone())];
    let started = Core::new(
        local,
        h.init(records),
        signers,
        Box::new(h.v.crypto.clone()),
        h.budget.clone(),
        0,
    );
    assert!(matches!(
        started,
        Err(ConfigError::ZeroInterval("build_timeout"))
    ));
}
