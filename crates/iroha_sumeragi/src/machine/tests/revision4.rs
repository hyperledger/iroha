//! Focused regression tests of the revision-4 / 4.1 changes that §13.4 does not name
//! (`det_r4_*`); the named ones live with their rule groups (`safety`, `liveness`, `cluster`).

use super::*;
use crate::{
    message::{Echo, PayloadRequest, Status, SyncEntry, SyncResponse},
    preimage::KIND_COMMIT,
};

fn prop(h: &mut H, view: u64, block: &AvailableBody, justify: Option<TimeoutCert>) -> Vec<Action> {
    let p = h.proposal(view, block, justify);
    h.deliver(h.leader(view), WireMessage::Proposal(Box::new(p)))
}

fn qc_msg(h: &mut H, qc: Qc) -> Vec<Action> {
    let from = h.others(1, &[])[0];
    h.deliver(from, WireMessage::Qc(qc))
}

fn statuses(actions: &[Action]) -> Vec<(Vec<PublicKey>, Status)> {
    sent(actions)
        .into_iter()
        .filter_map(|(to, m)| match m {
            WireMessage::Status(s) => Some((to, *s)),
            _ => None,
        })
        .collect()
}

fn deadline(h: &H, name: &str) -> Option<Millis> {
    h.core
        .deadlines()
        .into_iter()
        .find_map(|(n, at)| (n == name).then_some(at).flatten())
}

/// §3.5: the new `Status` fields; while awaiting a node reports `tip.height + 1`, view 0, the
/// tip's `CommitQC` and nothing else; after a late entry without a proposal it asks the leader
/// (`want_proposal`).
#[test]
fn det_r4_status_fields_and_awaiting_status() {
    let mut h = H::new(4, pick::at(3, 0, 1));
    h.auto_apply = false;
    h.commit_with(0, b"1");
    h.commit_with(0, b"2");
    assert!(h.core.awaiting);
    let s = h.core.status_message();
    assert_eq!((s.height, s.view), (3, 0));
    assert_eq!(s.committed_qc, h.core.tip.commit_qc);
    assert!(s.high_pqc.is_none() && s.high_tc.is_none() && s.proposal_hash.is_none());
    assert!(!s.want_proposal && s.probe.is_none() && s.echo.is_none());
    // The configuration of 3 arrives: a late entry without a proposal asks L(3, 0) at once.
    let out = h.apply_height(1);
    assert!(!h.core.awaiting && h.core.late_entry);
    let leader = h.key_at(h.leader(0));
    let asked = statuses(&out)
        .into_iter()
        .filter(|(to, s)| *to == vec![leader.clone()] && s.want_proposal)
        .count();
    assert_eq!(asked, 1, "{out:#?}");
    assert!(h.core.status_message().want_proposal);
    // Once the proposal is held, nobody is asked any more.
    let b = h.block(0, b"B3");
    prop(&mut h, 0, &b, None);
    assert!(!h.core.status_message().want_proposal);
}

/// §6.9 rules 1–3: sync responses are processed from any source this node asked (also late,
/// after the request was retried elsewhere); unsolicited ones are dropped; entries below `h` are
/// skipped; the source rotates on every request.
#[test]
fn det_r4_sync_responses_from_requested_sources() {
    let mut h = H::new(4, pick::set_a(0));
    h.auto_apply = false;
    let mut chain = Vec::new();
    let mut parent = (G_HASH, G_RESULT);
    for height in 1..=3u64 {
        let block = h.block_at(height, parent, 0, &height.to_be_bytes());
        let qc = h.cqc_for(&block, 0);
        parent = (h.bh(&block), result_of(&block));
        chain.push(SyncEntry {
            manifest: manifest(&block),
            commit_qc: qc,
        });
    }
    let o = h.others(3, &[]);
    let (p1, p2, stranger) = (o[0], o[1], o[2]);
    let request_to = |out: &[Action]| {
        sent(out).into_iter().find_map(|(to, m)| match m {
            WireMessage::SyncRequest(r) => Some((to, r.from_height)),
            _ => None,
        })
    };
    // Two members hint at height 3 (C_3 unknown: unverified hints).
    let out = h.deliver(p1, WireMessage::Qc(chain[2].commit_qc.clone()));
    assert_eq!(request_to(&out), Some((vec![h.key_at(p1)], 1)));
    h.deliver(p2, WireMessage::Qc(chain[2].commit_qc.clone()));
    // An unsolicited response is dropped.
    let response = |blocks: Vec<SyncEntry>| {
        WireMessage::SyncResponse(SyncResponse {
            instance: I,
            blocks,
        })
    };
    h.deliver(stranger, response(chain.clone()));
    assert_eq!(h.core.tip.height, 0, "unsolicited");
    // p1 does not answer; the retry rotates to p2.
    h.now += h.local.sync_retry;
    let out = h.fire(Event::Tick);
    assert_eq!(request_to(&out), Some((vec![h.key_at(p2)], 1)));
    // p1's late answer is still processed.
    h.deliver(p1, response(chain[..1].to_vec()));
    assert_eq!(h.core.tip.height, 1, "a late response of an earlier source");
    // p2's answer starts below h: entry 1 is skipped, 2 commits.
    h.deliver(p2, response(chain[..2].to_vec()));
    assert_eq!(h.core.tip.height, 2);
    assert!(halts(&h.all).is_empty());
}

/// §6.9 rule 1, §6.11: an unverifiable sync target never makes the node unsettled; a verified
/// one does.
#[test]
fn det_r4_unverified_target_never_unsettles() {
    let mut h = H::new(4, pick::set_a(0));
    h.commit_with(0, b"1");
    assert!(!h.core.late_entry, "entered from a Qc message");
    h.run_until(h.now + 10);
    let settled = h.core.last_status.unwrap() + h.local.status_keepalive;
    assert_eq!(deadline(&h, "status"), Some(settled));
    // A member hints at height 9 (its configuration is unknown).
    let mut far = h.qc_q(VoteKind::Commit, 0, &h.block(0, b"x"));
    far.height = 9;
    let peer = h.others(1, &[])[0];
    h.deliver(peer, WireMessage::Qc(far));
    assert_eq!(h.core.sync.target(), 9);
    assert_eq!(deadline(&h, "status"), Some(settled), "still settled");
    // A verified CommitQC of height 3 (C_3 is known after the apply of 1) unsettles it.
    let b2 = h.block(0, b"2");
    let b3 = h.block_at(3, (h.bh(&b2), result_of(&b2)), 0, b"3");
    let c3 = h.cqc_for(&b3, 0);
    h.deliver(peer, WireMessage::Qc(c3));
    assert_eq!(h.core.sync.verified_target(), 3);
    let unsettled = h.core.last_status.unwrap() + h.local.rebroadcast_interval;
    assert_eq!(deadline(&h, "status"), Some(unsettled));
}

/// §6.9 rule 5: fetch sources cycle through the source list (wrapping around).
#[test]
fn det_r4_fetch_sources_cycle() {
    let mut h = H::new(4, pick::set_b(0));
    h.auto_fetch = false;
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    let signers = h.signer_keys_of(&pqc);
    let out = qc_msg(&mut h, pqc);
    let fetches = |out: &[Action]| -> Vec<Vec<PublicKey>> {
        out.iter()
            .filter_map(|a| match a {
                Action::FetchPayload { peers, .. } => Some(peers.clone()),
                _ => None,
            })
            .collect()
    };
    assert_eq!(fetches(&out), vec![signers[..2].to_vec()]);
    let out = h.tick(h.local.fetch_retry);
    assert_eq!(
        fetches(&out),
        vec![vec![
            signers[2].clone(),
            signers[0].clone(),
            signers[1].clone()
        ]],
        "the next min(4, 3) sources, wrapping around"
    );
}

/// §6.13 (4.1): `BlockApplied` must name the next height, carry the applied header and a block
/// this core committed there (the tip or its parent); otherwise `Halt(DriverAnomaly)`. The header
/// feeds `recent_headers`.
#[test]
fn det_r4_block_applied_checks() {
    let setup = || {
        let mut h = H::new(4, pick::set_b(0));
        h.auto_apply = false;
        let b1 = h.commit_with(0, b"1");
        let b2 = h.commit_with(0, b"2");
        assert!(h.core.awaiting);
        (h, b1, b2)
    };
    let applied = |h: &H, block: &AvailableBody, bh: Hash32| Event::BlockApplied {
        height: block.header().height,
        block_hash: bh,
        header: Box::new(block.header().clone()),
        config: crate::testing::applied_config(
            block.header().height,
            &h.config(block.header().height),
            h.config(block.header().height + 1),
            h.config(block.header().height + 2),
        ),
    };
    let halted = |h: &mut H, event: Event| {
        let out = h.fire(event);
        halts(&out) == vec![HaltReason::DriverAnomaly]
    };
    // Out of order: 2 before 1.
    let (mut h, _, b2) = setup();
    let e = applied(&h, &b2, h.bh(&b2));
    assert!(halted(&mut h, e));
    // A header that does not hash to the block hash.
    let (mut h, b1, _) = setup();
    let e = applied(&h, &b1, Hash32([9; 32]));
    assert!(halted(&mut h, e));
    // A self-consistent header of another block at the parent height (a == tip − 1).
    let (mut h, _, _) = setup();
    let other = h.block_at(1, (G_HASH, G_RESULT), 0, b"other");
    let e = applied(&h, &other, h.bh(&other));
    assert!(halted(&mut h, e));
    // Height 3 was never committed (a > tip).
    let (mut h, b1, b2) = setup();
    let e = applied(&h, &b1, h.bh(&b1));
    h.fire(e);
    let e = applied(&h, &b2, h.bh(&b2));
    h.fire(e);
    assert_eq!(h.core.applied, 2);
    let b3 = h.block_at(3, (h.bh(&b2), result_of(&b2)), 0, b"3");
    let e = applied(&h, &b3, h.bh(&b3));
    assert!(halted(&mut h, e));
    // The valid reports: in order, the committed blocks; the headers enter `recent_headers`.
    let (mut h, b1, b2) = setup();
    let e = applied(&h, &b1, h.bh(&b1));
    assert!(halts(&h.fire(e)).is_empty());
    assert!(!h.core.awaiting, "the configuration of 3 is known");
    let e = applied(&h, &b2, h.bh(&b2));
    assert!(halts(&h.fire(e)).is_empty());
    let headers: Vec<u64> = h.core.recent_headers.iter().map(|x| x.height).collect();
    assert_eq!(headers, vec![1, 2]);
    // At the tip height itself, another block is an anomaly too.
    let (mut h, b1, _) = setup();
    let e = applied(&h, &b1, h.bh(&b1));
    h.fire(e);
    let other = h.block_at(2, (h.bh(&b1), result_of(&b1)), 0, b"other2");
    let e = applied(&h, &other, h.bh(&other));
    assert!(halted(&mut h, e));
}

/// §6.0, §6.1 rule 5: the verified-certificate cache is an LRU of capacity `4n`, cleared on
/// height entry.
#[test]
fn det_r4_cert_cache_lru_cleared_on_entry() {
    let mut cache = super::super::CertCache::default();
    cache.reset(3);
    let d = |b: u8| Hash32([b; 32]);
    for b in 1..=3 {
        cache.insert(d(b));
    }
    assert!(cache.hit(&d(1)), "1 becomes the most recently used");
    cache.insert(d(4));
    assert!(!cache.contains(&d(2)), "the least recently used is evicted");
    assert!(cache.contains(&d(1)) && cache.contains(&d(3)) && cache.contains(&d(4)));
    // In the core: capacity 4n, and the cache is empty after a height entry.
    let mut h = H::new(4, pick::set_a(0));
    assert_eq!(h.core.cert_cache.cap, 16);
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    qc_msg(&mut h, pqc.clone());
    assert!(h.core.cert_cache.contains(&pqc.digest(&h.v.crypto)));
    h.commit_with(0, b"B");
    assert!(h.core.cert_cache.set.is_empty(), "cleared on height entry");
}

/// §6.0 own messages: `pool_insert` / `timeout_insert` run formation on the node's own votes and
/// timeouts (with `n = 1` every certificate forms this way), and `route` never delivers locally.
#[test]
fn det_r4_own_messages_through_insertion() {
    let mut h = H::new(1, |_| 0);
    h.auto_exec = true;
    h.run_until(h.params.block_time);
    h.built(b"transaction");
    assert_eq!(h.core.tip.height, 1, "n = 1 commits through its own votes");
    assert!(votes(&h.all).is_empty(), "nothing is routed to itself");
    // Its own timeout forms the TC of the view.
    let mut h = H::new(1, |_| 0);
    let deadline = h.core.view_deadline().expect("a view deadline");
    h.run_until(deadline);
    assert_eq!(h.core.high_tc.as_ref().map(|tc| tc.view), Some(0));
    assert_eq!(h.core.view, 1);
}

/// §6.1 rule 5 (top-level only): a timeout carrying an older `PrepareQC` is verified, stored and
/// counted toward the TC; the lock does not decrease.
#[test]
fn det_r4_nested_pqc_timeout_counted() {
    let mut h = H::new(4, pick::set_b(0));
    let b0 = h.block(0, b"B0");
    let b1 = h.block(0, b"B1");
    let q1 = h.qc_q(VoteKind::Prepare, 2, &b1);
    qc_msg(&mut h, q1.clone());
    assert_eq!(h.core.view, 2);
    let q0 = h.qc_q(VoteKind::Prepare, 1, &b0);
    let o = h.others(2, &[]);
    let t0 = h.timeout(o[0], 2, Some(q0));
    h.deliver(o[0], WireMessage::Timeout(Box::new(t0)));
    let t1 = h.timeout(o[1], 2, None);
    h.deliver(o[1], WireMessage::Timeout(Box::new(t1)));
    assert_eq!(
        h.core.high_pqc,
        Some(q1.clone()),
        "the lock never decreases"
    );
    // With its own timeout (hq = 2) the TC of view 2 forms and includes the older entry.
    let deadline = h.core.view_deadline().unwrap();
    h.run_until(deadline);
    let tc = h.core.high_tc.clone().expect("TC(2)");
    assert_eq!(tc.view, 2);
    assert!(
        tc.entries
            .iter()
            .any(|e| e.signer == o[0] && e.hq == Some(1))
    );
    assert_eq!(tc.high_pqc, Some(q1));
    assert_eq!(h.core.view, 3);
}

/// §5.2, §6.11: stage entry re-sends each unanswered own vote once with the new routing and
/// restarts its retransmit schedule from that send (`t_vote`).
#[test]
fn det_r4_stage_entry_resend_restarts_schedule() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    let out = h.exec_all();
    let mine = votes_of(&out, VoteKind::Prepare)[0];
    let t_retx = h.core.pm.t_retx(0);
    h.now = 100;
    // Contagion: verified votes of view 0 (another value) from f + 1 = 2 non-P signers.
    let other = h.block(0, b"B-other");
    for s in h.others(2, &[h.proxy_tail(0)]) {
        let v = h.vote(VoteKind::Prepare, s, 0, &other);
        h.deliver(s, WireMessage::Vote(v));
    }
    assert_eq!(h.core.stage, 2);
    let resent = sent(&h.out)
        .into_iter()
        .filter(|(to, m)| matches!(m, WireMessage::Vote(v) if *v == mine) && to.len() == 3)
        .count();
    assert_eq!(resent, 1, "one broadcast re-send at stage entry");
    let retx = h.core.retx[0].expect("the schedule restarts");
    assert_eq!((retx.next, retx.k), (100 + t_retx, 1));
    let out = h.run_until(100 + t_retx - 1);
    assert!(votes_of(&out, VoteKind::Prepare).is_empty());
    let out = h.run_until(100 + t_retx);
    assert_eq!(votes_of(&out, VoteKind::Prepare), vec![mine]);
}

/// §6.12: `advance_to` keeps only the bodies of `high_pqc`, `high_tc.high_pqc` and
/// `pending_apply`, and resets `t_pqc`, `build`, `late_entry`, `asked` and the evidence keys of
/// the pruned views.
#[test]
fn det_r4_advance_to_prunes_blocks_and_reported() {
    let mut h = H::new(4, pick::set_b(0));
    let b = h.block(0, b"B");
    prop(&mut h, 0, &b, None);
    let locked = h.block(0, b"L");
    h.bodies.insert(h.bh(&locked), locked.clone());
    let pqc = h.qc_q(VoteKind::Prepare, 0, &locked);
    qc_msg(&mut h, pqc);
    assert!(h.core.blocks.contains_key(&h.bh(&b)));
    assert!(h.core.blocks.contains_key(&h.bh(&locked)));
    assert!(h.core.t_pqc.is_some());
    // Evidence at view 0 (a vote equivocation).
    let s = h.others(1, &[])[0];
    let v1 = h.vote(VoteKind::Prepare, s, 0, &b);
    let v2 = h.vote(VoteKind::Prepare, s, 0, &locked);
    h.deliver(s, WireMessage::Vote(v1));
    h.deliver(s, WireMessage::Vote(v2));
    assert_eq!(h.core.reported.len(), 1);
    let tc = h.tc_q(2);
    h.deliver(s, WireMessage::Tc(Box::new(tc)));
    assert_eq!(h.core.view, 3);
    assert!(
        !h.core.blocks.contains_key(&h.bh(&b)),
        "the proposal body is dropped"
    );
    assert!(
        h.core.blocks.contains_key(&h.bh(&locked)),
        "the lock's body is kept"
    );
    assert!(
        h.core.reported.is_empty(),
        "keys of views < view − 1 are pruned"
    );
    assert!(h.core.t_pqc.is_none() && !h.core.late_entry && !h.core.asked);
    assert!(matches!(
        h.core.build,
        super::super::Build::Requested { .. }
    ));
    assert!(
        h.core.proposal.is_none(),
        "the new leader waits for real work"
    );
}

/// §9.1: `exec_budget = min(e_max, φ·T_base/2)`, independent of the level (a view-1 build).
#[test]
fn det_r4_exec_budget_level_independent() {
    let mut h = H::new(4, pick::set_a(0));
    assert_eq!(h.leader(1), h.my_idx());
    let tc = h.tc_q(0);
    let out = h.deliver(h.others(1, &[])[0], WireMessage::Tc(Box::new(tc)));
    assert_eq!(h.core.status().level, 1);
    let budget = out.iter().find_map(|a| match a {
        Action::BuildPayload {
            view: 1,
            exec_budget_ms,
            ..
        } => Some(*exec_budget_ms),
        _ => None,
    });
    assert_eq!(budget, Some(500), "T_base / 4, not T(1) / 4 = 750");
}

/// §7.6: the monitor checks `tip.height − 1` while its configuration is retained (through
/// `tip.prev`); after a restart `C_{t−1}` is not retained and only `tip.height` is checked.
#[test]
fn det_r4_monitor_previous_height() {
    let mut h = H::new(4, pick::set_a(0));
    h.commit_heights(2);
    let other = h.block_at(1, (G_HASH, G_RESULT), 0, b"conflict");
    let conflicting = h.cqc_for(&other, 2);
    let out = qc_msg(&mut h, conflicting.clone());
    assert_eq!(halts(&out), vec![HaltReason::SafetyViolation { height: 1 }]);
    assert!(matches!(
        evidence(&out)[..],
        [Evidence::ConflictingCertificates(..)]
    ));
    // After a restart at tip 2 the configuration of 1 is not retained.
    let mut h = H::new(4, pick::set_a(0));
    h.commit_heights(2);
    h.restart();
    let out = qc_msg(&mut h, conflicting);
    assert!(halts(&out).is_empty());
}

/// §7.4 step 4 leader rules: restored at `view > 0` with `high_tc = TC(view − 1)` and nothing
/// recorded at `view`, the leader proposes with it; restored at view 0 it schedules the build.
#[test]
fn det_r4_restart_leader_rules() {
    // L(1, 1) with a record holding only TC(0).
    let mut h = H::new(4, pick::set_a(0));
    assert_eq!(h.leader(1), h.my_idx());
    let tc = h.tc_q(0);
    let key = h.signers[0].public_key().clone();
    let record = SafetyRecord {
        high_tc: Some(tc.clone()),
        ..SafetyRecord::fresh(I, crate::testing::TEST_EPOCH.id, key.clone(), 1, None)
    };
    h.records
        .insert(key.clone(), record.encode(&h.v.crypto).unwrap());
    let out = h.restart();
    assert_eq!(h.core.view, 1);
    assert!(
        out.iter()
            .any(|a| matches!(a, Action::BuildPayload { view: 1, .. }))
    );
    let out = h.built(b"P1");
    let p = proposals(&out);
    assert_eq!(p.len(), 1);
    assert_eq!((p[0].view, p[0].justify.clone()), (1, Some(tc)));
    // L(1, 0) with a fresh record at 1: the view-0 build is scheduled at t_enter + pace.
    let mut h = H::new(4, pick::leader(0));
    let key = h.signers[0].public_key().clone();
    let record = SafetyRecord::fresh(I, crate::testing::TEST_EPOCH.id, key.clone(), 1, None);
    h.records.insert(key, record.encode(&h.v.crypto).unwrap());
    h.restart();
    assert_eq!(deadline(&h, "build"), Some(h.now + h.params.block_time));
}

/// §7.4 step 4: after restoring a round whose lock is of the current view, `try_commit()`
/// re-signs the identical Commit (same preimage, same bytes).
#[test]
fn det_r4_restore_recommits_identical() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    let out = qc_msg(&mut h, pqc);
    let commit = votes_of(&out, VoteKind::Commit)[0];
    let out = h.restart();
    let again = votes_of(&out, VoteKind::Commit);
    assert_eq!(again, vec![commit], "identical bytes");
    assert_eq!(h.my_sigs(KIND_COMMIT, 1, 0).len(), 1);
}

/// §6.11 (4.1): while a key is unanchored every outgoing `Status` carries the probe nonce; an
/// echo is processed even inside the per-peer rate limit; an echo naming a non-member key never
/// counts, and one relayed by any peer counts for its signer.
#[test]
fn det_r4_probe_statuses_and_echoes() {
    let mut h = H::new(4, pick::set_a(0));
    h.records.clear();
    let key = h.signers[0].public_key().clone();
    let out = h.start(vec![(key, RecordState::Absent)]);
    let nonce = h.nonce;
    // The late entry's proposal request carries the probe.
    let requests = statuses(&out);
    assert!(!requests.is_empty());
    assert!(requests.iter().all(|(_, s)| s.probe == Some(nonce)));
    // A §6.1 rule-3 reply carries it too.
    h.commit_heights(1);
    let behind = h.others(1, &[])[0];
    let old = h.block_at(1, (G_HASH, G_RESULT), 0, b"old");
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
    assert!(statuses(&out).iter().all(|(_, s)| s.probe == Some(nonce)));
    assert!(!statuses(&out).is_empty());
    // An echo inside the rate-limit window of its sender is still processed.
    let peer = h.others(1, &[behind])[0];
    let plain = Status {
        instance: I,
        height: 2,
        ..Status::default()
    };
    h.deliver(peer, WireMessage::Status(Box::new(plain)));
    let echo = |h: &H, named: &PublicKey, signer: &PublicKey, height: u64| {
        let sig = h.signer_of(signer).sign(&preimage::echo_preimage(
            &I,
            &crate::testing::TEST_EPOCH.id,
            h.nonce,
            height,
        ));
        WireMessage::Status(Box::new(Status {
            instance: I,
            height,
            echo: Some(Echo {
                epoch: crate::testing::TEST_EPOCH.id,
                nonce: h.nonce,
                key: named.clone(),
                sig,
            }),
            ..Status::default()
        }))
    };
    let peer_key = h.key_at(peer);
    let msg = echo(&h, &peer_key, &peer_key, 2);
    h.deliver(peer, msg);
    assert_eq!(
        h.core.probe.get(&peer_key),
        Some(&2),
        "exempt from the rate limit"
    );
    // A non-member key never counts; a relayed echo counts for its signer.
    let outsider = crate::testing::FakeSigner::from_seed(b"outsider", None);
    let outsider_key = outsider.public_key().clone();
    let sig = outsider.sign(&preimage::echo_preimage(
        &I,
        &crate::testing::TEST_EPOCH.id,
        h.nonce,
        2,
    ));
    let foreign = WireMessage::Status(Box::new(Status {
        instance: I,
        height: 2,
        echo: Some(Echo {
            epoch: crate::testing::TEST_EPOCH.id,
            nonce: h.nonce,
            key: outsider_key.clone(),
            sig,
        }),
        ..Status::default()
    }));
    h.deliver_key(outsider_key.clone(), foreign);
    assert!(!h.core.probe.contains_key(&outsider_key));
    let third = h.others(3, &[])[2];
    let third_key = h.key_at(third);
    let relayed = echo(&h, &third_key, &third_key, 2);
    h.deliver_key(outsider_key, relayed);
    assert_eq!(h.core.probe.get(&third_key), Some(&2));
}

/// §6.11 `request_proposal` (4.1): an on-time member that sees evidence of a proposal it lacks
/// asks `L(h, view)` once per view; the leader never asks; `asked` resets on a view change.
#[test]
fn det_r4_request_proposal_conditions() {
    let mut h = H::new(4, pick::at(2, 0, 1));
    h.commit_with(0, b"1");
    assert_eq!(h.height(), 2);
    assert!(!h.core.late_entry);
    let leader = h.key_at(h.leader(0));
    let requests = |out: &[Action], to: &PublicKey| {
        statuses(out)
            .into_iter()
            .filter(|(t, s)| *t == vec![to.clone()] && s.want_proposal)
            .count()
    };
    // No evidence yet: nobody is asked.
    let out = h.run_until(h.now + 50);
    assert_eq!(requests(&out, &leader), 0);
    // A verified vote of (2, 0) is evidence: one request.
    let b = h.block(0, b"B");
    let voters = h.others(2, &[h.leader(0)]);
    let v = h.vote(VoteKind::Prepare, voters[0], 0, &b);
    let out = h.deliver(voters[0], WireMessage::Vote(v));
    assert_eq!(requests(&out, &leader), 1);
    assert!(h.core.asked);
    let v = h.vote(VoteKind::Prepare, voters[1], 0, &b);
    let out = h.deliver(voters[1], WireMessage::Vote(v));
    assert_eq!(requests(&out, &leader), 0, "once per view");
    // A view change resets `asked`; a PrepareQC of the new view is evidence again.
    h.enter_view(1);
    assert!(!h.core.asked);
    let next_leader = h.key_at(h.leader(1));
    if h.leader(1) != h.my_idx() {
        let pqc = h.qc_q(VoteKind::Prepare, 1, &b);
        let out = qc_msg(&mut h, pqc);
        assert_eq!(requests(&out, &next_leader), 1);
    }
}

/// §6.11 re-push (4.1): the leader re-sends its proposal at once to a recipient asking for it,
/// once per recipient per view, never to a non-recipient or to one that reports the proposal;
/// the request is honoured even inside the per-peer rate limit.
#[test]
fn det_r4_repush_only_to_recipients_once() {
    let mut h = H::new(4, pick::leader(0));
    h.run_until(1_000);
    h.built(b"tx");
    let bh = h.core.proposal.as_ref().unwrap().bh;
    let want = |proposal_hash: Option<Hash32>| {
        WireMessage::Status(Box::new(Status {
            instance: I,
            height: 1,
            view: 0,
            proposal_hash,
            want_proposal: true,
            ..Status::default()
        }))
    };
    let pushes = |out: &[Action]| -> Vec<Vec<PublicKey>> {
        sent(out)
            .into_iter()
            .filter(|(_, m)| matches!(m, WireMessage::Proposal(_)))
            .map(|(to, _)| to)
            .collect()
    };
    let stranger = PublicKey::new(vec![0x77; 32]).unwrap();
    assert!(pushes(&h.deliver_key(stranger, want(None))).is_empty());
    let o = h.others(3, &[]);
    // Inside the rate-limit window of the member (a plain Status just arrived).
    let plain = WireMessage::Status(Box::new(Status {
        instance: I,
        height: 1,
        ..Status::default()
    }));
    h.deliver(o[0], plain);
    let out = h.deliver(o[0], want(None));
    assert_eq!(pushes(&out), vec![vec![h.key_at(o[0])]]);
    h.now += h.local.rebroadcast_interval;
    assert!(
        pushes(&h.deliver(o[0], want(None))).is_empty(),
        "once per view"
    );
    assert!(
        pushes(&h.deliver(o[1], want(Some(bh)))).is_empty(),
        "it holds it"
    );
    let other_view = WireMessage::Status(Box::new(Status {
        instance: I,
        height: 1,
        view: 1,
        want_proposal: true,
        ..Status::default()
    }));
    assert!(pushes(&h.deliver(o[2], other_view)).is_empty());
}

/// §2.1, §10.1: `W` comes from `Init.demotion_window` (a genesis constant): with `W = 1` a
/// skipped leader of height 1 is demoted at height 3 only.
#[test]
fn det_r4_demotion_window_from_init() {
    let mut h = H::new(4, pick::set_b(0));
    h.w = 1;
    h.restart();
    let silent = h.leader(0);
    h.enter_view(1);
    h.commit_with(1, b"B1");
    h.commit_heights(1);
    assert_eq!(h.height(), 3);
    assert_eq!(h.core.topo.demoted(), &[silent]);
    h.commit_heights(1);
    assert!(
        h.core.topo.demoted().is_empty(),
        "the window of 1 height has passed"
    );
}

/// §6.9 serving (4.1 §3.5): a `PayloadRequest` for an unknown body is handed to the driver, which
/// may answer from its stores or not at all.
#[test]
fn det_r4_block_request_served_by_driver() {
    let mut h = H::new(4, pick::set_a(0));
    let o = h.others(1, &[])[0];
    let out = h.deliver(
        o,
        WireMessage::PayloadRequest(PayloadRequest {
            instance: I,
            height: 5,
            block_hash: Hash32([3; 32]),
        }),
    );
    assert!(matches!(out[..], [Action::ServePayload { height: 5, .. }]));
}
