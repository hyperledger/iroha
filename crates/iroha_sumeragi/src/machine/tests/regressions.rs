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

/// F28 seed 177: a restored proposal with a lost body must learn sync responders,
/// even after every peer has advanced beyond its proposal height.
#[test]
fn det_l32_sync_enriches_restored_body_want() {
    for existing_peer in [false, true] {
        let mut h = H::new(4, pick::leader(0));
        h.run_until(h.now + 1_100);
        h.built(b"original before restart");
        let bh = h.durable().unwrap().proposal.unwrap().block_hash;
        let first = h.bodies.remove(&bh).expect("original authored body");
        h.auto_fetch = false;
        h.withheld_rows.insert(bh);
        h.restart();
        assert_eq!(h.core.resend_recorded, Some(bh));
        assert!(h.core.wants[&bh].sources.is_empty());
        assert!(h.core.blocks.is_empty());
        let peers = h.others(2, &[]);
        let source = peers[0];
        let source_key = h.key_at(source);
        let stale_key = h.key_at(peers[1]);
        if existing_peer {
            h.core.want(bh, 1, vec![stale_key.clone()]);
        }
        let want = &h.core.wants[&bh];
        let retry = (want.cursor, want.attempt, want.next_retry);
        let second = h.block_at(2, (bh, result_of(&first)), 0, b"next committed body");
        let second_hash = h.bh(&second);
        h.withheld_rows.insert(second_hash);
        let second_qc = h.cqc_for(&second, 0);
        let out = h.deliver(source, WireMessage::Qc(second_qc.clone()));
        assert_eq!(sync_from(&out), Some(1));
        let first_qc = h.cqc_for(&first, 0);
        h.deliver(
            source,
            WireMessage::SyncResponse(SyncResponse {
                instance: I,
                blocks: vec![
                    SyncEntry {
                        manifest: manifest(&first),
                        commit_qc: first_qc,
                    },
                    SyncEntry {
                        manifest: manifest(&second),
                        commit_qc: second_qc,
                    },
                ],
            }),
        );
        let expected = if existing_peer {
            vec![stale_key, source_key.clone()]
        } else {
            vec![source_key.clone()]
        };
        let want = &h.core.wants[&bh];
        assert_eq!(
            want.sources, expected,
            "the original want learns the responder"
        );
        assert_eq!((want.cursor, want.attempt, want.next_retry), retry);
        h.fire(Event::Tick);
        assert_eq!(
            h.core.wants[&bh].sources, expected,
            "repeated merge deduplicates"
        );
        assert_eq!(h.core.tip.height, 0, "a manifest alone is not body custody");
        assert!(h.store.is_empty());
        let out = h.tick(h.local.fetch_retry);
        assert!(out.iter().any(|action| matches!(action,
            Action::FetchPayload { source: bound, peers }
                if bound.instance() == I && bound.height() == 1 && bound.block_hash() == bh
                    && bound.config() == h.core.config(1).unwrap() && peers.contains(&source_key)
        )), "the unchanged retry fetches the original authenticated source from its new peer");
        assert!(h.store.is_empty());
        h.deliver_rows(source, &first);
        assert_eq!(h.core.tip.height, 1);
        assert_eq!(h.store.len(), 1);
        h.deliver_rows(source, &second);
        assert_eq!(h.core.tip.height, 2);
        assert_eq!(
            h.store
                .iter()
                .map(|(body, _)| body.header().height)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }
}

/// A requested sync donor must remain fetchable after finite stale-source saturation.
#[test]
fn det_l33_verified_sync_donor_survives_saturated_history() {
    use crate::types::PublicKey;

    let mut h = H::new(4, pick::leader(0));
    h.run_until(h.now + 1_100);
    h.built(b"original before restart");
    let bh = h.durable().unwrap().proposal.unwrap().block_hash;
    let first = h.bodies.remove(&bh).expect("original authored body");
    h.auto_fetch = false;
    h.withheld_rows.insert(bh);
    h.restart();
    assert!(h.core.wants[&bh].sources.is_empty());
    let second = h.block_at(2, (bh, result_of(&first)), 0, b"next committed body");
    h.withheld_rows.insert(h.bh(&second));
    let entries = vec![
        SyncEntry {
            manifest: manifest(&first),
            commit_qc: h.cqc_for(&first, 0),
        },
        SyncEntry {
            manifest: manifest(&second),
            commit_qc: h.cqc_for(&second, 0),
        },
    ];
    let response = |blocks| {
        WireMessage::SyncResponse(SyncResponse {
            instance: I,
            blocks,
        })
    };
    let members: Vec<_> = h
        .others(3, &[])
        .into_iter()
        .map(|index| h.key_at(index))
        .collect();
    let mut stale = members.clone();
    stale.extend((0xa0..0xa9).map(|byte| PublicKey::new(vec![byte; 32]).unwrap()));
    assert_eq!(stale.len(), h.core.n() + 8);
    // Known-height certificates can be relayed by authenticated nonmembers. Across
    // rotations the same bounded history can retain peers which no longer serve rows.
    let donor = PublicKey::new(vec![0xe1; 48]).unwrap();
    let replacement = PublicKey::new(vec![0xe2; 64]).unwrap();
    assert!(!h.core.cfg.committee.contains(&donor));
    for peer in stale.iter().chain([&donor, &replacement]) {
        h.deliver_key(peer.clone(), WireMessage::Qc(entries[1].commit_qc.clone()));
    }
    h.core.want(bh, 1, stale.clone());
    assert_eq!(h.core.wants[&bh].sources, stale);
    let mut requested = false;
    for _ in 0..=stale.len() + 1 {
        let out = h.tick(h.local.sync_retry);
        if out.iter().any(|action| {
            matches!(action,
                Action::Send { to, msg: WireMessage::SyncRequest(request) }
                    if to == &replacement && request.from_height == 1
            )
        }) {
            requested = true;
            break;
        }
    }
    assert!(
        requested,
        "both later-generation donors were actually asked"
    );
    // Exercise the small-fanout retry state as well as a full peer list; promotion
    // must not reset these original fields or rely on exponential saturation.
    let retry_at = h.now + h.local.fetch_retry;
    let want = h.core.wants.get_mut(&bh).unwrap();
    want.cursor = 0;
    want.attempt = 0;
    want.next_retry = retry_at;
    let retry = (want.cursor, want.attempt, want.next_retry);
    let unrequested = PublicKey::new(vec![0xe3; 32]).unwrap();
    h.deliver_key(unrequested, response(entries.clone()));
    assert_eq!(
        h.core.wants[&bh].sources, stale,
        "unsolicited metadata cannot evict peers"
    );
    assert!(h.core.wants[&bh].sync_responder.is_none());
    let mut invalid = entries.clone();
    invalid[0].commit_qc.result = Hash32([0x99; 32]);
    h.deliver_key(stale[0].clone(), response(invalid));
    assert_eq!(
        h.core.wants[&bh].sources, stale,
        "invalid QC cannot promote a donor"
    );
    assert!(h.core.wants[&bh].sync_responder.is_none());
    let out = h.deliver_key(donor.clone(), response(entries.clone()));
    let want = &h.core.wants[&bh];
    assert!(
        want.sources.contains(&donor),
        "verified responder enters the saturated want"
    );
    assert_eq!(want.sync_responder.as_ref(), Some(&donor));
    assert_eq!(want.sources.len(), stale.len());
    assert!(members.iter().all(|peer| want.sources.contains(peer)));
    assert_eq!((want.cursor, want.attempt, want.next_retry), retry);
    assert!(out.iter().any(|action| matches!(action,
        Action::FetchPayload { source, peers }
            if source.instance() == I && source.height() == 1 && source.block_hash() == bh
                && source.config() == h.core.config(1).unwrap() && peers.as_slice() == std::slice::from_ref(&donor)
    )), "one immediate fetch uses the exact verified source and donor");
    let bytes_before = h.core.status().footprint.sync_bytes;
    // A solicited but different same-height carrier cannot replace the retained donor.
    let mut foreign = entries.clone();
    foreign[0].commit_qc.result = Hash32([0x88; 32]);
    foreign[1].commit_qc.result = Hash32([0x88; 32]);
    h.deliver_key(stale[1].clone(), response(foreign));
    assert_eq!(h.core.wants[&bh].sync_responder.as_ref(), Some(&donor));
    assert_eq!(h.core.status().footprint.sync_bytes, bytes_before);
    let keys: Vec<_> = std::iter::once(h.signers[0].public_key().clone())
        .chain(members.iter().take(h.q() - 1).cloned())
        .collect();
    let mut alternate = entries;
    for (entry, body) in alternate.iter_mut().zip([&first, &second]) {
        let height = body.header().height;
        let committee = h.config(height).committee;
        let qc = h.qc_keys(
            &committee,
            VoteKind::Commit,
            height,
            0,
            (h.bh(body), result_of(body)),
            &keys,
        );
        assert_ne!(entry.commit_qc.signers, qc.signers);
        entry.commit_qc = qc;
    }
    let out = h.deliver_key(replacement.clone(), response(alternate));
    assert_eq!(
        h.core.wants[&bh].sync_responder.as_ref(),
        Some(&replacement)
    );
    assert_eq!(
        h.core.status().footprint.sync_bytes,
        bytes_before,
        "both maximum donor keys were prepaid"
    );
    assert!(out.iter().any(|action| matches!(action,
        Action::FetchPayload { peers, .. } if peers.as_slice() == std::slice::from_ref(&replacement)
    )));
    assert_eq!(h.core.tip.height, 0, "a manifest is not body custody");
    assert!(h.store.is_empty());
    let out = h.fire(Event::Tick);
    assert!(
        !out.iter().any(|action| matches!(action,
            Action::FetchPayload { source, .. } if source.block_hash() == bh
        )),
        "reprocessing the same donor does not emit extra fetches"
    );
    assert_eq!(h.core.wants[&bh].sources.len(), stale.len());
    assert!(
        members
            .iter()
            .all(|peer| h.core.wants[&bh].sources.contains(peer))
    );
    assert_eq!(
        (
            h.core.wants[&bh].cursor,
            h.core.wants[&bh].attempt,
            h.core.wants[&bh].next_retry
        ),
        retry
    );
    let out = h.tick(h.local.fetch_retry);
    assert!(
        out.iter().any(|action| matches!(action,
            Action::FetchPayload { source, peers }
                if source.block_hash() == bh && source.height() == 1
                    && source.config() == h.core.config(1).unwrap()
                    && peers.len() == 2 && peers.contains(&replacement)
        )),
        "the next ordinary retry preserves original fanout and retained donor"
    );
    assert!(h.store.is_empty());
    // Deliver real authenticated rows using the donor's transport identity. No
    // auto-fetch or acquisition autofill can satisfy these withheld bodies.
    h.withheld_rows.remove(&bh);
    for chunk in h.chunks(&first) {
        h.deliver_key(replacement.clone(), WireMessage::PayloadChunk(chunk));
    }
    assert_eq!(h.core.tip.height, 1);
    h.withheld_rows.remove(&h.bh(&second));
    for chunk in h.chunks(&second) {
        h.deliver_key(replacement.clone(), WireMessage::PayloadChunk(chunk));
    }
    assert_eq!(h.core.tip.height, 2);
    assert_eq!(
        h.core.status().footprint.sync_bytes,
        0,
        "commits refund the prepaid donor slots"
    );
    assert_eq!(
        h.store
            .iter()
            .map(|(body, _)| body.header().height)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
}

/// A rejected future donor alternative must leave a route to refresh that same height.
#[test]
fn det_l34_deferred_sync_donor_failure_refetches_current_height() {
    use crate::types::PublicKey;

    let mut h = H::new(4, pick::set_a(0));
    h.auto_fetch = false;
    let mut bodies = Vec::new();
    let mut parent = (G_HASH, G_RESULT);
    for height in 1..=3_u64 {
        let body = h.block_at(height, parent, 0, &height.to_be_bytes());
        parent = (h.bh(&body), result_of(&body));
        h.withheld_rows.insert(h.bh(&body));
        bodies.push(body);
    }
    let entries: Vec<_> = bodies
        .iter()
        .map(|body| SyncEntry {
            manifest: manifest(body),
            commit_qc: h.cqc_for(body, 0),
        })
        .collect();
    let response = |blocks| {
        WireMessage::SyncResponse(SyncResponse {
            instance: I,
            blocks,
        })
    };
    let request_peer = |actions: &[Action]| {
        actions.iter().find_map(|action| match action {
            Action::Send {
                to,
                msg: WireMessage::SyncRequest(request),
            } if request.from_height == 3 => Some(to.clone()),
            _ => None,
        })
    };
    let source = h.key_at(h.others(1, &[])[0]);
    let donor = PublicKey::new(vec![0xe4; 48]).unwrap();
    let invalid_donor = PublicKey::new(vec![0xe5; 64]).unwrap();
    for peer in [&source, &donor, &invalid_donor] {
        h.deliver_key(peer.clone(), WireMessage::Qc(entries[1].commit_qc.clone()));
    }
    let mut requested = false;
    for _ in 0..3 {
        let out = h.tick(h.local.sync_retry);
        if out.iter().any(|action| {
            matches!(action,
                Action::Send { to, msg: WireMessage::SyncRequest(request) }
                    if to == &invalid_donor && request.from_height == 1
            )
        }) {
            requested = true;
            break;
        }
    }
    assert!(requested);
    assert!(
        h.core.config(3).is_none(),
        "the third authority is not yet known"
    );
    h.deliver_key(source.clone(), response(entries.clone()));
    let initial_bytes = h.core.status().footprint.sync_bytes;
    let mut keys = vec![h.signers[0].public_key().clone()];
    keys.extend(
        h.others(h.q() - 1, &[])
            .into_iter()
            .map(|index| h.key_at(index)),
    );
    let mut alternate = entries.clone();
    for (entry, body) in alternate.iter_mut().zip(&bodies) {
        let height = body.header().height;
        let committee = h.config(height).committee;
        let qc = h.qc_keys(
            &committee,
            VoteKind::Commit,
            height,
            0,
            (h.bh(body), result_of(body)),
            &keys,
        );
        assert_ne!(entry.commit_qc.signers, qc.signers);
        entry.commit_qc = qc;
    }
    h.deliver_key(donor.clone(), response(alternate.clone()));
    assert_eq!(
        h.core.status().footprint.sync_bytes,
        initial_bytes,
        "the complete alternate QC and both maximum donor keys were prepaid"
    );
    let mut invalid = alternate.clone();
    invalid[2].commit_qc.agg_sig.0[0] ^= 1;
    h.deliver_key(invalid_donor.clone(), response(invalid));
    assert_eq!(
        h.core.status().footprint.sync_bytes,
        initial_bytes,
        "a maximum reserved alternative can be replaced without extra capacity"
    );
    assert!(h.core.config(3).is_none());
    assert_eq!(
        h.core.status().footprint.sync_entries,
        3,
        "the original future carrier remains"
    );
    let mut out = Vec::new();
    for body in &bodies[..2] {
        h.withheld_rows.remove(&h.bh(body));
        for chunk in h.chunks(body) {
            out.extend(h.deliver_key(donor.clone(), WireMessage::PayloadChunk(chunk)));
        }
    }
    assert_eq!(h.core.tip.height, 2);
    assert!(h.core.config(3).is_some());
    assert_eq!(
        h.core.status().footprint.sync_entries,
        1,
        "the valid original carrier is retained"
    );
    let empty_peer =
        request_peer(&out).expect("invalid deferred donor requires a current-height request");
    let out = h.deliver_key(empty_peer, response(Vec::new()));
    let bad_peer = request_peer(&out).expect("empty reply retains current-height refresh");
    let mut invalid = alternate[2].clone();
    invalid.commit_qc.agg_sig.0[0] ^= 1;
    let out = h.deliver_key(bad_peer, response(vec![invalid]));
    assert!(
        request_peer(&out).is_some(),
        "invalid known-height alternative retains refresh"
    );
    let out = h.tick(h.local.sync_retry);
    assert!(
        request_peer(&out).is_some(),
        "timeout retains current-height refresh"
    );
    let mut donor_requested = request_peer(&out).as_ref() == Some(&donor);
    for _ in 0..3 {
        if donor_requested {
            break;
        }
        let out = h.tick(h.local.sync_retry);
        donor_requested = request_peer(&out).as_ref() == Some(&donor);
    }
    assert!(
        donor_requested,
        "bounded source rotation reaches the live donor again"
    );
    let out = h.deliver_key(donor.clone(), response(vec![alternate[2].clone()]));
    assert!(
        request_peer(&out).is_none(),
        "validated refresh ends the special current-height request"
    );
    let bh = h.bh(&bodies[2]);
    assert_eq!(h.core.wants[&bh].sync_responder.as_ref(), Some(&donor));
    assert_eq!(
        h.core.tip.height, 2,
        "valid alternate QC is not body custody"
    );
    let out = h.tick(h.local.fetch_retry);
    assert!(out.iter().any(|action| matches!(action,
        Action::FetchPayload { source, peers } if source.height() == 3 && source.block_hash() == bh
            && source.config() == h.core.config(3).unwrap() && peers.contains(&donor)
    )));
    h.withheld_rows.remove(&bh);
    for chunk in h.chunks(&bodies[2]) {
        h.deliver_key(donor.clone(), WireMessage::PayloadChunk(chunk));
    }
    assert_eq!(h.core.tip.height, 3);
    assert_eq!(
        h.core.status().footprint.sync_bytes,
        0,
        "deferred resolution and commits refund all entries"
    );
    assert_eq!(
        h.store
            .iter()
            .map(|(body, _)| body.header().height)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let out = h.tick(h.local.sync_retry);
    assert!(
        request_peer(&out).is_none(),
        "height advance clears stale refresh state"
    );
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
        let sig = h
            .signer_of(&k)
            .sign(&crate::preimage::echo_preimage(
                &I,
                &crate::testing::TEST_EPOCH.id,
                h.nonce,
                3,
            ))
            .expect("fixture signing succeeds");
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
