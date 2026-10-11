//! Authenticated epoch boundaries: original application owns activation and every signature
//! binds the exact scheduling context, including retained committees and work-driven boundaries.

use super::*;
use crate::{
    message::Status,
    types::{AppliedConfig, ConfigSlot},
};

/// Epoch `0` ends at `boundary`; the core's key is `pick` of the topology of height 1.
fn boundary_harness_at(boundary: u64, pick: impl Fn(&Topology) -> ValidatorIndex) -> H {
    let mut h = H::new(4, |_| 0);
    h.committees.insert(boundary + 1, h.v.committee.clone());
    let config = h.config(1);
    let topology = Topology::compute(
        &h.v.crypto,
        &I,
        &config.epoch,
        &config.committee,
        1,
        0,
        W,
        &[],
    );
    h.signers = vec![h.v.signer(pick(&topology)).clone()];
    h.records.clear();
    h.install_keys();
    h.restart();
    h
}

fn boundary_harness(boundary: u64, leader_view: u64) -> H {
    boundary_harness_at(boundary, pick::leader(leader_view))
}

/// After the boundary of height 1 committed and applied: the next epoch is installed.
fn assert_entered_next_epoch(h: &H) {
    assert_eq!(h.core.tip.height, 1, "the boundary committed");
    assert_eq!(h.core.applied, 1);
    assert_eq!(h.height(), 2, "its application installed the next epoch");
    assert_eq!(h.core.cfg.epoch, h.config(2).epoch);
    assert_eq!(h.core.halted, None);
}

#[test]
fn det_s43_every_signature_binds_epoch_and_complete_context() {
    let h = H::new(4, pick::leader(0));
    let epoch = h.config(1).epoch.id;
    let bh = Hash32([0x41; 32]);
    let result = Hash32([0x42; 32]);
    for changed in [
        crate::types::EpochId {
            epoch: epoch.epoch + 1,
            ..epoch
        },
        crate::types::EpochId {
            context: Hash32([0x99; 32]),
            ..epoch
        },
    ] {
        let preimages = |epoch: &crate::types::EpochId| {
            [
                preimage::prop_preimage(&I, epoch, 1, 0, &bh, &result),
                preimage::vote_preimage(VoteKind::Prepare, &I, epoch, 1, 0, &bh, &result),
                preimage::vote_preimage(VoteKind::Commit, &I, epoch, 1, 0, &bh, &result),
                preimage::tmo_preimage(&I, epoch, 1, 0, None),
                preimage::echo_preimage(&I, epoch, 7, 1),
            ]
        };
        for (original, different) in preimages(&epoch).iter().zip(preimages(&changed)) {
            let signer = &h.signers[0];
            let signature = signer.sign(original);
            assert!(h.v.crypto.verify(signer.public_key(), original, &signature));
            assert!(
                !h.v.crypto
                    .verify(signer.public_key(), &different, &signature)
            );
        }
    }
    let block = h.block(0, b"epoch");
    let qc = h.qc_q(VoteKind::Commit, 0, &block);
    let other = crate::types::EpochId {
        epoch: epoch.epoch + 1,
        ..epoch
    };
    assert_eq!(
        crate::crypto::Verifier::new(&h.v.crypto, &I, &other, &h.committee()).verify_qc(&qc),
        Err(crate::crypto::CertError::WrongEpoch)
    );
}

#[test]
fn det_s44_boundary_waits_for_original_application() {
    let mut h = boundary_harness(3, 0);
    h.commit_heights(2);
    assert!(matches!(
        h.core.configs.get(&4),
        Some(ConfigSlot::PendingBoundary {
            boundary_height: 3,
            ..
        })
    ));
    h.auto_apply = false;
    let boundary = h.commit_with(0, b"boundary work");
    assert_eq!(h.core.applied, 2);
    assert_eq!(h.core.tip.height, 3);
    assert!(h.core.awaiting);
    assert!(h.core.config(4).is_none());
    let signed = h.log.len();
    h.tick(60_000);
    assert_eq!(
        h.log.len(),
        signed,
        "pending epoch cannot propose, vote, timeout or echo"
    );
    h.apply_height(3);
    assert_eq!(h.height(), 4);
    assert!(!h.core.awaiting);
    assert_eq!(h.core.cfg.epoch, h.config(4).epoch);
    assert_eq!(h.core.cfg.committee, h.config(4).committee);
    let applied = h.core.applied;
    let replay = h.applied_event(&boundary);
    h.fire(replay);
    assert_eq!(h.core.applied, applied);
    assert_eq!(h.core.halted, Some(HaltReason::DriverAnomaly));
}

#[test]
fn det_s44_lag_two_cannot_install_next_epoch_early() {
    let mut h = boundary_harness(3, 0);
    h.commit_heights(1);
    h.auto_apply = false;
    let second = h.commit_with(0, b"ordinary");
    let event = Event::BlockApplied {
        height: 2,
        block_hash: h.bh(&second),
        header: Box::new(second.header().clone()),
        config: AppliedConfig::Continuation {
            after_next: ConfigSlot::Ready(h.config(4)),
        },
    };
    h.fire(event);
    assert_eq!(h.core.halted, Some(HaltReason::DriverAnomaly));
    assert_eq!(h.core.applied, 1);
    assert!(h.core.config(4).is_none());
}

#[test]
fn det_s44_boundary_conflict_is_atomic() {
    let mut h = boundary_harness(3, 0);
    h.commit_heights(2);
    h.auto_apply = false;
    let boundary = h.commit_with(0, b"boundary work");
    let mut wrong = h.config(5);
    wrong.epoch.id.context = Hash32([0xAB; 32]);
    let before = h.core.configs.clone();
    h.fire(Event::BlockApplied {
        height: 3,
        block_hash: h.bh(&boundary),
        header: Box::new(boundary.header().clone()),
        config: AppliedConfig::Boundary {
            next: h.config(4),
            after_next: wrong,
        },
    });
    assert_eq!(h.core.halted, Some(HaltReason::DriverAnomaly));
    assert_eq!(h.core.applied, 2);
    assert_eq!(h.core.configs, before);
}

/// At a boundary, at view 0 and after a view change, only nonempty work becomes a proposal.
#[test]
fn boundary_proposal_requires_nonempty_original_work() {
    for view in [0, 2] {
        let mut h = boundary_harness(1, view);
        if view > 0 {
            h.enter_view(view);
        } else {
            h.tick(h.params.block_time);
        }
        let req = h.last_build.expect("scheduled build");
        h.fire(Event::PayloadBuilt { req, payload: None });
        assert!(
            h.core.mine.proposal.is_none(),
            "empty boundary builds never become blocks"
        );
        h.fire(Event::PayloadReady { req });
        let req = h.last_build.expect("work triggers a new build");
        h.fire(Event::PayloadBuilt {
            req,
            payload: h.payload(b"boundary work"),
        });
        let proposal = h
            .core
            .mine
            .proposal
            .as_ref()
            .expect("nonempty boundary proposal");
        assert!(proposal.header.payload_len > 0);
        assert_eq!(proposal.header.epoch, h.config(1).epoch.id);
    }
}

/// Epoch boundaries commit through local proposal, remote proposal, sync and durable restart.
#[test]
fn boundary_commits_and_applies_through_all_native_sources() {
    // (a) The boundary leader proposes original work and commits.
    let mut h = boundary_harness_at(1, pick::leader(0));
    h.tick(h.params.block_time);
    h.built(b"boundary work");
    let header = h
        .core
        .mine
        .proposal
        .as_ref()
        .expect("nonempty boundary proposal")
        .header
        .clone();

    let block = h.author(header, b"boundary work");
    let out = h.exec_all();
    assert_eq!(
        votes_of(&out, VoteKind::Prepare).len(),
        1,
        "the leader Prepares"
    );
    let from = h.others(1, &[])[0];
    let out = h.deliver(from, WireMessage::Qc(h.qc_q(VoteKind::Prepare, 0, &block)));
    let commit = votes_of(&out, VoteKind::Commit);
    assert_eq!(
        commit.len(),
        1,
        "the prepared exact quorum permits the Commit vote"
    );

    assert!(faults(&h.all).is_empty());
    h.deliver(from, WireMessage::Qc(h.qc_q(VoteKind::Commit, 0, &block)));
    assert_entered_next_epoch(&h);

    // (d) The durable tip is the boundary certificate.
    h.restart();
    assert_entered_next_epoch(&h);

    // (b) A remote leader's boundary proposal is no signed defect.
    let mut h = boundary_harness_at(1, pick::set_a(0));
    let block = h.block(0, b"remote boundary");

    let p = h.proposal(0, &block, None);
    let mut out = h.deliver(h.leader(0), WireMessage::Proposal(Box::new(p)));
    out.extend(h.exec_all());
    assert!(evidence(&h.all).is_empty(), "no InvalidProposal evidence");
    assert_eq!(votes_of(&out, VoteKind::Prepare).len(), 1);
    let from = h.others(1, &[])[0];
    let out = h.deliver(from, WireMessage::Qc(h.qc_q(VoteKind::Prepare, 0, &block)));
    assert_eq!(votes_of(&out, VoteKind::Commit).len(), 1);
    h.deliver(from, WireMessage::Qc(h.qc_q(VoteKind::Commit, 0, &block)));
    assert_entered_next_epoch(&h);

    // (c) Sync: the boundary and its successor arrive as sync entries.
    let mut h = boundary_harness_at(1, pick::set_a(0));
    let boundary = h.block(0, b"synced boundary");

    let next = h.block_at(2, (h.bh(&boundary), result_of(&boundary)), 0, b"next epoch");
    let entries: Vec<_> = [&boundary, &next]
        .into_iter()
        .map(|block| crate::message::SyncEntry {
            manifest: manifest(block),
            commit_qc: h.cqc_for(block, 0),
        })
        .collect();
    let peer = h.others(1, &[])[0];
    h.deliver(
        peer,
        WireMessage::Status(Box::new(Status {
            instance: I,
            height: 3,
            committed_qc: Some(entries[1].commit_qc.clone()),
            ..Status::default()
        })),
    );
    h.deliver(
        peer,
        WireMessage::SyncResponse(crate::message::SyncResponse {
            instance: I,
            blocks: entries,
        }),
    );
    assert_eq!(h.core.tip.height, 2, "synced across the boundary");
    assert_eq!(h.core.halted, None);
}

#[test]
fn epoch_seed_changes_topology_without_changing_committee() {
    let h = H::new(7, |_| 0);
    let current = h.config(1);
    let original =
        crate::topology::committee_permutation(&h.v.crypto, &I, &current.epoch, &current.committee);
    let mut changed = current.epoch;
    let distinct = (0..32).any(|byte| {
        changed.leader_seed = Hash32([byte; 32]);
        crate::topology::committee_permutation(&h.v.crypto, &I, &changed, &current.committee)
            != original
    });
    assert!(
        distinct,
        "authenticated leader randomness must affect actual routing"
    );
}

#[test]
fn boundary_restart_never_installs_unapplied_authority() {
    let mut h = boundary_harness(3, 0);
    h.commit_heights(2);
    h.auto_apply = false;
    let boundary = h.commit_with(0, b"boundary");
    let (_, certificate) = h.store.pop().expect("unapplied boundary publication");
    // Restart reconstructs the config window from the applied durable state, not the
    // speculative execution or the received boundary certificate.
    h.restart();
    assert_eq!(h.core.applied, 2);
    assert_eq!(h.height(), 3);
    assert!(h.core.config(4).is_none());
    let from = h.others(1, &[])[0];
    h.deliver(from, WireMessage::Qc(certificate));
    assert_eq!(h.core.tip.height, 3);
    assert!(h.core.awaiting);
    h.apply_height(3);
    assert_eq!(h.height(), 4);
    assert_eq!(h.core.cfg.epoch.id, h.config(4).epoch.id);
    h.restart();
    assert_eq!(h.height(), 4);
    assert_eq!(h.core.cfg.epoch.id, h.config(4).epoch.id);
    assert_ne!(h.core.cfg.epoch.id, boundary.header().epoch);

    let mut record = h.core.safety.clone().expect("retained signer active");
    record.epoch = boundary.header().epoch;
    h.records
        .insert(record.key.clone(), record.encode(&h.v.crypto).unwrap());
    h.restart();
    assert_eq!(h.core.halted, Some(HaltReason::SafetyRecordInconsistent));
}

#[test]
fn boundary_core_four_seven_four_keeps_exact_quorums_and_contexts() {
    let mut h = H::new(7, |_| 0);
    let four = Committee::new(h.v.committee.members()[..4].to_vec()).unwrap();
    h.committees.insert(0, four.clone());
    h.committees.insert(4, h.v.committee.clone());
    h.committees.insert(7, four);
    h.records.clear();
    h.install_keys();
    h.restart();
    for height in 1..=9 {
        let before = h.config(height);
        assert_eq!(
            before.committee.n(),
            if (4..7).contains(&height) { 7 } else { 4 }
        );
        let block = h.commit_with(0, &height.to_be_bytes());
        let certificate = &h.store.last().unwrap().1;
        assert_eq!(certificate.signers.count_ones(), before.committee.q());
        assert_eq!(certificate.epoch, before.epoch.id);
        assert_eq!(block.header().epoch, certificate.epoch);
        assert_eq!(h.core.halted, None);
        assert_eq!(h.core.applied, height);
        assert_eq!(h.core.cfg.epoch.id, h.config(height + 1).epoch.id);
    }
}

#[test]
fn retained_key_probe_cannot_anchor_a_different_epoch_context() {
    let mut h = boundary_harness(3, 0);
    h.commit_heights(3);
    let old = h.config(3).epoch.id;
    let current = h.config(4).epoch.id;
    let key = h.key_at(h.others(1, &[])[0]);
    h.core.keys[0].unanchored = true;
    for (epoch, accepted) in [(old, false), (current, true)] {
        let sig = h
            .signer_of(&key)
            .sign(&preimage::echo_preimage(&I, &epoch, h.nonce, 4));
        let message = Status {
            instance: I,
            height: 4,
            echo: Some(crate::message::Echo {
                epoch,
                nonce: h.nonce,
                key: key.clone(),
                sig,
            }),
            ..Status::default()
        };
        h.deliver_key(key.clone(), WireMessage::Status(Box::new(message)));
        assert_eq!(h.core.probe.contains_key(&key), accepted);
    }
    assert_eq!(h.core.probe_epoch, Some(current));
    assert!(
        h.core.keys[0].unanchored,
        "one valid echo is not an anchoring quorum"
    );
}

#[test]
fn boundary_certificates_keep_context_checks_before_cache_hits() {
    let mut h = boundary_harness(1, 0);
    let block = h.block(0, b"boundary");

    let good_pqc = h.qc_q(VoteKind::Prepare, 0, &block);
    let entries = |qc: &Qc| {
        (0..3)
            .map(|index| (index, Some(qc.clone())))
            .collect::<Vec<_>>()
    };
    let good_tc = h.tc(0, &entries(&good_pqc));
    // The same certificates relabelled with the successor epoch's context.
    let successor = h.config(2).epoch.id;
    let mut bad_pqc = good_pqc.clone();
    bad_pqc.epoch = successor;
    let mut bad_tc = good_tc.clone();
    bad_tc.epoch = successor;
    assert!(!h.core.verify_qc_cached(&bad_pqc));
    assert!(!h.core.verify_tc_cached(&bad_tc));
    // Even a populated verification cache cannot bypass the installed context checks.
    h.core.cert_cache.insert(bad_pqc.digest(&h.v.crypto));
    h.core.cert_cache.insert(bad_tc.digest(&h.v.crypto));
    assert!(!h.core.verify_qc_cached(&bad_pqc));
    assert!(!h.core.verify_tc_cached(&bad_tc));
    assert!(h.core.verify_qc_cached(&good_pqc));
    assert!(h.core.verify_tc_cached(&good_tc));
}
