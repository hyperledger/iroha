//! Deterministic recovery tests: persisted certificates remain untrusted until verified.

use super::*;
use crate::{
    safety::{RecordedProposal, RecordedTimeout, RecordedVote},
    types::{AggregateSignature, SIGNATURE_LEN},
};

fn retained_record(h: &H) -> SafetyRecord {
    let block = h.block(0, b"retained certified block");
    let lock = h.qc_q(VoteKind::Prepare, 1, &block);
    let tc = h.v.tc(
        &I,
        h.height(),
        1,
        &[(0, Some(lock.clone())), (1, None), (2, None)],
    );
    SafetyRecord {
        instance: I,
        epoch: h.config(h.height()).epoch.id,
        key: h.signers[0].public_key().clone(),
        height: h.height(),
        parent_commit_qc: h.core.tip.commit_qc.clone(),
        proposal: Some(RecordedProposal {
            view: 2,
            block_hash: lock.block_hash,
            justify: Some(tc.clone()),
        }),
        proposal_signature: None,
        prepare: Some(RecordedVote {
            view: 2,
            block_hash: lock.block_hash,
            result: lock.result,
        }),
        prepare_signature: Some(
            h.signers[0]
                .sign(&crate::preimage::vote_preimage(
                    VoteKind::Prepare,
                    &I,
                    &h.config(h.height()).epoch.id,
                    h.height(),
                    2,
                    &lock.block_hash,
                    &lock.result,
                ))
                .unwrap(),
        ),
        timeout: Some(RecordedTimeout {
            view: 2,
            high_pqc: Some(lock.clone()),
        }),
        lock: Some(lock),
        high_tc: Some(tc),
    }
}

/// MS57: even a checksummed current record cannot turn any unverified retained or nested
/// certificate into a lock, trusted cache entry or local signature.
#[test]
fn det_s57_restart_verifies_every_retained_certificate() {
    for location in 0..6 {
        let mut h = H::new(4, pick::set_a(0));
        h.auto_fetch = false;
        let mut record = retained_record(&h);
        let bad = AggregateSignature([7; SIGNATURE_LEN]);
        match location {
            0 => record.lock.as_mut().unwrap().agg_sig = bad,
            1 => {
                record
                    .timeout
                    .as_mut()
                    .unwrap()
                    .high_pqc
                    .as_mut()
                    .unwrap()
                    .agg_sig = bad
            }
            2 => record.high_tc.as_mut().unwrap().agg_sig = bad,
            3 => {
                record
                    .high_tc
                    .as_mut()
                    .unwrap()
                    .high_pqc
                    .as_mut()
                    .unwrap()
                    .agg_sig = bad
            }
            4 => {
                record
                    .proposal
                    .as_mut()
                    .unwrap()
                    .justify
                    .as_mut()
                    .unwrap()
                    .agg_sig = bad
            }
            5 => {
                record
                    .proposal
                    .as_mut()
                    .unwrap()
                    .justify
                    .as_mut()
                    .unwrap()
                    .high_pqc
                    .as_mut()
                    .unwrap()
                    .agg_sig = bad;
            }
            _ => unreachable!(),
        }
        let lock_digest = record.lock.as_ref().unwrap().digest(&h.v.crypto);
        let bytes = record.encode(&h.v.crypto).unwrap();
        h.records.insert(record.key.clone(), bytes.clone());
        let signed_before = h.log.signatures_by(&record.key).len();
        let out = h.restart();
        assert_eq!(
            halts(&out),
            vec![HaltReason::SafetyRecordInconsistent],
            "location {location}"
        );
        assert!(
            h.core.high_pqc.is_none(),
            "no lock installed at location {location}"
        );
        assert!(h.core.high_tc.is_none());
        assert!(!h.core.cert_cache.contains(&lock_digest));
        assert_eq!(h.log.signatures_by(&record.key).len(), signed_before);
        assert_eq!(
            h.records[&record.key], bytes,
            "refused record remains intact"
        );
        assert!(!out.iter().any(|action| matches!(
            action,
            Action::PersistSafety(_) | Action::ReportEvidence(_) | Action::PayloadRejected { .. }
        )));
    }
}

#[test]
fn restart_current_record_restores_exact_lock_and_signing_reservations() {
    let mut h = H::new(4, pick::set_a(0));
    h.auto_fetch = false;
    let record = retained_record(&h);
    h.records
        .insert(record.key.clone(), record.encode(&h.v.crypto).unwrap());
    let out = h.restart();
    assert!(halts(&out).is_empty());
    assert_eq!(h.core.high_pqc, record.lock);
    assert_eq!(h.core.high_tc, record.high_tc);
    assert_eq!(h.core.timeout_view, Some(2));
    assert_eq!(
        (h.height(), h.core.view),
        (record.height, record.resume_view())
    );
    assert_eq!(h.durable(), Some(record.clone()));
    let prepare = h.core.mine.prepare.as_ref().unwrap();
    let reserved = record.prepare.unwrap();
    assert_eq!(
        (prepare.block_hash, prepare.result),
        (reserved.block_hash, reserved.result)
    );
    assert_eq!(h.core.mine.timeout.as_ref().unwrap().high_pqc, record.lock);
}

#[test]
fn restart_requires_verified_parent_above_genesis() {
    for absent in [true, false] {
        let mut h = H::new(4, pick::set_a(0));
        h.commit_heights(1);
        let mut record = retained_record(&h);
        if absent {
            record.parent_commit_qc = None;
        } else {
            record.parent_commit_qc.as_mut().unwrap().agg_sig =
                AggregateSignature([7; SIGNATURE_LEN]);
            // Equality to the local tip is not a cryptographic verification result.
            h.store.last_mut().unwrap().1 = record.parent_commit_qc.clone().unwrap();
        }
        let bytes = record.encode(&h.v.crypto).unwrap();
        h.records.insert(record.key.clone(), bytes.clone());
        let out = h.restart();
        assert_eq!(halts(&out), vec![HaltReason::SafetyRecordInconsistent]);
        assert!(h.core.high_pqc.is_none());
        assert!(h.core.high_tc.is_none());
        assert_eq!(h.records[&record.key], bytes);
    }
}

/// MS57 also covers R5: an authentic parent cannot make an otherwise corrupt record
/// advance the durable-store tip before its retained round certificates are checked.
#[test]
fn det_s57_recommit_refuses_unverified_retained_lock_before_advancing_tip() {
    let mut h = H::new(4, pick::set_a(0));
    h.commit_heights(2);
    let mut record = retained_record(&h);
    record.lock.as_mut().unwrap().agg_sig = AggregateSignature([7; SIGNATURE_LEN]);
    let bytes = record.encode(&h.v.crypto).unwrap();
    h.records.insert(record.key.clone(), bytes.clone());
    h.store.truncate(1);
    let out = h.restart();
    assert_eq!(halts(&out), vec![HaltReason::SafetyRecordInconsistent]);
    assert_eq!(
        h.core.tip.height, 1,
        "R5 must not install the authentic parent yet"
    );
    assert!(h.core.high_pqc.is_none());
    assert_eq!(h.records[&record.key], bytes);
    assert!(
        !out.iter()
            .any(|action| matches!(action, Action::CommitBlock { .. }))
    );
}

#[test]
fn recommit_waits_for_authenticated_record_epoch() {
    let mut h = H::new(4, pick::set_a(0));
    h.committees.insert(2, h.v.committee.clone());
    h.records.clear();
    h.install_keys();
    h.restart();
    h.commit_heights(1);
    let mut record = h.core.safety.clone().unwrap();
    let block = h.block(0, b"retained next epoch block");
    record.lock = Some(h.qc_q(VoteKind::Prepare, 0, &block));
    assert_eq!(record.height, 2);
    let bytes = record.encode(&h.v.crypto).unwrap();
    h.records.insert(record.key.clone(), bytes.clone());
    h.store.clear();
    let out = h.restart();
    assert!(halts(&out).is_empty());
    assert_eq!(h.core.tip.height, 0);
    assert!(
        h.core.config(2).is_none(),
        "new epoch has no authenticated authority yet"
    );
    assert!(h.core.high_pqc.is_none());
    assert_eq!(h.core.keys[0].restore.as_ref(), Some(&record));
    assert!(h.core.status().signer.is_none());
    assert_eq!(h.records[&record.key], bytes);
    assert!(
        !out.iter()
            .any(|action| matches!(action, Action::CommitBlock { .. }))
    );
}

/// MS64: a next-epoch reservation contains no certificate requiring that epoch's authority.
/// R5 verifies its sole parent certificate, applies that boundary, then restores under the
/// now-authenticated epoch. Requiring the future authority first would strand key rotation.
#[test]
fn det_s64_recommit_parent_only_record_authenticates_boundary_before_resuming() {
    let mut h = H::new(4, pick::set_a(0));
    h.committees.insert(2, h.v.committee.clone());
    h.records.clear();
    h.install_keys();
    h.restart();
    h.commit_heights(1);
    let mut record = h.core.safety.clone().unwrap();
    record.timeout = Some(RecordedTimeout {
        view: 0,
        high_pqc: None,
    });
    assert_eq!(record.height, 2);
    h.records
        .insert(record.key.clone(), record.encode(&h.v.crypto).unwrap());
    h.store.clear();
    let out = h.restart();
    assert!(halts(&out).is_empty());
    let committed: Vec<_> = h
        .all
        .iter()
        .filter_map(|action| match action {
            Action::CommitBlock { block, .. } => Some(block.header().height),
            _ => None,
        })
        .collect();
    assert_eq!(committed, vec![1]);
    assert_eq!((h.core.tip.height, h.height()), (1, 2));
    assert_eq!(h.core.cfg.epoch.id, record.epoch);
    assert_eq!(h.core.timeout_view, Some(0));
    assert_eq!(h.core.status().signer.as_ref(), Some(&record.key));
    assert_eq!(h.durable(), Some(record));
}
