//! Work-driven nonempty proposals, durable vote replay, and current consensus roles.
use super::*;
use crate::{
    message::Defect,
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

#[test]
fn empty_proposals_are_rejected_at_every_view() {
    for view in [0, 1, 2, 7] {
        let mut h = H::new(4, pick::set_b(0));
        for next in 1..=view {
            h.enter_view(next);
        }
        let justify = h.core.high_tc.clone();
        let block = h.block(view, b"nonempty author source");
        let mut p = h.proposal(view, &block, justify);
        p.proposal.header.payload_len = 0;
        p.proposal.header.payload_hash = preimage::payload_hash(&h.v.crypto, b"");
        p.proposal.sig = h
            .signer_of(&h.key_at(h.leader(view)))
            .sign(&p.proposal.signing_preimage(&h.v.crypto));
        let out = h.deliver(h.leader(view), WireMessage::Proposal(Box::new(p)));
        assert!(matches!(
            evidence(&out)[..],
            [Evidence::InvalidProposal {
                defect: Defect::EmptyPayload,
                ..
            }]
        ));
        assert_eq!(timeouts(&out).len(), 1, "early timeout");
        assert!(h.core.proposal.is_none());
    }
}

#[test]
fn restart_resends_identical_votes() {
    let mut h = H::new(4, pick::set_a(0));
    let b = h.block(0, b"payment");
    prop(&mut h, 0, &b, None);
    let out = h.exec_all();
    let prepare = votes_of(&out, VoteKind::Prepare)[0];
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    let out = qc_msg(&mut h, pqc);
    let commit = votes_of(&out, VoteKind::Commit)[0];
    let out = h.restart();
    assert_eq!(
        h.core.mine.prepare.as_ref(),
        Some(&prepare),
        "identical Prepare"
    );
    assert_eq!(
        votes_of(&out, VoteKind::Commit),
        vec![commit],
        "identical Commit"
    );
    assert_eq!(
        h.my_sigs(KIND_PREPARE, 1, 0).len(),
        1,
        "one Prepare preimage"
    );
    assert_eq!(h.my_sigs(KIND_COMMIT, 1, 0).len(), 1, "one Commit preimage");
}

#[test]
fn status_reports_roles_and_lock_view() {
    let mut h = H::new(4, pick::set_a(0));
    let status = h.core.status();
    assert_eq!(status.leader, Some(h.key_at(h.leader(0))));
    assert_eq!(status.proxy_tail, Some(h.key_at(h.proxy_tail(0))));
    assert_eq!(status.high_qc_view, None);
    let b = h.block(0, b"B");
    let pqc = h.qc_q(VoteKind::Prepare, 0, &b);
    qc_msg(&mut h, pqc);
    assert_eq!(h.core.status().high_qc_view, Some(0));
    h.enter_view(1);
    let status = h.core.status();
    assert_eq!(status.leader, Some(h.key_at(h.leader(1))));
    assert_eq!(status.proxy_tail, Some(h.key_at(h.proxy_tail(1))));
    // Awaiting (apply held back two heights): no roles.
    h.auto_apply = false;
    h.commit_heights(2);
    let block = h.block(0, b"C");
    h.bodies.insert(h.bh(&block), block.clone());
    let cqc = h.qc_q(VoteKind::Commit, 0, &block);
    qc_msg(&mut h, cqc);
    assert!(h.core.awaiting);
    let status = h.core.status();
    assert_eq!((status.leader, status.proxy_tail), (None, None));
}
