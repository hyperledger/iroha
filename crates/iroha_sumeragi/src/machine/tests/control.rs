//! Independent control witnesses and bounded all-validator partial delivery.

use super::*;
use crate::{api::ControlWitnessContext, message::ApplicationControl, types::ControlWitness};

fn request(h: &H) -> (u64, ControlWitnessContext) {
    h.all
        .iter()
        .rev()
        .find_map(|action| match action {
            Action::BuildControlWitness { req, context } => Some((*req, *context)),
            _ => None,
        })
        .expect("selected nonempty work requests exact source control")
}
fn answer(h: &mut H, req: u64, context: ControlWitnessContext) {
    h.fire(Event::ControlWitnessBuilt {
        req,
        context,
        witness: ControlWitness::try_from_slice(b"authenticated application input").unwrap(),
    });
}
#[test]
fn det_s46_control_witness_is_bound_by_header_hash_and_proposal_signature() {
    let h = H::new(4, pick::leader(0));
    let original = h.block(0, b"transactions");
    let mut header = original.header().clone();
    header.control_witness = ControlWitness::try_from_slice(b"pulse-A").unwrap();
    let original = h.author(header, original.payload().as_slice());
    let signed = h.proposal(0, &original, None);
    let leader = h.v.signer(h.leader(0));
    assert!(h.v.crypto.verify(
        leader.public_key(),
        &signed.proposal.signing_preimage(&h.v.crypto),
        &signed.proposal.sig
    ));
    for bytes in [b"pulse-B".as_slice(), b"", b"pulse-A\0"] {
        let mut changed = signed.clone();
        changed.proposal.header.control_witness = ControlWitness::try_from_slice(bytes).unwrap();
        assert_ne!(
            changed.proposal.block_hash(&h.v.crypto),
            signed.proposal.block_hash(&h.v.crypto)
        );
        assert!(!h.v.crypto.verify(
            leader.public_key(),
            &changed.proposal.signing_preimage(&h.v.crypto),
            &signed.proposal.sig
        ));
    }
}
#[test]
fn det_s47_nonempty_work_waits_for_independent_control_and_preserves_original_payload() {
    let mut h = H::new(4, pick::leader(2));
    h.auto_control = false;
    h.enter_view(2);
    assert!(
        !h.all
            .iter()
            .any(|a| matches!(a, Action::BuildControlWitness { .. }))
    );
    h.built(b"last transaction");
    let (req, context) = request(&h);
    assert!(
        h.core.mine.proposal.is_none(),
        "missing control cannot be invented"
    );
    assert!(h.core.build_deadline().is_none());
    let original = h
        .core
        .fresh_build
        .as_ref()
        .unwrap()
        .payload
        .as_ref()
        .unwrap()
        .as_slice()
        .as_ptr();
    h.fire(Event::PayloadBuilt {
        req,
        payload: h.payload(b"replacement"),
    });
    assert_eq!(
        h.core
            .fresh_build
            .as_ref()
            .unwrap()
            .payload
            .as_ref()
            .unwrap()
            .as_slice()
            .as_ptr(),
        original
    );
    answer(&mut h, req, context);
    let proposed = h.core.mine.proposal.as_ref().unwrap();
    assert_eq!(
        proposed.header.payload_len,
        u32::try_from(b"last transaction".len()).unwrap()
    );
    assert_eq!(
        proposed.header.control_witness.as_slice(),
        b"authenticated application input"
    );
    let hash = proposed.block_hash(&h.v.crypto);
    assert_eq!(h.bodies[&hash].payload().as_slice(), b"last transaction");
}
#[test]
fn transaction_timeout_cannot_start_control_or_accept_late_work() {
    let mut h = H::new(4, pick::leader(1));
    h.auto_control = false;
    h.enter_view(1);
    let req = h.last_build.unwrap();
    let context = h.core.fresh_build.as_ref().unwrap().context;
    // Even a matching unsolicited response cannot substitute for work selection.
    answer(&mut h, req, context);
    assert!(h.core.fresh_build.as_ref().unwrap().payload.is_none());
    assert!(h.core.mine.proposal.is_none());
    h.tick(h.local.build_timeout);
    assert!(h.core.mine.proposal.is_none());
    assert!(h.core.fresh_build.is_none());
    assert!(
        !h.all
            .iter()
            .any(|a| matches!(a, Action::BuildControlWitness { .. }))
    );
    h.fire(Event::PayloadBuilt {
        req,
        payload: h.payload(b"too late"),
    });
    answer(&mut h, req, context);
    assert!(h.core.mine.proposal.is_none());
    assert!(
        !h.all
            .iter()
            .any(|a| matches!(a, Action::BuildControlWitness { .. }))
    );
    // A real readiness signal starts a new request; only that source may complete.
    h.fire(Event::PayloadReady { req });
    let next = h.last_build.unwrap();
    assert_ne!(next, req);
    h.built(b"retry transaction");
    let (actual, next_context) = request(&h);
    assert_eq!(actual, next);
    answer(&mut h, req, context);
    assert!(h.core.mine.proposal.is_none());
    answer(&mut h, next, next_context);
    assert!(h.core.mine.proposal.is_some());
}
#[test]
fn empty_work_does_not_request_control_or_create_a_heartbeat() {
    let mut h = H::new(4, pick::leader(1));
    h.auto_control = false;
    h.enter_view(1);
    h.built(b"");
    assert!(h.core.mine.proposal.is_none());
    assert!(h.core.fresh_build.is_none());
    assert!(
        !h.all
            .iter()
            .any(|a| matches!(a, Action::BuildControlWitness { .. }))
    );
}
#[test]
fn det_s48_control_response_requires_exact_request_epoch_view_and_parent_source() {
    for field in 0..6 {
        let mut h = H::new(4, pick::leader(2));
        h.auto_control = false;
        h.enter_view(2);
        h.built(b"source-bound work");
        let (req, context) = request(&h);
        let mut changed = context;
        match field {
            0 => changed.height += 1,
            1 => changed.view += 1,
            2 => changed.epoch.epoch += 1,
            3 => changed.epoch.context = Hash32([0xFA; 32]),
            4 => changed.parent_hash = Hash32([0xFB; 32]),
            5 => changed.parent_result = Hash32([0xFC; 32]),
            _ => unreachable!(),
        }
        answer(&mut h, req, changed);
        assert!(h.core.mine.proposal.is_none());
        answer(&mut h, req + 1, context);
        assert!(h.core.mine.proposal.is_none());
        answer(&mut h, req, context);
        assert!(h.core.mine.proposal.is_some());
    }
}
#[test]
fn every_member_drives_exact_applied_parent_and_partial_ingress_is_bounded() {
    let mut h = H::new(4, pick::leader(1)); // nonleader in view zero
    let context = h.core.application_control_context().unwrap();
    assert!(
        h.all.iter().any(
            |a| matches!(a, Action::DriveApplicationControl { context: got } if *got == context)
        )
    );
    let message = ApplicationControl {
        context,
        bytes: ControlWitness::try_from_slice(b"signed share").unwrap(),
    };
    let other = h.others(1, &[])[0];
    let actions = h.deliver(other, WireMessage::ApplicationControl(message.clone()));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::ReceiveApplicationControl { .. }))
    );
    assert!(
        !h.deliver(other, WireMessage::ApplicationControl(message.clone()))
            .iter()
            .any(|a| matches!(a, Action::ReceiveApplicationControl { .. }))
    );
    let mut foreign = message.clone();
    foreign.context.parent_result = Hash32([0x99; 32]);
    assert!(
        !h.fire(Event::ApplicationControlBuilt { message: foreign })
            .iter()
            .any(|a| matches!(
                a,
                Action::Broadcast {
                    msg: WireMessage::ApplicationControl(_),
                    ..
                }
            ))
    );
    assert!(h.fire(Event::ApplicationControlBuilt { message }).iter().any(|a| matches!(a, Action::Broadcast { msg: WireMessage::ApplicationControl(_), to } if to.len() == 3)));
    h.auto_apply = false;
    h.commit_with(0, b"next");
    assert!(h.core.application_control_context().is_none());
    assert!(
        !h.tick(h.local.rebroadcast_interval)
            .iter()
            .any(|a| matches!(a, Action::DriveApplicationControl { .. }))
    );
    assert!(
        h.apply_height(1).iter().any(
            |a| matches!(a, Action::DriveApplicationControl { context } if context.height == 2)
        )
    );
}

#[test]
fn locked_reproposal_and_restart_preserve_exact_control_header() {
    let mut h = H::new(4, pick::leader(2));
    h.auto_control = false;
    let original = h.block(0, b"locked transactions");
    let mut header = original.header().clone();
    header.control_witness = ControlWitness::try_from_slice(b"original finalized pulse").unwrap();
    let original = h.author(header, original.payload().as_slice());
    let hash = h.bh(&original);
    h.bodies.insert(hash, original.clone());
    h.fire(Event::BodyAvailable {
        block: original.clone(),
    });
    let pqc = h.qc_q(VoteKind::Prepare, 0, &original);
    let entries = h
        .others(h.q(), &[])
        .into_iter()
        .map(|index| (index, Some(pqc.clone())))
        .collect::<Vec<_>>();
    let tc = h.tc(1, &entries);
    h.deliver(h.others(1, &[])[0], WireMessage::Tc(Box::new(tc)));
    let proposal = h
        .core
        .mine
        .proposal
        .as_ref()
        .expect("locked block reproposed");
    assert_eq!(proposal.header, original.header().clone());
    assert_eq!(proposal.block_hash(&h.v.crypto), hash);
    assert!(
        !h.out
            .iter()
            .any(|a| matches!(a, Action::BuildControlWitness { .. }))
    );
    h.restart();
    let replayed = h
        .core
        .mine
        .proposal
        .as_ref()
        .expect("recorded proposal replayed");
    assert_eq!(replayed.header, original.header().clone());
    assert_eq!(replayed.block_hash(&h.v.crypto), hash);
}

#[test]
fn control_work_context_requires_complete_applied_parent_and_current_signer() {
    let mut h = H::new(4, pick::leader(1));
    let (source, view) = h.core.control_work_context().unwrap();
    assert_eq!(Some(source), h.core.application_control_context());
    assert_eq!(view, h.core.view);
    h.enter_view(2);
    let (same_source, next_view) = h.core.control_work_context().unwrap();
    assert_eq!(same_source, source);
    assert_eq!(next_view, 2);
    h.auto_apply = false;
    h.commit_with(2, b"new applied parent");
    assert!(h.core.control_work_context().is_none());
    h.apply_height(1);
    let (next_source, _) = h.core.control_work_context().unwrap();
    assert_eq!(next_source.height, 2);
    assert_eq!(next_source.epoch, h.core.cfg.epoch.id);
    assert_eq!(next_source.parent_hash, h.core.tip.block_hash);
    assert_eq!(next_source.parent_result, h.core.tip.result);
    assert_ne!(next_source.parent_hash, source.parent_hash);
    let signer = h.core.me.take();
    assert!(
        h.core.control_work_context().is_none(),
        "an observer cannot authorize work"
    );
    h.core.me = signer;
    assert!(h.core.control_work_context().is_some());
    h.core.halted = Some(crate::api::HaltReason::PublicationRecoveryRequired { height: 1 });
    assert!(h.core.control_work_context().is_none());
}
