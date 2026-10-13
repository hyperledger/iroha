//! Local cryptographic refusals never acquire signed-message or certificate custody.
use super::*;
use crate::{
    api::{CertificateKind, SigningKind},
    crypto::{AggregationError, FormError, SigningError},
    types::AggregateSignature,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

struct RefusingSigner {
    inner: FakeSigner,
    refused: AtomicBool,
    attempts: Mutex<Vec<Vec<u8>>>,
    prepares: Mutex<Vec<ObservedPrepare>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedPrepare {
    preimage: Vec<u8>,
    instance: Hash32,
    epoch: crate::types::EpochId,
    height: u64,
    block_hash: Hash32,
    result: Hash32,
    certified: bool,
}

impl Signer for RefusingSigner {
    fn sign_prepare(
        &self,
        context: &crate::crypto::PrepareSigningContext<'_>,
    ) -> Result<Signature, crate::crypto::SigningError> {
        self.prepares.lock().unwrap().push(ObservedPrepare {
            preimage: context.preimage().to_vec(),
            instance: *context.instance(),
            epoch: *context.epoch(),
            height: context.height(),
            block_hash: *context.block_hash(),
            result: *context.result(),
            certified: context.certified(),
        });
        self.sign(context.preimage())
    }

    fn public_key(&self) -> &PublicKey {
        self.inner.public_key()
    }
    fn sign(&self, preimage: &[u8]) -> Result<Signature, SigningError> {
        self.attempts.lock().unwrap().push(preimage.to_vec());
        if self.refused.load(Ordering::Relaxed) {
            Err(SigningError::Refused)
        } else {
            self.inner.sign(preimage)
        }
    }
}

fn refuse(h: &mut H) -> Arc<RefusingSigner> {
    let signer = Arc::new(RefusingSigner {
        inner: h.signers[0].clone(),
        refused: AtomicBool::new(true),
        attempts: Mutex::new(Vec::new()),
        prepares: Mutex::new(Vec::new()),
    });
    let me = h.core.me.unwrap();
    h.core.keys[me.slot].signer = Some(signer.clone());
    signer
}

#[test]
fn det_prepare_context_uses_later_authenticated_qc_with_cached_valid_result() {
    let mut h = H::new(4, pick::set_a(0));
    let block = h.block(0, b"completed result later receives its actual PrepareQC");
    let proposal = h.proposal(0, &block, None);
    h.deliver(h.leader(0), WireMessage::Proposal(Box::new(proposal)));
    let signer = refuse(&mut h);
    let first = h.exec_all();
    assert_refused(&first, SigningKind::Prepare);
    let original = signer.prepares.lock().unwrap()[0].clone();
    assert!(
        !original.certified,
        "an uncertified successful execution grants no clock exemption"
    );
    assert_eq!(
        (
            original.instance,
            original.epoch,
            original.height,
            original.block_hash
        ),
        (I, h.config(1).epoch.id, 1, h.bh(&block))
    );
    assert_eq!(
        original.preimage,
        crate::preimage::vote_preimage(
            VoteKind::Prepare,
            &original.instance,
            &original.epoch,
            original.height,
            0,
            &original.block_hash,
            &original.result,
        )
    );
    let qc = h.qc_q(VoteKind::Prepare, 0, &block);
    assert_eq!(qc.result, original.result);
    h.deliver(h.others(1, &[])[0], WireMessage::Qc(qc));
    assert!(
        matches!(h.core.exec.get(&original.block_hash), Some(super::super::ExecState::Valid(result)) if *result == original.result)
    );
    signer.prepares.lock().unwrap().clear();
    h.core.try_prepare();
    let observed = signer.prepares.lock().unwrap().clone();
    assert_eq!(observed.len(), 1);
    assert!(
        observed[0].certified,
        "cached Valid must use the subsequently authenticated exact PrepareQC"
    );
    assert_eq!(observed[0].preimage, original.preimage);
    assert!(
        h.core.mine.prepare.is_none(),
        "local signing refusal still creates no vote"
    );
    // An authenticated certificate for one pair grants no exemption to another result/hash.
    let me = h.core.me.unwrap();
    h.core.record_vote(
        me,
        VoteKind::Prepare,
        (original.block_hash, Hash32([0xfa; 32])),
    );
    h.core
        .record_vote(me, VoteKind::Prepare, (Hash32([0xfb; 32]), original.result));
    let observed = signer.prepares.lock().unwrap();
    assert!(observed[1..].iter().all(|context| !context.certified));
}

#[test]
fn det_prepare_context_restart_reservation_alone_is_uncertified() {
    let mut h = H::new(4, pick::set_a(0));
    let block = h.block(0, b"durable reservation without any PrepareQC");
    let proposal = h.proposal(0, &block, None);
    h.deliver(h.leader(0), WireMessage::Proposal(Box::new(proposal)));
    let signer = refuse(&mut h);
    h.exec_all();
    let original = signer.prepares.lock().unwrap()[0].clone();
    let durable = h.durable().unwrap();
    assert!(durable.prepare.is_some());
    assert!(durable.lock.is_none());
    signer.prepares.lock().unwrap().clear();
    let init = h.init(vec![(
        durable.key.clone(),
        RecordState::Present(durable.encode(&h.v.crypto).unwrap()),
        false,
    )]);
    let (core, actions) = Core::new(
        h.local,
        init,
        vec![signer.clone()],
        Box::new(h.v.crypto.clone()),
        h.budget.clone(),
        h.now,
    )
    .unwrap();
    let observed = signer.prepares.lock().unwrap();
    assert_eq!(observed.len(), 1);
    assert!(
        !observed[0].certified,
        "a restarted durable Prepare reservation must not grant certified clock exemption"
    );
    assert_eq!(observed[0].preimage, original.preimage);
    assert!(core.mine.prepare.is_none());
    assert!(votes(&actions).is_empty());
    assert_refused(&actions, SigningKind::Prepare);
}

fn assert_refused(actions: &[Action], kind: SigningKind) {
    assert!(actions.iter().any(|action| matches!(action,
        Action::LocalFault(LocalFault::SigningFailed { kind: actual, height: 1, view: 0, error: SigningError::Refused }) if *actual == kind
    )), "missing local fault for {kind:?}");
    assert!(actions.iter().all(|action| !matches!(
        action,
        Action::ReportEvidence(_) | Action::Halt(_) | Action::CommitBlock { .. }
    )));
}

fn allow_identical_retry(signer: &RefusingSigner) {
    signer.refused.store(false, Ordering::Relaxed);
}

fn assert_identical_attempts(signer: &RefusingSigner) {
    let attempts = signer.attempts.lock().unwrap();
    assert!(attempts.len() >= 2);
    assert!(attempts.iter().all(|attempt| attempt == &attempts[0]));
}

#[test]
fn det_signing_refusal_proposal_preserves_reservation_without_publication() {
    let mut h = H::new(4, pick::leader(0));
    h.run_until(1_000);
    let signer = refuse(&mut h);
    let out = h.built(b"reserved proposal");
    assert_refused(&out, SigningKind::Proposal);
    assert!(proposals(&out).is_empty());
    assert!(h.core.mine.proposal.is_none());
    assert!(h.core.proposal.is_none());
    assert!(h.core.proposal_sent_at.is_none());
    assert!(
        !out.iter()
            .any(|a| matches!(a, Action::DisseminatePayload { .. }))
    );
    let reserved = h.core.safety.as_ref().unwrap().proposal.clone().unwrap();
    assert!(
        out.iter().any(
            |a| matches!(a, Action::PersistSafety(r) if r.proposal.as_ref() == Some(&reserved))
        )
    );
    allow_identical_retry(&signer);
    h.tick(h.local.rebroadcast_interval);
    assert!(h.core.mine.proposal.is_some());
    assert_identical_attempts(&signer);
}

#[test]
fn det_signing_refusal_prepare_preserves_reservation_without_pooling() {
    let mut h = H::new(4, pick::set_a(0));
    let block = h.block(0, b"reserved prepare");
    let proposal = h.proposal(0, &block, None);
    h.deliver(h.leader(0), WireMessage::Proposal(Box::new(proposal)));
    let signer = refuse(&mut h);
    let out = h.exec_all();
    assert_refused(&out, SigningKind::Prepare);
    assert!(votes(&out).is_empty());
    assert!(h.core.mine.prepare.is_none());
    assert!(h.core.votes.get(VoteKind::Prepare, 0, h.me).is_none());
    assert!(h.core.retx[0].is_none());
    assert!(h.core.t_lastvote.is_none());
    let reserved = h.core.safety.as_ref().unwrap().prepare.unwrap();
    assert!(
        out.iter()
            .any(|a| matches!(a, Action::PersistSafety(r) if r.prepare == Some(reserved)))
    );
    // A later local execution disagreement cannot rewrite the reserved signing preimage.
    let bh = h.bh(&block);
    h.core
        .exec
        .insert(bh, super::super::ExecState::Valid(Hash32([0xf3; 32])));
    allow_identical_retry(&signer);
    h.core.try_prepare();
    assert_eq!(signer.attempts.lock().unwrap().len(), 1);
    h.core
        .exec
        .insert(bh, super::super::ExecState::Valid(reserved.result));
    h.tick(h.local.rebroadcast_interval);
    assert!(h.core.mine.prepare.is_some());
    assert_identical_attempts(&signer);
}

#[test]
fn det_signing_refusal_commit_preserves_lock_without_pooling() {
    let mut h = H::new(4, pick::set_a(0));
    let block = h.block(0, b"reserved commit");
    let qc = h.qc_q(VoteKind::Prepare, 0, &block);
    let signer = refuse(&mut h);
    let out = h.deliver(h.others(1, &[])[0], WireMessage::Qc(qc.clone()));
    assert_refused(&out, SigningKind::Commit);
    assert!(votes_of(&out, VoteKind::Commit).is_empty());
    assert!(h.core.mine.commit.is_none());
    assert!(h.core.votes.get(VoteKind::Commit, 0, h.me).is_none());
    assert!(h.core.retx[1].is_none());
    assert_eq!(h.core.safety.as_ref().unwrap().lock.as_ref(), Some(&qc));
    allow_identical_retry(&signer);
    h.tick(h.local.rebroadcast_interval);
    assert!(h.core.mine.commit.is_some());
    assert_identical_attempts(&signer);
}

#[test]
fn det_signing_refusal_timeout_preserves_original_high_qc_on_retry() {
    let mut h = H::new(4, pick::set_a(0));
    let signer = refuse(&mut h);
    h.core.out.clear();
    h.core.sign_timeout(0);
    assert_refused(&h.core.out, SigningKind::Timeout);
    assert!(timeouts(&h.core.out).is_empty());
    assert!(h.core.mine.timeout.is_none());
    assert!(h.core.timeouts.iter().all(Option::is_none));
    assert!(h.core.safety.as_ref().unwrap().timeout.is_some());
    let block = h.block(0, b"new lock after refused timeout");
    h.core.high_pqc = Some(h.qc_q(VoteKind::Prepare, 0, &block));
    allow_identical_retry(&signer);
    h.tick(h.local.rebroadcast_interval);
    assert!(h.core.mine.timeout.as_ref().unwrap().high_pqc.is_none());
    assert_identical_attempts(&signer);
}

#[test]
fn det_signing_refusal_current_timeout_retries_with_prior_timeout_retained() {
    let mut h = H::new(4, pick::set_a(0));
    h.core.sign_timeout(0);
    let actions = std::mem::take(&mut h.core.out);
    h.absorb(actions);
    let old = h.core.mine.timeout.clone().unwrap();
    h.enter_view(1);
    assert_eq!(h.core.mine.timeout.as_ref(), Some(&old));
    let signer = refuse(&mut h);
    h.core.sign_timeout(1);
    assert!(h.core.out.iter().any(|action| matches!(
        action,
        Action::LocalFault(LocalFault::SigningFailed {
            kind: SigningKind::Timeout,
            height: 1,
            view: 1,
            error: SigningError::Refused
        })
    )));
    assert_eq!(h.core.mine.timeout.as_ref(), Some(&old));
    assert_eq!(
        h.core
            .safety
            .as_ref()
            .unwrap()
            .timeout
            .as_ref()
            .unwrap()
            .view,
        1
    );
    let out = h.tick(h.local.rebroadcast_interval);
    assert!(
        timeouts(&out).is_empty(),
        "a refused current timeout must not retransmit the prior view's timeout"
    );
    allow_identical_retry(&signer);
    let out = h.tick(h.local.rebroadcast_interval);
    let timeout = h.core.mine.timeout.as_ref().unwrap();
    assert_eq!(timeout.view, 1);
    assert!(timeouts(&out).iter().any(|sent| sent == timeout));
    assert_identical_attempts(&signer);
}

#[test]
fn det_signing_retry_retains_restored_proposal_until_delayed_body_arrives() {
    let mut h = H::new(4, pick::leader(0));
    h.run_until(1_000);
    let out = h.built(b"durable body delivered after cadence retry");
    let original = proposals(&out).into_iter().next().unwrap();
    let bh = original.block_hash(&h.v.crypto);
    let block = h.bodies.get(&bh).unwrap().clone();
    h.auto_fetch = false;
    let out = h.restart();
    assert!(proposals(&out).is_empty());
    assert_eq!(h.core.resend_recorded, Some(bh));
    assert!(!h.core.blocks.contains_key(&bh));
    let out = h.tick(h.local.rebroadcast_interval);
    assert!(proposals(&out).is_empty());
    assert_eq!(
        h.core.resend_recorded,
        Some(bh),
        "missing-body retry retains the durable proposal obligation"
    );
    let out = h.fire(Event::BodyAvailable { block });
    assert_eq!(proposals(&out), vec![original]);
    assert!(h.core.resend_recorded.is_none());
}

#[test]
fn det_signing_refusal_echo_does_not_consume_rate_limit() {
    let mut h = H::new(4, pick::set_a(0));
    let signer = refuse(&mut h);
    let peer = h.others(1, &[])[0];
    let key = h.key_at(peer);
    let mut status = h.core.status_message();
    status.probe = Some(73);
    let out = h.deliver(peer, WireMessage::Status(Box::new(status.clone())));
    assert_refused(&out, SigningKind::Echo);
    assert!(
        sent(&out)
            .iter()
            .all(|(_, msg)| !matches!(msg, WireMessage::Status(status) if status.echo.is_some()))
    );
    assert!(h.core.peers.get(&key).unwrap().echoed_at.is_none());
    allow_identical_retry(&signer);
    let out = h.deliver(peer, WireMessage::Status(Box::new(status.clone())));
    assert!(
        sent(&out)
            .iter()
            .any(|(_, msg)| matches!(msg, WireMessage::Status(status) if status.echo.is_some()))
    );
    assert_identical_attempts(&signer);
    let attempts = signer.attempts.lock().unwrap().len();
    let out = h.deliver(peer, WireMessage::Status(Box::new(status)));
    assert!(
        sent(&out)
            .iter()
            .all(|(_, msg)| !matches!(msg, WireMessage::Status(status) if status.echo.is_some()))
    );
    assert_eq!(
        signer.attempts.lock().unwrap().len(),
        attempts,
        "successful Echo retains its independent send rate limit"
    );
}

#[test]
fn det_signing_refusal_worker_event_is_only_local_telemetry() {
    for kind in [SigningKind::PayloadManifest, SigningKind::PayloadRow] {
        let mut h = H::new(4, pick::set_a(0));
        let out = h.fire(Event::SigningFailed {
            kind,
            height: 1,
            view: 0,
            error: SigningError::Refused,
        });
        assert_refused(&out, kind);
        assert!(h.core.high_pqc.is_none());
        assert!(h.core.mine.proposal.is_none());
        assert!(h.core.votes.len() == 0);
    }
}

struct RefusingAggregation(crate::testing::FakeCrypto);
impl Crypto for RefusingAggregation {
    fn hash_chunks(&self, chunks: &[&[u8]]) -> Hash32 {
        self.0.hash_chunks(chunks)
    }
    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
        self.0.verify(pk, msg, sig)
    }
    fn aggregate(&self, _: &[Signature]) -> Result<AggregateSignature, AggregationError> {
        Err(AggregationError::Refused)
    }
    fn verify_aggregate(&self, pks: &[&PublicKey], msg: &[u8], agg: &AggregateSignature) -> bool {
        self.0.verify_aggregate(pks, msg, agg)
    }
    fn verify_aggregate_multi(
        &self,
        groups: &[(Vec<&PublicKey>, Vec<u8>)],
        agg: &AggregateSignature,
    ) -> bool {
        self.0.verify_aggregate_multi(groups, agg)
    }
}

#[test]
fn det_aggregation_refusal_retains_verified_votes_without_certificates() {
    for kind in [VoteKind::Prepare, VoteKind::Commit] {
        let mut h = H::new(4, pick::proxy_tail(0));
        let block = h.block(0, b"aggregation refusal");
        let inputs: Vec<_> = h
            .others(h.q(), &[])
            .into_iter()
            .map(|i| h.vote(kind, i, 0, &block))
            .collect();
        let crypto = RefusingAggregation(h.v.crypto.clone());
        assert_eq!(
            crate::crypto::form_qc(&crypto, 4, &inputs.iter().collect::<Vec<_>>()),
            Err(FormError::AggregationFailed(AggregationError::Refused))
        );
        h.core.crypto = Box::new(crypto);
        let cache_before = h.core.status().footprint.cert_cache;
        let mut actions = Vec::new();
        for vote in &inputs {
            actions.extend(h.deliver(vote.signer, WireMessage::Vote(*vote)));
        }
        assert!(actions.iter().any(|a| matches!(a, Action::LocalFault(LocalFault::AggregationFailed { kind: actual, error: AggregationError::Refused, .. }) if *actual == match kind { VoteKind::Prepare => CertificateKind::Prepare, VoteKind::Commit => CertificateKind::Commit })));
        for vote in &inputs {
            assert_eq!(h.core.votes.get(kind, 0, vote.signer), Some(vote));
        }
        assert!(qcs(&actions).is_empty());
        assert!(h.core.high_pqc.is_none());
        assert_eq!(h.core.status().footprint.cert_cache, cache_before);
        assert_eq!(h.core.tip.height, 0);
        assert!(actions.iter().all(|a| !matches!(
            a,
            Action::CommitBlock { .. } | Action::ReportEvidence(_) | Action::Halt(_)
        )));
        // A fourth valid vote may arrive while the backend is still unavailable. Retain it,
        // then retry an exact quorum without another network event after recovery.
        let fourth = h.vote(kind, h.me, 0, &block);
        h.deliver(fourth.signer, WireMessage::Vote(fourth));
        for vote in inputs.iter().chain(std::iter::once(&fourth)) {
            assert_eq!(h.core.votes.get(kind, 0, vote.signer), Some(vote));
        }
        h.core.crypto = Box::new(h.v.crypto.clone());
        let out = h.tick(h.local.rebroadcast_interval);
        let certificates = qcs(&out);
        let formed = certificates
            .iter()
            .find(|qc| qc.kind == kind)
            .expect("retained quorum is retried");
        assert_eq!(formed.signers.ones().count(), h.v.committee.q());
        assert!(
            crate::crypto::Verifier::new(&h.v.crypto, &I, &h.config(1).epoch.id, &h.v.committee)
                .verify_qc(formed)
                .is_ok()
        );
        match kind {
            VoteKind::Prepare => assert_eq!(h.core.high_pqc.as_ref(), Some(formed)),
            VoteKind::Commit => assert_eq!(h.core.tip.height, 1),
        }
    }
    let mut h = H::new(4, pick::set_a(0));
    let inputs: Vec<_> = h
        .others(h.q(), &[])
        .into_iter()
        .map(|i| h.timeout(i, 0, None))
        .collect();
    let crypto = RefusingAggregation(h.v.crypto.clone());
    assert_eq!(
        crate::crypto::form_tc(&crypto, 4, &inputs.iter().collect::<Vec<_>>()),
        Err(FormError::AggregationFailed(AggregationError::Refused))
    );
    h.core.crypto = Box::new(crypto);
    // Keep the local key unavailable so joining cannot add another input to this exact pool.
    let me = h.core.me.unwrap();
    h.core.keys[me.slot].signer = None;
    let mut actions = Vec::new();
    for timeout in &inputs {
        actions.extend(h.deliver(
            timeout.signer,
            WireMessage::Timeout(Box::new(timeout.clone())),
        ));
    }
    assert!(actions.iter().any(|a| matches!(
        a,
        Action::LocalFault(LocalFault::AggregationFailed {
            kind: CertificateKind::Timeout,
            error: AggregationError::Refused,
            ..
        })
    )));
    for timeout in &inputs {
        assert_eq!(
            h.core.timeouts[timeout.signer as usize].as_ref(),
            Some(timeout)
        );
    }
    assert!(h.core.high_tc.is_none());
    assert_eq!(h.core.view, 0);
    assert!(
        actions
            .iter()
            .all(|a| !matches!(a, Action::ReportEvidence(_) | Action::Halt(_)))
    );
    h.core.crypto = Box::new(h.v.crypto.clone());
    h.tick(h.local.rebroadcast_interval);
    let tc = h
        .core
        .high_tc
        .as_ref()
        .expect("retained timeout quorum is retried");
    assert_eq!(tc.entries.len(), h.q());
    assert_eq!(h.core.view, 1);
    assert!(
        crate::crypto::Verifier::new(&h.v.crypto, &I, &h.config(1).epoch.id, &h.v.committee)
            .verify_tc(tc)
            .is_ok()
    );
    for timeout in &inputs {
        assert_eq!(
            h.core.timeouts[timeout.signer as usize].as_ref(),
            Some(timeout)
        );
    }
}
