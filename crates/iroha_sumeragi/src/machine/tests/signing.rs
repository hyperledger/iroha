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
        request: &crate::prepare_admission::PrepareSigningRequest,
        admission: &crate::prepare_admission::ExecutionAdmission,
    ) -> Result<Signature, SigningError> {
        let preimage = crate::preimage::vote_preimage(
            VoteKind::Prepare,
            &request.instance(),
            &request.epoch(),
            request.height(),
            request.view(),
            &request.block_hash(),
            &request.result(),
        );
        self.prepares.lock().unwrap().push(ObservedPrepare {
            preimage: preimage.clone(),
            instance: request.instance(),
            epoch: request.epoch(),
            height: request.height(),
            block_hash: request.block_hash(),
            result: request.result(),
            certified: request.certified(),
        });
        #[cfg(sumeragi_mutation = "MS71")]
        let _ = admission;
        #[cfg(not(sumeragi_mutation = "MS71"))]
        admission.check(request)?;
        self.sign(&preimage)
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
        matches!(h.core.exec.get(&original.block_hash), Some(super::super::ExecState::Valid { admission }) if admission.result() == original.result)
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
    assert_eq!(
        observed.len(),
        1,
        "substituted source must not reach the signer"
    );
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
    assert!(
        !original.certified,
        "a restarted durable Prepare reservation must not grant certified clock exemption"
    );
    let durable = h.durable().unwrap();
    assert!(durable.prepare.is_some());
    assert!(durable.prepare_signature.is_none());
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
    assert!(signer.prepares.lock().unwrap().is_empty());
    assert!(core.mine.prepare.is_none());
    assert!(votes(&actions).is_empty());
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
    h.core.exec.insert(
        bh,
        super::super::ExecState::Valid {
            admission: crate::testing::no_sensitive_work_admission(Hash32([0xf3; 32])),
        },
    );
    allow_identical_retry(&signer);
    h.core.try_prepare();
    assert_eq!(signer.attempts.lock().unwrap().len(), 1);
    h.core.exec.insert(
        bh,
        super::super::ExecState::Valid {
            admission: crate::testing::no_sensitive_work_admission(reserved.result),
        },
    );
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

#[test]
fn det_ct5_unsigned_prepare_reservation_restart_never_synthesizes_first_signature() {
    let mut h = H::new(4, pick::set_a(0));
    let block = h.block(0, b"first Prepare requires fresh admission after restart");
    let proposal = h.proposal(0, &block, None);
    h.deliver(h.leader(0), WireMessage::Proposal(Box::new(proposal)));
    let signer = refuse(&mut h);
    let out = h.exec_all();
    assert_refused(&out, SigningKind::Prepare);
    assert_eq!(signer.attempts.lock().unwrap().len(), 1);
    let reserved = h.core.safety.as_ref().unwrap().prepare.unwrap();
    assert!(h.core.mine.prepare.is_none());
    assert!(
        h.core.high_pqc.is_none(),
        "a local reservation is not a certificate"
    );
    // Model a stopped process: no ticks or new execution authorize a first signature.
    // Restart's working key must not turn the durable *refused* reservation into a vote.
    h.now += 600_000;
    h.auto_fetch = false;
    h.auto_exec = false;
    let out = h.restart();
    assert!(
        h.core.mine.prepare.is_none() && votes_of(&out, VoteKind::Prepare).is_empty(),
        "a durable unsigned reservation cannot synthesize a first Prepare without fresh source-bound execution or a genuine matching PQC"
    );
    assert_eq!(h.core.safety.as_ref().unwrap().prepare.unwrap(), reserved);
    assert!(h.core.high_pqc.is_none());
}

#[derive(Debug)]
struct DueAdmission {
    request: crate::prepare_admission::PrepareSigningRequest,
    wall: Arc<std::sync::atomic::AtomicU64>,
}
impl crate::prepare_admission::PrepareAdmission for DueAdmission {
    fn result(&self) -> Hash32 {
        self.request.result()
    }
    fn check(
        &self,
        request: &crate::prepare_admission::PrepareSigningRequest,
    ) -> Result<(), SigningError> {
        if request.instance() != self.request.instance()
            || request.epoch() != self.request.epoch()
            || request.height() != self.request.height()
            || request.block_hash() != self.request.block_hash()
            || request.result() != self.request.result()
        {
            return Err(SigningError::InvalidInput);
        }
        if !request.certified() && self.wall.load(Ordering::Relaxed) > 100 {
            return Err(SigningError::StaleExecution {
                block_time_ms: 50,
                observed_ms: self.wall.load(Ordering::Relaxed),
                max_lag_ms: 50,
            });
        }
        Ok(())
    }
}
fn due_outcome(
    h: &H,
    block: &AvailableBody,
    wall: Arc<std::sync::atomic::AtomicU64>,
) -> ExecOutcome {
    let result = result_of(block);
    let source = DueAdmission {
        request: crate::testing::prepare_signing_request(
            I,
            h.config(h.height()).epoch.id,
            h.height(),
            0,
            h.bh(block),
            result,
            false,
        ),
        wall,
    };
    let owner = iroha_allocation::shared::Shared::new(source, ());
    ExecOutcome::Valid {
        result,
        admission: crate::prepare_admission::ExecutionAdmission::from_owner(
            owner.project::<dyn crate::prepare_admission::PrepareAdmission>(|value| value),
        ),
    }
}

#[test]
fn det_ct5_cached_execution_waits_for_stage_and_checks_actual_first_signing_time() {
    let mut h = H::new(4, pick::set_b(0));
    let block = h.block(0, b"retained set B admission");
    let hash = h.bh(&block);
    let proposal = h.proposal(0, &block, None);
    h.deliver(h.leader(0), WireMessage::Proposal(Box::new(proposal)));
    let wall = Arc::new(std::sync::atomic::AtomicU64::new(100));
    h.exec(hash, due_outcome(&h, &block, wall.clone()));
    assert!(h.core.mine.prepare.is_none());
    wall.store(101, Ordering::Relaxed);
    h.core.raise_stage(1);
    assert!(
        h.core.mine.prepare.is_none(),
        "cached Valid cannot bypass first-Prepare freshness after stage delay"
    );
    assert!(matches!(
        h.core.exec.get(&hash),
        Some(super::super::ExecState::Valid { .. })
    ));
    assert!(h.core.out.iter().any(|a| matches!(
        a,
        Action::LocalFault(LocalFault::SigningFailed {
            error: SigningError::StaleExecution { .. },
            ..
        })
    )));
    wall.store(100, Ordering::Relaxed);
    h.core.try_prepare();
    assert!(
        h.core.mine.prepare.is_some(),
        "exact inclusive freshness boundary retries the original execution"
    );
}

#[test]
fn det_ct5_signer_resource_retry_rechecks_freshness_and_genuine_pqc_exempts() {
    let mut h = H::new(4, pick::set_a(0));
    let block = h.block(0, b"signer wait source bound");
    let hash = h.bh(&block);
    let proposal = h.proposal(0, &block, None);
    h.deliver(h.leader(0), WireMessage::Proposal(Box::new(proposal)));
    let signer = refuse(&mut h);
    let wall = Arc::new(std::sync::atomic::AtomicU64::new(100));
    h.exec(hash, due_outcome(&h, &block, wall.clone()));
    assert_eq!(signer.attempts.lock().unwrap().len(), 1);
    allow_identical_retry(&signer);
    wall.store(101, Ordering::Relaxed);
    h.tick(h.local.rebroadcast_interval);
    assert!(
        h.core.mine.prepare.is_none(),
        "resource recovery cannot sign an aged execution"
    );
    assert_eq!(
        signer.attempts.lock().unwrap().len(),
        1,
        "stale admission never calls signing backend"
    );
    let qc = h.qc_q(VoteKind::Prepare, 0, &block);
    h.deliver(h.others(1, &[])[0], WireMessage::Qc(qc));
    h.core.try_prepare();
    assert!(
        h.core.mine.prepare.is_some(),
        "a genuinely verified matching PQC preserves late completion"
    );
}

#[test]
fn det_ct5_successful_prepare_signature_is_exact_durable_and_authenticated_on_restart() {
    let mut h = H::new(4, pick::set_a(0));
    let block = h.block(0, b"persist actual successful signature");
    let proposal = h.proposal(0, &block, None);
    h.deliver(h.leader(0), WireMessage::Proposal(Box::new(proposal)));
    let out = h.exec_all();
    let original = h.core.mine.prepare.unwrap();
    let durable = h.durable().unwrap();
    assert_eq!(durable.prepare_signature, Some(original.sig));
    assert!(out.iter().any(|action| matches!(action, Action::PersistSafety(record) if record.prepare_signature == Some(original.sig))));
    h.auto_fetch = false;
    h.auto_exec = false;
    h.now += 600_000;
    h.restart();
    assert_eq!(
        h.core.mine.prepare.unwrap(),
        original,
        "restart reuses the exact successful signature without fresh execution"
    );
    let mut forged = durable;
    forged.prepare_signature = Some(Signature([0; crate::types::SIGNATURE_LEN]));
    h.records
        .insert(forged.key.clone(), forged.encode(&h.v.crypto).unwrap());
    let out = h.restart();
    assert!(
        !halts(&out).is_empty(),
        "a checksummed fabricated successful signature is not restart authority"
    );
    assert!(h.core.mine.prepare.is_none());
}

#[derive(Debug)]
struct ClockedProposalAdmission {
    context: crate::api::ControlWitnessContext,
    payload: PayloadBytes,
    wall: Arc<std::sync::atomic::AtomicU64>,
}

impl crate::proposal_admission::ProposalAdmissionOwner for ClockedProposalAdmission {
    fn check(
        &self,
        request: &crate::proposal_admission::ProposalSigningRequest,
    ) -> Result<(), SigningError> {
        if request.instance() != I
            || request.epoch() != self.context.epoch
            || request.height() != self.context.height
            || request.view() != self.context.view
            || request.parent_hash() != self.context.parent_hash
            || request.parent_result() != self.context.parent_result
            || request.payload().as_slice() != self.payload.as_slice()
        {
            return Err(SigningError::InvalidInput);
        }
        let observed_ms = self.wall.load(Ordering::Relaxed);
        if observed_ms < 1_000 {
            return Err(SigningError::ClockAhead {
                block_time_ms: 1_000,
                observed_ms,
                max_clock_drift_ms: 0,
            });
        }
        Ok(())
    }
}

fn clocked_proposal(
    h: &H,
    bytes: &[u8],
    wall: &Arc<std::sync::atomic::AtomicU64>,
) -> crate::proposal_admission::BuiltPayload {
    let req = h.last_build.unwrap();
    let mut built = h.payload(bytes).unwrap();
    let owner = iroha_allocation::shared::Shared::new(
        ClockedProposalAdmission {
            context: h.core.fresh_proposal_context(req).unwrap(),
            payload: built.payload.clone(),
            wall: wall.clone(),
        },
        (),
    );
    built.admission = crate::proposal_admission::ProposalAdmission::from_owner(
        owner.project::<dyn crate::proposal_admission::ProposalAdmissionOwner>(|value| value),
    );
    built
}

#[test]
fn det_ct3_proposal_signing_rechecks_original_clock_after_backend_refusal() {
    let mut h = H::new(4, pick::leader(0));
    h.run_until(1_000);
    let signer = refuse(&mut h);
    let wall = Arc::new(std::sync::atomic::AtomicU64::new(1_000));
    let built = clocked_proposal(&h, b"original timestamp and custody", &wall);
    let out = h.fire(Event::PayloadBuilt {
        req: h.last_build.unwrap(),
        payload: Some(built),
    });
    assert_refused(&out, SigningKind::Proposal);
    let original = h.core.safety.as_ref().unwrap().proposal.clone().unwrap();
    assert!(h.core.safety.as_ref().unwrap().proposal_signature.is_none());
    wall.store(999, Ordering::Relaxed);
    allow_identical_retry(&signer);
    let out = h.tick(h.local.rebroadcast_interval);
    assert!(
        proposals(&out).is_empty() && h.core.mine.proposal.is_none(),
        "a delayed first proposal signature must recheck the original timestamp against the current wall clock"
    );
    assert!(out.iter().any(|action| matches!(
        action,
        Action::LocalFault(LocalFault::SigningFailed {
            kind: SigningKind::Proposal,
            error: SigningError::ClockAhead {
                block_time_ms: 1_000,
                observed_ms: 999,
                max_clock_drift_ms: 0
            },
            ..
        })
    )));
    assert_eq!(
        h.core.safety.as_ref().unwrap().proposal.as_ref(),
        Some(&original)
    );
    assert_eq!(signer.attempts.lock().unwrap().len(), 1);
    wall.store(1_000, Ordering::Relaxed);
    let out = h.tick(h.local.rebroadcast_interval);
    assert_eq!(
        proposals(&out)[0].block_hash(&h.v.crypto),
        original.block_hash
    );
    assert_identical_attempts(&signer);
}

#[test]
fn det_ct3_successful_proposal_signature_is_durable_before_publication() {
    let mut h = H::new(4, pick::leader(0));
    h.run_until(1_000);
    let out = h.built(b"successful original proposal signature");
    let proposal = proposals(&out)[0].clone();
    let durable = out.iter().position(|action| {
        matches!(action,
            Action::PersistSafety(record) if record.proposal_signature == Some(proposal.sig)
        )
    });
    let published = out
        .iter()
        .position(|action| !proposals(std::slice::from_ref(action)).is_empty())
        .unwrap();
    assert!(
        durable.is_some_and(|index| index < published),
        "a successful proposal signature must be durable before any proposal publication"
    );
    assert_eq!(h.durable().unwrap().proposal_signature, Some(proposal.sig));
    let restored = h.restart();
    assert_eq!(proposals(&restored), vec![proposal]);
    assert!(
        !restored
            .iter()
            .any(|action| matches!(action, Action::RecoverProposalAdmission { .. }))
    );
}

#[test]
fn det_ct3_restore_authenticates_stored_successful_proposal_signature() {
    let mut h = H::new(4, pick::leader(0));
    h.run_until(1_000);
    h.built(b"stored proposal signature must authenticate");
    let mut record = h.durable().unwrap();
    record.proposal_signature = Some(Signature([0; 96]));
    h.records
        .insert(record.key.clone(), record.encode(&h.v.crypto).unwrap());
    let out = h.restart();
    assert!(
        !halts(&out).is_empty() && proposals(&out).is_empty(),
        "a checksummed record with a forged successful proposal signature must fail closed"
    );
}

#[test]
fn det_ct3_unsigned_proposal_restart_recovers_original_admission_before_signing() {
    let mut h = H::new(4, pick::leader(0));
    h.run_until(1_000);
    let signer = refuse(&mut h);
    let wall = Arc::new(std::sync::atomic::AtomicU64::new(1_000));
    let built = clocked_proposal(&h, b"same paid original after unsigned restart", &wall);
    let admission = built.admission.clone();
    let out = h.fire(Event::PayloadBuilt {
        req: h.last_build.unwrap(),
        payload: Some(built),
    });
    assert_refused(&out, SigningKind::Proposal);
    let original = h.durable().unwrap().proposal.unwrap();
    let block = h.bodies.get(&original.block_hash).unwrap().clone();
    assert!(h.core.safety.as_ref().unwrap().proposal_signature.is_none());
    h.auto_fetch = false;
    let out = h.restart();
    assert!(proposals(&out).is_empty());
    let out = h.fire(Event::BodyAvailable { block });
    assert!(
        proposals(&out).is_empty() && h.core.mine.proposal.is_none(),
        "an unsigned proposal reservation must reacquire original admission before its first signature"
    );
    let req = out
        .iter()
        .find_map(|action| match action {
            Action::RecoverProposalAdmission { req, body } => {
                assert_eq!(body.hash(&h.v.crypto), original.block_hash);
                Some(*req)
            }
            _ => None,
        })
        .unwrap();
    // A slow original-body worker retains its request across cadence ticks. Request churn
    // would otherwise make every successful completion stale forever.
    for _ in 0..3 {
        let out = h.tick(h.local.rebroadcast_interval);
        assert!(
            !out.iter()
                .any(|action| matches!(action, Action::RecoverProposalAdmission { .. })),
            "a live original-body admission request must survive cadence ticks without replacement"
        );
        assert_eq!(h.core.proposal_recovery.as_ref().unwrap().req, req);
    }
    let out = h.fire(Event::ProposalAdmissionRecovered {
        req: req + 1,
        admission: Some(admission.clone()),
    });
    assert!(proposals(&out).is_empty());
    wall.store(999, Ordering::Relaxed);
    let out = h.fire(Event::ProposalAdmissionRecovered {
        req,
        admission: Some(admission),
    });
    assert!(proposals(&out).is_empty());
    assert!(h.core.safety.as_ref().unwrap().proposal_signature.is_none());
    assert_eq!(
        h.core.safety.as_ref().unwrap().proposal.as_ref(),
        Some(&original)
    );
    wall.store(1_000, Ordering::Relaxed);
    let out = h.tick(h.local.rebroadcast_interval);
    let published = proposals(&out)[0].clone();
    assert_eq!(published.block_hash(&h.v.crypto), original.block_hash);
    assert_eq!(signer.attempts.lock().unwrap().len(), 1);
    wall.store(999, Ordering::Relaxed);
    h.auto_fetch = true;
    let out = h.restart();
    assert_eq!(proposals(&out), vec![published]);
    assert!(
        !out.iter()
            .any(|action| matches!(action, Action::RecoverProposalAdmission { .. }))
    );
}

#[test]
fn det_ct3_genuine_matching_pqc_reproposes_without_fresh_clock_owner() {
    let mut h = H::new(4, pick::leader(1));
    let block = h.block(0, b"genuine certified bytes survive clock rewind");
    let bh = h.bh(&block);
    let qc = h.qc_q(VoteKind::Prepare, 0, &block);
    h.bodies.insert(bh, block.clone());
    let entries: Vec<_> = h
        .others(h.q(), &[])
        .into_iter()
        .map(|peer| (peer, Some(qc.clone())))
        .collect();
    let tc = h.tc(0, &entries);
    let out = h.deliver(h.others(1, &[])[0], WireMessage::Tc(Box::new(tc)));
    let proposal = proposals(&out).into_iter().next().unwrap();
    assert_eq!(proposal.block_hash(&h.v.crypto), bh);
    assert_eq!(proposal.header, *block.header());
    assert!(!out.iter().any(|action| matches!(
        action,
        Action::BuildPayload { .. } | Action::RecoverProposalAdmission { .. }
    )));
}
