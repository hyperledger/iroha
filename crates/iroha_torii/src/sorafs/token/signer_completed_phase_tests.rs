//! Real codec refusal and signed-operation continuation; finality here remains simulated.

use super::*;
use crate::sorafs::token::signer_test_support::{
    NOW_MS, ObserverFault, PROVIDER, SignedFixture, TestSignerMode,
};
use norito::core::{DecodeAttemptErrorKind, DecodeResourceError};
use sorafs_manifest::signer::stream_token_evidence::SignerStreamTokenObservationRequestV1;
use std::{cell::RefCell, sync::atomic::Ordering};

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    request: SignerStreamTokenObservationRequestV1,
    reply_backing: usize,
    receipt_backing: usize,
    token_signature: usize,
    original_prepared: usize,
    native_pending: usize,
    deadline: Instant,
}
impl Snapshot {
    fn capture(owner: &Received<'_>) -> Self {
        let native_pending = match owner.native.as_ref().expect("retained native owner") {
            PendingCompletedFinalityV1::Native(pending) => {
                std::ptr::from_ref(pending.as_ref()) as usize
            }
            PendingCompletedFinalityV1::Simulated { .. } => 0,
        };
        Self {
            request: owner.expected.request().clone(),
            reply_backing: owner.reply.completed_observation().unwrap().as_ptr() as usize,
            receipt_backing: owner.inputs.receipt.bytes().as_ptr() as usize,
            token_signature: owner.inputs.token.token().signature.as_ptr() as usize,
            original_prepared: std::ptr::from_ref(owner.inputs.prepared) as usize,
            native_pending,
            deadline: owner.deadline,
        }
    }
}

struct Probe {
    phase: Phase,
    first: Option<Snapshot>,
    decodes: usize,
    refusals: usize,
}
thread_local! {
    static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) };
}
struct Guard(Option<Probe>);
impl Guard {
    fn install(phase: Phase) -> Self {
        Self(PROBE.with(|slot| {
            slot.replace(Some(Probe {
                phase,
                first: None,
                decodes: 0,
                refusals: 0,
            }))
        }))
    }
    #[expect(
        clippy::unused_self,
        reason = "the borrowed guard keeps the thread-local refusal probe installed throughout assertions"
    )]
    fn assert_retry(&self) {
        PROBE.with(|slot| {
            let probe = slot.borrow();
            let probe = probe.as_ref().unwrap();
            assert_eq!(probe.refusals, 1, "one actual original refusal");
            assert_eq!(probe.decodes, 2, "only the same returned frame retries");
        });
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        PROBE.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}

pub(super) fn decode(
    owner: &Received<'_>,
    bytes: &[u8],
) -> Result<SignerStreamTokenStateObservationV1, Admission> {
    let refuse = PROBE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(probe) = slot.as_mut() else {
            return false;
        };
        if owner.expected.request().phase != probe.phase {
            return false;
        }
        probe.decodes += 1;
        let snapshot = Snapshot::capture(owner);
        if let Some(first) = &probe.first {
            assert_eq!(
                &snapshot, first,
                "same reply/receipt/token/native owner and deadline"
            );
            false
        } else {
            probe.first = Some(snapshot);
            true
        }
    });
    if refuse {
        // Only the actual enclosing decoder allowance changes. No error/result is fabricated,
        // protocol ceiling widened, native proof supplied, or original deadline modified.
        norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || SignerStreamTokenStateObservationV1::decode_canonical(bytes),
        )
    } else {
        SignerStreamTokenStateObservationV1::decode_canonical(bytes)
    }
}

pub(super) fn inspect_refusal(failure: &Refused<'_>) {
    PROBE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(probe) = slot.as_mut() else { return };
        if !matches!(&failure.cause, Cause::Admission(error) if error.is_retryable()) {
            return;
        }
        let Cause::Admission(Admission::Codec(error)) = &failure.cause else {
            panic!("original codec refusal is preserved");
        };
        assert_eq!(error.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        let original = std::error::Error::source(error)
            .and_then(|source| source.downcast_ref::<norito::Error>())
            .expect("original Norito error survives its scope");
        assert!(matches!(original.decode_resource_error(),
            Some(DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 })
                if attempted > 0));
        assert_eq!(
            Some(&Snapshot::capture(&failure.phase)),
            probe.first.as_ref()
        );
        probe.refusals += 1;
    });
}

fn body(version: u64) -> StreamTokenBodyV1 {
    StreamTokenBodyV1 {
        token_id: "0123456789abcdef0123456789abcdef".into(),
        manifest_cid: vec![0x01, 0x55, 0x01],
        provider_id: PROVIDER,
        profile_handle: "sorafs.sf1@1.0.0".into(),
        max_streams: 4,
        ttl_epoch: NOW_MS / 1_000 + 60,
        rate_limit_bytes: 10 * 1024 * 1024,
        issued_at: NOW_MS / 1_000,
        requests_per_minute: 120,
        token_pk_version: u32::try_from(version).unwrap(),
    }
}

#[test]
fn completed_codec_refusal_retries_exact_reply_without_another_sign_or_observation() {
    for phase in [Phase::AfterCommit, Phase::BeforeRelease] {
        let signer = SignedFixture::new(1, TestSignerMode::Sign);
        let issuer = signer.issuer().expect("signed startup");
        let guard = Guard::install(phase);
        let token = issuer
            .signer
            .sign(body(issuer.signer.pins().binding().key_revision))
            .expect("the original returned observation retries after its enclosing scope retires");
        token.verify(issuer.verifying_key()).unwrap();
        guard.assert_retry();
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(signer.recover_calls.load(Ordering::SeqCst), 0);
        assert_eq!(signer.observer_calls.load(Ordering::SeqCst), 4);
        let requests = signer.requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.phase == Phase::AfterCommit)
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.phase == Phase::BeforeRelease)
                .count(),
            1
        );
    }
}

#[test]
fn semantic_rejection_after_codec_retry_never_observes_or_signs_again() {
    let signer = SignedFixture::new(1, TestSignerMode::Sign);
    signer
        .faults
        .lock()
        .unwrap()
        .insert(3, ObserverFault::WrongRequest);
    let issuer = signer.issuer().expect("signed startup");
    let guard = Guard::install(Phase::AfterCommit);
    let result = issuer
        .signer
        .sign(body(issuer.signer.pins().binding().key_revision));
    assert!(matches!(
        result,
        Err(StreamTokenIssuerError::SignerEvidenceInvalid)
    ));
    guard.assert_retry();
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(signer.recover_calls.load(Ordering::SeqCst), 0);
    assert_eq!(signer.observer_calls.load(Ordering::SeqCst), 3);
}
