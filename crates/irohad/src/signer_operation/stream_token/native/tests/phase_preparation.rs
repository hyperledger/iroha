//! Phase-local preparation over real native captures, signed execution and source mutations.

use super::super::preparation::{CapturedPhaseV1, capture_counts};
use super::*;
use iroha_core::query::stream_token_authority::observation::StreamTokenObservationErrorV1;
use iroha_data_model::{
    isi::sorafs::MutateSorafsStreamTokenCustody,
    sorafs::stream_token_custody::{
        SorafsStreamTokenCustodyActionV1, SorafsStreamTokenCustodyRevocationV1,
    },
};

struct OperationCase {
    fixture: Fixture,
    source: NativeStreamTokenSourceV1,
    reviewed: StreamTokenReviewedV1,
    custody: VerifiedSignerCustodyV1,
    reservation: SignerOperationReservationV1,
}

impl OperationCase {
    fn reserved() -> Self {
        let mut fixture = Fixture::new_at(now_ms() - 5_000);
        let source = source_with_timeout(&fixture, queue(), Duration::from_secs(10));
        let reviewed = reviewed(&source);
        let snapshot = source.observe_signing_state(&source.binding).unwrap();
        let custody = verify_signer_custody_use_v1(
            &source.custody_record,
            &source.binding,
            &source.custody_trust,
            &snapshot.custody,
        )
        .unwrap();
        let current = source.capture(reviewed.request.operation_id).unwrap();
        assert!(
            fixture.commit_instruction(
                MutateSorafsStreamTokenAuthority {
                    request: StreamTokenAuthorityRequestV1 {
                        network_id: source.binding.network_id,
                        provider_id: fixture.provider,
                        expected_control_revision: current.control_revision,
                        expected_control_digest: current.anchor.state_digest,
                        action: Action::Reserve(reviewed),
                    },
                }
                .into(),
                2,
                now_ms(),
            )
        );
        let reservation = source
            .capture(reviewed.request.operation_id)
            .unwrap()
            .operation
            .unwrap()
            .operation
            .operation
            .reservation;
        Self {
            fixture,
            source,
            reviewed,
            custody,
            reservation,
        }
    }

    fn check(&self) -> SignerOperationReservationCheckV1<'_> {
        SignerOperationReservationCheckV1 {
            request: SignerOperationReservationRequestV1 {
                intent: &self.reviewed.intent,
                intent_digest: self.reviewed.intent.digest().unwrap(),
                custody: &self.custody,
            },
            reservation: self.reservation,
        }
    }

    fn commit_request(&self) -> SignerOperationCommitRequestV1<'_> {
        SignerOperationCommitRequestV1 {
            check: self.check(),
            commitment: SignerOperationCommitmentV1 {
                audit: SignerOperationAuditHeadV1 {
                    sequence: self.reviewed.intent.previous_audit.sequence + 1,
                    digest: [67; 32],
                },
                response_digest: [68; 32],
            },
            signatures_digest: [69; 32],
            original_custody: SignerOperationCustodyV1::from_verified(&self.custody),
        }
    }

    fn complete(&mut self) {
        let request = self.commit_request();
        let action = Action::Complete(StreamTokenCompleteRequestV1 {
            reviewed: self.reviewed,
            reservation: self.reservation,
            commitment: request.commitment(),
            signatures_digest: request.signatures_digest(),
        });
        let current = self
            .source
            .capture(self.reviewed.request.operation_id)
            .unwrap();
        assert!(
            self.fixture.commit_instruction(
                MutateSorafsStreamTokenAuthority {
                    request: StreamTokenAuthorityRequestV1 {
                        network_id: self.source.binding.network_id,
                        provider_id: self.fixture.provider,
                        expected_control_revision: current.control_revision,
                        expected_control_digest: current.anchor.state_digest,
                        action,
                    },
                }
                .into(),
                2,
                now_ms(),
            )
        );
    }

    fn finalize(&mut self, prepared: PreparedStreamTokenCheckV1) -> VerifiedStreamTokenCheckV1 {
        let signed = self
            .source
            .transactions
            .sign(prepared.instruction(), true, prepared.deadline())
            .unwrap();
        let pending = prepared.bind_signed_transaction(signed.clone()).unwrap();
        assert!(self.fixture.commit_signed(signed, now_ms()));
        let verified = pending
            .verify_finalized(|| {
                self.source
                    .time()
                    .map_err(|_| StreamTokenObservationErrorV1::Clock)
            })
            .unwrap();
        self.source.checked_context(&verified).unwrap();
        verified
    }
}

#[test]
fn reserved_phases_prepare_from_one_real_capture_and_finalize_exact_rows() {
    let mut case = OperationCase::reserved();
    for phase in [
        SignerReservedObservationPhaseV1::BeforeProvider,
        SignerReservedObservationPhaseV1::AfterProvider,
        SignerReservedObservationPhaseV1::BeforeCommit,
    ] {
        let expected = case
            .source
            .capture(case.reviewed.request.operation_id)
            .unwrap();
        let (prepared, captures) =
            capture_counts::measure(|| case.source.prepare_reserved_check(&case.check(), phase));
        let prepared = prepared.unwrap();
        assert_eq!(captures, [expected.floor.height]);
        let request = &prepared.instruction().request;
        assert_eq!(request.expected_control_revision, expected.control_revision);
        assert_eq!(
            request.expected_control_digest,
            expected.anchor.state_digest
        );
        let Action::Check(check) = &request.action else {
            panic!("exact native Check")
        };
        assert_eq!(check.floor, expected.floor);
        assert_eq!(check.reviewed, case.reviewed);
        let row = expected.operation.unwrap().operation;
        let expected_phase = match phase {
            SignerReservedObservationPhaseV1::BeforeProvider => Phase::BeforeProvider(row),
            SignerReservedObservationPhaseV1::AfterProvider => Phase::AfterProvider(row),
            SignerReservedObservationPhaseV1::BeforeCommit => Phase::BeforeCommit(row),
        };
        assert_eq!(check.phase, expected_phase);
        drop(case.finalize(prepared));
    }
}

#[test]
fn completed_phases_prepare_from_one_fresh_capture_and_keep_commitment_checks() {
    let mut case = OperationCase::reserved();
    case.complete();
    for phase in [
        SignerCommittedObservationPhaseV1::AfterCommit,
        SignerCommittedObservationPhaseV1::BeforeRelease,
    ] {
        let expected = case
            .source
            .capture(case.reviewed.request.operation_id)
            .unwrap();
        let (prepared, captures) = capture_counts::measure(|| {
            case.source
                .prepare_committed_check(&case.commit_request(), phase)
        });
        let prepared = prepared.unwrap();
        assert_eq!(captures, [expected.floor.height]);
        let Action::Check(check) = &prepared.instruction().request.action else {
            panic!("exact native Check")
        };
        assert_eq!(check.floor, expected.floor);
        assert_eq!(check.reviewed, case.reviewed);
        let row = expected.operation.unwrap().operation;
        assert_eq!(
            check.phase,
            match phase {
                SignerCommittedObservationPhaseV1::AfterCommit => Phase::AfterCommit(row),
                SignerCommittedObservationPhaseV1::BeforeRelease => Phase::BeforeRelease(row),
            }
        );
        drop(case.finalize(prepared));
    }
    for field in 0..3 {
        let mut request = case.commit_request();
        match field {
            0 => request.commitment.response_digest[0] ^= 1,
            1 => request.signatures_digest[0] ^= 1,
            _ => request.original_custody.record_digest[0] ^= 1,
        }
        assert!(matches!(
            case.source.prepare_committed_check(
                &request,
                SignerCommittedObservationPhaseV1::BeforeRelease
            ),
            Err(SignerOperationErrorV1::CustodyChanged)
        ));
    }
}

#[test]
fn captured_operation_is_consumed_once_and_wrong_local_claims_reject() {
    let case = OperationCase::reserved();
    let mut captured =
        CapturedPhaseV1::capture(&case.source, case.reviewed.request.operation_id).unwrap();
    captured
        .take_operation(case.check().request(), Some(case.reservation))
        .unwrap();
    assert!(matches!(
        captured.take_operation(case.check().request(), Some(case.reservation)),
        Err(SignerOperationErrorV1::StateUnavailable)
    ));
    for field in 0..3 {
        let mut changed_intent = case.reviewed.intent;
        let mut check = case.check();
        match field {
            0 => {
                changed_intent.request_digest[0] ^= 1;
                check.request.intent = &changed_intent;
            }
            1 => check.request.intent_digest[0] ^= 1,
            _ => check.reservation.reservation_id[0] ^= 1,
        }
        assert!(matches!(
            case.source
                .prepare_reserved_check(&check, SignerReservedObservationPhaseV1::BeforeProvider),
            Err(SignerOperationErrorV1::CustodyChanged)
        ));
    }
    assert!(matches!(
        case.source.prepare_committed_check(
            &case.commit_request(),
            SignerCommittedObservationPhaseV1::AfterCommit
        ),
        Err(SignerOperationErrorV1::StateUnavailable)
    ));
}

#[test]
fn current_phase_still_captures_and_wrong_configured_operator_rejects() {
    let fixture = Fixture::new_at(now_ms() - 5_000);
    let mut source = source_with_timeout(&fixture, queue(), Duration::from_secs(10));
    let reviewed = reviewed(&source);
    let (prepared, captures) = capture_counts::measure(|| {
        source.prepare_check(&reviewed, Phase::Current(reviewed.intent.previous_audit))
    });
    let prepared = prepared.unwrap();
    assert_eq!(captures, [fixture.state.view().height() as u64]);
    let Action::Check(check) = &prepared.instruction().request.action else {
        panic!("exact native Check")
    };
    assert_eq!(check.phase, Phase::Current(reviewed.intent.previous_audit));
    source.transactions = NativeTransactionsV1::new(
        fixture.state.clone(),
        queue(),
        AccountId::new(Fixture::key(1).public_key().clone()),
        Fixture::key(1),
        Fixture::key(3),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        Duration::from_secs(10),
    )
    .unwrap();
    assert!(matches!(
        source.prepare_check(&reviewed, Phase::Current(reviewed.intent.previous_audit)),
        Err(SignerOperationErrorV1::CustodyChanged)
    ));
}

#[test]
fn intervening_permission_revocation_invalidates_the_prepared_phase() {
    for observer in [false, true] {
        let mut case = OperationCase::reserved();
        let prepared = case
            .source
            .prepare_reserved_check(
                &case.check(),
                SignerReservedObservationPhaseV1::BeforeProvider,
            )
            .unwrap();
        let signed = case
            .source
            .transactions
            .sign(prepared.instruction(), true, prepared.deadline())
            .unwrap();
        let pending = prepared.bind_signed_transaction(signed.clone()).unwrap();
        assert!(case.fixture.revoke_runtime_permission(observer, now_ms()));
        assert!(!case.fixture.commit_signed(signed, now_ms()));
        assert!(
            pending
                .verify_finalized(|| case
                    .source
                    .time()
                    .map_err(|_| StreamTokenObservationErrorV1::Clock))
                .is_err()
        );
        let height = case.fixture.state.view().height() as u64;
        let (next, captures) = capture_counts::measure(|| {
            case.source.prepare_reserved_check(
                &case.check(),
                SignerReservedObservationPhaseV1::AfterProvider,
            )
        });
        assert_eq!(captures, [height]);
        let next = next.unwrap();
        let signed = case
            .source
            .transactions
            .sign(next.instruction(), true, next.deadline())
            .unwrap();
        assert!(!case.fixture.commit_signed(signed, now_ms()));
    }
}

#[test]
fn intervening_complete_invalidates_reserved_phase_and_next_phase_captures_completion() {
    let mut case = OperationCase::reserved();
    let prepared = case
        .source
        .prepare_reserved_check(
            &case.check(),
            SignerReservedObservationPhaseV1::BeforeProvider,
        )
        .unwrap();
    let signed = case
        .source
        .transactions
        .sign(prepared.instruction(), true, prepared.deadline())
        .unwrap();
    let pending = prepared.bind_signed_transaction(signed.clone()).unwrap();
    case.complete();
    assert!(!case.fixture.commit_signed(signed, now_ms()));
    assert!(
        pending
            .verify_finalized(|| case
                .source
                .time()
                .map_err(|_| StreamTokenObservationErrorV1::Clock))
            .is_err()
    );
    let height = case.fixture.state.view().height() as u64;
    let (next, captures) = capture_counts::measure(|| {
        case.source.prepare_committed_check(
            &case.commit_request(),
            SignerCommittedObservationPhaseV1::AfterCommit,
        )
    });
    assert_eq!(captures, [height]);
    drop(case.finalize(next.unwrap()));
}

#[test]
fn intervening_custody_revocation_is_not_hidden_by_preparation_reuse() {
    let mut case = OperationCase::reserved();
    let current = case
        .source
        .capture(case.reviewed.request.operation_id)
        .unwrap();
    let prepared = case
        .source
        .prepare_reserved_check(
            &case.check(),
            SignerReservedObservationPhaseV1::BeforeProvider,
        )
        .unwrap();
    let signed = case
        .source
        .transactions
        .sign(prepared.instruction(), true, prepared.deadline())
        .unwrap();
    let pending = prepared.bind_signed_transaction(signed.clone()).unwrap();
    assert!(
        case.fixture.commit_instruction(
            MutateSorafsStreamTokenCustody {
                provider_id: case.fixture.provider,
                expected_revision: current.control_revision,
                expected_digest: current.anchor.state_digest,
                action: SorafsStreamTokenCustodyActionV1::Revoke(
                    SorafsStreamTokenCustodyRevocationV1 {
                        signer: true,
                        attester: false
                    }
                ),
            }
            .into(),
            1,
            now_ms(),
        )
    );
    assert!(!case.fixture.commit_signed(signed, now_ms()));
    assert!(
        pending
            .verify_finalized(|| case
                .source
                .time()
                .map_err(|_| StreamTokenObservationErrorV1::Clock))
            .is_err()
    );
    let height = case.fixture.state.view().height() as u64;
    let (next, captures) = capture_counts::measure(|| {
        case.source.prepare_reserved_check(
            &case.check(),
            SignerReservedObservationPhaseV1::AfterProvider,
        )
    });
    assert_eq!(captures, [height]);
    assert!(matches!(
        next,
        Err(SignerOperationErrorV1::StateUnavailable)
    ));
}

#[test]
fn later_phase_cannot_reuse_a_capture_after_its_durable_finality_disappears() {
    let case = OperationCase::reserved();
    let (first, captures) = capture_counts::measure(|| {
        case.source.prepare_reserved_check(
            &case.check(),
            SignerReservedObservationPhaseV1::BeforeProvider,
        )
    });
    drop(first.unwrap());
    assert_eq!(captures.len(), 1);
    case.fixture.remove_finality_for_test(captures[0]).unwrap();
    let (later, captures) = capture_counts::measure(|| {
        case.source.prepare_reserved_check(
            &case.check(),
            SignerReservedObservationPhaseV1::AfterProvider,
        )
    });
    assert!(captures.is_empty());
    assert!(matches!(
        later,
        Err(SignerOperationErrorV1::StateUnavailable)
    ));
}
