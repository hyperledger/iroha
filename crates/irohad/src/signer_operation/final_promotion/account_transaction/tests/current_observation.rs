//! Current and Reserved Check handoff tests use the real native State/Kura fixture.

use super::*;
use crate::signer_operation::final_promotion::current_observation::{
    FinalPromotionCheckObservationErrorV1 as CurrentError, FinalPromotionCurrentCheckRuntimeV1,
    FinalPromotionNativeSubmissionV1, FinalPromotionNativeSubmitOutcomeV1,
    FinalPromotionObserverCheckPayloadV1, FinalPromotionObserverCheckSignerV1,
    FinalPromotionQualifiedUtcV1, FinalPromotionRetainedFloorV1,
};
use crate::signer_operation::final_promotion::observer_transaction::FinalPromotionObserverKeyRequestV1;
use crate::signer_operation::final_promotion::pending_reserve_journal::FinalPromotionPendingReserveJournalV1;
use crate::signer_operation::final_promotion::reserved_observation::FinalPromotionReservedCheckRuntimeV1;
use iroha_core::{
    query::final_promotion_authority::observation::PendingFinalPromotionCheckV1, state::State,
};
use iroha_data_model::{
    isi::sorafs::MutateSorafsFinalPromotionAuthority,
    sorafs::final_promotion_authority::{FinalPromotionCompleteV1, FinalPromotionRevocationV1},
    transaction::TransactionPayload,
};
use sorafs_manifest::signer::{
    custody::SignerCustodyBindingV1, protocol::SignerOperationAuditHeadV1,
};
use std::{collections::VecDeque, os::unix::fs::MetadataExt as _};

fn pending_reserve_journal() -> (tempfile::TempDir, FinalPromotionPendingReserveJournalV1) {
    let directory = tempfile::tempdir().expect("private operation directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    for leaf in ["receipts", "pending-reserve-v1"] {
        let path = directory.path().join(leaf);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory
        .path()
        .join("pending-reserve-v1")
        .canonicalize()
        .unwrap();
    let journal = FinalPromotionPendingReserveJournalV1::open_test(&path).unwrap();
    (directory, journal)
}

struct QualifiedClock {
    intervals: VecDeque<Result<FinalPromotionEligibilityTimeIntervalV1, CurrentError>>,
    calls: usize,
}
impl QualifiedClock {
    fn fixed() -> Self {
        Self {
            intervals: VecDeque::from([Ok(times().0), Ok(times().0)]),
            calls: 0,
        }
    }
}
impl FinalPromotionQualifiedUtcV1 for QualifiedClock {
    fn sample(&mut self) -> Result<FinalPromotionEligibilityTimeIntervalV1, CurrentError> {
        self.calls += 1;
        self.intervals
            .pop_front()
            .unwrap_or(Err(CurrentError::Clock))
    }
}

struct RetainedFloor {
    current: FinalPromotionCheckFloorV1,
    advances: usize,
    fail_advance: bool,
    mismatched_readback: bool,
}
impl RetainedFloor {
    fn new(f: &Fixture) -> Self {
        let (height, block_hash, context_id) = f.native.finalized_floor();
        Self {
            current: FinalPromotionCheckFloorV1 {
                height,
                block_hash,
                context_id,
            },
            advances: 0,
            fail_advance: false,
            mismatched_readback: false,
        }
    }
}
impl FinalPromotionRetainedFloorV1 for RetainedFloor {
    fn read(&mut self) -> Result<FinalPromotionCheckFloorV1, CurrentError> {
        Ok(self.current)
    }

    fn advance_and_readback(
        &mut self,
        previous: FinalPromotionCheckFloorV1,
        applied: FinalPromotionCheckFloorV1,
    ) -> Result<FinalPromotionCheckFloorV1, CurrentError> {
        self.advances += 1;
        if self.fail_advance || self.current != previous {
            return Err(CurrentError::Floor);
        }
        self.current = applied;
        if self.mismatched_readback {
            Ok(previous)
        } else {
            Ok(self.current)
        }
    }
}

fn pending_current(f: &Fixture) -> PendingFinalPromotionCheckV1 {
    let prepared = f.prepare_receipt_check(None, Duration::from_secs(60));
    let payload = f.observer_payload(prepared.instruction().clone().into());
    f.observer_transactions()
        .sign_receipt_with(prepared, payload, |request| {
            Signature::try_new(key(3).private_key(), request.signing_message())
                .map_err(|_| ObserverError::Provider)
        })
        .unwrap()
}

#[test]
fn current_handoff_uses_one_finalized_snapshot_and_retains_floor_before_returning_state() {
    let mut f = Fixture::new();
    let mut floor = RetainedFloor::new(&f);
    let pending = pending_current(&f);
    assert_eq!(
        f.native
            .commit(NOW, vec![pending.signed_transaction().clone()]),
        [true]
    );
    let view = f.native.state().view();
    let expected = read_final_promotion_authority_at_v1(
        &view,
        &f.receipt_policy.binding,
        view.height() as u64,
        Some(f.expected.operation_id),
    )
    .unwrap()
    .unwrap();
    drop(view);
    let mut clock = QualifiedClock {
        intervals: VecDeque::from([
            Ok(times().0),
            Ok(FinalPromotionEligibilityTimeIntervalV1 {
                earliest_unix_ms: OBSERVED + 1,
                latest_unix_ms: OBSERVED + 2,
            }),
        ]),
        calls: 0,
    };
    let observation = f
        .observer_transactions()
        .finish_current_with(pending, &mut clock, &mut floor)
        .unwrap();
    assert_eq!(clock.calls, 2);
    assert_eq!(floor.advances, 1);
    assert_eq!(observation.applied_floor(), floor.current);
    let (verified, signing) = observation.into_reserve_context().unwrap();
    assert_eq!(signing.audit_head, expected.operations.audit);
    assert_eq!(signing.custody.current_anchor, expected.custody_anchor);
    assert_eq!(
        signing.custody.active_head,
        expected.control.active_head.unwrap()
    );
    assert_eq!(signing.custody.now_unix_ms, OBSERVED + 2);
    assert_eq!(signing.custody.anchor_observed_at_unix_ms, OBSERVED);
    assert_eq!(verified.snapshot().operations.audit, signing.audit_head);
    assert_eq!(
        verified.snapshot().custody_anchor,
        signing.custody.current_anchor
    );
    let prepared = f.prepare(verified);
    let FinalPromotionAuthorityActionV1::Check(current) =
        &prepared.receipt_check.instruction().action
    else {
        panic!("original verified Current Check");
    };
    let Executable::Instructions(instructions) = &prepared.payload.instructions else {
        panic!("direct role-15 Reserve");
    };
    let reserve = instructions[0]
        .as_any()
        .downcast_ref::<MutateSorafsFinalPromotionAuthority>()
        .unwrap();
    let FinalPromotionAuthorityActionV1::Reserve(reserve) = &reserve.action else {
        panic!("role-15 Reserve");
    };
    assert_eq!(reserve.intent.operation_id, current.request.operation_id);
    assert_eq!(reserve.intent.previous_audit, signing.audit_head);
    assert_eq!(reserve.custody, current.request.original_custody);
}

#[test]
fn pending_or_acknowledged_check_without_application_never_produces_signing_state() {
    let f = Fixture::new();
    let mut floor = RetainedFloor::new(&f);
    let pending = pending_current(&f);
    // A signed envelope or transport acknowledgement has no State/Kura execution proof.
    assert!(pending.signed_transaction().verify_signature().is_ok());
    let mut clock = QualifiedClock::fixed();
    assert!(matches!(
        f.observer_transactions()
            .finish_current_with(pending, &mut clock, &mut floor),
        Err(CurrentError::Check)
    ));
    assert_eq!(clock.calls, 0);
    assert_eq!(floor.advances, 0);
}

#[test]
fn current_handoff_rejects_another_subject_and_changed_custody() {
    let mut f = Fixture::new();
    let current = f.receipt_check(None);
    let prepared = f.prepare(current);
    let Executable::Instructions(instructions) = &prepared.payload.instructions else {
        panic!("native Reserve");
    };
    let reserve = f.signed(instructions[0].clone(), 2, NOW);
    assert_eq!(f.native.commit(NOW, vec![reserve]), [true]);
    let view = f.native.state().view();
    let reserved = read_final_promotion_authority_at_v1(
        &view,
        &f.receipt_policy.binding,
        view.height() as u64,
        Some(f.expected.operation_id),
    )
    .unwrap()
    .unwrap()
    .operation
    .unwrap();
    drop(view);
    let mut floor = RetainedFloor::new(&f);
    let prepared = f.prepare_receipt_check(
        Some(FinalPromotionCheckSubjectV1::BeforeProvider(reserved)),
        Duration::from_secs(60),
    );
    let payload = f.observer_payload(prepared.instruction().clone().into());
    let pending = f
        .observer_transactions()
        .sign_receipt_with(prepared, payload, |request| {
            Signature::try_new(key(3).private_key(), request.signing_message())
                .map_err(|_| ObserverError::Provider)
        })
        .unwrap();
    assert_eq!(
        f.native
            .commit(NOW, vec![pending.signed_transaction().clone()]),
        [true]
    );
    let mut clock = QualifiedClock::fixed();
    assert!(matches!(
        f.observer_transactions()
            .finish_current_with(pending, &mut clock, &mut floor),
        Err(CurrentError::Check)
    ));
    assert_eq!(floor.advances, 0);

    let mut f = Fixture::new();
    let mut floor = RetainedFloor::new(&f);
    let pending = pending_current(&f);
    let view = f.native.state().view();
    let snapshot = read_final_promotion_authority_at_v1(
        &view,
        &f.receipt_policy.binding,
        view.height() as u64,
        None,
    )
    .unwrap()
    .unwrap();
    drop(view);
    let revoke = MutateSorafsFinalPromotionAuthority {
        deployment_id: DEPLOYMENT.into(),
        expected_control_revision: snapshot.control_record.revision,
        expected_control_digest: snapshot.custody_anchor.state_digest,
        action: FinalPromotionAuthorityActionV1::Revoke(FinalPromotionRevocationV1 {
            signer: true,
            attester: false,
        }),
    };
    let revoke = f.signed(revoke.into(), 1, NOW);
    assert_eq!(
        f.native
            .commit(NOW, vec![pending.signed_transaction().clone(), revoke]),
        [true, true]
    );
    let mut clock = QualifiedClock::fixed();
    assert!(matches!(
        f.observer_transactions()
            .finish_current_with(pending, &mut clock, &mut floor),
        Err(CurrentError::Check)
    ));
    assert_eq!(floor.advances, 0);
}

#[test]
fn current_handoff_rejects_floor_regression_persistence_failure_and_false_readback() {
    for fault in 0..3 {
        let mut f = Fixture::new();
        let mut floor = RetainedFloor::new(&f);
        let pending = pending_current(&f);
        assert_eq!(
            f.native
                .commit(NOW, vec![pending.signed_transaction().clone()]),
            [true]
        );
        match fault {
            0 => floor.current.block_hash = [0xA5; 32],
            1 => floor.fail_advance = true,
            2 => floor.mismatched_readback = true,
            _ => unreachable!(),
        }
        let mut clock = QualifiedClock::fixed();
        assert!(matches!(
            f.observer_transactions()
                .finish_current_with(pending, &mut clock, &mut floor),
            Err(CurrentError::Floor)
        ));
        assert_eq!(clock.calls, 1, "fault {fault} must fail before reuse time");
        assert_eq!(floor.advances, usize::from(fault != 0));
    }
}

#[test]
fn current_handoff_rejects_backward_widened_and_unavailable_qualified_time() {
    for fault in 0..3 {
        let mut f = Fixture::new();
        let mut floor = RetainedFloor::new(&f);
        let pending = pending_current(&f);
        assert_eq!(
            f.native
                .commit(NOW, vec![pending.signed_transaction().clone()]),
            [true]
        );
        let later = match fault {
            0 => Ok(FinalPromotionEligibilityTimeIntervalV1 {
                earliest_unix_ms: OBSERVED - 1,
                latest_unix_ms: OBSERVED,
            }),
            1 => Ok(FinalPromotionEligibilityTimeIntervalV1 {
                earliest_unix_ms: OBSERVED,
                latest_unix_ms: 100_000,
            }),
            2 => Err(CurrentError::Clock),
            _ => unreachable!(),
        };
        let mut clock = QualifiedClock {
            intervals: VecDeque::from([Ok(times().0), later]),
            calls: 0,
        };
        assert!(matches!(
            f.observer_transactions()
                .finish_current_with(pending, &mut clock, &mut floor),
            Err(CurrentError::Clock)
        ));
        assert_eq!(clock.calls, 2);
        assert_eq!(floor.advances, 1, "durable floor only moves forward");
    }
}

fn current_runtime(f: &Fixture) -> FinalPromotionCurrentCheckRuntimeV1 {
    let prepared = f.prepare_receipt_check(None, Duration::from_secs(60));
    let FinalPromotionAuthorityActionV1::Check(check) = &prepared.instruction().action else {
        panic!("native Current Check");
    };
    FinalPromotionCurrentCheckRuntimeV1::new(
        Arc::clone(f.native.state()),
        f.observer_transactions(),
        check.request,
        Duration::from_secs(60),
    )
    .unwrap()
}

fn signed_reserve(
    f: &mut Fixture,
) -> (
    SignerFinalPromotionRequestV1,
    SignedFinalPromotionAccountTransactionV1,
) {
    let checked = f.receipt_check(None);
    let FinalPromotionAuthorityActionV1::Check(current) = &checked.instruction().action else {
        panic!("native Current Check");
    };
    let request = current.request;
    let prepared = f.prepare(checked);
    let account_check = f.execute_account_check(f.begin_account_check(&prepared));
    let authorized = prepared
        .authorize(account_check, times().0, times().1)
        .unwrap();
    let (pending, after_account) = authorized
        .sign_with(
            Arc::clone(f.native.state()),
            Duration::from_secs(60),
            || Ok(times()),
            |key_request| {
                Signature::try_new(key(2).private_key(), key_request.signing_message())
                    .map_err(|_| Error::Provider)
            },
        )
        .unwrap();
    let after_account = f.execute_account_check(after_account);
    let (pending, after_receipt) = pending
        .check_account(after_account, times().0, times().1)
        .unwrap();
    let after_receipt = f.execute_receipt_check(after_receipt);
    let signed_transaction = pending
        .release(after_receipt, times().0, times().1)
        .unwrap();
    (request, signed_transaction)
}

fn reserved_runtime(
    f: &Fixture,
    request: SignerFinalPromotionRequestV1,
    signed_transaction: SignedFinalPromotionAccountTransactionV1,
    floor: &mut RetainedFloor,
) -> (FinalPromotionReservedCheckRuntimeV1, tempfile::TempDir) {
    let (directory, journal) = pending_reserve_journal();
    let runtime = FinalPromotionReservedCheckRuntimeV1::new(
        Arc::clone(f.native.state()),
        f.observer_transactions(),
        request,
        signed_transaction,
        Duration::from_secs(60),
        floor,
        &journal,
    )
    .unwrap();
    (runtime, directory)
}

#[test]
fn pending_reserve_rejects_a_finalized_but_rolled_back_floor_before_staging() {
    let mut f = Fixture::new();
    let prepared_check = f.prepare_receipt_check(None, Duration::from_secs(60));
    let payload = f.observer_payload(prepared_check.instruction().clone().into());
    let pending_check = f
        .observer_transactions()
        .sign_receipt_with(prepared_check, payload, |request| {
            Signature::try_new(key(3).private_key(), request.signing_message())
                .map_err(|_| ObserverError::Provider)
        })
        .unwrap();
    assert_eq!(
        f.native
            .commit(NOW, vec![pending_check.signed_transaction().clone()]),
        [true]
    );
    assert!(f.native.commit(NOW, Vec::new()).is_empty());
    let checked = pending_check
        .verify_finalized(FinalPromotionCheckSourceV1::Current, || Ok(times().0))
        .unwrap();
    let check_height = checked.check_height();
    assert_eq!(checked.applied_floor().height, check_height + 1);
    let FinalPromotionAuthorityActionV1::Check(current) = &checked.instruction().action else {
        panic!("original Current Check");
    };
    let request = current.request;
    let prepared = f.prepare(checked);
    let account_check = f.execute_account_check(f.begin_account_check(&prepared));
    let authorized = prepared
        .authorize(account_check, times().0, times().1)
        .unwrap();
    let (pending, after_account) = authorized
        .sign_with(
            Arc::clone(f.native.state()),
            Duration::from_secs(60),
            || Ok(times()),
            |key_request| {
                Signature::try_new(key(2).private_key(), key_request.signing_message())
                    .map_err(|_| Error::Provider)
            },
        )
        .unwrap();
    let after_account = f.execute_account_check(after_account);
    let (pending, after_receipt) = pending
        .check_account(after_account, times().0, times().1)
        .unwrap();
    let after_receipt = f.execute_receipt_check(after_receipt);
    let signed_transaction = pending
        .release(after_receipt, times().0, times().1)
        .unwrap();

    let mut floor = RetainedFloor::new(&f);
    let certified = f.native.chain().committed(check_height);
    floor.current = FinalPromotionCheckFloorV1 {
        height: check_height,
        block_hash: *certified.block_hash().as_ref(),
        context_id: certified.id(),
    };
    let (directory, journal) = pending_reserve_journal();
    assert!(matches!(
        FinalPromotionReservedCheckRuntimeV1::new(
            Arc::clone(f.native.state()),
            f.observer_transactions(),
            request,
            signed_transaction,
            Duration::from_secs(60),
            &mut floor,
            &journal,
        ),
        Err(CurrentError::Floor)
    ));
    assert_eq!(
        crate::signer_operation::journal::test_record_count(
            directory.path().join("pending-reserve-v1")
        ),
        0,
        "rollback must be rejected before staging a durable operation ID"
    );
}

#[test]
fn pending_reserve_restart_recovers_only_the_original_signed_attempt() {
    let mut f = Fixture::new();
    let (request, signed_transaction) = signed_reserve(&mut f);
    let mut floor = RetainedFloor::new(&f);
    let source_floor = floor.current;
    let (runtime, directory) = reserved_runtime(&f, request, signed_transaction, &mut floor);
    let pending = directory
        .path()
        .join("pending-reserve-v1")
        .canonicalize()
        .unwrap();
    let file = pending.join(format!(
        "{}.pending-reserve.norito",
        hex::encode(request.operation_id)
    ));
    assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o7777, 0o400);
    assert!(FinalPromotionPendingReserveJournalV1::open_test(&pending).is_err());
    drop(runtime);
    let reopened = FinalPromotionPendingReserveJournalV1::open_test(&pending).unwrap();
    let recovered = reopened.recover(request.operation_id).unwrap();
    assert_eq!(recovered.operation_id(), request.operation_id);
    assert_eq!(recovered.source_floor(), source_floor);
    recovered.recheck().unwrap();
    assert_eq!(floor.advances, 0);
    // Recovery retains only exact evidence; no Reserve submission method exists on this owner.
}

#[test]
fn changed_pending_reserve_file_blocks_transport_before_submit() {
    let mut f = Fixture::new();
    let (request, signed_transaction) = signed_reserve(&mut f);
    let mut floor = RetainedFloor::new(&f);
    let (runtime, directory) = reserved_runtime(&f, request, signed_transaction, &mut floor);
    let file = directory.path().join("pending-reserve-v1").join(format!(
        "{}.pending-reserve.norito",
        hex::encode(request.operation_id)
    ));
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&file, b"changed pending bytes").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).unwrap();
    let mut submission = RuntimeSubmission::new(&mut f.native, SubmissionMode::Applied);
    assert!(matches!(
        runtime.submit_reserve_with(times().0, times().1, &mut floor, &mut submission),
        Err(CurrentError::Journal)
    ));
    assert_eq!(submission.submits, 0);
    assert_eq!(floor.advances, 0);
}

struct RuntimePayload {
    state: Arc<State>,
    calls: usize,
    substitute_instruction: bool,
}
impl RuntimePayload {
    fn new(f: &Fixture) -> Self {
        Self {
            state: Arc::clone(f.native.state()),
            calls: 0,
            substitute_instruction: false,
        }
    }
}
impl FinalPromotionObserverCheckPayloadV1 for RuntimePayload {
    fn prepare(
        &mut self,
        instruction: &MutateSorafsFinalPromotionAuthority,
    ) -> Result<TransactionPayload, CurrentError> {
        self.calls += 1;
        let mut instruction = instruction.clone();
        if self.substitute_instruction {
            let FinalPromotionAuthorityActionV1::Check(check) = &mut instruction.action else {
                panic!("native Check");
            };
            check.challenge = [0xA5; 32];
        }
        let mut builder = TransactionBuilder::new(
            *self.state.network_id_ref(),
            account(3),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(NOW));
        builder
            .with_instructions([instruction])
            .into_payload()
            .map_err(|_| CurrentError::Payload)
    }
}

struct RuntimeSigner {
    calls: usize,
    seed: u8,
}
impl FinalPromotionObserverCheckSignerV1 for RuntimeSigner {
    fn sign(
        &mut self,
        request: &FinalPromotionObserverKeyRequestV1<'_>,
    ) -> Result<Signature, ObserverError> {
        self.calls += 1;
        Signature::try_new(key(self.seed).private_key(), request.signing_message())
            .map_err(|_| ObserverError::Provider)
    }
}

enum SubmissionMode {
    Applied,
    Rejected,
    AcceptedWithoutApplication,
    AmbiguousThenApplied,
    AmbiguousReconciledWithoutApplication,
    AmbiguousUnresolved,
    AdvanceAudit {
        reserve: Box<SignedTransaction>,
        binding: Box<SignerCustodyBindingV1>,
        operation_id: [u8; 32],
    },
}
struct RuntimeSubmission<'a> {
    native: &'a mut NativeCheckTestFixtureV1,
    mode: SubmissionMode,
    submitted: Option<SignedTransaction>,
    submits: usize,
    reconciles: usize,
}
impl<'a> RuntimeSubmission<'a> {
    fn new(native: &'a mut NativeCheckTestFixtureV1, mode: SubmissionMode) -> Self {
        Self {
            native,
            mode,
            submitted: None,
            submits: 0,
            reconciles: 0,
        }
    }
}
impl FinalPromotionNativeSubmissionV1 for RuntimeSubmission<'_> {
    fn submit_exact(
        &mut self,
        transaction: &SignedTransaction,
    ) -> Result<FinalPromotionNativeSubmitOutcomeV1, CurrentError> {
        self.submits += 1;
        self.submitted = Some(transaction.clone());
        match &self.mode {
            SubmissionMode::Applied => {
                assert_eq!(self.native.commit(NOW, vec![transaction.clone()]), [true]);
                Ok(FinalPromotionNativeSubmitOutcomeV1::Accepted)
            }
            SubmissionMode::Rejected => {
                assert_eq!(self.native.commit(NOW, vec![transaction.clone()]), [false]);
                Ok(FinalPromotionNativeSubmitOutcomeV1::Accepted)
            }
            SubmissionMode::AcceptedWithoutApplication => {
                Ok(FinalPromotionNativeSubmitOutcomeV1::Accepted)
            }
            SubmissionMode::AmbiguousThenApplied
            | SubmissionMode::AmbiguousReconciledWithoutApplication
            | SubmissionMode::AmbiguousUnresolved => {
                Ok(FinalPromotionNativeSubmitOutcomeV1::Ambiguous)
            }
            SubmissionMode::AdvanceAudit {
                reserve,
                binding,
                operation_id,
            } => {
                assert_eq!(
                    self.native.commit(NOW, vec![reserve.as_ref().clone()]),
                    [true]
                );
                let view = self.native.state().view();
                let reserved = read_final_promotion_authority_at_v1(
                    &view,
                    binding,
                    view.height() as u64,
                    Some(*operation_id),
                )
                .unwrap()
                .unwrap();
                let row = reserved.operation.unwrap();
                drop(view);
                let complete = MutateSorafsFinalPromotionAuthority {
                    deployment_id: DEPLOYMENT.into(),
                    expected_control_revision: reserved.control_record.revision,
                    expected_control_digest: reserved.custody_anchor.state_digest,
                    action: FinalPromotionAuthorityActionV1::Complete(FinalPromotionCompleteV1 {
                        intent: row.intent,
                        custody: row.custody,
                        reservation: row.reservation,
                        commitment: SignerOperationCommitmentV1 {
                            audit: SignerOperationAuditHeadV1 {
                                sequence: row.intent.previous_audit.sequence + 1,
                                digest: [0xA4; 32],
                            },
                            response_digest: [0xA5; 32],
                        },
                        signatures_digest: [0xA6; 32],
                    }),
                };
                let mut builder = TransactionBuilder::new(
                    *self.native.state().network_id_ref(),
                    account(2),
                    FeePaymentIntent::authority(Vec::new(), None),
                );
                builder.set_creation_time(Duration::from_millis(NOW));
                let completed = builder
                    .with_instructions([complete])
                    .try_sign(key(2).private_key())
                    .unwrap();
                assert_eq!(self.native.commit(NOW, vec![completed]), [true]);
                assert_eq!(self.native.commit(NOW, vec![transaction.clone()]), [false]);
                Ok(FinalPromotionNativeSubmitOutcomeV1::Accepted)
            }
        }
    }

    fn reconcile_exact(&mut self, transaction: &SignedTransaction) -> Result<(), CurrentError> {
        self.reconciles += 1;
        assert_eq!(self.submitted.as_ref(), Some(transaction));
        match &self.mode {
            SubmissionMode::AmbiguousThenApplied => {
                assert_eq!(self.native.commit(NOW, vec![transaction.clone()]), [true]);
                Ok(())
            }
            SubmissionMode::AmbiguousReconciledWithoutApplication => Ok(()),
            SubmissionMode::AmbiguousUnresolved => Err(CurrentError::Submission),
            _ => panic!("only ambiguous submission may reconcile"),
        }
    }
}

#[test]
fn current_runtime_uses_original_signed_envelope_through_ambiguous_reconciliation() {
    for mode in [
        SubmissionMode::Applied,
        SubmissionMode::AmbiguousThenApplied,
    ] {
        let mut f = Fixture::new();
        let prepared = f.prepare_receipt_check(None, Duration::from_secs(60));
        let FinalPromotionAuthorityActionV1::Check(reviewed) = &prepared.instruction().action
        else {
            panic!("native Current Check");
        };
        let reviewed_request = reviewed.request;
        let runtime = current_runtime(&f);
        let mut payload = RuntimePayload::new(&f);
        let mut signer = RuntimeSigner { calls: 0, seed: 3 };
        let mut floor = RetainedFloor::new(&f);
        let mut clock = QualifiedClock::fixed();
        let mut submission = RuntimeSubmission::new(&mut f.native, mode);
        let observation = runtime
            .observe_current_with(
                &mut payload,
                &mut signer,
                &mut submission,
                &mut clock,
                &mut floor,
            )
            .unwrap();
        assert_eq!(submission.submits, 1);
        assert_eq!(
            submission.reconciles,
            usize::from(matches!(
                &submission.mode,
                SubmissionMode::AmbiguousThenApplied
            ))
        );
        assert_eq!(payload.calls, 1);
        assert_eq!(signer.calls, 1);
        assert_eq!(clock.calls, 2);
        assert_eq!(floor.advances, 1);
        let signed_transaction = submission.submitted.as_ref().unwrap();
        let Executable::Instructions(instructions) = &signed_transaction.payload().instructions
        else {
            panic!("signed native Check");
        };
        let instruction = instructions[0]
            .as_any()
            .downcast_ref::<MutateSorafsFinalPromotionAuthority>()
            .unwrap();
        let FinalPromotionAuthorityActionV1::Check(check) = &instruction.action else {
            panic!("signed native Current Check");
        };
        assert_eq!(check.request, reviewed_request);
        let (verified, state) = observation.into_reserve_context().unwrap();
        assert_eq!(state.audit_head.sequence, 0);
        assert_eq!(state.custody.current_anchor.height, floor.current.height);
        assert_eq!(verified.snapshot().operations.audit, state.audit_head);
    }
}

#[test]
fn current_runtime_rejects_unknown_or_unapplied_submission_without_finalized_application() {
    for mode in [
        SubmissionMode::AcceptedWithoutApplication,
        SubmissionMode::AmbiguousReconciledWithoutApplication,
        SubmissionMode::AmbiguousUnresolved,
    ] {
        let mut f = Fixture::new();
        let runtime = current_runtime(&f);
        let mut payload = RuntimePayload::new(&f);
        let mut signer = RuntimeSigner { calls: 0, seed: 3 };
        let mut floor = RetainedFloor::new(&f);
        let mut clock = QualifiedClock::fixed();
        let mut submission = RuntimeSubmission::new(&mut f.native, mode);
        let result = runtime.observe_current_with(
            &mut payload,
            &mut signer,
            &mut submission,
            &mut clock,
            &mut floor,
        );
        let expected_error = if matches!(&submission.mode, SubmissionMode::AmbiguousUnresolved) {
            CurrentError::Submission
        } else {
            CurrentError::Check
        };
        assert_eq!(result.err(), Some(expected_error));
        assert_eq!(submission.submits, 1);
        assert_eq!(
            submission.reconciles,
            usize::from(matches!(
                &submission.mode,
                SubmissionMode::AmbiguousReconciledWithoutApplication
                    | SubmissionMode::AmbiguousUnresolved
            ))
        );
        assert_eq!(floor.advances, 0);
        assert_eq!(clock.calls, 0);
    }
}

#[test]
fn current_runtime_rejects_payload_and_observer_substitution_before_submission() {
    for fault in 0..2 {
        let mut f = Fixture::new();
        let runtime = current_runtime(&f);
        let mut payload = RuntimePayload::new(&f);
        payload.substitute_instruction = fault == 0;
        let mut signer = RuntimeSigner {
            calls: 0,
            seed: if fault == 0 { 3 } else { 4 },
        };
        let mut floor = RetainedFloor::new(&f);
        let mut clock = QualifiedClock::fixed();
        let mut submission = RuntimeSubmission::new(&mut f.native, SubmissionMode::Applied);
        let result = runtime.observe_current_with(
            &mut payload,
            &mut signer,
            &mut submission,
            &mut clock,
            &mut floor,
        );
        assert!(matches!(
            result,
            Err(CurrentError::Payload | CurrentError::Provider)
        ));
        assert_eq!(signer.calls, usize::from(fault != 0));
        assert_eq!(submission.submits, 0);
        assert_eq!(floor.advances, 0);
    }
}

#[test]
fn current_runtime_rejects_changed_custody_audit_and_rollback() {
    let mut f = Fixture::new();
    let runtime = current_runtime(&f);
    let mut floor = RetainedFloor::new(&f);
    let view = f.native.state().view();
    let snapshot = read_final_promotion_authority_at_v1(
        &view,
        &f.receipt_policy.binding,
        view.height() as u64,
        None,
    )
    .unwrap()
    .unwrap();
    drop(view);
    let revoke = MutateSorafsFinalPromotionAuthority {
        deployment_id: DEPLOYMENT.into(),
        expected_control_revision: snapshot.control_record.revision,
        expected_control_digest: snapshot.custody_anchor.state_digest,
        action: FinalPromotionAuthorityActionV1::Revoke(FinalPromotionRevocationV1 {
            signer: true,
            attester: false,
        }),
    };
    let revoke = f.signed(revoke.into(), 1, NOW);
    assert_eq!(f.native.commit(NOW, vec![revoke]), [true]);
    let mut payload = RuntimePayload::new(&f);
    let mut signer = RuntimeSigner { calls: 0, seed: 3 };
    let mut submission = RuntimeSubmission::new(&mut f.native, SubmissionMode::Applied);
    let mut clock = QualifiedClock::fixed();
    assert!(matches!(
        runtime.observe_current_with(
            &mut payload,
            &mut signer,
            &mut submission,
            &mut clock,
            &mut floor,
        ),
        Err(CurrentError::Custody)
    ));
    assert_eq!(payload.calls, 0);
    assert_eq!(submission.submits, 0);

    let mut f = Fixture::new();
    let receipt = f.receipt_check(None);
    let prepared = f.prepare(receipt);
    let Executable::Instructions(instructions) = &prepared.payload.instructions else {
        panic!("native Reserve");
    };
    let reserve = f.signed(instructions[0].clone(), 2, NOW);
    let runtime = current_runtime(&f);
    let mut payload = RuntimePayload::new(&f);
    let mut signer = RuntimeSigner { calls: 0, seed: 3 };
    let mut floor = RetainedFloor::new(&f);
    let mut clock = QualifiedClock::fixed();
    let binding = f.receipt_policy.binding.clone();
    let operation_id = f.expected.operation_id;
    let mut submission = RuntimeSubmission::new(
        &mut f.native,
        SubmissionMode::AdvanceAudit {
            reserve: Box::new(reserve),
            binding: Box::new(binding),
            operation_id,
        },
    );
    assert!(matches!(
        runtime.observe_current_with(
            &mut payload,
            &mut signer,
            &mut submission,
            &mut clock,
            &mut floor,
        ),
        Err(CurrentError::Check)
    ));
    assert_eq!(floor.advances, 0);

    let mut f = Fixture::new();
    let runtime = current_runtime(&f);
    let mut payload = RuntimePayload::new(&f);
    let mut signer = RuntimeSigner { calls: 0, seed: 3 };
    let mut floor = RetainedFloor::new(&f);
    floor.current.block_hash = [0xA5; 32];
    let mut clock = QualifiedClock::fixed();
    let mut submission = RuntimeSubmission::new(&mut f.native, SubmissionMode::Rejected);
    assert!(
        runtime
            .observe_current_with(
                &mut payload,
                &mut signer,
                &mut submission,
                &mut clock,
                &mut floor,
            )
            .is_err()
    );
    assert_eq!(floor.advances, 0);
}

#[test]
fn current_runtime_rejects_invalid_reviewed_request_at_construction() {
    let f = Fixture::new();
    let prepared = f.prepare_receipt_check(None, Duration::from_secs(60));
    let FinalPromotionAuthorityActionV1::Check(check) = &prepared.instruction().action else {
        panic!("native Current Check");
    };
    let mut request = check.request;
    request.binding_digest = [0xA5; 32];
    assert!(matches!(
        FinalPromotionCurrentCheckRuntimeV1::new(
            Arc::clone(f.native.state()),
            f.observer_transactions(),
            request,
            Duration::from_secs(60),
        ),
        Err(CurrentError::Binding)
    ));
}

#[test]
fn reserved_runtime_keeps_original_role15_envelope_through_reconciliation_and_finalized_check() {
    let mut f = Fixture::new();
    let (request, signed_transaction) = signed_reserve(&mut f);
    let mut floor = RetainedFloor::new(&f);
    let pre_reserve = floor.current;
    let (runtime, _journal_directory) =
        reserved_runtime(&f, request, signed_transaction, &mut floor);
    let mut reserve_submission =
        RuntimeSubmission::new(&mut f.native, SubmissionMode::AmbiguousThenApplied);
    let submitted = runtime
        .submit_reserve_with(times().0, times().1, &mut floor, &mut reserve_submission)
        .unwrap();
    assert_eq!(reserve_submission.submits, 1);
    assert_eq!(reserve_submission.reconciles, 1);
    assert!(
        reserve_submission
            .submitted
            .as_ref()
            .unwrap()
            .verify_signature()
            .is_ok()
    );
    drop(reserve_submission);

    let mut payload = RuntimePayload::new(&f);
    let mut signer = RuntimeSigner { calls: 0, seed: 3 };
    let mut clock = QualifiedClock::fixed();
    let mut check_submission = RuntimeSubmission::new(&mut f.native, SubmissionMode::Applied);
    let mut post_persistence = submitted
        .observe_before_provider_with(
            &mut payload,
            &mut signer,
            &mut check_submission,
            &mut clock,
            &mut floor,
        )
        .unwrap();
    assert_eq!(check_submission.submits, 1);
    assert_eq!(check_submission.reconciles, 0);
    assert_eq!(payload.calls, 1);
    assert_eq!(signer.calls, 1);
    assert_eq!(clock.calls, 1);
    assert_eq!(floor.advances, 1);
    assert_ne!(floor.current, pre_reserve);
    assert_eq!(post_persistence.applied_floor(), Some(floor.current));
    let observation = post_persistence.finish_with(&mut clock).unwrap();
    assert_eq!(clock.calls, 2);
    assert_eq!(observation.applied_floor(), floor.current);
    let (verified, custody) = observation.into_reserved_context().unwrap();
    let FinalPromotionAuthorityActionV1::Check(check) = &verified.instruction().action else {
        panic!("native BeforeProvider Check");
    };
    let FinalPromotionCheckSubjectV1::BeforeProvider(row) = &check.subject else {
        panic!("original Reserved subject");
    };
    assert_eq!(row.intent.operation_id, request.operation_id);
    assert!(row.reserved.height > pre_reserve.height);
    assert_eq!(custody.current_anchor, verified.snapshot().custody_anchor);
    assert_eq!(custody.now_unix_ms, OBSERVED);
}

#[test]
fn reserved_post_persistence_clock_failure_retains_the_in_memory_check_owner() {
    let mut f = Fixture::new();
    let (request, signed_transaction) = signed_reserve(&mut f);
    let mut floor = RetainedFloor::new(&f);
    let (runtime, _journal_directory) =
        reserved_runtime(&f, request, signed_transaction, &mut floor);
    let mut reserve_submission = RuntimeSubmission::new(&mut f.native, SubmissionMode::Applied);
    let submitted = runtime
        .submit_reserve_with(times().0, times().1, &mut floor, &mut reserve_submission)
        .unwrap();
    drop(reserve_submission);
    let mut payload = RuntimePayload::new(&f);
    let mut signer = RuntimeSigner { calls: 0, seed: 3 };
    let mut clock = QualifiedClock {
        intervals: VecDeque::from([Ok(times().0), Err(CurrentError::Clock), Ok(times().0)]),
        calls: 0,
    };
    let mut check_submission = RuntimeSubmission::new(&mut f.native, SubmissionMode::Applied);
    let mut post_persistence = submitted
        .observe_before_provider_with(
            &mut payload,
            &mut signer,
            &mut check_submission,
            &mut clock,
            &mut floor,
        )
        .unwrap();
    assert_eq!(floor.advances, 1);
    assert_eq!(post_persistence.applied_floor(), Some(floor.current));
    assert!(matches!(
        post_persistence.finish_with(&mut clock),
        Err(CurrentError::Clock)
    ));
    assert_eq!(post_persistence.applied_floor(), Some(floor.current));
    let observation = post_persistence.finish_with(&mut clock).unwrap();
    assert_eq!(observation.applied_floor(), floor.current);
    assert_eq!(clock.calls, 3);
    assert_eq!(floor.advances, 1);
}

#[test]
fn reserved_runtime_refuses_floor_advance_before_reserve_transport() {
    let mut f = Fixture::new();
    let (request, signed_transaction) = signed_reserve(&mut f);
    let mut floor = RetainedFloor::new(&f);
    let (runtime, _journal_directory) =
        reserved_runtime(&f, request, signed_transaction, &mut floor);
    let concurrent = pending_current(&f);
    assert_eq!(
        f.native
            .commit(NOW, vec![concurrent.signed_transaction().clone()]),
        [true]
    );
    floor.current = RetainedFloor::new(&f).current;
    let mut reserve_submission = RuntimeSubmission::new(&mut f.native, SubmissionMode::Applied);
    assert!(matches!(
        runtime.submit_reserve_with(times().0, times().1, &mut floor, &mut reserve_submission),
        Err(CurrentError::Floor)
    ));
    assert_eq!(reserve_submission.submits, 0);
    assert_eq!(reserve_submission.reconciles, 0);
    drop(reserve_submission);
    let view = f.native.state().view();
    let snapshot = read_final_promotion_authority_at_v1(
        &view,
        &f.receipt_policy.binding,
        view.height() as u64,
        Some(request.operation_id),
    )
    .unwrap()
    .unwrap();
    assert!(snapshot.operation.is_none());
}

#[test]
fn reserved_runtime_rejects_wrong_finalized_floor_context_before_construction() {
    let mut f = Fixture::new();
    let earlier_context = f.native.finalized_floor().2;
    let (request, signed_transaction) = signed_reserve(&mut f);
    let mut floor = RetainedFloor::new(&f);
    assert_ne!(earlier_context, floor.current.context_id);
    floor.current.context_id = earlier_context;
    let (_journal_directory, journal) = pending_reserve_journal();
    assert!(matches!(
        FinalPromotionReservedCheckRuntimeV1::new(
            Arc::clone(f.native.state()),
            f.observer_transactions(),
            request,
            signed_transaction,
            Duration::from_secs(60),
            &mut floor,
            &journal,
        ),
        Err(CurrentError::Floor)
    ));
    assert_eq!(floor.advances, 0);
    let view = f.native.state().view();
    let snapshot = read_final_promotion_authority_at_v1(
        &view,
        &f.receipt_policy.binding,
        view.height() as u64,
        Some(request.operation_id),
    )
    .unwrap()
    .unwrap();
    assert!(snapshot.operation.is_none());
}

#[test]
fn reserved_runtime_rejects_unapplied_or_substituted_reserve_before_floor_advance() {
    for substitute in [false, true] {
        let mut f = Fixture::new();
        let (request, signed_transaction) = signed_reserve(&mut f);
        let mut floor = RetainedFloor::new(&f);
        let (runtime, _journal_directory) =
            reserved_runtime(&f, request, signed_transaction, &mut floor);
        let mut reserve_submission =
            RuntimeSubmission::new(&mut f.native, SubmissionMode::AcceptedWithoutApplication);
        let submitted = runtime
            .submit_reserve_with(times().0, times().1, &mut floor, &mut reserve_submission)
            .unwrap();
        let original = reserve_submission.submitted.clone().unwrap();
        drop(reserve_submission);
        if substitute {
            let Executable::Instructions(instructions) = &original.payload().instructions else {
                panic!("direct role-15 Reserve");
            };
            let alternate = f.signed(instructions[0].clone(), 2, NOW - 1);
            assert_ne!(alternate.payload(), original.payload());
            assert_eq!(f.native.commit(NOW, vec![alternate]), [true]);
        }
        let mut payload = RuntimePayload::new(&f);
        let mut signer = RuntimeSigner { calls: 0, seed: 3 };
        let mut clock = QualifiedClock::fixed();
        let mut check_submission = RuntimeSubmission::new(&mut f.native, SubmissionMode::Applied);
        assert!(matches!(
            submitted.observe_before_provider_with(
                &mut payload,
                &mut signer,
                &mut check_submission,
                &mut clock,
                &mut floor,
            ),
            Err(CurrentError::Check)
        ));
        assert_eq!(payload.calls, usize::from(substitute));
        assert_eq!(signer.calls, usize::from(substitute));
        assert_eq!(clock.calls, 0);
        assert_eq!(floor.advances, 0);
    }
}

#[test]
fn reserved_runtime_rejects_post_reserve_floor_before_any_check_work() {
    let mut f = Fixture::new();
    let (request, signed_transaction) = signed_reserve(&mut f);
    let mut floor = RetainedFloor::new(&f);
    let (runtime, _journal_directory) =
        reserved_runtime(&f, request, signed_transaction, &mut floor);
    let mut reserve_submission = RuntimeSubmission::new(&mut f.native, SubmissionMode::Applied);
    let submitted = runtime
        .submit_reserve_with(times().0, times().1, &mut floor, &mut reserve_submission)
        .unwrap();
    drop(reserve_submission);
    floor.current = RetainedFloor::new(&f).current;
    let mut payload = RuntimePayload::new(&f);
    let mut signer = RuntimeSigner { calls: 0, seed: 3 };
    let mut clock = QualifiedClock::fixed();
    let mut check_submission = RuntimeSubmission::new(&mut f.native, SubmissionMode::Applied);
    assert!(matches!(
        submitted.observe_before_provider_with(
            &mut payload,
            &mut signer,
            &mut check_submission,
            &mut clock,
            &mut floor,
        ),
        Err(CurrentError::Floor)
    ));
    assert_eq!(payload.calls, 0);
    assert_eq!(signer.calls, 0);
    assert_eq!(check_submission.submits, 0);
    assert_eq!(floor.advances, 0);
}

#[test]
fn reserved_runtime_rejects_late_reconstruction_after_original_reserve() {
    let mut f = Fixture::new();
    let (request, signed_transaction) = signed_reserve(&mut f);
    let original = signed_transaction
        .for_submission(times().0, times().1)
        .unwrap()
        .clone();
    assert_eq!(f.native.commit(NOW, vec![original]), [true]);
    let mut floor = RetainedFloor::new(&f);
    let (_journal_directory, journal) = pending_reserve_journal();
    assert!(matches!(
        FinalPromotionReservedCheckRuntimeV1::new(
            Arc::clone(f.native.state()),
            f.observer_transactions(),
            request,
            signed_transaction,
            Duration::from_secs(60),
            &mut floor,
            &journal,
        ),
        Err(CurrentError::Check)
    ));
    assert_eq!(floor.advances, 0);
}

#[test]
fn current_verification_refusal_retries_exact_signed_owner_before_fresh_clock_and_floor() {
    use crate::native_check_binding::complete_check_with;
    use iroha_core::execution_attempt::ExecutionAttemptError;
    let mut f = Fixture::new();
    let pending = pending_current(&f);
    let signed_transaction = pending.signed_transaction().clone();
    let deadline = pending.deadline();
    assert_eq!(
        f.native.commit(NOW, vec![signed_transaction.clone()]),
        [true]
    );
    let pool = f.native.state().ivm_execution_budget();
    let original_limit = pool.limit_bytes();
    let retained = pool.reserved_bytes();
    let clock_calls = std::cell::Cell::new(0);
    let verify = |pending: PendingFinalPromotionCheckV1| {
        pending.verify_finalized(FinalPromotionCheckSourceV1::Current, || {
            clock_calls.set(clock_calls.get() + 1);
            Ok(times().0)
        })
    };
    pool.set_limit_bytes(0);
    let failed = verify(pending)
        .err()
        .expect("actual original State source allocation refuses");
    assert_eq!(clock_calls.get(), 0, "source refusal precedes UTC sampling");
    assert_eq!(
        pool.reserved_bytes(),
        retained,
        "failed replay releases transient source owners"
    );
    let mut waits = 0;
    let verified = complete_check_with(
        Err(failed),
        |failure| verify(failure.into_pending()),
        std::time::Instant::now,
        |failure, delay| {
            waits += 1;
            assert_eq!(failure.signed_transaction(), &signed_transaction);
            assert_eq!(failure.deadline(), deadline);
            assert_eq!(delay, Duration::from_millis(1));
            let ExecutionAttemptError::Deferred(original) = failure.error() else {
                panic!("local source refusal");
            };
            assert!(matches!(
                original.allocation_refusal(),
                Some(iroha_allocation::AllocationRefusal::ExceedsLimit { limit_bytes: 0, .. })
            ));
            assert_eq!(pool.reserved_bytes(), retained);
            pool.set_limit_bytes(original_limit);
        },
    )
    .unwrap_or_else(|_| {
        panic!("same signed Check should verify after original capacity is restored")
    });
    assert_eq!(waits, 1);
    assert_eq!(clock_calls.get(), 1);
    assert_eq!(
        verified.original_floor().height + 1,
        verified.applied_floor().height
    );
    // The caller's durable floor has not been advanced by this source-only retry.
    drop(verified);
    assert!(
        pool.reserved_bytes() < retained,
        "last signed owner releases its original backing"
    );
}

#[test]
fn current_verification_clock_rejection_remains_clock_and_never_retries() {
    use crate::native_check_binding::{CheckTermination, complete_check_with};
    use iroha_core::query::final_promotion_authority::observation::FinalPromotionObservationErrorV1;
    let mut f = Fixture::new();
    let pending = pending_current(&f);
    assert_eq!(
        f.native
            .commit(NOW, vec![pending.signed_transaction().clone()]),
        [true]
    );
    let failed = pending
        .verify_finalized(FinalPromotionCheckSourceV1::Current, || {
            Err(FinalPromotionObservationErrorV1::Clock)
        })
        .err()
        .expect("actual completed clock rejection");
    assert_eq!(
        failed.rejection(),
        Some(FinalPromotionObservationErrorV1::Clock)
    );
    let original_deadline = failed.deadline();
    let result: Result<(), _> = complete_check_with(
        Err(failed),
        |_| panic!("terminal Clock cannot retry"),
        || original_deadline,
        |_, _| panic!("terminal Clock cannot wait"),
    );
    let Err(terminal @ CheckTermination::Terminal(_)) = result else {
        panic!("completed Clock retained");
    };
    assert_eq!(
        crate::signer_operation::final_promotion::current_observation::verification_error(terminal),
        CurrentError::Clock
    );
}

#[test]
fn current_verification_local_expiry_is_capacity_not_a_completed_check_rejection() {
    use crate::native_check_binding::{CheckTermination, complete_check_with};
    use iroha_core::execution_attempt::ExecutionAttemptError;
    let mut f = Fixture::new();
    let pending = pending_current(&f);
    let deadline = pending.deadline();
    let signed_transaction = pending.signed_transaction().clone();
    assert_eq!(
        f.native.commit(NOW, vec![signed_transaction.clone()]),
        [true]
    );
    let pool = f.native.state().ivm_execution_budget();
    let limit = pool.limit_bytes();
    let retained = pool.reserved_bytes();
    pool.set_limit_bytes(0);
    let failed = pending
        .verify_finalized(FinalPromotionCheckSourceV1::Current, || {
            panic!("source refusal cannot sample the clock");
        })
        .err()
        .expect("actual original source refusal");
    assert_eq!(failed.deadline(), deadline);
    assert_eq!(failed.signed_transaction(), &signed_transaction);
    let ExecutionAttemptError::Deferred(original) = failed.error() else {
        panic!("local State refusal");
    };
    assert!(matches!(
        original.allocation_refusal(),
        Some(iroha_allocation::AllocationRefusal::ExceedsLimit { limit_bytes: 0, .. })
    ));
    assert_eq!(pool.reserved_bytes(), retained);
    let result: Result<(), _> = complete_check_with(
        Err(failed),
        |_| panic!("no retry after original expiry"),
        || deadline,
        |_, _| panic!("already expired owner cannot wait"),
    );
    let Err(expired @ CheckTermination::Expired) = result else {
        panic!("original lifetime expired locally");
    };
    assert_eq!(
        crate::signer_operation::final_promotion::current_observation::verification_error(expired),
        CurrentError::LocalCapacity,
    );
    assert!(
        pool.reserved_bytes() < retained,
        "expired original owner releases its backing"
    );
    pool.set_limit_bytes(limit);
}
