//! Authoritative enrollment and terminal-transition simulations; never hardware readiness evidence.

use super::*;
use crate::signer_operation::control::{
    SignerCustodyEnrollmentRequestV1, enroll_initial_signer_custody_v1,
    signer_custody_transition_request_digest_v1,
};

pub(super) fn apply_enrollment(
    state: &mut SourceState,
    request: &SignerCustodyEnrollmentRequestV1<'_>,
) -> Result<(), SignerOperationErrorV1> {
    let statement = request.enrollment().statement();
    let Some((binding, context)) = &state.enrollment else {
        return Err(SignerOperationErrorV1::ReservationConflict);
    };
    if binding != &statement.binding
        || context.next_sequence != statement.sequence
        || context.predecessor_digest != statement.predecessor_digest
        || context.current_anchor != statement.anchor
        || state.context.current_anchor.state_digest != context.current_anchor.state_digest
    {
        return Err(SignerOperationErrorV1::ReservationConflict);
    }
    let record: SignerCustodyRecordV1 =
        norito::decode_canonical(request.record_bytes()).expect("canonical public record");
    assert_eq!(&record.statement, statement);
    state.active_binding = statement.binding.clone();
    state.context.active_head = SignerCustodyActiveHeadV1 {
        record_digest: request.enrollment().record_digest(),
        sequence: statement.sequence,
        approved_anchor: statement.anchor,
        key_revision: statement.binding.key_revision,
        policy_revision: statement.binding.policy_revision,
        policy_digest: statement.binding.policy_digest,
    };
    state.context.current_anchor.height += 1;
    state.context.current_anchor.block_hash[0] ^= 1;
    state.context.current_anchor.state_digest[0] ^= 1;
    state.context.now_unix_ms += 1;
    state.context.signer_revoked = false;
    state.context.attester_revoked = false;
    state.initially_enrolled = true;
    state.enrollment = None;
    Ok(())
}
fn attest(statement: SignerCustodyStatementV1) -> Vec<u8> {
    let signature = Signature::try_new(
        key(0x31).private_key(),
        &statement.signing_payload().expect("qualified statement"),
    )
    .expect("independent test authority");
    norito::encode_canonical(&SignerCustodyRecordV1 {
        statement,
        attestation: signature.payload().try_into().expect("Ed25519"),
    })
    .expect("canonical record")
}
fn successor(fixture: &Fixture, binding: SignerCustodyBindingV1) -> Vec<u8> {
    let mut record: SignerCustodyRecordV1 =
        norito::decode_canonical(&fixture.coordinator.record).expect("record");
    let mut state = fixture.source.state.lock().expect("lock");
    record.statement.binding = binding.clone();
    record.statement.sequence += 1;
    record.statement.predecessor_digest = state.context.active_head.record_digest;
    record.statement.anchor = state.context.current_anchor;
    state.enrollment = Some((
        binding,
        SignerCustodyEnrollmentContextV1 {
            now_unix_ms: state.context.now_unix_ms,
            anchor_observed_at_unix_ms: state.context.anchor_observed_at_unix_ms,
            current_anchor: state.context.current_anchor,
            next_sequence: record.statement.sequence,
            predecessor_digest: record.statement.predecessor_digest,
            signer_revoked: false,
            attester_revoked: false,
        },
    ));
    attest(record.statement)
}
fn terminal_intent(
    fixture: &Fixture,
    action: SignerOperationActionV1,
    transition_digest: [u8; 32],
) -> SignerOperationIntentV1 {
    let mut value = intent(action);
    value.operation_id[0] = 0x81;
    value.previous_audit = fixture.source.state.lock().expect("lock").audit;
    let previous_record = fixture
        .source
        .state
        .lock()
        .expect("lock")
        .context
        .active_head
        .record_digest;
    value.request_digest = signer_custody_transition_request_digest_v1(
        action,
        value.operation_id,
        previous_record,
        value.previous_audit,
        transition_digest,
    )
    .expect("terminal request");
    value
}
#[test]
fn initial_enrollment_cas_is_once_only_and_never_invokes_a_role_key() {
    let fixture = fixture();
    let record: SignerCustodyRecordV1 =
        norito::decode_canonical(&fixture.coordinator.record).expect("record");
    {
        let mut state = fixture.source.state.lock().expect("lock");
        state.initially_enrolled = false;
        state.context.current_anchor = record.statement.anchor;
        state.enrollment = Some((
            fixture.source.binding.clone(),
            SignerCustodyEnrollmentContextV1 {
                now_unix_ms: 1_500,
                anchor_observed_at_unix_ms: 1_450,
                current_anchor: record.statement.anchor,
                next_sequence: 1,
                predecessor_digest: [0; 32],
                signer_revoked: false,
                attester_revoked: false,
            },
        ));
    }
    let active = enroll_initial_signer_custody_v1(
        &fixture.source.binding,
        &fixture.coordinator.record,
        &fixture.coordinator.trust,
        fixture.source.as_ref(),
    )
    .expect("enroll initial");
    assert_eq!(active.statement(), &record.statement);
    assert!(
        enroll_initial_signer_custody_v1(
            &fixture.source.binding,
            &fixture.coordinator.record,
            &fixture.coordinator.trust,
            fixture.source.as_ref()
        )
        .is_err()
    );
    assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        fixture
            .source
            .state
            .lock()
            .expect("lock")
            .transition_commits,
        1
    );
}
#[test]
fn enrollment_requires_independent_successor_configuration_authority_and_exact_slot() {
    let fixture = fixture();
    let record = successor(&fixture, fixture.source.binding.clone());
    assert!(
        enroll_initial_signer_custody_v1(
            &fixture.source.binding,
            &record,
            &fixture.coordinator.trust,
            fixture.source.as_ref()
        )
        .is_err()
    );
    let mut wrong = fixture.source.binding.clone();
    wrong.key_revision += 1;
    assert!(
        fixture
            .coordinator
            .prepare_custody_activation(
                fixture.source.as_ref(),
                wrong,
                record.clone(),
                fixture.coordinator.trust.clone()
            )
            .is_err()
    );
    let mut trust = fixture.coordinator.trust.clone();
    trust.public_key = key(0x41).public_key().clone();
    assert!(
        fixture
            .coordinator
            .prepare_custody_activation(
                fixture.source.as_ref(),
                fixture.source.binding.clone(),
                record,
                trust
            )
            .is_err()
    );
    assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        fixture
            .source
            .state
            .lock()
            .expect("lock")
            .transition_commits,
        0
    );
}
#[test]
fn exact_key_renewal_new_policy_and_new_key_activate_only_after_old_key_terminal_audit() {
    for kind in 0..3 {
        let fixture = fixture();
        let mut binding = fixture.source.binding.clone();
        match kind {
            1 => {
                binding.policy_revision += 1;
                binding.policy_digest[0] ^= 1;
            }
            2 => {
                binding.key_revision += 1;
                binding.key_handle = "pkcs11:production/promotion/key-8".into();
                binding.public_key = key(0x41).public_key().clone();
            }
            _ => {}
        }
        let record = successor(&fixture, binding.clone());
        let prepared = fixture
            .coordinator
            .prepare_custody_activation(
                fixture.source.as_ref(),
                binding.clone(),
                record,
                fixture.coordinator.trust.clone(),
            )
            .expect("qualified successor");
        let digest = prepared.record_digest();
        let mut operation = fixture
            .coordinator
            .begin(terminal_intent(
                &fixture,
                SignerOperationActionV1::ActivateCustody,
                digest,
            ))
            .expect("reserve terminal action");
        operation
            .sign(
                SignerKeyOperationPurposeV1::AuditRecord,
                &commitment().audit.signing_message(),
            )
            .expect("old-key terminal audit");
        let completed = operation
            .finish_custody_activation(fixture.source.as_ref(), &prepared, commitment().audit)
            .expect("activate exact successor");
        assert_eq!(completed.action(), SignerOperationActionV1::ActivateCustody);
        assert_eq!(completed.audit(), commitment().audit);
        assert_eq!(completed.transition_digest(), digest);
        assert_eq!(
            completed
                .activation()
                .expect("eligible successor")
                .statement()
                .binding,
            binding
        );
        assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            fixture
                .source
                .state
                .lock()
                .expect("lock")
                .transition_commits,
            1
        );
        assert!(
            fixture
                .coordinator
                .begin(intent(SignerOperationActionV1::Sign))
                .is_err()
        );
    }
}
#[test]
fn successor_identity_alias_and_revision_rollback_are_rejected_before_provider_io() {
    let mutations: &[fn(&mut SignerCustodyBindingV1)] = &[
        |binding| binding.runtime_handle = "hsm://sorafs/promotion/substituted".into(),
        |binding| binding.service_id = "promotion-substituted".into(),
        |binding| binding.administrator_id = "security-substituted".into(),
        |binding| binding.key_revision += 1,
        |binding| binding.key_handle = "pkcs11:production/promotion/key-alias".into(),
        |binding| binding.public_key = key(0x41).public_key().clone(),
        |binding| binding.policy_revision -= 1,
        |binding| binding.policy_digest[0] ^= 1,
    ];
    for mutate in mutations {
        let fixture = fixture();
        let mut binding = fixture.source.binding.clone();
        mutate(&mut binding);
        let record = successor(&fixture, binding.clone());
        assert!(
            fixture
                .coordinator
                .prepare_custody_activation(
                    fixture.source.as_ref(),
                    binding,
                    record,
                    fixture.coordinator.trust.clone()
                )
                .is_err()
        );
        assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn revocation_finalizes_audit_without_provenance_response_or_post_revocation_key_use() {
    let fixture = fixture();
    let mut operation = fixture
        .coordinator
        .begin(terminal_intent(
            &fixture,
            SignerOperationActionV1::RevokeCustody,
            [0x91; 32],
        ))
        .expect("reserve revoke");
    operation
        .sign(
            SignerKeyOperationPurposeV1::AuditRecord,
            &commitment().audit.signing_message(),
        )
        .expect("terminal audit");
    let completed = operation
        .finish_custody_revocation(fixture.source.as_ref(), [0x91; 32], commitment().audit)
        .expect("finalized revocation");
    assert_eq!(completed.action(), SignerOperationActionV1::RevokeCustody);
    assert!(completed.activation().is_none());
    assert_eq!(completed.audit(), commitment().audit);
    assert_eq!(completed.transition_digest(), [0x91; 32]);
    assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 1);
    assert!(
        fixture
            .coordinator
            .begin(intent(SignerOperationActionV1::Sign))
            .is_err()
    );
    assert!(
        fixture
            .coordinator
            .begin(intent(SignerOperationActionV1::Status))
            .is_err()
    );
    let state = fixture.source.state.lock().expect("lock");
    assert!(state.context.signer_revoked);
    assert_eq!(state.audit, commitment().audit);
    assert_eq!(state.transition_commits, 1);
}

#[test]
fn explicit_control_source_must_own_the_exact_original_reservation() {
    let original = fixture();
    let substituted = fixture();
    let old_audit = original.source.state.lock().expect("source lock").audit;
    let mut operation = original
        .coordinator
        .begin(terminal_intent(
            &original,
            SignerOperationActionV1::RevokeCustody,
            [0x91; 32],
        ))
        .expect("reserve only on the original authority");
    operation
        .sign(
            SignerKeyOperationPurposeV1::AuditRecord,
            &commitment().audit.signing_message(),
        )
        .expect("prepare the exact old-key audit");
    assert!(matches!(
        operation.finish_custody_revocation(
            substituted.source.as_ref(),
            [0x91; 32],
            commitment().audit,
        ),
        Err(SignerOperationErrorV1::ReservationConflict)
    ));
    for source in [&original.source, &substituted.source] {
        let state = source.state.lock().expect("source lock");
        assert_eq!(state.transition_commits, 0);
        assert_eq!(state.audit, old_audit);
        assert!(!state.context.signer_revoked);
    }
    assert!(
        original
            .source
            .state
            .lock()
            .expect("source lock")
            .reservation
            .is_some()
    );
    assert_eq!(original.provider.calls.load(Ordering::Relaxed), 1);
}
#[test]
fn terminal_actions_cannot_escape_through_ordinary_completion_or_substituted_audit_reason() {
    for kind in 0..4 {
        let fixture = fixture();
        let mut operation = fixture
            .coordinator
            .begin(terminal_intent(
                &fixture,
                SignerOperationActionV1::RevokeCustody,
                [0x91; 32],
            ))
            .expect("reserve revoke");
        operation
            .sign(
                SignerKeyOperationPurposeV1::AuditRecord,
                &commitment().audit.signing_message(),
            )
            .expect("audit");
        match kind {
            0 => assert!(operation.finish(commitment()).is_err()),
            1 => assert!(
                operation
                    .finish_custody_revocation(
                        fixture.source.as_ref(),
                        [0x93; 32],
                        commitment().audit
                    )
                    .is_err()
            ),
            2 => {
                let mut audit = commitment().audit;
                audit.digest[0] ^= 1;
                assert!(
                    operation
                        .finish_custody_revocation(fixture.source.as_ref(), [0x91; 32], audit)
                        .is_err()
                );
            }
            _ => {
                fixture.source.state.lock().expect("lock").fail_transition = true;
                assert!(
                    operation
                        .finish_custody_revocation(
                            fixture.source.as_ref(),
                            [0x91; 32],
                            commitment().audit
                        )
                        .is_err()
                );
            }
        }
        let state = fixture.source.state.lock().expect("lock");
        assert_eq!(state.transition_commits, 0);
        assert!(!state.context.signer_revoked);
    }
}
#[test]
fn control_drift_during_terminal_audit_prevents_activation_or_revocation_commit() {
    let fixture = fixture();
    let mut operation = fixture
        .coordinator
        .begin(terminal_intent(
            &fixture,
            SignerOperationActionV1::RevokeCustody,
            [0x91; 32],
        ))
        .expect("reserve revoke");
    *fixture.provider.fault.lock().expect("lock") = Some(ProviderFault::Mutate(Mutation::Control));
    assert!(
        operation
            .sign(
                SignerKeyOperationPurposeV1::AuditRecord,
                &commitment().audit.signing_message()
            )
            .is_err()
    );
    assert!(
        operation
            .finish_custody_revocation(fixture.source.as_ref(), [0x91; 32], commitment().audit)
            .is_err()
    );
    assert_eq!(
        fixture
            .source
            .state
            .lock()
            .expect("lock")
            .transition_commits,
        0
    );
}
#[test]
fn terminal_request_digest_binds_action_predecessor_and_transition() {
    let audit = commitment().audit;
    let digest = signer_custody_transition_request_digest_v1(
        SignerOperationActionV1::RevokeCustody,
        [1; 32],
        [2; 32],
        audit,
        [3; 32],
    )
    .expect("valid digest");
    assert_ne!(
        digest,
        signer_custody_transition_request_digest_v1(
            SignerOperationActionV1::ActivateCustody,
            [1; 32],
            [2; 32],
            audit,
            [3; 32]
        )
        .expect("different action")
    );
    assert_ne!(
        digest,
        signer_custody_transition_request_digest_v1(
            SignerOperationActionV1::RevokeCustody,
            [1; 32],
            [2; 32],
            audit,
            [4; 32]
        )
        .expect("different reason")
    );
    assert!(
        signer_custody_transition_request_digest_v1(
            SignerOperationActionV1::Sign,
            [1; 32],
            [2; 32],
            audit,
            [3; 32]
        )
        .is_err()
    );
    assert!(
        signer_custody_transition_request_digest_v1(
            SignerOperationActionV1::RevokeCustody,
            [1; 32],
            [0; 32],
            audit,
            [3; 32]
        )
        .is_err()
    );
}

#[test]
fn completed_response_cannot_be_relabelled_after_same_key_custody_renewal() {
    let fixture = fixture();
    let mut signing = fixture
        .coordinator
        .begin(intent(SignerOperationActionV1::Sign))
        .expect("reserve original sign");
    stage(&mut signing);
    let original = signing
        .finish(commitment())
        .expect("original durable completion");
    let binding = fixture.source.binding.clone();
    let record = successor(&fixture, binding.clone());
    let prepared = fixture
        .coordinator
        .prepare_custody_activation(
            fixture.source.as_ref(),
            binding.clone(),
            record.clone(),
            fixture.coordinator.trust.clone(),
        )
        .expect("same-key renewal");
    let digest = prepared.record_digest();
    let mut renewal = fixture
        .coordinator
        .begin(terminal_intent(
            &fixture,
            SignerOperationActionV1::ActivateCustody,
            digest,
        ))
        .expect("reserve renewal");
    let audit = SignerOperationAuditHeadV1 {
        sequence: 5,
        digest: [0x95; 32],
    };
    renewal
        .sign(
            SignerKeyOperationPurposeV1::AuditRecord,
            &audit.signing_message(),
        )
        .expect("terminal audit");
    let activated = renewal
        .finish_custody_activation(fixture.source.as_ref(), &prepared, audit)
        .expect("activate renewal");
    let new_custody =
        SignerOperationCustodyV1::from_verified(activated.activation().expect("new custody"));
    let coordinator = SignerOperationCoordinatorV1::new(
        binding,
        record,
        fixture.coordinator.trust.clone(),
        fixture.provider.clone(),
        fixture.source.clone(),
    )
    .expect("new coordinator for same key");
    assert_eq!(
        coordinator.binding.public_key,
        fixture.coordinator.binding.public_key
    );
    // Honest old metadata must fail the current-custody check.
    assert!(matches!(
        coordinator.recover_completed(super::recovery::recovered(&original)),
        Err(SignerOperationErrorV1::CustodyChanged)
    ));
    // Relabelling the old signatures with new custody must fail authoritative history replay.
    let mut substituted = super::recovery::recovered(&original);
    substituted.original_custody = new_custody;
    assert!(matches!(
        coordinator.recover_completed(substituted),
        Err(SignerOperationErrorV1::ReservationConflict)
    ));
    assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 5);
    assert_eq!(fixture.source.state.lock().expect("lock").commits, 1);
}

#[test]
fn terminal_final_observation_rejects_post_commit_custody_drift_without_old_key_response() {
    for action in [
        SignerOperationActionV1::ActivateCustody,
        SignerOperationActionV1::RevokeCustody,
    ] {
        for mutation in [
            Mutation::Control,
            Mutation::Record,
            Mutation::AttesterRevoked,
            Mutation::TimeBackwards,
            Mutation::SameHeightFork,
        ] {
            let fixture = fixture();
            let prepared = if action == SignerOperationActionV1::ActivateCustody {
                let record = successor(&fixture, fixture.source.binding.clone());
                Some(
                    fixture
                        .coordinator
                        .prepare_custody_activation(
                            fixture.source.as_ref(),
                            fixture.source.binding.clone(),
                            record,
                            fixture.coordinator.trust.clone(),
                        )
                        .expect("successor"),
                )
            } else {
                None
            };
            let digest = prepared.as_ref().map_or(
                [0x91; 32],
                super::super::control::PreparedSignerCustodyActivationV1::record_digest,
            );
            let mut operation = fixture
                .coordinator
                .begin(terminal_intent(&fixture, action, digest))
                .expect("reserve terminal action");
            operation
                .sign(
                    SignerKeyOperationPurposeV1::AuditRecord,
                    &commitment().audit.signing_message(),
                )
                .expect("old-key audit");
            fixture
                .source
                .state
                .lock()
                .expect("lock")
                .mutate_on_transition_observe = Some(mutation);
            let result = match prepared {
                Some(prepared) => operation.finish_custody_activation(
                    fixture.source.as_ref(),
                    &prepared,
                    commitment().audit,
                ),
                None => operation.finish_custody_revocation(
                    fixture.source.as_ref(),
                    digest,
                    commitment().audit,
                ),
            };
            assert!(result.is_err());
            assert_eq!(
                fixture
                    .source
                    .state
                    .lock()
                    .expect("lock")
                    .transition_commits,
                1
            );
            assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 1);
        }
    }
}
