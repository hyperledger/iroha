//! Simulated opaque-provider races and durable-CAS failures; these are not deployment evidence.

mod completion_finality;
mod control;
#[cfg(unix)]
mod credential_provider;
#[cfg(unix)]
mod final_promotion;
mod recovery;
#[cfg(unix)]
mod release_manifest;
#[cfg(unix)]
mod stream_token;

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use sorafs_manifest::signer::{
    custody::{
        SIGNER_CUSTODY_MAGIC_V1, SIGNER_CUSTODY_VERSION_V1, SignerCustodyActiveHeadV1,
        SignerCustodyAnchorV1, SignerCustodyAuthorityV1, SignerCustodyEnrollmentContextV1,
        SignerCustodyRecordV1, SignerCustodyStatementV1, verify_signer_custody_enrollment_v1,
    },
    protocol::{SignerKeyAlgorithmV1, SignerPurposeBindingV1, SignerRoleV1},
};
use std::{
    collections::BTreeSet,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Clone, Copy)]
enum Mutation {
    Control,
    Record,
    SignerRevoked,
    AttesterRevoked,
    TimeBackwards,
    SameHeightFork,
    Expired,
    ObservationTime { now: u64, observed: u64 },
    LostReservation,
    LostCompletion,
}
type CompletedOperation = (
    SignerOperationReservationV1,
    [u8; 32],
    SignerOperationCommitmentV1,
    [u8; 32],
    SignerOperationCustodyV1,
);
#[derive(Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "these independent test fault switches exercise combinations of custody, observation, commit and journal failures"
)]
struct SourceState {
    active_binding: SignerCustodyBindingV1,
    enrollment: Option<(SignerCustodyBindingV1, SignerCustodyEnrollmentContextV1)>,
    initially_enrolled: bool,
    fail_transition: bool,
    transition_commits: usize,
    mutate_on_transition_observe: Option<Mutation>,
    context: SignerCustodyUseContextV1,
    audit: SignerOperationAuditHeadV1,
    reservation: Option<(SignerOperationReservationV1, [u8; 32])>,
    used_ids: BTreeSet<[u8; 32]>,
    completed: Option<CompletedOperation>,
    reserve_override: Option<SignerOperationReservationV1>,
    mutate_after_reserve: Option<Mutation>,
    mutate_at_reserved: Option<(usize, Mutation)>,
    mutate_after_commit: Option<Mutation>,
    mutate_at_completed: Option<(SignerCommittedObservationPhaseV1, Mutation)>,
    mutate_at_release: Option<Mutation>,
    fail_observe: bool,
    signing_reads: usize,
    advance_audit_after_signing_snapshot: bool,
    fail_commit: bool,
    expected_journal: Option<std::path::PathBuf>,
    journal_checked: usize,
    mutate_journal_after_commit: bool,
    mutate_journal_at_release: bool,
    reserved_reads: usize,
    commits: usize,
    reserved_phases: Vec<SignerReservedObservationPhaseV1>,
    completed_phases: Vec<SignerCommittedObservationPhaseV1>,
    fail_reserved_phase: Option<SignerReservedObservationPhaseV1>,
    fail_completed_phase: Option<SignerCommittedObservationPhaseV1>,
}
impl SourceState {
    fn mutate(&mut self, mutation: Mutation) {
        if matches!(
            mutation,
            Mutation::Control
                | Mutation::Record
                | Mutation::SignerRevoked
                | Mutation::AttesterRevoked
        ) {
            // Model an actual later finalized custody-control change, not mutable state
            // relabeled using the same finalized height/hash.
            self.context.current_anchor.height += 1;
            self.context.current_anchor.block_hash[0] ^= 1;
            self.context.current_anchor.state_digest[0] ^= 1;
            self.context.now_unix_ms += 1;
        }
        match mutation {
            Mutation::Control => {}
            Mutation::Record => self.context.active_head.record_digest[0] ^= 1,
            Mutation::SignerRevoked => self.context.signer_revoked = true,
            Mutation::AttesterRevoked => self.context.attester_revoked = true,
            Mutation::TimeBackwards => self.context.now_unix_ms -= 1,
            Mutation::SameHeightFork => self.context.current_anchor.block_hash[0] ^= 1,
            Mutation::Expired => {
                self.context.now_unix_ms = 1_800;
                self.context.anchor_observed_at_unix_ms = 1_800;
            }
            Mutation::ObservationTime { now, observed } => {
                self.context.now_unix_ms = now;
                self.context.anchor_observed_at_unix_ms = observed;
            }
            Mutation::LostReservation => self.reservation = None,
            Mutation::LostCompletion => self.completed = None,
        }
    }
    fn owns(&self, check: &SignerOperationReservationCheckV1<'_>) -> bool {
        self.reservation == Some((check.reservation(), check.request().intent_digest()))
            && self.audit == check.request().intent().previous_audit
            && self.context.now_unix_ms < check.reservation().expires_at_unix_ms
    }
}
struct Source {
    binding: SignerCustodyBindingV1,
    state: Mutex<SourceState>,
}
impl SignerOperationStateSourceV1 for Source {
    fn observe_signing_state(
        &self,
        binding: &SignerCustodyBindingV1,
    ) -> Result<SignerOperationSigningStateV1, SignerOperationErrorV1> {
        let mut state = self.state.lock().expect("test source lock");
        state.signing_reads += 1;
        if state.fail_observe || binding != &state.active_binding || !state.initially_enrolled {
            return Err(SignerOperationErrorV1::StateUnavailable);
        }
        let snapshot = SignerOperationSigningStateV1 {
            custody: state.context,
            audit_head: state.audit,
        };
        if state.advance_audit_after_signing_snapshot {
            state.audit.sequence += 1;
            state.audit.digest[0] ^= 1;
        }
        Ok(snapshot)
    }
    fn observe(
        &self,
        binding: &SignerCustodyBindingV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        let mut state = self.state.lock().expect("test source lock");
        if state.transition_commits > 0
            && let Some(mutation) = state.mutate_on_transition_observe.take()
        {
            state.mutate(mutation);
        }
        if state.fail_observe || binding != &state.active_binding || !state.initially_enrolled {
            return Err(SignerOperationErrorV1::StateUnavailable);
        }
        Ok(state.context)
    }
    fn reserve(
        &self,
        request: &SignerOperationReservationRequestV1<'_>,
    ) -> Result<SignerOperationReservationV1, SignerOperationErrorV1> {
        let mut state = self.state.lock().expect("test source lock");
        if state.reservation.is_some()
            || state.used_ids.contains(&request.intent().operation_id)
            || state.audit != request.intent().previous_audit
            || state.context.active_head.record_digest != request.custody().record_digest()
            || state.context.current_anchor.state_digest
                != request.custody().current_anchor().state_digest
        {
            return Err(SignerOperationErrorV1::ReservationConflict);
        }
        assert_eq!(
            request.intent_digest(),
            request.intent().digest().expect("canonical intent")
        );
        let reservation = state
            .reserve_override
            .unwrap_or(SignerOperationReservationV1 {
                reservation_id: [0x71; 32],
                fence: state.used_ids.len() as u64 + 1,
                expires_at_unix_ms: 1_800,
            });
        state.used_ids.insert(request.intent().operation_id);
        state.reservation = Some((reservation, request.intent_digest()));
        if let Some(mutation) = state.mutate_after_reserve.take() {
            state.mutate(mutation);
        }
        Ok(reservation)
    }
    fn reserve_stream_token(
        &self,
        _request: &SignerOperationReservationRequestV1<'_>,
        _review: &SignerStreamTokenReservationReviewV1<'_>,
    ) -> Result<SignerOperationReservationV1, SignerOperationErrorV1> {
        // This generic fixture has no body-bearing native role-11 source.
        Err(SignerOperationErrorV1::InvalidOperation)
    }
    fn observe_reserved(
        &self,
        check: &SignerOperationReservationCheckV1<'_>,
        phase: SignerReservedObservationPhaseV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        let mut state = self.state.lock().expect("test source lock");
        state.reserved_phases.push(phase);
        if state.fail_reserved_phase == Some(phase) {
            return Err(SignerOperationErrorV1::StateUnavailable);
        }
        state.reserved_reads += 1;
        if let Some((index, mutation)) = state.mutate_at_reserved
            && index == state.reserved_reads
        {
            state.mutate(mutation);
            state.mutate_at_reserved = None;
        }
        if state.fail_observe {
            return Err(SignerOperationErrorV1::StateUnavailable);
        }
        if !state.owns(check) {
            return Err(SignerOperationErrorV1::ReservationConflict);
        }
        Ok(state.context)
    }
    fn commit(
        &self,
        request: &SignerOperationCommitRequestV1<'_>,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        let mut state = self.state.lock().expect("test source lock");
        if state.fail_commit
            || !state.owns(request.check())
            || state.context.current_anchor.state_digest
                != request
                    .check()
                    .request()
                    .custody()
                    .current_anchor()
                    .state_digest
            || state.context.active_head.record_digest
                != request.check().request().custody().record_digest()
            || state.context.signer_revoked
            || state.context.attester_revoked
        {
            return Err(SignerOperationErrorV1::ReservationConflict);
        }
        assert_ne!(request.signatures_digest(), [0; 32]);
        if let Some(directory) = &state.expected_journal {
            let path = directory.join(format!(
                "{}.receipt.norito",
                hex::encode(request.check().request().intent().operation_id)
            ));
            let bytes = std::fs::read(path)
                .expect("receipt must be durably staged before authoritative commit");
            let (intent, original_custody, reservation, commitment, signatures) = if self
                .binding
                .role
                == SignerRoleV1::FinalPromotionProvenance
            {
                let receipt: sorafs_manifest::signer::final_promotion::SignerFinalPromotionReceiptV1 =
                        norito::decode_canonical(&bytes).expect("canonical staged final promotion receipt");
                (
                    receipt.intent,
                    receipt.request.original_custody,
                    receipt.reservation,
                    receipt.commitment,
                    receipt.signatures,
                )
            } else {
                let receipt: sorafs_manifest::signer::receipt::SignerReleaseManifestReceiptV1 =
                    norito::decode_canonical(&bytes).expect("canonical staged release receipt");
                (
                    receipt.intent,
                    receipt.request.original_custody,
                    receipt.reservation,
                    receipt.commitment,
                    receipt.signatures,
                )
            };
            assert_eq!(
                intent.digest().unwrap(),
                request.check().request().intent_digest()
            );
            assert_eq!(original_custody, request.original_custody());
            assert_eq!(reservation, request.check().reservation());
            assert_eq!(commitment, request.commitment());
            assert_eq!(
                sorafs_manifest::signer::protocol::signer_operation_signatures_digest_v1(
                    &signatures
                )
                .unwrap(),
                request.signatures_digest()
            );
            state.journal_checked += 1;
        }
        state.completed = Some((
            request.check().reservation(),
            request.check().request().intent_digest(),
            request.commitment(),
            request.signatures_digest(),
            request.original_custody(),
        ));
        state.audit = request.commitment().audit;
        state.reservation = None;
        state.commits += 1;
        #[cfg(unix)]
        if state.mutate_journal_after_commit {
            use std::os::unix::fs::PermissionsExt as _;
            let path = state.expected_journal.as_ref().unwrap().join(format!(
                "{}.receipt.norito",
                hex::encode(request.check().request().intent().operation_id)
            ));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::write(path, b"substituted pending receipt").unwrap();
        }
        if let Some(mutation) = state.mutate_after_commit.take() {
            state.mutate(mutation);
        }
        Ok(state.context)
    }
    fn observe_committed(
        &self,
        request: &SignerOperationCommitRequestV1<'_>,
        phase: SignerCommittedObservationPhaseV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        let mut state = self.state.lock().expect("test source lock");
        state.completed_phases.push(phase);
        if state.fail_completed_phase == Some(phase) {
            return Err(SignerOperationErrorV1::StateUnavailable);
        }
        if let Some((expected, mutation)) = state.mutate_at_completed
            && phase == expected
        {
            state.mutate(mutation);
            state.mutate_at_completed = None;
        }
        if phase == SignerCommittedObservationPhaseV1::BeforeRelease {
            #[cfg(unix)]
            if state.mutate_journal_at_release {
                use std::os::unix::fs::PermissionsExt as _;
                let path = state.expected_journal.as_ref().unwrap().join(format!(
                    "{}.receipt.norito",
                    hex::encode(request.check().request().intent().operation_id)
                ));
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
                std::fs::write(path, b"journal changed during final completion observation")
                    .unwrap();
            }
            if let Some(mutation) = state.mutate_at_release.take() {
                state.mutate(mutation);
            }
        }
        if state.fail_observe {
            return Err(SignerOperationErrorV1::StateUnavailable);
        }
        if state.completed
            != Some((
                request.check().reservation(),
                request.check().request().intent_digest(),
                request.commitment(),
                request.signatures_digest(),
                request.original_custody(),
            ))
        {
            return Err(SignerOperationErrorV1::ReservationConflict);
        }
        Ok(state.context)
    }
}
impl super::control::SignerCustodyEnrollmentStateSourceV1 for Source {
    fn observe_enrollment(
        &self,
        binding: &SignerCustodyBindingV1,
    ) -> Result<SignerCustodyEnrollmentContextV1, SignerOperationErrorV1> {
        let state = self.state.lock().expect("test source lock");
        match &state.enrollment {
            Some((expected, context)) if expected == binding => Ok(*context),
            _ => Err(SignerOperationErrorV1::StateUnavailable),
        }
    }
    fn enroll_initial(
        &self,
        request: &super::control::SignerCustodyEnrollmentRequestV1<'_>,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        let mut state = self.state.lock().expect("test source lock");
        if state.initially_enrolled
            || state.fail_transition
            || request.enrollment().statement().sequence != 1
            || request.enrollment().statement().predecessor_digest != [0; 32]
        {
            return Err(SignerOperationErrorV1::ReservationConflict);
        }
        control::apply_enrollment(&mut state, request)?;
        state.transition_commits += 1;
        Ok(state.context)
    }
}
impl super::control::SignerCustodyControlStateSourceV1 for Source {
    fn commit_custody_transition(
        &self,
        request: &super::control::SignerCustodyTransitionRequestV1<'_>,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        let mut state = self.state.lock().expect("test source lock");
        if state.fail_transition
            || !state.owns(request.check())
            || state.context.signer_revoked
            || state.context.attester_revoked
            || state.context.current_anchor.state_digest
                != request
                    .check()
                    .request()
                    .custody()
                    .current_anchor()
                    .state_digest
            || state.context.active_head.record_digest
                != request.check().request().custody().record_digest()
            || request.audit().sequence != state.audit.sequence + 1
        {
            return Err(SignerOperationErrorV1::ReservationConflict);
        }
        // Validate on a transaction-local copy; a failed CAS cannot partially advance the journal.
        let mut updated = state.clone();
        updated.audit = request.audit();
        match (
            request.check().request().intent().action,
            request.activation(),
        ) {
            (SignerOperationActionV1::ActivateCustody, Some(activation)) => {
                if activation.enrollment().record_digest() != request.transition_digest() {
                    return Err(SignerOperationErrorV1::ReservationConflict);
                }
                control::apply_enrollment(&mut updated, activation)?;
            }
            (SignerOperationActionV1::RevokeCustody, None) => {
                updated.mutate(Mutation::SignerRevoked)
            }
            _ => return Err(SignerOperationErrorV1::InvalidOperation),
        }
        updated.transition_commits += 1;
        updated.reservation = None;
        *state = updated;
        Ok(state.context)
    }
}
#[derive(Clone, Copy)]
enum ProviderFault {
    Mutate(Mutation),
    WrongKey,
    WrongMessage,
    Unavailable,
    AdvanceFinality,
}
struct Provider {
    key: KeyPair,
    source: Arc<Source>,
    fault: Mutex<Option<ProviderFault>>,
    calls: AtomicUsize,
}
impl SignerKeyOperationProviderV1 for Provider {
    fn sign(
        &self,
        request: &SignerKeyOperationRequestV1<'_>,
    ) -> Result<Signature, SignerOperationErrorV1> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        assert_eq!(
            request.check().request().custody().statement().binding,
            self.source.binding
        );
        assert_ne!(request.check().reservation().fence, 0);
        assert_ne!(request.ordinal(), 0);
        assert!(!format!("{request:?}").contains("sensitive-operation-payload"));
        match self.fault.lock().expect("test provider lock").take() {
            Some(ProviderFault::Unavailable) => {
                return Err(SignerOperationErrorV1::ProviderUnavailable);
            }
            Some(ProviderFault::WrongKey) => {
                return Ok(Signature::try_new(key(99).private_key(), request.message())
                    .expect("test wrong-key signature"));
            }
            Some(ProviderFault::WrongMessage) => {
                return Ok(Signature::try_new(self.key.private_key(), b"substituted")
                    .expect("test wrong-message signature"));
            }
            Some(ProviderFault::Mutate(mutation)) => self
                .source
                .state
                .lock()
                .expect("test source lock")
                .mutate(mutation),
            Some(ProviderFault::AdvanceFinality) => {
                let mut state = self.source.state.lock().expect("test source lock");
                state.context.now_unix_ms += 1;
                state.context.current_anchor.height += 1;
                state.context.current_anchor.block_hash[0] ^= 1;
            }
            None => {}
        }
        Signature::try_new(self.key.private_key(), request.message())
            .map_err(|_| SignerOperationErrorV1::ProviderUnavailable)
    }
}
struct Fixture {
    coordinator: SignerOperationCoordinatorV1,
    source: Arc<Source>,
    provider: Arc<Provider>,
}
fn key(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("test key")
}
fn fixture() -> Fixture {
    fixture_for(
        SignerRoleV1::Promotion,
        SignerPurposeBindingV1::NativeOrPromotion,
    )
}
fn fixture_for(role: SignerRoleV1, purpose: SignerPurposeBindingV1) -> Fixture {
    let signer = key(0x21);
    let attester = key(0x31);
    let binding = SignerCustodyBindingV1 {
        chain_id: "sorafs-reference".parse().expect("chain"),
        network_id: [0x11; 32],
        runtime_handle: "software://sorafs/final-promotion-provenance/primary".into(),
        key_handle: "software://sorafs/final-promotion-provenance/key-7".into(),
        service_id: "promotion-primary".into(),
        administrator_id: "promotion-security-primary".into(),
        role,
        purpose,
        algorithm: SignerKeyAlgorithmV1::Ed25519,
        public_key: signer.public_key().clone(),
        key_revision: 7,
        policy_revision: 9,
        policy_digest: [0x51; 32],
    };
    let authority = SignerCustodyAuthorityV1 {
        service_id: "custody-authority-primary".into(),
        administrator_id: "custody-security-primary".into(),
        key_revision: 3,
        policy_revision: 5,
        policy_digest: [0x41; 32],
    };
    let anchor = SignerCustodyAnchorV1 {
        height: 90,
        block_hash: [0x43; 32],
        state_digest: [0x45; 32],
    };
    let statement = SignerCustodyStatementV1 {
        magic: SIGNER_CUSTODY_MAGIC_V1,
        version: SIGNER_CUSTODY_VERSION_V1,
        binding: binding.clone(),
        authority: authority.clone(),
        anchor,
        sequence: 1,
        predecessor_digest: [0; 32],
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        evidence_digest: [0x55; 32],
        revoked: false,
    };
    let trust = SignerCustodyTrustV1 {
        authority,
        public_key: attester.public_key().clone(),
        active_from_unix_ms: 900,
        active_until_unix_ms: 3_000,
        max_validity_ms: 1_000,
        max_anchor_age_ms: 100,
    };
    let attestation = Signature::try_new(
        attester.private_key(),
        &statement.signing_payload().expect("statement payload"),
    )
    .expect("test independent attestation");
    let bytes = norito::encode_canonical(&SignerCustodyRecordV1 {
        statement,
        attestation: attestation.payload().try_into().expect("Ed25519"),
    })
    .expect("custody record");
    let enrollment = verify_signer_custody_enrollment_v1(
        &bytes,
        &binding,
        &trust,
        &SignerCustodyEnrollmentContextV1 {
            now_unix_ms: 1_500,
            anchor_observed_at_unix_ms: 1_450,
            current_anchor: anchor,
            next_sequence: 1,
            predecessor_digest: [0; 32],
            signer_revoked: false,
            attester_revoked: false,
        },
    )
    .expect("test enrollment");
    let context = SignerCustodyUseContextV1 {
        now_unix_ms: 1_500,
        anchor_observed_at_unix_ms: 1_450,
        current_anchor: SignerCustodyAnchorV1 {
            height: 91,
            block_hash: [0x81; 32],
            state_digest: [0x83; 32],
        },
        active_head: SignerCustodyActiveHeadV1 {
            record_digest: enrollment.record_digest(),
            sequence: 1,
            approved_anchor: anchor,
            key_revision: binding.key_revision,
            policy_revision: binding.policy_revision,
            policy_digest: binding.policy_digest,
        },
        signer_revoked: false,
        attester_revoked: false,
    };
    let source = Arc::new(Source {
        binding: binding.clone(),
        state: Mutex::new(SourceState {
            active_binding: binding.clone(),
            enrollment: None,
            initially_enrolled: true,
            fail_transition: false,
            transition_commits: 0,
            mutate_on_transition_observe: None,
            context,
            audit: intent(SignerOperationActionV1::Sign).previous_audit,
            reservation: None,
            used_ids: BTreeSet::new(),
            completed: None,
            reserve_override: None,
            mutate_after_reserve: None,
            mutate_at_reserved: None,
            mutate_after_commit: None,
            mutate_at_completed: None,
            mutate_at_release: None,
            fail_observe: false,
            signing_reads: 0,
            advance_audit_after_signing_snapshot: false,
            fail_commit: false,
            expected_journal: None,
            journal_checked: 0,
            mutate_journal_after_commit: false,
            mutate_journal_at_release: false,
            reserved_reads: 0,
            commits: 0,
            reserved_phases: Vec::new(),
            completed_phases: Vec::new(),
            fail_reserved_phase: None,
            fail_completed_phase: None,
        }),
    });
    let provider = Arc::new(Provider {
        key: signer,
        source: Arc::clone(&source),
        fault: Mutex::new(None),
        calls: AtomicUsize::new(0),
    });
    let coordinator =
        SignerOperationCoordinatorV1::new(binding, bytes, trust, provider.clone(), source.clone())
            .expect("qualified coordinator");
    Fixture {
        coordinator,
        source,
        provider,
    }
}
fn intent(action: SignerOperationActionV1) -> SignerOperationIntentV1 {
    SignerOperationIntentV1 {
        action,
        operation_id: [0x61; 32],
        request_digest: [0x63; 32],
        previous_audit: SignerOperationAuditHeadV1 {
            sequence: 3,
            digest: [0x65; 32],
        },
    }
}
fn commitment() -> SignerOperationCommitmentV1 {
    SignerOperationCommitmentV1 {
        audit: SignerOperationAuditHeadV1 {
            sequence: 4,
            digest: [0x67; 32],
        },
        response_digest: [0x69; 32],
    }
}
fn stage(operation: &mut SignerOperationV1<'_>) {
    for purpose in required_purposes(operation.intent.action) {
        let message = match purpose {
            SignerKeyOperationPurposeV1::AuditRecord => {
                commitment().audit.signing_message().to_vec()
            }
            SignerKeyOperationPurposeV1::Response => {
                commitment().response_signing_message().to_vec()
            }
            SignerKeyOperationPurposeV1::Provenance => vec![0x73; 32],
            _ => b"sensitive-operation-payload".to_vec(),
        };
        operation
            .sign(*purpose, &message)
            .expect("stage exact message");
    }
}
#[test]
fn complete_action_requires_durable_commit_and_releases_exact_ordered_signatures() {
    for action in [
        SignerOperationActionV1::Sign,
        SignerOperationActionV1::Qualify,
        SignerOperationActionV1::Status,
    ] {
        let fixture = fixture();
        let mut operation = fixture.coordinator.begin(intent(action)).expect("reserve");
        stage(&mut operation);
        assert_eq!(fixture.source.state.lock().expect("lock").commits, 0);
        let completed = operation.finish(commitment()).expect("durable completion");
        assert_eq!(completed.commitment(), commitment());
        assert_eq!(
            completed.intent_digest(),
            intent(action).digest().expect("digest")
        );
        assert_ne!(completed.signatures_digest(), [0; 32]);
        assert_eq!(completed.reservation().fence, 1);
        assert_eq!(
            completed.custody().statement().binding,
            fixture.source.binding
        );
        assert_eq!(
            completed
                .signature(SignerKeyOperationPurposeV1::RolePayload)
                .is_some(),
            action == SignerOperationActionV1::Sign
        );
        let signature = Signature::try_from_bytes(
            completed
                .signature(SignerKeyOperationPurposeV1::Response)
                .expect("completed response"),
        )
        .expect("signature");
        signature
            .verify(
                &fixture.source.binding.public_key,
                &commitment().response_signing_message(),
            )
            .expect("exact response");
        let state = fixture.source.state.lock().expect("lock");
        assert_eq!(state.commits, 1);
        assert_eq!(state.audit, commitment().audit);
        assert!(state.reservation.is_none());
        assert!(!format!("{completed:?}").contains("promotion-primary"));
    }
}
#[test]
fn exact_message_provider_failure_or_signature_substitution_permanently_poison_operation() {
    for (fault, expected) in [
        (
            ProviderFault::WrongKey,
            SignerOperationErrorV1::InvalidSignature,
        ),
        (
            ProviderFault::WrongMessage,
            SignerOperationErrorV1::InvalidSignature,
        ),
        (
            ProviderFault::Unavailable,
            SignerOperationErrorV1::ProviderUnavailable,
        ),
    ] {
        let fixture = fixture();
        let mut operation = fixture
            .coordinator
            .begin(intent(SignerOperationActionV1::Sign))
            .expect("reserve");
        *fixture.provider.fault.lock().expect("lock") = Some(fault);
        assert_eq!(
            operation
                .sign(SignerKeyOperationPurposeV1::RolePayload, b"payload")
                .expect_err("reject provider"),
            expected
        );
        assert_eq!(
            operation
                .sign(SignerKeyOperationPurposeV1::RolePayload, b"payload")
                .expect_err("no retry"),
            SignerOperationErrorV1::Poisoned
        );
        assert_eq!(
            operation.finish(commitment()).expect_err("no release"),
            SignerOperationErrorV1::Poisoned
        );
        assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.source.state.lock().expect("lock").commits, 0);
    }
}
#[test]
fn provider_io_cannot_release_after_rotation_revocation_control_fork_or_lost_fence() {
    for mutation in [
        Mutation::Control,
        Mutation::Record,
        Mutation::SignerRevoked,
        Mutation::AttesterRevoked,
        Mutation::TimeBackwards,
        Mutation::SameHeightFork,
        Mutation::Expired,
        Mutation::LostReservation,
    ] {
        let fixture = fixture();
        let mut operation = fixture
            .coordinator
            .begin(intent(SignerOperationActionV1::Sign))
            .expect("reserve");
        *fixture.provider.fault.lock().expect("lock") = Some(ProviderFault::Mutate(mutation));
        assert!(
            operation
                .sign(SignerKeyOperationPurposeV1::RolePayload, b"payload")
                .is_err()
        );
        assert_eq!(
            operation.finish(commitment()).expect_err("no release"),
            SignerOperationErrorV1::Poisoned
        );
        assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.source.state.lock().expect("lock").commits, 0);
    }
}
#[test]
fn later_finality_with_unchanged_custody_allows_operation_journal_to_advance() {
    let fixture = fixture();
    let mut operation = fixture
        .coordinator
        .begin(intent(SignerOperationActionV1::Sign))
        .expect("reserve");
    *fixture.provider.fault.lock().expect("lock") = Some(ProviderFault::AdvanceFinality);
    stage(&mut operation);
    let completed = operation
        .finish(commitment())
        .expect("same active custody at later finalized block");
    assert_eq!(completed.custody().current_anchor().height, 92);
    assert_eq!(completed.custody().verified_at_unix_ms(), 1_501);
    assert_eq!(completed.commitment().audit.sequence, 4);
}
#[test]
fn reservation_cas_and_pre_io_revalidation_fence_drift_before_calling_provider() {
    for after_reserve in [true, false] {
        let fixture = fixture();
        if after_reserve {
            fixture
                .source
                .state
                .lock()
                .expect("lock")
                .mutate_after_reserve = Some(Mutation::Control);
            assert!(
                fixture
                    .coordinator
                    .begin(intent(SignerOperationActionV1::Sign))
                    .is_err()
            );
        } else {
            let mut operation = fixture
                .coordinator
                .begin(intent(SignerOperationActionV1::Sign))
                .expect("reserve");
            fixture
                .source
                .state
                .lock()
                .expect("lock")
                .mutate_at_reserved = Some((2, Mutation::SignerRevoked));
            assert!(
                operation
                    .sign(SignerKeyOperationPurposeV1::RolePayload, b"payload")
                    .is_err()
            );
        }
        assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.source.state.lock().expect("lock").commits, 0);
    }
}
#[test]
fn abandoned_and_completed_ids_and_conflicting_journal_predecessors_are_not_re_reserved() {
    let fixture = fixture();
    let mut wrong = intent(SignerOperationActionV1::Sign);
    wrong.previous_audit.digest[0] ^= 1;
    assert!(matches!(
        fixture.coordinator.begin(wrong),
        Err(SignerOperationErrorV1::ReservationConflict)
    ));
    let operation = fixture
        .coordinator
        .begin(intent(SignerOperationActionV1::Sign))
        .expect("reserve");
    assert!(matches!(
        fixture
            .coordinator
            .begin(intent(SignerOperationActionV1::Sign)),
        Err(SignerOperationErrorV1::ReservationConflict)
    ));
    drop(operation);
    assert!(matches!(
        fixture
            .coordinator
            .begin(intent(SignerOperationActionV1::Sign)),
        Err(SignerOperationErrorV1::ReservationConflict)
    ));
    // Model explicit operator recovery retaining the durable replay tombstone.
    fixture.source.state.lock().expect("lock").reservation = None;
    assert!(matches!(
        fixture
            .coordinator
            .begin(intent(SignerOperationActionV1::Sign)),
        Err(SignerOperationErrorV1::ReservationConflict)
    ));
    let fixture = self::fixture();
    let mut operation = fixture
        .coordinator
        .begin(intent(SignerOperationActionV1::Sign))
        .expect("reserve");
    stage(&mut operation);
    operation.finish(commitment()).expect("commit");
    let mut replay = intent(SignerOperationActionV1::Sign);
    replay.previous_audit = commitment().audit;
    assert!(matches!(
        fixture.coordinator.begin(replay),
        Err(SignerOperationErrorV1::ReservationConflict)
    ));
}
#[test]
fn invalid_action_inputs_and_reservation_bounds_fail_before_provider_io() {
    let invalid_intents: &[fn(&mut SignerOperationIntentV1)] = &[
        |intent| intent.operation_id = [0; 32],
        |intent| intent.request_digest = [0; 32],
        |intent| intent.previous_audit.sequence = 0,
        |intent| intent.previous_audit.sequence = u64::MAX,
        |intent| intent.previous_audit.digest = [0; 32],
    ];
    for mutate in invalid_intents {
        let fixture = fixture();
        let mut value = intent(SignerOperationActionV1::Sign);
        mutate(&mut value);
        assert!(matches!(
            fixture.coordinator.begin(value),
            Err(SignerOperationErrorV1::InvalidOperation)
        ));
        assert!(
            fixture
                .source
                .state
                .lock()
                .expect("lock")
                .used_ids
                .is_empty()
        );
        assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 0);
    }
    let invalid_reservations: &[fn(&mut SignerOperationReservationV1)] = &[
        |reservation| reservation.reservation_id = [0; 32],
        |reservation| reservation.fence = 0,
        |reservation| reservation.expires_at_unix_ms = 1_500,
        |reservation| reservation.expires_at_unix_ms = 2_001,
        |reservation| reservation.expires_at_unix_ms = u64::MAX,
    ];
    for mutate in invalid_reservations {
        let fixture = fixture();
        let mut value = SignerOperationReservationV1 {
            reservation_id: [0x71; 32],
            fence: 1,
            expires_at_unix_ms: 1_800,
        };
        mutate(&mut value);
        fixture.source.state.lock().expect("lock").reserve_override = Some(value);
        assert!(matches!(
            fixture
                .coordinator
                .begin(intent(SignerOperationActionV1::Sign)),
            Err(SignerOperationErrorV1::ReservationConflict)
        ));
        assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn message_bounds_duplicate_purposes_and_out_of_order_signatures_fail_closed() {
    for (purpose, message) in [
        (SignerKeyOperationPurposeV1::Response, vec![1]),
        (SignerKeyOperationPurposeV1::RolePayload, vec![]),
        (
            SignerKeyOperationPurposeV1::RolePayload,
            vec![1; SIGNER_MAX_REQUEST_PAYLOAD_BYTES_V1 + 1],
        ),
    ] {
        let fixture = fixture();
        let mut operation = fixture
            .coordinator
            .begin(intent(SignerOperationActionV1::Sign))
            .expect("reserve");
        assert_eq!(
            operation
                .sign(purpose, &message)
                .expect_err("invalid signing request"),
            SignerOperationErrorV1::InvalidOperation
        );
        assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            operation.finish(commitment()).expect_err("cannot finish"),
            SignerOperationErrorV1::Poisoned
        );
    }
    let fixture = fixture();
    let mut operation = fixture
        .coordinator
        .begin(intent(SignerOperationActionV1::Sign))
        .expect("reserve");
    operation
        .sign(SignerKeyOperationPurposeV1::RolePayload, b"payload")
        .expect("first");
    assert_eq!(
        operation
            .sign(SignerKeyOperationPurposeV1::RolePayload, b"payload")
            .expect_err("duplicate"),
        SignerOperationErrorV1::InvalidOperation
    );
    assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 1);
}
#[test]
fn incomplete_or_substituted_commitments_never_reach_completion_cas() {
    let mutations: &[fn(&mut SignerOperationCommitmentV1)] = &[
        |commitment| commitment.audit.sequence -= 1,
        |commitment| commitment.audit.sequence += 1,
        |commitment| commitment.audit.digest = [0; 32],
        |commitment| commitment.audit.digest = [0x65; 32],
        |commitment| commitment.audit.digest[0] ^= 1,
        |commitment| commitment.response_digest = [0; 32],
        |commitment| commitment.response_digest[0] ^= 1,
    ];
    for mutate in mutations {
        let fixture = fixture();
        let mut operation = fixture
            .coordinator
            .begin(intent(SignerOperationActionV1::Sign))
            .expect("reserve");
        stage(&mut operation);
        let mut value = commitment();
        mutate(&mut value);
        assert_eq!(
            operation.finish(value).expect_err("substituted successor"),
            SignerOperationErrorV1::InvalidOperation
        );
        assert_eq!(fixture.source.state.lock().expect("lock").commits, 0);
    }
    let fixture = fixture();
    let operation = fixture
        .coordinator
        .begin(intent(SignerOperationActionV1::Sign))
        .expect("reserve");
    assert_eq!(
        operation.finish(commitment()).expect_err("incomplete"),
        SignerOperationErrorV1::InvalidOperation
    );
}
#[test]
fn commit_failure_and_post_commit_or_release_revocation_cannot_release_signatures() {
    for phase in 0..4 {
        let fixture = fixture();
        let mut operation = fixture
            .coordinator
            .begin(intent(SignerOperationActionV1::Sign))
            .expect("reserve");
        stage(&mut operation);
        {
            let mut state = fixture.source.state.lock().expect("lock");
            match phase {
                0 => state.fail_commit = true,
                1 => state.mutate_after_commit = Some(Mutation::SignerRevoked),
                2 => state.mutate_at_release = Some(Mutation::Control),
                _ => {
                    state.mutate_at_release = Some(Mutation::ObservationTime {
                        now: 2_000,
                        observed: 2_000,
                    });
                }
            }
        }
        assert!(operation.finish(commitment()).is_err());
        if phase >= 2 {
            assert_eq!(
                fixture.source.state.lock().expect("lock").completed_phases,
                [
                    SignerCommittedObservationPhaseV1::AfterCommit,
                    SignerCommittedObservationPhaseV1::BeforeRelease
                ],
                "release mutations must occur only after the earlier completion read succeeds"
            );
        }
        assert_eq!(
            fixture.source.state.lock().expect("lock").commits,
            usize::from(phase != 0)
        );
        assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 4);
    }
}
#[test]
fn unavailable_current_state_and_wrong_expected_custody_prevent_provider_use() {
    let fixture = fixture();
    fixture.source.state.lock().expect("lock").fail_observe = true;
    assert!(matches!(
        fixture
            .coordinator
            .begin(intent(SignerOperationActionV1::Sign)),
        Err(SignerOperationErrorV1::StateUnavailable)
    ));
    assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 0);
    let fixture = self::fixture();
    let mut binding = fixture.coordinator.binding.clone();
    binding.key_revision += 1;
    assert!(
        SignerOperationCoordinatorV1::new(
            binding,
            fixture.coordinator.record.clone(),
            fixture.coordinator.trust.clone(),
            fixture.provider.clone(),
            fixture.source.clone()
        )
        .is_err()
    );
    assert_eq!(fixture.provider.calls.load(Ordering::Relaxed), 0);
}
#[test]
fn canonical_commitment_messages_and_intent_are_deterministic_and_purpose_separated() {
    let first = intent(SignerOperationActionV1::Sign);
    let bytes = norito::encode_canonical(&first).expect("intent");
    let decoded: SignerOperationIntentV1 =
        norito::decode_canonical(&bytes).expect("canonical intent");
    assert_eq!(first.digest(), decoded.digest());
    assert_ne!(
        first.digest(),
        intent(SignerOperationActionV1::Qualify).digest()
    );
    assert_ne!(
        commitment().audit.signing_message(),
        commitment().response_signing_message()
    );
    let mut changed = commitment();
    changed.audit.sequence += 1;
    assert_ne!(
        commitment().audit.signing_message(),
        changed.audit.signing_message()
    );
    changed.response_digest[0] ^= 1;
    assert_ne!(
        commitment().response_signing_message(),
        changed.response_signing_message()
    );
    assert!(!format!("{:?}", fixture().coordinator).contains("pkcs11"));
    assert!(!format!("{first:?}").contains("63636363"));
}

mod observation_phases;
