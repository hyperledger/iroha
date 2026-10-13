//! Simulated independent custody/source/provider fixtures; never hardware qualification evidence.

use super::*;
use iroha_data_model::sorafs::stream_token_authority::StreamTokenReviewedV1;
use sorafs_manifest::signer::stream_token::SignerStreamTokenRequestV1;
use sorafs_manifest::signer::stream_token::validate_stream_token_signatures_v1;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::Condvar,
    time::{Duration, Instant},
};

pub(super) struct SnapshotGate {
    arrivals: Mutex<usize>,
    ready: Condvar,
}

impl SnapshotGate {
    pub fn new() -> Self {
        Self {
            arrivals: Mutex::new(0),
            ready: Condvar::new(),
        }
    }

    fn arrive(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut arrivals = self.arrivals.lock().unwrap();
        *arrivals += 1;
        assert!(
            *arrivals <= 2,
            "only two exact signing snapshots may reach this gate"
        );
        if *arrivals == 2 {
            self.ready.notify_all();
        }
        while *arrivals != 2 {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("both signing snapshots must arrive within five seconds");
            let (next, timeout) = self.ready.wait_timeout(arrivals, remaining).unwrap();
            arrivals = next;
            assert!(
                !timeout.timed_out() || *arrivals == 2,
                "second signing snapshot did not arrive"
            );
        }
    }
}

type Completion = (
    SignerOperationReservationV1,
    [u8; 32],
    SignerOperationCommitmentV1,
    [u8; 32],
    SignerOperationCustodyV1,
);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Reads {
    pub current: usize,
    pub signing: usize,
    pub reserves: usize,
    pub commits: usize,
    pub completed: usize,
}

pub(super) struct StreamSource {
    pub base: Arc<Source>,
    pub directory: PathBuf,
    pub record: Vec<u8>,
    pub trust: SignerCustodyTrustV1,
    pub reads: Mutex<Reads>,
    pub last_reserved_review: Mutex<Option<StreamTokenReviewedV1>>,
    pub history: Mutex<BTreeMap<[u8; 32], Completion>>,
    commit_transaction: Mutex<()>,
    bodies: Mutex<BTreeMap<[u8; 32], StreamTokenBodyV1>>,
    pub snapshot_gate: Mutex<Option<Arc<SnapshotGate>>>,
    pub advance_head_after_snapshot: Mutex<bool>,
    pub substitute_after_commit: Mutex<bool>,
    pub staged_checked: AtomicUsize,
}

impl StreamSource {
    pub fn register(&self, body: &StreamTokenBodyV1) -> SignerStreamTokenExpectedV1 {
        let expected = SignerStreamTokenExpectedV1::new(body, &self.base.binding).unwrap();
        self.bodies
            .lock()
            .unwrap()
            .insert(expected.operation_id(), body.clone());
        expected
    }

    pub fn counts(&self) -> Reads {
        *self.reads.lock().unwrap()
    }

    pub fn path(&self, operation_id: [u8; 32]) -> PathBuf {
        self.directory
            .join(format!("{}.receipt.norito", hex::encode(operation_id)))
    }

    fn check_staged(&self, request: &SignerOperationCommitRequestV1<'_>) {
        let bytes = fs::read(self.path(request.check().request().intent().operation_id))
            .expect("exact receipt is durably staged before authoritative commit");
        let receipt: SignerStreamTokenReceiptV1 = norito::decode_canonical(&bytes).unwrap();
        assert_eq!(receipt.encode_canonical().unwrap(), bytes);
        assert_eq!(receipt.custody_record, self.record);
        assert_eq!(
            receipt.intent.digest().unwrap(),
            request.check().request().intent_digest()
        );
        assert_eq!(receipt.request.original_custody, request.original_custody());
        assert_eq!(receipt.reservation, request.check().reservation());
        assert_eq!(receipt.commitment, request.commitment());
        assert_eq!(
            signer_operation_signatures_digest_v1(&receipt.signatures).unwrap(),
            request.signatures_digest()
        );
        let body = self.bodies.lock().unwrap()[&receipt.intent.operation_id].clone();
        let expected = SignerStreamTokenExpectedV1::new(&body, &self.base.binding).unwrap();
        let token = StreamTokenV1 {
            body,
            signature: receipt.signatures[0].signature.clone(),
        };
        let current = self.base.state.lock().unwrap().context;
        let custody =
            verify_signer_custody_use_v1(&self.record, &self.base.binding, &self.trust, &current)
                .unwrap();
        validate_stream_token_signatures_v1(&receipt, &token, &expected, &custody)
            .expect("actual token and all four ordered signatures validate before CAS");
        assert_eq!(
            receipt
                .signatures
                .iter()
                .map(|part| part.purpose)
                .collect::<Vec<_>>(),
            vec![
                SignerKeyOperationPurposeV1::RolePayload,
                SignerKeyOperationPurposeV1::AuditRecord,
                SignerKeyOperationPurposeV1::Provenance,
                SignerKeyOperationPurposeV1::Response,
            ]
        );
        assert_eq!(
            fs::metadata(self.path(receipt.intent.operation_id))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        self.staged_checked.fetch_add(1, Ordering::SeqCst);
    }
}

// Deliberately signing-only: production-style receipt tests must not require an enrollment or
// terminal-control implementation. Renewal fixtures request that capability from `base` explicitly.
impl SignerOperationStateSourceV1 for StreamSource {
    fn observe(
        &self,
        binding: &SignerCustodyBindingV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        self.reads.lock().unwrap().current += 1;
        self.base.observe(binding)
    }

    fn observe_signing_state(
        &self,
        binding: &SignerCustodyBindingV1,
    ) -> Result<SignerOperationSigningStateV1, SignerOperationErrorV1> {
        self.reads.lock().unwrap().signing += 1;
        let snapshot = {
            let mut state = self.base.state.lock().unwrap();
            if state.fail_observe || binding != &state.active_binding || !state.initially_enrolled {
                return Err(SignerOperationErrorV1::StateUnavailable);
            }
            // Both coordinates come from one independently owned authenticated snapshot.
            let snapshot = SignerOperationSigningStateV1 {
                custody: state.context,
                audit_head: state.audit,
            };
            if std::mem::take(&mut *self.advance_head_after_snapshot.lock().unwrap()) {
                state.audit.sequence += 1;
                state.audit.digest[0] ^= 1;
            }
            snapshot
        };
        let gate = self.snapshot_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.arrive();
        }
        Ok(snapshot)
    }

    fn reserve(
        &self,
        request: &SignerOperationReservationRequestV1<'_>,
    ) -> Result<SignerOperationReservationV1, SignerOperationErrorV1> {
        self.reads.lock().unwrap().reserves += 1;
        self.base.reserve(request)
    }

    fn reserve_stream_token(
        &self,
        request: &SignerOperationReservationRequestV1<'_>,
        review: &SignerStreamTokenReservationReviewV1<'_>,
    ) -> Result<SignerOperationReservationV1, SignerOperationErrorV1> {
        let body_bytes = review
            .signing_payload()
            .strip_prefix(sorafs_manifest::token::STREAM_TOKEN_SIGNATURE_DOMAIN_V1)
            .ok_or(SignerOperationErrorV1::InvalidOperation)?;
        norito::verify_exact_canonical_frame(review.body(), body_bytes)
            .map_err(|_| SignerOperationErrorV1::InvalidOperation)?;
        let expected = SignerStreamTokenExpectedV1::new(review.body(), &self.base.binding)
            .map_err(|_| SignerOperationErrorV1::InvalidOperation)?;
        let exact = SignerStreamTokenRequestV1::new(request.custody(), &expected, review.body())
            .map_err(|_| SignerOperationErrorV1::InvalidOperation)?;
        if review.reviewed().request != exact
            || review.reviewed().intent != *request.intent()
            || review.reviewed().intent.request_digest
                != exact
                    .digest()
                    .map_err(|_| SignerOperationErrorV1::InvalidOperation)?
        {
            return Err(SignerOperationErrorV1::InvalidOperation);
        }
        self.reads.lock().unwrap().reserves += 1;
        let reservation = self.base.reserve(request)?;
        *self.last_reserved_review.lock().unwrap() = Some(*review.reviewed());
        Ok(reservation)
    }

    fn observe_reserved(
        &self,
        check: &SignerOperationReservationCheckV1<'_>,
        phase: SignerReservedObservationPhaseV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        self.base.observe_reserved(check, phase)
    }

    fn commit(
        &self,
        request: &SignerOperationCommitRequestV1<'_>,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        // Keep the independently committed row and its historical copy one source transaction.
        // A later-head commit cannot replace the base fixture's single slot before this copy.
        let _transaction = self.commit_transaction.lock().unwrap();
        self.reads.lock().unwrap().commits += 1;
        self.check_staged(request);
        let current = self.base.commit(request)?;
        let completed = self.base.state.lock().unwrap().completed.unwrap();
        self.history
            .lock()
            .unwrap()
            .insert(request.check().request().intent().operation_id, completed);
        if *self.substitute_after_commit.lock().unwrap() {
            let path = self.path(request.check().request().intent().operation_id);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&path, b"substituted completed stream receipt").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        }
        Ok(current)
    }

    fn observe_committed(
        &self,
        request: &SignerOperationCommitRequestV1<'_>,
        phase: SignerCommittedObservationPhaseV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1> {
        self.reads.lock().unwrap().completed += 1;
        let mut state = self.base.state.lock().unwrap();
        state.completed_phases.push(phase);
        if state.fail_completed_phase == Some(phase) || state.fail_observe {
            return Err(SignerOperationErrorV1::StateUnavailable);
        }
        if phase == SignerCommittedObservationPhaseV1::BeforeRelease
            && let Some(mutation) = state.mutate_at_release.take()
        {
            state.mutate(mutation);
        }
        let exact = (
            request.check().reservation(),
            request.check().request().intent_digest(),
            request.commitment(),
            request.signatures_digest(),
            request.original_custody(),
        );
        // Historical immutable rows survive later commits; the live audit head is not the row.
        if self
            .history
            .lock()
            .unwrap()
            .get(&request.check().request().intent().operation_id)
            != Some(&exact)
        {
            return Err(SignerOperationErrorV1::ReservationConflict);
        }
        Ok(state.context)
    }
}

pub(super) struct Harness {
    _directory: tempfile::TempDir,
    pub service: Option<SignerStreamTokenServiceV1>,
    pub source: Arc<StreamSource>,
    pub provider: Arc<Provider>,
}

impl Harness {
    pub fn new() -> Self {
        Self::with_custody_expiry(2000)
    }

    pub fn with_custody_expiry(expires_at_unix_ms: u64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let directory_path = directory.path().canonicalize().unwrap();
        let mut fixture = fixture_for(
            SignerRoleV1::StreamToken,
            SignerPurposeBindingV1::StreamToken {
                provider_id: [0x62; 32],
            },
        );
        if expires_at_unix_ms != 2000 {
            let mut record: SignerCustodyRecordV1 =
                norito::decode_canonical(&fixture.coordinator.record).unwrap();
            record.statement.expires_at_unix_ms = expires_at_unix_ms;
            fixture.coordinator.trust.active_until_unix_ms = fixture
                .coordinator
                .trust
                .active_until_unix_ms
                .max(expires_at_unix_ms);
            fixture.coordinator.trust.max_validity_ms =
                expires_at_unix_ms - record.statement.issued_at_unix_ms;
            record.attestation = Signature::try_new(
                key(0x31).private_key(),
                &record.statement.signing_payload().unwrap(),
            )
            .unwrap()
            .payload()
            .try_into()
            .unwrap();
            fixture.coordinator.record = norito::encode_canonical(&record).unwrap();
            let enrollment = verify_signer_custody_enrollment_v1(
                &fixture.coordinator.record,
                &fixture.coordinator.binding,
                &fixture.coordinator.trust,
                &SignerCustodyEnrollmentContextV1 {
                    now_unix_ms: 1500,
                    anchor_observed_at_unix_ms: 1450,
                    current_anchor: record.statement.anchor,
                    next_sequence: 1,
                    predecessor_digest: [0; 32],
                    signer_revoked: false,
                    attester_revoked: false,
                },
            )
            .expect("independently attested longer-lived custody positive");
            fixture
                .source
                .state
                .lock()
                .unwrap()
                .context
                .active_head
                .record_digest = enrollment.record_digest();
        }
        assert!(
            fixture
                .source
                .state
                .lock()
                .unwrap()
                .expected_journal
                .is_none()
        );
        let source = Arc::new(StreamSource {
            base: fixture.source.clone(),
            directory: directory_path.clone(),
            record: fixture.coordinator.record.clone(),
            trust: fixture.coordinator.trust.clone(),
            reads: Mutex::new(Reads::default()),
            last_reserved_review: Mutex::new(None),
            history: Mutex::new(BTreeMap::new()),
            commit_transaction: Mutex::new(()),
            bodies: Mutex::new(BTreeMap::new()),
            snapshot_gate: Mutex::new(None),
            advance_head_after_snapshot: Mutex::new(false),
            substitute_after_commit: Mutex::new(false),
            staged_checked: AtomicUsize::new(0),
        });
        fixture.coordinator.source = source.clone();
        let service = SignerStreamTokenServiceV1::new(
            fixture.coordinator,
            SignerReceiptJournalV1::open_test(&directory_path, SignerReceiptPurposeV1::StreamToken)
                .unwrap(),
        )
        .unwrap();
        Self {
            _directory: directory,
            service: Some(service),
            source,
            provider: fixture.provider,
        }
    }

    pub fn service(&self) -> &SignerStreamTokenServiceV1 {
        self.service.as_ref().unwrap()
    }

    pub fn restart(&mut self) {
        self.restart_with_record(self.source.record.clone());
    }

    pub fn restart_with_record(&mut self, record: Vec<u8>) {
        drop(self.service.take());
        let coordinator = SignerOperationCoordinatorV1::new(
            self.source.base.binding.clone(),
            record,
            self.source.trust.clone(),
            self.provider.clone(),
            self.source.clone(),
        )
        .unwrap();
        self.service = Some(
            SignerStreamTokenServiceV1::new(
                coordinator,
                SignerReceiptJournalV1::open_test(
                    &self.source.directory,
                    SignerReceiptPurposeV1::StreamToken,
                )
                .unwrap(),
            )
            .unwrap(),
        );
    }

    pub fn sign(
        &self,
        body: &StreamTokenBodyV1,
    ) -> Result<SignerStreamTokenReceiptBytesV1, SignerStreamTokenErrorV1> {
        self.source.register(body);
        self.service().sign(&payload(body))
    }

    pub fn calls(&self) -> usize {
        self.provider.calls.load(Ordering::SeqCst)
    }

    pub fn renew_same_key(&self) -> (Vec<u8>, SignerOperationCustodyV1) {
        use super::super::super::control::signer_custody_transition_request_digest_v1;
        let binding = self.source.base.binding.clone();
        let coordinator = SignerOperationCoordinatorV1::new(
            binding.clone(),
            self.source.record.clone(),
            self.source.trust.clone(),
            self.provider.clone(),
            self.source.clone(),
        )
        .unwrap();
        let mut record: SignerCustodyRecordV1 =
            norito::decode_canonical(&self.source.record).unwrap();
        let (previous_audit, predecessor) = {
            let mut state = self.source.base.state.lock().unwrap();
            record.statement.sequence += 1;
            record.statement.predecessor_digest = state.context.active_head.record_digest;
            record.statement.anchor = state.context.current_anchor;
            state.enrollment = Some((
                binding.clone(),
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
            (state.audit, state.context.active_head.record_digest)
        };
        record.attestation = Signature::try_new(
            key(0x31).private_key(),
            &record.statement.signing_payload().unwrap(),
        )
        .unwrap()
        .payload()
        .try_into()
        .unwrap();
        let bytes = norito::encode_canonical(&record).unwrap();
        let prepared = coordinator
            .prepare_custody_activation(
                self.source.base.as_ref(),
                binding,
                bytes.clone(),
                self.source.trust.clone(),
            )
            .unwrap();
        let operation_id = [0x94; 32];
        let intent = SignerOperationIntentV1 {
            action: SignerOperationActionV1::ActivateCustody,
            operation_id,
            previous_audit,
            request_digest: signer_custody_transition_request_digest_v1(
                SignerOperationActionV1::ActivateCustody,
                operation_id,
                predecessor,
                previous_audit,
                prepared.record_digest(),
            )
            .unwrap(),
        };
        let mut transition = coordinator.begin(intent).unwrap();
        let audit = SignerOperationAuditHeadV1 {
            sequence: previous_audit.sequence + 1,
            digest: [0x95; 32],
        };
        transition
            .sign(
                SignerKeyOperationPurposeV1::AuditRecord,
                &audit.signing_message(),
            )
            .unwrap();
        let activated = transition
            .finish_custody_activation(self.source.base.as_ref(), &prepared, audit)
            .unwrap();
        let custody = SignerOperationCustodyV1::from_verified(activated.activation().unwrap());
        (bytes, custody)
    }
}

pub(super) fn body(id: u8) -> StreamTokenBodyV1 {
    StreamTokenBodyV1 {
        token_id: hex::encode([id; 16]),
        manifest_cid: vec![0x01, 0x55, 0x01],
        provider_id: [0x62; 32],
        profile_handle: "sorafs.sf1@1.0.0".into(),
        max_streams: 4,
        ttl_epoch: 2,
        rate_limit_bytes: 1024,
        issued_at: 1,
        requests_per_minute: 120,
        token_pk_version: 7,
    }
}

pub(super) fn payload(body: &StreamTokenBodyV1) -> Vec<u8> {
    let mut bytes = b"sorafs.stream-token.signature.v1\0".to_vec();
    bytes.extend(norito::encode_canonical(body).unwrap());
    bytes
}

pub(super) fn layouts() -> [u8; 2] {
    [0, norito::core::header_flags::COMPACT_LEN]
}
