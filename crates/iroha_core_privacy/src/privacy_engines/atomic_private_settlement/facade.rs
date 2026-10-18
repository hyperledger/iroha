//! Production-facing prover and verifier for one private settlement leg.

use super::{
    relation::{
        AtomicPrivateSettlementProverWitnessV1, AtomicPrivateSettlementRelationErrorV1,
        compile_witness_v1, validate_public_binding_v1,
    },
    stark::{
        prove_atomic_private_settlement_stark_v1_with_rng,
        verify_atomic_private_settlement_stark_v1,
        verify_constructed_atomic_private_settlement_stark_v1,
    },
};
#[cfg(test)]
use crate::privacy_engines::proof_phase_diagnostics::APS_PROOF_PHASE_TARGET_V1;
use crate::privacy_engines::{
    proof_managed_note_stark::ProofManagedNoteStarkErrorV1,
    proof_phase_diagnostics::{
        ProofPhaseInvocationV1, ProofPhaseV1, with_aps_candidate_phase_parent_v1,
    },
    prover_randomness::{HealthCheckedTryCryptoRngV1, TryCryptoProverRandomnessErrorV1},
};
use iroha_data_model::nexus::{
    AtomicPrivateSettlementV1, PrivateSettlementProofIntentV1, PrivateSettlementProofStatementV1,
};
use rand::{TryCryptoRng, rngs::OsRng};
use thiserror::Error;

/// Failure constructing or verifying one settlement-only private-note proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AtomicPrivateSettlementProofErrorV1 {
    /// Public or private relation material failed its fixed binding.
    #[error(transparent)]
    Relation(#[from] AtomicPrivateSettlementRelationErrorV1),
    /// The injected or operating-system cryptographic source failed.
    #[error("atomic private settlement prover entropy is unavailable")]
    RandomnessUnavailable,
    /// The cryptographic source emitted a catastrophic repeated pattern.
    #[error("atomic private settlement prover entropy failed its health check")]
    UnhealthyRandomness,
    /// A fixed proof or allocation bound was exceeded.
    #[error("atomic private settlement proof resource bound is exceeded")]
    ResourceLimit,
    /// Supplied proof bytes are malformed or invalid for the public bundle and leg.
    #[error("atomic private settlement proof verification failed")]
    InvalidProof,
    /// The fixed prover profile is internally inconsistent.
    #[error("atomic private settlement prover invariant failed")]
    ProverInvariant,
    /// The independent final verifier rejected bytes emitted by the prover.
    #[error("atomic private settlement prover self-verification failed")]
    SelfVerification,
}

fn map_entropy_error_v1(
    error: TryCryptoProverRandomnessErrorV1,
) -> AtomicPrivateSettlementProofErrorV1 {
    match error {
        TryCryptoProverRandomnessErrorV1::Unavailable => {
            AtomicPrivateSettlementProofErrorV1::RandomnessUnavailable
        }
        TryCryptoProverRandomnessErrorV1::Unhealthy => {
            AtomicPrivateSettlementProofErrorV1::UnhealthyRandomness
        }
    }
}

fn map_prover_error_v1(error: ProofManagedNoteStarkErrorV1) -> AtomicPrivateSettlementProofErrorV1 {
    match error {
        ProofManagedNoteStarkErrorV1::Randomness => {
            AtomicPrivateSettlementProofErrorV1::RandomnessUnavailable
        }
        ProofManagedNoteStarkErrorV1::Resource => {
            AtomicPrivateSettlementProofErrorV1::ResourceLimit
        }
        ProofManagedNoteStarkErrorV1::InvalidProfile
        | ProofManagedNoteStarkErrorV1::InvalidTrace
        | ProofManagedNoteStarkErrorV1::Copy
        | ProofManagedNoteStarkErrorV1::Constraint
        | ProofManagedNoteStarkErrorV1::ProofWire
        | ProofManagedNoteStarkErrorV1::TraceOpening
        | ProofManagedNoteStarkErrorV1::Composition
        | ProofManagedNoteStarkErrorV1::Fri
        | ProofManagedNoteStarkErrorV1::Transcript
        | ProofManagedNoteStarkErrorV1::Internal => {
            AtomicPrivateSettlementProofErrorV1::ProverInvariant
        }
    }
}

fn map_verifier_error_v1(
    error: ProofManagedNoteStarkErrorV1,
) -> AtomicPrivateSettlementProofErrorV1 {
    match error {
        ProofManagedNoteStarkErrorV1::Resource => {
            AtomicPrivateSettlementProofErrorV1::ResourceLimit
        }
        ProofManagedNoteStarkErrorV1::InvalidProfile | ProofManagedNoteStarkErrorV1::Internal => {
            AtomicPrivateSettlementProofErrorV1::ProverInvariant
        }
        ProofManagedNoteStarkErrorV1::InvalidTrace
        | ProofManagedNoteStarkErrorV1::Copy
        | ProofManagedNoteStarkErrorV1::Constraint
        | ProofManagedNoteStarkErrorV1::ProofWire
        | ProofManagedNoteStarkErrorV1::TraceOpening
        | ProofManagedNoteStarkErrorV1::Composition
        | ProofManagedNoteStarkErrorV1::Fri
        | ProofManagedNoteStarkErrorV1::Transcript
        | ProofManagedNoteStarkErrorV1::Randomness => {
            AtomicPrivateSettlementProofErrorV1::InvalidProof
        }
    }
}

/// Construct one canonical settlement proof with injected masking entropy.
///
/// The exact public manifest, fixed leg statement, trusted genesis hash,
/// current height, auditor plaintext, two membership witnesses, and three
/// fixed outputs are checked before the full trace is allocated.
///
/// # Errors
///
/// Returns a redacted relation, entropy, resource, or prover failure.
pub fn prove_atomic_private_settlement_v1_with_rng<R: TryCryptoRng + ?Sized>(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
    witness: &AtomicPrivateSettlementProverWitnessV1,
    randomness: &mut R,
) -> Result<Vec<u8>, AtomicPrivateSettlementProofErrorV1> {
    manifest
        .validate()
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidManifest)?;
    prove_atomic_private_settlement_intent_v1_with_rng(
        &manifest.proof_intent(),
        statement,
        canonical_genesis_hash,
        current_height,
        witness,
        randomness,
    )
}

/// Prove a distinct pre-proof public intent, using the same canonical native relation.
/// No incomplete full manifest is constructed or accepted.
/// # Errors
/// Exact intent/statement/witness, entropy, resource, prover or self-verification failure.
pub fn prove_atomic_private_settlement_intent_v1_with_rng<R: TryCryptoRng + ?Sized>(
    manifest: &PrivateSettlementProofIntentV1,
    statement: &PrivateSettlementProofStatementV1,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
    witness: &AtomicPrivateSettlementProverWitnessV1,
    randomness: &mut R,
) -> Result<Vec<u8>, AtomicPrivateSettlementProofErrorV1> {
    validate_public_binding_v1(manifest, statement, canonical_genesis_hash, current_height)?;
    let compiled = compile_witness_v1(manifest, statement, witness)?;
    let mut checked_randomness =
        HealthCheckedTryCryptoRngV1::new(randomness).map_err(map_entropy_error_v1)?;
    let phase_invocation = ProofPhaseInvocationV1::new_aps();
    let construction_clock = phase_invocation
        .as_ref()
        .and_then(|invocation| invocation.start(ProofPhaseV1::ApsCandidateConstruction));
    let proof = with_aps_candidate_phase_parent_v1(phase_invocation.as_ref(), || {
        prove_atomic_private_settlement_stark_v1_with_rng(
            manifest,
            statement,
            canonical_genesis_hash,
            current_height,
            &compiled,
            &mut checked_randomness,
        )
        .map_err(map_prover_error_v1)
    });
    if let Some(clock) = construction_clock {
        clock.finish(proof.is_ok());
    }
    let proof = proof?;
    // The candidate exposes no owned bytes until this independent public-adapter check.
    let verification_clock = phase_invocation
        .as_ref()
        .and_then(|invocation| invocation.start(ProofPhaseV1::ApsSelfVerification));
    let verified = verify_constructed_atomic_private_settlement_stark_v1(
        manifest,
        statement,
        canonical_genesis_hash,
        current_height,
        proof,
    )
    .map_err(|_| AtomicPrivateSettlementProofErrorV1::SelfVerification);
    if let Some(clock) = verification_clock {
        clock.finish(verified.is_ok());
    }
    verified
}

/// Construct one canonical settlement proof with operating-system entropy.
///
/// # Errors
///
/// Returns the same closed failures as
/// [`prove_atomic_private_settlement_v1_with_rng`].
pub fn prove_atomic_private_settlement_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
    witness: &AtomicPrivateSettlementProverWitnessV1,
) -> Result<Vec<u8>, AtomicPrivateSettlementProofErrorV1> {
    prove_atomic_private_settlement_v1_with_rng(
        manifest,
        statement,
        canonical_genesis_hash,
        current_height,
        witness,
        &mut OsRng,
    )
}

/// Verify one canonical settlement proof against the complete public bundle.
///
/// # Errors
///
/// Rejects expired, cross-network, manifest-substituted, statement-substituted,
/// malformed, oversized, non-canonical, or cryptographically invalid proofs.
pub fn verify_atomic_private_settlement_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
    proof: &[u8],
) -> Result<(), AtomicPrivateSettlementProofErrorV1> {
    manifest
        .validate()
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidManifest)?;
    verify_atomic_private_settlement_intent_v1(
        &manifest.proof_intent(),
        statement,
        canonical_genesis_hash,
        current_height,
        proof,
    )
}

/// Verify the exact pre-proof intent through the same native public relation and STARK owner.
/// # Errors
/// Malformed, expired, substituted, noncanonical or cryptographically invalid evidence.
pub fn verify_atomic_private_settlement_intent_v1(
    manifest: &PrivateSettlementProofIntentV1,
    statement: &PrivateSettlementProofStatementV1,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
    proof: &[u8],
) -> Result<(), AtomicPrivateSettlementProofErrorV1> {
    validate_public_binding_v1(manifest, statement, canonical_genesis_hash, current_height)?;
    verify_atomic_private_settlement_stark_v1(
        manifest,
        statement,
        canonical_genesis_hash,
        current_height,
        proof,
    )
    .map_err(map_verifier_error_v1)
}

/// Prove one pre-proof intent with operating-system entropy and independent self-verification.
/// # Errors
/// The same closed errors as the injected-entropy producer.
pub fn prove_atomic_private_settlement_intent_v1(
    intent: &PrivateSettlementProofIntentV1,
    statement: &PrivateSettlementProofStatementV1,
    genesis: [u8; 32],
    height: u64,
    witness: &AtomicPrivateSettlementProverWitnessV1,
) -> Result<Vec<u8>, AtomicPrivateSettlementProofErrorV1> {
    prove_atomic_private_settlement_intent_v1_with_rng(
        intent, statement, genesis, height, witness, &mut OsRng,
    )
}

#[cfg(test)]
pub(super) mod phase_test_support {
    use super::APS_PROOF_PHASE_TARGET_V1;
    use std::{
        collections::{BTreeMap, BTreeSet},
        fmt,
        sync::{Arc, Mutex},
    };
    use tracing::{
        Event, Metadata, Subscriber,
        field::{Field, Visit},
        level_filters::LevelFilter,
        span::{Attributes, Id, Record},
        subscriber::Interest,
    };

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum CapturedValueV1 {
        Unsigned(u64),
        Text(String),
        Debug(String),
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct CapturedPhaseEventV1 {
        target: String,
        level: tracing::Level,
        fields: BTreeMap<String, CapturedValueV1>,
    }

    struct FieldVisitorV1(BTreeMap<String, CapturedValueV1>);
    impl FieldVisitorV1 {
        fn insert(&mut self, field: &Field, value: CapturedValueV1) {
            assert!(self.0.insert(field.name().to_owned(), value).is_none());
        }
    }
    impl Visit for FieldVisitorV1 {
        fn record_u64(&mut self, field: &Field, value: u64) {
            self.insert(field, CapturedValueV1::Unsigned(value));
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            self.insert(field, CapturedValueV1::Text(value.to_owned()));
        }
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            self.insert(field, CapturedValueV1::Debug(format!("{value:?}")));
        }
    }

    struct CaptureSubscriberV1 {
        enabled: bool,
        events: Arc<Mutex<Vec<CapturedPhaseEventV1>>>,
    }
    impl Subscriber for CaptureSubscriberV1 {
        fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
            // Recheck the active thread-local subscriber for every call. Never
            // cache an enabled/disabled answer across separate capture scopes.
            Interest::sometimes()
        }
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            self.enabled
                && metadata.target() == APS_PROOF_PHASE_TARGET_V1
                && *metadata.level() == tracing::Level::DEBUG
        }
        fn max_level_hint(&self) -> Option<LevelFilter> {
            Some(LevelFilter::DEBUG)
        }
        fn new_span(&self, _attributes: &Attributes<'_>) -> Id {
            panic!("the narrow APS phase diagnostic must emit events, not spans")
        }
        fn record(&self, _span: &Id, _values: &Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
        fn event(&self, event: &Event<'_>) {
            if !self.enabled(event.metadata()) {
                return;
            }
            let mut visitor = FieldVisitorV1(BTreeMap::new());
            event.record(&mut visitor);
            let recorded = CapturedPhaseEventV1 {
                target: event.metadata().target().to_owned(),
                level: *event.metadata().level(),
                fields: visitor.0,
            };
            self.events
                .lock()
                .expect("phase capture lock")
                .push(recorded);
        }
        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }

    pub(crate) struct PhaseCaptureV1 {
        enabled: bool,
        events: Arc<Mutex<Vec<CapturedPhaseEventV1>>>,
    }
    impl PhaseCaptureV1 {
        pub(crate) fn new(enabled: bool) -> Self {
            Self {
                enabled,
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }
        pub(crate) fn with_default<R>(&self, run: impl FnOnce() -> R) -> R {
            tracing::subscriber::with_default(
                CaptureSubscriberV1 {
                    enabled: self.enabled,
                    events: Arc::clone(&self.events),
                },
                run,
            )
        }
        pub(crate) fn events_v1(&self) -> Vec<CapturedPhaseEventV1> {
            self.events.lock().expect("phase capture lock").clone()
        }
        pub(crate) fn assert_one_successful_invocation_v1(&self) -> Vec<CapturedPhaseEventV1> {
            let events = self.events_v1();
            assert_eq!(events.len(), 4, "exact two-phase success population");
            let first = assert_pair_v1(&events[..2], 1, "candidate_construction_call", "succeeded");
            let second = assert_pair_v1(
                &events[2..],
                2,
                "mandatory_self_verification_call",
                "succeeded",
            );
            assert_eq!(first.0, second.0, "one facade invocation");
            assert!(first.2 <= second.1, "two serial direct calls");
            events
        }
    }

    fn unsigned(event: &CapturedPhaseEventV1, key: &str) -> u64 {
        match event.fields.get(key) {
            Some(CapturedValueV1::Unsigned(value)) => *value,
            other => panic!("{key} must remain a typed unsigned integer, got {other:?}"),
        }
    }
    fn text(event: &CapturedPhaseEventV1, key: &str, expected: &str) {
        assert_eq!(
            event.fields.get(key),
            Some(&CapturedValueV1::Text(expected.to_owned()))
        );
    }
    fn common(event: &CapturedPhaseEventV1, ordinal: u64, phase: &str, completed: bool) {
        assert_eq!(event.target, APS_PROOF_PHASE_TARGET_V1);
        assert_eq!(event.level, tracing::Level::DEBUG);
        let mut expected = BTreeSet::from([
            "event",
            "message",
            "process_id",
            "invocation_id",
            "phase_ordinal",
            "phase",
            "start_ns",
        ]);
        if completed {
            expected.extend(["end_ns", "duration_ns", "status"]);
        }
        assert_eq!(
            event
                .fields
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(
            event.fields.get("message"),
            Some(&CapturedValueV1::Debug("aps_proof_phase_v1".to_owned()))
        );
        assert_eq!(unsigned(event, "process_id"), u64::from(std::process::id()));
        assert!(unsigned(event, "invocation_id") > 0);
        assert_eq!(unsigned(event, "phase_ordinal"), ordinal);
        text(event, "phase", phase);
    }
    pub(super) fn assert_started_v1(event: &CapturedPhaseEventV1, ordinal: u64, phase: &str) {
        common(event, ordinal, phase, false);
        text(event, "event", "started");
        let _ = unsigned(event, "start_ns");
    }
    pub(super) fn assert_pair_v1(
        events: &[CapturedPhaseEventV1],
        ordinal: u64,
        phase: &str,
        status: &str,
    ) -> (u64, u64, u64) {
        assert_eq!(events.len(), 2);
        assert_started_v1(&events[0], ordinal, phase);
        common(&events[1], ordinal, phase, true);
        text(&events[1], "event", "completed");
        text(&events[1], "status", status);
        let id = unsigned(&events[0], "invocation_id");
        assert_eq!(unsigned(&events[1], "invocation_id"), id);
        let start = unsigned(&events[0], "start_ns");
        assert_eq!(unsigned(&events[1], "start_ns"), start);
        let end = unsigned(&events[1], "end_ns");
        assert_eq!(
            unsigned(&events[1], "duration_ns"),
            end.checked_sub(start).expect("monotonic phase endpoints")
        );
        (id, start, end)
    }
}

#[cfg(test)]
mod phase_diagnostic_tests {
    use super::{
        ProofPhaseInvocationV1, ProofPhaseV1,
        phase_test_support::{PhaseCaptureV1, assert_pair_v1, assert_started_v1},
    };

    #[test]
    fn disabled_target_stays_disabled_after_enabled_callsite_registration() {
        let enabled = PhaseCaptureV1::new(true);
        let invocation = enabled.with_default(|| {
            let invocation = ProofPhaseInvocationV1::new_aps().expect("enabled invocation");
            invocation
                .start(ProofPhaseV1::ApsCandidateConstruction)
                .expect("construction clock")
                .finish(true);
            invocation
        });
        let disabled = PhaseCaptureV1::new(false);
        disabled.with_default(|| {
            assert!(ProofPhaseInvocationV1::new_aps().is_none());
            // Also exercise already registered start/end callsites under the
            // disabled subscriber rather than merely skipping timer creation.
            invocation
                .start(ProofPhaseV1::ApsCandidateConstruction)
                .expect("existing invocation clock")
                .finish(true);
        });
        assert!(disabled.events_v1().is_empty());
        enabled.with_default(|| assert!(ProofPhaseInvocationV1::new_aps().is_some()));
    }

    #[test]
    fn enabled_invocations_have_distinct_ids_without_resetting_global_sequence() {
        let capture = PhaseCaptureV1::new(true);
        let (first, second) = capture.with_default(|| {
            let first = ProofPhaseInvocationV1::new_aps().expect("enabled first invocation");
            let second = ProofPhaseInvocationV1::new_aps().expect("enabled second invocation");
            (first.id(), second.id())
        });
        assert!(first > 0 && second > 0);
        assert_ne!(first, second);
    }

    #[test]
    fn two_successful_calls_emit_exact_ordered_typed_fields() {
        let capture = PhaseCaptureV1::new(true);
        capture.with_default(|| {
            let invocation = ProofPhaseInvocationV1::new_aps().expect("enabled invocation");
            invocation
                .start(ProofPhaseV1::ApsCandidateConstruction)
                .expect("construction clock")
                .finish(true);
            invocation
                .start(ProofPhaseV1::ApsSelfVerification)
                .expect("verification clock")
                .finish(true);
        });
        capture.assert_one_successful_invocation_v1();
    }

    #[test]
    fn failed_finish_records_failure_without_a_success_status() {
        let capture = PhaseCaptureV1::new(true);
        capture.with_default(|| {
            let invocation = ProofPhaseInvocationV1::new_aps().expect("enabled invocation");
            invocation
                .start(ProofPhaseV1::ApsCandidateConstruction)
                .expect("construction clock")
                .finish(false);
        });
        assert_pair_v1(
            &capture.events_v1(),
            1,
            "candidate_construction_call",
            "failed",
        );
    }

    #[test]
    fn dropped_started_clock_has_no_completion_event() {
        let capture = PhaseCaptureV1::new(true);
        capture.with_default(|| {
            let invocation = ProofPhaseInvocationV1::new_aps().expect("enabled invocation");
            let clock = invocation
                .start(ProofPhaseV1::ApsCandidateConstruction)
                .expect("construction clock");
            drop(clock);
        });
        let events = capture.events_v1();
        assert_eq!(events.len(), 1, "Drop must not manufacture a completion");
        assert_started_v1(&events[0], 1, "candidate_construction_call");
    }

    #[test]
    fn unwinding_keeps_incomplete_start_and_restores_outer_subscriber() {
        let capture = PhaseCaptureV1::new(true);
        let disabled_outer = PhaseCaptureV1::new(false);
        disabled_outer.with_default(|| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                capture.with_default(|| {
                    let invocation = ProofPhaseInvocationV1::new_aps().expect("enabled invocation");
                    let _clock = invocation
                        .start(ProofPhaseV1::ApsCandidateConstruction)
                        .expect("construction clock");
                    panic!("controlled diagnostic unwind");
                });
            }));
            assert!(result.is_err());
            assert!(
                ProofPhaseInvocationV1::new_aps().is_none(),
                "outer disabled subscriber restored"
            );
        });
        let events = capture.events_v1();
        assert_eq!(events.len(), 1);
        assert_started_v1(&events[0], 1, "candidate_construction_call");
        assert!(disabled_outer.events_v1().is_empty());
    }
}
