//! Fixed, opt-in timing events for synchronous native proof construction.
//!
//! These diagnostics contain only public phase labels and timing identities. They never
//! participate in proof computation, error selection, randomness or verification.

use std::{
    cell::Cell,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

pub(super) const APS_PROOF_PHASE_TARGET_V1: &str = "iroha_core::aps_proof_phases";
const NOTE_PROOF_PHASE_TARGET_V1: &str = "iroha_core::proof_managed_note_stark_phases";
static PROOF_PHASE_SEQUENCE_V1: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProofPhaseFamilyV1 {
    Aps,
    ManagedNote,
}

/// Closed public phase vocabulary; callers cannot supply proof-derived labels.
#[derive(Clone, Copy)]
pub(super) enum ProofPhaseV1 {
    ApsCandidateConstruction,
    ApsSelfVerification,
    ProfilePreparation,
    BaseLde,
    BaseCommitment,
    AuxiliaryConstruction,
    NativeConstraints,
    AuxiliaryLde,
    AuxiliaryCommitment,
    FixedLdeAndChallenges,
    CompositionValues,
    CompositionCommitments,
    FriMaskOracles,
    DeepEvaluations,
    FriLayers,
    Nonce,
    Openings,
    Encode,
}
impl ProofPhaseV1 {
    fn descriptor(self) -> (ProofPhaseFamilyV1, u8, &'static str) {
        match self {
            Self::ApsCandidateConstruction => {
                (ProofPhaseFamilyV1::Aps, 1, "candidate_construction_call")
            }
            Self::ApsSelfVerification => (
                ProofPhaseFamilyV1::Aps,
                2,
                "mandatory_self_verification_call",
            ),
            Self::ProfilePreparation => (ProofPhaseFamilyV1::ManagedNote, 1, "profile_preparation"),
            Self::BaseLde => (ProofPhaseFamilyV1::ManagedNote, 2, "base_lde"),
            Self::BaseCommitment => (ProofPhaseFamilyV1::ManagedNote, 3, "base_commitment"),
            Self::AuxiliaryConstruction => {
                (ProofPhaseFamilyV1::ManagedNote, 4, "auxiliary_construction")
            }
            Self::NativeConstraints => (ProofPhaseFamilyV1::ManagedNote, 5, "native_constraints"),
            Self::AuxiliaryLde => (ProofPhaseFamilyV1::ManagedNote, 6, "auxiliary_lde"),
            Self::AuxiliaryCommitment => {
                (ProofPhaseFamilyV1::ManagedNote, 7, "auxiliary_commitment")
            }
            Self::FixedLdeAndChallenges => (
                ProofPhaseFamilyV1::ManagedNote,
                8,
                "fixed_lde_and_challenges",
            ),
            Self::CompositionValues => (ProofPhaseFamilyV1::ManagedNote, 9, "composition_values"),
            Self::CompositionCommitments => (
                ProofPhaseFamilyV1::ManagedNote,
                10,
                "composition_commitments",
            ),
            Self::FriMaskOracles => (ProofPhaseFamilyV1::ManagedNote, 11, "fri_mask_oracles"),
            Self::DeepEvaluations => (ProofPhaseFamilyV1::ManagedNote, 12, "deep_evaluations"),
            Self::FriLayers => (ProofPhaseFamilyV1::ManagedNote, 13, "fri_layers"),
            Self::Nonce => (ProofPhaseFamilyV1::ManagedNote, 14, "nonce"),
            Self::Openings => (ProofPhaseFamilyV1::ManagedNote, 15, "openings"),
            Self::Encode => (ProofPhaseFamilyV1::ManagedNote, 16, "encode"),
        }
    }
}

#[derive(Clone, Copy)]
struct ProofPhaseParentV1 {
    id: u64,
    origin: Instant,
}
thread_local! {
    // The prover driver is synchronous. No worker-thread parent inference is attempted.
    static APS_CANDIDATE_PARENT_V1: Cell<Option<ProofPhaseParentV1>> = const { Cell::new(None) };
}
struct RestoreProofPhaseParentV1(Option<ProofPhaseParentV1>);
impl Drop for RestoreProofPhaseParentV1 {
    fn drop(&mut self) {
        APS_CANDIDATE_PARENT_V1.set(self.0);
    }
}

/// Run one synchronous candidate call with an exact, lexically restored diagnostic parent.
/// Drop restores only context; it never manufactures a timing completion.
pub(super) fn with_aps_candidate_phase_parent_v1<T>(
    invocation: Option<&ProofPhaseInvocationV1>,
    run: impl FnOnce() -> T,
) -> T {
    let parent = invocation
        .filter(|value| value.family == ProofPhaseFamilyV1::Aps)
        .map(|value| ProofPhaseParentV1 {
            id: value.id,
            origin: value.origin,
        });
    let _restore = RestoreProofPhaseParentV1(APS_CANDIDATE_PARENT_V1.replace(parent));
    run()
}

/// One enabled invocation; a parent-linked child uses exactly the parent's clock origin.
pub(super) struct ProofPhaseInvocationV1 {
    id: u64,
    origin: Instant,
    family: ProofPhaseFamilyV1,
    parent_invocation_id: u64,
}
impl ProofPhaseInvocationV1 {
    pub(super) fn new_aps() -> Option<Self> {
        Self::new(ProofPhaseFamilyV1::Aps)
    }
    pub(super) fn new_managed_note() -> Option<Self> {
        Self::new(ProofPhaseFamilyV1::ManagedNote)
    }
    fn new(family: ProofPhaseFamilyV1) -> Option<Self> {
        let enabled = match family {
            ProofPhaseFamilyV1::Aps => {
                tracing::enabled!(target: APS_PROOF_PHASE_TARGET_V1, tracing::Level::DEBUG)
            }
            ProofPhaseFamilyV1::ManagedNote => {
                tracing::enabled!(target: NOTE_PROOF_PHASE_TARGET_V1, tracing::Level::DEBUG)
            }
        };
        if !enabled {
            return None;
        }
        let id = PROOF_PHASE_SEQUENCE_V1
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .ok()?;
        let parent = match family {
            ProofPhaseFamilyV1::Aps => None,
            ProofPhaseFamilyV1::ManagedNote => APS_CANDIDATE_PARENT_V1.get(),
        };
        let (origin, parent_invocation_id) =
            parent.map_or_else(|| (Instant::now(), 0), |value| (value.origin, value.id));
        Some(Self {
            id,
            origin,
            family,
            parent_invocation_id,
        })
    }
    #[cfg(test)]
    pub(super) fn id(&self) -> u64 {
        self.id
    }
    pub(super) fn start(&self, phase: ProofPhaseV1) -> Option<ProofPhaseClockV1<'_>> {
        let (family, ordinal, label) = phase.descriptor();
        if family != self.family {
            return None;
        }
        let started = Instant::now();
        let start_ns = u64::try_from(started.duration_since(self.origin).as_nanos()).ok()?;
        match family {
            ProofPhaseFamilyV1::Aps => tracing::debug!(
                target: APS_PROOF_PHASE_TARGET_V1,
                event = "started", process_id = std::process::id(), invocation_id = self.id,
                phase_ordinal = ordinal, phase = label, start_ns, "aps_proof_phase_v1"
            ),
            ProofPhaseFamilyV1::ManagedNote => tracing::debug!(
                target: NOTE_PROOF_PHASE_TARGET_V1,
                event = "started", process_id = std::process::id(), invocation_id = self.id,
                parent_invocation_id = self.parent_invocation_id,
                phase_ordinal = ordinal, phase = label, start_ns, "proof_managed_note_stark_phase_v1"
            ),
        }
        Some(ProofPhaseClockV1 {
            invocation: self,
            ordinal,
            label,
            started,
            start_ns,
        })
    }
}

/// Explicit completion of a started phase. Dropping the clock records no completion.
pub(super) struct ProofPhaseClockV1<'a> {
    invocation: &'a ProofPhaseInvocationV1,
    ordinal: u8,
    label: &'static str,
    started: Instant,
    start_ns: u64,
}
impl ProofPhaseClockV1<'_> {
    pub(super) fn finish(self, succeeded: bool) {
        let ended = Instant::now();
        let Ok(end_ns) = u64::try_from(ended.duration_since(self.invocation.origin).as_nanos())
        else {
            // An unrepresentable observation remains incomplete; proof results are untouched.
            return;
        };
        let Ok(duration_ns) = u64::try_from(ended.duration_since(self.started).as_nanos()) else {
            return;
        };
        match self.invocation.family {
            ProofPhaseFamilyV1::Aps => tracing::debug!(
                target: APS_PROOF_PHASE_TARGET_V1,
                event = "completed", process_id = std::process::id(), invocation_id = self.invocation.id,
                phase_ordinal = self.ordinal, phase = self.label, start_ns = self.start_ns,
                end_ns, duration_ns, status = if succeeded { "succeeded" } else { "failed" }, "aps_proof_phase_v1"
            ),
            ProofPhaseFamilyV1::ManagedNote => tracing::debug!(
                target: NOTE_PROOF_PHASE_TARGET_V1,
                event = "completed", process_id = std::process::id(), invocation_id = self.invocation.id,
                parent_invocation_id = self.invocation.parent_invocation_id,
                phase_ordinal = self.ordinal, phase = self.label, start_ns = self.start_ns,
                end_ns, duration_ns, status = if succeeded { "succeeded" } else { "failed" }, "proof_managed_note_stark_phase_v1"
            ),
        }
    }
}
// No clock/cursor Drop logger: unwind or missing filtered records leave an incomplete population.

/// Local cursor for the synchronous shared prover's explicit stage boundaries.
pub(super) struct ManagedNotePhaseCursorV1<'a> {
    invocation: Option<&'a ProofPhaseInvocationV1>,
    active: Option<ProofPhaseClockV1<'a>>,
}
impl<'a> ManagedNotePhaseCursorV1<'a> {
    pub(super) fn new(invocation: Option<&'a ProofPhaseInvocationV1>) -> Self {
        Self {
            invocation,
            active: None,
        }
    }
    pub(super) fn advance(&mut self, phase: ProofPhaseV1) {
        self.finish(true);
        self.active = self
            .invocation
            .and_then(|invocation| invocation.start(phase));
    }
    pub(super) fn finish(&mut self, succeeded: bool) {
        if let Some(clock) = self.active.take() {
            clock.finish(succeeded);
        }
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;
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
    enum ValueV1 {
        Unsigned(u64),
        Text(String),
        Debug(String),
    }
    #[derive(Clone, Debug)]
    pub struct CapturedEventV1 {
        pub(super) target: String,
        level: tracing::Level,
        fields: BTreeMap<String, ValueV1>,
    }
    impl CapturedEventV1 {
        pub(crate) fn unsigned(&self, key: &str) -> u64 {
            match self.fields.get(key) {
                Some(ValueV1::Unsigned(value)) => *value,
                value => panic!("{key} is not unsigned: {value:?}"),
            }
        }
        pub(super) fn text(&self, key: &str) -> &str {
            match self.fields.get(key) {
                Some(ValueV1::Text(value)) => value,
                value => panic!("{key} is not text: {value:?}"),
            }
        }
        pub(super) fn assert_fields(&self, completed: bool) {
            assert_eq!(self.level, tracing::Level::DEBUG);
            let mut allowed = BTreeSet::from([
                "event",
                "process_id",
                "invocation_id",
                "phase_ordinal",
                "phase",
                "start_ns",
                "message",
            ]);
            let message = if self.target == NOTE_PROOF_PHASE_TARGET_V1 {
                allowed.insert("parent_invocation_id");
                "proof_managed_note_stark_phase_v1"
            } else {
                assert_eq!(self.target, APS_PROOF_PHASE_TARGET_V1);
                "aps_proof_phase_v1"
            };
            if completed {
                allowed.extend(["end_ns", "duration_ns", "status"]);
            }
            assert_eq!(
                self.fields
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                allowed
            );
            assert_eq!(
                self.fields.get("message"),
                Some(&ValueV1::Debug(message.to_owned()))
            );
            assert_eq!(self.unsigned("process_id"), u64::from(std::process::id()));
            assert!(self.unsigned("invocation_id") > 0);
            assert_eq!(
                self.text("event"),
                if completed { "completed" } else { "started" }
            );
        }
    }
    struct VisitorV1(BTreeMap<String, ValueV1>);
    impl VisitorV1 {
        fn insert(&mut self, field: &Field, value: ValueV1) {
            assert!(self.0.insert(field.name().to_owned(), value).is_none());
        }
    }
    impl Visit for VisitorV1 {
        fn record_u64(&mut self, field: &Field, value: u64) {
            self.insert(field, ValueV1::Unsigned(value));
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            self.insert(field, ValueV1::Text(value.to_owned()));
        }
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            self.insert(field, ValueV1::Debug(format!("{value:?}")));
        }
    }
    #[derive(Clone)]
    pub struct CaptureV1 {
        aps: bool,
        note: bool,
        events: Arc<Mutex<Vec<CapturedEventV1>>>,
    }
    impl CaptureV1 {
        pub(crate) fn new(aps: bool, note: bool) -> Self {
            Self {
                aps,
                note,
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }
        pub(crate) fn with_default<T>(&self, run: impl FnOnce() -> T) -> T {
            tracing::subscriber::with_default(self.clone(), run)
        }
        pub(crate) fn events(&self) -> Vec<CapturedEventV1> {
            self.events.lock().expect("phase capture").clone()
        }
        pub(crate) fn note_events(&self) -> Vec<CapturedEventV1> {
            self.events()
                .into_iter()
                .filter(|event| event.target == NOTE_PROOF_PHASE_TARGET_V1)
                .collect()
        }
        pub(crate) fn assert_note_prefix(
            &self,
            count: usize,
            final_status: &str,
            parent: u64,
        ) -> Vec<CapturedEventV1> {
            let events = self.note_events();
            assert_eq!(events.len(), 2 * count);
            assert!(count > 0 && count <= NOTE_LABELS_V1.len());
            let invocation_id = events[0].unsigned("invocation_id");
            let mut last_end = 0;
            for (index, pair) in events.chunks_exact(2).enumerate() {
                pair[0].assert_fields(false);
                pair[1].assert_fields(true);
                for event in pair {
                    assert_eq!(event.unsigned("invocation_id"), invocation_id);
                    assert_eq!(event.unsigned("parent_invocation_id"), parent);
                    assert_eq!(
                        event.unsigned("phase_ordinal"),
                        u64::try_from(index + 1).expect("small phase ordinal")
                    );
                    assert_eq!(event.text("phase"), NOTE_LABELS_V1[index]);
                }
                assert_eq!(pair[0].unsigned("start_ns"), pair[1].unsigned("start_ns"));
                assert!(last_end <= pair[0].unsigned("start_ns"));
                assert!(pair[1].unsigned("end_ns") >= pair[0].unsigned("start_ns"));
                assert_eq!(
                    pair[1].unsigned("duration_ns"),
                    pair[1].unsigned("end_ns") - pair[0].unsigned("start_ns")
                );
                assert_eq!(
                    pair[1].text("status"),
                    if index + 1 == count {
                        final_status
                    } else {
                        "succeeded"
                    }
                );
                last_end = pair[1].unsigned("end_ns");
            }
            events
        }
    }
    impl Subscriber for CaptureV1 {
        fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
            Interest::sometimes()
        }
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            *metadata.level() == tracing::Level::DEBUG
                && ((self.aps && metadata.target() == APS_PROOF_PHASE_TARGET_V1)
                    || (self.note && metadata.target() == NOTE_PROOF_PHASE_TARGET_V1))
        }
        fn max_level_hint(&self) -> Option<LevelFilter> {
            Some(LevelFilter::DEBUG)
        }
        fn new_span(&self, _attributes: &Attributes<'_>) -> Id {
            panic!("proof phase diagnostics must use events, not spans")
        }
        fn record(&self, _span: &Id, _values: &Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
        fn event(&self, event: &Event<'_>) {
            if !self.enabled(event.metadata()) {
                return;
            }
            let mut visitor = VisitorV1(BTreeMap::new());
            event.record(&mut visitor);
            self.events
                .lock()
                .expect("phase capture")
                .push(CapturedEventV1 {
                    target: event.metadata().target().to_owned(),
                    level: *event.metadata().level(),
                    fields: visitor.0,
                });
        }
        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }
    pub(super) const NOTE_LABELS_V1: [&str; 16] = [
        "profile_preparation",
        "base_lde",
        "base_commitment",
        "auxiliary_construction",
        "native_constraints",
        "auxiliary_lde",
        "auxiliary_commitment",
        "fixed_lde_and_challenges",
        "composition_values",
        "composition_commitments",
        "fri_mask_oracles",
        "deep_evaluations",
        "fri_layers",
        "nonce",
        "openings",
        "encode",
    ];
    pub(super) const NOTE_PHASES_V1: [ProofPhaseV1; 16] = [
        ProofPhaseV1::ProfilePreparation,
        ProofPhaseV1::BaseLde,
        ProofPhaseV1::BaseCommitment,
        ProofPhaseV1::AuxiliaryConstruction,
        ProofPhaseV1::NativeConstraints,
        ProofPhaseV1::AuxiliaryLde,
        ProofPhaseV1::AuxiliaryCommitment,
        ProofPhaseV1::FixedLdeAndChallenges,
        ProofPhaseV1::CompositionValues,
        ProofPhaseV1::CompositionCommitments,
        ProofPhaseV1::FriMaskOracles,
        ProofPhaseV1::DeepEvaluations,
        ProofPhaseV1::FriLayers,
        ProofPhaseV1::Nonce,
        ProofPhaseV1::Openings,
        ProofPhaseV1::Encode,
    ];
}

#[cfg(test)]
mod tests {
    use super::{
        test_support::{CaptureV1, NOTE_PHASES_V1},
        *,
    };

    fn complete_note_invocation() -> u64 {
        let invocation =
            ProofPhaseInvocationV1::new_managed_note().expect("enabled note invocation");
        let mut phases = ManagedNotePhaseCursorV1::new(Some(&invocation));
        for phase in NOTE_PHASES_V1 {
            phases.advance(phase);
        }
        phases.finish(true);
        invocation.id
    }

    #[test]
    fn standalone_note_phases_emit_exact_ordered_public_fields() {
        let capture = CaptureV1::new(false, true);
        capture.with_default(complete_note_invocation);
        capture.assert_note_prefix(16, "succeeded", 0);
    }

    #[test]
    fn nested_note_phases_join_candidate_without_changing_facade_population() {
        let capture = CaptureV1::new(true, true);
        let (parent_id, child_id) = capture.with_default(|| {
            let parent = ProofPhaseInvocationV1::new_aps().expect("enabled APS invocation");
            let candidate = parent
                .start(ProofPhaseV1::ApsCandidateConstruction)
                .expect("candidate clock");
            let child_id =
                with_aps_candidate_phase_parent_v1(Some(&parent), complete_note_invocation);
            candidate.finish(true);
            parent
                .start(ProofPhaseV1::ApsSelfVerification)
                .expect("verification clock")
                .finish(true);
            (parent.id, child_id)
        });
        assert_ne!(parent_id, child_id);
        let note = capture.assert_note_prefix(16, "succeeded", parent_id);
        let aps = capture
            .events()
            .into_iter()
            .filter(|event| event.target == APS_PROOF_PHASE_TARGET_V1)
            .collect::<Vec<_>>();
        assert_eq!(aps.len(), 4);
        for (index, pair) in aps.chunks_exact(2).enumerate() {
            pair[0].assert_fields(false);
            pair[1].assert_fields(true);
            for event in pair {
                assert_eq!(event.unsigned("invocation_id"), parent_id);
            }
            assert_eq!(
                pair[0].unsigned("phase_ordinal"),
                u64::try_from(index + 1).expect("small phase ordinal")
            );
            assert_eq!(pair[1].text("status"), "succeeded");
        }
        assert!(aps[0].unsigned("start_ns") <= note[0].unsigned("start_ns"));
        assert!(
            note.last().expect("last note phase").unsigned("end_ns") <= aps[1].unsigned("end_ns")
        );
        assert!(aps[1].unsigned("end_ns") <= aps[2].unsigned("start_ns"));
    }

    #[test]
    fn diagnostic_targets_remain_independent_after_callsite_registration() {
        let enabled = CaptureV1::new(true, true);
        let existing = enabled.with_default(|| {
            complete_note_invocation();
            ProofPhaseInvocationV1::new_managed_note().expect("registered invocation")
        });
        let disabled = CaptureV1::new(false, false);
        disabled.with_default(|| {
            assert!(ProofPhaseInvocationV1::new_aps().is_none());
            assert!(ProofPhaseInvocationV1::new_managed_note().is_none());
            existing
                .start(ProofPhaseV1::ProfilePreparation)
                .expect("registered clock")
                .finish(true);
        });
        assert!(disabled.events().is_empty());
        CaptureV1::new(true, false).with_default(|| {
            assert!(ProofPhaseInvocationV1::new_aps().is_some());
            assert!(ProofPhaseInvocationV1::new_managed_note().is_none());
        });
        let note_only = CaptureV1::new(false, true);
        note_only.with_default(|| {
            let parent = ProofPhaseInvocationV1::new_aps();
            assert!(parent.is_none());
            with_aps_candidate_phase_parent_v1(parent.as_ref(), complete_note_invocation);
        });
        note_only.assert_note_prefix(16, "succeeded", 0);
        enabled.with_default(|| assert!(ProofPhaseInvocationV1::new_managed_note().is_some()));
    }

    #[test]
    fn ordinary_error_closes_only_the_active_note_phase_as_failed() {
        let capture = CaptureV1::new(false, true);
        capture.with_default(|| {
            let invocation =
                ProofPhaseInvocationV1::new_managed_note().expect("enabled invocation");
            let mut phases = ManagedNotePhaseCursorV1::new(Some(&invocation));
            let result: Result<(), ()> = {
                phases.advance(ProofPhaseV1::ProfilePreparation);
                phases.advance(ProofPhaseV1::BaseLde);
                Err(())
            };
            if result.is_err() {
                phases.finish(false);
            }
            assert_eq!(result, Err(()));
        });
        capture.assert_note_prefix(2, "failed", 0);
    }

    #[test]
    fn dropping_or_unwinding_a_note_cursor_never_completes_it() {
        for unwind in [false, true] {
            let capture = CaptureV1::new(false, true);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                capture.with_default(|| {
                    let invocation =
                        ProofPhaseInvocationV1::new_managed_note().expect("enabled invocation");
                    let mut phases = ManagedNotePhaseCursorV1::new(Some(&invocation));
                    phases.advance(ProofPhaseV1::ProfilePreparation);
                    assert!(!unwind, "controlled diagnostic unwind");
                    // Let the cursor's lexical scope end without completing its active phase.
                })
            }));
            assert_eq!(result.is_err(), unwind);
            let events = capture.note_events();
            assert_eq!(events.len(), 1);
            events[0].assert_fields(false);
        }
    }

    #[test]
    fn parent_scope_restores_nested_context_on_success_error_and_unwind() {
        let capture = CaptureV1::new(true, true);
        capture.with_default(|| {
            assert!(APS_CANDIDATE_PARENT_V1.get().is_none());
            let outer = ProofPhaseInvocationV1::new_aps().expect("outer invocation");
            let inner = ProofPhaseInvocationV1::new_aps().expect("inner invocation");
            with_aps_candidate_phase_parent_v1(Some(&outer), || {
                for mode in 0..3 {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        with_aps_candidate_phase_parent_v1(Some(&inner), || {
                            let child =
                                ProofPhaseInvocationV1::new_managed_note().expect("nested child");
                            assert_eq!(child.parent_invocation_id, inner.id);
                            assert_eq!(child.origin, inner.origin);
                            assert!(mode != 2, "controlled scope unwind");
                            if mode == 1 { Err(()) } else { Ok(()) }
                        })
                    }));
                    if mode == 2 {
                        assert!(result.is_err());
                    } else {
                        assert_eq!(
                            result.expect("normal scope return"),
                            if mode == 1 { Err(()) } else { Ok(()) }
                        );
                    }
                    let child =
                        ProofPhaseInvocationV1::new_managed_note().expect("restored outer child");
                    assert_eq!(child.parent_invocation_id, outer.id);
                    assert_eq!(child.origin, outer.origin);
                }
                with_aps_candidate_phase_parent_v1(None, || {
                    assert_eq!(
                        ProofPhaseInvocationV1::new_managed_note()
                            .expect("unparented child")
                            .parent_invocation_id,
                        0
                    )
                });
                assert_eq!(
                    APS_CANDIDATE_PARENT_V1
                        .get()
                        .expect("outer parent restored")
                        .id,
                    outer.id
                );
            });
            assert!(APS_CANDIDATE_PARENT_V1.get().is_none());
        });
        assert!(
            capture.events().is_empty(),
            "scope restoration is not a logger"
        );
    }

    #[test]
    fn consecutive_note_invocations_have_distinct_nonzero_ids() {
        let capture = CaptureV1::new(false, true);
        capture.with_default(|| {
            let first = ProofPhaseInvocationV1::new_managed_note().expect("first invocation");
            let second = ProofPhaseInvocationV1::new_managed_note().expect("second invocation");
            assert!(first.id > 0 && second.id > 0);
            assert_ne!(first.id, second.id);
        });
    }
}
