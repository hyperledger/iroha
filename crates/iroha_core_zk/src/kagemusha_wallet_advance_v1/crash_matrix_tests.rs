//! Exhaustive crash-point matrices over complete provider flows (G2 design rev 2 test plan,
//! invariants I1-I12).
//!
//! Each matrix runs one flow (enrollment, Bootstrap, Advance with marker retirement,
//! abandonment, custody deletion) on a fork of a prepared device, injects one fault at every
//! filesystem step the flow executes, then recovers in one of five ways: the same process
//! continues, the process restarts, or power is lost (unsynced state dropped, or two seeded
//! models of independent survival of unsynced directory operations and kept, lost or torn
//! unsynced data). A fresh boot identity follows every power loss. After recovery the case
//! checks:
//!
//! - **coverage** (I1): every payment key is covered by exactly one current marker (only one
//!   marker file remains after reconciliation) or a terminal marker, or its slot is abandoned
//!   before any marker with no journal record;
//! - **one successor** (I3): at most one successor of the head is ever released, even when a
//!   competing operation is tried first after recovery;
//! - **byte-identical retries** (I4): every retry of a released result returns the exact
//!   frame, and a result released by the faulted call is the one retained;
//! - **not performed means not selected** (I8);
//! - **signing and key-lifecycle guards** (I6, I10, I12, D3): the fake platform records a
//!   violation when it signs under anything but a lone Selected marker, generates a key outside
//!   "intent, no marker, not abandoned", or deletes a key before a durable, anchored terminal
//!   marker;
//! - **rollback** (I11, iOS): restoring the files of the starting state while the keychain
//!   anchor survives is `RolledBack`, never a selectable older head.

use std::{fmt::Debug, io};

use iroha_data_model::kagemusha::{
    KagemushaWalletCompletionRecordV1, KagemushaWalletRecoveryCapsuleV1,
    KagemushaWalletTerminalReasonV1,
};

use super::{
    test_support::{
        AnchorWriteV1, BOOT_B, DeviceV1, PROFILE, SimProviderV1, TestOwnerV1, advance_request,
        bootstrap_capsule, bootstrap_capsule_variant, bootstrapped_device, enrolled_device,
        enrollment_challenge, next_capsule, next_capsule_variant, open_provider, released,
    },
    *,
};

const FAULTS: [KagemushaWalletSimFaultV1; 6] = [
    KagemushaWalletSimFaultV1::Error,
    KagemushaWalletSimFaultV1::ErrorKind(io::ErrorKind::StorageFull),
    KagemushaWalletSimFaultV1::PartialWrite,
    KagemushaWalletSimFaultV1::LostWriteback,
    KagemushaWalletSimFaultV1::CrashBefore,
    KagemushaWalletSimFaultV1::CrashAfter,
];

/// How the device recovers after the faulted call.
#[derive(Debug, Clone, Copy)]
enum RecoveryV1 {
    /// The process continues with the same provider (when it did not crash).
    SameProcess,
    /// The process restarts; visible state survives.
    Restart,
    /// Power is lost; only durable state survives, as the model decides.
    PowerLoss(KagemushaWalletSimPowerLossV1),
}

const RECOVERIES: [RecoveryV1; 5] = [
    RecoveryV1::SameProcess,
    RecoveryV1::Restart,
    RecoveryV1::PowerLoss(KagemushaWalletSimPowerLossV1::DropUnsynced),
    RecoveryV1::PowerLoss(KagemushaWalletSimPowerLossV1::Seeded(1)),
    RecoveryV1::PowerLoss(KagemushaWalletSimPowerLossV1::Seeded(2)),
];

const POLICIES: [KagemushaWalletAnchorPolicyV1; 2] = [
    KagemushaWalletAnchorPolicyV1::NotRequired,
    KagemushaWalletAnchorPolicyV1::Keychain,
];

type OutcomeV1 = KagemushaWalletAdvanceOutcomeV1<KagemushaWalletCompletionRecordV1>;
type RetainedV1 = KagemushaWalletRetainedV1<KagemushaWalletCompletionRecordV1>;

/// Number of filesystem steps `flow` takes on a fresh provider over a fork of `base`.
fn flow_steps<T>(base: &DeviceV1, flow: &dyn Fn(&mut SimProviderV1) -> T) -> u64 {
    let device = base.fork();
    let mut provider = device.open();
    let start = device.fs.steps();
    let _ = flow(&mut provider);
    device.fs.steps() - start
}

/// Filesystem state right after a faulted call, before recovery.
struct AfterCallV1 {
    /// Whether the simulated process crashed during the call (its outcome is then never seen).
    crashed: bool,
    /// Marker generations visible right after the call.
    visible: Vec<u128>,
    /// Marker generations that survive a power loss right after the call.
    durable: Vec<u128>,
}

/// Run `flow` with `fault` at its `step`-th filesystem step, then recover.
fn faulted_case<T>(
    base: &DeviceV1,
    step: u64,
    fault: KagemushaWalletSimFaultV1,
    recovery: RecoveryV1,
    flow: &dyn Fn(&mut SimProviderV1) -> T,
) -> (DeviceV1, SimProviderV1, T) {
    let (device, provider, outcome, _) =
        faulted_case_observed(base, step, fault, recovery, flow, None);
    (device, provider, outcome)
}

/// [`faulted_case`] that also reports the marker generations of `slot` right after the call.
fn faulted_case_observed<T>(
    base: &DeviceV1,
    step: u64,
    fault: KagemushaWalletSimFaultV1,
    recovery: RecoveryV1,
    flow: &dyn Fn(&mut SimProviderV1) -> T,
    slot: Option<&KagemushaWalletSlotIdV1>,
) -> (DeviceV1, SimProviderV1, T, Option<AfterCallV1>) {
    let device = base.fork();
    let mut provider = device.open();
    device.fs.inject(device.fs.steps() + step, fault);
    let outcome = flow(&mut provider);
    device.fs.clear_faults();
    let after = slot.map(|slot| {
        let durable = device.fork();
        durable
            .fs
            .power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
        AfterCallV1 {
            crashed: device.fs.crashed(),
            visible: visible_markers(&device, slot),
            durable: visible_markers(&durable, slot),
        }
    });
    let provider = match recovery {
        RecoveryV1::SameProcess if !device.fs.crashed() => provider,
        RecoveryV1::SameProcess | RecoveryV1::Restart => {
            drop(provider);
            device.fs.restart();
            device.open()
        }
        RecoveryV1::PowerLoss(mode) => {
            drop(provider);
            device.power_loss(mode, BOOT_B);
            device.open()
        }
    };
    (device, provider, outcome, after)
}

/// Pending exactly as the contract requires: a call whose Selected marker is durable reports
/// the operation performed (released or pending), never an error or not-performed; a call
/// reporting not-performed left no successor marker visible. `base_generation` is the current
/// marker's generation before the call.
fn assert_selection_reported(
    outcome: &Result<OutcomeV1, KagemushaWalletProviderErrorV1>,
    after: &AfterCallV1,
    base_generation: u128,
    label: &str,
) {
    if after.crashed {
        return;
    }
    let selected = |generations: &[u128]| generations.iter().any(|g| *g > base_generation);
    if selected(&after.durable) {
        assert!(
            matches!(
                outcome,
                Ok(KagemushaWalletAdvanceOutcomeV1::Released { .. }
                    | KagemushaWalletAdvanceOutcomeV1::Pending { .. })
            ),
            "{label}: a durable selection must be reported as performed"
        );
    }
    if matches!(
        outcome,
        Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(_))
    ) {
        assert!(
            !selected(&after.visible),
            "{label}: not performed but a successor marker is visible: {:?}",
            after.visible
        );
    }
}

/// Visible marker generations of `slot`.
fn visible_markers(device: &DeviceV1, slot: &KagemushaWalletSlotIdV1) -> Vec<u128> {
    device
        .fs
        .visible_names(&kagemusha_wallet_markers_dir_v1(slot))
        .iter()
        .filter_map(|name| kagemusha_wallet_parse_marker_name_v1(name))
        .collect()
}

/// I1 and the platform guards on every slot of the device, after reconciliation.
fn assert_covered(device: &DeviceV1, provider: &mut SimProviderV1, label: &str) {
    let violations = device.platform.with(|state| state.violations.clone());
    assert!(violations.is_empty(), "{label}: {violations:?}");
    for slot in provider.slots().expect(label) {
        let status = provider
            .status(&slot)
            .unwrap_or_else(|error| panic!("{label}: status {error:?}"));
        let key = device.platform.key_of(&slot);
        match &status {
            KagemushaWalletSlotStatusV1::Enrollment(record)
            | KagemushaWalletSlotStatusV1::Pending(record)
            | KagemushaWalletSlotStatusV1::Released(record) => {
                assert_eq!(
                    key.as_ref(),
                    Some(record.payment_key()),
                    "{label}: key covered"
                );
                assert_eq!(
                    visible_markers(device, &slot),
                    vec![record.generation()],
                    "{label}: exactly one current marker"
                );
            }
            KagemushaWalletSlotStatusV1::Terminal(record) => {
                assert_eq!(
                    visible_markers(device, &slot),
                    vec![record.generation()],
                    "{label}: exactly one terminal marker"
                );
                if key.is_some() {
                    assert_eq!(key.as_ref(), Some(record.payment_key()), "{label}");
                }
            }
            KagemushaWalletSlotStatusV1::SlotAbandoned => {
                assert!(visible_markers(device, &slot).is_empty(), "{label}");
                assert_eq!(
                    provider.enrollment_record(&slot).expect(label),
                    None,
                    "{label}: an abandoned slot never requested a credential"
                );
            }
            KagemushaWalletSlotStatusV1::IntentOnly | KagemushaWalletSlotStatusV1::Empty => {
                assert_eq!(key, None, "{label}: a key without a marker is abandoned");
            }
        }
    }
}

fn label(
    flow: &str,
    policy: KagemushaWalletAnchorPolicyV1,
    step: u64,
    fault: KagemushaWalletSimFaultV1,
    recovery: RecoveryV1,
    outcome: &dyn Debug,
) -> String {
    format!(
        "{flow} {policy:?} step {step} fault {fault:?} recovery {recovery:?} outcome {outcome:?}"
    )
}

/// Released result of an outcome, if any.
fn released_of(outcome: &Result<OutcomeV1, KagemushaWalletProviderErrorV1>) -> Option<RetainedV1> {
    match outcome {
        Ok(KagemushaWalletAdvanceOutcomeV1::Released { retained, .. }) => {
            Some((**retained).clone())
        }
        _ => None,
    }
}

/// Remember a released result of `result` in `releases`.
fn record(
    result: Result<OutcomeV1, KagemushaWalletProviderErrorV1>,
    releases: &mut Vec<RetainedV1>,
) -> Result<OutcomeV1, KagemushaWalletProviderErrorV1> {
    if let Some(retained) = released_of(&result) {
        releases.push(retained);
    }
    result
}

/// Whether a faulted call's outcome is admissible: a definitive answer, a pending operation or a
/// retryable error, never an invalid-input verdict for a valid request.
fn assert_admissible(outcome: &Result<OutcomeV1, KagemushaWalletProviderErrorV1>, label: &str) {
    match outcome {
        Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
            KagemushaWalletNotPerformedV1::Invalid { .. },
        ))
        | Ok(KagemushaWalletAdvanceOutcomeV1::Archived(_))
        | Ok(KagemushaWalletAdvanceOutcomeV1::DeliveryDataLoss { .. }) => {
            panic!("{label}: inadmissible outcome")
        }
        Err(
            KagemushaWalletProviderErrorV1::LostCustody(_)
            | KagemushaWalletProviderErrorV1::KeyLost
            | KagemushaWalletProviderErrorV1::Invalid { .. }
            | KagemushaWalletProviderErrorV1::UnavailableCustodyData { .. }
            | KagemushaWalletProviderErrorV1::OperationIdConflict { .. },
        ) => panic!("{label}: inadmissible error"),
        _ => {}
    }
}

/// How a case resolves after recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolutionV1 {
    /// Retry the faulted operation.
    Retry,
    /// Try the competing successor first.
    CompetitorFirst,
    /// Try abandonment first (Bootstrap only).
    AbandonFirst,
}

/// Run one head-advancing matrix: `request` is the faulted operation, `competitor` a
/// competing successor of the same head.
fn advance_matrix(
    flow: &str,
    base: &DeviceV1,
    slot: KagemushaWalletSlotIdV1,
    request: &KagemushaWalletAdvanceRequestV1<KagemushaWalletRecoveryCapsuleV1>,
    competitor: &KagemushaWalletAdvanceRequestV1<KagemushaWalletRecoveryCapsuleV1>,
    resolutions: &[ResolutionV1],
) -> MatrixTallyV1 {
    let policy = base.platform.with(|state| state.policy);
    let request_digest = request
        .capsule
        .capsule_digest()
        .expect("request capsule digest");
    let base_generation = *visible_markers(base, &slot).last().expect("base marker");
    let run = |provider: &mut SimProviderV1| provider.advance(&slot, &TestOwnerV1, request);
    let steps = flow_steps(base, &run);
    assert!(steps > 20, "{flow}: {steps} steps");
    let mut tally = MatrixTallyV1::default();
    let mut rotation = 0_usize;
    for step in 0..steps {
        for fault in FAULTS {
            for recovery in RECOVERIES {
                rotation += 1;
                let resolution = resolutions[rotation % resolutions.len()];
                let (device, mut provider, outcome, after) =
                    faulted_case_observed(base, step, fault, recovery, &run, Some(&slot));
                let label = label(flow, policy, step, fault, recovery, &outcome)
                    + &format!(" resolution {resolution:?}");
                assert_admissible(&outcome, &label);
                assert_selection_reported(
                    &outcome,
                    &after.expect("observed"),
                    base_generation,
                    &label,
                );
                assert_covered(&device, &mut provider, &label);
                let first = released_of(&outcome);
                let not_performed = matches!(
                    outcome,
                    Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(_))
                );
                // Resolve: every call below is fault-free and must be definitive.
                let mut releases: Vec<RetainedV1> = first.iter().cloned().collect();
                match resolution {
                    ResolutionV1::CompetitorFirst => {
                        let competing = record(
                            provider.advance(&slot, &TestOwnerV1, competitor),
                            &mut releases,
                        );
                        if not_performed {
                            assert!(
                                released_of(&competing).is_some(),
                                "{label}: not performed means not selected: {competing:?}"
                            );
                        }
                    }
                    ResolutionV1::AbandonFirst => {
                        let abandoned = provider.abandon_enrollment(&slot);
                        if not_performed {
                            assert!(abandoned.is_ok(), "{label}: {abandoned:?}");
                        }
                    }
                    ResolutionV1::Retry => {}
                }
                let retried = record(
                    provider.advance(&slot, &TestOwnerV1, request),
                    &mut releases,
                );
                let again = record(
                    provider.advance(&slot, &TestOwnerV1, request),
                    &mut releases,
                );
                match (&retried, &again) {
                    (Ok(KagemushaWalletAdvanceOutcomeV1::Released { .. }), _) => {
                        assert_eq!(released_of(&retried), released_of(&again), "{label}");
                    }
                    (
                        Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
                            KagemushaWalletNotPerformedV1::StaleHead,
                        ))
                        | Err(
                            KagemushaWalletProviderErrorV1::OperationIdConflict { .. }
                            | KagemushaWalletProviderErrorV1::Terminal,
                        ),
                        _,
                    ) => {
                        assert!(first.is_none(), "{label}: a released result was lost");
                    }
                    other => panic!("{label}: retry not definitive: {other:?}"),
                }
                // I3 and I4: one released successor, byte-identical everywhere.
                let mut distinct: Vec<&RetainedV1> = Vec::new();
                for retained in &releases {
                    if !distinct.iter().any(|seen| *seen == retained) {
                        distinct.push(retained);
                    }
                }
                assert!(distinct.len() <= 1, "{label}: {} releases", distinct.len());
                if let Some(first) = &first {
                    assert_eq!(distinct, vec![first], "{label}: first release retained");
                    tally.released_by_faulted_call += 1;
                }
                match distinct.first() {
                    Some(winner) if winner.capsule_digest == request_digest => {
                        tally.request_won += 1
                    }
                    Some(_) => tally.competitor_won += 1,
                    None => tally.abandoned += 1,
                }
                assert_covered(&device, &mut provider, &label);
                // Durability of what was released: after a power loss in a new boot the same
                // bytes are retained (fresh-inode adoption after lost writebacks, design R3).
                if let Some(winner) = distinct.first() {
                    let winner = (*winner).clone();
                    let winning = if winner.capsule_digest == request_digest {
                        request
                    } else {
                        competitor
                    };
                    drop(provider);
                    device.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced, [0xc3; 32]);
                    provider = device.open();
                    assert_eq!(
                        released_of(&provider.advance(&slot, &TestOwnerV1, winning)),
                        Some(winner),
                        "{label}: released bytes survive a later power loss"
                    );
                    tally.durable_after_power_loss += 1;
                }
                // I11: once a successor is released, the starting files are a rollback.
                if policy == KagemushaWalletAnchorPolicyV1::Keychain && !distinct.is_empty() {
                    drop(provider);
                    let restored = DeviceV1 {
                        fs: base.fs.fork(),
                        platform: device.platform.fork(None),
                    };
                    let mut restored_provider = restored.open();
                    assert_eq!(
                        restored_provider.status(&slot),
                        Err(KagemushaWalletProviderErrorV1::LostCustody(
                            KagemushaWalletLostCustodyV1::RolledBack
                        )),
                        "{label}: restored starting files"
                    );
                    tally.rollbacks_refused += 1;
                }
                tally.cases += 1;
            }
        }
    }
    tally
}

/// Outcome counts of one matrix, so a matrix that never reaches a branch fails.
#[derive(Debug, Default)]
struct MatrixTallyV1 {
    cases: usize,
    released_by_faulted_call: usize,
    request_won: usize,
    competitor_won: usize,
    abandoned: usize,
    rollbacks_refused: usize,
    durable_after_power_loss: usize,
}

#[test]
fn wallet_advance_v1_crash_matrix_bootstrap() {
    for (index, policy) in POLICIES.into_iter().enumerate() {
        let seed = 0x60 + u8::try_from(index).expect("index");
        let (base, f, slot) = enrolled_device(policy, seed);
        let current = base.open().status(&slot).expect("status");
        let enrollment = current.marker().expect("marker").clone();
        let request = advance_request(&enrollment, &bootstrap_capsule(&f));
        let competitor = advance_request(&enrollment, &bootstrap_capsule_variant(&f, 1));
        let tally = advance_matrix(
            "bootstrap",
            &base,
            slot,
            &request,
            &competitor,
            &[
                ResolutionV1::Retry,
                ResolutionV1::CompetitorFirst,
                ResolutionV1::AbandonFirst,
            ],
        );
        assert!(tally.cases > 600, "{policy:?}: {tally:?}");
        assert!(tally.released_by_faulted_call > 0, "{policy:?}: {tally:?}");
        assert!(
            tally.competitor_won > 0 && tally.request_won > 0,
            "{policy:?}: {tally:?}"
        );
        assert!(tally.abandoned > 0, "{policy:?}: {tally:?}");
        if policy == KagemushaWalletAnchorPolicyV1::Keychain {
            assert!(tally.rollbacks_refused > 0, "{tally:?}");
        }
        eprintln!("bootstrap matrix {policy:?}: {tally:?}");
    }
}

#[test]
fn wallet_advance_v1_crash_matrix_advance_and_retirement() {
    for (index, policy) in POLICIES.into_iter().enumerate() {
        let seed = 0x62 + u8::try_from(index).expect("index");
        let (base, f, slot, bootstrap) = bootstrapped_device(policy, seed);
        let current = base.open().status(&slot).expect("status");
        let released = current.marker().expect("marker").clone();
        assert_eq!(released.generation(), 2);
        let request = advance_request(&released, &next_capsule(&f, &bootstrap));
        let competitor = advance_request(&released, &next_capsule_variant(&f, &bootstrap, 1));
        let tally = advance_matrix(
            "advance",
            &base,
            slot,
            &request,
            &competitor,
            &[ResolutionV1::Retry, ResolutionV1::CompetitorFirst],
        );
        assert!(tally.cases > 600, "{policy:?}: {tally:?}");
        assert!(tally.released_by_faulted_call > 0, "{policy:?}: {tally:?}");
        assert!(
            tally.competitor_won > 0 && tally.request_won > 0,
            "{policy:?}: {tally:?}"
        );
        assert_eq!(tally.abandoned, 0, "{policy:?}: {tally:?}");
        if policy == KagemushaWalletAnchorPolicyV1::Keychain {
            assert_eq!(tally.rollbacks_refused, tally.cases, "{tally:?}");
        }
        eprintln!("advance matrix {policy:?}: {tally:?}");
    }
}

/// Complete an enrollment after recovery and return the enrolled slot.
fn finish_enrollment(
    provider: &mut SimProviderV1,
    device: &DeviceV1,
    seed: u8,
    label: &str,
) -> KagemushaWalletSlotIdV1 {
    for slot in provider.slots().expect(label) {
        match provider.status(&slot).expect(label) {
            KagemushaWalletSlotStatusV1::Enrollment(_) => return slot,
            KagemushaWalletSlotStatusV1::IntentOnly => {
                match provider
                    .test_resume_enrollment(&slot, KagemushaWalletChallengeLivenessV1::Live)
                    .expect(label)
                {
                    KagemushaWalletEnrollmentStepV1::Enrolled { slot, .. } => return slot,
                    other => panic!("{label}: resume {other:?}"),
                }
            }
            _ => {}
        }
    }
    // Abandoned or empty slots are never reused: a new slot, alias and key.
    let next = seed.wrapping_add(0x80);
    device.platform.with(|state| state.next_key_seed = next);
    match provider
        .test_begin_enrollment(
            &enrollment_challenge(next),
            PROFILE,
            crate::kagemusha_wallet_advance_v1::KagemushaWalletEnrollmentDatesV1 {
                issued_at_ms: 1,
                expires_at_ms: 600_001,
            },
        )
        .expect(label)
    {
        KagemushaWalletEnrollmentStepV1::Enrolled { slot, .. } => slot,
        other => panic!("{label}: begin {other:?}"),
    }
}

#[test]
fn wallet_advance_v1_crash_matrix_enrollment() {
    const FIRST: &[u8] = b"first request";
    const SECOND: &[u8] = b"second request";
    for (index, policy) in POLICIES.into_iter().enumerate() {
        let seed = 0x64 + u8::try_from(index).expect("index");
        let base = DeviceV1::new(policy, seed);
        let run = |provider: &mut SimProviderV1| {
            let step = provider.test_begin_enrollment(
                &enrollment_challenge(seed),
                PROFILE,
                crate::kagemusha_wallet_advance_v1::KagemushaWalletEnrollmentDatesV1 {
                    issued_at_ms: 1,
                    expires_at_ms: 600_001,
                },
            );
            let request = match &step {
                Ok(KagemushaWalletEnrollmentStepV1::Enrolled { slot, .. }) => {
                    let request = provider.retain_enrollment_request(slot, FIRST);
                    let credential = request
                        .as_ref()
                        .ok()
                        .map(|_| provider.store_credential(slot, 0, b"credential"));
                    Some((request, credential))
                }
                _ => None,
            };
            (step, request)
        };
        let steps = flow_steps(&base, &run);
        assert!(steps > 20, "{steps} steps");
        let mut cases = 0_usize;
        for step in 0..steps {
            for fault in FAULTS {
                for recovery in RECOVERIES {
                    let (device, mut provider, outcome) =
                        faulted_case(&base, step, fault, recovery, &run);
                    let label = label("enrollment", policy, step, fault, recovery, &outcome);
                    if let Err(error) = &outcome.0 {
                        assert!(
                            matches!(
                                error,
                                KagemushaWalletProviderErrorV1::Unavailable(_)
                                    | KagemushaWalletProviderErrorV1::Uncertain(_)
                                    | KagemushaWalletProviderErrorV1::NoSpace
                                    | KagemushaWalletProviderErrorV1::NoReplaceUnsupported
                            ),
                            "{label}"
                        );
                    }
                    assert_covered(&device, &mut provider, &label);
                    let slot = finish_enrollment(&mut provider, &device, seed, &label);
                    let sent = provider
                        .retain_enrollment_request(&slot, SECOND)
                        .expect(&label);
                    if let (
                        Ok(KagemushaWalletEnrollmentStepV1::Enrolled { slot: first, .. }),
                        Some((Ok(first_sent), _)),
                    ) = (&outcome.0, &outcome.1)
                    {
                        assert_eq!(first_sent.as_slice(), FIRST, "{label}");
                        if *first == slot {
                            assert_eq!(
                                sent.as_slice(),
                                FIRST,
                                "{label}: retries send identical bytes"
                            );
                        }
                    }
                    assert!(sent == FIRST || sent == SECOND, "{label}");
                    assert_eq!(
                        provider
                            .retain_enrollment_request(&slot, SECOND)
                            .expect(&label),
                        sent,
                        "{label}"
                    );
                    provider
                        .store_credential(&slot, 0, b"credential")
                        .expect(&label);
                    assert_covered(&device, &mut provider, &label);
                    let enrolled = provider
                        .slots()
                        .expect(&label)
                        .into_iter()
                        .filter(|slot| {
                            matches!(
                                provider.status(slot),
                                Ok(KagemushaWalletSlotStatusV1::Enrollment(_))
                            )
                        })
                        .count();
                    assert_eq!(enrolled, 1, "{label}: one enrolled incarnation");
                    // What was returned to send survives a later power loss unchanged.
                    drop(provider);
                    device.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced, [0xc3; 32]);
                    let mut provider = device.open();
                    assert_eq!(
                        provider.retain_enrollment_request(&slot, b"third"),
                        Ok(sent),
                        "{label}: the request survives a power loss"
                    );
                    assert_eq!(
                        provider.credential(&slot, 0),
                        Ok(Some(b"credential".to_vec())),
                        "{label}"
                    );
                    assert_covered(&device, &mut provider, &label);
                    cases += 1;
                }
            }
        }
        assert!(cases > 600, "{policy:?}: {cases} cases");
    }
}

#[test]
fn wallet_advance_v1_crash_matrix_abandonment() {
    for (index, policy) in POLICIES.into_iter().enumerate() {
        let seed = 0x66 + u8::try_from(index).expect("index");
        let (base, f, slot) = enrolled_device(policy, seed);
        let enrollment = base.open().status(&slot).expect("status");
        let bootstrap =
            advance_request(enrollment.marker().expect("marker"), &bootstrap_capsule(&f));
        let run = |provider: &mut SimProviderV1| provider.abandon_enrollment(&slot);
        let steps = flow_steps(&base, &run);
        let mut cases = 0_usize;
        for step in 0..steps {
            for fault in FAULTS {
                for (recovery_index, recovery) in RECOVERIES.into_iter().enumerate() {
                    let (device, mut provider, outcome) =
                        faulted_case(&base, step, fault, recovery, &run);
                    let label = label("abandon", policy, step, fault, recovery, &outcome);
                    if let Err(error) = &outcome {
                        assert!(
                            matches!(
                                error,
                                KagemushaWalletProviderErrorV1::Unavailable(_)
                                    | KagemushaWalletProviderErrorV1::Uncertain(_)
                                    | KagemushaWalletProviderErrorV1::NoSpace
                            ),
                            "{label}"
                        );
                    }
                    assert_covered(&device, &mut provider, &label);
                    let terminal = matches!(
                        provider.status(&slot).expect(&label),
                        KagemushaWalletSlotStatusV1::Terminal(_)
                    );
                    // Abandonment and Bootstrap compete for generation 1: exactly one wins.
                    if (step + u64::try_from(recovery_index).expect("index")) % 2 == 1 {
                        let advanced = provider.advance(&slot, &TestOwnerV1, &bootstrap);
                        if terminal {
                            assert_eq!(
                                advanced,
                                Err(KagemushaWalletProviderErrorV1::Terminal),
                                "{label}"
                            );
                        } else {
                            assert!(released_of(&advanced).is_some(), "{label}: {advanced:?}");
                            assert_eq!(
                                provider.abandon_enrollment(&slot),
                                Err(KagemushaWalletProviderErrorV1::Invalid {
                                    field: "abandon.bootstrap"
                                }),
                                "{label}"
                            );
                            assert!(outcome.is_err(), "{label}: an abandonment was released");
                            cases += 1;
                            continue;
                        }
                    }
                    let frame = provider.abandon_enrollment(&slot).expect(&label);
                    assert_eq!(
                        provider.abandon_enrollment(&slot).expect(&label),
                        frame,
                        "{label}"
                    );
                    if let Ok(first) = &outcome {
                        assert_eq!(*first, frame, "{label}: retained abandonment");
                    }
                    let abandonment = iroha_data_model::kagemusha::KagemushaWalletAbandonmentV1::decode_canonical(
                        &frame,
                        &f.scheme_id(),
                    )
                    .expect(&label);
                    let status = provider.status(&slot).expect(&label);
                    abandonment
                        .require_terminal_marker(status.marker().expect(&label).marker())
                        .expect(&label);
                    assert_eq!(
                        provider.advance(&slot, &TestOwnerV1, &bootstrap),
                        Err(KagemushaWalletProviderErrorV1::Terminal),
                        "{label}"
                    );
                    assert_covered(&device, &mut provider, &label);
                    // The retained abandonment survives a later power loss unchanged.
                    drop(provider);
                    device.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced, [0xc3; 32]);
                    let mut provider = device.open();
                    assert_eq!(provider.abandon_enrollment(&slot), Ok(frame), "{label}");
                    cases += 1;
                }
            }
        }
        assert!(cases > 300, "{policy:?}: {cases} cases");
    }
}

#[test]
fn wallet_advance_v1_crash_matrix_custody_deletion() {
    for (index, policy) in POLICIES.into_iter().enumerate() {
        let seed = 0x68 + u8::try_from(index).expect("index");
        let (base, _f, slot, _bootstrap) = bootstrapped_device(policy, seed);
        let status = base.open().status(&slot).expect("status");
        let confirmation =
            KagemushaWalletDestructiveConfirmationV1::for_status(slot, &status).expect("confirm");
        let run = |provider: &mut SimProviderV1| provider.delete_custody(&slot, &confirmation);
        let steps = flow_steps(&base, &run);
        let mut cases = 0_usize;
        for step in 0..steps {
            for fault in FAULTS {
                for recovery in RECOVERIES {
                    let (device, mut provider, outcome) =
                        faulted_case(&base, step, fault, recovery, &run);
                    let label = label("delete", policy, step, fault, recovery, &outcome);
                    assert_covered(&device, &mut provider, &label);
                    let status = provider.status(&slot).expect(&label);
                    let terminal = matches!(status, KagemushaWalletSlotStatusV1::Terminal(_));
                    if outcome.is_ok() {
                        assert!(terminal, "{label}: a completed deletion is durable");
                    }
                    if device.platform.key_of(&slot).is_none() {
                        assert!(terminal, "{label}: key deleted before the terminal marker");
                    }
                    let confirmation =
                        KagemushaWalletDestructiveConfirmationV1::for_status(slot, &status)
                            .unwrap_or(confirmation);
                    let deleted = provider.delete_custody(&slot, &confirmation).expect(&label);
                    let KagemushaWalletSlotStatusV1::Terminal(record) = &deleted else {
                        panic!("{label}: {deleted:?}");
                    };
                    assert!(
                        matches!(
                            record.marker().state,
                            iroha_data_model::kagemusha::KagemushaWalletMarkerStateV1::Terminal {
                                reason: KagemushaWalletTerminalReasonV1::CustodyDeleted,
                                ..
                            }
                        ),
                        "{label}"
                    );
                    assert_eq!(device.platform.key_of(&slot), None, "{label}");
                    for dir in [
                        kagemusha_wallet_capsules_dir_v1(&slot),
                        kagemusha_wallet_completion_dir_v1(&slot),
                    ] {
                        assert!(device.fs.visible_names(&dir).is_empty(), "{label}");
                    }
                    assert!(
                        device
                            .fs
                            .visible_names(&kagemusha_wallet_slot_dir_v1(&slot))
                            .iter()
                            .any(|name| name == KAGEMUSHA_WALLET_INTENT_NAME_V1),
                        "{label}: the intent is kept"
                    );
                    assert_covered(&device, &mut provider, &label);
                    cases += 1;
                }
            }
        }
        assert!(cases > 300, "{policy:?}: {cases} cases");
    }
}

/// Read errors at every step of a full reconcile are `Unavailable` (or a retried write's
/// `Uncertain`), never absence: nothing is lost, abandoned or deleted, and the next clean
/// reconcile reaches the same status.
#[test]
fn wallet_advance_v1_crash_matrix_read_errors_are_unavailable() {
    let (released_device, f, slot, bootstrap) =
        bootstrapped_device(KagemushaWalletAnchorPolicyV1::Keychain, 0x6a);
    // A second, intent-only slot exercises the no-marker classification.
    let intent_device = released_device.fork();
    {
        let mut provider = released_device.open();
        let current = provider.status(&slot).expect("status");
        let request = advance_request(
            current.marker().expect("marker"),
            &next_capsule(&f, &bootstrap),
        );
        super::test_support::released(
            provider
                .advance(&slot, &TestOwnerV1, &request)
                .expect("advance"),
        );
    }
    for (name, base) in [("released", &released_device), ("intent", &intent_device)] {
        if name == "intent" {
            base.platform.with(|state| state.next_key_seed = 0x6b);
            base.platform
                .with(|state| state.generate_unavailable = Some(false));
            let mut provider = base.open();
            let _ = provider.test_begin_enrollment(
                &enrollment_challenge(0x6b),
                PROFILE,
                crate::kagemusha_wallet_advance_v1::KagemushaWalletEnrollmentDatesV1 {
                    issued_at_ms: 1,
                    expires_at_ms: 600_001,
                },
            );
            base.platform
                .with(|state| state.generate_unavailable = None);
        }
        let clean: Vec<_> = {
            let device = base.fork();
            let mut provider = device.open();
            provider
                .slots()
                .expect("slots")
                .iter()
                .map(|slot| provider.status(slot))
                .collect()
        };
        let run = |provider: &mut SimProviderV1| -> Vec<_> {
            provider
                .slots()
                .map(|slots| slots.iter().map(|slot| provider.status(slot)).collect())
                .unwrap_or_default()
        };
        let steps = flow_steps(base, &run);
        for step in 0..steps {
            for fault in [
                KagemushaWalletSimFaultV1::Error,
                KagemushaWalletSimFaultV1::ErrorKind(io::ErrorKind::PermissionDenied),
                KagemushaWalletSimFaultV1::ErrorKind(io::ErrorKind::TimedOut),
            ] {
                let device = base.fork();
                let before = all_names(&device);
                let mut provider = device.open();
                device.fs.inject(device.fs.steps() + step, fault);
                for result in run(&mut provider) {
                    let label = format!("{name} step {step} fault {fault:?} result {result:?}");
                    match result {
                        Ok(status) => assert!(clean.contains(&Ok(status)), "{label}"),
                        Err(
                            KagemushaWalletProviderErrorV1::Unavailable(_)
                            | KagemushaWalletProviderErrorV1::Uncertain(_),
                        ) => {}
                        Err(other) => panic!("{label}: {other:?}"),
                    }
                }
                device.fs.clear_faults();
                drop(provider);
                let after = all_names(&device);
                for entry in &before {
                    assert!(after.contains(entry), "{name} step {step}: {entry} removed");
                }
                let mut provider = device.open();
                let recovered: Vec<_> = provider
                    .slots()
                    .expect("slots")
                    .iter()
                    .map(|slot| provider.status(slot))
                    .collect();
                assert_eq!(recovered, clean, "{name} step {step} fault {fault:?}");
            }
        }
    }
}

/// Every non-staging custody file, as `dir/name`.
fn all_names(device: &DeviceV1) -> Vec<String> {
    let mut names = Vec::new();
    let mut queue = vec![KagemushaWalletCustodyDirV1::root()];
    while let Some(dir) = queue.pop() {
        for name in device.fs.visible_names(&dir) {
            if kagemusha_wallet_is_staging_name_v1(&name) {
                continue;
            }
            let entry = KagemushaWalletEntryNameV1::new(&name).expect("name");
            let child = dir.child(&entry);
            if device.fs.visible_dir(&child) {
                queue.push(child);
            } else {
                names.push(format!("{}/{name}", dir.label()));
            }
        }
    }
    names.sort();
    names
}

// ---------------------------------------------------------------------------------------
// Extended matrices: faults inside open, faults during recovery, platform faults, keychain
// write loss, exhaustive survival subsets and restored intermediate snapshots.
// ---------------------------------------------------------------------------------------

/// Seeds of the independent-survival model when a crash point has 12 or more unsynced
/// directory operations (fewer are enumerated exhaustively). Developers may raise it with
/// `KAGEMUSHA_WALLET_CRASH_SEEDS`; test-only, never read outside tests.
fn survival_seeds() -> u64 {
    std::env::var("KAGEMUSHA_WALLET_CRASH_SEEDS")
        .ok()
        .and_then(|seeds| seeds.parse().ok())
        .unwrap_or(1_000)
}

/// Every power-loss model to explore for the unsynced operations pending now on `fs`:
/// every subset when there are fewer than 12, otherwise [`survival_seeds`] seeds.
fn survival_models(fs: &KagemushaWalletSimFsV1) -> Vec<KagemushaWalletSimPowerLossV1> {
    let pending = fs.pending_dir_ops();
    if pending < 12 {
        let subsets = 1_u64 << pending;
        (0..subsets)
            .map(|mask| KagemushaWalletSimPowerLossV1::Subset { mask, seed: mask })
            .collect()
    } else {
        (0..survival_seeds())
            .map(KagemushaWalletSimPowerLossV1::Seeded)
            .collect()
    }
}

/// Resolve an advance case after recovery: optionally try the competitor first, then retry
/// the request twice. Asserts definitive, byte-identical answers and at most one released
/// successor (including `earlier` releases); returns the distinct release, if any.
fn resolve_advance(
    provider: &mut SimProviderV1,
    slot: &KagemushaWalletSlotIdV1,
    request: &KagemushaWalletAdvanceRequestV1<KagemushaWalletRecoveryCapsuleV1>,
    competitor: Option<&KagemushaWalletAdvanceRequestV1<KagemushaWalletRecoveryCapsuleV1>>,
    earlier: &[RetainedV1],
    label: &str,
) -> Option<RetainedV1> {
    let mut releases: Vec<RetainedV1> = earlier.to_vec();
    if let Some(competitor) = competitor {
        let _ = record(
            provider.advance(slot, &TestOwnerV1, competitor),
            &mut releases,
        );
    }
    let retried = record(provider.advance(slot, &TestOwnerV1, request), &mut releases);
    let again = record(provider.advance(slot, &TestOwnerV1, request), &mut releases);
    match (&retried, &again) {
        (Ok(KagemushaWalletAdvanceOutcomeV1::Released { .. }), _) => {
            assert_eq!(released_of(&retried), released_of(&again), "{label}");
        }
        (
            Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
                KagemushaWalletNotPerformedV1::StaleHead,
            ))
            | Err(KagemushaWalletProviderErrorV1::OperationIdConflict { .. }),
            _,
        ) => {}
        other => panic!("{label}: retry not definitive: {other:?}"),
    }
    let mut distinct: Vec<RetainedV1> = Vec::new();
    for retained in releases {
        if !distinct.contains(&retained) {
            distinct.push(retained);
        }
    }
    assert!(distinct.len() <= 1, "{label}: {} releases", distinct.len());
    distinct.pop()
}

/// A device after Bootstrap plus the next request and a competing successor of its head.
fn advance_base(
    policy: KagemushaWalletAnchorPolicyV1,
    seed: u8,
) -> (
    DeviceV1,
    KagemushaWalletSlotIdV1,
    KagemushaWalletAdvanceRequestV1<KagemushaWalletRecoveryCapsuleV1>,
    KagemushaWalletAdvanceRequestV1<KagemushaWalletRecoveryCapsuleV1>,
) {
    let (base, f, slot, bootstrap) = bootstrapped_device(policy, seed);
    let current = base.open().status(&slot).expect("status");
    let head = current.marker().expect("marker").clone();
    let request = advance_request(&head, &next_capsule(&f, &bootstrap));
    let competitor = advance_request(&head, &next_capsule_variant(&f, &bootstrap, 1));
    (base, slot, request, competitor)
}

#[test]
fn wallet_advance_v1_crash_matrix_open() {
    // Faults armed before `open` (sentinel adoption, skeleton preparation), on a fresh root
    // and on an enrolled one; recovery by a same-boot reopen, then optionally power loss.
    for (index, policy) in POLICIES.into_iter().enumerate() {
        let seed = 0x70 + u8::try_from(index).expect("index");
        let fresh = DeviceV1::new(policy, seed);
        let (enrolled, _f, slot) = enrolled_device(policy, seed.wrapping_add(2));
        for (name, base) in [("fresh", &fresh), ("enrolled", &enrolled)] {
            let probe = base.fork();
            let start = probe.fs.steps();
            drop(probe.open());
            let steps = probe.fs.steps() - start;
            assert!(steps > 5, "{name}: {steps}");
            let mut cases = 0_usize;
            for step in 0..steps {
                for fault in FAULTS {
                    for recovery in [
                        None,
                        Some(KagemushaWalletSimPowerLossV1::DropUnsynced),
                        Some(KagemushaWalletSimPowerLossV1::Seeded(3)),
                    ] {
                        let device = base.fork();
                        device.fs.inject(device.fs.steps() + step, fault);
                        let opened = open_provider(&device.fs, &device.platform);
                        let label = format!(
                            "open {name} {policy:?} step {step} fault {fault:?} recovery {recovery:?} opened {}",
                            opened.is_ok()
                        );
                        if let Err(error) = &opened {
                            assert!(
                                matches!(
                                    error,
                                    KagemushaWalletProviderErrorV1::Unavailable(_)
                                        | KagemushaWalletProviderErrorV1::Uncertain(_)
                                        | KagemushaWalletProviderErrorV1::NoSpace
                                ),
                                "{label}: {error:?}"
                            );
                        }
                        drop(opened);
                        device.fs.clear_faults();
                        // The same boot opens again first: this is where a vacuous sync would
                        // have been trusted.
                        device.fs.restart();
                        let mut provider = device.open();
                        if name == "fresh" {
                            // Enroll on the reopened root before any power loss.
                            let _ = provider
                                .test_begin_enrollment(&enrollment_challenge(seed), PROFILE, crate::kagemusha_wallet_advance_v1::KagemushaWalletEnrollmentDatesV1 { issued_at_ms: 1, expires_at_ms: 600_001 })
                                .expect(&label);
                        }
                        drop(provider);
                        if let Some(mode) = recovery {
                            device.power_loss(mode, BOOT_B);
                        } else {
                            device.fs.restart();
                        }
                        let mut provider = device.open();
                        assert_covered(&device, &mut provider, &label);
                        let slots = provider.slots().expect(&label);
                        if name == "enrolled" {
                            assert_eq!(slots, vec![slot], "{label}");
                        } else {
                            assert_eq!(slots.len(), 1, "{label}: the enrolled slot survives");
                        }
                        cases += 1;
                    }
                }
            }
            assert!(cases > 50, "{name}: {cases}");
        }
    }
}

/// A first `first` fault at every step of Advance, a same-boot restart, then a second fault
/// at every step of the recovery reconcile (R0-R10 with a transition owner: the fresh-inode
/// rewrites of R3, the R8 retirement, R9 offline finishing and the anchor raise), then power
/// loss: one successor, byte-identical retries, coverage and durable releases. iOS policy: its
/// recovery is the Android sequence plus the anchor raise.
fn faulted_recovery_matrix(first: KagemushaWalletSimFaultV1, seed: u8) -> usize {
    const SECOND: [KagemushaWalletSimFaultV1; 3] = [
        KagemushaWalletSimFaultV1::LostWriteback,
        KagemushaWalletSimFaultV1::CrashAfter,
        KagemushaWalletSimFaultV1::Error,
    ];
    let policy = KagemushaWalletAnchorPolicyV1::Keychain;
    let (base, slot, request, competitor) = advance_base(policy, seed);
    let run = |provider: &mut SimProviderV1| provider.advance(&slot, &TestOwnerV1, &request);
    let recover = |provider: &mut SimProviderV1| provider.reconcile(&slot, &TestOwnerV1);
    let steps = flow_steps(&base, &run);
    let mut cases = 0_usize;
    let mut rotation = 0_usize;
    for step in 0..steps {
        let (recovered, provider, outcome) =
            faulted_case(&base, step, first, RecoveryV1::Restart, &run);
        drop(provider);
        let earlier: Vec<RetainedV1> = released_of(&outcome).into_iter().collect();
        // Steps of the fault-free recovery reconcile from this state.
        let recovery_steps = flow_steps(&recovered, &recover);
        for second_step in 0..recovery_steps {
            rotation += 1;
            let second = SECOND[rotation % SECOND.len()];
            let device = recovered.fork();
            let mut provider = device.open();
            device.fs.inject(device.fs.steps() + second_step, second);
            let reconciled = provider.reconcile(&slot, &TestOwnerV1);
            device.fs.clear_faults();
            drop(provider);
            device.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced, BOOT_B);
            let label = format!(
                "faulted recovery {first:?} at {step}, then {second:?} at recovery step {second_step}: {reconciled:?}"
            );
            if let Err(error) = &reconciled {
                assert!(
                    matches!(
                        error,
                        KagemushaWalletProviderErrorV1::Unavailable(_)
                            | KagemushaWalletProviderErrorV1::Uncertain(_)
                            | KagemushaWalletProviderErrorV1::NoSpace
                    ),
                    "{label}: inadmissible error"
                );
            }
            let mut provider = device.open();
            assert_covered(&device, &mut provider, &label);
            let competitor = (rotation % 2 == 0).then_some(&competitor);
            let winner =
                resolve_advance(&mut provider, &slot, &request, competitor, &earlier, &label);
            assert_covered(&device, &mut provider, &label);
            // What was released stays released after another power loss.
            if let Some(winner) = winner {
                let winning = if winner.operation_id == request.operation_id {
                    &request
                } else {
                    competitor.expect("competitor won")
                };
                drop(provider);
                device.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced, [0xc4; 32]);
                let mut provider = device.open();
                assert_eq!(
                    released_of(&provider.advance(&slot, &TestOwnerV1, winning)),
                    Some(winner),
                    "{label}: durable"
                );
            }
            cases += 1;
        }
    }
    eprintln!("faulted recovery {first:?}: {cases} cases");
    cases
}

#[test]
fn wallet_advance_v1_crash_matrix_faulted_recovery_after_lost_writeback() {
    let cases = faulted_recovery_matrix(KagemushaWalletSimFaultV1::LostWriteback, 0x74);
    assert!(cases > 300, "{cases}");
}

#[test]
fn wallet_advance_v1_crash_matrix_faulted_recovery_after_crash() {
    let cases = faulted_recovery_matrix(KagemushaWalletSimFaultV1::CrashAfter, 0x75);
    assert!(cases > 300, "{cases}");
}

/// One platform fault armed for a flow.
#[derive(Debug, Clone, Copy)]
enum PlatformFaultV1 {
    /// The anchor write with this index behaves as given.
    AnchorWrite(usize, AnchorWriteV1),
    /// The `key_sign` call with this index is unavailable.
    Sign(usize),
    /// The `key_probe` call with this index is unavailable.
    Probe(usize),
    /// Storage locks after this many further storage checks.
    StorageLockAfter(usize),
}

impl PlatformFaultV1 {
    fn arm(self, platform: &super::test_support::FakePlatformV1) {
        platform.with(|state| match self {
            Self::AnchorWrite(at, mode) => {
                state.anchor_fault_at = Some((state.anchor_writes + at, mode));
            }
            Self::Sign(at) => state.sign_fault_at = Some(state.sign_calls + at),
            Self::Probe(at) => state.probe_fault_at = Some(state.probe_calls + at),
            Self::StorageLockAfter(after) => state.storage_lock_after = Some(after),
        });
    }
}

/// Every platform fault for a flow that makes the given numbers of platform calls.
fn platform_faults(
    anchor_writes: usize,
    signs: usize,
    probes: usize,
    storage_checks: usize,
) -> Vec<PlatformFaultV1> {
    let mut faults = Vec::new();
    for at in 0..anchor_writes {
        for mode in [
            AnchorWriteV1::Refused,
            AnchorWriteV1::UncertainApplied,
            AnchorWriteV1::UncertainLost,
        ] {
            faults.push(PlatformFaultV1::AnchorWrite(at, mode));
        }
    }
    faults.extend((0..signs).map(PlatformFaultV1::Sign));
    faults.extend((0..probes).map(PlatformFaultV1::Probe));
    faults.extend((0..storage_checks).map(PlatformFaultV1::StorageLockAfter));
    faults
}

/// Platform calls `flow` makes on a fresh provider over a fork of `base` (after opening it).
fn platform_counts<T>(
    base: &DeviceV1,
    flow: &dyn Fn(&mut SimProviderV1) -> T,
) -> (usize, usize, usize, usize) {
    let device = base.fork();
    let mut provider = device.open();
    let before = device.platform.with(|state| {
        (
            state.anchor_writes,
            state.sign_calls,
            state.probe_calls,
            state.storage_calls,
        )
    });
    let _ = flow(&mut provider);
    let after = device.platform.with(|state| {
        (
            state.anchor_writes,
            state.sign_calls,
            state.probe_calls,
            state.storage_calls,
        )
    });
    (
        after.0 - before.0,
        after.1 - before.1,
        after.2 - before.2,
        after.3 - before.3,
    )
}

#[test]
fn wallet_advance_v1_crash_matrix_platform_faults_advance() {
    // Anchor writes refused, applied or lost behind an uncertain answer, signing unavailable,
    // key probes unavailable and storage locking at every call of Advance (A10 included).
    for (index, policy) in POLICIES.into_iter().enumerate() {
        let (base, slot, request, competitor) =
            advance_base(policy, 0x76 + u8::try_from(index).expect("index"));
        let base_generation = *visible_markers(&base, &slot).last().expect("marker");
        let run = |provider: &mut SimProviderV1| provider.advance(&slot, &TestOwnerV1, &request);
        let (anchors, signs, probes, storage) = platform_counts(&base, &run);
        if policy == KagemushaWalletAnchorPolicyV1::Keychain {
            assert!(anchors > 0, "the release raises the anchor");
        }
        let mut cases = 0_usize;
        for (fault_index, fault) in platform_faults(anchors, signs, probes, storage)
            .into_iter()
            .enumerate()
        {
            for recovery in [
                RecoveryV1::SameProcess,
                RecoveryV1::Restart,
                RecoveryV1::PowerLoss(KagemushaWalletSimPowerLossV1::DropUnsynced),
            ] {
                let device = base.fork();
                let mut provider = device.open();
                fault.arm(&device.platform);
                let outcome = provider.advance(&slot, &TestOwnerV1, &request);
                device.platform.clear_faults();
                let label = format!(
                    "platform {policy:?} {fault:?} recovery {recovery:?} outcome {outcome:?}"
                );
                assert_admissible(&outcome, &label);
                let durable = device.fork();
                durable
                    .fs
                    .power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
                assert_selection_reported(
                    &outcome,
                    &AfterCallV1 {
                        crashed: false,
                        visible: visible_markers(&device, &slot),
                        durable: visible_markers(&durable, &slot),
                    },
                    base_generation,
                    &label,
                );
                let mut provider = match recovery {
                    RecoveryV1::SameProcess => provider,
                    RecoveryV1::Restart => {
                        drop(provider);
                        device.fs.restart();
                        device.open()
                    }
                    RecoveryV1::PowerLoss(mode) => {
                        drop(provider);
                        device.power_loss(mode, BOOT_B);
                        device.open()
                    }
                };
                assert_covered(&device, &mut provider, &label);
                let earlier: Vec<RetainedV1> = released_of(&outcome).into_iter().collect();
                let competitor = (fault_index % 2 == 1).then_some(&competitor);
                resolve_advance(&mut provider, &slot, &request, competitor, &earlier, &label);
                assert_covered(&device, &mut provider, &label);
                cases += 1;
            }
        }
        // Every fault kind is reached: a signature, key probes and storage checks (and on iOS
        // the anchor raise), each under three recoveries.
        assert!(signs > 0 && probes > 0 && storage > 0, "{policy:?}");
        assert!(cases >= 20, "{policy:?}: {cases}");
    }
}

#[test]
fn wallet_advance_v1_crash_matrix_platform_faults_lifecycle() {
    // The same platform faults during enrollment (E2/E4 anchor), abandonment (T2) and custody
    // deletion (D2, D3): every outcome is retryable and the flow completes once the faults
    // clear, with the key never generated, signed or deleted outside its state.
    for (index, policy) in POLICIES.into_iter().enumerate() {
        let seed = 0x78 + u8::try_from(index).expect("index");
        // Enrollment.
        let fresh = DeviceV1::new(policy, seed);
        let enroll = |provider: &mut SimProviderV1| {
            provider.test_begin_enrollment(
                &enrollment_challenge(seed),
                PROFILE,
                crate::kagemusha_wallet_advance_v1::KagemushaWalletEnrollmentDatesV1 {
                    issued_at_ms: 1,
                    expires_at_ms: 600_001,
                },
            )
        };
        let (anchors, signs, probes, storage) = platform_counts(&fresh, &enroll);
        for fault in platform_faults(anchors, signs, probes, storage) {
            let device = fresh.fork();
            let mut provider = device.open();
            fault.arm(&device.platform);
            let outcome = enroll(&mut provider);
            device.platform.clear_faults();
            let label = format!("enroll {policy:?} {fault:?} outcome {outcome:?}");
            if let Err(error) = &outcome {
                assert!(
                    matches!(
                        error,
                        KagemushaWalletProviderErrorV1::Unavailable(_)
                            | KagemushaWalletProviderErrorV1::Uncertain(_)
                    ),
                    "{label}"
                );
            }
            drop(provider);
            device.fs.restart();
            let mut provider = device.open();
            assert_covered(&device, &mut provider, &label);
            let slot = finish_enrollment(&mut provider, &device, seed, &label);
            assert!(
                matches!(
                    provider.status(&slot),
                    Ok(KagemushaWalletSlotStatusV1::Enrollment(_))
                ),
                "{label}"
            );
            assert_covered(&device, &mut provider, &label);
        }
        // Abandonment and custody deletion.
        let (enrolled, _f, slot) = enrolled_device(policy, seed.wrapping_add(4));
        let (released, _f, released_slot, _) = bootstrapped_device(policy, seed.wrapping_add(6));
        let status = released.open().status(&released_slot).expect("status");
        let confirmation =
            KagemushaWalletDestructiveConfirmationV1::for_status(released_slot, &status)
                .expect("confirmation");
        let abandon = |provider: &mut SimProviderV1| provider.abandon_enrollment(&slot).map(|_| ());
        let delete = |provider: &mut SimProviderV1| {
            provider
                .delete_custody(&released_slot, &confirmation)
                .map(|_| ())
        };
        let flows: [(
            &str,
            &DeviceV1,
            KagemushaWalletSlotIdV1,
            &dyn Fn(&mut SimProviderV1) -> Result<(), KagemushaWalletProviderErrorV1>,
        ); 2] = [
            ("abandon", &enrolled, slot, &abandon),
            ("delete", &released, released_slot, &delete),
        ];
        for (name, base, flow_slot, flow) in flows {
            let (anchors, signs, probes, storage) = platform_counts(base, flow);
            for fault in platform_faults(anchors, signs, probes, storage) {
                let device = base.fork();
                let mut provider = device.open();
                fault.arm(&device.platform);
                let outcome = flow(&mut provider);
                device.platform.clear_faults();
                let label = format!("{name} {policy:?} {fault:?} outcome {outcome:?}");
                if let Err(error) = &outcome {
                    assert!(
                        matches!(
                            error,
                            KagemushaWalletProviderErrorV1::Unavailable(_)
                                | KagemushaWalletProviderErrorV1::Uncertain(_)
                        ),
                        "{label}"
                    );
                }
                drop(provider);
                device.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced, BOOT_B);
                let mut provider = device.open();
                assert_covered(&device, &mut provider, &label);
                flow(&mut provider).expect(&label);
                assert!(
                    matches!(
                        provider.status(&flow_slot),
                        Ok(KagemushaWalletSlotStatusV1::Terminal(_))
                    ),
                    "{label}"
                );
                assert_covered(&device, &mut provider, &label);
            }
        }
    }
}

#[test]
fn wallet_advance_v1_crash_matrix_keychain_write_loss() {
    // Keychain power-loss model: the last anchor write may not survive a power loss. At every
    // crash point of Advance, losing it never produces a false rollback verdict and never a
    // second successor.
    let (base, slot, request, competitor) =
        advance_base(KagemushaWalletAnchorPolicyV1::Keychain, 0x7c);
    let run = |provider: &mut SimProviderV1| provider.advance(&slot, &TestOwnerV1, &request);
    let steps = flow_steps(&base, &run);
    let mut cases = 0_usize;
    for step in 0..steps {
        for lose in [false, true] {
            let device = base.fork();
            let mut provider = device.open();
            device.fs.inject(
                device.fs.steps() + step,
                KagemushaWalletSimFaultV1::CrashAfter,
            );
            let _ = provider.advance(&slot, &TestOwnerV1, &request);
            drop(provider);
            device.fs.clear_faults();
            device.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced, BOOT_B);
            if lose {
                device.platform.lose_last_anchor_writes();
            }
            let label = format!("keychain loss step {step} lose {lose}");
            let mut provider = device.open();
            assert_covered(&device, &mut provider, &label);
            let competitor = (step % 2 == 0).then_some(&competitor);
            resolve_advance(&mut provider, &slot, &request, competitor, &[], &label);
            assert_covered(&device, &mut provider, &label);
            cases += 1;
        }
    }
    assert!(cases > 40, "{cases}");
}

#[test]
fn wallet_advance_v1_crash_matrix_keychain_residual_window_is_documented() {
    // Design risk (iOS residual window, test plan item iii): if the last anchor raise is lost
    // to power loss and the files are then restored to exactly the state before that Advance,
    // the rollback is not detected. Two independent events are needed. This test pins the
    // current behaviour so a future fix (for example raising the anchor before release
    // acknowledgement is reported) must update it deliberately.
    // TODO(G2-iOS): device power-cut tests of `SecItemUpdate` durability.
    let (device, slot, request, _competitor) =
        advance_base(KagemushaWalletAnchorPolicyV1::Keychain, 0x7d);
    let before = device.fork();
    let mut provider = device.open();
    released(
        provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("advance"),
    );
    drop(provider);
    device.platform.lose_last_anchor_writes();
    let restored = DeviceV1 {
        fs: before.fs.fork(),
        platform: device.platform.fork(None),
    };
    let status = restored.open().status(&slot);
    assert!(
        matches!(status, Ok(KagemushaWalletSlotStatusV1::Released(ref record)) if record.generation() == 2),
        "residual window: {status:?}"
    );
    // Without the lost write the same restore is a rollback.
    let (device, slot, request, _competitor) =
        advance_base(KagemushaWalletAnchorPolicyV1::Keychain, 0x7e);
    let before = device.fork();
    let mut provider = device.open();
    released(
        provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("advance"),
    );
    drop(provider);
    let restored = DeviceV1 {
        fs: before.fs.fork(),
        platform: device.platform.fork(None),
    };
    assert_eq!(
        restored.open().status(&slot),
        Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::RolledBack
        ))
    );
}

#[test]
fn wallet_advance_v1_crash_matrix_independent_survival() {
    // (L*) At every crash point of Advance, every subset of the unsynced directory operations
    // survives (exhaustively below 12 operations, otherwise `survival_seeds` seeds): one
    // successor, definitive byte-identical retries, coverage and durable releases.
    for (index, policy) in POLICIES.into_iter().enumerate() {
        let (base, slot, request, competitor) =
            advance_base(policy, 0x80 + u8::try_from(index).expect("index"));
        let run = |provider: &mut SimProviderV1| provider.advance(&slot, &TestOwnerV1, &request);
        let steps = flow_steps(&base, &run);
        let mut cases = 0_usize;
        let mut widest = 0_usize;
        for step in 0..steps {
            let crashed = base.fork();
            let mut provider = crashed.open();
            crashed.fs.inject(
                crashed.fs.steps() + step,
                KagemushaWalletSimFaultV1::CrashAfter,
            );
            let _ = provider.advance(&slot, &TestOwnerV1, &request);
            drop(provider);
            crashed.fs.clear_faults();
            widest = widest.max(crashed.fs.pending_dir_ops());
            for (model_index, model) in survival_models(&crashed.fs).into_iter().enumerate() {
                let device = crashed.fork();
                device.power_loss(model, BOOT_B);
                let label = format!("survival {policy:?} step {step} model {model:?}");
                let mut provider = device.open();
                assert_covered(&device, &mut provider, &label);
                let competitor = (model_index % 2 == 1).then_some(&competitor);
                let winner =
                    resolve_advance(&mut provider, &slot, &request, competitor, &[], &label);
                if let Some(winner) = winner {
                    let winning = if winner.operation_id == request.operation_id {
                        &request
                    } else {
                        competitor.expect("competitor won")
                    };
                    drop(provider);
                    device.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced, [0xc5; 32]);
                    let mut provider = device.open();
                    assert_eq!(
                        released_of(&provider.advance(&slot, &TestOwnerV1, winning)),
                        Some(winner),
                        "{label}: durable"
                    );
                }
                cases += 1;
            }
        }
        assert!(
            widest > 1,
            "{policy:?}: some crash point leaves unsynced operations"
        );
        assert!(
            cases > usize::try_from(steps).expect("steps"),
            "{policy:?}: {cases}"
        );
        eprintln!("independent survival {policy:?}: {cases} cases, widest {widest}");
    }
}

#[test]
fn wallet_advance_v1_crash_matrix_restored_snapshots() {
    // (I11) iOS: the files as they stood at every intermediate point of an Advance, restored
    // after it completed while the keychain anchor survived, are a rollback or the same
    // released head; never an older head that could sign again.
    let (base, slot, request, _competitor) =
        advance_base(KagemushaWalletAnchorPolicyV1::Keychain, 0x82);
    let run = |provider: &mut SimProviderV1| provider.advance(&slot, &TestOwnerV1, &request);
    let steps = flow_steps(&base, &run);
    let mut rolled_back = 0_usize;
    let mut same_head = 0_usize;
    for step in 0..steps {
        let device = base.fork();
        let mut provider = device.open();
        device.fs.inject(
            device.fs.steps() + step,
            KagemushaWalletSimFaultV1::CrashAfter,
        );
        let _ = provider.advance(&slot, &TestOwnerV1, &request);
        drop(provider);
        device.fs.clear_faults();
        let snapshot = device.fs.fork();
        device.fs.restart();
        let mut provider = device.open();
        let retained = released(
            provider
                .advance(&slot, &TestOwnerV1, &request)
                .expect("finished"),
        );
        let head = provider.status(&slot).expect("status");
        let head = head.marker().expect("head").clone();
        drop(provider);
        let restored = DeviceV1 {
            fs: snapshot,
            platform: device.platform.fork(None),
        };
        restored.fs.restart();
        let signed = restored.platform.with(|state| state.sign_calls);
        let mut provider = restored.open();
        let label = format!("snapshot step {step}");
        match provider.reconcile(&slot, &TestOwnerV1) {
            Err(KagemushaWalletProviderErrorV1::LostCustody(
                KagemushaWalletLostCustodyV1::RolledBack,
            )) => rolled_back += 1,
            Ok(KagemushaWalletSlotStatusV1::Released(record)) => {
                assert_eq!(
                    record.marker_file_digest(),
                    head.marker_file_digest(),
                    "{label}"
                );
                assert_eq!(
                    released_of(&provider.advance(&slot, &TestOwnerV1, &request)),
                    Some(retained.clone()),
                    "{label}"
                );
                same_head += 1;
            }
            other => panic!("{label}: {other:?}"),
        }
        assert_eq!(
            restored.platform.with(|state| state.sign_calls),
            signed,
            "{label}: a restored snapshot never signs"
        );
    }
    assert!(
        rolled_back > 0 && same_head > 0,
        "{rolled_back} {same_head}"
    );
}
