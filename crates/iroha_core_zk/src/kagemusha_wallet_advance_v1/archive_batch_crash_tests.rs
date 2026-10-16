//! Crash matrices of the provider archive batch (ML §7 flows 1-4).
//!
//! Each flow runs on forks of a prepared device with one fault at each selected filesystem
//! step, then recovers in the same process, after a restart or after a power loss. A crash
//! inside the batch publication is also recovered under every subset of the unsynced
//! directory operations it leaves when fewer than 12 are pending, as the provider crash
//! matrices do; otherwise under structured subsets and the provider matrices' seeded models
//! (`KAGEMUSHA_WALLET_CRASH_SEEDS`, default 1,000). After recovery each case checks:
//!
//! - **D1** durable before authority: a marker naming the checkpoint, a selected Advance or a
//!   removal implies every record staged before it is present and exact;
//! - **D2** outcome truth: an answer is durable after a power loss; an error poisons the slot,
//!   publishes nothing when it precedes the first rename and is uncertain after one;
//! - **D3** no torn names: every visible record copy is absent or exact;
//! - **D4** retry: the same call publishes, adopting every visible copy on a fresh inode;
//! - **D5** pointer order: Frozen ⇒ Capsule ⇒ Preparation ⇒ its staged plan;
//! - **D6** the platform guards record no violation; for Advance, the release of the faulted
//!   call is the one every retry returns, byte for byte (I3, I4), and an answer of "not
//!   performed" selected nothing (I8);
//! - **D7** after a restart, the first full reconcile leaves no staging name in the archive
//!   directory.
//!
//! Flow 1 runs the full matrix at one and three records and a structured sample at 33 records,
//! whose 68 copies cross the 64-file chunk of production chunking (four seeded models per
//! crash there). Chunk boundaries at small sizes, with every survival subset, are covered by
//! the store-level batch matrix (`store_tests.rs`).

use std::{collections::BTreeSet, fmt::Debug, io};

use iroha_data_model::kagemusha::{
    KagemushaWalletCompletionRecordV1, KagemushaWalletRecoveryCapsuleV1,
};

use super::{
    batch_tests::{
        RecordV1, assert_absent, assert_absent_or_exact, assert_exact, assert_no_archive_residue,
        copies, copy_states, durable_view, framed, records,
    },
    *,
};
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletAdvanceOutcomeV1, KagemushaWalletAdvanceRequestV1,
    KagemushaWalletAnchorPolicyV1 as Policy, KagemushaWalletSimFaultV1 as Fault,
    KagemushaWalletSimPowerLossV1 as PowerLoss, KagemushaWalletSimStepV1 as Step,
    crash_matrix_tests::survival_seeds,
    store::KAGEMUSHA_WALLET_BATCH_LIVE_STAGED_V1,
    test_support::{
        BOOT_B, DeviceV1, SimProviderV1, TestOwnerV1, advance_request, bootstrap_capsule,
        bootstrapped_device, enrolled_device, next_capsule,
    },
};

type AdvanceResultV1 =
    Result<KagemushaWalletAdvanceOutcomeV1<KagemushaWalletCompletionRecordV1>, Error>;

const FAULTS: [Fault; 6] = [
    Fault::Error,
    Fault::ErrorKind(io::ErrorKind::StorageFull),
    Fault::PartialWrite,
    Fault::LostWriteback,
    Fault::CrashBefore,
    Fault::CrashAfter,
];

/// How the device recovers after the faulted call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryV1 {
    /// The process continues with the same provider (when it did not crash).
    SameProcess,
    /// The process restarts; visible state survives.
    Restart,
    /// Power is lost; only durable state survives, as the model decides.
    PowerLoss(PowerLoss),
}

const RECOVERIES: [RecoveryV1; 3] = [
    RecoveryV1::SameProcess,
    RecoveryV1::Restart,
    RecoveryV1::PowerLoss(PowerLoss::DropUnsynced),
];

/// One recovered case.
struct CaseV1<T> {
    label: String,
    step: u64,
    fault: Fault,
    recovery: RecoveryV1,
    outcome: T,
    /// The faulted call crashed the simulated process (its outcome is never seen).
    crashed: bool,
    /// The slot's verified state was dropped by the call (an error poisons it).
    poisoned: bool,
    /// Visible state right after the call, before recovery.
    after_call: DeviceV1,
    /// What a power loss right after the call would keep.
    durable: DeviceV1,
    /// The device and provider after recovery.
    device: DeviceV1,
    provider: SimProviderV1,
}

impl<T> CaseV1<T> {
    // Whether the retry runs in the same process with the slot still verified, so records the
    // call published are answered from the exact-bytes memo (no fresh inode is expected then).
    // A poisoned slot reconciles fully first, which forgets the memo; a new process has none.
    fn remembered(&self) -> bool {
        self.recovery == RecoveryV1::SameProcess && !self.crashed && !self.poisoned
    }
}

/// One flow on forks of `base`.
struct MatrixV1<'a, T> {
    name: String,
    base: &'a DeviceV1,
    slot: Slot,
    flow: &'a dyn Fn(&mut SimProviderV1) -> T,
}

/// Steps of the batch publication in a trace: its first staging step, first rename and
/// directory sync (the first create-new rename of every flow is its batch's).
#[derive(Debug, Clone, Copy)]
struct WindowV1 {
    start: u64,
    rename: u64,
    sync: u64,
}

impl WindowV1 {
    fn of(trace: &[Step]) -> Self {
        let rename = trace
            .iter()
            .position(|step| *step == Step::RenameNoReplace)
            .expect("batch rename");
        let sync = rename
            + trace[rename..]
                .iter()
                .position(|step| *step == Step::SyncDir)
                .expect("batch directory sync");
        let mut start = rename;
        while start > 0
            && matches!(
                trace[start - 1],
                Step::CreateNew | Step::Write | Step::SyncFile
            )
        {
            start -= 1;
        }
        let step = |index: usize| u64::try_from(index).expect("step");
        Self {
            start: step(start),
            rename: step(rename),
            sync: step(sync),
        }
    }

    fn contains(&self, step: u64) -> bool {
        (self.start..=self.sync).contains(&step)
    }

    // Whether a non-crashing fault at `step` must leave the batch uncertain: from the first
    // rename to the directory sync it is, except for a definitive refusal of the first rename
    // itself (before it nothing is published).
    fn requires_uncertain(&self, step: u64, fault: Fault) -> bool {
        (self.rename..=self.sync).contains(&step)
            && !(step == self.rename && fault == Fault::ErrorKind(io::ErrorKind::StorageFull))
    }
}

/// Survival models of `pending` unsynced directory operations left by a crash: every subset
/// when fewer than 12 are pending (as the provider crash matrices); otherwise every prefix and
/// suffix, each single loss, alternating subsets and seeded models, [`survival_seeds`] of them
/// when `dense` (a sparse run explores every eighth cut and four seeds).
fn survival(pending: usize, dense: bool) -> Vec<PowerLoss> {
    if pending == 0 {
        return vec![PowerLoss::DropUnsynced];
    }
    if pending < 12 {
        return (0..1_u64 << pending)
            .map(|mask| PowerLoss::Subset { mask, seed: mask })
            .collect();
    }
    let ops = pending.min(64);
    let all = u64::MAX >> (64 - ops);
    let mut masks = BTreeSet::new();
    for cut in (0..=ops).filter(|cut| dense || cut % 8 == 0 || *cut == ops) {
        let prefix = if cut == 0 { 0 } else { u64::MAX >> (64 - cut) };
        masks.insert(prefix);
        masks.insert(all & !prefix);
    }
    for op in (0..ops).filter(|op| dense || *op < 4 || *op + 4 >= ops) {
        masks.insert(all & !(1_u64 << op));
    }
    masks.insert(all & 0x5555_5555_5555_5555);
    masks.insert(all & 0xaaaa_aaaa_aaaa_aaaa);
    masks
        .into_iter()
        .map(|mask| PowerLoss::Subset { mask, seed: mask })
        .chain((0..if dense { survival_seeds() } else { 4 }).map(PowerLoss::Seeded))
        .collect()
}

/// A structured sample of `trace`: every step outside staging, renames and reads, the first
/// and last step of each kind in every run of them (each chunk's boundaries), and 16 seeded
/// steps.
fn sampled_steps(trace: &[Step]) -> Vec<u64> {
    let group = |step: &Step| match step {
        Step::CreateNew | Step::Write | Step::SyncFile => 1,
        Step::RenameNoReplace | Step::RenameReplace => 2,
        Step::Read => 3,
        _ => 0,
    };
    let mut picked = BTreeSet::new();
    let mut start = 0;
    while start < trace.len() {
        let kind = group(&trace[start]);
        let mut end = start;
        while end + 1 < trace.len() && group(&trace[end + 1]) == kind {
            end += 1;
        }
        if kind == 0 {
            picked.extend(start..=end);
        } else {
            for step in [
                Step::CreateNew,
                Step::Write,
                Step::SyncFile,
                Step::RenameNoReplace,
                Step::RenameReplace,
                Step::Read,
            ] {
                let hits: Vec<usize> = (start..=end).filter(|at| trace[*at] == step).collect();
                picked.extend(hits.first().copied());
                picked.extend(hits.last().copied());
            }
        }
        start = end + 1;
    }
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    for _ in 0..16 {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        picked.insert(usize::try_from(seed >> 33).expect("index") % trace.len());
    }
    picked
        .into_iter()
        .map(|at| u64::try_from(at).expect("step"))
        .collect()
}

impl<T: Clone + Debug> MatrixV1<'_, T> {
    fn trace(&self) -> Vec<Step> {
        let device = self.base.fork();
        let mut provider = device.open();
        let start = device.fs.steps();
        let _ = (self.flow)(&mut provider);
        device.fs.trace_since(start)
    }

    fn case(&self, step: u64, fault: Fault, recovery: RecoveryV1) -> CaseV1<T> {
        let device = self.base.fork();
        let mut provider = device.open();
        device.fs.inject(device.fs.steps() + step, fault);
        let outcome = (self.flow)(&mut provider);
        device.fs.clear_faults();
        let crashed = device.fs.crashed();
        let poisoned = !provider.cache.contains_key(&self.slot);
        let after_call = device.fork();
        let durable = durable_view(&device);
        let provider = match recovery {
            RecoveryV1::SameProcess if !crashed => provider,
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
        CaseV1 {
            label: format!(
                "{} step {step} fault {fault:?} recovery {recovery:?} outcome {outcome:?}",
                self.name
            ),
            step,
            fault,
            recovery,
            outcome,
            crashed,
            poisoned,
            after_call,
            durable,
            device,
            provider,
        }
    }

    /// Every case: each step × fault × recovery, and every survival model of a crash after a
    /// step inside `window`. Returns the number of cases.
    fn run(
        &self,
        steps: &[u64],
        faults: &[Fault],
        recoveries: &[RecoveryV1],
        window: WindowV1,
        dense: bool,
        check: &mut dyn FnMut(CaseV1<T>),
    ) -> usize {
        let mut cases = 0_usize;
        for &step in steps {
            for &fault in faults {
                for &recovery in recoveries {
                    check(self.case(step, fault, recovery));
                    cases += 1;
                }
                if fault != Fault::CrashAfter || !window.contains(step) {
                    continue;
                }
                let crashed = self.base.fork();
                let mut provider = crashed.open();
                crashed.fs.inject(crashed.fs.steps() + step, fault);
                let outcome = (self.flow)(&mut provider);
                drop(provider);
                crashed.fs.clear_faults();
                let durable = durable_view(&crashed);
                for model in survival(crashed.fs.pending_dir_ops(), dense) {
                    let device = crashed.fork();
                    device.power_loss(model, BOOT_B);
                    let provider = device.open();
                    check(CaseV1 {
                        label: format!("{} step {step} crash, survival {model:?}", self.name),
                        step,
                        fault,
                        recovery: RecoveryV1::PowerLoss(model),
                        outcome: outcome.clone(),
                        crashed: true,
                        poisoned: true,
                        after_call: crashed.fork(),
                        durable: durable.fork(),
                        device,
                        provider,
                    });
                    cases += 1;
                }
            }
        }
        cases
    }
}

/// Inodes of the visible copies of `staged`.
fn visible_inodes(device: &DeviceV1, slot: &Slot, staged: &[RecordV1]) -> Vec<(String, u64)> {
    let dir = kagemusha_wallet_archive_dir_v1(slot);
    staged
        .iter()
        .flat_map(|(key, _)| copies(key))
        .filter_map(|name| device.fs.inode_of(&dir, &name).map(|inode| (name, inode)))
        .collect()
}

/// D4: every copy visible before a retry is adopted on a fresh inode by it.
fn assert_fresh_inodes(device: &DeviceV1, slot: &Slot, before: &[(String, u64)], label: &str) {
    let dir = kagemusha_wallet_archive_dir_v1(slot);
    for (name, inode) in before {
        assert_ne!(
            device.fs.inode_of(&dir, name),
            Some(*inode),
            "{label}: {name} adopted on a fresh inode"
        );
    }
}

/// D2 for an error: the slot is poisoned, nothing is published before the first rename and
/// the batch is uncertain from it on; never a conflict or custody loss.
fn assert_error_truth(
    error: &Error,
    case: (u64, Fault, bool),
    window: WindowV1,
    after_call: &DeviceV1,
    slot: &Slot,
    staged: &[RecordV1],
    label: &str,
) {
    let (step, fault, poisoned) = case;
    assert!(
        !matches!(
            error,
            Error::Invalid { .. }
                | Error::UnavailableCustodyData { .. }
                | Error::LostCustody(_)
                | Error::KeyLost
        ),
        "{label}: a storage fault is never a conflict or custody loss"
    );
    if window.contains(step) {
        assert!(poisoned, "{label}: a failed drain poisons the slot");
    }
    if step < window.rename {
        assert_absent(after_call, slot, staged, label);
    }
    if window.requires_uncertain(step, fault) {
        assert!(
            matches!(error, Error::Uncertain(_)),
            "{label}: a batch that failed after a rename is uncertain"
        );
    }
}

/// D7, then the final state is durable: after a restart the first reconcile is full and leaves
/// no archive staging residue.
fn reopen_without_residue(device: &DeviceV1, slot: &Slot, label: &str) -> SimProviderV1 {
    device.fs.restart();
    let mut provider = device.open();
    provider
        .status(slot)
        .unwrap_or_else(|error| panic!("{label}: reconcile {error:?}"));
    assert_no_archive_residue(device, slot, label);
    provider
}

// ---------------------------------------------------------------------------------------
// Flow 1: a staged batch, then the archive checkpoint publication.
// ---------------------------------------------------------------------------------------

const MANIFEST: &[u8] = b"flow one archive manifest";

fn publish_staged(
    provider: &mut SimProviderV1,
    slot: &Slot,
    staged: &[RecordV1],
    expected: [u8; 32],
) -> Result<[u8; 32], Error> {
    provider.open_archive_call(slot);
    for (key, bytes) in staged {
        provider.stage_archive_record(slot, key, bytes, None)?;
    }
    provider.publish_archive_checkpoint(slot, expected, MANIFEST)
}

fn checkpoint_copies(device: &DeviceV1, slot: &Slot) -> [Option<Vec<u8>>; 2] {
    let dir = kagemusha_wallet_archive_dir_v1(slot);
    names(&kagemusha_wallet_archive_checkpoint_digest_v1(MANIFEST))
        .map(|name| device.fs.visible_file(&dir, name.as_str()))
}

fn checkpoint_matrix(policy: Policy, seed: u8, count: u8, sampled: bool) -> usize {
    let (base, _, slot, boot) = bootstrapped_device(policy, seed);
    let staged = records(0x10, count);
    let digest = kagemusha_wallet_archive_checkpoint_digest_v1(MANIFEST);
    let retained = base
        .open()
        .lookup(&slot, &boot.operation_id())
        .expect("lookup");
    let flow = |provider: &mut SimProviderV1| publish_staged(provider, &slot, &staged, [0; 32]);
    let matrix = MatrixV1 {
        name: format!("checkpoint {policy:?} records {count}"),
        base: &base,
        slot,
        flow: &flow,
    };
    let trace = matrix.trace();
    let window = WindowV1::of(&trace);
    let copies_total = 2 * usize::from(count) + 2;
    assert_eq!(
        trace[usize::try_from(window.rename).expect("step")..]
            .iter()
            .filter(|step| **step == Step::RenameNoReplace)
            .count(),
        copies_total + 1,
        "every record copy, both checkpoint copies and the marker are renamed create-new"
    );
    if copies_total > KAGEMUSHA_WALLET_BATCH_LIVE_STAGED_V1 {
        let window_steps = &trace[usize::try_from(window.rename).expect("step")
            ..usize::try_from(window.sync).expect("step")];
        assert!(
            window_steps.contains(&Step::CreateNew),
            "the batch crosses a production chunk"
        );
    }
    let all: Vec<u64> = (0..u64::try_from(trace.len()).expect("steps")).collect();
    let (steps, faults, recoveries): (Vec<u64>, &[Fault], &[RecoveryV1]) = if sampled {
        (
            sampled_steps(&trace),
            &[Fault::Error, Fault::LostWriteback, Fault::CrashAfter],
            &[
                RecoveryV1::SameProcess,
                RecoveryV1::PowerLoss(PowerLoss::DropUnsynced),
            ],
        )
    } else {
        (all, &FAULTS, &RECOVERIES)
    };
    let mut check = |case: CaseV1<Result<[u8; 32], Error>>| {
        let remembered = case.remembered();
        let CaseV1 {
            label,
            step,
            fault,
            outcome,
            crashed,
            poisoned,
            after_call,
            durable,
            device,
            mut provider,
            ..
        } = case;
        // D2.
        if !crashed {
            match &outcome {
                Ok(published) => {
                    assert_eq!(*published, digest, "{label}");
                    assert_exact(&durable, &slot, &staged, &label);
                    assert_eq!(
                        checkpoint_copies(&durable, &slot),
                        [Some(MANIFEST.to_vec()), Some(MANIFEST.to_vec())],
                        "{label}"
                    );
                }
                Err(error) => assert_error_truth(
                    error,
                    (step, fault, poisoned),
                    window,
                    &after_call,
                    &slot,
                    &staged,
                    &label,
                ),
            }
        }
        // D3, D6.
        assert_absent_or_exact(&device, &slot, &staged, &label);
        for copy in checkpoint_copies(&device, &slot) {
            assert!(
                copy.as_ref().is_none_or(|copy| copy == MANIFEST),
                "{label}: checkpoint copy"
            );
        }
        assert!(
            device.platform.with(|state| state.violations.is_empty()),
            "{label}"
        );
        // D1.
        let selected = provider
            .archive_checkpoint(&slot)
            .unwrap_or_else(|error| panic!("{label}: reconcile {error:?}"));
        if let Some((found, bytes)) = &selected {
            assert_eq!((*found, bytes.as_slice()), (digest, MANIFEST), "{label}");
            assert_exact(&device, &slot, &staged, &label);
        }
        // D4.
        let visible = visible_inodes(&device, &slot, &staged);
        let expected = selected.map_or([0; 32], |(found, _)| found);
        assert_eq!(
            publish_staged(&mut provider, &slot, &staged, expected),
            Ok(digest),
            "{label}: retry"
        );
        provider
            .close_archive_call(&slot, true)
            .unwrap_or_else(|error| panic!("{label}: close {error:?}"));
        if !remembered {
            assert_fresh_inodes(&device, &slot, &visible, &label);
        }
        assert_eq!(
            provider.lookup(&slot, &boot.operation_id()),
            Ok(retained.clone()),
            "{label}: the monetary head is untouched"
        );
        // D7.
        drop(provider);
        let mut provider = reopen_without_residue(&device, &slot, &label);
        assert_eq!(
            provider.archive_checkpoint(&slot).expect("checkpoint"),
            Some((digest, MANIFEST.to_vec())),
            "{label}"
        );
        drop(provider);
        let view = durable_view(&device);
        assert_exact(&view, &slot, &staged, &label);
        assert_eq!(
            checkpoint_copies(&view, &slot),
            [Some(MANIFEST.to_vec()), Some(MANIFEST.to_vec())],
            "{label}"
        );
    };
    matrix.run(&steps, faults, recoveries, window, !sampled, &mut check)
}

#[test]
fn archive_batch_crash_matrix_checkpoint_one_record() {
    for (index, policy) in [Policy::NotRequired, Policy::Keychain]
        .into_iter()
        .enumerate()
    {
        let cases = checkpoint_matrix(policy, 0xd0 + u8::try_from(index).expect("index"), 1, false);
        assert!(cases > 500, "{policy:?}: {cases}");
    }
}

#[test]
fn archive_batch_crash_matrix_checkpoint_three_records() {
    let cases = checkpoint_matrix(Policy::NotRequired, 0xd2, 3, false);
    assert!(cases > 800, "{cases}");
}

#[test]
fn archive_batch_crash_matrix_checkpoint_crosses_a_production_chunk() {
    // 33 records: 66 copies and two checkpoint copies, one more than a 64-file chunk.
    let cases = checkpoint_matrix(Policy::NotRequired, 0xd3, 33, true);
    assert!(cases > 100, "{cases}");
}

// ---------------------------------------------------------------------------------------
// Flow 2: a staged batch, then Advance (Bootstrap and a later head).
// ---------------------------------------------------------------------------------------

fn advance_staged(
    provider: &mut SimProviderV1,
    slot: &Slot,
    staged: &[RecordV1],
    request: &KagemushaWalletAdvanceRequestV1<KagemushaWalletRecoveryCapsuleV1>,
) -> AdvanceResultV1 {
    provider.open_archive_call(slot);
    for (key, bytes) in staged {
        provider.stage_archive_record(slot, key, bytes, None)?;
    }
    provider.advance(slot, &TestOwnerV1, request)
}

fn advance_matrix(
    name: &str,
    base: &DeviceV1,
    slot: Slot,
    request: &KagemushaWalletAdvanceRequestV1<KagemushaWalletRecoveryCapsuleV1>,
) -> usize {
    let staged = records(0x30, 2);
    let flow = |provider: &mut SimProviderV1| advance_staged(provider, &slot, &staged, request);
    let matrix = MatrixV1 {
        name: format!("advance {name}"),
        base,
        slot,
        flow: &flow,
    };
    let trace = matrix.trace();
    let window = WindowV1::of(&trace);
    let steps: Vec<u64> = (0..u64::try_from(trace.len()).expect("steps")).collect();
    let mut check = |case: CaseV1<AdvanceResultV1>| {
        let remembered = case.remembered();
        let CaseV1 {
            label,
            step,
            fault,
            outcome,
            crashed,
            poisoned,
            after_call,
            durable,
            device,
            mut provider,
            ..
        } = case;
        // D2: any answer of Advance follows its drain.
        if !crashed {
            match &outcome {
                Ok(_) => assert_exact(&durable, &slot, &staged, &label),
                Err(error) => assert_error_truth(
                    error,
                    (step, fault, poisoned),
                    window,
                    &after_call,
                    &slot,
                    &staged,
                    &label,
                ),
            }
        }
        // D3, D6.
        assert_absent_or_exact(&device, &slot, &staged, &label);
        assert!(
            device.platform.with(|state| state.violations.is_empty()),
            "{label}"
        );
        // D1: a selected head implies the records staged before it; I8: a call answered "not
        // performed" selected nothing.
        let status = provider
            .status(&slot)
            .unwrap_or_else(|error| panic!("{label}: reconcile {error:?}"));
        let selected = status
            .marker()
            .and_then(KagemushaWalletMarkerRecordV1::head)
            .is_some_and(|(_, operation, _)| operation == request.operation_id);
        if selected {
            assert_exact(&device, &slot, &staged, &label);
        }
        if !crashed
            && matches!(
                &outcome,
                Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(_))
            )
        {
            assert!(!selected, "{label}: not performed means not selected");
        }
        // D4.
        let visible = visible_inodes(&device, &slot, &staged);
        let retried = advance_staged(&mut provider, &slot, &staged, request);
        assert!(
            matches!(
                &retried,
                Ok(KagemushaWalletAdvanceOutcomeV1::Released { retained, .. })
                    if retained.operation_id == request.operation_id
            ),
            "{label}: retry {retried:?}"
        );
        // I3, I4: a release answered by the faulted call is the one retained, byte for byte.
        if let (
            false,
            Ok(KagemushaWalletAdvanceOutcomeV1::Released {
                retained: first, ..
            }),
            Ok(KagemushaWalletAdvanceOutcomeV1::Released { retained, .. }),
        ) = (crashed, &outcome, &retried)
        {
            assert_eq!(retained, first, "{label}: byte-identical retry");
        }
        provider
            .close_archive_call(&slot, true)
            .unwrap_or_else(|error| panic!("{label}: close {error:?}"));
        if !remembered {
            assert_fresh_inodes(&device, &slot, &visible, &label);
        }
        // D7.
        drop(provider);
        drop(reopen_without_residue(&device, &slot, &label));
        assert_exact(&durable_view(&device), &slot, &staged, &label);
    };
    matrix.run(&steps, &FAULTS, &RECOVERIES, window, true, &mut check)
}

#[test]
fn archive_batch_crash_matrix_advance() {
    let (base, f, slot, bootstrap) = bootstrapped_device(Policy::NotRequired, 0xd4);
    let current = base.open().status(&slot).expect("status");
    let request = advance_request(
        current.marker().expect("marker"),
        &next_capsule(&f, &bootstrap),
    );
    let cases = advance_matrix("next head", &base, slot, &request);
    assert!(cases > 500, "{cases}");
}

#[test]
fn archive_batch_crash_matrix_bootstrap() {
    let (base, f, slot) = enrolled_device(Policy::NotRequired, 0xd5);
    let current = base.open().status(&slot).expect("status");
    let request = advance_request(current.marker().expect("marker"), &bootstrap_capsule(&f));
    let cases = advance_matrix("bootstrap", &base, slot, &request);
    assert!(cases > 500, "{cases}");
}

// ---------------------------------------------------------------------------------------
// Flow 3: a staged batch, then the removal of a staged or a durable record.
// ---------------------------------------------------------------------------------------

fn remove_matrix(seed: u8, staged_target: bool) -> usize {
    let (base, _, slot, _) = bootstrapped_device(Policy::NotRequired, seed);
    let durable_record = records(0x40, 1);
    let staged = records(0x48, 2);
    {
        let mut provider = base.open();
        let (key, bytes) = &durable_record[0];
        provider
            .with_archive(&slot, |archive| archive.write_record(key, bytes))
            .expect("durable record");
    }
    // The removed record, and the records that must stay.
    let (target, kept): (RecordV1, Vec<RecordV1>) = if staged_target {
        (
            staged[0].clone(),
            vec![staged[1].clone(), durable_record[0].clone()],
        )
    } else {
        (durable_record[0].clone(), staged.clone())
    };
    let object = [[0; 32], [0; 32], target.0];
    let flow = |provider: &mut SimProviderV1| -> Result<(), Error> {
        provider.open_archive_call(&slot);
        for (key, bytes) in &staged {
            provider.stage_archive_record(&slot, key, bytes, None)?;
        }
        provider.remove_archive_record(&slot, &target.0, &object)
    };
    let matrix = MatrixV1 {
        name: format!("remove staged {staged_target}"),
        base: &base,
        slot,
        flow: &flow,
    };
    let trace = matrix.trace();
    let window = WindowV1::of(&trace);
    let steps: Vec<u64> = (0..u64::try_from(trace.len()).expect("steps")).collect();
    let everything: Vec<RecordV1> = staged.iter().chain(&durable_record).cloned().collect();
    let mut check = |case: CaseV1<Result<(), Error>>| {
        let CaseV1 {
            label,
            step,
            outcome,
            crashed,
            durable,
            device,
            mut provider,
            ..
        } = case;
        // D2.
        if !crashed && outcome.is_ok() {
            assert_absent(&durable, &slot, std::slice::from_ref(&target), &label);
            assert_exact(&durable, &slot, &kept, &label);
        }
        // D3.
        assert_absent_or_exact(&device, &slot, &everything, &label);
        // D1: a copy is removed only after the batch is durable, so every kept staged record
        // is present once the removal may have started, and the durable record is never lost
        // before it. A fault that stopped the call (a crash or an error) at or before the
        // batch directory sync leaves the durable record intact. A fault the call absorbs (a
        // crash-after on a step the simulator fails with NotFound before completing it, such
        // as the read of the absent abandoned-slot record or of an absent staged copy) neither
        // crashes nor fails it: the call completes, and D2 and the causal check cover it.
        let target_intact = copy_states(&device, &slot, &target.0)
            .iter()
            .all(|copy| copy.as_deref() == Some(framed(&target.1).as_slice()));
        if step > window.sync || (!staged_target && !target_intact) {
            assert_exact(&device, &slot, &kept, &label);
        }
        if step <= window.sync && !staged_target && (crashed || outcome.is_err()) {
            assert!(
                target_intact,
                "{label}: removed before the batch was durable"
            );
        }
        // D4.
        assert_eq!(flow(&mut provider), Ok(()), "{label}: retry");
        provider
            .close_archive_call(&slot, true)
            .unwrap_or_else(|error| panic!("{label}: close {error:?}"));
        // D7.
        drop(provider);
        drop(reopen_without_residue(&device, &slot, &label));
        let view = durable_view(&device);
        assert_absent(&view, &slot, std::slice::from_ref(&target), &label);
        assert_exact(&view, &slot, &kept, &label);
    };
    matrix.run(&steps, &FAULTS, &RECOVERIES, window, true, &mut check)
}

#[test]
fn archive_batch_crash_matrix_remove_staged_and_durable_records() {
    for (seed, staged_target) in [(0xd6, true), (0xd7, false)] {
        let cases = remove_matrix(seed, staged_target);
        assert!(cases > 300, "staged {staged_target}: {cases}");
    }
}

// ---------------------------------------------------------------------------------------
// Flow 4: pointer records follow their referents (Preparation → Capsule → Frozen).
// ---------------------------------------------------------------------------------------

const PLAN: [u8; 32] = [0x50; 32];
const PREPARATION: [u8; 32] = [0x51; 32];
const CAPSULE: [u8; 32] = [0x52; 32];
const FROZEN: [u8; 32] = [0x53; 32];

fn pointer_flow(provider: &mut SimProviderV1, slot: &Slot) -> Result<(), Error> {
    provider.open_archive_call(slot);
    provider.stage_archive_record(slot, &PLAN, b"plan", None)?;
    provider.publish_archive_record(slot, &PREPARATION, b"preparation pointer", None)?;
    provider.stage_archive_record(slot, &CAPSULE, b"capsule", None)?;
    provider.publish_archive_record(slot, &FROZEN, b"frozen pointer", None)?;
    provider.close_archive_call(slot, true)
}

fn pointer_records() -> [RecordV1; 4] {
    [
        (PLAN, b"plan".to_vec()),
        (PREPARATION, b"preparation pointer".to_vec()),
        (CAPSULE, b"capsule".to_vec()),
        (FROZEN, b"frozen pointer".to_vec()),
    ]
}

#[test]
fn archive_batch_crash_matrix_pointer_records_follow_their_referents() {
    let (base, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xd8);
    let chain = pointer_records();
    let flow = |provider: &mut SimProviderV1| pointer_flow(provider, &slot);
    let matrix = MatrixV1 {
        name: "pointers".to_owned(),
        base: &base,
        slot,
        flow: &flow,
    };
    let trace = matrix.trace();
    let steps: Vec<u64> = (0..u64::try_from(trace.len()).expect("steps")).collect();
    // Every crash of the flow is explored under its survival models.
    let window = WindowV1 {
        start: 0,
        rename: 0,
        sync: u64::try_from(trace.len()).expect("steps"),
    };
    let mut check = |case: CaseV1<Result<(), Error>>| {
        let CaseV1 {
            label,
            outcome,
            crashed,
            durable,
            device,
            mut provider,
            ..
        } = case;
        if !crashed && outcome.is_ok() {
            assert_exact(&durable, &slot, &chain, &label);
        }
        assert_absent_or_exact(&device, &slot, &chain, &label);
        // D5: any visible copy of a record implies both copies of everything before it.
        for (later, (key, _)) in chain.iter().enumerate().skip(1) {
            if copy_states(&device, &slot, key).iter().any(Option::is_some) {
                assert_exact(&device, &slot, &chain[..later], &label);
            }
        }
        assert_eq!(pointer_flow(&mut provider, &slot), Ok(()), "{label}: retry");
        drop(provider);
        drop(reopen_without_residue(&device, &slot, &label));
        assert_exact(&durable_view(&device), &slot, &chain, &label);
    };
    let cases = matrix.run(&steps, &FAULTS, &RECOVERIES, window, true, &mut check);
    assert!(cases > 500, "{cases}");
}

// These regressions exercise provider-level retirement through its durable journal. They
// preserve D2/D3/D4/D7 unchanged and do not require a readable platform boot identity.
fn retirement_fixture(seed: u8) -> (DeviceV1, Slot, RecordV1) {
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, seed);
    let target = records(seed, 1).remove(0);
    device
        .open()
        .with_archive(&slot, |archive| archive.write_record(&target.0, &target.1))
        .expect("seed exact record");
    (device, slot, target)
}

fn remove_retirement_target(
    provider: &mut SimProviderV1,
    slot: &Slot,
    target: &RecordV1,
) -> Result<(), Error> {
    provider.with_archive(slot, |archive| archive.remove_record(&target.0))
}

fn retirement_trace(device: &DeviceV1, slot: &Slot, target: &RecordV1) -> Vec<Step> {
    let trial = device.fork();
    let mut provider = trial.open();
    let start = trial.fs.steps();
    remove_retirement_target(&mut provider, slot, target).expect("unfaulted retirement");
    trial.fs.trace_since(start)
}

#[test]
fn acknowledged_retirement_never_resurrects_during_later_boot_recovery_faults() {
    let (base, slot, target) = retirement_fixture(0xe4);
    let trace = retirement_trace(&base, &slot, &target);
    let reap_sync = trace
        .iter()
        .rposition(|step| *step == Step::SyncDir)
        .expect("retirement reaping directory sync") as u64;
    let mut provider = base.open();
    base.fs
        .inject(base.fs.steps() + reap_sync, Fault::LostWriteback);
    remove_retirement_target(&mut provider, &slot, &target)
        .expect("target absence is committed before the reap sync");
    drop(provider);
    base.power_loss(PowerLoss::DropUnsynced, BOOT_B);
    assert_absent(
        &base,
        &slot,
        std::slice::from_ref(&target),
        "acknowledged deletion after boot",
    );
    let directory = kagemusha_wallet_archive_dir_v1(&slot);
    assert!(
        base.fs
            .visible_names(&directory)
            .iter()
            .any(|name| parse_grave(name).is_some()),
        "the lost cleanup must leave a durable completed-operation grave, so the regression is not vacuous"
    );
    let trace = {
        let trial = base.fork();
        let mut provider = trial.open();
        let start = trial.fs.steps();
        provider
            .status(&slot)
            .expect("unfaulted completed-operation recovery");
        trial.fs.trace_since(start)
    };
    assert!(!trace.is_empty());
    for step in 0..trace.len() as u64 {
        for fault in [Fault::CrashBefore, Fault::CrashAfter, Fault::LostWriteback] {
            let device = base.fork();
            let mut provider = device.open();
            device.fs.inject(device.fs.steps() + step, fault);
            let _ = provider.status(&slot);
            drop(provider);
            let label = format!("completed-operation cleanup step={step} fault={fault:?}");
            assert_absent(&device, &slot, std::slice::from_ref(&target), &label);
            for model in survival(device.fs.pending_dir_ops(), false) {
                let recovered = device.fork();
                recovered.power_loss(model, [0xc3; 32]);
                assert_absent(&recovered, &slot, std::slice::from_ref(&target), &label);
                let mut provider = recovered.open();
                provider
                    .status(&slot)
                    .expect("fault-free later-boot recovery");
                assert_absent(&recovered, &slot, std::slice::from_ref(&target), &label);
                assert!(
                    !recovered
                        .fs
                        .visible_names(&directory)
                        .iter()
                        .any(|name| parse_grave(name).is_some()),
                    "{label}: recovery must finish completed-operation grave cleanup"
                );
            }
        }
    }
}

#[test]
fn unreferenced_stale_grave_never_replaces_a_new_record_incarnation() {
    use crate::kagemusha_wallet_advance_v1::KagemushaWalletPublishOutcomeV1 as Publish;
    let (base, slot, target) = retirement_fixture(0xe5);
    let old = b"earlier value at the reused immutable key";
    assert_ne!(target.1.as_slice(), old);
    let directory = kagemusha_wallet_archive_dir_v1(&slot);
    let stale = grave_names(&target.0, "11111111111111111111111111111111");
    let store = KagemushaWalletDurableStoreV1::new(base.fs.clone());
    for grave in &stale {
        assert_eq!(
            store.write_new(&directory, grave, &framed(old)),
            Publish::Published
        );
    }
    let trace = retirement_trace(&base, &slot, &target);
    for step in 0..trace.len() as u64 {
        for fault in [Fault::CrashBefore, Fault::CrashAfter, Fault::LostWriteback] {
            let device = base.fork();
            let mut provider = device.open();
            device.fs.inject(device.fs.steps() + step, fault);
            let _ = remove_retirement_target(&mut provider, &slot, &target);
            drop(provider);
            let label = format!("different-byte stale grave step={step} fault={fault:?}");
            assert_absent_or_exact(&device, &slot, std::slice::from_ref(&target), &label);
            for model in survival(device.fs.pending_dir_ops(), false) {
                let recovered = device.fork();
                recovered.power_loss(model, BOOT_B);
                assert_absent_or_exact(&recovered, &slot, std::slice::from_ref(&target), &label);
                let mut provider = recovered.open();
                remove_retirement_target(&mut provider, &slot, &target)
                    .expect("fault-free exact retry");
                drop(provider);
                recovered.power_loss(PowerLoss::DropUnsynced, [0xc3; 32]);
                assert_absent(&recovered, &slot, std::slice::from_ref(&target), &label);
            }
        }
    }
}

#[test]
fn retirement_with_unknown_boot_remains_available_and_durable() {
    for boot in [Err(Unavailable::Platform(812)), Ok([0; 32])] {
        let (device, slot, target) = retirement_fixture(0xe6);
        device.platform.with(|state| state.boot = boot);
        let mut provider = device.open();
        let read = provider
            .with_archive(&slot, |archive| {
                archive.read_record(&target.0, target.1.len())
            })
            .expect("ordinary read with unknown boot")
            .expect("seeded record");
        assert_eq!(read.as_slice(), target.1.as_slice());
        remove_retirement_target(&mut provider, &slot, &target)
            .expect("retirement uses durable journal, never a platform boot gate");
        assert_absent(
            &device,
            &slot,
            std::slice::from_ref(&target),
            "unknown boot removal succeeded",
        );
        drop(provider);
        device.power_loss(PowerLoss::DropUnsynced, BOOT_B);
        device.platform.with(|state| state.boot = boot);
        let mut provider = device.open();
        provider
            .status(&slot)
            .expect("journal recovery remains available with unknown boot");
        assert_absent(
            &device,
            &slot,
            std::slice::from_ref(&target),
            "unknown boot removal survives power loss",
        );
        assert!(
            provider
                .with_archive(&slot, |archive| archive
                    .read_record(&target.0, target.1.len()))
                .expect("read after removal")
                .is_none()
        );
    }
}

#[test]
fn remove_then_republish_different_bytes_in_one_call_survives_reboot() {
    let (device, slot, target) = retirement_fixture(0xe7);
    let successor = (
        target.0,
        b"new archive incarnation after committed collection".to_vec(),
    );
    let mut provider = device.open();
    provider.open_archive_call(&slot);
    provider
        .remove_archive_record(&slot, &target.0, &[[0; 32], [0; 32], target.0])
        .expect("remove before same-key staged replacement");
    provider
        .stage_archive_record(&slot, &successor.0, &successor.1, None)
        .expect("stage new incarnation");
    provider
        .close_archive_call(&slot, true)
        .expect("commit new incarnation");
    drop(provider);
    device.power_loss(PowerLoss::DropUnsynced, BOOT_B);
    let mut provider = device.open();
    provider.status(&slot).expect("reconcile new incarnation");
    assert_exact(
        &device,
        &slot,
        &[successor],
        "old retirement cannot delete or restore over successor",
    );
}

#[test]
fn retirement_journal_writeback_failure_is_repaired_before_reuse() {
    let (base, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xe8);
    let targets = records(0xe8, 3);
    {
        let mut provider = base.open();
        for (key, bytes) in &targets {
            provider
                .with_archive(&slot, |archive| archive.write_record(key, bytes))
                .expect("seed record");
        }
        remove_retirement_target(&mut provider, &slot, &targets[0]).expect("seed Complete journal");
    }
    let trace = retirement_trace(&base, &slot, &targets[1]);
    let syncs: Vec<usize> = trace
        .iter()
        .enumerate()
        .filter_map(|(index, step)| (*step == Step::SyncDir).then_some(index))
        .collect();
    assert!(
        syncs.len() >= 3,
        "exercise journal publication, durable retirement and completion publication"
    );
    for step in syncs {
        for process_restart in [false, true] {
            let device = base.fork();
            let mut provider = device.open();
            device
                .fs
                .inject(device.fs.steps() + step as u64, Fault::LostWriteback);
            let _ = remove_retirement_target(&mut provider, &slot, &targets[1]);
            if process_restart {
                drop(provider);
                device.fs.restart();
                provider = device.open();
            }
            let label = format!("journal sync={step} restart={process_restart}");
            remove_retirement_target(&mut provider, &slot, &targets[1])
                .expect("exact retry repairs the visible journal phase");
            remove_retirement_target(&mut provider, &slot, &targets[2])
                .expect("next operation reuses the single journal safely");
            drop(provider);
            device.power_loss(PowerLoss::DropUnsynced, BOOT_B);
            assert_absent(&device, &slot, &targets, &label);
            let mut provider = device.open();
            provider
                .status(&slot)
                .expect("reconcile after journal reuse");
            assert_absent(&device, &slot, &targets, &label);
            assert!(
                !device
                    .fs
                    .visible_names(&kagemusha_wallet_archive_dir_v1(&slot))
                    .iter()
                    .any(|name| parse_grave(name).is_some()),
                "{label}: no unreferenced retirement grave remains"
            );
        }
    }
}

fn retirement_journal(device: &DeviceV1, slot: &Slot) -> Option<ArchiveRetirementV1> {
    device
        .fs
        .visible_file(
            &kagemusha_wallet_archive_dir_v1(slot),
            retirement_name().as_str(),
        )
        .map(|bytes| {
            super::super::decode_envelope_v1(&bytes, RETIREMENT_MAX_BYTES)
                .expect("valid retirement journal fixture")
        })
}

#[test]
fn visible_complete_journal_is_adopted_before_recovery_even_after_another_fault() {
    let (base, slot, target) = retirement_fixture(0xeb);
    let trace = retirement_trace(&base, &slot, &target);
    let mut uncertain_complete = None;
    for (step, _) in trace
        .iter()
        .enumerate()
        .filter(|(_, step)| **step == Step::SyncDir)
    {
        let device = base.fork();
        let mut provider = device.open();
        device
            .fs
            .inject(device.fs.steps() + step as u64, Fault::LostWriteback);
        let result = remove_retirement_target(&mut provider, &slot, &target);
        drop(provider);
        if retirement_journal(&device, &slot).is_some_and(|journal| journal.complete)
            && retirement_journal(&durable_view(&device), &slot)
                .is_some_and(|journal| !journal.complete)
        {
            assert!(
                result.is_err(),
                "lost Complete publication may not acknowledge retirement"
            );
            assert!(
                uncertain_complete.replace(device).is_none(),
                "one Complete publication boundary"
            );
        }
    }
    let uncertain =
        uncertain_complete.expect("exercise actual visible Complete / durable Pending state");
    let trace = {
        let device = uncertain.fork();
        device.fs.restart();
        let mut provider = device.open();
        let start = device.fs.steps();
        provider.status(&slot).expect("unfaulted journal adoption");
        device.fs.trace_since(start)
    };
    assert!(!trace.is_empty());
    for step in 0..trace.len() as u64 {
        for fault in [Fault::CrashBefore, Fault::CrashAfter, Fault::LostWriteback] {
            let device = uncertain.fork();
            device.fs.restart();
            let mut provider = device.open();
            device.fs.inject(device.fs.steps() + step, fault);
            let _ = provider.status(&slot);
            drop(provider);
            let label = format!("Complete adoption step={step} fault={fault:?}");
            assert_absent_or_exact(&device, &slot, std::slice::from_ref(&target), &label);
            for model in survival(device.fs.pending_dir_ops(), false) {
                let recovered = device.fork();
                recovered.power_loss(model, BOOT_B);
                assert_absent_or_exact(&recovered, &slot, std::slice::from_ref(&target), &label);
                let mut provider = recovered.open();
                remove_retirement_target(&mut provider, &slot, &target)
                    .expect("fault-free exact retry after second failure");
                drop(provider);
                recovered.power_loss(PowerLoss::DropUnsynced, [0xc3; 32]);
                assert_absent(&recovered, &slot, std::slice::from_ref(&target), &label);
            }
        }
    }
}

#[test]
fn retirement_journal_of_another_slot_refuses_before_deleting_records() {
    use crate::kagemusha_wallet_advance_v1::KagemushaWalletPublishOutcomeV1 as Publish;
    let (device, slot, target) = retirement_fixture(0xec);
    let journal = ArchiveRetirementV1 {
        version: 1,
        slot: [0xed; 32],
        key: target.0,
        nonce: [0xee; 16],
        complete: false,
    };
    let bytes = super::super::encode_envelope_v1(&journal, RETIREMENT_MAX_BYTES)
        .expect("encode foreign-slot journal");
    let store = KagemushaWalletDurableStoreV1::new(device.fs.clone());
    assert_eq!(
        store.write_new(
            &kagemusha_wallet_archive_dir_v1(&slot),
            &retirement_name(),
            &bytes
        ),
        Publish::Published
    );
    let mut provider = device.open();
    assert!(
        provider.status(&slot).is_err(),
        "another slot cannot authorize retirement"
    );
    assert_exact(
        &device,
        &slot,
        std::slice::from_ref(&target),
        "foreign-slot journal preserves exact records",
    );
}
