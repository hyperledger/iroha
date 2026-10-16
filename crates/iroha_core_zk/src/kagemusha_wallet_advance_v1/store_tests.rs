//! Durable store tests: the publication algorithm under single-fault matrices on the
//! simulator (every step, every fault, process crash, restart and power loss), simulator
//! semantics, and the `std::fs` backend.

use std::io;

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletCustodyDirV1, KagemushaWalletEntryNameV1, KagemushaWalletPublishOutcomeV1,
    KagemushaWalletRemoveOutcomeV1, KagemushaWalletStorageCountersV1,
};

type SimStore = KagemushaWalletDurableStoreV1<KagemushaWalletSimFsV1>;

const BYTES: &[u8] = b"published custody bytes";
const OTHER: &[u8] = b"pre-existing custody bytes";

/// Every fault kind of the matrices.
const FAULTS: [KagemushaWalletSimFaultV1; 7] = [
    KagemushaWalletSimFaultV1::Error,
    KagemushaWalletSimFaultV1::ErrorKind(io::ErrorKind::PermissionDenied),
    KagemushaWalletSimFaultV1::ErrorKind(io::ErrorKind::StorageFull),
    KagemushaWalletSimFaultV1::PartialWrite,
    KagemushaWalletSimFaultV1::LostWriteback,
    KagemushaWalletSimFaultV1::CrashBefore,
    KagemushaWalletSimFaultV1::CrashAfter,
];
/// Seeds of the independent-survival power-loss model per case.
const SEEDS: u64 = 6;

fn name(text: &str) -> KagemushaWalletEntryNameV1 {
    KagemushaWalletEntryNameV1::new(text).expect("valid name")
}

fn dir() -> KagemushaWalletCustodyDirV1 {
    KagemushaWalletCustodyDirV1::root().child(&name("d"))
}

fn store(fs: &KagemushaWalletSimFsV1) -> SimStore {
    KagemushaWalletDurableStoreV1::new(fs.clone())
}

/// Simulator holding the durable directory `d`.
fn base() -> KagemushaWalletSimFsV1 {
    let fs = KagemushaWalletSimFsV1::new();
    assert_eq!(
        store(&fs).create_dir(&KagemushaWalletCustodyDirV1::root(), &name("d")),
        KagemushaWalletPublishOutcomeV1::Published
    );
    fs
}

/// Base holding the durable file `d/f` with `bytes`.
fn base_with_file(bytes: &[u8]) -> KagemushaWalletSimFsV1 {
    let fs = base();
    assert_eq!(
        store(&fs).write_new(&dir(), &name("f"), bytes),
        KagemushaWalletPublishOutcomeV1::Published
    );
    fs
}

/// When an invariant is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Moment {
    /// Right after the primitive returned (or the process crashed).
    Immediate,
    /// After a restart that keeps visible state.
    Restart,
    /// After power loss dropping everything unsynced.
    PowerStrict,
    /// After power loss with independent survival of unsynced operations.
    PowerSeeded(u64),
}

impl Moment {
    fn after_power_loss(self) -> bool {
        matches!(self, Self::PowerStrict | Self::PowerSeeded(_))
    }
}

/// One matrix case as seen by an invariant check.
struct CaseV1<'a, T> {
    fs: &'a KagemushaWalletSimFsV1,
    outcome: &'a T,
    /// The process crashed during the primitive; its outcome was never observed.
    crashed: bool,
    moment: Moment,
    step: u64,
    fault: KagemushaWalletSimFaultV1,
}

impl<T> CaseV1<'_, T> {
    fn observed(&self) -> bool {
        !self.crashed
    }

    fn file(&self, file: &str) -> Option<Vec<u8>> {
        self.fs.visible_file(&dir(), file)
    }

    fn label(&self) -> String {
        format!(
            "step {} fault {:?} moment {:?} crashed {}",
            self.step, self.fault, self.moment, self.crashed
        )
    }
}

/// Number of steps the primitive takes without faults, and their kinds.
fn fault_free_trace<T>(
    base: &KagemushaWalletSimFsV1,
    op: &dyn Fn(&SimStore) -> T,
) -> Vec<KagemushaWalletSimStepV1> {
    let fs = base.fork();
    let start = fs.steps();
    op(&store(&fs));
    fs.trace_since(start)
}

/// Run `op` under every single fault at every step of its fault-free trace, then check
/// `invariant` immediately and after a restart and every power-loss model.
fn matrix<T: std::fmt::Debug>(
    base: &KagemushaWalletSimFsV1,
    faults: &[KagemushaWalletSimFaultV1],
    op: &dyn Fn(&SimStore) -> T,
    invariant: &dyn Fn(&CaseV1<'_, T>),
) -> usize {
    matrix_where(base, faults, &|_| true, op, invariant)
}

/// [`matrix`] over the steps of the fault-free trace that `select` accepts.
fn matrix_where<T: std::fmt::Debug>(
    base: &KagemushaWalletSimFsV1,
    faults: &[KagemushaWalletSimFaultV1],
    select: &dyn Fn(u64) -> bool,
    op: &dyn Fn(&SimStore) -> T,
    invariant: &dyn Fn(&CaseV1<'_, T>),
) -> usize {
    let steps = u64::try_from(fault_free_trace(base, op).len()).expect("steps");
    assert!(steps > 0, "primitive takes at least one step");
    let mut cases = 0;
    for step in (0..steps).filter(|step| select(*step)) {
        for &fault in faults {
            let fs = base.fork();
            fs.inject(fs.steps() + step, fault);
            let outcome = op(&store(&fs));
            let crashed = fs.crashed();
            let mut moments = vec![Moment::Immediate, Moment::Restart, Moment::PowerStrict];
            moments.extend((0..SEEDS).map(Moment::PowerSeeded));
            for moment in moments {
                let view = fs.fork();
                match moment {
                    Moment::Immediate => {}
                    Moment::Restart => view.restart(),
                    Moment::PowerStrict => {
                        view.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
                    }
                    Moment::PowerSeeded(seed) => {
                        view.power_loss(KagemushaWalletSimPowerLossV1::Seeded(seed));
                    }
                }
                invariant(&CaseV1 {
                    fs: &view,
                    outcome: &outcome,
                    crashed,
                    moment,
                    step,
                    fault,
                });
                cases += 1;
            }
        }
    }
    cases
}

/// Every visible name in `d` is `allowed` or a staging file.
fn only_names(case: &CaseV1<'_, impl Sized>, allowed: &[&str]) {
    for entry in case.fs.visible_names(&dir()) {
        assert!(
            allowed.contains(&entry.as_str())
                || crate::kagemusha_wallet_advance_v1::kagemusha_wallet_is_staging_name_v1(&entry),
            "unexpected entry {entry} at {}",
            case.label()
        );
    }
}

/// Create-new invariant for a name that was absent: atomic, honest and durable.
fn check_created(case: &CaseV1<'_, KagemushaWalletPublishOutcomeV1>, file: &str, bytes: &[u8]) {
    let value = case.file(file);
    assert!(
        value.is_none() || value.as_deref() == Some(bytes),
        "torn or foreign {file} at {}",
        case.label()
    );
    if case.observed() {
        match case.outcome {
            KagemushaWalletPublishOutcomeV1::Published => assert_eq!(
                value.as_deref(),
                Some(bytes),
                "published {file} lost at {}",
                case.label()
            ),
            KagemushaWalletPublishOutcomeV1::NotPublished(_) => {
                assert_eq!(
                    value,
                    None,
                    "unpublished {file} visible at {}",
                    case.label()
                );
            }
            KagemushaWalletPublishOutcomeV1::Uncertain(_) => {}
        }
    }
}

#[test]
fn wallet_advance_v1_store_write_new_publishes_with_one_dir_sync() {
    let fs = base();
    let start = fs.steps();
    assert_eq!(
        store(&fs).write_new(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::Published
    );
    assert_eq!(
        fs.trace_since(start),
        [
            KagemushaWalletSimStepV1::CreateNew,
            KagemushaWalletSimStepV1::Write,
            KagemushaWalletSimStepV1::SyncFile,
            KagemushaWalletSimStepV1::RenameNoReplace,
            KagemushaWalletSimStepV1::SyncDir,
        ]
    );
    assert_eq!(fs.visible_names(&dir()), ["f"]);
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert_eq!(fs.visible_file(&dir(), "f").as_deref(), Some(BYTES));
}

#[test]
fn wallet_advance_v1_store_write_new_fault_matrix() {
    let cases = matrix(
        &base(),
        &FAULTS,
        &|store| store.write_new(&dir(), &name("f"), BYTES),
        &|case| {
            check_created(case, "f", BYTES);
            only_names(case, &["f"]);
        },
    );
    assert!(cases >= 5 * FAULTS.len() * 9);
}

#[test]
fn wallet_advance_v1_store_write_new_never_replaces() {
    let base = base_with_file(OTHER);
    assert_eq!(
        store(&base.fork()).write_new(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::DestinationExists
        )
    );
    matrix(
        &base,
        &FAULTS,
        &|store| store.write_new(&dir(), &name("f"), BYTES),
        &|case| {
            assert_eq!(case.file("f").as_deref(), Some(OTHER), "{}", case.label());
            if case.observed() {
                assert_ne!(*case.outcome, KagemushaWalletPublishOutcomeV1::Published);
            }
            only_names(case, &["f"]);
        },
    );
}

#[test]
fn wallet_advance_v1_store_write_new_pair_fault_matrix() {
    let base = base();
    assert_eq!(
        fault_free_trace(&base, &|store| store.write_new_pair(
            &dir(),
            (&name("p"), BYTES),
            (&name("p.r"), BYTES)
        ))
        .iter()
        .filter(|step| **step == KagemushaWalletSimStepV1::SyncDir)
        .count(),
        1,
        "a pair publishes with one directory sync"
    );
    matrix(
        &base,
        &FAULTS,
        &|store| store.write_new_pair(&dir(), (&name("p"), BYTES), (&name("p.r"), OTHER)),
        &|case| {
            for (index, (file, bytes)) in [("p", BYTES), ("p.r", OTHER)].into_iter().enumerate() {
                check_created(
                    &CaseV1 {
                        fs: case.fs,
                        outcome: &case.outcome[index],
                        crashed: case.crashed,
                        moment: case.moment,
                        step: case.step,
                        fault: case.fault,
                    },
                    file,
                    bytes,
                );
            }
            only_names(case, &["p", "p.r"]);
        },
    );
}

#[test]
fn wallet_advance_v1_store_write_new_pair_reports_per_name() {
    let fs = base_with_file(OTHER);
    let outcomes = store(&fs).write_new_pair(&dir(), (&name("f"), BYTES), (&name("g"), BYTES));
    assert_eq!(
        outcomes,
        [
            KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::DestinationExists
            ),
            KagemushaWalletPublishOutcomeV1::Published,
        ]
    );
    assert_eq!(fs.visible_file(&dir(), "f").as_deref(), Some(OTHER));
    assert_eq!(fs.visible_names(&dir()), ["f", "g"]);
}

#[test]
fn wallet_advance_v1_store_rewrite_same_fault_matrix() {
    let base = base_with_file(BYTES);
    let original = base.inode_of(&dir(), "f").expect("inode");
    matrix(
        &base,
        &FAULTS,
        &|store| store.rewrite_same(&dir(), &name("f"), BYTES),
        &|case| {
            assert_eq!(case.file("f").as_deref(), Some(BYTES), "{}", case.label());
            if case.observed()
                && case.moment == Moment::Immediate
                && *case.outcome == KagemushaWalletPublishOutcomeV1::Published
            {
                assert_ne!(case.fs.inode_of(&dir(), "f"), Some(original), "fresh inode");
            }
            only_names(case, &["f"]);
        },
    );
}

#[test]
fn wallet_advance_v1_store_rewrite_same_refuses_other_content() {
    let fs = base_with_file(OTHER);
    let store = store(&fs);
    assert_eq!(
        store.rewrite_same(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::ContentMismatch
        )
    );
    assert_eq!(
        store.rewrite_same(&dir(), &name("g"), BYTES),
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::DestinationAbsent
        )
    );
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        store.rewrite_same(&dir(), &name("f"), OTHER),
        KagemushaWalletPublishOutcomeV1::NotPublished(KagemushaWalletNotPublishedV1::Failed(_))
    ));
    assert_eq!(fs.visible_file(&dir(), "f").as_deref(), Some(OTHER));
}

#[test]
fn wallet_advance_v1_store_rewrite_same_repairs_lost_writeback() {
    // A publication whose directory sync reported a writeback error and dropped the entry:
    // a later directory sync succeeds vacuously and the name is lost on power loss.
    let base = base();
    base.inject(base.steps() + 4, KagemushaWalletSimFaultV1::LostWriteback);
    assert!(matches!(
        store(&base).write_new(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::Uncertain(_)
    ));
    let synced = base.fork();
    assert_eq!(store(&synced).sync_dir(&dir()), Ok(()));
    synced.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert_eq!(
        synced.visible_file(&dir(), "f"),
        None,
        "vacuous sync is not durable"
    );
    // A same-content rewrite to a fresh inode makes it durable.
    let rewritten = base.fork();
    assert_eq!(
        store(&rewritten).rewrite_same(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::Published
    );
    rewritten.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert_eq!(rewritten.visible_file(&dir(), "f").as_deref(), Some(BYTES));
}

#[test]
fn wallet_advance_v1_store_remove_file_fault_matrix() {
    matrix(
        &base_with_file(BYTES),
        &FAULTS,
        &|store| store.remove_file(&dir(), &name("f")),
        &|case| {
            let value = case.file("f");
            assert!(
                value.is_none() || value.as_deref() == Some(BYTES),
                "{}",
                case.label()
            );
            if case.observed() {
                match case.outcome {
                    KagemushaWalletRemoveOutcomeV1::Removed => {
                        assert_eq!(value, None, "removed file back at {}", case.label());
                    }
                    KagemushaWalletRemoveOutcomeV1::NotRemoved(_)
                        if !case.moment.after_power_loss() =>
                    {
                        assert_eq!(value.as_deref(), Some(BYTES), "{}", case.label());
                    }
                    _ => {}
                }
            }
        },
    );
}

#[test]
fn wallet_advance_v1_store_remove_absent_is_durable_absence() {
    // An unlinked but unsynced entry: removing the absent name syncs the directory.
    let fs = base_with_file(BYTES);
    fs.inject(fs.steps() + 1, KagemushaWalletSimFaultV1::LostWriteback);
    assert!(matches!(
        store(&fs).remove_file(&dir(), &name("f")),
        KagemushaWalletRemoveOutcomeV1::Uncertain(_)
    ));
    let durable = base_with_file(BYTES);
    assert!(matches!(store(&durable).fs().unlink(&dir(), "f"), Ok(())));
    assert_eq!(
        store(&durable).remove_file(&dir(), &name("f")),
        KagemushaWalletRemoveOutcomeV1::Removed
    );
    durable.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert_eq!(durable.visible_file(&dir(), "f"), None);
}

#[test]
fn wallet_advance_v1_store_create_dir_fault_matrix() {
    let child = || dir().child(&name("e"));
    matrix(
        &base(),
        &FAULTS,
        &|store| store.create_dir(&dir(), &name("e")),
        &|case| {
            let visible = case.fs.visible_dir(&child());
            if case.observed() {
                match case.outcome {
                    KagemushaWalletPublishOutcomeV1::Published => {
                        assert!(visible, "created dir lost at {}", case.label());
                    }
                    KagemushaWalletPublishOutcomeV1::NotPublished(_) => {
                        assert!(!visible, "uncreated dir at {}", case.label());
                    }
                    KagemushaWalletPublishOutcomeV1::Uncertain(_) => {}
                }
            }
        },
    );
    let fs = base();
    assert_eq!(
        store(&fs).create_dir(&KagemushaWalletCustodyDirV1::root(), &name("d")),
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::DestinationExists
        )
    );
}

#[test]
fn wallet_advance_v1_store_sync_dir_fault_matrix() {
    let base = base();
    base.place_unsynced(&dir(), "u", BYTES);
    matrix(&base, &FAULTS, &|store| store.sync_dir(&dir()), &|case| {
        if case.observed() && case.outcome.is_ok() && case.moment.after_power_loss() {
            assert!(
                case.fs.visible_names(&dir()).contains(&"u".to_owned()),
                "synced entry lost at {}",
                case.label()
            );
        }
    });
}

#[test]
fn wallet_advance_v1_store_sync_file_fault_matrix() {
    let base = base();
    base.place_unsynced(&dir(), "u", BYTES);
    assert_eq!(store(&base).sync_dir(&dir()), Ok(()));
    matrix(
        &base,
        &FAULTS,
        &|store| store.sync_file(&dir(), &name("u")),
        &|case| {
            let value = case.file("u").expect("entry is durable");
            assert!(BYTES.starts_with(&value), "{}", case.label());
            if case.observed() && case.outcome.is_ok() {
                assert_eq!(value, BYTES, "synced data lost at {}", case.label());
            }
        },
    );
}

#[test]
fn wallet_advance_v1_store_sync_after_lost_writeback_is_vacuous() {
    let fs = base();
    fs.place_unsynced(&dir(), "u", BYTES);
    let store = store(&fs);
    assert_eq!(store.sync_dir(&dir()), Ok(()));
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::LostWriteback);
    assert!(store.sync_file(&dir(), &name("u")).is_err());
    assert_eq!(store.sync_file(&dir(), &name("u")), Ok(()));
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert_eq!(fs.visible_file(&dir(), "u").as_deref(), Some(&[][..]));
}

#[test]
fn wallet_advance_v1_store_read_and_list_fault_matrix_never_absent() {
    let reads = [
        KagemushaWalletSimFaultV1::Error,
        KagemushaWalletSimFaultV1::ErrorKind(io::ErrorKind::PermissionDenied),
        KagemushaWalletSimFaultV1::CrashBefore,
        KagemushaWalletSimFaultV1::CrashAfter,
    ];
    let base = base_with_file(BYTES);
    matrix(
        &base,
        &reads,
        &|store| store.read(&dir(), &name("f"), 1_024),
        &|case| match case.outcome {
            KagemushaWalletReadV1::Present(bytes) => assert_eq!(bytes.as_slice(), BYTES),
            KagemushaWalletReadV1::Unavailable(_) => assert!(case.step == 0),
            other => panic!("read error became {other:?} at {}", case.label()),
        },
    );
    matrix(
        &base,
        &reads,
        &|store| store.list(&dir()),
        &|case| match case.outcome {
            KagemushaWalletProbeV1::Present(entries) => assert_eq!(entries.len(), 1),
            KagemushaWalletProbeV1::Unavailable(_) => {}
            KagemushaWalletProbeV1::Absent => panic!("listing error became absence"),
        },
    );
}

#[test]
fn wallet_advance_v1_store_read_bounds_and_absence() {
    let fs = base_with_file(BYTES);
    let store = store(&fs);
    assert_eq!(
        store.read(&dir(), &name("f"), BYTES.len()),
        KagemushaWalletReadV1::Present(BYTES.to_vec())
    );
    assert_eq!(
        store.read(&dir(), &name("f"), BYTES.len() - 1),
        KagemushaWalletReadV1::Oversized
    );
    assert_eq!(
        store.read(&dir(), &name("g"), 8),
        KagemushaWalletReadV1::Absent
    );
    assert_eq!(
        store.list(&dir().child(&name("missing"))),
        KagemushaWalletProbeV1::Absent
    );
    fs.place_other(&dir(), "link");
    assert!(matches!(
        store.read(&dir(), &name("link"), 8),
        KagemushaWalletReadV1::Unavailable(_)
    ));
    let KagemushaWalletProbeV1::Present(entries) = store.list(&dir()) else {
        panic!("listing");
    };
    assert_eq!(
        entries,
        [
            KagemushaWalletListedEntryV1 {
                name: "f".to_owned(),
                kind: KagemushaWalletEntryKindV1::File,
            },
            KagemushaWalletListedEntryV1 {
                name: "link".to_owned(),
                kind: KagemushaWalletEntryKindV1::Other,
            },
        ]
    );
}

#[test]
fn wallet_advance_v1_store_lock_is_exclusive_and_fails_closed() {
    let fs = base();
    let first = store(&fs);
    let second = store(&fs);
    let lock = first.lock_exclusive().expect("lock");
    assert_eq!(
        second.lock_exclusive().err(),
        Some(KagemushaWalletUnavailableV1::Busy)
    );
    drop(lock);
    let lock = second.lock_exclusive().expect("released on drop");
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::CrashBefore);
    assert!(first.lock_exclusive().is_err());
    fs.restart();
    drop(lock);
    let _held = first.lock_exclusive().expect("a crash releases the lock");
    matrix(
        &base(),
        &[
            KagemushaWalletSimFaultV1::Error,
            KagemushaWalletSimFaultV1::CrashAfter,
        ],
        &|store| store.lock_exclusive().map(|_| ()),
        &|case| {
            if let Err(reason) = case.outcome {
                assert_ne!(
                    *reason,
                    KagemushaWalletUnavailableV1::Busy,
                    "{}",
                    case.label()
                );
            }
        },
    );
}

#[test]
fn wallet_advance_v1_store_available_bytes_and_capacity() {
    let fs = base();
    let store = store(&fs);
    assert!(store.available_bytes().expect("free space") > 1_000_000);
    fs.set_capacity(Some(10));
    assert_eq!(store.available_bytes(), Ok(10));
    assert_eq!(
        store.write_new(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::NotPublished(KagemushaWalletNotPublishedV1::NoSpace)
    );
    assert_eq!(fs.visible_names(&dir()), Vec::<String>::new());
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(store.available_bytes().is_err());
}

#[test]
fn wallet_advance_v1_store_noreplace_unsupported_is_not_published() {
    let fs = base();
    fs.set_noreplace_supported(false);
    assert_eq!(
        store(&fs).write_new(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::NoReplaceUnsupported
        )
    );
    assert_eq!(fs.visible_names(&dir()), Vec::<String>::new());
}

#[test]
fn wallet_advance_v1_store_staging_exhaustion_is_never_destination_exists() {
    let fs = base();
    for index in 0..u64::from(STAGING_ATTEMPTS) {
        fs.place_unsynced(&dir(), &format!(".tmp-{index:032x}"), b"");
    }
    let outcome = store(&fs).write_new(&dir(), &name("f"), BYTES);
    assert!(
        matches!(
            outcome,
            KagemushaWalletPublishOutcomeV1::NotPublished(KagemushaWalletNotPublishedV1::Failed(_))
        ),
        "{outcome:?}"
    );
}

#[test]
fn wallet_advance_v1_store_remove_staging_fault_matrix() {
    let base = base_with_file(BYTES);
    base.place_unsynced(&dir(), ".tmp-00000000000000000000000000000abc", b"x");
    assert_eq!(store(&base.fork()).remove_staging(&dir()), Ok(1));
    matrix(
        &base,
        &[
            KagemushaWalletSimFaultV1::Error,
            KagemushaWalletSimFaultV1::CrashBefore,
            KagemushaWalletSimFaultV1::CrashAfter,
        ],
        &|store| store.remove_staging(&dir()),
        &|case| {
            assert_eq!(case.file("f").as_deref(), Some(BYTES), "{}", case.label());
            if case.observed() && case.outcome == &Ok(1) {
                assert_eq!(case.fs.visible_names(&dir()), ["f"], "{}", case.label());
            }
        },
    );
    assert_eq!(
        store(&base).remove_staging(&dir().child(&name("none"))),
        Ok(0)
    );
}

#[test]
fn wallet_advance_v1_store_classify_errors() {
    use io::ErrorKind as K;
    assert!(classify(&io::Error::from(K::AlreadyExists)) == FailureClassV1::Exists);
    for kind in [K::Unsupported, K::InvalidInput] {
        assert!(classify(&io::Error::from(kind)) == FailureClassV1::Unsupported);
    }
    for kind in [K::StorageFull, K::QuotaExceeded] {
        assert!(classify(&io::Error::from(kind)) == FailureClassV1::NoSpace);
    }
    for kind in [
        K::PermissionDenied,
        K::NotFound,
        K::ReadOnlyFilesystem,
        K::IsADirectory,
    ] {
        assert!(classify(&io::Error::from(kind)) == FailureClassV1::Definitive);
    }
    for kind in [K::Other, K::Interrupted, K::TimedOut, K::UnexpectedEof] {
        assert!(classify(&io::Error::from(kind)) == FailureClassV1::Indeterminate);
    }
    assert_eq!(
        not_published(&io::Error::from(K::StorageFull)),
        KagemushaWalletNotPublishedV1::NoSpace
    );
    assert_eq!(
        unavailable(&io::Error::from(K::WouldBlock)),
        KagemushaWalletUnavailableV1::Busy
    );
}

#[test]
fn wallet_advance_v1_sim_power_loss_models() {
    let fs = base();
    fs.place_unsynced(&dir(), "u", BYTES);
    assert_eq!(fs.visible_file(&dir(), "u").as_deref(), Some(BYTES));
    let strict = fs.fork();
    strict.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert_eq!(strict.visible_file(&dir(), "u"), None);
    let restarted = fs.fork();
    restarted.restart();
    assert_eq!(restarted.visible_file(&dir(), "u").as_deref(), Some(BYTES));
    // Seeded power loss is deterministic per seed and explores both survival outcomes.
    let mut survived = 0;
    for seed in 0..32 {
        let left = fs.fork();
        let right = fs.fork();
        left.power_loss(KagemushaWalletSimPowerLossV1::Seeded(seed));
        right.power_loss(KagemushaWalletSimPowerLossV1::Seeded(seed));
        assert_eq!(
            left.visible_file(&dir(), "u"),
            right.visible_file(&dir(), "u")
        );
        if let Some(value) = left.visible_file(&dir(), "u") {
            assert!(BYTES.starts_with(&value));
            survived += 1;
        }
    }
    assert!(survived > 0 && survived < 32);
    // An unsynced directory disappears with its contents.
    let nested = base();
    KagemushaWalletFsV1::mkdir(&nested, &dir(), "e").expect("mkdir");
    assert!(nested.visible_dir(&dir().child(&name("e"))));
    nested.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert!(!nested.visible_dir(&dir().child(&name("e"))));
}

#[test]
fn wallet_advance_v1_store_remove_dir_only_removes_empty_directories() {
    let fs = base();
    let store = store(&fs);
    let root = KagemushaWalletCustodyDirV1::root();
    assert_eq!(
        store.remove_dir(&root, &name("d")),
        KagemushaWalletRemoveOutcomeV1::Removed,
        "an empty directory"
    );
    assert!(!fs.visible_dir(&dir()));
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert!(!fs.visible_dir(&dir()), "the removal is durable");
    assert_eq!(
        store.remove_dir(&root, &name("d")),
        KagemushaWalletRemoveOutcomeV1::Removed,
        "an absent directory is synced as absent"
    );
    let fs = base_with_file(BYTES);
    let store = self::store(&fs);
    assert!(matches!(
        store.remove_dir(&root, &name("d")),
        KagemushaWalletRemoveOutcomeV1::NotRemoved(_)
    ));
    assert!(matches!(
        store.remove_dir(&dir(), &name("f")),
        KagemushaWalletRemoveOutcomeV1::NotRemoved(_)
    ));
    assert_eq!(fs.visible_file(&dir(), "f").as_deref(), Some(BYTES));
    // An unsynced removal that does not survive power loss leaves the directory, empty.
    let fs = base();
    KagemushaWalletFsV1::remove_dir(&fs, &root, "d").expect("rmdir");
    assert!(!fs.visible_dir(&dir()));
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert!(fs.visible_dir(&dir()));
    assert_eq!(fs.visible_names(&dir()), Vec::<String>::new());
    let fs = base();
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        self::store(&fs).remove_dir(&root, &name("d")),
        KagemushaWalletRemoveOutcomeV1::Uncertain(_)
    ));
    fs.inject(fs.steps() + 1, KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        self::store(&fs).remove_dir(&root, &name("d")),
        KagemushaWalletRemoveOutcomeV1::Uncertain(_)
    ));
}

#[test]
fn wallet_advance_v1_sim_subset_power_loss_enumerates_pending_operations() {
    let fs = base();
    assert_eq!(fs.pending_dir_ops(), 0);
    fs.place_unsynced(&dir(), "a", BYTES);
    fs.place_unsynced(&dir(), "b", BYTES);
    assert_eq!(fs.pending_dir_ops(), 2);
    let mut seen = Vec::new();
    for mask in 0..4_u64 {
        let survivor = fs.fork();
        survivor.power_loss(KagemushaWalletSimPowerLossV1::Subset { mask, seed: 0 });
        assert_eq!(survivor.pending_dir_ops(), 0);
        let names = survivor.visible_names(&dir());
        assert_eq!(
            names.contains(&"a".to_owned()),
            mask & 1 == 1,
            "mask {mask}"
        );
        assert_eq!(
            names.contains(&"b".to_owned()),
            mask & 2 == 2,
            "mask {mask}"
        );
        seen.push(names);
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 4, "every subset is distinct");
}

#[test]
fn wallet_advance_v1_sim_fork_and_crash_semantics() {
    let fs = base();
    let forked = fs.fork();
    assert_eq!(
        store(&forked).write_new(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::Published
    );
    assert_eq!(fs.visible_file(&dir(), "f"), None, "forks are independent");
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::CrashBefore);
    assert!(matches!(
        store(&fs).write_new(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::NotPublished(_)
    ));
    assert!(fs.crashed());
    assert!(matches!(
        store(&fs).read(&dir(), &name("f"), 8),
        KagemushaWalletReadV1::Unavailable(_)
    ));
    fs.restart();
    assert!(!fs.crashed());
    fs.inject(fs.steps() + 3, KagemushaWalletSimFaultV1::Error);
    fs.clear_faults();
    assert_eq!(
        store(&fs).write_new(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::Published
    );
}

// ---------------------------------------------------------------------------------------
// Batch publication (ML W1)
// ---------------------------------------------------------------------------------------

/// Staged files per chunk in the batch matrices: three records (six copies) cross a chunk
/// boundary.
const LIVE: usize = 4;

/// Batch names, each with the exact bytes it is to hold.
type BatchNamesV1 = Vec<(KagemushaWalletEntryNameV1, Vec<u8>)>;

/// Both copies of `records` archive records, in record order. Every copy has its own bytes,
/// so a name that holds another name's bytes is detected.
fn batch_names(records: usize) -> BatchNamesV1 {
    (0..records)
        .flat_map(|record| {
            [format!("w-{record:02}.rec"), format!("w-{record:02}.rec.r")]
                .map(|copy| (name(&copy), format!("bytes of {copy}").into_bytes()))
        })
        .collect()
}

/// Entries publishing `names`, with the action `action` chooses for each index.
fn batch_entries(
    names: &[(KagemushaWalletEntryNameV1, Vec<u8>)],
    action: impl Fn(usize) -> KagemushaWalletBatchActionV1,
) -> Vec<KagemushaWalletBatchEntryV1<'_>> {
    names
        .iter()
        .enumerate()
        .map(|(index, (entry_name, bytes))| KagemushaWalletBatchEntryV1 {
            name: entry_name,
            bytes: bytes.as_slice(),
            action: action(index),
        })
        .collect()
}

/// Publish every name of `names` create-new, [`LIVE`] staged files per chunk.
fn publish_new(
    store: &SimStore,
    names: &[(KagemushaWalletEntryNameV1, Vec<u8>)],
) -> KagemushaWalletPublishOutcomeV1 {
    store.publish_batch_chunked(
        &dir(),
        &batch_entries(names, |_| KagemushaWalletBatchActionV1::New),
        LIVE,
    )
}

/// Index of the first rename in a batch trace.
fn first_rename(trace: &[KagemushaWalletSimStepV1]) -> u64 {
    let index = trace
        .iter()
        .position(|step| {
            matches!(
                step,
                KagemushaWalletSimStepV1::RenameNoReplace | KagemushaWalletSimStepV1::RenameReplace
            )
        })
        .expect("a batch renames");
    u64::try_from(index).expect("index")
}

/// Every visible entry of `d` is a batch name holding exactly its bytes, or a staging file:
/// no name is torn or foreign.
fn check_absent_or_exact(
    fs: &KagemushaWalletSimFsV1,
    names: &[(KagemushaWalletEntryNameV1, Vec<u8>)],
    label: &str,
) {
    for entry in fs.visible_names(&dir()) {
        assert!(
            names
                .iter()
                .any(|(entry_name, _)| entry_name.as_str() == entry)
                || kagemusha_wallet_is_staging_name_v1(&entry),
            "unexpected entry {entry} at {label}"
        );
    }
    for (entry_name, bytes) in names {
        let value = fs.visible_file(&dir(), entry_name.as_str());
        assert!(
            value.is_none() || value.as_deref() == Some(bytes.as_slice()),
            "torn or foreign {} at {label}",
            entry_name.as_str()
        );
    }
}

/// No batch name is visible.
fn check_none_published(
    fs: &KagemushaWalletSimFsV1,
    names: &[(KagemushaWalletEntryNameV1, Vec<u8>)],
    label: &str,
) {
    for (entry_name, _) in names {
        assert_eq!(
            fs.visible_file(&dir(), entry_name.as_str()),
            None,
            "unpublished {} visible at {label}",
            entry_name.as_str()
        );
    }
}

/// The caller's retry after it reconciled, run on a copy of `fs`: a visible name that holds
/// exactly its bytes is adopted on a fresh inode and an absent one is created. The retry
/// publishes every name, and the result survives power loss exactly.
fn check_retry_publishes(
    fs: &KagemushaWalletSimFsV1,
    names: &[(KagemushaWalletEntryNameV1, Vec<u8>)],
    label: &str,
) {
    let fs = fs.fork();
    fs.restart();
    fs.clear_faults();
    let before: Vec<Option<u64>> = names
        .iter()
        .map(|(entry_name, _)| fs.inode_of(&dir(), entry_name.as_str()))
        .collect();
    let retry = batch_entries(names, |index| {
        let (entry_name, bytes) = &names[index];
        match fs.visible_file(&dir(), entry_name.as_str()) {
            None => KagemushaWalletBatchActionV1::New,
            Some(value) if value == *bytes => KagemushaWalletBatchActionV1::Replace,
            Some(_) => panic!(
                "torn or foreign {} before the retry at {label}",
                entry_name.as_str()
            ),
        }
    });
    assert_eq!(
        store(&fs).publish_batch_chunked(&dir(), &retry, LIVE),
        KagemushaWalletPublishOutcomeV1::Published,
        "retry at {label}"
    );
    for ((entry_name, _), before) in names.iter().zip(before) {
        if before.is_some() {
            assert_ne!(
                fs.inode_of(&dir(), entry_name.as_str()),
                before,
                "{} adopted on a fresh inode at {label}",
                entry_name.as_str()
            );
        }
    }
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    for (entry_name, bytes) in names {
        assert_eq!(
            fs.visible_file(&dir(), entry_name.as_str()).as_deref(),
            Some(bytes.as_slice()),
            "retried {} durable at {label}",
            entry_name.as_str()
        );
    }
}

#[test]
fn wallet_advance_v1_store_batch_syncs_every_copy_then_renames_then_syncs_the_directory_once() {
    use KagemushaWalletSimStepV1 as Step;
    // 35 records are 70 copies: two production chunks.
    for records in [1_usize, 3, 35] {
        let names = batch_names(records);
        let fs = base();
        let start = fs.steps();
        let (outcome, c) = KagemushaWalletStorageCountersV1::observe(|| {
            store(&fs).publish_batch(
                &dir(),
                &batch_entries(&names, |_| KagemushaWalletBatchActionV1::New),
            )
        });
        assert_eq!(outcome, KagemushaWalletPublishOutcomeV1::Published);
        let mut expected = Vec::new();
        for chunk in names.chunks(KAGEMUSHA_WALLET_BATCH_LIVE_STAGED_V1) {
            for _ in chunk {
                expected.extend([Step::CreateNew, Step::Write, Step::SyncFile]);
            }
            expected.extend(chunk.iter().map(|_| Step::RenameNoReplace));
        }
        expected.push(Step::SyncDir);
        assert_eq!(fs.trace_since(start), expected, "{records} records");
        let copies = u64::try_from(names.len()).expect("copies");
        assert_eq!(
            (
                c.batch_publishes,
                c.batch_names,
                c.write_new,
                c.rewrite_same,
                c.reads,
                c.staged_syncs,
                c.publish_syncs,
                c.dir_syncs,
                c.file_syncs,
                c.fsync_class_calls(),
            ),
            (1, copies, copies, 0, 0, copies, 1, 0, 0, copies + 1),
            "{records} records: a data sync per copy and one directory sync"
        );
        fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
        for (entry_name, bytes) in &names {
            assert_eq!(
                fs.visible_file(&dir(), entry_name.as_str()).as_deref(),
                Some(bytes.as_slice())
            );
        }
        // The same copies published one name at a time: a data and a directory sync each.
        let single = base();
        let ((), one_by_one) = KagemushaWalletStorageCountersV1::observe(|| {
            for (entry_name, bytes) in &names {
                assert_eq!(
                    store(&single).write_new(&dir(), entry_name, bytes),
                    KagemushaWalletPublishOutcomeV1::Published
                );
            }
        });
        assert_eq!(one_by_one.fsync_class_calls(), 2 * copies);
    }
}

#[test]
fn wallet_advance_v1_store_batch_fault_before_a_rename_is_not_published_and_names_no_file() {
    let names = batch_names(3);
    let base = base();
    let first = first_rename(&fault_free_trace(&base, &|store| {
        publish_new(store, &names)
    }));
    assert_eq!(first, 3 * 4, "the first chunk stages four copies first");
    let cases = matrix_where(
        &base,
        &FAULTS,
        &|step| step < first,
        &|store| publish_new(store, &names),
        &|case| {
            let label = case.label();
            check_none_published(case.fs, &names, &label);
            only_names(case, &[]);
            if case.observed() {
                assert!(
                    matches!(
                        case.outcome,
                        KagemushaWalletPublishOutcomeV1::NotPublished(_)
                    ),
                    "{:?} at {label}",
                    case.outcome
                );
                if case.moment == Moment::Immediate {
                    assert!(
                        case.fs.visible_names(&dir()).is_empty(),
                        "staged files discarded at {label}"
                    );
                }
            }
            check_retry_publishes(case.fs, &names, &label);
        },
    );
    assert_eq!(
        u64::try_from(cases).expect("cases"),
        first * u64::try_from(FAULTS.len()).expect("faults") * (3 + SEEDS)
    );
}

#[test]
fn wallet_advance_v1_store_batch_fault_after_a_rename_is_uncertain_for_every_record() {
    let names = batch_names(3);
    let base = base();
    let first = first_rename(&fault_free_trace(&base, &|store| {
        publish_new(store, &names)
    }));
    let cases = matrix_where(
        &base,
        &FAULTS,
        &|step| step >= first,
        &|store| publish_new(store, &names),
        &|case| {
            let label = case.label();
            check_absent_or_exact(case.fs, &names, &label);
            if case.observed() {
                match case.outcome {
                    KagemushaWalletPublishOutcomeV1::Uncertain(_) => {}
                    // Only the first rename can refuse definitively: nothing is renamed then.
                    KagemushaWalletPublishOutcomeV1::NotPublished(_) if case.step == first => {
                        check_none_published(case.fs, &names, &label);
                    }
                    other => panic!("{other:?} at {label}"),
                }
            }
            check_retry_publishes(case.fs, &names, &label);
        },
    );
    assert!(cases > 0);
}

#[test]
fn wallet_advance_v1_store_batch_lost_writeback_is_never_published() {
    use KagemushaWalletSimStepV1 as Step;
    let names = batch_names(3);
    let base = base();
    let trace = fault_free_trace(&base, &|store| publish_new(store, &names));
    let first = first_rename(&trace);
    let mut syncs = 0;
    for (step, kind) in (0_u64..).zip(&trace) {
        if !matches!(kind, Step::SyncFile | Step::SyncDir) {
            continue;
        }
        syncs += 1;
        let label = format!("lost writeback at step {step} ({kind:?})");
        let fs = base.fork();
        fs.inject(fs.steps() + step, KagemushaWalletSimFaultV1::LostWriteback);
        let outcome = publish_new(&store(&fs), &names);
        assert!(!fs.crashed(), "{label}");
        match outcome {
            KagemushaWalletPublishOutcomeV1::NotPublished(_) => {
                assert!(step < first, "{label}");
                check_none_published(&fs, &names, &label);
            }
            KagemushaWalletPublishOutcomeV1::Uncertain(_) => assert!(step > first, "{label}"),
            KagemushaWalletPublishOutcomeV1::Published => panic!("{label} was published"),
        }
        if *kind == Step::SyncDir {
            // The lost directory writeback dropped every rename; a later sync is vacuous.
            let vacuous = fs.fork();
            assert_eq!(store(&vacuous).sync_dir(&dir()), Ok(()));
            vacuous.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
            check_none_published(&vacuous, &names, &label);
        }
        let lost = fs.fork();
        lost.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
        check_absent_or_exact(&lost, &names, &label);
        check_retry_publishes(&fs, &names, &label);
        check_retry_publishes(&lost, &names, &label);
    }
    assert_eq!(
        syncs,
        names.len() + 1,
        "a data sync per copy and one directory sync"
    );
}

#[test]
fn wallet_advance_v1_store_batch_power_loss_subsets_leave_each_name_absent_or_exact() {
    for records in [1_usize, 3] {
        let names = batch_names(records);
        let base = base();
        let trace = fault_free_trace(&base, &|store| publish_new(store, &names));
        assert_eq!(trace.last(), Some(&KagemushaWalletSimStepV1::SyncDir));
        let last = u64::try_from(trace.len()).expect("steps") - 1;
        // A crash before step `s` leaves the state of a crash after step `s - 1`.
        let crashes = std::iter::once((0, KagemushaWalletSimFaultV1::CrashBefore))
            .chain((0..=last).map(|step| (step, KagemushaWalletSimFaultV1::CrashAfter)));
        let mut models = 0_usize;
        for (step, fault) in crashes {
            let crashed = base.fork();
            crashed.inject(crashed.steps() + step, fault);
            assert_ne!(
                publish_new(&store(&crashed), &names),
                KagemushaWalletPublishOutcomeV1::Published
            );
            assert!(crashed.crashed());
            // A link and a rename per copy at most: every subset is enumerated.
            let pending = crashed.pending_dir_ops();
            assert!(pending <= 2 * names.len(), "{pending} pending operations");
            let mut power: Vec<KagemushaWalletSimPowerLossV1> = (0..1_u64 << pending)
                .map(|mask| KagemushaWalletSimPowerLossV1::Subset { mask, seed: mask })
                .collect();
            power.push(KagemushaWalletSimPowerLossV1::DropUnsynced);
            power.extend((0..SEEDS).map(KagemushaWalletSimPowerLossV1::Seeded));
            for model in power {
                let label = format!("{records} records, {fault:?} at step {step}, {model:?}");
                let view = crashed.fork();
                view.power_loss(model);
                check_absent_or_exact(&view, &names, &label);
                if model == KagemushaWalletSimPowerLossV1::DropUnsynced {
                    // Only the completed directory sync makes the batch durable.
                    let durable = step == last && fault == KagemushaWalletSimFaultV1::CrashAfter;
                    for (entry_name, bytes) in &names {
                        assert_eq!(
                            view.visible_file(&dir(), entry_name.as_str()).as_deref(),
                            durable.then_some(bytes.as_slice()),
                            "{} at {label}",
                            entry_name.as_str()
                        );
                    }
                }
                check_retry_publishes(&view, &names, &label);
                models += 1;
            }
        }
        assert!(models > usize::try_from(last).expect("steps"));
    }
}

#[test]
fn wallet_advance_v1_store_batch_replace_adopts_on_a_fresh_inode() {
    use KagemushaWalletSimStepV1 as Step;
    let names = batch_names(3);
    // The first chunk replaces four durable copies; the second creates two new ones.
    let replaced = 4;
    let base = base();
    for (entry_name, bytes) in &names[..replaced] {
        assert_eq!(
            store(&base).write_new(&dir(), entry_name, bytes),
            KagemushaWalletPublishOutcomeV1::Published
        );
    }
    let action = move |index: usize| {
        if index < replaced {
            KagemushaWalletBatchActionV1::Replace
        } else {
            KagemushaWalletBatchActionV1::New
        }
    };
    let inodes: Vec<Option<u64>> = names[..replaced]
        .iter()
        .map(|(entry_name, _)| base.inode_of(&dir(), entry_name.as_str()))
        .collect();
    let fs = base.fork();
    let start = fs.steps();
    let (outcome, c) = KagemushaWalletStorageCountersV1::observe(|| {
        store(&fs).publish_batch_chunked(&dir(), &batch_entries(&names, action), LIVE)
    });
    assert_eq!(outcome, KagemushaWalletPublishOutcomeV1::Published);
    let trace = fs.trace_since(start);
    let steps = |kind: Step| trace.iter().filter(|step| **step == kind).count();
    assert_eq!(
        (
            steps(Step::Read),
            steps(Step::RenameReplace),
            steps(Step::RenameNoReplace),
            steps(Step::SyncFile),
            steps(Step::SyncDir),
        ),
        (0, replaced, names.len() - replaced, names.len(), 1)
    );
    assert_eq!(
        (
            c.batch_names,
            c.rewrite_same,
            c.write_new,
            c.reads,
            c.fsync_class_calls()
        ),
        (6, 4, 2, 0, 7)
    );
    for ((entry_name, _), inode) in names[..replaced].iter().zip(&inodes) {
        assert_ne!(
            fs.inode_of(&dir(), entry_name.as_str()),
            *inode,
            "fresh inode"
        );
    }
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    for (entry_name, bytes) in &names {
        assert_eq!(
            fs.visible_file(&dir(), entry_name.as_str()).as_deref(),
            Some(bytes.as_slice())
        );
    }
    // A replaced name holds its exact bytes at every step, fault and moment: never absent.
    matrix(
        &base,
        &FAULTS,
        &|store| store.publish_batch_chunked(&dir(), &batch_entries(&names, action), LIVE),
        &|case| {
            let label = case.label();
            check_absent_or_exact(case.fs, &names, &label);
            for (entry_name, bytes) in &names[..replaced] {
                assert_eq!(
                    case.file(entry_name.as_str()).as_deref(),
                    Some(bytes.as_slice()),
                    "replaced {} at {label}",
                    entry_name.as_str()
                );
            }
            if case.observed() {
                assert_ne!(
                    *case.outcome,
                    KagemushaWalletPublishOutcomeV1::Published,
                    "{label}"
                );
            }
            check_retry_publishes(case.fs, &names, &label);
        },
    );
}

#[test]
fn wallet_advance_v1_store_batch_chunks_bound_live_staged_files() {
    use KagemushaWalletSimStepV1 as Step;
    assert_eq!(KAGEMUSHA_WALLET_BATCH_LIVE_STAGED_V1, 64);
    // Staged files created and neither renamed nor discarded: at the end, and at most.
    let live_staged = |trace: &[Step]| {
        let (mut live, mut most) = (0_usize, 0_usize);
        for step in trace {
            match step {
                Step::CreateNew => {
                    live += 1;
                    most = most.max(live);
                }
                Step::RenameNoReplace | Step::RenameReplace | Step::Unlink => {
                    live = live
                        .checked_sub(1)
                        .expect("a staged file to rename or discard");
                }
                _ => {}
            }
        }
        (live, most)
    };
    for (records, live, chunks) in [
        (5_usize, LIVE, vec![4_usize, 4, 2]),
        (35, KAGEMUSHA_WALLET_BATCH_LIVE_STAGED_V1, vec![64, 6]),
    ] {
        let names = batch_names(records);
        let entries = batch_entries(&names, |_| KagemushaWalletBatchActionV1::New);
        let fs = base();
        let start = fs.steps();
        let outcome = if live == KAGEMUSHA_WALLET_BATCH_LIVE_STAGED_V1 {
            store(&fs).publish_batch(&dir(), &entries)
        } else {
            store(&fs).publish_batch_chunked(&dir(), &entries, live)
        };
        assert_eq!(outcome, KagemushaWalletPublishOutcomeV1::Published);
        let trace = fs.trace_since(start);
        assert_eq!(
            live_staged(trace.as_slice()),
            (0, live),
            "{records} records"
        );
        let mut expected = Vec::new();
        for chunk in chunks {
            for _ in 0..chunk {
                expected.extend([Step::CreateNew, Step::Write, Step::SyncFile]);
            }
            expected.extend((0..chunk).map(|_| Step::RenameNoReplace));
        }
        expected.push(Step::SyncDir);
        assert_eq!(trace, expected, "{records} records");
    }
    // A failure inside any chunk discards every staged file it still holds.
    let names = batch_names(5);
    let base = base();
    let trace = fault_free_trace(&base, &|store| publish_new(store, &names));
    for (step, kind) in (0_u64..).zip(&trace) {
        if *kind != Step::SyncFile {
            continue;
        }
        let fs = base.fork();
        let start = fs.steps();
        fs.inject(start + step, KagemushaWalletSimFaultV1::Error);
        assert_ne!(
            publish_new(&store(&fs), &names),
            KagemushaWalletPublishOutcomeV1::Published
        );
        let (left, most) = live_staged(fs.trace_since(start).as_slice());
        assert_eq!(
            left, 0,
            "step {step}: every staged file is renamed or discarded"
        );
        assert!(most <= LIVE, "step {step}");
        assert!(
            !fs.visible_names(&dir())
                .iter()
                .any(|entry| kagemusha_wallet_is_staging_name_v1(entry)),
            "step {step}: no staging residue"
        );
    }
}

#[test]
fn wallet_advance_v1_store_batch_refuses_repeated_names_and_an_empty_batch_takes_no_step() {
    let fs = base();
    let start = fs.steps();
    let (outcome, c) =
        KagemushaWalletStorageCountersV1::observe(|| store(&fs).publish_batch(&dir(), &[]));
    assert_eq!(outcome, KagemushaWalletPublishOutcomeV1::Published);
    assert_eq!(c, KagemushaWalletStorageCountersV1::default());
    let repeated_name = name("f");
    let repeated = [
        KagemushaWalletBatchEntryV1 {
            name: &repeated_name,
            bytes: BYTES,
            action: KagemushaWalletBatchActionV1::New,
        },
        KagemushaWalletBatchEntryV1 {
            name: &repeated_name,
            bytes: OTHER,
            action: KagemushaWalletBatchActionV1::Replace,
        },
    ];
    let (outcome, c) =
        KagemushaWalletStorageCountersV1::observe(|| store(&fs).publish_batch(&dir(), &repeated));
    assert_eq!(
        outcome,
        KagemushaWalletPublishOutcomeV1::NotPublished(KagemushaWalletNotPublishedV1::Failed(
            KagemushaWalletUnavailableV1::Io(0)
        ))
    );
    assert_eq!(c, KagemushaWalletStorageCountersV1::default());
    assert!(fs.trace_since(start).is_empty(), "no filesystem step");
    assert!(fs.visible_names(&dir()).is_empty());
}

#[test]
fn wallet_advance_v1_store_batch_create_new_never_replaces() {
    let base = base_with_file(OTHER);
    let (occupied, fresh) = (name("f"), name("g"));
    let alone = [KagemushaWalletBatchEntryV1 {
        name: &occupied,
        bytes: BYTES,
        action: KagemushaWalletBatchActionV1::New,
    }];
    let fs = base.fork();
    assert_eq!(
        store(&fs).publish_batch(&dir(), &alone),
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::DestinationExists
        )
    );
    assert_eq!(fs.visible_names(&dir()), ["f"]);
    assert_eq!(fs.visible_file(&dir(), "f").as_deref(), Some(OTHER));
    // After an earlier rename the same refusal leaves the batch uncertain.
    let after = [
        KagemushaWalletBatchEntryV1 {
            name: &fresh,
            bytes: BYTES,
            action: KagemushaWalletBatchActionV1::New,
        },
        alone[0],
    ];
    let fs = base.fork();
    assert!(matches!(
        store(&fs).publish_batch(&dir(), &after),
        KagemushaWalletPublishOutcomeV1::Uncertain(_)
    ));
    assert_eq!(fs.visible_names(&dir()), ["f", "g"]);
    assert_eq!(fs.visible_file(&dir(), "f").as_deref(), Some(OTHER));
    matrix(
        &base,
        &FAULTS,
        &|store| store.publish_batch(&dir(), &after),
        &|case| {
            assert_eq!(case.file("f").as_deref(), Some(OTHER), "{}", case.label());
            let created = case.file("g");
            assert!(
                created.is_none() || created.as_deref() == Some(BYTES),
                "{}",
                case.label()
            );
            if case.observed() {
                assert_ne!(
                    *case.outcome,
                    KagemushaWalletPublishOutcomeV1::Published,
                    "{}",
                    case.label()
                );
            }
            only_names(case, &["f", "g"]);
        },
    );
}

#[test]
fn wallet_advance_v1_store_batch_noreplace_unsupported_is_not_published() {
    let names = batch_names(1);
    let fs = base();
    fs.set_noreplace_supported(false);
    assert_eq!(
        publish_new(&store(&fs), &names),
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::NoReplaceUnsupported
        )
    );
    assert!(fs.visible_names(&dir()).is_empty());
    // Fresh-inode adoption needs only a replacing rename.
    fs.set_noreplace_supported(true);
    assert_eq!(
        publish_new(&store(&fs), &names),
        KagemushaWalletPublishOutcomeV1::Published
    );
    fs.set_noreplace_supported(false);
    assert_eq!(
        store(&fs).publish_batch(
            &dir(),
            &batch_entries(&names, |_| KagemushaWalletBatchActionV1::Replace)
        ),
        KagemushaWalletPublishOutcomeV1::Published
    );
}

#[cfg(unix)]
mod std_fs {
    use super::*;
    use crate::kagemusha_wallet_advance_v1::{
        KagemushaWalletStdFsV1, kagemusha_wallet_probe_noreplace_v1,
    };

    fn std_store() -> (
        tempfile::TempDir,
        KagemushaWalletDurableStoreV1<KagemushaWalletStdFsV1>,
    ) {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("root");
        assert_eq!(
            KagemushaWalletStdFsV1::create_root(&root),
            KagemushaWalletPublishOutcomeV1::Published
        );
        assert_eq!(
            KagemushaWalletStdFsV1::create_root(&root),
            KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::DestinationExists
            )
        );
        let fs = KagemushaWalletStdFsV1::open(&root).expect("open");
        assert_eq!(fs.root(), root.as_path());
        let store = KagemushaWalletDurableStoreV1::new(fs);
        assert_eq!(
            store.create_dir(&KagemushaWalletCustodyDirV1::root(), &name("d")),
            KagemushaWalletPublishOutcomeV1::Published
        );
        (temp, store)
    }

    fn deep_cached_store(
        depth: usize,
    ) -> (
        tempfile::TempDir,
        KagemushaWalletDurableStoreV1<KagemushaWalletStdFsV1>,
        KagemushaWalletCustodyDirV1,
        Vec<std::path::PathBuf>,
    ) {
        assert!(depth > 0);
        let (temp, store) = std_store();
        let mut selected = dir();
        let mut path = temp.path().join("root");
        let mut ancestors = vec![path.clone()];
        path.push("d");
        ancestors.push(path.clone());
        for level in 1..depth {
            let child = name(&format!("level-{level:02}"));
            assert_eq!(
                store.create_dir(&selected, &child),
                KagemushaWalletPublishOutcomeV1::Published
            );
            selected = selected.child(&child);
            path.push(format!("level-{level:02}"));
            ancestors.push(path.clone());
        }
        assert_eq!(
            store.write_new(&selected, &name("f"), BYTES),
            KagemushaWalletPublishOutcomeV1::Published
        );
        assert_eq!(
            store.read(&selected, &name("f"), 1024),
            KagemushaWalletReadV1::Present(BYTES.to_vec())
        );
        (temp, store, selected, ancestors)
    }

    #[test]
    fn wallet_advance_v1_std_fs_deep_cached_reads_reject_each_replaced_ancestor() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        for position in 0..5 {
            let (temp, store, selected, ancestors) = deep_cached_store(4);
            let original = &ancestors[position];
            let displaced = temp.path().join("displaced-original");
            std::fs::rename(original, &displaced).unwrap();
            assert!(
                matches!(
                    store.read(&selected, &name("missing"), 0),
                    KagemushaWalletReadV1::Unavailable(_)
                ),
                "a vanished cached ancestor is not leaf absence: {position}"
            );
            for path in &ancestors[position..] {
                std::fs::create_dir(path).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let leaf = ancestors.last().unwrap();
            std::fs::write(leaf.join("f"), OTHER).unwrap();
            std::fs::set_permissions(leaf.join("f"), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            assert!(
                matches!(
                    store.read(&selected, &name("f"), 1024),
                    KagemushaWalletReadV1::Unavailable(_)
                ),
                "same-name replacement cannot be adopted: {position}"
            );
            assert!(matches!(
                store.list(&selected),
                KagemushaWalletProbeV1::Unavailable(_)
            ));
            assert!(matches!(
                store.write_new(&selected, &name("intruder"), OTHER),
                KagemushaWalletPublishOutcomeV1::NotPublished(_)
            ));
            assert!(!leaf.join("intruder").exists());
            std::fs::remove_dir_all(original).unwrap();
            symlink(&displaced, original).unwrap();
            assert!(
                matches!(
                    store.read(&selected, &name("f"), 1024),
                    KagemushaWalletReadV1::Unavailable(_)
                ),
                "even a link to the retained inode must be refused: {position}"
            );
            std::fs::remove_file(original).unwrap();
            std::fs::rename(&displaced, original).unwrap();
            assert_eq!(
                store.read(&selected, &name("f"), 1024),
                KagemushaWalletReadV1::Present(BYTES.to_vec())
            );
        }
    }

    #[test]
    fn wallet_advance_v1_std_fs_deep_cached_reads_recheck_each_ancestor_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_temp, store, selected, ancestors) = deep_cached_store(4);
        for path in ancestors {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o770)).unwrap();
            assert!(matches!(
                store.read(&selected, &name("f"), 1024),
                KagemushaWalletReadV1::Unavailable(_)
            ));
            assert!(matches!(
                store.read(&selected, &name("missing"), 0),
                KagemushaWalletReadV1::Unavailable(_)
            ));
            assert!(matches!(
                store.list(&selected),
                KagemushaWalletProbeV1::Unavailable(_)
            ));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(
                store.read(&selected, &name("f"), 1024),
                KagemushaWalletReadV1::Present(BYTES.to_vec())
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn wallet_advance_v1_std_fs_deep_cached_reads_recheck_each_ancestor_acl() {
        let (_temp, store, selected, ancestors) = deep_cached_store(4);
        for path in ancestors {
            assert!(
                std::process::Command::new("chmod")
                    .args(["+a", "everyone allow add_file"])
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(matches!(
                store.read(&selected, &name("f"), 1024),
                KagemushaWalletReadV1::Unavailable(_)
            ));
            assert!(matches!(
                store.read(&selected, &name("missing"), 0),
                KagemushaWalletReadV1::Unavailable(_)
            ));
            assert!(
                std::process::Command::new("chmod")
                    .arg("-N")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            );
            assert_eq!(
                store.read(&selected, &name("f"), 1024),
                KagemushaWalletReadV1::Present(BYTES.to_vec())
            );
        }
    }

    /// A bounded host comparison only; wall-clock samples do not assert phone latency.
    #[test]
    #[ignore = "host filesystem microbenchmark, run explicitly before and after the same source change"]
    fn wallet_advance_v1_std_fs_deep_read_profile() {
        const ITERATIONS: usize = 128;
        for depth in [1, 3, 8] {
            let (_temp, store, selected, _ancestors) = deep_cached_store(depth);
            for sample in 0..5 {
                let start = std::time::Instant::now();
                for _ in 0..ITERATIONS {
                    assert_eq!(
                        store.read(&selected, &name("f"), 1024),
                        KagemushaWalletReadV1::Present(BYTES.to_vec())
                    );
                }
                eprintln!(
                    "WALLET_FS_DEEP_READ depth={depth} sample={sample} iterations={ITERATIONS} elapsed_ns={}",
                    start.elapsed().as_nanos()
                );
            }
        }
    }

    #[test]
    fn wallet_advance_v1_std_fs_open_requires_a_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        assert!(KagemushaWalletStdFsV1::open(temp.path().join("missing")).is_err());
        std::fs::write(temp.path().join("file"), b"x").expect("file");
        assert!(KagemushaWalletStdFsV1::open(temp.path().join("file")).is_err());
        std::os::unix::fs::symlink(temp.path(), temp.path().join("link")).expect("symlink");
        assert!(KagemushaWalletStdFsV1::open(temp.path().join("link")).is_err());
    }

    #[test]
    fn wallet_advance_v1_std_fs_open_requires_a_private_root() {
        use std::os::unix::fs::PermissionsExt as _;
        // Regression: a root open to group or others, or owned by another user, is refused.
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("root");
        assert_eq!(
            KagemushaWalletStdFsV1::create_root(&root),
            KagemushaWalletPublishOutcomeV1::Published
        );
        KagemushaWalletStdFsV1::open(&root).expect("0700 root");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o750)).expect("chmod");
        assert_eq!(
            KagemushaWalletStdFsV1::open(&root).err(),
            Some(KagemushaWalletUnavailableV1::Io(
                rustix::io::Errno::ACCESS.raw_os_error()
            ))
        );
        let euid = rustix::process::geteuid().as_raw();
        assert!(super::super::std_fs::root_is_private(euid, 0o700));
        assert!(!super::super::std_fs::root_is_private(euid, 0o701));
        assert!(!super::super::std_fs::root_is_private(
            euid.wrapping_add(1),
            0o700
        ));
        assert_ne!(super::super::std_fs::NOFOLLOW, 0, "fails closed");
    }

    #[test]
    fn wallet_advance_v1_std_fs_remove_dir() {
        let (temp, store) = std_store();
        let root = KagemushaWalletCustodyDirV1::root();
        std::fs::write(temp.path().join("root").join("d").join("f"), b"x").expect("file");
        assert!(matches!(
            store.remove_dir(&root, &name("d")),
            KagemushaWalletRemoveOutcomeV1::NotRemoved(_)
        ));
        std::fs::remove_file(temp.path().join("root").join("d").join("f")).expect("rm");
        assert_eq!(
            store.remove_dir(&root, &name("d")),
            KagemushaWalletRemoveOutcomeV1::Removed
        );
        assert_eq!(
            store.remove_dir(&root, &name("d")),
            KagemushaWalletRemoveOutcomeV1::Removed
        );
        assert!(!temp.path().join("root").join("d").exists());
    }

    #[test]
    fn wallet_advance_v1_std_fs_create_new_rewrite_remove() {
        let (_temp, store) = std_store();
        assert_eq!(
            store.write_new(&dir(), &name("f"), BYTES),
            KagemushaWalletPublishOutcomeV1::Published
        );
        assert_eq!(
            store.write_new(&dir(), &name("f"), OTHER),
            KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::DestinationExists
            )
        );
        assert_eq!(
            store.read(&dir(), &name("f"), 1_024),
            KagemushaWalletReadV1::Present(BYTES.to_vec())
        );
        assert_eq!(
            store.write_new_pair(&dir(), (&name("p"), BYTES), (&name("f"), BYTES)),
            [
                KagemushaWalletPublishOutcomeV1::Published,
                KagemushaWalletPublishOutcomeV1::NotPublished(
                    KagemushaWalletNotPublishedV1::DestinationExists
                ),
            ]
        );
        assert_eq!(
            store.rewrite_same(&dir(), &name("f"), BYTES),
            KagemushaWalletPublishOutcomeV1::Published
        );
        assert_eq!(
            store.rewrite_same(&dir(), &name("f"), OTHER),
            KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::ContentMismatch
            )
        );
        assert_eq!(store.sync_file(&dir(), &name("f")), Ok(()));
        assert_eq!(store.sync_dir(&dir()), Ok(()));
        assert_eq!(
            store.remove_file(&dir(), &name("f")),
            KagemushaWalletRemoveOutcomeV1::Removed
        );
        assert_eq!(
            store.remove_file(&dir(), &name("f")),
            KagemushaWalletRemoveOutcomeV1::Removed
        );
        assert_eq!(
            store.read(&dir(), &name("f"), 8),
            KagemushaWalletReadV1::Absent
        );
        let KagemushaWalletProbeV1::Present(entries) = store.list(&dir()) else {
            panic!("listing");
        };
        assert_eq!(
            entries,
            [KagemushaWalletListedEntryV1 {
                name: "p".to_owned(),
                kind: KagemushaWalletEntryKindV1::File,
            }]
        );
        assert_eq!(store.remove_staging(&dir()), Ok(0));
    }

    #[test]
    fn wallet_advance_v1_std_fs_batch_publication_retains_each_staged_original() {
        use std::os::unix::fs::MetadataExt as _;
        let (temp, store) = std_store();
        let path = temp.path().join("root").join("d");
        let inode = |entry: &KagemushaWalletEntryNameV1| {
            std::fs::symlink_metadata(path.join(entry.as_str()))
                .expect("published name")
                .ino()
        };
        // Seventy copies cross one production chunk of retained staged originals.
        let names = batch_names(35);
        let (outcome, c) = KagemushaWalletStorageCountersV1::observe(|| {
            store.publish_batch(
                &dir(),
                &batch_entries(&names, |_| KagemushaWalletBatchActionV1::New),
            )
        });
        assert_eq!(outcome, KagemushaWalletPublishOutcomeV1::Published);
        assert_eq!(
            (
                c.batch_publishes,
                c.batch_names,
                c.staged_syncs,
                c.publish_syncs,
                c.fsync_class_calls()
            ),
            (1, 70, 70, 1, 71)
        );
        for (entry_name, bytes) in &names {
            assert_eq!(
                store.read(&dir(), entry_name, bytes.len()),
                KagemushaWalletReadV1::Present(bytes.clone())
            );
        }
        // The exact retry adopts every copy on a fresh inode.
        let before: Vec<u64> = names
            .iter()
            .map(|(entry_name, _)| inode(entry_name))
            .collect();
        assert_eq!(
            store.publish_batch(
                &dir(),
                &batch_entries(&names, |_| KagemushaWalletBatchActionV1::Replace)
            ),
            KagemushaWalletPublishOutcomeV1::Published
        );
        for ((entry_name, bytes), before) in names.iter().zip(before) {
            assert_eq!(
                store.read(&dir(), entry_name, bytes.len()),
                KagemushaWalletReadV1::Present(bytes.clone())
            );
            assert_ne!(inode(entry_name), before, "{}", entry_name.as_str());
        }
        // Create-new never replaces, and no staging file remains.
        let (occupied, kept) = &names[0];
        assert_eq!(
            store.publish_batch(
                &dir(),
                &[KagemushaWalletBatchEntryV1 {
                    name: occupied,
                    bytes: OTHER,
                    action: KagemushaWalletBatchActionV1::New,
                }]
            ),
            KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::DestinationExists
            )
        );
        assert_eq!(
            store.read(&dir(), occupied, kept.len()),
            KagemushaWalletReadV1::Present(kept.clone())
        );
        assert_eq!(store.remove_staging(&dir()), Ok(0));
    }

    #[test]
    fn wallet_advance_v1_std_fs_listing_and_reads_fail_closed() {
        let (temp, store) = std_store();
        let path = temp.path().join("root").join("d");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path.join("big"), vec![0_u8; 64]).expect("big");
        std::fs::set_permissions(path.join("big"), std::fs::Permissions::from_mode(0o600))
            .expect("private fixture");
        assert_eq!(
            store.read(&dir(), &name("big"), 63),
            KagemushaWalletReadV1::Oversized
        );
        std::fs::create_dir(path.join("sub")).expect("sub");
        assert!(matches!(
            store.read(&dir(), &name("sub"), 8),
            KagemushaWalletReadV1::Unavailable(_)
        ));
        std::os::unix::fs::symlink(path.join("big"), path.join("link")).expect("symlink");
        assert!(matches!(
            store.read(&dir(), &name("link"), 1_024),
            KagemushaWalletReadV1::Unavailable(_)
        ));
        std::fs::write(path.join(".tmp-0123456789abcdef0123456789abcdef"), b"t").expect("tmp");
        std::fs::set_permissions(
            path.join(".tmp-0123456789abcdef0123456789abcdef"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("private fixture");
        let KagemushaWalletProbeV1::Present(entries) = store.list(&dir()) else {
            panic!("listing");
        };
        let kinds: Vec<_> = entries
            .iter()
            .map(|entry| (entry.name.as_str(), entry.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                (
                    ".tmp-0123456789abcdef0123456789abcdef",
                    KagemushaWalletEntryKindV1::File
                ),
                ("big", KagemushaWalletEntryKindV1::File),
                ("link", KagemushaWalletEntryKindV1::Other),
                ("sub", KagemushaWalletEntryKindV1::Directory),
            ]
        );
        assert_eq!(store.remove_staging(&dir()), Ok(1));
        assert_eq!(
            store.list(&dir().child(&name("missing"))),
            KagemushaWalletProbeV1::Absent
        );
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStrExt as _;
            std::fs::write(path.join(std::ffi::OsStr::from_bytes(b"\xff")), b"x").expect("raw");
            assert!(matches!(
                store.list(&dir()),
                KagemushaWalletProbeV1::Unavailable(_)
            ));
        }
    }

    #[test]
    fn wallet_advance_v1_std_fs_optional_reads_preserve_prefix_oversized_and_absence() {
        let (temp, store) = std_store();
        assert_eq!(
            store.read(&dir(), &name("missing"), 0),
            KagemushaWalletReadV1::Absent
        );
        assert_eq!(
            store.read(&dir().child(&name("missing-dir")), &name("f"), 8),
            KagemushaWalletReadV1::Absent
        );
        assert_eq!(
            store.write_new(&dir(), &name("bounded"), b"12345678"),
            KagemushaWalletPublishOutcomeV1::Published
        );
        assert_eq!(store.fs().read(&dir(), "bounded", 3).unwrap(), b"123");
        assert_eq!(
            store.read(&dir(), &name("bounded"), 0),
            KagemushaWalletReadV1::Oversized
        );
        assert_eq!(
            store.read(&dir(), &name("bounded"), 7),
            KagemushaWalletReadV1::Oversized
        );
        assert_eq!(
            store.read(&dir(), &name("bounded"), 8),
            KagemushaWalletReadV1::Present(b"12345678".to_vec())
        );
        assert_eq!(
            store.write_new(&dir(), &name("empty"), b""),
            KagemushaWalletPublishOutcomeV1::Published
        );
        assert_eq!(
            store.read(&dir(), &name("empty"), 0),
            KagemushaWalletReadV1::Present(Vec::new())
        );
        let root = temp.path().join("root/d");
        std::fs::rename(&root, temp.path().join("retained-d")).unwrap();
        std::fs::create_dir(&root).unwrap();
        assert!(matches!(
            store.read(&dir(), &name("missing"), 8),
            KagemushaWalletReadV1::Unavailable(_)
        ));
        assert!(matches!(
            store.list(&dir()),
            KagemushaWalletProbeV1::Unavailable(_)
        ));
    }

    // On Android run under the disposable app UID with TMPDIR selected from its
    // private Context directory. Separate opens must contend even within one process.
    #[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn wallet_advance_v1_std_fs_lock_matches_kernel_flock_and_preserves_inode() {
        use rustix::fs::{FlockOperation::NonBlockingLockExclusive, flock};
        use std::os::unix::fs::MetadataExt as _;

        #[cfg(target_os = "android")]
        assert_ne!(rustix::process::geteuid().as_raw(), 0, "use the app UID");
        let (temp, store) = std_store();
        let root = temp.path().join("root");
        let other = KagemushaWalletDurableStoreV1::new(
            KagemushaWalletStdFsV1::open(&root).expect("independent owner"),
        );
        let held = store.lock_exclusive().expect("wallet kernel lock");
        let before = std::fs::symlink_metadata(root.join("lock")).unwrap();
        let directory = iroha_fs::PrivateDirectory::open(&root).unwrap();
        let competing = directory.open_ownership_lock("lock").unwrap();
        assert_eq!(
            flock(&competing, NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        assert_eq!(
            other.lock_exclusive().err(),
            Some(KagemushaWalletUnavailableV1::Busy)
        );
        assert_eq!(
            store.lock_exclusive().err(),
            Some(KagemushaWalletUnavailableV1::Busy)
        );
        drop(held);
        flock(&competing, NonBlockingLockExclusive).expect("guard drop releases the kernel lock");
        assert_eq!(
            other.lock_exclusive().err(),
            Some(KagemushaWalletUnavailableV1::Busy)
        );
        drop(competing);
        let acquired = other
            .lock_exclusive()
            .expect("external descriptor drop releases the lock");
        assert_eq!(
            store.lock_exclusive().err(),
            Some(KagemushaWalletUnavailableV1::Busy)
        );
        drop(acquired);
        let _reacquired = store.lock_exclusive().expect("wallet can acquire again");
        let after = std::fs::symlink_metadata(root.join("lock")).unwrap();
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.uid(),
                before.gid(),
                before.mode(),
                before.nlink()
            ),
            (
                after.dev(),
                after.ino(),
                after.uid(),
                after.gid(),
                after.mode(),
                after.nlink()
            )
        );
        assert_eq!(after.mode() & 0o7777, 0o600);
        assert_eq!(after.nlink(), 1);
    }

    #[test]
    fn wallet_advance_v1_std_fs_lock_space_and_noreplace_probe() {
        let (temp, store) = std_store();
        let other = KagemushaWalletDurableStoreV1::new(
            KagemushaWalletStdFsV1::open(temp.path().join("root")).expect("open"),
        );
        let lock = store.lock_exclusive().expect("lock");
        assert_eq!(
            other.lock_exclusive().err(),
            Some(KagemushaWalletUnavailableV1::Busy)
        );
        drop(lock);
        let _lock = other.lock_exclusive().expect("released");
        assert!(store.available_bytes().expect("statvfs") > 0);
        assert_eq!(kagemusha_wallet_probe_noreplace_v1(&store), Ok(()));
        let staging = store.fs().staging_name().expect("staging name");
        assert!(crate::kagemusha_wallet_advance_v1::kagemusha_wallet_is_staging_name_v1(&staging));
        assert_ne!(
            staging,
            store.fs().staging_name().expect("another staging name")
        );
    }
    #[test]
    fn wallet_advance_v1_std_fs_retains_root_and_child_authority_across_replacement() {
        use std::os::unix::fs::PermissionsExt as _;
        for replace_root in [false, true] {
            let (temp, store) = std_store();
            assert_eq!(
                store.write_new(&dir(), &name("f"), BYTES),
                KagemushaWalletPublishOutcomeV1::Published
            );
            let original = if replace_root {
                temp.path().join("root")
            } else {
                temp.path().join("root/d")
            };
            let displaced = temp.path().join("displaced");
            std::fs::rename(&original, &displaced).expect("move original");
            assert!(
                matches!(
                    store.read(&dir(), &name("f"), 1024),
                    KagemushaWalletReadV1::Unavailable(_)
                ),
                "missing retained parent is unavailable, never file absence"
            );
            std::fs::create_dir(&original).expect("replacement");
            std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700))
                .expect("private replacement");
            assert!(matches!(
                store.list(&dir()),
                KagemushaWalletProbeV1::Unavailable(_)
            ));
            assert!(matches!(
                store.write_new(&dir(), &name("intruder"), OTHER),
                KagemushaWalletPublishOutcomeV1::NotPublished(_)
            ));
            assert!(!original.join("intruder").exists());
            std::fs::remove_dir(&original).expect("remove replacement");
            std::os::unix::fs::symlink(&displaced, &original).expect("redirect");
            assert!(matches!(
                store.read(&dir(), &name("f"), 1024),
                KagemushaWalletReadV1::Unavailable(_)
            ));
        }
    }
    #[test]
    fn wallet_advance_v1_std_fs_refuses_substituted_staging_and_distinguishes_absence() {
        use std::os::unix::fs::PermissionsExt as _;
        let (temp, store) = std_store();
        let fs = store.fs();
        let staged = fs.staging_name().expect("staging name");
        let mut file = fs.create_new(&dir(), &staged).expect("create");
        fs.write_all(&mut file, BYTES).expect("write");
        fs.sync_staged(&file).expect("sync");
        let path = temp.path().join("root/d").join(&staged);
        std::fs::remove_file(&path).expect("remove original");
        std::fs::write(&path, OTHER).expect("substitute");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("private substitute");
        assert!(fs.rename_noreplace(&dir(), &staged, "published").is_err());
        assert_eq!(
            store.read(&dir(), &name("published"), 1024),
            KagemushaWalletReadV1::Absent
        );
        assert!(!temp.path().join("root/d/published").exists());
        assert!(fs.write_all(&mut file, OTHER).is_err());
        assert!(fs.sync_staged(&file).is_err());
        let shared = temp.path().join("root/d/shared");
        std::fs::write(&shared, OTHER).expect("shared mode");
        // The unsafe-mode fixture must remain shared under a private process umask.
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o644))
            .expect("explicit shared mode");
        assert!(matches!(
            store.read(&dir(), &name("shared"), 1024),
            KagemushaWalletReadV1::Unavailable(_)
        ));
    }
}

#[cfg(windows)]
mod windows_std_fs {
    use super::*;
    use crate::kagemusha_wallet_advance_v1::{
        KagemushaWalletStdFsV1, kagemusha_wallet_probe_noreplace_v1,
    };
    fn native_store() -> (
        tempfile::TempDir,
        KagemushaWalletDurableStoreV1<KagemushaWalletStdFsV1>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        assert_eq!(
            KagemushaWalletStdFsV1::create_root(&root),
            KagemushaWalletPublishOutcomeV1::Published
        );
        let fs = KagemushaWalletStdFsV1::open(&root).unwrap();
        let store = KagemushaWalletDurableStoreV1::new(fs);
        assert_eq!(
            store.create_dir(&KagemushaWalletCustodyDirV1::root(), &name("d")),
            KagemushaWalletPublishOutcomeV1::Published
        );
        (temp, store)
    }
    #[test]
    fn wallet_windows_original_publication_collision_rewrite_sync_and_removal() {
        let (_temp, store) = native_store();
        assert_eq!(
            store.write_new(&dir(), &name("record"), BYTES),
            KagemushaWalletPublishOutcomeV1::Published
        );
        assert_eq!(
            store.write_new(&dir(), &name("record"), OTHER),
            KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::DestinationExists
            )
        );
        assert_eq!(
            store.read(&dir(), &name("record"), 1024),
            KagemushaWalletReadV1::Present(BYTES.to_vec())
        );
        assert_eq!(
            store.rewrite_same(&dir(), &name("record"), BYTES),
            KagemushaWalletPublishOutcomeV1::Published
        );
        assert_eq!(store.sync_file(&dir(), &name("record")), Ok(()));
        assert_eq!(store.remove_staging(&dir()), Ok(0));
        assert_eq!(
            store.remove_file(&dir(), &name("record")),
            KagemushaWalletRemoveOutcomeV1::Removed
        );
        assert_eq!(kagemusha_wallet_probe_noreplace_v1(&store), Ok(()));
    }
    #[test]
    fn wallet_windows_missing_sync_and_cached_empty_directory_removal() {
        let (_temp, store) = native_store();
        assert!(store.sync_file(&dir(), &name("missing")).is_err());
        assert_eq!(
            store.read(&dir(), &name("missing"), 1024),
            KagemushaWalletReadV1::Absent
        );
        assert!(matches!(
            store.list(&dir()),
            KagemushaWalletProbeV1::Present(_)
        ));
        assert_eq!(
            store.remove_dir(&KagemushaWalletCustodyDirV1::root(), &name("d")),
            KagemushaWalletRemoveOutcomeV1::Removed
        );
        assert_eq!(
            store.remove_dir(&KagemushaWalletCustodyDirV1::root(), &name("d")),
            KagemushaWalletRemoveOutcomeV1::Removed
        );
    }
    #[test]
    fn wallet_windows_failed_consuming_removal_never_adopts_a_reopened_child() {
        let (temp, store) = native_store();
        assert!(matches!(
            store.list(&dir()),
            KagemushaWalletProbeV1::Present(_)
        ));
        // An independently retained exact child prevents the required DELETE transfer.
        let held = iroha_fs::PrivateDirectory::open(temp.path().join("root/d")).unwrap();
        assert!(!matches!(
            store.remove_dir(&KagemushaWalletCustodyDirV1::root(), &name("d")),
            KagemushaWalletRemoveOutcomeV1::Removed
        ));
        drop(held);
        assert!(matches!(
            store.list(&dir()),
            KagemushaWalletProbeV1::Unavailable(_)
        ));
        assert!(matches!(
            store.write_new(&dir(), &name("intruder"), BYTES),
            KagemushaWalletPublishOutcomeV1::NotPublished(_)
        ));
        assert!(!temp.path().join("root/d/intruder").exists());
        assert!(matches!(
            store.create_dir(&KagemushaWalletCustodyDirV1::root(), &name("d")),
            KagemushaWalletPublishOutcomeV1::Uncertain(_)
        ));
    }
    #[test]
    fn wallet_windows_ownership_fence_and_available_space_use_native_custody() {
        let (temp, store) = native_store();
        let other = KagemushaWalletDurableStoreV1::new(
            KagemushaWalletStdFsV1::open(temp.path().join("root")).unwrap(),
        );
        let lock = store.lock_exclusive().unwrap();
        assert_eq!(
            other.lock_exclusive().err(),
            Some(KagemushaWalletUnavailableV1::Busy)
        );
        assert!(std::fs::rename(temp.path().join("root"), temp.path().join("moved")).is_err());
        assert!(store.available_bytes().unwrap() > 0);
        drop(lock);
        let _lock = other.lock_exclusive().unwrap();
    }
}

#[test]
fn staging_name_entropy_failure_never_returns_a_fallback_name() {
    let name = staging_name_with_entropy(|bytes| {
        *bytes = [0xab; 16];
        Ok(())
    })
    .unwrap();
    assert_eq!(name, format!(".tmp-{}", "ab".repeat(16)));
    assert!(crate::kagemusha_wallet_advance_v1::kagemusha_wallet_is_staging_name_v1(&name));
    let error = staging_name_with_entropy(|bytes| {
        *bytes = [0xff; 16];
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn staging_entropy_failure_does_not_mutate_and_retry_publishes_exact_bytes() {
    let fs = base();
    fs.inject_staging_name_error(0, io::ErrorKind::Other);
    let before = fs.steps();
    assert_eq!(
        store(&fs).write_new(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::NotPublished(KagemushaWalletNotPublishedV1::Failed(
            KagemushaWalletUnavailableV1::Io(0)
        ))
    );
    assert_eq!(
        fs.steps(),
        before,
        "no filesystem operation followed failed entropy"
    );
    assert!(fs.visible_names(&dir()).is_empty());
    assert_eq!(
        store(&fs).write_new(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::Published
    );
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert_eq!(fs.visible_file(&dir(), "f").as_deref(), Some(BYTES));
}

#[test]
fn staging_entropy_failure_keeps_existing_destination_during_rewrite() {
    let fs = base_with_file(BYTES);
    fs.inject_staging_name_error(0, io::ErrorKind::Other);
    let before = fs.steps();
    assert!(matches!(
        store(&fs).rewrite_same(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::NotPublished(KagemushaWalletNotPublishedV1::Failed(_))
    ));
    assert_eq!(fs.trace_since(before), [KagemushaWalletSimStepV1::Read]);
    assert_eq!(fs.visible_names(&dir()), ["f"]);
    assert_eq!(fs.visible_file(&dir(), "f").as_deref(), Some(BYTES));
    assert_eq!(
        store(&fs).rewrite_same(&dir(), &name("f"), BYTES),
        KagemushaWalletPublishOutcomeV1::Published
    );
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert_eq!(fs.visible_file(&dir(), "f").as_deref(), Some(BYTES));
}

#[test]
fn staging_entropy_failure_on_either_pair_member_never_publishes_a_destination() {
    for before_error in [0, 1] {
        let fs = base();
        fs.inject_staging_name_error(before_error, io::ErrorKind::Other);
        let outcome = store(&fs).write_new_pair(&dir(), (&name("a"), BYTES), (&name("b"), OTHER));
        assert!(outcome.iter().all(|result| matches!(
            result,
            KagemushaWalletPublishOutcomeV1::NotPublished(KagemushaWalletNotPublishedV1::Failed(_))
        )));
        assert!(
            fs.visible_names(&dir()).is_empty(),
            "first staged member is discarded"
        );
        fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
        assert!(fs.visible_names(&dir()).is_empty());
        assert_eq!(
            store(&fs).write_new_pair(&dir(), (&name("a"), BYTES), (&name("b"), OTHER)),
            [KagemushaWalletPublishOutcomeV1::Published; 2]
        );
        fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
        assert_eq!(fs.visible_file(&dir(), "a").as_deref(), Some(BYTES));
        assert_eq!(fs.visible_file(&dir(), "b").as_deref(), Some(OTHER));
    }
}

#[test]
fn simulated_staging_entropy_faults_are_separate_and_resettable() {
    let fs = base();
    let before = fs.steps();
    fs.inject_staging_name_error(1, io::ErrorKind::PermissionDenied);
    assert!(fs.staging_name().is_ok());
    assert_eq!(
        fs.staging_name().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(fs.staging_name().is_ok());
    assert_eq!(
        fs.steps(),
        before,
        "name requests do not renumber filesystem faults"
    );
    fs.inject_staging_name_error(0, io::ErrorKind::Other);
    fs.clear_faults();
    assert!(fs.staging_name().is_ok());
    fs.inject_staging_name_error(0, io::ErrorKind::Other);
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert!(fs.staging_name().is_ok());
}

#[test]
fn wallet_advance_v1_store_retirement_retry_after_lost_writeback_fault_matrix() {
    let fs = base_with_file(BYTES);
    let retire =
        |store: &SimStore| store.retain_retired_files(&dir(), &[(&name("f"), &name("grave-new"))]);
    let trace = fault_free_trace(&fs, &retire);
    let first_sync = trace
        .iter()
        .position(|step| *step == KagemushaWalletSimStepV1::SyncDir)
        .expect("retirement sync");
    fs.inject(
        fs.steps() + first_sync as u64,
        KagemushaWalletSimFaultV1::LostWriteback,
    );
    assert!(matches!(
        retire(&store(&fs)),
        KagemushaWalletRemoveOutcomeV1::Uncertain(_)
    ));
    assert_eq!(fs.visible_file(&dir(), "f"), None);
    assert_eq!(fs.visible_file(&dir(), "grave-new").as_deref(), Some(BYTES));
    fs.restart();
    // A retry in the same boot must reissue the exact move. Exercise another fault at
    // every step, including both directory syncs, before restart or power loss.
    matrix(&fs, &FAULTS, &retire, &|case| {
        let original = case.file("f");
        let grave = case.file("grave-new");
        assert!(
            original.is_none() || original.as_deref() == Some(BYTES),
            "original bytes: {}",
            case.label()
        );
        assert!(
            grave.is_none() || grave.as_deref() == Some(BYTES),
            "retained bytes: {}",
            case.label()
        );
        if case.observed() && *case.outcome == KagemushaWalletRemoveOutcomeV1::Removed {
            assert_eq!(
                original,
                None,
                "completed retirement resurrected: {}",
                case.label()
            );
        }
    });
    assert_eq!(retire(&store(&fs)), KagemushaWalletRemoveOutcomeV1::Removed);
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert_eq!(fs.visible_file(&dir(), "f"), None);
}

#[test]
fn wallet_advance_v1_store_completed_retirement_cleanup_never_restores_original() {
    let fs = base_with_file(BYTES);
    let retire = |store: &SimStore| {
        store.retain_retired_files(&dir(), &[(&name("f"), &name("grave-complete"))])
    };
    assert_eq!(retire(&store(&fs)), KagemushaWalletRemoveOutcomeV1::Removed);
    // The archive publishes its durable Complete journal before selecting this cleanup.
    // This primitive test starts from the already-durable original absence.
    let reap = |store: &SimStore| store.reap_retired_files(&dir(), &[&name("grave-complete")]);
    let trace = fault_free_trace(&fs, &reap);
    let last_sync = trace
        .iter()
        .rposition(|step| *step == KagemushaWalletSimStepV1::SyncDir)
        .expect("grave cleanup sync");
    fs.inject(
        fs.steps() + last_sync as u64,
        KagemushaWalletSimFaultV1::LostWriteback,
    );
    assert_eq!(reap(&store(&fs)), KagemushaWalletRemoveOutcomeV1::Removed);
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert_eq!(fs.visible_file(&dir(), "f"), None);
    assert_eq!(
        fs.visible_file(&dir(), "grave-complete").as_deref(),
        Some(BYTES)
    );
    // The provider selects this garbage-only operation after durable Complete.
    // Its own later failure or crash may retain garbage, but must never relink f.
    matrix(
        &fs,
        &FAULTS,
        &|store| store.reap_retired_files(&dir(), &[&name("grave-complete")]),
        &|case| {
            assert_eq!(
                case.file("f"),
                None,
                "cleanup resurrected original: {}",
                case.label()
            );
            let grave = case.file("grave-complete");
            assert!(
                grave.is_none() || grave.as_deref() == Some(BYTES),
                "{}",
                case.label()
            );
        },
    );
}

#[test]
fn wallet_advance_v1_store_retirement_never_replaces_an_existing_grave() {
    let fs = base_with_file(BYTES);
    assert_eq!(
        store(&fs).write_new(&dir(), &name("grave-old"), OTHER),
        KagemushaWalletPublishOutcomeV1::Published
    );
    assert!(matches!(
        store(&fs).retain_retired_files(&dir(), &[(&name("f"), &name("grave-old"))]),
        KagemushaWalletRemoveOutcomeV1::NotRemoved(_)
    ));
    for power_loss in [false, true] {
        let view = fs.fork();
        if power_loss {
            view.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
        }
        assert_eq!(view.visible_file(&dir(), "f").as_deref(), Some(BYTES));
        assert_eq!(
            view.visible_file(&dir(), "grave-old").as_deref(),
            Some(OTHER)
        );
    }
}

#[test]
fn wallet_advance_v1_store_remove_dir_retry_after_lost_writeback_is_durable() {
    let fs = base();
    assert_eq!(
        store(&fs).create_dir(&dir(), &name("empty")),
        KagemushaWalletPublishOutcomeV1::Published
    );
    let remove = |store: &SimStore| store.remove_dir(&dir(), &name("empty"));
    let trace = fault_free_trace(&fs, &remove);
    let sync = trace
        .iter()
        .position(|step| *step == KagemushaWalletSimStepV1::SyncDir)
        .expect("directory removal sync");
    fs.inject(
        fs.steps() + sync as u64,
        KagemushaWalletSimFaultV1::LostWriteback,
    );
    assert!(matches!(
        remove(&store(&fs)),
        KagemushaWalletRemoveOutcomeV1::Uncertain(_)
    ));
    fs.restart();
    assert!(!fs.visible_dir(&dir().child(&name("empty"))));
    matrix(&fs, &FAULTS, &remove, &|case| {
        if case.observed() && *case.outcome == KagemushaWalletRemoveOutcomeV1::Removed {
            assert!(
                !case.fs.visible_dir(&dir().child(&name("empty"))),
                "directory resurrected: {}",
                case.label()
            );
        }
    });
    assert_eq!(remove(&store(&fs)), KagemushaWalletRemoveOutcomeV1::Removed);
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert!(!fs.visible_dir(&dir().child(&name("empty"))));
}
