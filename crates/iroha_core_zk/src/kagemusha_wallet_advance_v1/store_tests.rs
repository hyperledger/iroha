//! Durable store tests: the publication algorithm under single-fault matrices on the
//! simulator (every step, every fault, process crash, restart and power loss), simulator
//! semantics, and the `std::fs` backend.

use std::io;

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletCustodyDirV1, KagemushaWalletEntryNameV1, KagemushaWalletPublishOutcomeV1,
    KagemushaWalletRemoveOutcomeV1,
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
    let steps = u64::try_from(fault_free_trace(base, op).len()).expect("steps");
    assert!(steps > 0, "primitive takes at least one step");
    let mut cases = 0;
    for step in 0..steps {
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
