//! Fault, byte-equality, and retained-buffer controls for durable artifact publication.

use std::sync::{Arc, Mutex, atomic::AtomicBool};

use iroha_allocation::{AllocationBudget, ChargedBuffer};

use super::*;
use crate::sumeragi::records::NoFaults;

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        for _ in 0..100 {
            let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("iroha-artifact-{}-{serial}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("test directory: {error}"),
            }
        }
        panic!("test directory namespace exhausted");
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove owned test directory");
    }
}

#[derive(Default)]
struct Events(Mutex<Vec<(FsStep, PathBuf)>>);
impl Faults for Events {
    fn before(&self, step: FsStep, path: &Path) -> io::Result<()> {
        self.0.lock().unwrap().push((step, path.to_owned()));
        Ok(())
    }
}

struct FailOnce {
    step: FsStep,
    path: Option<PathBuf>,
    armed: AtomicBool,
}
impl Faults for FailOnce {
    fn before(&self, step: FsStep, path: &Path) -> io::Result<()> {
        if step == self.step
            && self.path.as_ref().is_none_or(|wanted| wanted == path)
            && self.armed.swap(false, Ordering::SeqCst)
        {
            return Err(io::Error::other("injected publication failure"));
        }
        Ok(())
    }
}

#[test]
fn exact_retry_syncs_file_directory_and_parent_without_rewriting() {
    let dir = Directory::new();
    let child = dir.0.join("height");
    fs::create_dir(&child).unwrap();
    let bytes = b"complete authenticated header/body/availability/certificate frame";
    publish(&NoFaults, &child, "frame", bytes).unwrap();
    let events = Events::default();
    publish(&events, &child, "frame", bytes).unwrap();
    assert_eq!(
        *events.0.lock().unwrap(),
        vec![
            (FsStep::SyncFile, child.join("frame")),
            (FsStep::SyncDir, child.clone()),
            (FsStep::SyncDir, dir.0.clone()),
        ]
    );
    check_exact(&child.join("frame"), bytes).unwrap();
}

#[test]
fn every_failure_retains_the_original_charged_backing_through_retry() {
    for step in [
        FsStep::CreateTemp,
        FsStep::WriteTemp,
        FsStep::WriteTempRest,
        FsStep::SyncFile,
        FsStep::Rename,
        FsStep::SyncDir,
    ] {
        let dir = Directory::new();
        let budget = AllocationBudget::new(COMPARE_BYTES + 37);
        let mut owner = ChargedBuffer::new(COMPARE_BYTES + 37, &budget).unwrap();
        for index in 0..COMPARE_BYTES + 37 {
            owner.push_reserved((index % 251) as u8);
        }
        let pointer = owner.as_slice().as_ptr();
        let faults = FailOnce {
            step,
            path: None,
            armed: AtomicBool::new(true),
        };
        assert!(
            publish(&faults, &dir.0, "frame", owner.as_slice()).is_err(),
            "{step:?}"
        );
        assert_eq!(owner.as_slice().as_ptr(), pointer);
        assert!(owner.belongs_to(&budget));
        assert_eq!(budget.reserved_bytes(), COMPARE_BYTES + 37);
        publish(&faults, &dir.0, "frame", owner.as_slice()).unwrap();
        assert_eq!(owner.as_slice().as_ptr(), pointer);
        assert_eq!(budget.peak_reserved_bytes(), COMPARE_BYTES + 37);
        check_exact(&dir.0.join("frame"), owner.as_slice()).unwrap();
        assert!(fs::read_dir(&dir.0).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
        drop(owner);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn failure_after_visible_publication_cannot_replace_the_original_frame() {
    let dir = Directory::new();
    let faults = FailOnce {
        step: FsStep::SyncDir,
        path: Some(dir.0.clone()),
        armed: AtomicBool::new(true),
    };
    assert!(publish(&faults, &dir.0, "frame", b"original QC").is_err());
    assert_eq!(fs::read(dir.0.join("frame")).unwrap(), b"original QC");
    let error = publish(&NoFaults, &dir.0, "frame", b"modified QC").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    publish(&NoFaults, &dir.0, "frame", b"original QC").unwrap();
    assert_eq!(fs::read(dir.0.join("frame")).unwrap(), b"original QC");
}

#[test]
fn failed_parent_directory_sync_is_repeated_by_exact_retry() {
    let dir = Directory::new();
    let child = dir.0.join("height");
    fs::create_dir(&child).unwrap();
    let faults = FailOnce {
        step: FsStep::SyncDir,
        path: Some(dir.0.clone()),
        armed: AtomicBool::new(true),
    };
    assert!(publish(&faults, &child, "frame", b"complete").is_err());
    let events = Events::default();
    publish(&events, &child, "frame", b"complete").unwrap();
    assert_eq!(
        events.0.lock().unwrap().last(),
        Some(&(FsStep::SyncDir, dir.0.clone()))
    );
}

#[test]
fn full_comparison_rejects_prefix_tail_truncation_and_extra_bytes() {
    let dir = Directory::new();
    let expected = vec![17; COMPARE_BYTES * 2 + 1];
    let target = dir.0.join("frame");
    for index in [0, COMPARE_BYTES, expected.len() - 1] {
        let mut corrupt = expected.clone();
        corrupt[index] ^= 1;
        fs::write(&target, &corrupt).unwrap();
        assert_eq!(
            check_exact(&target, &expected).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(publish(&NoFaults, &dir.0, "frame", &expected).is_err());
        assert_eq!(fs::read(&target).unwrap(), corrupt);
    }
    for length in [expected.len() - 1, expected.len() + 1] {
        let corrupt = vec![17; length];
        fs::write(&target, &corrupt).unwrap();
        assert!(publish(&NoFaults, &dir.0, "frame", &expected).is_err());
        assert_eq!(fs::read(&target).unwrap(), corrupt);
    }
}

struct RacingWriter<'a> {
    target: PathBuf,
    bytes: &'a [u8],
}
impl Faults for RacingWriter<'_> {
    fn before(&self, step: FsStep, _path: &Path) -> io::Result<()> {
        if step == FsStep::Rename {
            fs::write(&self.target, self.bytes)?;
        }
        Ok(())
    }
}

#[test]
fn no_clobber_publication_verifies_a_writer_racing_the_initial_check() {
    let dir = Directory::new();
    let target = dir.0.join("frame");
    let race = RacingWriter {
        target: target.clone(),
        bytes: b"other complete frame",
    };
    assert!(publish(&race, &dir.0, "frame", b"our complete frame").is_err());
    assert_eq!(fs::read(&target).unwrap(), race.bytes);
    fs::remove_file(&target).unwrap();
    let race = RacingWriter {
        target: target.clone(),
        bytes: b"our complete frame",
    };
    publish(&race, &dir.0, "frame", race.bytes).unwrap();
    check_exact(&target, race.bytes).unwrap();
}

#[test]
fn competing_writers_preserve_one_complete_exact_frame() {
    let dir = Directory::new();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            publish(&NoFaults, &dir.0, "frame", b"first")
        });
        let second = scope.spawn(|| {
            barrier.wait();
            publish(&NoFaults, &dir.0, "frame", b"second")
        });
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert_ne!(first.is_ok(), second.is_ok());
        assert_eq!(
            fs::read(dir.0.join("frame")).unwrap(),
            if first.is_ok() {
                b"first".as_slice()
            } else {
                b"second".as_slice()
            }
        );
    });
}

#[test]
fn non_regular_existing_targets_and_path_escapes_are_refused() {
    let dir = Directory::new();
    fs::create_dir(dir.0.join("frame")).unwrap();
    assert!(publish(&NoFaults, &dir.0, "frame", b"body").is_err());
    for name in ["", ".", "..", "../escape", "/absolute", "nested/frame"] {
        assert_eq!(
            publish(&NoFaults, &dir.0, name, b"body")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    #[cfg(unix)]
    {
        let real = dir.0.join("real");
        fs::write(&real, b"body").unwrap();
        std::os::unix::fs::symlink(&real, dir.0.join("link")).unwrap();
        assert!(publish(&NoFaults, &dir.0, "link", b"body").is_err());
        assert_eq!(fs::read(real).unwrap(), b"body");
    }
}

#[cfg(unix)]
#[test]
fn named_pipe_is_refused_without_waiting_for_a_writer() {
    let dir = Directory::new();
    let target = dir.0.join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&target)
            .status()
            .expect("POSIX mkfifo test fixture")
            .success()
    );
    assert_eq!(
        check_exact(&target, b"frame").unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        publish(&NoFaults, &dir.0, "fifo", b"frame")
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn interrupted_directory_creation_repairs_every_ancestor_on_retry() {
    for failed_depth in 0..=3 {
        let root = Directory::new();
        let mut parents = vec![root.0.clone()];
        for name in ["configured-root", "instance", "height"] {
            parents.push(parents.last().unwrap().join(name));
        }
        let leaf = parents.last().unwrap();
        let faults = FailOnce {
            step: FsStep::SyncDir,
            path: Some(parents[failed_depth].clone()),
            armed: AtomicBool::new(true),
        };
        assert!(establish_dir(&faults, leaf).is_err());
        let events = Events::default();
        establish_dir(&events, leaf).unwrap();
        let absolute = std::path::absolute(leaf).unwrap();
        let repaired: Vec<_> = absolute
            .ancestors()
            .map(|path| (FsStep::SyncDir, path.to_owned()))
            .collect();
        assert!(events.0.lock().unwrap().ends_with(&repaired));
        assert_eq!(repaired.last().unwrap().1, Path::new("/"));
        assert!(leaf.is_dir());
        let existing = Events::default();
        establish_dir(&existing, leaf).unwrap();
        assert_eq!(*existing.0.lock().unwrap(), repaired);
    }
}

struct RemoveExistingBeforeSync(AtomicBool);
impl Faults for RemoveExistingBeforeSync {
    fn before(&self, step: FsStep, path: &Path) -> io::Result<()> {
        if step == FsStep::SyncFile && self.0.swap(false, Ordering::SeqCst) {
            fs::rename(path, path.with_file_name("original-frame"))?;
        }
        Ok(())
    }
}

#[test]
fn late_existing_artifact_loss_is_not_reclassified_as_initial_absence() {
    let dir = Directory::new();
    publish(&NoFaults, &dir.0, "frame", b"original").unwrap();
    let faults = RemoveExistingBeforeSync(AtomicBool::new(true));
    assert_eq!(
        publish(&faults, &dir.0, "frame", b"original")
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert!(!faults.0.load(Ordering::SeqCst));
    assert!(
        !dir.0.join("frame").exists(),
        "late source loss cannot silently publish a new frame"
    );
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    assert_eq!(fs::read(dir.0.join("original-frame")).unwrap(), b"original");
    fs::rename(dir.0.join("original-frame"), dir.0.join("frame")).unwrap();
    publish(&NoFaults, &dir.0, "frame", b"original").unwrap();
    check_exact(&dir.0.join("frame"), b"original").unwrap();
}
