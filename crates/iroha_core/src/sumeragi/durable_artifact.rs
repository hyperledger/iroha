//! Exact-byte, no-clobber artifact publication. Authentication belongs to the caller.
//!
//! The caller retains its prepared original-funded bytes through every error and retry.
//! This module borrows those bytes and never clones, decodes, or re-signs their contents.

use iroha_fs::{AtomicWriteStep, OwnerDirectory, PublishMode};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

#[cfg(test)]
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

pub use super::availability_schedule::AvailabilitySchedule;
pub use super::body_read::{BodyReadError, BodyReadJob, BodyReadPoll, BodyReader};
use crate::sumeragi::records::{Faults, FsStep, create_dir_durable, sync_dir};

const COMPARE_BYTES: usize = 8192;
const TEMP_ATTEMPTS: u32 = 16;
#[cfg(test)]
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn conflict(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "artifact differs from original prepared bytes: {}",
            path.display()
        ),
    )
}

/// Compare every original byte, including the certificate, without a file-sized allocation.
/// A successful retry re-establishes both file and directory durability before reporting it.
fn open_exact(dir: &OwnerDirectory, name: &str, bytes: &[u8]) -> io::Result<Option<File>> {
    let target = dir.path().join(name);
    let Some(mut file) = dir.open_regular_optional(name)? else {
        return Ok(None);
    };
    if file.metadata()?.len() != u64::try_from(bytes.len()).map_err(|_| conflict(&target))? {
        return Err(conflict(&target));
    }
    let mut scratch = [0; COMPARE_BYTES];
    for expected in bytes.chunks(COMPARE_BYTES) {
        file.read_exact(&mut scratch[..expected.len()])?;
        if scratch[..expected.len()] != *expected {
            return Err(conflict(&target));
        }
    }
    if file.read(&mut scratch[..1])? != 0 {
        return Err(conflict(&target));
    }
    dir.require_same_regular_file(name, &file)?;
    Ok(Some(file))
}

/// Compare a complete existing artifact with the exact prepared bytes using bounded scratch.
/// This proves byte equality only; the caller must authenticate the original artifact.
#[cfg(test)]
fn check_exact(target: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = OwnerDirectory::open(
        target
            .parent()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?,
    )?;
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    open_exact(&dir, name, bytes)?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        .map(drop)
}

/// Check a possible existing frame through the caller's original publication directory.
/// Only initial file absence yields false; all bytes and final identity use the same reader.
pub(super) fn check_exact_in(dir: &OwnerDirectory, name: &str, bytes: &[u8]) -> io::Result<bool> {
    open_exact(dir, name, bytes).map(|file| file.is_some())
}

/// Establish a store directory and repair all ancestor durability after an interrupted open.
///
/// An earlier attempt may have created any ancestor before its parent fsync failed. Therefore
/// an existing directory is not proof that its entire path is durable. This runs at store open,
/// not on each artifact write, and also resolves relative paths through the filesystem root.
pub(super) fn establish_dir(faults: &dyn Faults, dir: &Path) -> io::Result<()> {
    let absolute = std::path::absolute(dir)?;
    create_dir_durable(faults, &absolute)?;
    for ancestor in absolute.ancestors() {
        sync_dir(faults, ancestor)?;
    }
    Ok(())
}

fn sync_parent(
    faults: &dyn Faults,
    dir: &OwnerDirectory,
    display: &Path,
    validate: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    if let Some(parent) = display
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        faults.before(FsStep::SyncDir, parent)?;
        validate()?;
        dir.sync_parent()?;
    }
    validate()
}

fn verify_existing(
    faults: &dyn Faults,
    dir: &OwnerDirectory,
    display: &Path,
    name: &str,
    bytes: &[u8],
    validate: &impl Fn() -> io::Result<()>,
) -> io::Result<bool> {
    validate()?;
    let Some(file) = open_exact(dir, name, bytes)? else {
        return Ok(false);
    };
    faults.before(FsStep::SyncFile, &display.join(name))?;
    validate()?;
    dir.require_same_regular_file(name, &file)?;
    file.sync_all()?;
    faults.before(FsStep::SyncDir, display)?;
    validate()?;
    dir.sync()?;
    sync_parent(faults, dir, display, validate)?;
    dir.require_same_regular_file(name, &file)?;
    Ok(true)
}

/// Publish exact borrowed bytes through one freshly selected operation directory.
/// Long-lived stores use `publish_in` with their retained directory and lock authority.
#[cfg(test)]
fn publish(faults: &dyn Faults, dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    publish_in(
        faults,
        &OwnerDirectory::open(dir)?,
        dir,
        name,
        bytes,
        || Ok(()),
    )
}

/// Publish through the caller's original directory, never a newly resolved namespace.
/// The extra join retains the caller's lock through every observed filesystem boundary.
/// Errors leave the exact prepared bytes with the caller and never advance its durable tip.
/// `display` preserves the caller's diagnostic/fault-injection spelling (including system
/// aliases); only `dir` supplies native I/O authority.
pub(super) fn publish_in(
    faults: &dyn Faults,
    dir: &OwnerDirectory,
    display: &Path,
    name: &str,
    bytes: &[u8],
    validate: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact name must be one path component",
        ));
    }
    match verify_existing(faults, dir, display, name, bytes, &validate) {
        Ok(true) => return Ok(()),
        Ok(false) => {
            validate()?;
            dir.revalidate()?;
        }
        Err(error) => return Err(error),
    }
    let result = dir.write_atomic_observed(
        name,
        bytes,
        PublishMode::CreateNew,
        TEMP_ATTEMPTS,
        |step, path| {
            let step = match step {
                AtomicWriteStep::CreateTemp => FsStep::CreateTemp,
                AtomicWriteStep::WriteHead => FsStep::WriteTemp,
                AtomicWriteStep::WriteTail => FsStep::WriteTempRest,
                AtomicWriteStep::SyncFile => FsStep::SyncFile,
                AtomicWriteStep::Publish => FsStep::Rename,
                AtomicWriteStep::SyncDirectory => FsStep::SyncDir,
            };
            let display_path = if step == FsStep::SyncDir {
                display.to_owned()
            } else {
                display.join(path.file_name().expect("native child publication path"))
            };
            faults.before(step, &display_path)?;
            validate()
        },
    );
    match result {
        Ok(()) => {
            sync_parent(faults, dir, display, &validate)?;
            dir.revalidate()
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            match verify_existing(faults, dir, display, name, bytes, &validate) {
                Ok(false) => {
                    // A full staging-name collision budget must retain its native cause.
                    // Recheck custody first so a missing original lock is never hidden.
                    validate()?;
                    dir.revalidate()?;
                    Err(error)
                }
                Ok(true) => Ok(()),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "durable_artifact/tests.rs"]
mod tests;
