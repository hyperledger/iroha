//! Native owner-private publication for freshly generated localnet artifacts.

use color_eyre::eyre::{Result, ensure, eyre};
use iroha_fs::{PrivateDirectory, PublishMode};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

pub(super) fn prepare_empty_private_directory(path: &Path) -> Result<PathBuf> {
    let directory = PrivateDirectory::open_or_create(path)?;
    ensure!(
        fs::read_dir(directory.path())?.next().is_none(),
        "localnet output directory must be empty"
    );
    Ok(directory.path().to_path_buf())
}

pub(super) fn ensure_directory(path: &Path) -> Result<()> {
    PrivateDirectory::open_or_create(path)?;
    Ok(())
}

pub(super) fn create_directory(path: &Path) -> Result<()> {
    let parent =
        PrivateDirectory::open(path.parent().ok_or_else(|| eyre!("output has no parent"))?)?;
    parent.create_child(
        path.file_name()
            .ok_or_else(|| eyre!("output has no filename"))?,
    )?;
    Ok(())
}

fn publish(path: &Path, bytes: &[u8], mode: PublishMode) -> Result<()> {
    let parent =
        PrivateDirectory::open(path.parent().ok_or_else(|| eyre!("output has no parent"))?)?;
    parent.write_atomic(
        path.file_name()
            .ok_or_else(|| eyre!("output has no filename"))?,
        bytes,
        mode,
    )?;
    Ok(())
}

pub(super) fn write(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> Result<()> {
    publish(path.as_ref(), bytes.as_ref(), PublishMode::CreateNew)
}

pub(super) fn replace(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> Result<()> {
    publish(path.as_ref(), bytes.as_ref(), PublishMode::Replace)
}

pub(super) fn write_private_file_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 1024 * 1024,
        "private file payload must be within 1..=1048576 bytes"
    );
    write(path, bytes)
}

pub(super) fn create_file(path: &Path) -> Result<File> {
    write(path, [])?;
    let parent =
        PrivateDirectory::open(path.parent().ok_or_else(|| eyre!("output has no parent"))?)?;
    Ok(parent.open_lock(
        path.file_name()
            .ok_or_else(|| eyre!("output has no filename"))?,
    )?)
}

pub(super) fn validate_private_tree(path: &Path, executables: &[&Path]) -> Result<()> {
    let root = PrivateDirectory::open(path)?;
    // Retain the root capability, but open one subtree at a time. Keeping every queued child's
    // full ancestor chain open can exhaust the native default file limit for a large bundle.
    let mut pending = vec![root.path().to_path_buf()];
    let mut count = 0;
    while let Some(path) = pending.pop() {
        root.revalidate()?;
        let directory = PrivateDirectory::open(path)?;
        for entry in fs::read_dir(directory.path())? {
            let entry = entry?;
            count += 1;
            ensure!(
                count <= 16384,
                "localnet artifact tree exceeds its entry bound"
            );
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else if executables.contains(&entry.path().as_path()) {
                iroha_fs::read_regular(entry.path(), 16 * 1024 * 1024)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    ensure!(
                        entry.metadata()?.permissions().mode() & 0o7777 == 0o700,
                        "localnet executable must be owner-only"
                    );
                }
            } else {
                directory.open_read(entry.file_name())?;
            }
        }
    }
    Ok(())
}

/// Sync every validated private file and directory before publishing a completed generation.
pub fn sync_private_tree(path: &Path) -> Result<()> {
    let root = PrivateDirectory::open(path)?;
    let mut pending = vec![(root.path().to_path_buf(), false)];
    let mut count = 0;
    while let Some((path, visited)) = pending.pop() {
        root.revalidate()?;
        let directory = PrivateDirectory::open(path)?;
        if visited {
            directory.sync()?;
            continue;
        }
        pending.push((directory.path().to_path_buf(), true));
        for entry in fs::read_dir(directory.path())? {
            let entry = entry?;
            count += 1;
            ensure!(
                count <= 16384,
                "localnet artifact tree exceeds its entry bound"
            );
            if entry.file_type()?.is_dir() {
                pending.push((entry.path(), false));
            } else {
                // This validated existing-file handle includes native flush authority on Windows.
                directory
                    .open_existing_lock(entry.file_name())?
                    .sync_all()?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_publication_stays_private_and_refuses_reuse() {
        let temporary = crate::localnet::localnet_test_helpers::private_tempdir().unwrap();
        let root = prepare_empty_private_directory(&temporary.path().join("bundle")).unwrap();
        ensure_directory(&root.join("nested/deeper")).unwrap();
        create_directory(&root.join("new")).unwrap();
        assert!(create_directory(&root.join("new")).is_err());
        write(root.join("manifest"), b"first").unwrap();
        assert!(write(root.join("manifest"), b"second").is_err());
        replace(root.join("manifest"), b"bound").unwrap();
        write_private_file_atomic(&root.join("key"), b"private").unwrap();
        assert!(write_private_file_atomic(&root.join("key"), b"replaced").is_err());
        create_file(&root.join("stream")).unwrap();
        validate_private_tree(&root, &[]).unwrap();
        sync_private_tree(&root).unwrap();
        assert!(prepare_empty_private_directory(&root).is_err());
        assert_eq!(
            iroha_fs::read_private(root.join("manifest"), 16)
                .unwrap()
                .as_slice(),
            b"bound"
        );
    }
}
