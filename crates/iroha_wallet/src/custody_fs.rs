//! Wallet placement and unpublished-wallet cleanup over shared native custody.

use eyre::{Result, bail, eyre};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

pub use iroha_fs::PrivateDirectory;

/// Resolve the existing platform prefix, retaining only normal missing path components.
pub fn resolved_target(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        bail!("wallet store must be an absolute path without parent traversal");
    }
    let mut ancestor = path;
    let mut suffix = Vec::new();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    bail!("wallet store ancestor must be a real directory");
                }
                let mut resolved = ancestor.canonicalize()?;
                for component in suffix.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                suffix.push(
                    ancestor
                        .file_name()
                        .ok_or_else(|| eyre!("invalid wallet store"))?,
                );
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| eyre!("invalid wallet store"))?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Read an external wallet input through the shared bounded native custody reader.
pub fn read_external(path: &Path, maximum: usize, private: bool) -> Result<Zeroizing<Vec<u8>>> {
    Ok(if private {
        iroha_fs::read_private(path, maximum)?
    } else {
        iroha_fs::read_regular(path, maximum)?
    })
}

/// Remove only an exact unpublished wallet child and its three recognized private files.
pub fn remove_pending(parent: &PrivateDirectory, temporary: PrivateDirectory) -> Result<()> {
    if temporary.path().parent() != Some(parent.path())
        || !temporary
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".pending-"))
    {
        bail!("cleanup requires this store's unpublished wallet directory");
    }
    parent.revalidate()?;
    temporary.revalidate()?;
    for name in temporary.entries(3)? {
        if !matches!(
            name.to_str(),
            Some("private.key" | "client.toml" | "wallet.json")
        ) {
            bail!("unpublished wallet contains an unrecognized entry");
        }
    }
    temporary.clear_contents_preserving(&[])?;
    temporary.remove_empty()?;
    parent.revalidate()?;
    Ok(())
}
