//! Immutable bounded metadata publication shared by raw compiler and encoded carriers.

use iroha_fs::PrivateDirectory;
use rand::rand_core::TryRngCore as _;
use sha2::{Digest as _, Sha256};
use std::{io, io::Read as _, io::Write as _};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn verify_metadata(
    directory: &PrivateDirectory,
    name: &str,
    bytes: &[u8],
) -> io::Result<Option<()>> {
    directory.revalidate()?;
    // Only the first native child open can establish absence. A later NotFound
    // from retained-file or directory validation must never authorize publication.
    let Some(mut original) = directory.open_retained_read_only_optional(name, bytes.len())? else {
        return Ok(None);
    };
    if original.len()? != bytes.len() as u64 {
        return Err(invalid("existing metadata extent differs"));
    }
    let snapshot = original.snapshot()?;
    let expected: [u8; 32] = Sha256::digest(bytes).into();
    let mut hash = Sha256::new();
    let mut total = 0_usize;
    let mut buffer = super::original_stream_buffer()?;
    loop {
        original.revalidate()?;
        if original.snapshot()? != snapshot {
            return Err(invalid("metadata changed before streaming"));
        }
        let count = original.read(&mut buffer)?;
        original.revalidate()?;
        if original.snapshot()? != snapshot {
            return Err(invalid("metadata changed during streaming"));
        }
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count)
            .ok_or_else(|| invalid("metadata extent overflow"))?;
        if total > bytes.len() {
            return Err(invalid("metadata extended during streaming"));
        }
        hash.update(&buffer[..count]);
    }
    let actual: [u8; 32] = hash.finalize().into();
    if total != bytes.len() || actual != expected {
        return Err(invalid("existing metadata original differs"));
    }
    directory.sync()?;
    directory.revalidate()?;
    Ok(Some(()))
}

pub(super) fn publish_metadata(
    directory: &PrivateDirectory,
    name: &str,
    bytes: &[u8],
) -> io::Result<()> {
    if bytes.is_empty() {
        return Err(invalid("empty metadata original"));
    }
    if verify_metadata(directory, name, bytes)?.is_some() {
        return Ok(());
    }
    let mut nonce = [0_u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(io::Error::other)?;
    let staging = format!("wallet-metadata-{}.partial", hex::encode(nonce));
    let mut writer = directory.create_retained_private(staging, bytes.len())?;
    writer.write_all(bytes)?;
    let sealed = writer.seal_read_only()?;
    match sealed.publish_new_name(name) {
        Ok(original) => original.revalidate()?,
        // A competing identical writer may win. Its whole original must still pass
        // all checks; neither the winning file nor our partial evidence is replaced.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    verify_metadata(directory, name, bytes)?.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
}
