//! Filesystem primitives shared by the finalized provider-ingest and reputation archives.
//!
//! Both archives stage immutable records under an exclusive temporary name, hard-link them to a
//! canonical digest name, and re-validate every descriptor-relative identity before trusting it.

#[cfg(unix)]
use std::{
    ffi::{OsStr, OsString},
    fs, io,
};

/// Prefix of exclusive staged artifacts awaiting publication under their canonical name.
pub(super) const STAGED_FILE_PREFIX: &str = ".staged-";

pub(super) fn bounded_bytes_len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}
pub(super) fn is_canonical_digest_file_name(name: &str, suffix: &str) -> bool {
    let Some(stem) = name.strip_suffix(suffix) else {
        return false;
    };
    stem.len() == 64
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub(super) fn canonical_bytes_domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
#[cfg(unix)]
pub(super) fn create_unix_staged_file(directory: &fs::File) -> io::Result<(fs::File, OsString)> {
    use std::os::unix::fs::MetadataExt as _;
    for _ in 0..128 {
        let name = OsString::from(format!(
            "{STAGED_FILE_PREFIX}{:08x}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let file = match rustix::fs::openat(
            directory,
            &name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        ) {
            Ok(file) => fs::File::from(file),
            Err(rustix::io::Errno::EXIST) => continue,
            Err(error) => return Err(io::Error::from(error)),
        };
        let metadata = file.metadata()?;
        let entry = rustix::fs::statat(directory, &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || !unix_stat_matches_metadata(&entry, &metadata, 1)
        {
            let _ = rustix::fs::unlinkat(directory, &name, rustix::fs::AtFlags::empty());
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "exclusive staged artifact identity changed during creation",
            ));
        }
        return Ok((file, name));
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique staged archive artifact",
    ))
}
#[cfg(unix)]
pub(super) fn unix_staged_file_has_canonical_target(
    directory: &fs::File,
    staged_name: &OsStr,
    staged: &rustix::fs::Stat,
    canonical_suffix: &str,
) -> Result<bool, rustix::io::Errno> {
    use std::os::unix::ffi::OsStrExt as _;
    let entries = rustix::fs::Dir::read_from(directory)?;
    let mut matches = 0_u8;
    for entry in entries {
        let entry = entry?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if name == OsStr::new(".") || name == OsStr::new("..") || name == staged_name {
            continue;
        }
        let Some(name_utf8) = name.to_str() else {
            continue;
        };
        if !is_canonical_digest_file_name(name_utf8, canonical_suffix) {
            continue;
        }
        let candidate = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        if candidate.st_dev == staged.st_dev && candidate.st_ino == staged.st_ino {
            if rustix::fs::FileType::from_raw_mode(candidate.st_mode)
                != rustix::fs::FileType::RegularFile
                || candidate.st_nlink as u64 != 2
                || candidate.st_size != staged.st_size
            {
                return Ok(false);
            }
            matches = matches.saturating_add(1);
        }
    }
    Ok(matches == 1)
}
#[cfg(unix)]
pub(super) fn unix_stat_matches_metadata(
    entry: &rustix::fs::Stat,
    metadata: &fs::Metadata,
    expected_links: u64,
) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    rustix::fs::FileType::from_raw_mode(entry.st_mode) == rustix::fs::FileType::RegularFile
        && crate::kura::unix_device_identity(entry.st_dev) == metadata.dev()
        && entry.st_ino == metadata.ino()
        && entry.st_nlink as u64 == expected_links
        && metadata.nlink() == expected_links
        && u64::try_from(entry.st_size).ok() == Some(metadata.len())
}
