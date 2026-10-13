//! Helpers for resolving SoraFS manifests by their blinded CID representations.
//!
//! The gateway ingests daily salt announcements published by the SoraNet Salt Council. Requests can
//! then reference manifests using a BLAKE3 digest derived from the salt and canonical CID instead
//! of exposing the raw identifier on the wire.
use hex::FromHex;
use iroha_crypto::soranet::blinding::canonical_cache_key;
use sorafs_node::store::StoredManifest;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
};
use thiserror::Error;

/// Width of the blinded CID digest (BLAKE3-256).
pub const BLINDED_CID_LEN: usize = 32;

/// Maximum number of directory entries examined while loading salt announcements.
const MAX_SALT_ANNOUNCEMENT_FILES_V1: usize = 64;
/// Maximum encoded size of one canonical `SaltAnnouncementV1`.
const MAX_SALT_ANNOUNCEMENT_BYTES_V1: usize = 16 * 1024;
/// Gateways accept only the latest epoch and its immediate predecessor.
const ACTIVE_SALT_EPOCH_WINDOW_V1: u32 = 2;
/// Maximum number of successful blinded-CID resolutions retained in memory.
const MAX_RESOLVER_CACHE_ENTRIES_V1: usize = 4_096;
/// Maximum number of epoch filters retained in memory.
const MAX_RESOLVER_FILTER_EPOCHS_V1: usize = ACTIVE_SALT_EPOCH_WINDOW_V1 as usize;
/// Lower and upper allocation bounds for one resolver bloom filter.
const MIN_RESOLVER_BLOOM_BITS_V1: usize = 1_024;
const MAX_RESOLVER_BLOOM_BITS_V1: usize = 1 << 20;
const MANIFEST_SET_GENERATION_DOMAIN_V1: &[u8] = b"iroha.sorafs.blinded.manifest-set.v1";

#[derive(Debug, crate::json_macros::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct SaltAnnouncementV1 {
    epoch_id: u32,
    #[norito(required)]
    previous_epoch: Option<u32>,
    valid_after: i64,
    valid_until: i64,
    blinded_cid_salt_hex: String,
    // The remaining fields belong to the exact announcement schema; they are
    // decoded so malformed announcements are rejected, but not consulted.
    #[allow(dead_code)]
    emergency_rotation: bool,
    #[allow(dead_code)]
    #[norito(required)]
    notes: Option<String>,
    #[allow(dead_code)]
    #[norito(required)]
    signature: Option<String>,
}

/// Salt schedule loaded from Norito JSON announcements on disk.
#[derive(Debug)]
pub struct SaltSchedule {
    salts: BTreeMap<u32, [u8; 32]>,
}

impl SaltSchedule {
    /// Load salt announcements from the supplied directory.
    ///
    /// Every entry must be a direct regular file named
    /// `epoch-<six-or-more-digits>.norito.json` and contain the complete, schema-closed
    /// `SaltAnnouncementV1` payload. The resulting schedule retains the latest epoch and its
    /// immediate numeric predecessor only.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory or any entry is indirect, changes during loading,
    /// exceeds its fixed bound, is not canonical, cannot be parsed, or contains an invalid salt
    /// or epoch relationship.
    pub fn load_from_dir(dir: &Path) -> Result<Self, SaltScheduleError> {
        let mut salts = load_direct_salt_announcements(dir)?;
        let Some((&latest_epoch, _)) = salts.last_key_value() else {
            return Err(SaltScheduleError::NoAnnouncementsFound(dir.to_path_buf()));
        };
        let first_active_epoch = latest_epoch.saturating_sub(ACTIVE_SALT_EPOCH_WINDOW_V1 - 1);
        salts = salts.split_off(&first_active_epoch);
        Ok(Self { salts })
    }

    /// Returns the 32-byte salt for the supplied epoch.
    #[must_use]
    pub fn salt(&self, epoch: u32) -> Option<[u8; 32]> {
        self.salts.get(&epoch).copied()
    }
}

fn canonical_salt_filename(epoch: u32) -> String {
    format!("epoch-{epoch:06}.norito.json")
}

fn epoch_from_salt_filename(filename: &str) -> Option<u32> {
    let epoch = filename
        .strip_prefix("epoch-")?
        .strip_suffix(".norito.json")?
        .parse::<u32>()
        .ok()?;
    (canonical_salt_filename(epoch) == filename).then_some(epoch)
}

fn decode_salt_announcement(
    path: &Path,
    filename_epoch: u32,
    bytes: &[u8],
) -> Result<[u8; 32], SaltScheduleError> {
    let contents = std::str::from_utf8(bytes).map_err(|source| SaltScheduleError::InvalidUtf8 {
        path: path.to_path_buf(),
        source,
    })?;
    let record: SaltAnnouncementV1 =
        norito::json::from_str(contents).map_err(|source| SaltScheduleError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    let SaltAnnouncementV1 {
        epoch_id,
        previous_epoch,
        valid_after,
        valid_until,
        blinded_cid_salt_hex,
        emergency_rotation: _,
        notes: _,
        signature: _,
    } = record;
    if epoch_id != filename_epoch {
        return Err(SaltScheduleError::FilenameEpochMismatch {
            path: path.to_path_buf(),
            filename_epoch,
            declared_epoch: epoch_id,
        });
    }
    if valid_after < 0 || valid_after >= valid_until {
        return Err(SaltScheduleError::InvalidValidityWindow {
            path: path.to_path_buf(),
        });
    }
    if previous_epoch.is_some_and(|previous| previous.checked_add(1) != Some(epoch_id)) {
        return Err(SaltScheduleError::InvalidPreviousEpoch {
            path: path.to_path_buf(),
            epoch: epoch_id,
            previous_epoch,
        });
    }

    let decoded =
        Vec::from_hex(&blinded_cid_salt_hex).map_err(|source| SaltScheduleError::SaltDecode {
            path: path.to_path_buf(),
            source,
        })?;
    if decoded.len() != 32 {
        return Err(SaltScheduleError::SaltLength {
            path: path.to_path_buf(),
            len: decoded.len(),
        });
    }
    if hex::encode(&decoded) != blinded_cid_salt_hex {
        return Err(SaltScheduleError::NonCanonicalSaltHex {
            path: path.to_path_buf(),
        });
    }
    let mut salt = [0_u8; 32];
    salt.copy_from_slice(&decoded);
    Ok(salt)
}

#[cfg(unix)]
fn load_direct_salt_announcements(
    dir: &Path,
) -> Result<BTreeMap<u32, [u8; 32]>, SaltScheduleError> {
    use std::os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _};

    let named_before = match fs::symlink_metadata(dir) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(SaltScheduleError::DirectoryMissing(dir.to_path_buf()));
        }
        Err(source) => return Err(source.into()),
    };
    if named_before.file_type().is_symlink() || !named_before.is_dir() {
        return Err(SaltScheduleError::UnsafeDirectory(dir.to_path_buf()));
    }
    let directory = File::from(
        rustix::fs::open(
            dir,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let opened_before = directory.metadata()?;
    if !opened_before.is_dir()
        || named_before.dev() != opened_before.dev()
        || named_before.ino() != opened_before.ino()
    {
        return Err(SaltScheduleError::DirectoryChanged(dir.to_path_buf()));
    }

    let mut salts = BTreeMap::new();
    let mut entry_count = 0_usize;
    let mut entries = rustix::fs::Dir::read_from(&directory).map_err(io::Error::from)?;
    for entry in &mut entries {
        let entry = entry.map_err(io::Error::from)?;
        let filename_bytes = entry.file_name().to_bytes();
        if matches!(filename_bytes, b"." | b"..") {
            continue;
        }
        entry_count =
            entry_count
                .checked_add(1)
                .ok_or_else(|| SaltScheduleError::TooManyAnnouncements {
                    dir: dir.to_path_buf(),
                    limit: MAX_SALT_ANNOUNCEMENT_FILES_V1,
                })?;
        if entry_count > MAX_SALT_ANNOUNCEMENT_FILES_V1 {
            return Err(SaltScheduleError::TooManyAnnouncements {
                dir: dir.to_path_buf(),
                limit: MAX_SALT_ANNOUNCEMENT_FILES_V1,
            });
        }
        let filename = std::str::from_utf8(filename_bytes).ok().ok_or_else(|| {
            SaltScheduleError::NonCanonicalFilename {
                path: dir.join(std::ffi::OsStr::from_bytes(filename_bytes)),
            }
        })?;
        let path = dir.join(filename);
        let filename_epoch = epoch_from_salt_filename(filename)
            .ok_or_else(|| SaltScheduleError::NonCanonicalFilename { path: path.clone() })?;
        let bytes = read_direct_salt_announcement(&directory, filename, &path)?;
        let salt = decode_salt_announcement(&path, filename_epoch, &bytes)?;
        if salts.insert(filename_epoch, salt).is_some() {
            return Err(SaltScheduleError::DuplicateEpoch {
                path,
                epoch: filename_epoch,
            });
        }
    }

    let opened_after = directory.metadata()?;
    let named_after = fs::symlink_metadata(dir)?;
    if named_after.file_type().is_symlink()
        || !named_after.is_dir()
        || opened_before.dev() != opened_after.dev()
        || opened_before.ino() != opened_after.ino()
        || opened_before.len() != opened_after.len()
        || opened_before.mtime() != opened_after.mtime()
        || opened_before.mtime_nsec() != opened_after.mtime_nsec()
        || opened_before.ctime() != opened_after.ctime()
        || opened_before.ctime_nsec() != opened_after.ctime_nsec()
        || opened_after.dev() != named_after.dev()
        || opened_after.ino() != named_after.ino()
    {
        return Err(SaltScheduleError::DirectoryChanged(dir.to_path_buf()));
    }
    Ok(salts)
}

#[cfg(unix)]
fn read_direct_salt_announcement(
    directory: &File,
    filename: &str,
    path: &Path,
) -> Result<Vec<u8>, SaltScheduleError> {
    use std::os::unix::fs::MetadataExt as _;

    let maximum_bytes = u64::try_from(MAX_SALT_ANNOUNCEMENT_BYTES_V1)
        .map_err(|_| io::Error::other("salt announcement byte limit exceeds this platform"))?;
    let before = rustix::fs::statat(directory, filename, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)?;
    let before_len = u64::try_from(before.st_size).ok();
    if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
        || before.st_nlink != 1
    {
        return Err(SaltScheduleError::UnsafeAnnouncement(path.to_path_buf()));
    }
    if before_len.is_none_or(|len| len > maximum_bytes) {
        return Err(SaltScheduleError::AnnouncementTooLarge {
            path: path.to_path_buf(),
            limit: MAX_SALT_ANNOUNCEMENT_BYTES_V1,
        });
    }

    let mut file = File::from(
        rustix::fs::openat(
            directory,
            filename,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::NOCTTY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let opened_before = file.metadata()?;
    if !opened_before.is_file()
        || opened_before.nlink() != 1
        || u64::try_from(before.st_dev).ok() != Some(opened_before.dev())
        || before.st_ino != opened_before.ino()
        || before_len != Some(opened_before.len())
        || opened_before.len() > maximum_bytes
    {
        return Err(SaltScheduleError::UnsafeAnnouncement(path.to_path_buf()));
    }

    let initial_capacity = usize::try_from(opened_before.len())
        .map_err(|_| io::Error::other("salt announcement length exceeds this platform"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(initial_capacity)
        .map_err(io::Error::other)?;
    (&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SALT_ANNOUNCEMENT_BYTES_V1 {
        return Err(SaltScheduleError::AnnouncementTooLarge {
            path: path.to_path_buf(),
            limit: MAX_SALT_ANNOUNCEMENT_BYTES_V1,
        });
    }

    let opened_after = file.metadata()?;
    let named_after =
        rustix::fs::statat(directory, filename, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)?;
    if !opened_after.is_file()
        || opened_after.nlink() != 1
        || opened_before.dev() != opened_after.dev()
        || opened_before.ino() != opened_after.ino()
        || opened_before.len() != opened_after.len()
        || opened_after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        || named_after.st_dev != before.st_dev
        || named_after.st_ino != before.st_ino
        || named_after.st_size != before.st_size
        || named_after.st_mtime != before.st_mtime
        || named_after.st_mtime_nsec != before.st_mtime_nsec
        || named_after.st_ctime != before.st_ctime
        || named_after.st_ctime_nsec != before.st_ctime_nsec
    {
        return Err(SaltScheduleError::AnnouncementChanged(path.to_path_buf()));
    }
    Ok(bytes)
}

#[cfg(windows)]
fn load_direct_salt_announcements(
    dir: &Path,
) -> Result<BTreeMap<u32, [u8; 32]>, SaltScheduleError> {
    use crate::secure_file_metadata::{
        from_file, from_path, is_direct_directory, same_file, unchanged,
    };
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ_WRITE: u32 = 0x0000_0001 | 0x0000_0002;

    let named_before = match from_path(dir) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(SaltScheduleError::DirectoryMissing(dir.to_path_buf()));
        }
        Err(source) => return Err(source.into()),
    };
    if !is_direct_directory(&named_before) {
        return Err(SaltScheduleError::UnsafeDirectory(dir.to_path_buf()));
    }

    // Retain a handle that denies delete sharing for the complete scan. Windows therefore cannot
    // rename or replace this directory after it has been bound below, while read/write sharing
    // still permits ordinary child-file access.
    let directory = fs::OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(dir)?;
    let opened_before = from_file(&directory)?;
    let named_after_open = from_path(dir)?;
    if !is_direct_directory(&opened_before)
        || !is_direct_directory(&named_after_open)
        || !same_file(&named_before, &opened_before)
        || !unchanged(&named_before, &opened_before)
        || !same_file(&opened_before, &named_after_open)
        || !unchanged(&opened_before, &named_after_open)
    {
        return Err(SaltScheduleError::DirectoryChanged(dir.to_path_buf()));
    }

    let mut entries = fs::read_dir(dir)?;
    revalidate_windows_salt_directory(dir, &directory, &opened_before)?;
    let mut salts = BTreeMap::new();
    let mut entry_count = 0_usize;
    while let Some(entry) = entries.next() {
        // Charge every result produced by the OS before doing any work on it. This keeps a
        // concurrently changing enumeration inside the same fixed work bound as a stable one.
        entry_count =
            entry_count
                .checked_add(1)
                .ok_or_else(|| SaltScheduleError::TooManyAnnouncements {
                    dir: dir.to_path_buf(),
                    limit: MAX_SALT_ANNOUNCEMENT_FILES_V1,
                })?;
        if entry_count > MAX_SALT_ANNOUNCEMENT_FILES_V1 {
            return Err(SaltScheduleError::TooManyAnnouncements {
                dir: dir.to_path_buf(),
                limit: MAX_SALT_ANNOUNCEMENT_FILES_V1,
            });
        }
        let entry = entry?;
        revalidate_windows_salt_directory(dir, &directory, &opened_before)?;
        let filename = entry.file_name();
        let path = dir.join(&filename);
        let filename = filename
            .to_str()
            .ok_or_else(|| SaltScheduleError::NonCanonicalFilename { path: path.clone() })?;
        let filename_epoch = epoch_from_salt_filename(filename)
            .ok_or_else(|| SaltScheduleError::NonCanonicalFilename { path: path.clone() })?;
        let bytes = read_direct_salt_announcement_windows(dir, &directory, &opened_before, &path)?;
        let salt = decode_salt_announcement(&path, filename_epoch, &bytes)?;
        if salts.insert(filename_epoch, salt).is_some() {
            return Err(SaltScheduleError::DuplicateEpoch {
                path,
                epoch: filename_epoch,
            });
        }
    }

    revalidate_windows_salt_directory(dir, &directory, &opened_before)?;
    Ok(salts)
}

#[cfg(windows)]
fn revalidate_windows_salt_directory(
    path: &Path,
    directory: &File,
    original: &crate::secure_file_metadata::SecureMetadata,
) -> Result<(), SaltScheduleError> {
    use crate::secure_file_metadata::{
        from_file, from_path, is_direct_directory, same_file, unchanged,
    };

    let opened_after = from_file(directory)?;
    let named_after = match from_path(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(SaltScheduleError::DirectoryChanged(path.to_path_buf()));
        }
        Err(source) => return Err(source.into()),
    };
    if !is_direct_directory(&opened_after)
        || !is_direct_directory(&named_after)
        || !same_file(original, &opened_after)
        || !unchanged(original, &opened_after)
        || !same_file(&opened_after, &named_after)
        || !unchanged(&opened_after, &named_after)
    {
        return Err(SaltScheduleError::DirectoryChanged(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(windows)]
fn read_direct_salt_announcement_windows(
    directory_path: &Path,
    directory: &File,
    directory_before: &crate::secure_file_metadata::SecureMetadata,
    path: &Path,
) -> Result<Vec<u8>, SaltScheduleError> {
    use crate::secure_file_metadata::{
        from_file, from_path, is_direct_file, number_of_links, same_file, unchanged,
    };

    let maximum_bytes = u64::try_from(MAX_SALT_ANNOUNCEMENT_BYTES_V1)
        .map_err(|_| io::Error::other("salt announcement byte limit exceeds this platform"))?;
    let named_before = match from_path(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(SaltScheduleError::AnnouncementChanged(path.to_path_buf()));
        }
        Err(source) => return Err(source.into()),
    };
    if !is_direct_file(&named_before) || number_of_links(&named_before) != Some(1) {
        return Err(SaltScheduleError::UnsafeAnnouncement(path.to_path_buf()));
    }
    if named_before.len() > maximum_bytes {
        return Err(SaltScheduleError::AnnouncementTooLarge {
            path: path.to_path_buf(),
            limit: MAX_SALT_ANNOUNCEMENT_BYTES_V1,
        });
    }
    revalidate_windows_salt_directory(directory_path, directory, directory_before)?;

    let mut file = match crate::secure_file_metadata::open_direct_file(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(SaltScheduleError::AnnouncementChanged(path.to_path_buf()));
        }
        Err(source) => return Err(source.into()),
    };
    let opened_before = from_file(&file)?;
    let named_after_open = match from_path(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(SaltScheduleError::AnnouncementChanged(path.to_path_buf()));
        }
        Err(source) => return Err(source.into()),
    };
    if !is_direct_file(&opened_before)
        || !is_direct_file(&named_after_open)
        || number_of_links(&opened_before) != Some(1)
        || number_of_links(&named_after_open) != Some(1)
    {
        return Err(SaltScheduleError::UnsafeAnnouncement(path.to_path_buf()));
    }
    if !same_file(&named_before, &opened_before)
        || !unchanged(&named_before, &opened_before)
        || !same_file(&opened_before, &named_after_open)
        || !unchanged(&opened_before, &named_after_open)
        || opened_before.len() > maximum_bytes
    {
        return Err(SaltScheduleError::AnnouncementChanged(path.to_path_buf()));
    }
    revalidate_windows_salt_directory(directory_path, directory, directory_before)?;

    let initial_capacity = usize::try_from(opened_before.len())
        .map_err(|_| io::Error::other("salt announcement length exceeds this platform"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(initial_capacity)
        .map_err(io::Error::other)?;
    (&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SALT_ANNOUNCEMENT_BYTES_V1 {
        return Err(SaltScheduleError::AnnouncementTooLarge {
            path: path.to_path_buf(),
            limit: MAX_SALT_ANNOUNCEMENT_BYTES_V1,
        });
    }

    let opened_after = from_file(&file)?;
    let named_after_read = match from_path(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(SaltScheduleError::AnnouncementChanged(path.to_path_buf()));
        }
        Err(source) => return Err(source.into()),
    };
    if !is_direct_file(&opened_after)
        || !is_direct_file(&named_after_read)
        || number_of_links(&opened_after) != Some(1)
        || number_of_links(&named_after_read) != Some(1)
        || !same_file(&opened_before, &opened_after)
        || !unchanged(&opened_before, &opened_after)
        || !same_file(&opened_after, &named_after_read)
        || !unchanged(&opened_after, &named_after_read)
        || !same_file(&named_before, &named_after_read)
        || !unchanged(&named_before, &named_after_read)
        || u64::try_from(bytes.len()).ok() != Some(opened_before.len())
    {
        return Err(SaltScheduleError::AnnouncementChanged(path.to_path_buf()));
    }
    revalidate_windows_salt_directory(directory_path, directory, directory_before)?;
    Ok(bytes)
}

#[cfg(not(any(unix, windows)))]
fn load_direct_salt_announcements(
    _dir: &Path,
) -> Result<BTreeMap<u32, [u8; 32]>, SaltScheduleError> {
    Err(SaltScheduleError::UnsupportedPlatform)
}

/// Error raised while loading the salt schedule.
#[derive(Debug, Error)]
pub enum SaltScheduleError {
    /// Directory containing the announcements does not exist.
    #[error("salt announcement directory {0} does not exist")]
    DirectoryMissing(PathBuf),
    /// I/O failure while scanning the directory.
    #[error("failed to read salt announcements: {0}")]
    Io(#[from] io::Error),
    /// Direct salt schedule loading is unavailable on this platform.
    #[error("direct salt announcement loading is unsupported on this platform")]
    UnsupportedPlatform,
    /// The named schedule directory is a symlink or is not a directory.
    #[error("salt announcement directory {0} must be a direct directory")]
    UnsafeDirectory(PathBuf),
    /// The named schedule directory changed while it was loaded.
    #[error("salt announcement directory {0} changed while it was loaded")]
    DirectoryChanged(PathBuf),
    /// The schedule directory exceeds its fixed entry budget.
    #[error("salt announcement directory {dir} exceeds its {limit}-entry limit")]
    TooManyAnnouncements {
        /// Directory that exceeded the bound.
        dir: PathBuf,
        /// First-release entry limit.
        limit: usize,
    },
    /// An entry does not use the canonical epoch filename.
    #[error("salt announcement {path} does not use the canonical epoch filename")]
    NonCanonicalFilename {
        /// Path to the invalid entry.
        path: PathBuf,
    },
    /// An entry is indirect or is not one regular file.
    #[error("salt announcement {0} must be a single-link direct regular file")]
    UnsafeAnnouncement(PathBuf),
    /// An announcement exceeds its fixed byte budget.
    #[error("salt announcement {path} exceeds its {limit}-byte limit")]
    AnnouncementTooLarge {
        /// Path to the oversized entry.
        path: PathBuf,
        /// First-release byte limit.
        limit: usize,
    },
    /// An announcement changed while it was read.
    #[error("salt announcement {0} changed while it was read")]
    AnnouncementChanged(PathBuf),
    /// An announcement is not UTF-8 encoded.
    #[error("salt announcement {path} is not UTF-8: {source}")]
    InvalidUtf8 {
        /// Path to the failing file.
        path: PathBuf,
        /// UTF-8 validation error.
        source: std::str::Utf8Error,
    },
    /// Failed to parse a Norito announcement.
    #[error("failed to parse salt announcement {path}: {source}")]
    Parse {
        /// Path to the failing file.
        path: PathBuf,
        /// Underlying serialization error.
        source: norito::json::Error,
    },
    /// Filename and payload declare different epochs.
    #[error(
        "salt announcement {path} filename declares epoch {filename_epoch}, payload declares {declared_epoch}"
    )]
    FilenameEpochMismatch {
        /// Path to the failing file.
        path: PathBuf,
        /// Epoch encoded in the filename.
        filename_epoch: u32,
        /// Epoch encoded in the payload.
        declared_epoch: u32,
    },
    /// The validity interval is empty, reversed, or before the Unix epoch.
    #[error("salt announcement {path} contains an invalid validity window")]
    InvalidValidityWindow {
        /// Path to the failing file.
        path: PathBuf,
    },
    /// The optional predecessor does not immediately precede this epoch.
    #[error("salt announcement {path} epoch {epoch} has invalid previous epoch {previous_epoch:?}")]
    InvalidPreviousEpoch {
        /// Path to the failing file.
        path: PathBuf,
        /// Epoch declared by the announcement.
        epoch: u32,
        /// Invalid predecessor value.
        previous_epoch: Option<u32>,
    },
    /// Salt could not be decoded from hex.
    #[error("salt announcement {path} contains invalid salt: {source}")]
    SaltDecode {
        /// Path to the failing file.
        path: PathBuf,
        /// Underlying hex parsing error.
        source: hex::FromHexError,
    },
    /// Salt does not decode to 32 bytes.
    #[error("salt announcement {path} decoded salt length {len} (expected 32 bytes)")]
    SaltLength {
        /// Path to the failing file.
        path: PathBuf,
        /// Actual decoded length.
        len: usize,
    },
    /// Salt hex is not the canonical lowercase spelling.
    #[error("salt announcement {path} salt must use canonical lowercase hex")]
    NonCanonicalSaltHex {
        /// Path to the failing file.
        path: PathBuf,
    },
    /// Two announcements declared the same epoch.
    #[error("salt announcement {path} duplicates epoch {epoch}")]
    DuplicateEpoch {
        /// Path to the duplicate announcement.
        path: PathBuf,
        /// Epoch value that was duplicated.
        epoch: u32,
    },
    /// No announcement files were discovered in the directory.
    #[error("no salt announcements found in {0}")]
    NoAnnouncementsFound(PathBuf),
}
/// Error raised when resolving a blinded CID.
#[derive(Debug, Error, PartialEq, Eq, Copy, Clone)]
pub enum ResolveError {
    /// Requested salt epoch does not exist in the local schedule.
    #[error("salt epoch {0} is not known on this gateway")]
    UnknownEpoch(u32),
}
/// Resolver that maps blinded CIDs to canonical manifest identifiers.
#[derive(Debug)]
pub struct BlindedCidResolver {
    schedule: Arc<SaltSchedule>,
    state: Mutex<ResolverState>,
    cache_capacity: usize,
    filter_capacity: usize,
}

type ResolverCacheKey = (u32, [u8; BLINDED_CID_LEN]);

#[derive(Debug)]
struct CachedManifest {
    manifest_id: String,
    last_access: u64,
}

#[derive(Debug)]
struct CachedEpochFilter {
    manifest_generation: [u8; 32],
    filter: Arc<EpochBloom>,
    last_access: u64,
}

#[derive(Debug, Default)]
struct ResolverState {
    cache: BTreeMap<ResolverCacheKey, CachedManifest>,
    filters: BTreeMap<u32, CachedEpochFilter>,
    access_sequence: u64,
}

impl ResolverState {
    fn next_access(&mut self) -> u64 {
        self.access_sequence = self.access_sequence.saturating_add(1);
        self.access_sequence
    }

    fn cached_manifest_id(&self, key: &ResolverCacheKey) -> Option<String> {
        self.cache.get(key).map(|entry| entry.manifest_id.clone())
    }

    fn touch_cache_entry(&mut self, key: &ResolverCacheKey, manifest_id: &str) {
        let access = self.next_access();
        if let Some(entry) = self.cache.get_mut(key)
            && entry.manifest_id == manifest_id
        {
            entry.last_access = access;
        }
    }

    fn remove_cache_entry(&mut self, key: &ResolverCacheKey, manifest_id: &str) {
        if self
            .cache
            .get(key)
            .is_some_and(|entry| entry.manifest_id == manifest_id)
        {
            self.cache.remove(key);
        }
    }

    fn insert_cache_entry(&mut self, key: ResolverCacheKey, manifest_id: String, capacity: usize) {
        if capacity == 0 {
            return;
        }
        if !self.cache.contains_key(&key)
            && self.cache.len() >= capacity
            && let Some(victim) = self
                .cache
                .iter()
                .map(|(victim_key, entry)| (*victim_key, entry.last_access))
                .min_by_key(|(victim_key, last_access)| (*last_access, *victim_key))
                .map(|(victim_key, _)| victim_key)
        {
            self.cache.remove(&victim);
        }
        let last_access = self.next_access();
        self.cache.insert(
            key,
            CachedManifest {
                manifest_id,
                last_access,
            },
        );
    }

    fn current_filter(
        &mut self,
        epoch: u32,
        manifest_generation: &[u8; 32],
    ) -> Option<Arc<EpochBloom>> {
        let matches_generation = self
            .filters
            .get(&epoch)
            .is_some_and(|entry| entry.manifest_generation == *manifest_generation);
        if !matches_generation {
            self.filters.remove(&epoch);
            return None;
        }
        let access = self.next_access();
        let entry = self.filters.get_mut(&epoch)?;
        entry.last_access = access;
        Some(Arc::clone(&entry.filter))
    }

    fn insert_filter(
        &mut self,
        epoch: u32,
        manifest_generation: [u8; 32],
        filter: Arc<EpochBloom>,
        capacity: usize,
    ) {
        if capacity == 0 {
            return;
        }
        if !self.filters.contains_key(&epoch)
            && self.filters.len() >= capacity
            && let Some(victim) = self
                .filters
                .iter()
                .map(|(victim_epoch, entry)| (*victim_epoch, entry.last_access))
                .min_by_key(|(victim_epoch, last_access)| (*last_access, *victim_epoch))
                .map(|(victim_epoch, _)| victim_epoch)
        {
            self.filters.remove(&victim);
        }
        let last_access = self.next_access();
        self.filters.insert(
            epoch,
            CachedEpochFilter {
                manifest_generation,
                filter,
                last_access,
            },
        );
    }
}

impl BlindedCidResolver {
    /// Construct a new resolver backed by the supplied schedule.
    #[must_use]
    pub fn new(schedule: Arc<SaltSchedule>) -> Self {
        Self::with_capacities(
            schedule,
            MAX_RESOLVER_CACHE_ENTRIES_V1,
            MAX_RESOLVER_FILTER_EPOCHS_V1,
        )
    }

    fn with_capacities(
        schedule: Arc<SaltSchedule>,
        cache_capacity: usize,
        filter_capacity: usize,
    ) -> Self {
        Self {
            schedule,
            state: Mutex::new(ResolverState::default()),
            cache_capacity,
            filter_capacity,
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, ResolverState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Resolve a blinded CID into a manifest identifier using the gateway's stored manifests.
    ///
    /// Successful lookups and negative filters are cached within fixed first-release bounds. A
    /// cached manifest is returned only while the current manifest snapshot still contains the
    /// exact identifier and blinded CID.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError::UnknownEpoch`] when the requested epoch is not
    /// present in the local schedule.
    pub fn resolve_manifest_id(
        &self,
        manifests: &[StoredManifest],
        epoch: u32,
        blinded: &[u8; BLINDED_CID_LEN],
    ) -> Result<Option<String>, ResolveError> {
        let salt = self
            .schedule
            .salt(epoch)
            .ok_or(ResolveError::UnknownEpoch(epoch))?;
        let cache_key = (epoch, *blinded);
        let cached_manifest_id = self.state().cached_manifest_id(&cache_key);
        if let Some(manifest_id) = cached_manifest_id {
            let is_current = manifests.iter().any(|manifest| {
                manifest.manifest_id() == manifest_id.as_str()
                    && canonical_cache_key(&salt, manifest.manifest_cid()).as_bytes() == blinded
            });
            if is_current {
                self.state().touch_cache_entry(&cache_key, &manifest_id);
                return Ok(Some(manifest_id));
            }
            self.state().remove_cache_entry(&cache_key, &manifest_id);
        }

        let manifest_generation = manifest_set_generation(manifests);
        let current_filter = self.state().current_filter(epoch, &manifest_generation);
        if current_filter
            .as_ref()
            .is_some_and(|filter| !filter.probably_contains(blinded))
        {
            return Ok(None);
        }

        let mut rebuilt_filter = current_filter
            .is_none()
            .then(|| EpochBloom::new(manifests.len()));
        let mut matched_id: Option<String> = None;
        for manifest in manifests {
            let derived = canonical_cache_key(&salt, manifest.manifest_cid());
            let derived_bytes = derived.as_bytes();
            if let Some(filter) = rebuilt_filter.as_mut() {
                filter.insert(derived_bytes);
            }
            if derived_bytes == blinded
                && matched_id
                    .as_deref()
                    .is_none_or(|current| manifest.manifest_id() < current)
            {
                matched_id = Some(manifest.manifest_id().to_owned());
            }
        }
        if let Some(filter) = rebuilt_filter {
            self.state().insert_filter(
                epoch,
                manifest_generation,
                Arc::new(filter),
                self.filter_capacity,
            );
        }
        matched_id.map_or(Ok(None), |manifest_id| {
            self.state()
                .insert_cache_entry(cache_key, manifest_id.clone(), self.cache_capacity);
            Ok(Some(manifest_id))
        })
    }
}

fn update_length_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn manifest_set_generation(manifests: &[StoredManifest]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_SET_GENERATION_DOMAIN_V1);
    hasher.update(
        &u64::try_from(manifests.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for manifest in manifests {
        update_length_prefixed(&mut hasher, manifest.manifest_id().as_bytes());
        update_length_prefixed(&mut hasher, manifest.manifest_cid());
        hasher.update(manifest.manifest_digest());
    }
    *hasher.finalize().as_bytes()
}

/// Lightweight bloom filter used to short-circuit blinded CID lookups.
#[derive(Debug)]
struct EpochBloom {
    bits: Vec<u64>,
    mask: u64,
}

impl EpochBloom {
    fn new(expected_items: usize) -> Self {
        let requested_bits = expected_items
            .max(1)
            .saturating_mul(16)
            .clamp(MIN_RESOLVER_BLOOM_BITS_V1, MAX_RESOLVER_BLOOM_BITS_V1);
        let bits = requested_bits
            .checked_next_power_of_two()
            .unwrap_or(MAX_RESOLVER_BLOOM_BITS_V1)
            .min(MAX_RESOLVER_BLOOM_BITS_V1);
        let bit_mask = bits as u64 - 1;
        let words = bits / 64;
        Self {
            bits: vec![0; words],
            mask: bit_mask,
        }
    }

    fn probably_contains(&self, data: &[u8]) -> bool {
        self.positions(data)
            .into_iter()
            .all(|(word_index, bit)| self.bits[word_index] & bit == bit)
    }

    fn insert(&mut self, data: &[u8]) {
        for (word_index, bit) in self.positions(data) {
            self.bits[word_index] |= bit;
        }
    }

    fn positions(&self, data: &[u8]) -> [(usize, u64); 6] {
        let digest = blake3::hash(data);
        let bytes = digest.as_bytes();
        let h1 = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let mut h2 = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        if h2 == 0 {
            h2 = 0x9e3779b97f4a7c15;
        }
        std::array::from_fn(|index| {
            let position = h1.wrapping_add((index as u64).wrapping_mul(h2)) & self.mask;
            ((position >> 6) as usize, 1_u64 << (position & 63))
        })
    }
}

#[cfg(all(test, windows))]
mod windows_salt_schedule_tests {
    use super::*;

    const TEST_SALT: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn announcement_payload(epoch: u32, previous_epoch: Option<u32>) -> String {
        let previous_epoch =
            previous_epoch.map_or_else(|| "null".to_owned(), |epoch| epoch.to_string());
        let valid_after = i64::from(epoch).saturating_mul(1_000).saturating_add(1);
        let valid_until = valid_after.saturating_add(999);
        format!(
            r#"{{
                "epoch_id": {epoch},
                "previous_epoch": {previous_epoch},
                "valid_after": {valid_after},
                "valid_until": {valid_until},
                "blinded_cid_salt_hex": "{TEST_SALT}",
                "emergency_rotation": false,
                "notes": null,
                "signature": null
            }}"#
        )
    }

    fn write_announcement(directory: &Path, epoch: u32) -> PathBuf {
        let path = directory.join(canonical_salt_filename(epoch));
        fs::write(&path, announcement_payload(epoch, epoch.checked_sub(1)))
            .expect("write salt announcement");
        path
    }

    #[test]
    fn loads_direct_bounded_announcement() {
        let directory = tempfile::tempdir().expect("create salt directory");
        write_announcement(directory.path(), 1);

        let schedule = SaltSchedule::load_from_dir(directory.path()).expect("load salt schedule");

        assert_eq!(
            schedule.salt(1).map(hex::encode).as_deref(),
            Some(TEST_SALT)
        );
    }

    #[test]
    fn rejects_hard_linked_announcement() {
        let directory = tempfile::tempdir().expect("create salt directory");
        let outside = tempfile::tempdir().expect("create hard-link holder");
        let announcement = write_announcement(directory.path(), 1);
        fs::hard_link(&announcement, outside.path().join("second-link.json"))
            .expect("hard-link salt announcement");

        assert!(matches!(
            SaltSchedule::load_from_dir(directory.path()),
            Err(SaltScheduleError::UnsafeAnnouncement(_))
        ));
    }

    #[test]
    fn rejects_reparse_directory_and_file_when_platform_allows_fixture() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let source = tempfile::tempdir().expect("create source salt directory");
        write_announcement(source.path(), 1);
        let holder = tempfile::tempdir().expect("create reparse holder");
        let linked_directory = holder.path().join("linked-salts");
        match symlink_dir(source.path(), &linked_directory) {
            Ok(()) => assert!(matches!(
                SaltSchedule::load_from_dir(&linked_directory),
                Err(SaltScheduleError::UnsafeDirectory(_))
            )),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("create salt directory reparse point: {error}"),
        }

        let directory = tempfile::tempdir().expect("create direct salt directory");
        let external = holder.path().join("external.json");
        fs::write(&external, announcement_payload(1, Some(0)))
            .expect("write external salt announcement");
        let linked_file = directory.path().join(canonical_salt_filename(1));
        match symlink_file(&external, &linked_file) {
            Ok(()) => assert!(matches!(
                SaltSchedule::load_from_dir(directory.path()),
                Err(SaltScheduleError::UnsafeAnnouncement(_))
            )),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
            Err(error) => panic!("create salt announcement reparse point: {error}"),
        }
    }

    #[test]
    fn bounds_directory_entries_and_file_bytes() {
        let directory = tempfile::tempdir().expect("create oversized salt directory");
        fs::write(
            directory.path().join(canonical_salt_filename(1)),
            vec![b' '; MAX_SALT_ANNOUNCEMENT_BYTES_V1 + 1],
        )
        .expect("write oversized salt announcement");
        assert!(matches!(
            SaltSchedule::load_from_dir(directory.path()),
            Err(SaltScheduleError::AnnouncementTooLarge { .. })
        ));

        let directory = tempfile::tempdir().expect("create crowded salt directory");
        for epoch in 0..=MAX_SALT_ANNOUNCEMENT_FILES_V1 as u32 {
            write_announcement(directory.path(), epoch);
        }
        assert!(matches!(
            SaltSchedule::load_from_dir(directory.path()),
            Err(SaltScheduleError::TooManyAnnouncements { .. })
        ));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sorafs_car::{CarBuildPlan, CarWriter, compute_chunk_plan_digest_sha3, compute_por_root};
    use sorafs_manifest::{BLAKE3_256_MULTIHASH_CODE, DagCodecId, ManifestBuilder, PinPolicy};
    use sorafs_node::{config::StorageConfig, store::StorageBackend};

    const SALT_ALPHA: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const SALT_BETA: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff00112233445566778899aabbccddeeff";

    fn storage_backend(temp_dir: &tempfile::TempDir) -> StorageBackend {
        let physical_parent = temp_dir
            .path()
            .canonicalize()
            .expect("physical temp parent");
        StorageBackend::new(
            StorageConfig::builder()
                .enabled(true)
                .data_dir(physical_parent.join("storage"))
                .build(),
        )
        .expect("open canonical test storage")
    }
    fn ingest_test_manifest(backend: &StorageBackend, payload: &[u8]) -> StoredManifest {
        let plan = CarBuildPlan::single_file(payload).expect("build canonical manifest plan");
        let car_stats = CarWriter::new(&plan, payload)
            .expect("construct canonical CAR writer")
            .write_to(std::io::sink())
            .expect("derive canonical CAR metadata");
        let manifest = ManifestBuilder::new()
            .root_cid(
                car_stats
                    .root_cids
                    .first()
                    .cloned()
                    .expect("canonical CAR root"),
            )
            .dag_codec(DagCodecId(car_stats.dag_codec))
            .chunking_from_profile(plan.chunk_profile, BLAKE3_256_MULTIHASH_CODE)
            .chunk_digest_sha3_256(compute_chunk_plan_digest_sha3(&plan.chunks))
            .por_root(compute_por_root(payload, &plan).expect("derive canonical PoR root"))
            .content_length(plan.content_length)
            .car_digest(*car_stats.car_archive_digest.as_bytes())
            .car_size(car_stats.car_size)
            .pin_policy(PinPolicy::default())
            .build()
            .expect("build canonical manifest");
        let mut reader = payload;
        let manifest_id = backend
            .ingest_manifest(&manifest, &plan, &mut reader)
            .expect("ingest canonical manifest");
        backend
            .manifest(&manifest_id)
            .expect("read back canonical stored manifest")
    }

    fn announcement_payload(epoch: u32, previous_epoch: Option<u32>, salt_hex: &str) -> String {
        let previous_epoch =
            previous_epoch.map_or_else(|| "null".to_owned(), |epoch| epoch.to_string());
        let valid_after = i64::from(epoch).saturating_mul(1_000).saturating_add(1);
        let valid_until = valid_after.saturating_add(999);
        format!(
            r#"{{
                "epoch_id": {epoch},
                "previous_epoch": {previous_epoch},
                "valid_after": {valid_after},
                "valid_until": {valid_until},
                "blinded_cid_salt_hex": "{salt_hex}",
                "emergency_rotation": false,
                "notes": null,
                "signature": null
            }}"#
        )
    }

    fn write_announcement(
        directory: &Path,
        epoch: u32,
        previous_epoch: Option<u32>,
        salt_hex: &str,
    ) -> PathBuf {
        let path = directory.join(canonical_salt_filename(epoch));
        fs::write(&path, announcement_payload(epoch, previous_epoch, salt_hex))
            .expect("write canonical salt announcement");
        path
    }

    fn blinded_for(
        resolver: &BlindedCidResolver,
        epoch: u32,
        manifest: &StoredManifest,
    ) -> [u8; BLINDED_CID_LEN] {
        let salt = resolver.schedule.salt(epoch).expect("test salt");
        let canonical = canonical_cache_key(&salt, manifest.manifest_cid());
        *canonical.as_bytes()
    }

    #[test]
    fn salt_schedule_loads_announcements() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_announcement(dir.path(), 1, Some(0), SALT_BETA);
        let schedule = SaltSchedule::load_from_dir(dir.path()).expect("schedule");
        let salt = schedule.salt(1).expect("epoch");
        assert_eq!(hex::encode(salt), SALT_BETA);
        assert!(schedule.salt(2).is_none());
    }

    #[test]
    fn salt_schedule_retains_only_the_latest_numeric_epoch_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_announcement(dir.path(), 1, Some(0), SALT_ALPHA);
        write_announcement(dir.path(), 42, Some(41), SALT_ALPHA);
        write_announcement(dir.path(), 43, Some(42), SALT_BETA);

        let schedule = SaltSchedule::load_from_dir(dir.path()).expect("schedule");
        assert!(schedule.salt(1).is_none());
        assert!(schedule.salt(42).is_some());
        assert!(schedule.salt(43).is_some());
        assert_eq!(schedule.salts.len(), ACTIVE_SALT_EPOCH_WINDOW_V1 as usize);
    }

    #[test]
    fn salt_schedule_rejects_noncanonical_filename_and_epoch_binding() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("epoch-1.norito.json"),
            announcement_payload(1, Some(0), SALT_ALPHA),
        )
        .expect("write noncanonical name");
        assert!(matches!(
            SaltSchedule::load_from_dir(dir.path()),
            Err(SaltScheduleError::NonCanonicalFilename { .. })
        ));

        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join(canonical_salt_filename(2)),
            announcement_payload(1, Some(0), SALT_ALPHA),
        )
        .expect("write mismatched epoch");
        assert!(matches!(
            SaltSchedule::load_from_dir(dir.path()),
            Err(SaltScheduleError::FilenameEpochMismatch {
                filename_epoch: 2,
                declared_epoch: 1,
                ..
            })
        ));
    }

    #[test]
    fn salt_schedule_rejects_noncanonical_schema_and_salt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = announcement_payload(1, Some(0), SALT_ALPHA).replacen(
            "\"signature\": null",
            "\"signature\": null, \"unexpected\": true",
            1,
        );
        fs::write(dir.path().join(canonical_salt_filename(1)), payload)
            .expect("write schema-invalid announcement");
        assert!(matches!(
            SaltSchedule::load_from_dir(dir.path()),
            Err(SaltScheduleError::Parse { .. })
        ));

        let dir = tempfile::tempdir().expect("tempdir");
        write_announcement(dir.path(), 1, Some(0), &SALT_ALPHA.to_ascii_uppercase());
        assert!(matches!(
            SaltSchedule::load_from_dir(dir.path()),
            Err(SaltScheduleError::NonCanonicalSaltHex { .. })
        ));
    }

    #[test]
    fn salt_schedule_rejects_invalid_epoch_predecessor_and_validity() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_announcement(dir.path(), 7, Some(5), SALT_ALPHA);
        assert!(matches!(
            SaltSchedule::load_from_dir(dir.path()),
            Err(SaltScheduleError::InvalidPreviousEpoch { .. })
        ));

        let dir = tempfile::tempdir().expect("tempdir");
        let payload = announcement_payload(7, Some(6), SALT_ALPHA).replacen(
            "\"valid_until\": 8000",
            "\"valid_until\": 7001",
            1,
        );
        fs::write(dir.path().join(canonical_salt_filename(7)), payload)
            .expect("write invalid validity window");
        assert!(matches!(
            SaltSchedule::load_from_dir(dir.path()),
            Err(SaltScheduleError::InvalidValidityWindow { .. })
        ));
    }

    #[test]
    fn salt_schedule_rejects_indirect_directory_and_file() {
        use std::os::unix::fs::symlink;

        let source = tempfile::tempdir().expect("source tempdir");
        write_announcement(source.path(), 1, Some(0), SALT_ALPHA);
        let holder = tempfile::tempdir().expect("holder tempdir");
        let linked_directory = holder.path().join("linked-salts");
        symlink(source.path(), &linked_directory).expect("link salt directory");
        assert!(matches!(
            SaltSchedule::load_from_dir(&linked_directory),
            Err(SaltScheduleError::UnsafeDirectory(_))
        ));

        let directory = tempfile::tempdir().expect("salt tempdir");
        let external = holder.path().join("external.json");
        fs::write(&external, announcement_payload(1, Some(0), SALT_ALPHA))
            .expect("write external announcement");
        symlink(&external, directory.path().join(canonical_salt_filename(1)))
            .expect("link salt announcement");
        assert!(matches!(
            SaltSchedule::load_from_dir(directory.path()),
            Err(SaltScheduleError::UnsafeAnnouncement(_))
        ));
    }

    #[test]
    fn salt_schedule_enforces_file_and_directory_bounds() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join(canonical_salt_filename(1)),
            vec![b' '; MAX_SALT_ANNOUNCEMENT_BYTES_V1 + 1],
        )
        .expect("write oversized announcement");
        assert!(matches!(
            SaltSchedule::load_from_dir(dir.path()),
            Err(SaltScheduleError::AnnouncementTooLarge { .. })
        ));

        let dir = tempfile::tempdir().expect("tempdir");
        for epoch in 0..=MAX_SALT_ANNOUNCEMENT_FILES_V1 as u32 {
            write_announcement(dir.path(), epoch, epoch.checked_sub(1), SALT_ALPHA);
        }
        assert!(matches!(
            SaltSchedule::load_from_dir(dir.path()),
            Err(SaltScheduleError::TooManyAnnouncements { .. })
        ));
    }

    #[test]
    fn resolver_matches_manifest_by_blinded_cid() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_announcement(dir.path(), 42, Some(41), SALT_ALPHA);
        let schedule = Arc::new(SaltSchedule::load_from_dir(dir.path()).expect("schedule"));
        let resolver = BlindedCidResolver::new(schedule);
        let backend = storage_backend(&dir);
        let manifests = vec![
            ingest_test_manifest(&backend, b"cid-alpha"),
            ingest_test_manifest(&backend, b"cid-beta"),
        ];
        let expected_manifest_id = manifests[1].manifest_id().to_owned();
        let blinded = blinded_for(&resolver, 42, &manifests[1]);
        let hit = resolver
            .resolve_manifest_id(&manifests, 42, &blinded)
            .expect("resolution");
        assert_eq!(hit.as_deref(), Some(expected_manifest_id.as_str()));

        let removed = resolver
            .resolve_manifest_id(&[], 42, &blinded)
            .expect("resolution after removal");
        assert_eq!(removed, None, "a cache hit must remain provider-backed");
        assert!(resolver.state().cache.is_empty());
    }

    #[test]
    fn resolver_rebuilds_filter_when_same_sized_manifest_set_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_announcement(dir.path(), 100, Some(99), SALT_BETA);
        let schedule = Arc::new(SaltSchedule::load_from_dir(dir.path()).expect("schedule"));
        let resolver = BlindedCidResolver::new(schedule);
        let backend = storage_backend(&dir);
        let first_snapshot = vec![
            ingest_test_manifest(&backend, b"cid-alpha"),
            ingest_test_manifest(&backend, b"cid-beta"),
        ];
        let replacement = ingest_test_manifest(&backend, b"cid-gamma");
        let expected_manifest_id = replacement.manifest_id().to_owned();
        let replacement_blinded = blinded_for(&resolver, 100, &replacement);
        let second_snapshot = vec![replacement, ingest_test_manifest(&backend, b"cid-delta")];

        assert_eq!(
            resolver
                .resolve_manifest_id(&first_snapshot, 100, &replacement_blinded)
                .expect("prime negative filter"),
            None
        );
        let resolved_manifest = resolver
            .resolve_manifest_id(&second_snapshot, 100, &replacement_blinded)
            .expect("resolution");
        assert_eq!(
            resolved_manifest.as_deref(),
            Some(expected_manifest_id.as_str())
        );
    }

    #[test]
    fn resolver_cache_and_filter_state_are_hard_bounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_announcement(dir.path(), 100, Some(99), SALT_ALPHA);
        write_announcement(dir.path(), 101, Some(100), SALT_BETA);
        let schedule = Arc::new(SaltSchedule::load_from_dir(dir.path()).expect("schedule"));
        let resolver = BlindedCidResolver::with_capacities(schedule, 2, 1);
        let backend = storage_backend(&dir);
        let manifests = vec![
            ingest_test_manifest(&backend, b"cid-alpha"),
            ingest_test_manifest(&backend, b"cid-beta"),
            ingest_test_manifest(&backend, b"cid-gamma"),
        ];

        for manifest in &manifests {
            let blinded = blinded_for(&resolver, 100, manifest);
            assert!(
                resolver
                    .resolve_manifest_id(&manifests, 100, &blinded)
                    .expect("epoch 100 resolution")
                    .is_some()
            );
        }
        let second_epoch_blinded = blinded_for(&resolver, 101, &manifests[0]);
        resolver
            .resolve_manifest_id(&manifests, 101, &second_epoch_blinded)
            .expect("epoch 101 resolution");
        let state = resolver.state();
        assert_eq!(state.cache.len(), 2);
        assert_eq!(state.filters.len(), 1);
        assert!(state.filters.contains_key(&101));
    }

    #[test]
    fn bloom_allocation_is_bounded_for_untrusted_manifest_counts() {
        let bloom = EpochBloom::new(usize::MAX);
        assert_eq!(bloom.bits.len(), MAX_RESOLVER_BLOOM_BITS_V1 / 64);
    }
}
