//! Owner-private, locked, immutable native deployment evidence.
use eyre::{Result, WrapErr as _, eyre};
use iroha_fs::{FileSnapshot, OwnerDirectory, PrivateDirectory, PublishMode};
use norito::json::{JsonDeserialize, JsonSerialize};
use std::{fs::File, path::Path};

const MAX_RECORD_BYTES: usize = 128 * 1024 * 1024;
const MAX_JOURNAL_ENTRIES: usize = 1024;

pub struct Journal {
    directory: PrivateDirectory,
    lock: File,
    lock_snapshot: FileSnapshot,
}

impl Journal {
    pub(super) fn open(path: &Path, create: bool) -> Result<Self> {
        let directory = if create {
            PrivateDirectory::open_or_create(path)?
        } else {
            PrivateDirectory::open(path)?
        };
        Self::lock(directory, create)
    }

    /// Publish the original plan and lock as one complete private directory.
    /// An occupied incomplete destination is never repaired or interpreted as a new journal.
    pub(super) fn persist_plan<T: JsonSerialize>(path: &Path, record: &T) -> Result<Self> {
        if path.as_os_str().is_empty() {
            return Err(eyre!("deployment journal path must not be empty"));
        }
        let encoded = norito::json::to_json_bounded(record, MAX_RECORD_BYTES)?;
        let path = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let name = path
            .file_name()
            .ok_or_else(|| eyre!("deployment journal has no directory name"))?;
        let parent = OwnerDirectory::open_or_create(
            path.parent()
                .ok_or_else(|| eyre!("deployment journal has no parent directory"))?,
        )?;
        let directory = match parent
            .publish_private_child(name, &[("lock", b""), ("plan.json", encoded.as_bytes())])
        {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                parent.open_private_child(name)?
            }
            Err(error) => return Err(error.into()),
        };
        let journal = Self::lock(directory, false)?;
        journal.require_exact_bytes("plan.json", encoded.as_bytes(), MAX_RECORD_BYTES)?;
        // Reconcile a prior publication that became visible before its durability result.
        journal.directory.open_existing_lock("lock")?.sync_all()?;
        journal
            .directory
            .open_existing_lock("plan.json")?
            .sync_all()?;
        journal.directory.sync()?;
        parent.sync()?;
        journal.revalidate()?;
        Ok(journal)
    }

    fn lock(directory: PrivateDirectory, create: bool) -> Result<Self> {
        let lock = if create {
            directory.open_lock("lock")?
        } else {
            // Read-only inspection must not repair missing evidence or change journal files.
            directory.open_read("lock")?
        };
        lock.try_lock().map_err(|error| {
            eyre!("deployment journal is already in use or cannot be locked: {error}")
        })?;
        if create {
            lock.sync_all()?;
            directory.sync()?;
        }
        let lock_snapshot = FileSnapshot::private_journal(&lock)?;
        let journal = Self {
            directory,
            lock,
            lock_snapshot,
        };
        journal.revalidate()?;
        Ok(journal)
    }

    pub(super) fn revalidate(&self) -> Result<()> {
        self.directory.revalidate()?;
        let current = self.directory.open_read("lock")?;
        if FileSnapshot::private_journal(&current)? != self.lock_snapshot
            || FileSnapshot::private_journal(&self.lock)? != self.lock_snapshot
        {
            return Err(eyre!("deployment journal lock was changed or replaced"));
        }
        self.directory.revalidate()?;
        Ok(())
    }

    fn with_custody<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        self.revalidate()?;
        let result = action();
        self.revalidate()?;
        result
    }

    pub(super) fn exists(&self, name: &str) -> Result<bool> {
        self.with_custody(|| {
            validate_name(name)?;
            match self.directory.open_read(name) {
                Ok(file) => {
                    if file.metadata()?.len() > MAX_RECORD_BYTES as u64 {
                        return Err(eyre!("deployment journal record exceeds fixed byte bound"));
                    }
                    Ok(true)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error.into()),
            }
        })
    }

    pub(super) fn require_unattempted(&self) -> Result<()> {
        self.with_custody(|| {
            for name in self.directory.entries(MAX_JOURNAL_ENTRIES)? {
                if !matches!(name.to_str(), Some("lock" | "plan.json" | "cancelled.json")) {
                    return Err(eyre!(
                        "only a fully unattempted deployment may be cancelled; retained execution or unknown evidence blocks cancellation"
                    ));
                }
            }
            Ok(())
        })
    }

    pub(super) fn read<T: JsonDeserialize>(&self, name: &str) -> Result<T> {
        self.with_custody(|| {
            validate_name(name)?;
            norito::json::from_slice(&self.directory.read(name, MAX_RECORD_BYTES)?)
                .wrap_err("decode closed deployment journal record")
        })
    }

    pub(super) fn read_limited<T: JsonDeserialize>(
        &self,
        name: &str,
        max_bytes: usize,
        limits: norito::DecodeLimits,
    ) -> Result<T> {
        self.with_custody(|| {
            validate_name(name)?;
            let bytes = self.directory.read(name, max_bytes)?;
            norito::json::preflight_slice(
                &bytes,
                norito::json::JsonPreflightLimits::from_decode_limits(max_bytes, limits),
            )?;
            norito::with_decode_limits_scope(limits, || norito::json::from_slice(&bytes))
                .wrap_err("decode bounded closed contract journal record")
        })
    }

    pub(super) fn require_exact<T: JsonSerialize>(&self, name: &str, record: &T) -> Result<()> {
        let encoded = norito::json::to_json_bounded(record, MAX_RECORD_BYTES)?;
        self.require_exact_bytes(name, encoded.as_bytes(), MAX_RECORD_BYTES)
    }

    fn require_exact_bytes(&self, name: &str, bytes: &[u8], maximum: usize) -> Result<()> {
        self.with_custody(|| {
            validate_name(name)?;
            if maximum > MAX_RECORD_BYTES || bytes.len() > maximum {
                return Err(eyre!("deployment journal record exceeds fixed byte bound"));
            }
            if self.directory.read(name, maximum)?.as_slice() != bytes {
                return Err(eyre!(
                    "immutable deployment journal record {name} disagrees with this operation"
                ));
            }
            Ok(())
        })
    }

    pub(super) fn put_exact<T: JsonSerialize>(&self, name: &str, record: &T) -> Result<()> {
        validate_name(name)?;
        let bytes = norito::json::to_vec(record)?;
        self.put_exact_bytes(name, &bytes, MAX_RECORD_BYTES)
    }

    pub(super) fn put_exact_limited<T: JsonSerialize>(
        &self,
        name: &str,
        record: &T,
        maximum: usize,
    ) -> Result<()> {
        validate_name(name)?;
        let encoded = norito::json::to_json_bounded(record, maximum)?;
        self.put_exact_bytes(name, encoded.as_bytes(), maximum)
    }

    fn put_exact_bytes(&self, name: &str, bytes: &[u8], maximum: usize) -> Result<()> {
        self.with_custody(|| {
            if maximum > MAX_RECORD_BYTES || bytes.len() > maximum {
                return Err(eyre!("deployment journal record exceeds fixed byte bound"));
            }
            if self.exists(name)? {
                return self.require_exact_bytes(name, bytes, maximum);
            }
            // Native create-new publication cannot overwrite partial or uncertain evidence.
            // Dispatch follows only after the complete record and its durability boundary.
            self.directory
                .write_atomic(name, bytes, PublishMode::CreateNew)?;
            Ok(())
        })
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 80
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        || name == "."
        || name == ".."
    {
        return Err(eyre!("invalid fixed deployment journal record name"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
