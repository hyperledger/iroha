//! Immutable original storage for the real offline compiler and native stage imports.
//!
//! Names are exact content addresses, never witness-selected paths. Existing files are
//! reread without replacement. Publication seals the original descriptor before atomic
//! no-replace rename; an uncertain failure preserves evidence for the next exact retry.
//! This is DATA custody only: it cannot authenticate a catalog, install a verifier or
//! create a wallet. The complete signed inventory and strict source import remain mandatory.

use std::{io, io::Read, io::Write, path::Path};

use iroha_fs::{FileSnapshot, PrivateDirectory, SealedPrivateFile};
use rand::rand_core::TryRngCore as _;
use sha2::{Digest as _, Sha256};

use super::{
    BlobV1, Error, OriginalCustodyFailure, OriginalSinkV1, OriginalSourceV1,
    PROVING_KEY_MAX_BYTES_V1,
};

/// A retained existing private directory of immutable content-addressed originals.
/// Wallet producer directories contain exact descriptor/VK/PK bytes.
/// The authenticated inventory selects the required roles; verifier-only consumers
/// may read descriptor/VK originals without granting a complete producer graph.
/// Every read retains actual no-follow native ancestry and a sealed original file.
/// Opening never creates, hardens, cleans or replaces an existing directory/file.
pub struct DirectoryOriginalsV1 {
    directory: PrivateDirectory,
    maximum_bytes: usize,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn name(digest: [u8; 32]) -> io::Result<String> {
    if digest == [0; 32] {
        return Err(invalid("zero original content address"));
    }
    Ok(hex::encode(digest))
}

struct StableOriginal {
    file: SealedPrivateFile,
    snapshot: FileSnapshot,
}

impl StableOriginal {
    fn recheck(&self) -> io::Result<()> {
        self.file.revalidate()?;
        if self.file.snapshot()? != self.snapshot {
            return Err(invalid("original changed during streaming"));
        }
        Ok(())
    }
}

impl Read for StableOriginal {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let custody = |error| io::Error::other(OriginalCustodyFailure(error));
        self.recheck().map_err(custody)?;
        let result = self.file.read(bytes);
        // Close custody even on a native read error. Integrity refusal takes
        // precedence; ordinary read failures retain their availability category.
        self.recheck().map_err(custody)?;
        result
    }
}

impl DirectoryOriginalsV1 {
    /// Exact retained canonical root for transporting a closed catalog's original list.
    /// Revalidates real private ancestry; the path grants no catalog or wallet authority.
    ///
    /// # Errors
    /// Replaced or no longer owner-private original directory/ancestor.
    pub fn root(&self) -> io::Result<&Path> {
        self.directory.revalidate()?;
        Ok(self.directory.path())
    }

    /// Retain an existing exact, owner-private directory with a finite original ceiling.
    /// The authenticated inventory separately applies descriptor, VK and PK role limits.
    ///
    /// # Errors
    /// Unsafe/noncanonical/missing directory, zero/oversized ceiling or native I/O failure.
    pub fn open_existing(path: impl AsRef<Path>, maximum_bytes: usize) -> io::Result<Self> {
        if maximum_bytes == 0 || maximum_bytes > PROVING_KEY_MAX_BYTES_V1 {
            return Err(invalid("invalid original storage byte ceiling"));
        }
        Ok(Self {
            directory: PrivateDirectory::open_exact(path)?,
            maximum_bytes,
        })
    }

    /// Reauthenticate one whole exact original using a bounded 64 KiB stream.
    ///
    /// # Errors
    /// Changed extent, content address, immutable mode, original file or ancestry.
    pub fn verify_original(&self, identity: BlobV1) -> io::Result<()> {
        self.require(identity)
    }

    /// Open one retained immutable original through the genuine bounded no-follow reader.
    /// Cloned native source owners share directory ancestry, never proving-key buffers.
    /// # Errors
    /// Missing/unavailable native storage or changed mode, file or retained ancestry.
    pub fn open_original(&self, sha256: [u8; 32]) -> Result<Box<dyn Read>, Error> {
        self.reader(sha256)
            .map(|reader| -> Box<dyn Read> { Box::new(reader) })
            .map_err(|error| {
                if matches!(
                    error.kind(),
                    io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput
                ) {
                    Error::Inventory
                } else {
                    Error::Unavailable
                }
            })
    }

    fn reader(&self, digest: [u8; 32]) -> io::Result<StableOriginal> {
        self.reader_optional(digest)?
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    fn reader_optional(&self, digest: [u8; 32]) -> io::Result<Option<StableOriginal>> {
        self.directory.revalidate()?;
        let result = (|| {
            let Some(file) = self
                .directory
                .open_retained_read_only_optional(name(digest)?, self.maximum_bytes)?
            else {
                return Ok(None);
            };
            if file.is_empty()? {
                return Err(invalid("empty original"));
            }
            let snapshot = file.snapshot()?;
            let original = StableOriginal { file, snapshot };
            original.recheck()?;
            Ok(Some(original))
        })();
        self.directory.revalidate()?;
        result
    }

    fn require(&self, identity: BlobV1) -> io::Result<()> {
        if identity.bytes == 0 || identity.bytes > self.maximum_bytes as u64 {
            return Err(invalid("original extent exceeds storage ceiling"));
        }
        let mut original = self.reader(identity.sha256)?;
        if original.file.len()? != identity.bytes {
            return Err(invalid("original extent differs from exact identity"));
        }
        let mut hash = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = original.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or_else(|| invalid("original extent overflow"))?;
            if total > identity.bytes {
                return Err(invalid("extended original"));
            }
            hash.update(&buffer[..count]);
        }
        let actual: [u8; 32] = hash.finalize().into();
        if total != identity.bytes || actual != identity.sha256 {
            return Err(invalid("original content address differs"));
        }
        self.directory.sync()?;
        self.directory.revalidate()
    }

    /// Atomically publish one exact original, or reauthenticate an existing identical one.
    /// No existing name is replaced or made writable. On failure, staged evidence and any
    /// published destination are retained; retry reconciles the exact final original first.
    ///
    /// # Errors
    /// Wrong digest/length, oversized bytes, unsafe custody, conflicting existing original,
    /// unavailable entropy/storage or uncertain native publication/durability.
    pub fn store_original(&mut self, identity: BlobV1, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > self.maximum_bytes || BlobV1::of(bytes) != identity {
            return Err(invalid(
                "supplied bytes differ from bounded original identity",
            ));
        }
        let final_name = name(identity.sha256)?;
        match self.reader_optional(identity.sha256)? {
            Some(_) => return self.require(identity),
            None => {}
        }
        let mut nonce = [0_u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(io::Error::other)?;
        let staging = format!("original-{}.partial", hex::encode(nonce));
        let mut writer = self
            .directory
            .create_retained_private(staging, bytes.len())?;
        writer.write_all(bytes)?;
        let sealed = writer.seal_read_only()?;
        match sealed.publish_new_name(final_name) {
            Ok(original) => original.revalidate()?,
            // Another exact publisher can win. Preserve our sealed staging evidence and
            // accept only after the winning original's complete hash/extent is verified.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        self.require(identity)
    }
}

impl OriginalSourceV1 for DirectoryOriginalsV1 {
    fn open(&mut self, sha256: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        // Only the initial native open can report absent reinstallable content.
        // Failed custody/admission (including a later NotFound) remains integrity
        // refusal; this conservative category never permits replacement material.
        self.reader_optional(sha256)
            .map_err(|_| Error::Inventory)?
            .ok_or(Error::Unavailable)
            .map(|reader| -> Box<dyn Read> { Box::new(reader) })
    }
}

impl OriginalSinkV1 for DirectoryOriginalsV1 {
    fn store(&mut self, identity: BlobV1, bytes: &[u8]) -> Result<(), Error> {
        self.store_original(identity, bytes)
            .map_err(|_| Error::Inventory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory() -> (tempfile::TempDir, DirectoryOriginalsV1) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("originals");
        let private = PrivateDirectory::open_or_create(&root).unwrap();
        drop(private);
        // /tmp is an OS alias on macOS; the exact native spelling is required here.
        let root = root.canonicalize().unwrap();
        let source = DirectoryOriginalsV1::open_existing(root, 1024).unwrap();
        (temp, source)
    }

    #[test]
    fn owned_reader_retains_the_actual_original_when_source_owner_is_released() {
        let (_temp, mut source) = directory();
        let bytes = b"retained owned source reader";
        let identity = BlobV1::of(bytes);
        source.store_original(identity, bytes).unwrap();
        let mut reader = source.open_original(identity.sha256).unwrap();
        drop(source);
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes);
    }

    #[test]
    fn owned_reader_never_falls_back_after_namespace_replacement() {
        let (_temp, mut source) = directory();
        let bytes = b"one immutable original";
        let identity = BlobV1::of(bytes);
        source.store_original(identity, bytes).unwrap();
        let root = source.root().unwrap().to_owned();
        let mut reader = source.open_original(identity.sha256).unwrap();
        std::fs::rename(
            root.join(hex::encode(identity.sha256)),
            root.join("retained-old"),
        )
        .unwrap();
        std::fs::write(root.join(hex::encode(identity.sha256)), bytes).unwrap();
        assert!(reader.read(&mut [0; 1]).is_err());
    }

    #[test]
    fn exact_retry_preserves_the_original_inode_and_owned_bytes() {
        let (_temp, mut source) = directory();
        let bytes = b"exact retained original bytes";
        let identity = BlobV1::of(bytes);
        source.store_original(identity, bytes).unwrap();
        let before = source
            .reader(identity.sha256)
            .unwrap()
            .file
            .identity()
            .unwrap();
        source.store_original(identity, bytes).unwrap();
        let after = source
            .reader(identity.sha256)
            .unwrap()
            .file
            .identity()
            .unwrap();
        assert_eq!(before, after);
        let mut actual = Vec::new();
        source
            .open(identity.sha256)
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, bytes);
    }

    #[test]
    fn missing_original_is_unavailable_and_exact_reinstallation_recovers() {
        let (_temp, mut source) = directory();
        let bytes = b"exact reinstallable proving original";
        let identity = BlobV1::of(bytes);
        assert_eq!(
            super::super::read(&mut source, identity, 1024),
            Err(Error::Unavailable)
        );
        assert!(matches!(source.open([0; 32]), Err(Error::Inventory)));
        source.store_original(identity, bytes).unwrap();
        assert_eq!(
            super::super::read(&mut source, identity, 1024).unwrap(),
            bytes
        );
    }

    #[test]
    fn disappeared_retained_original_is_integrity_refusal_not_unavailable() {
        struct RemoveAfterOpen {
            source: DirectoryOriginalsV1,
            path: std::path::PathBuf,
        }
        impl OriginalSourceV1 for RemoveAfterOpen {
            fn open(&mut self, sha256: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
                let reader = self.source.open(sha256)?;
                std::fs::remove_file(&self.path).unwrap();
                Ok(reader)
            }
        }
        let (_temp, mut source) = directory();
        let bytes = b"exact retained original";
        let identity = BlobV1::of(bytes);
        source.store_original(identity, bytes).unwrap();
        let path = source.directory.path().join(name(identity.sha256).unwrap());
        let mut changed = RemoveAfterOpen { source, path };
        assert_eq!(
            super::super::read(&mut changed, identity, 1024),
            Err(Error::Inventory)
        );
        // A fresh open can observe actual absence. It cannot turn the failed
        // retained read into acceptance or erase the earlier integrity refusal.
        assert_eq!(
            super::super::read(&mut changed.source, identity, 1024),
            Err(Error::Unavailable)
        );
    }

    #[test]
    fn changed_length_digest_empty_and_oversized_inputs_never_publish() {
        let (_temp, mut source) = directory();
        let bytes = b"original";
        let identity = BlobV1::of(bytes);
        let mut wrong = identity;
        wrong.bytes += 1;
        assert!(source.store_original(wrong, bytes).is_err());
        wrong = identity;
        wrong.sha256[0] ^= 1;
        assert!(source.store_original(wrong, bytes).is_err());
        assert!(source.store_original(BlobV1::of(b""), b"").is_err());
        let large = vec![1; 1025];
        assert!(source.store_original(BlobV1::of(&large), &large).is_err());
        assert!(source.open(identity.sha256).is_err());
        assert!(source.open([0; 32]).is_err());
    }

    #[test]
    fn conflicting_existing_original_is_retained_without_replacement() {
        let (_temp, mut source) = directory();
        let original = b"original";
        let changed = b"modified";
        let identity = BlobV1::of(original);
        let mut writer = source
            .directory
            .create_retained_private(name(identity.sha256).unwrap(), 8)
            .unwrap();
        writer.write_all(changed).unwrap();
        writer.seal_read_only().unwrap();
        let before = source
            .reader(identity.sha256)
            .unwrap()
            .file
            .identity()
            .unwrap();
        assert!(source.store_original(identity, original).is_err());
        let after = source
            .reader(identity.sha256)
            .unwrap()
            .file
            .identity()
            .unwrap();
        assert_eq!(before, after);
        let mut actual = Vec::new();
        source
            .open(identity.sha256)
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, changed);
    }

    #[test]
    fn a_reader_refuses_replaced_parent_ancestry() {
        let (temp, mut source) = directory();
        let bytes = b"original";
        let identity = BlobV1::of(bytes);
        source.store_original(identity, bytes).unwrap();
        let mut reader = source.open(identity.sha256).unwrap();
        let root = temp.path().join("originals");
        std::fs::rename(&root, temp.path().join("retained-old")).unwrap();
        std::fs::create_dir(&root).unwrap();
        let failure = reader.read(&mut [0; 8]).unwrap_err();
        assert!(failure.get_ref().unwrap().is::<OriginalCustodyFailure>());
    }

    #[cfg(unix)]
    #[test]
    fn writable_and_symlink_originals_never_enter_the_stream() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (_temp, mut source) = directory();
        let bytes = b"original";
        let identity = BlobV1::of(bytes);
        let root = source.directory.path().to_path_buf();
        let writable = root.join(name(identity.sha256).unwrap());
        std::fs::write(&writable, bytes).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            source.open(identity.sha256),
            Err(Error::Inventory)
        ));
        std::fs::remove_file(&writable).unwrap();
        let target = root.join("unselected");
        std::fs::write(&target, bytes).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o400)).unwrap();
        symlink(&target, &writable).unwrap();
        assert!(matches!(
            source.open(identity.sha256),
            Err(Error::Inventory)
        ));
        assert!(source.store_original(identity, bytes).is_err());
        assert!(
            writable
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
