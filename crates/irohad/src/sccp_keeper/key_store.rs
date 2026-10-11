//! Owner-only keeper-key directory of the SCCP keeper (`specs/sccp.md` §4.13.4).
//!
//! The directory is created `0700` and holds the node's keeper key as one regular `0600` file
//! [`KEY_FILE_NAME`]: the canonical multihash text of an Ed25519 private key and one line feed.
//! The key is generated on first start and never registered or funded. A symlinked directory
//! or file, another mode, another key algorithm and non-canonical text are refused, and a
//! refused file is never replaced. The write is atomic: a temporary file is written and
//! fsynced, renamed into place, and the directory is fsynced, so a crash leaves either no key
//! or the whole key.

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair, PrivateKey};
use zeroize::Zeroizing;

/// File name of the keeper key inside the key directory.
pub(super) const KEY_FILE_NAME: &str = "keeper.key";
/// Largest key file read: far above the 71 bytes of an Ed25519 key, so a foreign file is
/// refused without being loaded.
const MAX_KEY_FILE_BYTES: u64 = 1_024;

/// Why the key directory or the key file is refused.
#[derive(Debug, thiserror::Error)]
pub(super) enum KeyStoreError {
    /// The directory or the file could not be created, read or written.
    #[error("keeper-key path {path}: {source}")]
    Io {
        /// Offending path.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The path is not an owner-only directory or regular file.
    #[error("keeper-key path {path} is refused: {reason}")]
    Refused {
        /// Offending path.
        path: PathBuf,
        /// Why it is refused.
        reason: &'static str,
    },
    /// The key file does not hold one canonical Ed25519 private key.
    #[error("keeper-key file {path} is malformed: {reason}")]
    Malformed {
        /// Offending path.
        path: PathBuf,
        /// What is wrong.
        reason: &'static str,
    },
    /// The key could not be generated.
    #[error("keeper key generation failed: {0}")]
    Generate(String),
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> KeyStoreError + '_ {
    move |source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// `open(2)` flag that refuses a symlink as the last path component.
fn no_follow() -> i32 {
    i32::from_ne_bytes(rustix::fs::OFlags::NOFOLLOW.bits().to_ne_bytes())
}

/// The keeper's key directory.
#[derive(Debug, Clone)]
pub(super) struct KeyStore {
    dir: PathBuf,
}

impl KeyStore {
    /// Open `dir`, creating it `0700` when absent.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be created, is a symlink or not a directory, or grants
    /// any access to group or others.
    pub(super) fn open(dir: &Path) -> Result<Self, KeyStoreError> {
        if fs::symlink_metadata(dir).is_err() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(io(dir))?;
        }
        let metadata = fs::symlink_metadata(dir).map_err(io(dir))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(KeyStoreError::Refused {
                path: dir.to_path_buf(),
                reason: "not a directory (symlinks are refused)",
            });
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyStoreError::Refused {
                path: dir.to_path_buf(),
                reason: "grants access to group or others (expected 0700)",
            });
        }
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// Path of the key file.
    pub(super) fn key_path(&self) -> PathBuf {
        self.dir.join(KEY_FILE_NAME)
    }

    /// Path of the temporary file a write goes through. It is hidden and never read as a key.
    fn temporary_path(&self) -> PathBuf {
        self.dir.join(format!(".{KEY_FILE_NAME}.tmp"))
    }

    /// Load the keeper key, generating and writing it first when the directory holds none.
    ///
    /// # Errors
    ///
    /// Fails when an existing key file is refused or malformed (it is never replaced), or when
    /// a new key cannot be generated or written.
    pub(super) fn load_or_generate(&self) -> Result<KeyPair, KeyStoreError> {
        self.load()?.map_or_else(|| self.generate(), Ok)
    }

    /// Load the keeper key, or `None` when the directory holds no key file yet.
    ///
    /// # Errors
    ///
    /// Fails when the key file is a symlink or not a regular file, has another mode than
    /// `0600`, or does not hold one canonical Ed25519 private key.
    pub(super) fn load(&self) -> Result<Option<KeyPair>, KeyStoreError> {
        let path = self.key_path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io(&path)(error)),
        };
        check_key_file(&path, &metadata)?;
        // `O_NOFOLLOW` and the second check close the window in which the checked file could
        // be swapped for a symlink or another file.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(no_follow())
            .open(&path)
            .map_err(io(&path))?;
        check_key_file(&path, &file.metadata().map_err(io(&path))?)?;
        let mut text = Zeroizing::new(Vec::new());
        file.take(MAX_KEY_FILE_BYTES.saturating_add(1))
            .read_to_end(&mut text)
            .map_err(io(&path))?;
        parse_key(&path, &text).map(Some)
    }

    /// Generate a keeper key and write it atomically as the `0600` key file.
    ///
    /// # Errors
    ///
    /// Fails when a key file already exists, or generation or the write fails.
    fn generate(&self) -> Result<KeyPair, KeyStoreError> {
        let path = self.key_path();
        if fs::symlink_metadata(&path).is_ok() {
            return Err(KeyStoreError::Refused {
                path,
                reason: "a keeper key already exists",
            });
        }
        let key = KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .map_err(|error| KeyStoreError::Generate(error.to_string()))?;
        let mut text = Zeroizing::new(
            ExposedPrivateKey(key.private_key().clone())
                .try_to_multihash_string()
                .map_err(|error| KeyStoreError::Generate(error.to_string()))?,
        );
        text.push('\n');
        self.write(&text)
            .map_err(|source| KeyStoreError::Io { path, source })?;
        Ok(key)
    }

    /// Write `text` as the `0600` key file: into the temporary file, fsynced, renamed into
    /// place, and the directory fsynced.
    ///
    /// # Errors
    ///
    /// Fails when any write, fsync or the rename fails; a failed write leaves no temporary
    /// file behind.
    fn write(&self, text: &str) -> std::io::Result<()> {
        let temporary = self.temporary_path();
        // Only this node writes the directory, so a temporary file is the rest of a write that
        // a crash interrupted.
        let _ = fs::remove_file(&temporary);
        let written = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(no_follow())
                .open(&temporary)?;
            // The creation mode is subject to the process umask; the key file mode is not.
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            fs::rename(&temporary, self.key_path())?;
            File::open(&self.dir)?.sync_all()
        })();
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        written
    }
}

/// Refuse a key file that is not a regular `0600` file.
fn check_key_file(path: &Path, metadata: &fs::Metadata) -> Result<(), KeyStoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KeyStoreError::Refused {
            path: path.to_path_buf(),
            reason: "not a regular file (symlinks are refused)",
        });
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(KeyStoreError::Refused {
            path: path.to_path_buf(),
            reason: "mode is not 0600",
        });
    }
    Ok(())
}

/// Parse the canonical multihash text of an Ed25519 private key followed by one line feed.
fn parse_key(path: &Path, bytes: &[u8]) -> Result<KeyPair, KeyStoreError> {
    let malformed = |reason| KeyStoreError::Malformed {
        path: path.to_path_buf(),
        reason,
    };
    let text = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.strip_suffix('\n'))
        .ok_or_else(|| malformed("not one line of text"))?;
    let private_key: PrivateKey = text.parse().map_err(|_| malformed("not a private key"))?;
    if private_key.algorithm() != Algorithm::Ed25519 {
        return Err(malformed("not an Ed25519 key"));
    }
    let canonical = Zeroizing::new(
        ExposedPrivateKey(private_key.clone())
            .try_to_multihash_string()
            .map_err(|_| malformed("not a private key"))?,
    );
    if canonical.as_str() != text {
        return Err(malformed("not the canonical encoding of its key"));
    }
    KeyPair::from_private_key(private_key).map_err(|_| malformed("not a signing key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .expect("list")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("name")
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn the_key_is_generated_owner_only_into_an_empty_key_dir() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("sccp").join("keeper-key");
        let store = KeyStore::open(&dir).expect("created");
        assert_eq!(mode(&dir), 0o700);
        assert!(store.load().expect("empty directory").is_none());
        let key = store.load_or_generate().expect("generated");
        assert_eq!(key.public_key().algorithm(), Algorithm::Ed25519);
        assert_eq!(mode(&store.key_path()), 0o600);
        assert_eq!(names(&dir), [KEY_FILE_NAME]);
        // The file is the canonical key text and one line feed.
        let text = fs::read_to_string(store.key_path()).expect("key file");
        let private_key: PrivateKey = text.strip_suffix('\n').expect("line").parse().expect("key");
        assert_eq!(&private_key, key.private_key());
        // Later starts load the same key and never write again.
        let reopened = KeyStore::open(&dir).expect("reopened");
        assert_eq!(reopened.load_or_generate().expect("loaded"), key);
        assert_eq!(reopened.load().expect("loaded"), Some(key));
        assert_eq!(names(&dir), [KEY_FILE_NAME]);
        // Another node generates another key.
        let other = KeyStore::open(&root.path().join("other")).expect("created");
        assert_ne!(
            other.load_or_generate().expect("generated").public_key(),
            reopened.load_or_generate().expect("loaded").public_key()
        );
    }

    #[test]
    fn the_key_write_is_atomic() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = KeyStore::open(&root.path().join("keys")).expect("created");
        // A write interrupted before its rename left only the temporary file: it is never read
        // as the key, and the next start replaces it.
        fs::write(store.temporary_path(), b"8026").expect("partial write");
        assert!(store.load().expect("no key yet").is_none());
        let key = store.load_or_generate().expect("generated");
        assert_eq!(names(&store.dir), [KEY_FILE_NAME]);
        assert_eq!(store.load().expect("loaded"), Some(key.clone()));
        // An existing key is never overwritten.
        assert!(matches!(
            store.generate(),
            Err(KeyStoreError::Refused { .. })
        ));
        assert_eq!(store.load().expect("loaded"), Some(key));
        // A write whose rename fails (a directory holds the key's name) leaves no temporary
        // file, and the directory is refused as a key.
        let blocked = KeyStore::open(&root.path().join("blocked")).expect("created");
        fs::create_dir(blocked.key_path()).expect("directory");
        fs::write(blocked.key_path().join("content"), b"x").expect("non-empty");
        blocked.write("text\n").expect_err("the rename fails");
        assert_eq!(names(&blocked.dir), [KEY_FILE_NAME]);
        assert!(matches!(
            blocked.load_or_generate(),
            Err(KeyStoreError::Refused { .. })
        ));
    }

    #[test]
    fn symlinks_are_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("keys");
        let store = KeyStore::open(&dir).expect("created");
        let key = store.load_or_generate().expect("generated");

        // A symlinked directory is refused, also when it points at a valid key directory.
        let linked_dir = root.path().join("linked");
        std::os::unix::fs::symlink(&dir, &linked_dir).expect("symlink");
        assert!(matches!(
            KeyStore::open(&linked_dir),
            Err(KeyStoreError::Refused { .. })
        ));

        // A symlinked key file is refused, also when it points at a valid key file, and it is
        // not replaced by a new key.
        let other = KeyStore::open(&root.path().join("other")).expect("created");
        std::os::unix::fs::symlink(store.key_path(), other.key_path()).expect("symlink");
        assert!(matches!(other.load(), Err(KeyStoreError::Refused { .. })));
        assert!(matches!(
            other.load_or_generate(),
            Err(KeyStoreError::Refused { .. })
        ));
        assert!(
            fs::symlink_metadata(other.key_path())
                .expect("still there")
                .file_type()
                .is_symlink()
        );

        // A dangling symlink is not "no key yet": nothing is written through it.
        let dangling = KeyStore::open(&root.path().join("dangling")).expect("created");
        let target = root.path().join("elsewhere.key");
        std::os::unix::fs::symlink(&target, dangling.key_path()).expect("symlink");
        assert!(matches!(
            dangling.load_or_generate(),
            Err(KeyStoreError::Refused { .. })
        ));
        assert!(!target.exists());

        // A symlink planted at the temporary path is removed, not written through.
        let planted = KeyStore::open(&root.path().join("planted")).expect("created");
        std::os::unix::fs::symlink(&target, planted.temporary_path()).expect("symlink");
        planted.load_or_generate().expect("generated");
        assert!(!target.exists());
        assert_eq!(names(&planted.dir), [KEY_FILE_NAME]);

        assert_eq!(store.load().expect("untouched"), Some(key));
    }

    #[test]
    fn other_modes_and_foreign_content_are_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let open = root.path().join("open");
        fs::create_dir(&open).expect("dir");
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(matches!(
            KeyStore::open(&open),
            Err(KeyStoreError::Refused { .. })
        ));
        let file = root.path().join("file");
        fs::write(&file, b"x").expect("file");
        assert!(matches!(
            KeyStore::open(&file),
            Err(KeyStoreError::Refused { .. })
        ));

        let store = KeyStore::open(&root.path().join("keys")).expect("created");
        store.load_or_generate().expect("generated");
        let path = store.key_path();
        for loose in [0o644, 0o640, 0o400, 0o700] {
            fs::set_permissions(&path, fs::Permissions::from_mode(loose)).expect("chmod");
            assert!(
                matches!(store.load(), Err(KeyStoreError::Refused { .. })),
                "{loose:o}"
            );
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        store.load().expect("loads again").expect("key");

        let text = fs::read_to_string(&path).expect("key file");
        let secp256k1 = ExposedPrivateKey(
            KeyPair::try_random_with_algorithm(Algorithm::Secp256k1)
                .expect("key")
                .private_key()
                .clone(),
        )
        .try_to_multihash_string()
        .expect("text");
        for foreign in [
            String::new(),
            text.trim_end().to_owned(),
            format!("{text}\n"),
            // The canonical payload is upper-case hex.
            text.to_lowercase(),
            "not a key\n".to_owned(),
            format!("{secp256k1}\n"),
            "x".repeat(4_096),
        ] {
            fs::write(&path, &foreign).expect("overwrite");
            assert!(
                matches!(store.load(), Err(KeyStoreError::Malformed { .. })),
                "{} bytes",
                foreign.len()
            );
            assert!(
                matches!(
                    store.load_or_generate(),
                    Err(KeyStoreError::Malformed { .. })
                ),
                "a malformed key file is never replaced"
            );
        }
    }
}
