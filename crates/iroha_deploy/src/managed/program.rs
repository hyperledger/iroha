//! Native executable format admission shared by CLI packaging and runtime qualification.

use iroha_fs::{FileSnapshot, RetainedBuildInput, RetainedFile};
use std::{
    env,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use super::{BinaryPin, Result};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Resolve parent aliases while leaving the selected native leaf unfollowed.
fn selected_program_path(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| invalid("managed executable has no filename"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(parent.canonicalize()?.join(name))
}

/// One live selected native program, without persisting an inode or executable bytes.
#[derive(Debug)]
pub(super) struct NativeProgram {
    original: RetainedFile,
    snapshot: FileSnapshot,
    pin: BinaryPin,
}

impl NativeProgram {
    pub(super) fn capture(path: &Path) -> Result<Self> {
        let path = selected_program_path(path)?;
        let mut original = RetainedFile::open_regular(&path)?;
        let snapshot = original.snapshot()?;
        let length = original.file().metadata()?.len();
        admit_native_program(&mut original)?;
        #[cfg(test)]
        tests::note_content_hash();
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut offset = 0_u64;
        // Every read has an absolute offset, so the header reader's cursor and Windows
        // seek_read's physical cursor cannot alter this exact original extent.
        while offset < length {
            let count = usize::try_from((length - offset).min(buffer.len() as u64))
                .expect("bounded native program chunk");
            iroha_fs::read_exact_at(original.file(), &mut buffer[..count], offset)?;
            hasher.update(&buffer[..count]);
            offset += count as u64;
        }
        let mut extra = [0_u8; 1];
        let beyond = loop {
            match iroha_fs::read_at(original.file(), &mut extra, length) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                outcome => break outcome?,
            }
        };
        if beyond != 0 || original.snapshot()? != snapshot {
            return Err(invalid("managed executable changed during native admission").into());
        }
        Ok(Self {
            original,
            snapshot,
            pin: BinaryPin {
                path,
                blake3: hasher.finalize().to_hex().to_string(),
            },
        })
    }

    pub(super) fn matching(pin: &BinaryPin) -> Result<Self> {
        let program = Self::capture(&pin.path)?;
        if program.pin.path != pin.path || program.pin.blake3 != pin.blake3 {
            return Err(super::Error::Invalid(
                "managed executable changed since this generation was prepared".into(),
            ));
        }
        Ok(program)
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.original.snapshot()? != self.snapshot {
            return Err(invalid("selected managed executable changed").into());
        }
        Ok(())
    }

    pub(super) fn pin(&self) -> Result<BinaryPin> {
        self.validate()?;
        Ok(self.pin.clone())
    }

    /// Reuse this content pin only for a freshly joined, unchanged original native object.
    /// Foreign paths retain independent native format, whole-content and custody admission.
    pub(super) fn pin_for_path(&self, path: &Path) -> Result<BinaryPin> {
        let selected = selected_program_path(path)?;
        if selected != self.pin.path {
            return Self::capture(path)?.pin();
        }
        self.validate()?;
        let candidate = RetainedFile::open_regular(&selected)?;
        let joined = (|| -> Result<BinaryPin> {
            if candidate.snapshot()? != self.snapshot
                || candidate.identity()? != self.original.identity()?
            {
                return Err(
                    invalid("worker executable differs from its live native admission").into(),
                );
            }
            Ok(self.pin.clone())
        })();
        // Keep both opened owners through their final native checks, even when the join refused.
        // This is a same-operation endpoint observation, not an atomic loaded-image attestation.
        let candidate_exit = candidate.revalidate();
        let original_exit = self.validate();
        candidate_exit?;
        original_exit?;
        joined
    }

    pub(super) fn path(&self) -> &Path {
        &self.pin.path
    }
}

/// Immutable live selection shared by discovery and its startup request clones.
#[derive(Debug)]
pub(super) struct RuntimePrograms {
    launcher: NativeProgram,
    daemon: NativeProgram,
}

impl RuntimePrograms {
    pub(super) fn capture(launcher: &Path, daemon: &Path) -> Result<Self> {
        let programs = Self {
            launcher: NativeProgram::capture(launcher)?,
            daemon: NativeProgram::capture(daemon)?,
        };
        programs.validate()?;
        Ok(programs)
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.launcher.validate()?;
        self.daemon.validate()
    }

    pub(super) fn pins(&self) -> Result<(BinaryPin, BinaryPin)> {
        Ok((self.launcher.pin()?, self.daemon.pin()?))
    }

    pub(super) fn require_paths(&self, launcher: &Path, daemon: &Path) -> Result<()> {
        if launcher != self.launcher.path() || daemon != self.daemon.path() {
            return Err(invalid("startup paths differ from the selected installed runtime").into());
        }
        self.validate()
    }
}

/// Admit one retained executable for this exact native operating system and architecture.
///
/// This checks executable format and custody, not authenticated build provenance.
///
/// # Errors
/// Rejects nonexecutable, cross-platform, cross-architecture, nonregular or changed inputs.
pub fn admit_native_program(file: &mut RetainedFile) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.file().metadata()?.permissions().mode() & 0o100 == 0 {
            return Err(invalid("CLI program is not executable"));
        }
    }
    admit_native_header(file.file_mut())?;
    file.revalidate()
}

/// Admit the same native executable format from a retained Cargo build input.
///
/// This supplies format admission only; it never grants installed or private-file authority.
/// # Errors
/// Refuses a nonexecutable, wrong-host or malformed original, changed custody and native errors.
pub fn admit_native_build_input(file: &mut RetainedBuildInput) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.permissions()?.mode() & 0o100 == 0 {
            return Err(invalid("CLI program is not executable"));
        }
    }
    admit_native_header(file)?;
    file.revalidate()
}

fn admit_native_header(file: &mut (impl Read + Seek + ?Sized)) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0_u8; 64];
    file.read_exact(&mut header)?;
    let native = match (env::consts::OS, env::consts::ARCH) {
        ("macos", arch) => {
            let cpu = match arch {
                "aarch64" => 0x0100_000c,
                "x86_64" => 0x0100_0007,
                _ => return Err(invalid("unsupported native CLI architecture")),
            };
            header[..4] == [0xcf, 0xfa, 0xed, 0xfe]
                && u32::from_le_bytes(header[4..8].try_into().expect("fixed native header field"))
                    == cpu
                && u32::from_le_bytes(
                    header[12..16]
                        .try_into()
                        .expect("fixed native header field"),
                ) == 2
        }
        ("linux", arch) => {
            let cpu = match arch {
                "aarch64" => 183,
                "x86_64" => 62,
                _ => return Err(invalid("unsupported native CLI architecture")),
            };
            header[..7] == [0x7f, b'E', b'L', b'F', 2, 1, 1]
                && matches!(
                    u16::from_le_bytes(
                        header[16..18]
                            .try_into()
                            .expect("fixed native header field")
                    ),
                    2 | 3
                )
                && u16::from_le_bytes(
                    header[18..20]
                        .try_into()
                        .expect("fixed native header field"),
                ) == cpu
                && u64::from_le_bytes(
                    header[24..32]
                        .try_into()
                        .expect("fixed native header field"),
                ) != 0
        }
        ("windows", arch) => {
            let cpu = match arch {
                "aarch64" => 0xaa64,
                "x86_64" => 0x8664,
                _ => return Err(invalid("unsupported native CLI architecture")),
            };
            let offset = u32::from_le_bytes(
                header[60..64]
                    .try_into()
                    .expect("fixed native header field"),
            );
            if header[..2] != *b"MZ" || !(64..=1024 * 1024).contains(&offset) {
                return Err(invalid("invalid native PE executable"));
            }
            file.seek(SeekFrom::Start(u64::from(offset)))?;
            let mut pe = [0_u8; 26];
            file.read_exact(&mut pe)?;
            let flags =
                u16::from_le_bytes(pe[22..24].try_into().expect("fixed native header field"));
            pe[..4] == *b"PE\0\0"
                && u16::from_le_bytes(pe[4..6].try_into().expect("fixed native header field"))
                    == cpu
                && flags & 2 != 0
                && flags & 0x2000 == 0
                && u16::from_le_bytes(pe[24..26].try_into().expect("fixed native header field"))
                    == 0x20b
        }
        _ => return Err(invalid("unsupported native CLI operating system")),
    };
    if !native {
        return Err(invalid(
            "CLI artifact is not an executable for this native host",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    std::thread_local! {
        static CONTENT_HASHES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    }

    /// Record entry into the actual whole-content hash producer for this test thread.
    pub(super) fn note_content_hash() {
        CONTENT_HASHES.with(|slot| {
            if let Some(count) = slot.get() {
                slot.set(Some(count + 1));
            }
        });
    }

    /// Restore the previous test-only observation even when the test unwinds.
    struct ContentHashProbe(Option<usize>);

    impl ContentHashProbe {
        fn begin() -> Self {
            Self(CONTENT_HASHES.with(|slot| slot.replace(Some(0))))
        }

        fn count(&self) -> usize {
            CONTENT_HASHES.with(|slot| slot.get().expect("active content hash probe"))
        }
    }

    impl Drop for ContentHashProbe {
        fn drop(&mut self) {
            CONTENT_HASHES.with(|slot| slot.set(self.0));
        }
    }

    fn copied_native_program() -> (tempfile::TempDir, PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().join("native");
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join(format!("program{}", env::consts::EXE_SUFFIX));
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        (temporary, path)
    }

    #[test]
    fn native_program_admits_actual_current_harness_and_refuses_plain_text() {
        let mut original = RetainedFile::open_regular(std::env::current_exe().unwrap()).unwrap();
        admit_native_program(&mut original).unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("nonexecutable");
        std::fs::write(&path, b"ordinary text is not a native executable").unwrap();
        let mut text = RetainedFile::open_regular(&path).unwrap();
        assert!(admit_native_program(&mut text).is_err());
    }

    #[test]
    fn native_build_input_admits_a_real_linked_harness_but_keeps_installed_sources_strict() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("cargo-program");
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::hard_link(&path, temporary.path().join("dependency-program")).unwrap();
        assert!(RetainedFile::open_regular(&path).is_err());
        let mut input = RetainedBuildInput::open(&path).unwrap();
        let before = input.snapshot().unwrap();
        admit_native_build_input(&mut input).unwrap();
        assert_eq!(input.snapshot().unwrap(), before);
        drop(input);
        std::fs::write(&path, b"not a native executable").unwrap();
        let mut invalid = RetainedBuildInput::open(&path).unwrap();
        assert!(admit_native_build_input(&mut invalid).is_err());
    }

    fn installed_pair() -> (tempfile::TempDir, super::super::InstalledRuntime) {
        let temporary = tempfile::tempdir().unwrap();
        for name in ["kagami", "iroha3d"] {
            std::fs::copy(
                std::env::current_exe().unwrap(),
                temporary
                    .path()
                    .join(format!("{name}{}", env::consts::EXE_SUFFIX)),
            )
            .unwrap();
        }
        let runtime = super::super::InstalledRuntime::from_directory(temporary.path()).unwrap();
        (temporary, runtime)
    }

    fn assert_unprepared(store: &super::super::ManagedStore) {
        assert!(store.contexts().unwrap().is_empty());
        assert_eq!(
            std::fs::read_dir(store.root().join("networks"))
                .unwrap()
                .count(),
            0
        );
        assert!(matches!(
            store.context(None),
            Err(super::super::Error::NoSelection)
        ));
    }

    #[test]
    fn live_native_selection_and_request_clones_share_the_original_programs() {
        let _resources = super::super::native_test_guard();
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<NativeProgram>();
        require_send_sync::<super::super::InstalledRuntime>();
        require_send_sync::<super::super::LocalnetRequest>();
        let actual = std::env::current_exe().unwrap();
        let program = NativeProgram::capture(&actual).unwrap();
        let pin = program.pin().unwrap();
        assert_eq!(program.path(), actual.canonicalize().unwrap());
        assert_eq!(pin.blake3.len(), 64);
        NativeProgram::matching(&pin).unwrap().validate().unwrap();
        program.validate().unwrap();
        let (temporary, runtime) = installed_pair();
        let request = runtime.localnet_request("selected", std::time::Duration::from_secs(30));
        let cloned = request.clone();
        let original = request.admit_programs().unwrap();
        let again = cloned.admit_programs().unwrap();
        assert!(std::sync::Arc::ptr_eq(&original, &again));
        assert_eq!(original.pins().unwrap().0.blake3, pin.blake3);
        let store = super::super::ManagedStore::open(&temporary.path().join("state")).unwrap();
        for change_launcher in [false, true] {
            let mut changed = cloned.clone();
            if change_launcher {
                changed.launcher = actual.clone();
            } else {
                changed.daemon = actual.clone();
            }
            assert!(
                matches!(store.up(&changed), Err(super::super::Error::Io(error))
                if error.kind() == io::ErrorKind::InvalidData)
            );
            assert_unprepared(&store);
        }
        request.admit_programs().unwrap().validate().unwrap();
        assert_unprepared(&store);
    }

    #[test]
    fn manual_native_admission_refuses_invalid_inputs_before_generation_and_preserves_install_help()
    {
        let _resources = super::super::native_test_guard();
        let temporary = tempfile::tempdir().unwrap();
        let store = super::super::ManagedStore::open(&temporary.path().join("state")).unwrap();
        let text = temporary.path().join("text");
        std::fs::write(&text, b"ordinary executable text still is not a native program................................").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&text, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let actual = std::env::current_exe().unwrap();
        for invalid in [text, temporary.path().join("missing")] {
            let request = super::super::LocalnetRequest::new(actual.clone(), invalid);
            assert!(store.up(&request).is_err());
            assert_unprepared(&store);
        }
        for name in ["kagami", "iroha3d"] {
            let installation = temporary.path().join(name);
            std::fs::create_dir(&installation).unwrap();
            std::fs::copy(
                &actual,
                installation.join(format!("{name}{}", env::consts::EXE_SUFFIX)),
            )
            .unwrap();
            assert!(matches!(
                super::super::InstalledRuntime::from_directory(&installation),
                Err(super::super::Error::Invalid(message)) if message == "the matching Kagami and iroha3d programs must be installed together; install the complete native developer bundle"
            ));
        }
        super::super::LocalnetRequest::new(actual.clone(), actual)
            .admit_programs()
            .unwrap()
            .validate()
            .unwrap();
        assert_unprepared(&store);
    }

    #[cfg(unix)]
    #[test]
    fn installed_and_manual_startup_refuse_a_replaced_link_before_preparation() {
        let _resources = super::super::native_test_guard();
        let (temporary, runtime) = installed_pair();
        let request = runtime.localnet_request("selected", std::time::Duration::from_secs(30));
        let original = temporary.path().join("original-daemon");
        std::fs::rename(&request.daemon, &original).unwrap();
        std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &request.daemon).unwrap();
        let store = super::super::ManagedStore::open(&temporary.path().join("state")).unwrap();
        assert!(store.up(&request).is_err());
        assert!(super::super::InstalledRuntime::from_directory(temporary.path()).is_err());
        let manual =
            super::super::LocalnetRequest::new(request.launcher.clone(), request.daemon.clone());
        assert!(store.up(&manual).is_err());
        assert_unprepared(&store);
        std::fs::remove_file(&request.daemon).unwrap();
        std::fs::rename(&original, &request.daemon).unwrap();
        // Rename changed native metadata: an old live cut is not revived by restoration.
        assert!(request.admit_programs().is_err());
        super::super::InstalledRuntime::from_directory(temporary.path())
            .unwrap()
            .localnet_request("selected", std::time::Duration::from_secs(30))
            .admit_programs()
            .unwrap()
            .validate()
            .unwrap();
        assert_unprepared(&store);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_fifo_selection_refuses_without_opening_a_blocking_data_reader() {
        use std::{os::unix::fs::FileTypeExt, process::Command};
        let _resources = super::super::native_test_guard();
        let (temporary, runtime) = installed_pair();
        let request = runtime.localnet_request("selected", std::time::Duration::from_secs(30));
        let original = temporary.path().join("original-daemon");
        std::fs::rename(&request.daemon, &original).unwrap();
        let created = Command::new("/usr/bin/mkfifo")
            .arg("-m")
            .arg("600")
            .arg(&request.daemon)
            .status()
            .unwrap();
        assert!(created.success(), "native FIFO creation must succeed");
        assert!(
            std::fs::symlink_metadata(&request.daemon)
                .unwrap()
                .file_type()
                .is_fifo()
        );
        let store = super::super::ManagedStore::open(&temporary.path().join("state")).unwrap();
        assert!(super::super::InstalledRuntime::from_directory(temporary.path()).is_err());
        let manual =
            super::super::LocalnetRequest::new(request.launcher.clone(), request.daemon.clone());
        assert!(store.up(&manual).is_err());
        assert!(store.up(&request).is_err());
        assert_unprepared(&store);
        std::fs::remove_file(&request.daemon).unwrap();
        std::fs::rename(&original, &request.daemon).unwrap();
        super::super::InstalledRuntime::from_directory(temporary.path())
            .unwrap()
            .localnet_request("selected", std::time::Duration::from_secs(30))
            .admit_programs()
            .unwrap()
            .validate()
            .unwrap();
        assert_unprepared(&store);
    }

    #[cfg(unix)]
    #[test]
    fn equal_contents_replacement_invalidates_live_selection_but_not_a_fresh_content_pin() {
        let _resources = super::super::native_test_guard();
        let (temporary, runtime) = installed_pair();
        let request = runtime.localnet_request("selected", std::time::Duration::from_secs(30));
        let pins = request.admit_programs().unwrap().pins().unwrap();
        let original = temporary.path().join("original-daemon");
        std::fs::rename(&request.daemon, &original).unwrap();
        std::fs::copy(std::env::current_exe().unwrap(), &request.daemon).unwrap();
        let store = super::super::ManagedStore::open(&temporary.path().join("state")).unwrap();
        assert!(store.up(&request).is_err());
        assert!(request.clone().admit_programs().is_err());
        assert_unprepared(&store);
        // A separately selected equal-content executable deliberately satisfies the persisted
        // path/content pin; the original request still owns, and rejects changes to, its old cut.
        NativeProgram::matching(&pins.1)
            .unwrap()
            .validate()
            .unwrap();
        let fresh = super::super::InstalledRuntime::from_directory(temporary.path()).unwrap();
        fresh
            .localnet_request("selected", std::time::Duration::from_secs(30))
            .admit_programs()
            .unwrap()
            .validate()
            .unwrap();
        drop(fresh);
        std::fs::remove_file(&request.daemon).unwrap();
        std::fs::rename(&original, &request.daemon).unwrap();
        assert!(request.admit_programs().is_err());
        NativeProgram::matching(&pins.1)
            .unwrap()
            .validate()
            .unwrap();
        assert_unprepared(&store);
    }

    #[cfg(unix)]
    #[test]
    fn changed_native_contents_and_execute_permissions_require_fresh_admission() {
        use std::{io::Write, os::unix::fs::PermissionsExt};
        let _resources = super::super::native_test_guard();
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("program");
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let selected = NativeProgram::capture(&path).unwrap();
        let pin = selected.pin().unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"changed native contents")
            .unwrap();
        assert!(selected.validate().is_err());
        assert!(super::super::store::verify_binary(&pin).is_err());
        assert_ne!(
            super::super::store::pin_binary(&path).unwrap().blake3,
            pin.blake3
        );
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        assert!(selected.validate().is_err());
        super::super::store::verify_binary(&pin).unwrap();
        let permissions = std::fs::metadata(&path).unwrap().permissions();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            matches!(NativeProgram::capture(&path), Err(super::super::Error::Io(error))
            if error.kind() == io::ErrorKind::InvalidData && error.to_string() == "CLI program is not executable")
        );
        std::fs::set_permissions(&path, permissions).unwrap();
        NativeProgram::matching(&pin).unwrap().validate().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn held_native_selection_denies_writers_and_replacement_until_drop() {
        let _resources = super::super::native_test_guard();
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("program.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let selected = NativeProgram::capture(&path).unwrap();
        let pin = selected.pin().unwrap();
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::rename(&path, temporary.path().join("moved.exe")).is_err());
        selected.validate().unwrap();
        drop(selected);
        let moved = temporary.path().join("moved.exe");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::rename(&moved, &path).unwrap();
        NativeProgram::matching(&pin).unwrap().validate().unwrap();
    }

    #[test]
    fn current_program_path_reuses_only_same_native_admission_and_hashes_foreign_paths() {
        let _resources = super::super::native_test_guard();
        let hashes = ContentHashProbe::begin();
        let current = std::env::current_exe().unwrap();
        let launcher = NativeProgram::capture(&current).unwrap();
        let pin = launcher.pin().unwrap();
        assert_eq!(hashes.count(), 1);
        for path in [
            current.clone(),
            current
                .parent()
                .unwrap()
                .join(".")
                .join(current.file_name().unwrap()),
        ] {
            let reused = launcher.pin_for_path(&path).unwrap();
            assert_eq!(reused.path, pin.path);
            assert_eq!(reused.blake3, pin.blake3);
            assert_eq!(hashes.count(), 1);
        }
        let (_temporary, foreign_path) = copied_native_program();
        let foreign = launcher.pin_for_path(&foreign_path).unwrap();
        assert_eq!(foreign.path, selected_program_path(&foreign_path).unwrap());
        assert_ne!(foreign.path, pin.path);
        assert_eq!(foreign.blake3, pin.blake3);
        assert_eq!(hashes.count(), 2, "foreign content must be freshly hashed");
        let daemon = NativeProgram::matching(&foreign).unwrap();
        daemon.validate().unwrap();
        assert_eq!(
            hashes.count(),
            3,
            "independent daemon admission still hashes"
        );
        let missing = foreign_path.with_file_name("absent");
        assert!(
            matches!(launcher.pin_for_path(&missing), Err(super::super::Error::Io(error))
            if error.kind() == io::ErrorKind::NotFound)
        );
        assert_eq!(hashes.count(), 3);
        launcher.validate().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn current_program_path_refuses_same_inode_edits_and_requires_fresh_restored_admission() {
        use std::{io::Write, os::unix::fs::PermissionsExt};
        let _resources = super::super::native_test_guard();
        let (_temporary, path) = copied_native_program();
        let hashes = ContentHashProbe::begin();
        let launcher = NativeProgram::capture(&path).unwrap();
        let pin = launcher.pin().unwrap();
        let original_identity = launcher.original.identity().unwrap();
        let length = std::fs::metadata(&path).unwrap().len();
        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writer.write_all(b"changed native extent").unwrap();
        writer.sync_all().unwrap();
        assert_eq!(
            iroha_fs::FileIdentity::of(&writer).unwrap(),
            original_identity
        );
        assert!(matches!(
            launcher.pin_for_path(&path),
            Err(super::super::Error::Io(_))
        ));
        assert_eq!(
            hashes.count(),
            1,
            "a changed live object cannot rehash into authority"
        );
        writer.set_len(length).unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        assert!(
            launcher.pin_for_path(&path).is_err(),
            "restoring bytes does not restore old metadata"
        );
        let restored = NativeProgram::matching(&pin).unwrap();
        assert_eq!(hashes.count(), 2);
        assert_eq!(restored.original.identity().unwrap(), original_identity);
        assert_eq!(restored.pin_for_path(&path).unwrap().blake3, pin.blake3);
        assert_eq!(hashes.count(), 2);
        let permissions = std::fs::metadata(&path).unwrap().permissions();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(restored.pin_for_path(&path).is_err());
        std::fs::set_permissions(&path, permissions).unwrap();
        assert!(restored.pin_for_path(&path).is_err());
        let restored = NativeProgram::matching(&pin).unwrap();
        assert_eq!(restored.pin_for_path(&path).unwrap().blake3, pin.blake3);
        assert_eq!(hashes.count(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn current_program_path_refuses_leaf_and_ancestor_replacement_and_keeps_original_retry() {
        let _resources = super::super::native_test_guard();
        let (temporary, path) = copied_native_program();
        let hashes = ContentHashProbe::begin();
        let launcher = NativeProgram::capture(&path).unwrap();
        let pin = launcher.pin().unwrap();
        let displaced = path.with_file_name("original");
        std::fs::rename(&path, &displaced).unwrap();
        assert!(matches!(
            launcher.pin_for_path(&path),
            Err(super::super::Error::Io(_))
        ));
        std::os::unix::fs::symlink(&displaced, &path).unwrap();
        assert!(launcher.pin_for_path(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::copy(&displaced, &path).unwrap();
        assert_ne!(
            iroha_fs::FileIdentity::of(&std::fs::File::open(&path).unwrap()).unwrap(),
            launcher.original.identity().unwrap()
        );
        assert!(
            launcher.pin_for_path(&path).is_err(),
            "equal bytes in a different inode cannot reuse"
        );
        assert_eq!(hashes.count(), 1);
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&displaced, &path).unwrap();
        assert!(
            launcher.pin_for_path(&path).is_err(),
            "leaf rename changed the saved snapshot"
        );
        let restored = NativeProgram::matching(&pin).unwrap();
        assert_eq!(restored.pin_for_path(&path).unwrap().blake3, pin.blake3);
        assert_eq!(hashes.count(), 2);
        let parent = path.parent().unwrap();
        let displaced_parent = temporary.path().join("original-parent");
        std::fs::rename(parent, &displaced_parent).unwrap();
        assert!(restored.pin_for_path(&path).is_err());
        std::fs::create_dir(parent).unwrap();
        std::fs::copy(displaced_parent.join(path.file_name().unwrap()), &path).unwrap();
        assert!(restored.pin_for_path(&path).is_err());
        assert_eq!(hashes.count(), 2);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(parent).unwrap();
        std::fs::rename(&displaced_parent, parent).unwrap();
        assert_eq!(restored.pin_for_path(&path).unwrap().blake3, pin.blake3);
        assert_eq!(
            hashes.count(),
            2,
            "the same unchanged file and ancestor regain custody"
        );
    }

    #[cfg(windows)]
    #[test]
    fn current_program_path_keeps_native_writer_and_replacement_denial_and_original_retry() {
        let _resources = super::super::native_test_guard();
        let (_temporary, path) = copied_native_program();
        let hashes = ContentHashProbe::begin();
        let launcher = NativeProgram::capture(&path).unwrap();
        let pin = launcher.pin().unwrap();
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::rename(&path, path.with_file_name("displaced.exe")).is_err());
        assert_eq!(launcher.pin_for_path(&path).unwrap().blake3, pin.blake3);
        assert_eq!(hashes.count(), 1);
        drop(launcher);
        let displaced = path.with_file_name("displaced.exe");
        std::fs::rename(&path, &displaced).unwrap();
        std::fs::rename(&displaced, &path).unwrap();
        let restored = NativeProgram::matching(&pin).unwrap();
        assert_eq!(restored.pin_for_path(&path).unwrap().blake3, pin.blake3);
        assert_eq!(hashes.count(), 2);
    }
}
