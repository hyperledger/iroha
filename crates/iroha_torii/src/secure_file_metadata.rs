//! Stable filesystem metadata snapshots for security-sensitive path checks.

#[cfg(unix)]
mod unix {
    use std::{
        fs::{self, File, OpenOptions},
        io,
        ops::Deref,
        os::unix::fs::OpenOptionsExt as _,
        path::Path,
    };

    /// Standard metadata with a retained handle that pins the sampled filesystem object.
    #[derive(Debug)]
    pub struct SecureMetadata {
        metadata: fs::Metadata,
        _identity_handle: File,
    }

    impl Deref for SecureMetadata {
        type Target = fs::Metadata;

        fn deref(&self) -> &Self::Target {
            &self.metadata
        }
    }

    pub fn from_file(file: &File) -> io::Result<SecureMetadata> {
        Ok(SecureMetadata {
            metadata: file.metadata()?,
            _identity_handle: file.try_clone()?,
        })
    }

    pub fn from_path(path: &Path) -> io::Result<SecureMetadata> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(path)?;
        Ok(SecureMetadata {
            metadata: file.metadata()?,
            _identity_handle: file,
        })
    }
}

#[cfg(unix)]
pub use unix::{SecureMetadata, from_file, from_path};

#[cfg(not(any(unix, windows)))]
use std::{fs, io, path::Path};

#[cfg(not(any(unix, windows)))]
pub(crate) type SecureMetadata = fs::Metadata;

#[cfg(not(any(unix, windows)))]
pub(crate) fn from_file(file: &fs::File) -> io::Result<SecureMetadata> {
    file.metadata()
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn from_path(path: &Path) -> io::Result<SecureMetadata> {
    fs::symlink_metadata(path)
}

#[cfg(unix)]
pub fn same_file(left: &SecureMetadata, right: &SecureMetadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
pub(crate) fn same_file(left: &SecureMetadata, right: &SecureMetadata) -> bool {
    left.same_file(right)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn same_file(_left: &SecureMetadata, _right: &SecureMetadata) -> bool {
    false
}

#[cfg(unix)]
pub fn unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    same_file(left, right)
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
        && left.mode() == right.mode()
}

#[cfg(windows)]
pub(crate) fn unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
    left.unchanged(right)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn unchanged(_left: &SecureMetadata, _right: &SecureMetadata) -> bool {
    false
}

#[cfg(unix)]
pub fn is_direct_file(metadata: &SecureMetadata) -> bool {
    !metadata.file_type().is_symlink() && metadata.file_type().is_file()
}

#[cfg(windows)]
pub(crate) fn is_direct_file(metadata: &SecureMetadata) -> bool {
    metadata.is_direct_file()
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn is_direct_file(_metadata: &SecureMetadata) -> bool {
    false
}

#[cfg(unix)]
pub fn is_direct_directory(metadata: &SecureMetadata) -> bool {
    !metadata.file_type().is_symlink() && metadata.file_type().is_dir()
}

#[cfg(windows)]
pub(crate) fn is_direct_directory(metadata: &SecureMetadata) -> bool {
    metadata.is_direct_directory()
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn is_direct_directory(_metadata: &SecureMetadata) -> bool {
    false
}

#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the shared platform API represents unavailable link counts as None"
)]
pub fn number_of_links(metadata: &SecureMetadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;

    Some(metadata.nlink())
}

#[cfg(windows)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the shared platform API represents unavailable link counts as None"
)]
pub(crate) fn number_of_links(metadata: &SecureMetadata) -> Option<u64> {
    Some(u64::from(metadata.number_of_links()))
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn number_of_links(_metadata: &SecureMetadata) -> Option<u64> {
    None
}

#[cfg(windows)]
mod windows {
    #![allow(unsafe_code)]

    use std::{
        ffi::{OsStr, OsString, c_void},
        fs::{self, File, OpenOptions},
        io,
        mem::{MaybeUninit, offset_of, size_of},
        ops::Deref,
        os::windows::{ffi::OsStringExt as _, fs::OpenOptionsExt as _, io::AsRawHandle as _},
        path::Path,
        ptr,
    };

    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ_DELETE: u32 = 0x0000_0001 | 0x0000_0004;
    const FILE_SHARE_READ_WRITE_DELETE: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_ID_BOTH_DIRECTORY_INFO: i32 = 10;
    const FILE_ID_BOTH_DIRECTORY_RESTART_INFO: i32 = 11;
    const ERROR_NO_MORE_FILES: i32 = 18;
    const DIRECTORY_BUFFER_BYTES: usize = 64 * 1024;

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        _last_access_time: FileTime,
        last_write_time: FileTime,
        _volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        _file_index_high: u32,
        _file_index_low: u32,
    }

    const _: () = assert!(std::mem::size_of::<ByHandleFileInformation>() == 52);
    const _: () = assert!(std::mem::align_of::<ByHandleFileInformation>() == 4);

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FileId128 {
        identifier: [u8; 16],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FileIdInformation {
        volume_serial_number: u64,
        file_id: FileId128,
    }

    const _: () = assert!(std::mem::size_of::<FileIdInformation>() == 24);
    const _: () = assert!(std::mem::align_of::<FileIdInformation>() == 8);

    const FILE_ID_INFO: i32 = 18;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FileIdBothDirectoryInfo {
        next_entry_offset: u32,
        _file_index: u32,
        _creation_time: i64,
        _last_access_time: i64,
        _last_write_time: i64,
        _change_time: i64,
        _end_of_file: i64,
        _allocation_size: i64,
        _file_attributes: u32,
        file_name_length: u32,
        _ea_size: u32,
        _short_name_length: i8,
        _short_name: [u16; 12],
        _file_id: i64,
        file_name: [u16; 1],
    }

    const _: () = assert!(size_of::<FileIdBothDirectoryInfo>() == 112);
    const _: () = assert!(std::mem::align_of::<FileIdBothDirectoryInfo>() == 8);
    const _: () = assert!(offset_of!(FileIdBothDirectoryInfo, _file_id) == 96);
    const _: () = assert!(offset_of!(FileIdBothDirectoryInfo, file_name) == 104);

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "GetFileInformationByHandle"]
        fn get_file_information_by_handle(
            file: *mut c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;

        #[link_name = "GetFileInformationByHandleEx"]
        fn get_file_information_by_handle_ex(
            file: *mut c_void,
            information_class: i32,
            information: *mut c_void,
            information_size: u32,
        ) -> i32;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FileIdentity {
        volume_serial_number: u64,
        identifier: [u8; 16],
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_write_time: FileTime,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        identity: FileIdentity,
    }

    impl FileInformation {
        const fn is_direct_file(self) -> bool {
            self.file_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) == 0
        }

        const fn is_direct_directory(self) -> bool {
            self.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
                && self.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        }

        fn same_file(self, other: Self) -> bool {
            self.identity == other.identity
        }
    }

    fn identity(file: &File) -> io::Result<FileIdentity> {
        let mut raw = MaybeUninit::<FileIdInformation>::uninit();
        // SAFETY: `file` owns a valid handle and `raw` is the exact writable output buffer
        // documented for the `FileIdInfo` information class.
        let succeeded = unsafe {
            get_file_information_by_handle_ex(
                file.as_raw_handle().cast(),
                FILE_ID_INFO,
                raw.as_mut_ptr().cast(),
                u32::try_from(std::mem::size_of::<FileIdInformation>())
                    .expect("FILE_ID_INFO size fits u32"),
            )
        };
        if succeeded == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful `GetFileInformationByHandleEx` call initialized the buffer.
        let raw = unsafe { raw.assume_init() };
        Ok(FileIdentity {
            volume_serial_number: raw.volume_serial_number,
            identifier: raw.file_id.identifier,
        })
    }

    fn information(file: &File) -> io::Result<FileInformation> {
        let mut raw = MaybeUninit::<ByHandleFileInformation>::uninit();
        // SAFETY: `file` owns a valid handle and `raw` points to writable storage with the
        // documented `BY_HANDLE_FILE_INFORMATION` layout.
        let succeeded = unsafe {
            get_file_information_by_handle(file.as_raw_handle().cast(), raw.as_mut_ptr())
        };
        if succeeded == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful `GetFileInformationByHandle` call initializes the entire output.
        let raw = unsafe { raw.assume_init() };
        Ok(FileInformation {
            file_attributes: raw.file_attributes,
            creation_time: raw.creation_time,
            last_write_time: raw.last_write_time,
            file_size_high: raw.file_size_high,
            file_size_low: raw.file_size_low,
            number_of_links: raw.number_of_links,
            identity: identity(file)?,
        })
    }

    /// Standard metadata bound to stable Win32 identity, revision, and link fields.
    #[derive(Debug)]
    pub(crate) struct SecureMetadata {
        metadata: fs::Metadata,
        information: FileInformation,
        // Keep the sampled object alive so its file identifier cannot be recycled before a
        // subsequent snapshot is compared with it. Every pathname handle is opened with delete
        // sharing, so retaining it does not prevent a legitimate atomic replacement.
        _identity_handle: File,
    }

    impl SecureMetadata {
        pub(super) fn same_file(&self, other: &Self) -> bool {
            self.information.same_file(other.information)
        }

        pub(super) fn unchanged(&self, other: &Self) -> bool {
            self.information == other.information
        }

        pub(super) const fn is_direct_file(&self) -> bool {
            self.information.is_direct_file()
        }

        pub(super) const fn is_direct_directory(&self) -> bool {
            self.information.is_direct_directory()
        }

        pub(super) const fn number_of_links(&self) -> u32 {
            self.information.number_of_links
        }
    }

    impl Deref for SecureMetadata {
        type Target = fs::Metadata;

        fn deref(&self) -> &Self::Target {
            &self.metadata
        }
    }

    fn sample(file: &File) -> io::Result<(fs::Metadata, FileInformation)> {
        let information_before = information(file)?;
        let metadata = file.metadata()?;
        let information_after = information(file)?;
        if information_before != information_after {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file metadata changed while it was sampled",
            ));
        }
        Ok((metadata, information_after))
    }

    pub(crate) fn from_file(file: &File) -> io::Result<SecureMetadata> {
        let (metadata, information) = sample(file)?;
        Ok(SecureMetadata {
            metadata,
            information,
            _identity_handle: file.try_clone()?,
        })
    }

    pub(crate) fn from_path(path: &Path) -> io::Result<SecureMetadata> {
        let file = OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ_WRITE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let (metadata, information) = sample(&file)?;
        Ok(SecureMetadata {
            metadata,
            information,
            _identity_handle: file,
        })
    }

    pub(crate) fn open_direct_file(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            // Deny write sharing for the complete lifetime of bounded reads. Delete sharing
            // remains enabled so a pathname replacement is observable instead of merely blocked.
            .share_mode(FILE_SHARE_READ_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    /// Incremental, retained-handle directory enumeration with delete sharing.
    pub(crate) struct DirectDirectoryEntryStream {
        _directory: File,
        storage: Vec<usize>,
        next_offset: Option<usize>,
        restart: bool,
        exhausted: bool,
    }

    impl DirectDirectoryEntryStream {
        pub(crate) fn open(path: &Path) -> io::Result<Self> {
            let named_before = from_path(path)?;
            if !named_before.is_direct_directory() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory stream path is not a direct directory",
                ));
            }
            let directory = OpenOptions::new()
                .access_mode(GENERIC_READ)
                // Enumeration must not delay a legitimate POSIX-semantics unlink. Identity is
                // requalified against a short namespace pin at each higher-level scan step.
                .share_mode(FILE_SHARE_READ_WRITE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)?;
            sorafs_node::validate_private_local_storage_acl(&directory, path)?;
            let opened = from_file(&directory)?;
            let named_after = from_path(path)?;
            if !opened.is_direct_directory()
                || !named_after.is_direct_directory()
                || !named_before.same_file(&opened)
                || !opened.same_file(&named_after)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory changed while its retained enumeration handle was opened",
                ));
            }
            Ok(Self {
                _directory: directory,
                storage: vec![0; DIRECTORY_BUFFER_BYTES.div_ceil(size_of::<usize>())],
                next_offset: None,
                restart: true,
                exhausted: false,
            })
        }

        pub(crate) fn next_name(&mut self) -> io::Result<Option<OsString>> {
            loop {
                if self.next_offset.is_none() && !self.load_batch()? {
                    return Ok(None);
                }
                let offset = self
                    .next_offset
                    .expect("a successful directory batch has a first entry");
                let (name, next_offset) = parse_directory_entry(self.bytes(), offset)?;
                self.next_offset = next_offset;
                if name != OsStr::new(".") && name != OsStr::new("..") {
                    return Ok(Some(name));
                }
            }
        }

        fn load_batch(&mut self) -> io::Result<bool> {
            if self.exhausted {
                return Ok(false);
            }
            self.storage.fill(0);
            let information_class = if self.restart {
                FILE_ID_BOTH_DIRECTORY_RESTART_INFO
            } else {
                FILE_ID_BOTH_DIRECTORY_INFO
            };
            // SAFETY: the retained handle is a direct directory opened for enumeration and the
            // aligned storage is writable for exactly DIRECTORY_BUFFER_BYTES.
            let succeeded = unsafe {
                get_file_information_by_handle_ex(
                    self._directory.as_raw_handle().cast(),
                    information_class,
                    self.storage.as_mut_ptr().cast(),
                    u32::try_from(DIRECTORY_BUFFER_BYTES).expect("directory buffer fits u32"),
                )
            };
            if succeeded == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_NO_MORE_FILES) {
                    self.exhausted = true;
                    return Ok(false);
                }
                return Err(error);
            }
            self.restart = false;
            self.next_offset = Some(0);
            Ok(true)
        }

        fn bytes(&self) -> &[u8] {
            // SAFETY: the usize allocation contains exactly the zeroed/kernel-initialized bytes
            // advertised to GetFileInformationByHandleEx and remains live for the returned borrow.
            unsafe {
                std::slice::from_raw_parts(
                    self.storage.as_ptr().cast::<u8>(),
                    DIRECTORY_BUFFER_BYTES,
                )
            }
        }
    }

    fn parse_directory_entry(
        buffer: &[u8],
        offset: usize,
    ) -> io::Result<(OsString, Option<usize>)> {
        let file_name_offset = offset_of!(FileIdBothDirectoryInfo, file_name);
        let header_end = offset.checked_add(file_name_offset).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "directory offset overflow")
        })?;
        let fixed_end = offset
            .checked_add(size_of::<FileIdBothDirectoryInfo>())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "directory entry size overflow")
            })?;
        if header_end > buffer.len() || fixed_end > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "directory entry header exceeds its kernel buffer",
            ));
        }
        // SAFETY: the complete fixed record is in `buffer`; unaligned access avoids assumptions
        // about the kernel's packed chain offsets.
        let entry = unsafe {
            ptr::read_unaligned(
                buffer
                    .as_ptr()
                    .add(offset)
                    .cast::<FileIdBothDirectoryInfo>(),
            )
        };
        let name_bytes = usize::try_from(entry.file_name_length).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "directory entry name length exceeds usize",
            )
        })?;
        if name_bytes % size_of::<u16>() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "directory entry name has an odd byte length",
            ));
        }
        let name_end = header_end.checked_add(name_bytes).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "directory entry name length overflow",
            )
        })?;
        if name_end > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "directory entry name exceeds its kernel buffer",
            ));
        }
        let unit_count = name_bytes / size_of::<u16>();
        let mut units = Vec::with_capacity(unit_count);
        for position in 0..unit_count {
            // SAFETY: every two-byte unit ends at or before the validated `name_end`.
            units.push(unsafe {
                ptr::read_unaligned(
                    buffer
                        .as_ptr()
                        .add(header_end + position * size_of::<u16>())
                        .cast::<u16>(),
                )
            });
        }
        let next_offset = if entry.next_entry_offset == 0 {
            None
        } else {
            let relative = usize::try_from(entry.next_entry_offset).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory next-entry offset exceeds usize",
                )
            })?;
            let consumed = file_name_offset.checked_add(name_bytes).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory entry length overflow",
                )
            })?;
            if relative < consumed {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory next-entry offset overlaps its current entry",
                ));
            }
            let absolute = offset.checked_add(relative).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory next-entry offset overflow",
                )
            })?;
            if absolute >= buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory next-entry offset exceeds its kernel buffer",
                ));
            }
            Some(absolute)
        };
        Ok((OsString::from_wide(&units), next_offset))
    }
}

#[cfg(windows)]
pub(crate) use windows::{
    DirectDirectoryEntryStream, SecureMetadata, from_file, from_path, open_direct_file,
};

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use std::{fs, io::Write as _};

    use super::*;

    #[test]
    fn snapshots_bind_path_and_handle_to_one_object() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("record.bin");
        fs::write(&path, b"stable").expect("write record");
        let file = fs::File::open(&path).expect("open record");

        let named = from_path(&path).expect("snapshot named record");
        let opened = from_file(&file).expect("snapshot opened record");

        assert!(is_direct_file(&named));
        assert!(same_file(&named, &opened));
        assert!(unchanged(&named, &opened));
        assert_eq!(number_of_links(&opened), Some(1));
        assert!(is_direct_directory(
            &from_path(directory.path()).expect("snapshot directory")
        ));
    }

    #[test]
    fn retained_snapshot_rejects_an_equal_length_replacement() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("record.bin");
        let displaced = directory.path().join("record.displaced.bin");
        fs::write(&path, b"same-length").expect("write original record");
        let original = from_path(&path).expect("snapshot original record");

        fs::rename(&path, &displaced).expect("displace original record");
        fs::write(&path, b"same-length").expect("write replacement record");
        let replacement = from_path(&path).expect("snapshot replacement record");

        assert!(!same_file(&original, &replacement));
        assert!(!unchanged(&original, &replacement));
    }

    #[test]
    fn revision_snapshot_detects_in_place_length_change() {
        let mut file = tempfile::NamedTempFile::new().expect("create temporary file");
        file.write_all(b"before").expect("write initial bytes");
        file.flush().expect("flush initial bytes");
        let before = from_file(file.as_file()).expect("snapshot original revision");

        file.write_all(b"-after").expect("extend temporary file");
        file.flush().expect("flush extended bytes");
        let after = from_file(file.as_file()).expect("snapshot changed revision");

        assert!(same_file(&before, &after));
        assert!(!unchanged(&before, &after));
    }

    #[test]
    fn link_count_snapshot_tracks_hard_links() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("record.bin");
        let link = directory.path().join("record.link.bin");
        let renamed = directory.path().join("record.renamed.bin");
        fs::write(&path, b"linked").expect("write record");
        let before = from_path(&path).expect("snapshot unlinked record");
        fs::hard_link(&path, &link).expect("create hard link");
        let after = from_path(&path).expect("snapshot linked record");
        let alias = from_path(&link).expect("snapshot hard-link alias");
        fs::rename(&path, &renamed).expect("rename original hard link");
        let after_rename = from_path(&renamed).expect("snapshot renamed record");

        assert_eq!(number_of_links(&before), Some(1));
        assert_eq!(number_of_links(&after), Some(2));
        assert!(same_file(&before, &after));
        assert!(same_file(&after, &alias));
        assert!(same_file(&after, &after_rename));
        assert!(!unchanged(&before, &after));
    }
}
