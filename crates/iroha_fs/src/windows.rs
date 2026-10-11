//! Windows retained-handle custody and current-user security attributes.
//!
//! Mutable handles use `FILE_FLAG_WRITE_THROUGH`: NTFS flushes metadata changes (including
//! rename) caused by these requests. File bytes additionally pass `FlushFileBuffers` before
//! publication. Ancestor handles omit delete sharing, preventing rename/reparse replacement.
//! The supported private store filesystem is NTFS; a different filesystem fails closed.
#![allow(
    unsafe_code,
    reason = "native Win32 handles, ACL inspection and retained-handle rename require FFI"
)]

use super::*;
use std::{
    borrow::Borrow,
    ffi::c_void,
    io::Write as _,
    mem::{offset_of, size_of},
    os::windows::{
        ffi::OsStrExt as _,
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    },
    path::Prefix,
    ptr::{from_mut, from_ref, null_mut},
    sync::Arc,
};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_TOKEN, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_FILE_OBJECT,
        },
        CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetSecurityDescriptorControl, GetTokenInformation, OWNER_SECURITY_INFORMATION, PSID,
        SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER,
        TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    },
    Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_APPEND_DATA,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO, FILE_DELETE_CHILD,
        FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_WRITE_THROUGH, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
        FILE_WRITE_ATTRIBUTES, FileBasicInfo, FileDispositionInfo, FileIdInfo, FileRenameInfo,
        FileStandardInfo, GetFileInformationByHandleEx, GetVolumeInformationByHandleW, OPEN_ALWAYS,
        OPEN_EXISTING, READ_CONTROL, SetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
    },
    System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
        PROCESS_QUERY_LIMITED_INFORMATION,
    },
};

#[derive(Debug)]
struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: every instance owns one pointer allocated by a Win32 LocalAlloc API.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn native_size<T>() -> io::Result<u32> {
    u32::try_from(size_of::<T>()).map_err(|_| invalid("native structure size overflow"))
}

fn win_ok(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut result: Vec<_> = value.encode_wide().collect();
    if result.contains(&0) {
        return Err(invalid("native path contains NUL"));
    }
    result.push(0);
    Ok(result)
}

struct UserSid {
    storage: Vec<usize>,
}
impl UserSid {
    fn current() -> io::Result<Self> {
        let mut token = null_mut();
        // SAFETY: output is valid; pseudo handles remain owned by the operating system.
        unsafe {
            if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_NO_TOKEN.cast_signed()) {
                    return Err(error);
                }
                win_ok(OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY,
                    &raw mut token,
                ))?;
            }
        }
        // SAFETY: token was returned as one owned valid handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        Self::from_token(&token)
    }
    fn from_token(token: &OwnedHandle) -> io::Result<Self> {
        let mut bytes = 0u32;
        // SAFETY: zero buffer is the documented size-query form.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                null_mut(),
                0,
                &raw mut bytes,
            );
        }
        if bytes == 0 || bytes > 4096 {
            return Err(denied("invalid native token size"));
        }
        let mut storage = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
        // SAFETY: naturally aligned allocation covers the exact requested byte length.
        unsafe {
            win_ok(GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                storage.as_mut_ptr().cast(),
                bytes,
                &raw mut bytes,
            ))?;
        }
        Ok(Self { storage })
    }
    fn pointer(&self) -> PSID {
        // SAFETY: GetTokenInformation populated TOKEN_USER in retained aligned storage.
        unsafe { (*self.storage.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
    fn equals(&self, other: PSID) -> bool {
        // SAFETY: caller's SID is retained inside a GetSecurityInfo allocation or valid ACE.
        !other.is_null() && unsafe { EqualSid(self.pointer(), other) != 0 }
    }
}

/// Check the process token's user against the caller's effective Windows user.
///
/// Obtain `pid` from the connected named-pipe kernel endpoint, never from a peer's request.
/// A process disappearing or refusing token inspection is an error, never an accepted owner.
///
/// # Errors
/// Returns an error if either effective user token cannot be queried.
pub fn is_current_user_process(pid: u32) -> io::Result<bool> {
    let user = UserSid::current()?;
    // SAFETY: this requests only token-query authority and returns an owned process handle.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful native call returned exactly one owned handle.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut token = null_mut();
    // SAFETY: the process remains open and the output is a valid handle slot.
    unsafe {
        win_ok(OpenProcessToken(
            process.as_raw_handle(),
            TOKEN_QUERY,
            &raw mut token,
        ))?;
    }
    // SAFETY: OpenProcessToken returned exactly one owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    Ok(user.equals(UserSid::from_token(&token)?.pointer()))
}

fn is_system_sid(sid: PSID) -> bool {
    if sid.is_null() {
        return false;
    }
    [WinLocalSystemSid, WinBuiltinAdministratorsSid]
        .into_iter()
        .any(|kind| {
            let mut storage =
                [0usize; (SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<usize>())];
            let mut length = SECURITY_MAX_SID_SIZE;
            // SAFETY: aligned buffer covers the maximum SID size; both SIDs are retained.
            unsafe {
                CreateWellKnownSid(
                    kind,
                    null_mut(),
                    storage.as_mut_ptr().cast(),
                    &raw mut length,
                ) != 0
                    && EqualSid(sid, storage.as_mut_ptr().cast()) != 0
            }
        })
}

/// Call a native creation API with an explicit current-user owner and protected user-only DACL.
///
/// The callback receives a `SECURITY_ATTRIBUTES` pointer, suitable for Tokio's
/// `create_with_security_attributes_raw`. It must not retain or use the pointer after returning.
/// Handles created with these attributes are non-inheritable unless explicitly duplicated later.
///
/// # Errors
/// Returns an error if the current token or protected security descriptor cannot be constructed.
pub fn with_owner_security_attributes<R>(
    operation: impl FnOnce(*mut c_void) -> R,
) -> io::Result<R> {
    let user = UserSid::current()?;
    let mut sid_text = null_mut();
    // SAFETY: user SID is valid and retained; API allocates the output.
    unsafe {
        win_ok(ConvertSidToStringSidW(user.pointer(), &raw mut sid_text))?;
    }
    let _sid_allocation = LocalAllocation(sid_text.cast());
    let mut length = 0;
    // SAFETY: ConvertSidToStringSidW returns a terminated wide SID string.
    unsafe {
        while *sid_text.add(length) != 0 {
            length += 1;
        }
    }
    // SAFETY: measured initialized UTF-16 string excludes its terminator.
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, length) })
        .map_err(|_| invalid("native SID text is invalid"))?;
    let sddl = wide(OsStr::new(&format!("O:{sid}D:P(A;OICI;FA;;;{sid})")))?;
    let mut descriptor = null_mut();
    // SAFETY: terminated input, output is an owned self-relative descriptor.
    unsafe {
        win_ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &raw mut descriptor,
            null_mut(),
        ))?;
    }
    let _descriptor_allocation = LocalAllocation(descriptor);
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: native_size::<SECURITY_ATTRIBUTES>()?,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    Ok(operation(from_mut(&mut attributes).cast()))
}

fn validate_acl(file: &File, private: bool, directory: bool) -> io::Result<()> {
    let user = UserSid::current()?;
    let mut owner = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: output addresses and file handle remain valid for the call.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    let _allocation = LocalAllocation(descriptor);
    if !user.equals(owner) && (private || !is_system_sid(owner)) {
        return Err(denied("native object has foreign ownership"));
    }
    if dacl.is_null() {
        return Err(denied("unrestricted native DACL is not admitted"));
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: descriptor is retained and outputs are initialized scalars.
    unsafe {
        win_ok(GetSecurityDescriptorControl(
            descriptor,
            &raw mut control,
            &raw mut revision,
        ))?;
    }
    if private && control & SE_DACL_PROTECTED == 0 {
        return Err(denied(
            "private native DACL must be protected from inheritance",
        ));
    }
    // SAFETY: GetSecurityInfo returned a valid ACL.
    let count = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(count) {
        let mut ace = null_mut();
        // SAFETY: index is bounded by ACL count, returned ACE lives inside retained descriptor.
        unsafe {
            win_ok(GetAce(dacl, index, &raw mut ace))?;
        }
        // SAFETY: every ACE begins with ACE_HEADER.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags & 8 != 0 {
            continue;
        } // INHERIT_ONLY_ACE grants no rights here.
        if header.AceType == 1 {
            continue;
        } // A denied ACE cannot grant authority.
        if header.AceType != 0 || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
            return Err(denied("unsupported native access-control entry"));
        }
        // SAFETY: checked ACE type and minimum layout; SID starts at SidStart.
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = from_ref(&allowed.SidStart).cast_mut().cast();
        if user.equals(sid) || (!private && is_system_sid(sid)) {
            continue;
        }
        // Ancestors may permit creating a new child, but cannot grant deletion or control of
        // existing children. Every selected child is independently opened and pinned.
        let mutations = DELETE
            | WRITE_DAC
            | WRITE_OWNER
            | FILE_DELETE_CHILD
            | FILE_WRITE_ATTRIBUTES
            | 0x1000_0000
            | GENERIC_WRITE
            | if directory { 2 | 16 } else { 2 | 4 | 16 };
        if private || allowed.Mask & mutations != 0 {
            return Err(denied("native object grants another principal access"));
        }
    }
    Ok(())
}

fn info<T: Default>(file: &File, class: i32) -> io::Result<T> {
    let mut value = T::default();
    // SAFETY: each caller pairs a concrete Win32 structure with its information class.
    unsafe {
        win_ok(GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            from_mut(&mut value).cast(),
            native_size::<T>()?,
        ))?;
    }
    Ok(value)
}

pub(super) fn identity(file: &File) -> io::Result<FileIdentity> {
    let value: FILE_ID_INFO = info(file, FileIdInfo)?;
    Ok(FileIdentity {
        volume: value.VolumeSerialNumber,
        object: value.FileId.Identifier,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snapshot {
    id: FileIdentity,
    length: u64,
    modified: i64,
    changed: i64,
    attributes: u32,
    links: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileSnapshot(Snapshot);

impl FileSnapshot {
    pub(super) fn local_parts(self) -> LocalFileSnapshot {
        (
            2,
            (self.0.id.volume, self.0.id.object),
            self.0.length,
            [u64::from(self.0.attributes), u64::from(self.0.links), 0, 0],
            [self.0.modified, 0],
            [self.0.changed, 0],
        )
    }
}

pub(super) fn journal_snapshot(file: &File) -> io::Result<FileSnapshot> {
    let value = snapshot(file, true, false)?;
    if value.attributes & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY != 0 {
        return Err(denied("private journal is read-only"));
    }
    Ok(FileSnapshot(value))
}
pub(super) fn validate_public_original(file: &File) -> io::Result<()> {
    snapshot(file, false, false).map(|_| ())
}
impl Directory {
    pub(super) fn snapshot_directory(&self) -> io::Result<FileSnapshot> {
        self.revalidate()?;
        snapshot(&self.current().file, false, true).map(FileSnapshot)
    }
}

pub(super) fn snapshot_file(file: &File, private: bool) -> io::Result<FileSnapshot> {
    snapshot(file, private, false).map(FileSnapshot)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkPolicy {
    Single,
    BuildInput,
}

fn snapshot(file: &File, private: bool, directory: bool) -> io::Result<Snapshot> {
    snapshot_with_links(file, private, directory, LinkPolicy::Single)
}

fn snapshot_with_links(
    file: &File,
    private: bool,
    directory: bool,
    links: LinkPolicy,
) -> io::Result<Snapshot> {
    let basic: FILE_BASIC_INFO = info(file, FileBasicInfo)?;
    let standard: FILE_STANDARD_INFO = info(file, FileStandardInfo)?;
    if basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || standard.DeletePending
        || (!directory
            && (standard.NumberOfLinks == 0
                || (links == LinkPolicy::Single && standard.NumberOfLinks != 1)))
    {
        return Err(denied(
            "native object is a reparse point, has shared links, or has the wrong type",
        ));
    }
    validate_acl(file, private, directory)?;
    Ok(Snapshot {
        id: identity(file)?,
        length: u64::try_from(standard.EndOfFile)
            .map_err(|_| invalid("invalid native file length"))?,
        modified: basic.LastWriteTime,
        changed: basic.ChangeTime,
        attributes: basic.FileAttributes,
        // Directory snapshots retain their existing semantics; only file link custody varies.
        links: if directory { 0 } else { standard.NumberOfLinks },
    })
}

fn named_file_matches(
    named: Snapshot,
    after: Snapshot,
    expected: FileIdentity,
    links: LinkPolicy,
) -> bool {
    named.id == expected && (links == LinkPolicy::Single || named == after)
}

fn open_file(
    path: &Path,
    access: u32,
    share: u32,
    disposition: u32,
    directory: bool,
    private_creation: bool,
) -> io::Result<File> {
    let path = wide(path.as_os_str())?;
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        }
        | if access & (GENERIC_WRITE | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | DELETE) != 0 {
            FILE_FLAG_WRITE_THROUGH
        } else {
            0
        };
    let create = |attributes: *mut c_void| {
        // SAFETY: path and optional security attributes are live for this call.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                access | READ_CONTROL,
                share,
                attributes.cast(),
                disposition,
                flags,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: one newly acquired owned handle is transferred into File.
            Ok(unsafe { File::from_raw_handle(handle) })
        }
    };
    if private_creation {
        with_owner_security_attributes(create)?
    } else {
        create(null_mut())
    }
}

#[derive(Debug)]
struct Link {
    path: PathBuf,
    file: File,
    private: bool,
}

#[derive(Clone, Debug)]
pub(super) struct Directory {
    links: Vec<Arc<Link>>,
}

#[path = "windows/custody_io.rs"]
mod custody_io;
#[path = "windows/private_files.rs"]
mod private_files;

impl Directory {
    pub(super) fn open(path: &Path, create: bool) -> io::Result<Self> {
        Self::open_with_policy(path, create, true)
    }

    pub(super) fn open_owned(path: &Path, create: bool) -> io::Result<Self> {
        let mut directory = Self::open_with_policy(path, create, false)?;
        validate_current_owner(&directory.current().file)?;
        let previous = directory.links.pop().ok_or_else(changed)?;
        let file = open_file(
            &previous.path,
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            true,
            false,
        )?;
        if identity(&file)? != identity(&previous.file)? {
            return Err(changed());
        }
        directory.links.push(Arc::new(Link {
            path: previous.path.clone(),
            file,
            private: false,
        }));
        directory.revalidate()?;
        Ok(directory)
    }

    pub(super) fn open_reader(path: &Path) -> io::Result<Self> {
        Self::open_with_policy(path, false, false)
    }

    pub(super) fn identity(&self) -> io::Result<FileIdentity> {
        identity(&self.current().file)
    }

    pub(super) fn entries(&self, maximum: usize) -> io::Result<Vec<std::ffi::OsString>> {
        self.revalidate()?;
        self.entries_native(maximum, |mut names| {
            self.revalidate()?;
            names.sort();
            Ok(names)
        })
    }

    // Consume the original census while its directory metadata and native owner remain live.
    pub(super) fn entries_native<T>(
        &self,
        maximum: usize,
        consume: impl FnOnce(Vec<std::ffi::OsString>) -> io::Result<T>,
    ) -> io::Result<T> {
        let before = snapshot(&self.current().file, self.current().private, true)?;
        let mut names = Vec::new();
        for entry in std::fs::read_dir(self.path())? {
            let name = entry?.file_name();
            checked_name(&name)?;
            if names.len() >= maximum {
                return Err(invalid("directory entry count exceeds the bound"));
            }
            names.push(name);
        }
        if before != snapshot(&self.current().file, self.current().private, true)? {
            return Err(changed());
        }
        consume(names)
    }

    fn open_with_policy(path: &Path, create: bool, private: bool) -> io::Result<Self> {
        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return Err(invalid("native drive path required"));
        };
        if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
            || !matches!(components.next(), Some(Component::RootDir))
        {
            return Err(invalid(
                "private stores require an absolute local drive path",
            ));
        }
        let mut current = PathBuf::from(prefix.as_os_str());
        current.push("\\");
        let root = open_file(
            &current,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            true,
            false,
        )?;
        snapshot(&root, false, true)?;
        let mut filesystem = [0u16; 32];
        // SAFETY: file-system-name output is bounded and all unused output pointers are null.
        unsafe {
            win_ok(GetVolumeInformationByHandleW(
                root.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                null_mut(),
                filesystem.as_mut_ptr(),
                32,
            ))?;
        }
        let length = filesystem
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(filesystem.len());
        if String::from_utf16_lossy(&filesystem[..length]) != "NTFS" {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "private native custody requires NTFS",
            ));
        }
        let mut links = vec![Arc::new(Link {
            path: current.clone(),
            file: root,
            private: false,
        })];
        let parts: Vec<_> = components.collect();
        if parts.is_empty() && private {
            return Err(denied("drive root cannot be a private store"));
        }
        for (index, part) in parts.iter().enumerate() {
            let name = match part {
                Component::Normal(name) => checked_name(name)?,
                Component::CurDir => continue,
                _ => return Err(invalid("normal native components required")),
            };
            current.push(name);
            let final_private = private && index + 1 == parts.len();
            let mut created = false;
            let mut file = open_file(
                &current,
                FILE_READ_ATTRIBUTES
                    | if final_private {
                        FILE_WRITE_ATTRIBUTES
                    } else {
                        0
                    },
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                OPEN_EXISTING,
                true,
                false,
            );
            if matches!(&file, Err(error) if error.kind() == io::ErrorKind::NotFound) && create {
                create_directory(&current)?;
                created = true;
                file = open_file(
                    &current,
                    FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    OPEN_EXISTING,
                    true,
                    false,
                );
            }
            let file = file?;
            snapshot(&file, final_private || created, true)?;
            if created {
                sync_directory_metadata(&file)?;
            }
            links.push(Arc::new(Link {
                path: current.clone(),
                file,
                private: final_private || created,
            }));
        }
        let result = Self { links };
        result.revalidate()?;
        Ok(result)
    }

    fn current(&self) -> &Link {
        self.links.last().expect("directory retains root")
    }
    pub(super) fn path(&self) -> &Path {
        &self.current().path
    }
    pub(super) fn revalidate(&self) -> io::Result<()> {
        self.revalidate_from(0)
    }

    // Only a strict descendant with this complete shared native chain omits the prefix.
    // Independently opened or unrelated owners retain their original full validation.
    pub(super) fn revalidate_in_tree(&self, anchor: &Self) -> io::Result<()> {
        let first = if self.links.len() > anchor.links.len()
            && self
                .links
                .iter()
                .zip(&anchor.links)
                .all(|(descendant, ancestor)| Arc::ptr_eq(descendant, ancestor))
        {
            anchor.links.len()
        } else {
            0
        };
        self.revalidate_from(first)
    }

    fn revalidate_from(&self, first: usize) -> io::Result<()> {
        for link in self.links.iter().skip(first) {
            let held = snapshot(&link.file, link.private, true)?;
            let named = open_file(
                &link.path,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                OPEN_EXISTING,
                true,
                false,
            )?;
            if held.id != snapshot(&named, link.private, true)?.id {
                return Err(changed());
            }
        }
        Ok(())
    }

    pub(super) fn child_reader(&self, name: &OsStr) -> io::Result<Self> {
        self.revalidate()?;
        let path = self.path().join(name);
        let file = open_file(
            &path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            true,
            false,
        )?;
        snapshot(&file, false, true)?;
        let mut links = self.links.clone();
        if links.len() >= 128 {
            return Err(invalid("private directory depth bound exceeded"));
        }
        links.push(Arc::new(Link {
            path,
            file,
            private: false,
        }));
        let result = Self { links };
        result.revalidate()?;
        Ok(result)
    }

    pub(super) fn child(&self, name: &OsStr, create: bool, exclusive: bool) -> io::Result<Self> {
        self.child_policy(name, create, exclusive, true)
    }

    pub(super) fn child_owned(
        &self,
        name: &OsStr,
        create: bool,
        exclusive: bool,
    ) -> io::Result<Self> {
        self.child_policy(name, create, exclusive, false)
    }

    fn child_policy(
        &self,
        name: &OsStr,
        create: bool,
        exclusive: bool,
        private: bool,
    ) -> io::Result<Self> {
        match self.child_admission(name, create, exclusive, private)? {
            NativeChildOutcome::Present(child) => Ok(child),
            NativeChildOutcome::InitialAbsence(error) => Err(error),
        }
    }

    pub(super) fn child_optional(&self, name: &OsStr) -> io::Result<Option<Self>> {
        let result = match self.child_admission(name, false, false, true) {
            // The admitted child already closed its complete retained ancestry.
            Ok(NativeChildOutcome::Present(child)) => return Ok(Some(child)),
            Ok(NativeChildOutcome::InitialAbsence(_)) => Ok(None),
            Err(error) => Err(error),
        };
        // No body failure or initial absence may skip the original parent exit.
        if let Err(error) = self.revalidate() {
            drop(result);
            return Err(error);
        }
        result
    }

    fn child_admission(
        &self,
        name: &OsStr,
        create: bool,
        exclusive: bool,
        private: bool,
    ) -> io::Result<NativeChildOutcome<Self>> {
        self.revalidate()?;
        let path = self.path().join(name);
        if create {
            match create_directory(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists && !exclusive => {}
                Err(error) => return Err(error),
            }
        }
        let file = match open_file(
            &path,
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            true,
            false,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(NativeChildOutcome::InitialAbsence(error));
            }
            Err(error) => return Err(error),
        };
        snapshot(&file, private, true)?;
        validate_current_owner(&file)?;
        sync_directory_metadata(&file)?;
        let mut links = self.links.clone();
        if links.len() >= 128 {
            return Err(invalid("private directory depth bound exceeded"));
        }
        links.push(Arc::new(Link {
            path,
            file,
            private,
        }));
        let result = Self { links };
        result.revalidate()?;
        Ok(NativeChildOutcome::Present(result))
    }

    pub(super) fn open_readonly(&self, name: &OsStr) -> io::Result<File> {
        self.revalidate()?;
        let file = self
            .open_readonly_native(name, false)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        self.revalidate()?;
        Ok(file)
    }

    // Sole original readonly-open admission, with no ancestry observation. Only the initial
    // native opener may yield optional absence; named admission and final-name errors remain errors.
    pub(super) fn open_readonly_native(
        &self,
        name: &OsStr,
        optional: bool,
    ) -> io::Result<Option<File>> {
        let file = match open_file(
            &self.path().join(name),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            false,
            false,
        ) {
            Ok(file) => file,
            Err(error) if optional && error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        snapshot(&file, true, false)?;
        Ok(Some(file))
    }

    pub(super) fn open_retained(
        &self,
        name: &OsStr,
        private: bool,
        create_new: bool,
    ) -> io::Result<RetainedFile> {
        RetainedFile::open(self.clone(), name.to_owned(), private, create_new)
    }

    pub(super) fn open_build_input(&self, name: &OsStr) -> io::Result<RetainedFile> {
        RetainedFile::open_build_input(self.clone(), name.to_owned())
    }

    pub(super) fn read(
        &self,
        name: &OsStr,
        maximum: usize,
        private: bool,
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        self.revalidate()?;
        self.read_native(name, maximum, private, |bytes| {
            self.revalidate()?;
            Ok(bytes)
        })
    }

    pub(super) fn read_optional(
        &self,
        name: &OsStr,
        maximum: usize,
        private: bool,
    ) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        self.revalidate()?;
        let mut exit_checked = false;
        let result = checked_name(name).and_then(|name| {
            self.read_optional_native(name, maximum, private, |bytes| {
                exit_checked = true;
                self.revalidate()?;
                Ok(bytes)
            })
        });
        if !exit_checked {
            self.revalidate()?;
        }
        result
    }

    // Required admission over the sole native leaf recipe. Initial absence retains the
    // original native error; file/snapshot owners remain live through the internal consumer.
    // No consumer or file descriptor is exposed by the closed public comparison API.
    pub(super) fn read_native<T>(
        &self,
        name: &OsStr,
        maximum: usize,
        private: bool,
        consume: impl FnOnce(Zeroizing<Vec<u8>>) -> io::Result<T>,
    ) -> io::Result<T> {
        match self.read_leaf_native(name, maximum, private, consume)? {
            NativeReadOutcome::InitialAbsence(error) => Err(error),
            NativeReadOutcome::Present(value) => Ok(value),
        }
    }

    pub(super) fn read_optional_native<T>(
        &self,
        name: &OsStr,
        maximum: usize,
        private: bool,
        consume: impl FnOnce(Zeroizing<Vec<u8>>) -> io::Result<T>,
    ) -> io::Result<Option<T>> {
        match self.read_leaf_native(name, maximum, private, consume)? {
            NativeReadOutcome::InitialAbsence(_) => Ok(None),
            NativeReadOutcome::Present(value) => Ok(Some(value)),
        }
    }

    // Sole leaf recipe: every error after the first open remains a native refusal.
    // Its original held/named owners stay live through the internal consumer.
    fn read_leaf_native<T>(
        &self,
        name: &OsStr,
        maximum: usize,
        private: bool,
        consume: impl FnOnce(Zeroizing<Vec<u8>>) -> io::Result<T>,
    ) -> io::Result<NativeReadOutcome<T>> {
        let mut file = match open_file(
            &self.path().join(name),
            GENERIC_READ,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            false,
            false,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(NativeReadOutcome::InitialAbsence(error));
            }
            Err(error) => return Err(error),
        };
        let before = snapshot(&file, private, false)?;
        let bytes = bounded_read(&mut file, before.length, maximum)?;
        if before != snapshot(&file, private, false)? {
            return Err(changed());
        }
        consume(bytes).map(NativeReadOutcome::Present)
    }

    pub(super) fn write_atomic(
        &self,
        name: &OsStr,
        bytes: &[u8],
        mode: PublishMode,
        private_destination: bool,
    ) -> io::Result<()> {
        self.revalidate()?;
        let destination = self.path().join(name);
        if mode == PublishMode::Replace {
            match open_file(
                &destination,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                OPEN_EXISTING,
                false,
                false,
            ) {
                Ok(file) => {
                    snapshot(&file, private_destination, false)?;
                    validate_current_owner(&file)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let (temporary, mut file) = (0..128)
            .find_map(|_| {
                let path = self.path().join(temporary_name());
                match open_file(
                    &path,
                    GENERIC_READ | GENERIC_WRITE | DELETE,
                    FILE_SHARE_READ,
                    CREATE_NEW,
                    false,
                    true,
                ) {
                    Ok(file) => Some(Ok((path, file))),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .unwrap_or_else(|| {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "private staging names exhausted",
                ))
            })?;
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            let staged = snapshot(&file, true, false)?;
            self.revalidate()?;
            rename_handle(&file, &destination, mode)?;
            file.sync_all()?;
            if staged.id != snapshot(&file, true, false)?.id {
                return Err(changed());
            }
            self.sync()
        })();
        if result.is_err() {
            // The retained source handle prevents path substitution until it is closed. A
            // failed post-rename sync deliberately leaves the destination for reconciliation.
            let same = open_file(
                &temporary,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ
                    | FILE_SHARE_WRITE
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE,
                OPEN_EXISTING,
                false,
                false,
            )
            .and_then(|named| identity(&named))
            .ok()
            .zip(identity(&file).ok())
            .is_some_and(|(named, retained)| named == retained);
            drop(file);
            if same {
                let _ = std::fs::remove_file(&temporary);
            }
        }
        result
    }

    pub(super) fn open_mutable(&self, name: &OsStr, append: bool) -> io::Result<File> {
        self.revalidate()?;
        let access = if append {
            GENERIC_READ | FILE_APPEND_DATA
        } else {
            GENERIC_READ | GENERIC_WRITE
        };
        let file = open_file(
            &self.path().join(name),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_ALWAYS,
            false,
            true,
        )?;
        snapshot(&file, true, false)?;
        // An append-only handle cannot request GENERIC_WRITE solely for FlushFileBuffers;
        // write-through already enforces every append's durability on this native handle.
        if !append {
            file.sync_all()?;
        }
        self.sync()?;
        Ok(file)
    }

    pub(super) fn open_exact_lock(&self, name: &OsStr, create_new: bool) -> io::Result<File> {
        self.revalidate()?;
        let file = open_file(
            &self.path().join(name),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            if create_new {
                CREATE_NEW
            } else {
                OPEN_EXISTING
            },
            false,
            true,
        )?;
        snapshot(&file, true, false)?;
        if create_new {
            file.sync_all()?;
            self.sync()?;
        }
        self.revalidate()?;
        Ok(file)
    }

    pub(super) fn remove_empty(mut self) -> io::Result<()> {
        self.revalidate()?;
        if self.links.len() < 2 {
            return Err(denied("filesystem root cannot be removed"));
        }
        if Arc::strong_count(self.links.last().ok_or_else(changed)?) != 1 {
            return Err(denied("directory removal has live descendant handles"));
        }
        let current =
            Arc::try_unwrap(self.links.pop().ok_or_else(changed)?).map_err(|_| changed())?;
        let id = identity(&current.file)?;
        // Keep the original object alive while transferring namespace custody to a DELETE
        // handle. A substitution cannot recycle that identity while this handle is retained.
        let retained = open_file(
            &current.path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            true,
            false,
        )?;
        if identity(&retained)? != id {
            return Err(changed());
        }
        let Link {
            path,
            file,
            private,
        } = current;
        drop(file);
        let removing = open_file(
            &path,
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            true,
            false,
        )?;
        if identity(&removing)? != id {
            return Err(changed());
        }
        snapshot(&removing, private, true)?;
        self.revalidate()?;
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: disposition addresses the exact retained no-reparse directory. Windows
        // refuses a nonempty directory; no recursive or path-based deletion occurs.
        unsafe {
            win_ok(SetFileInformationByHandle(
                removing.as_raw_handle(),
                FileDispositionInfo,
                from_ref(&disposition).cast(),
                native_size::<FILE_DISPOSITION_INFO>()?,
            ))?;
        }
        drop(removing);
        drop(retained);
        self.sync()
    }

    pub(super) fn open_ownership_lock(&self, name: &OsStr) -> io::Result<File> {
        self.revalidate()?;
        // The write-sharing fence belongs to the kernel file object. Unlike LockFileEx's
        // process lock, it remains effective through inherited duplicates after our exit.
        // Metadata-only readers can still validate the preserved name during reset.
        let file = open_file(
            &self.path().join(name),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            OPEN_ALWAYS,
            false,
            true,
        )
        .map_err(|error| {
            if error.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION.cast_signed())
            {
                io::Error::from(io::ErrorKind::WouldBlock)
            } else {
                error
            }
        })?;
        snapshot(&file, true, false)?;
        file.sync_all()?;
        self.sync()?;
        Ok(file)
    }

    pub(super) fn sync(&self) -> io::Result<()> {
        self.revalidate()?;
        sync_directory_metadata(&self.current().file)
    }

    pub(super) fn rename_to_sibling(mut self, name: &OsStr, mode: PublishMode) -> io::Result<Self> {
        if mode != PublishMode::CreateNew {
            return Err(invalid(
                "directory publication requires an absent destination",
            ));
        }
        self.revalidate()?;
        if self.links.len() < 2 {
            return Err(denied("filesystem root cannot be published"));
        }
        if Arc::strong_count(self.links.last().ok_or_else(changed)?) != 1 {
            return Err(denied("directory publication has live descendant handles"));
        }
        let current = self.links.pop().ok_or_else(changed)?;
        let current = Arc::try_unwrap(current).map_err(|_| changed())?;
        let parent = self.links.last().ok_or_else(changed)?;
        let id = identity(&current.file)?;
        // Retain the exact original object throughout the change from a namespace pin to
        // DELETE authority. A competing rename may fail this operation, but can never make
        // it publish a different object: the original ID cannot be recycled while retained.
        let retained = open_file(
            &current.path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            true,
            false,
        )?;
        if identity(&retained)? != id {
            return Err(changed());
        }
        let Link {
            path,
            file,
            private,
        } = current;
        drop(file);
        let publishing = open_file(
            &path,
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            true,
            false,
        )?;
        if identity(&publishing)? != id {
            return Err(changed());
        }
        snapshot(&publishing, private, true)?;
        let destination = parent.path.join(name);
        rename_handle(&publishing, &destination, mode)?;
        sync_directory_metadata(&publishing)?;
        // DELETE authority is needed only for publication. Returning that handle would
        // conflict with ordinary readers that exclude delete sharing while traversing this
        // directory. The original read-only handle stays live through this transition, so
        // the final namespace pin must still name the same original native object.
        drop(publishing);
        let published = open_file(
            &destination,
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            true,
            false,
        )?;
        if identity(&published)? != id {
            return Err(changed());
        }
        snapshot(&published, private, true)?;
        self.links.push(Arc::new(Link {
            path: destination,
            file: published,
            private,
        }));
        self.revalidate()?;
        Ok(self)
    }

    // The public removal bracket owns full entry and every-result exit custody.
    pub(super) fn remove_private_native(&self, name: &OsStr) -> io::Result<bool> {
        let path = self.path().join(name);
        let file = match open_file(
            &path,
            GENERIC_READ | DELETE,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            false,
            false,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let before = journal_snapshot(&file)?;
        self.revalidate()?;
        // This observer permits the original handle's DELETE access, without acquiring
        // write or delete authority itself. The original excludes replacement sharing.
        let named = open_file(
            &path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            false,
            false,
        )?;
        if journal_snapshot(&file)? != before || journal_snapshot(&named)? != before {
            return Err(changed());
        }
        drop(named);
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: this exact no-reparse private regular single-link file owns DELETE
        // access and excludes write/delete sharing; no pathname deletion is performed.
        unsafe {
            win_ok(SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                from_ref(&disposition).cast(),
                native_size::<FILE_DISPOSITION_INFO>()?,
            ))?;
        }
        drop(file);
        sync_directory_metadata(&self.current().file)?;
        Ok(true)
    }

    pub(super) fn reconcile_atomic_staging(
        &self,
        required: &[&str],
        maximum_staged: usize,
        maximum_bytes: usize,
    ) -> io::Result<usize> {
        let maximum_entries = required.len() + maximum_staged;
        let names = self.entries(maximum_entries)?;
        validate_atomic_staging_inventory(&names, required, maximum_staged)?;
        let mut retained = Vec::with_capacity(names.len());
        for name in &names {
            let staged = is_atomic_staging_name(name);
            let file = open_file(
                &self.path().join(name),
                GENERIC_READ | if staged { DELETE } else { 0 },
                FILE_SHARE_READ | if staged { 0 } else { FILE_SHARE_WRITE },
                OPEN_EXISTING,
                false,
                false,
            )?;
            let before = journal_snapshot(&file)?;
            if staged && before.0.length > maximum_bytes as u64 {
                return Err(invalid("atomic staging extent exceeds the bound"));
            }
            retained.push((file, before, staged));
        }
        // Staging handles exclude both write and delete sharing. Required files exclude
        // delete sharing and permit the caller's already-owned read/write lock descriptor.
        if self.entries(maximum_entries)? != names {
            return Err(changed());
        }
        for (file, before, _) in &retained {
            if journal_snapshot(file)? != *before {
                return Err(changed());
            }
        }
        let mut committed = Vec::with_capacity(required.len());
        let mut removed = 0;
        for (file, before, staged) in retained {
            if staged {
                self.revalidate()?;
                if journal_snapshot(&file)? != before {
                    return Err(changed());
                }
                let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
                // SAFETY: the retained no-reparse private file owns DELETE access and
                // excludes delete sharing; disposition targets that exact opened object.
                unsafe {
                    win_ok(SetFileInformationByHandle(
                        file.as_raw_handle(),
                        FileDispositionInfo,
                        from_ref(&disposition).cast(),
                        native_size::<FILE_DISPOSITION_INFO>()?,
                    ))?;
                }
                drop(file);
                removed += 1;
            } else {
                committed.push((file, before));
            }
        }
        self.sync()?;
        validate_atomic_staging_inventory(&self.entries(required.len())?, required, 0)?;
        for (file, before) in committed {
            if journal_snapshot(&file)? != before {
                return Err(changed());
            }
        }
        Ok(removed)
    }

    pub(super) fn clear_contents_preserving(&self, preserved: &[&OsStr]) -> io::Result<()> {
        self.revalidate()?;
        for name in preserved {
            let file = open_file(
                &self.path().join(name),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                OPEN_EXISTING,
                false,
                false,
            )?;
            snapshot(&file, true, false)?;
        }
        self.clear(
            &self.current().file,
            self.path(),
            preserved,
            0,
            &mut 100_000,
        )?;
        self.sync()
    }

    fn clear(
        &self,
        parent: &File,
        path: &Path,
        preserved: &[&OsStr],
        depth: usize,
        remaining: &mut usize,
    ) -> io::Result<()> {
        if depth >= 128 {
            return Err(invalid("private removal depth bound exceeded"));
        }
        let parent_id = identity(parent)?;
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name();
            if preserved.contains(&name.as_os_str()) {
                continue;
            }
            checked_name(&name)?;
            *remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| invalid("private removal entry bound exceeded"))?;
            self.revalidate()?;
            if identity(parent)? != parent_id {
                return Err(changed());
            }
            let file = open_file(
                &path.join(&name),
                GENERIC_READ | FILE_WRITE_ATTRIBUTES | DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                OPEN_EXISTING,
                true,
                false,
            )?;
            let standard: FILE_STANDARD_INFO = info(&file, FileStandardInfo)?;
            let directory = standard.Directory;
            snapshot(&file, false, directory)?;
            validate_current_owner(&file)?;
            if directory {
                self.clear(&file, &path.join(&name), &[], depth + 1, remaining)?;
            }
            self.revalidate()?;
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            // SAFETY: the opened no-reparse object retains DELETE authority and excludes
            // delete sharing. Deletion targets this retained identity, never a reopened path.
            unsafe {
                win_ok(SetFileInformationByHandle(
                    file.as_raw_handle(),
                    FileDispositionInfo,
                    from_ref(&disposition).cast(),
                    native_size::<FILE_DISPOSITION_INFO>()?,
                ))?;
            }
            drop(file);
        }
        sync_directory_metadata(parent)
    }
}

#[derive(Debug)]
pub(super) struct RetainedFile<D = Directory, N = std::ffi::OsString> {
    directory: D,
    name: N,
    file: File,
    before: Snapshot,
    links: LinkPolicy,
    private: bool,
    writable: bool,
    read_only: bool,
    publishable: bool,
}

impl<D: Borrow<Directory>, N: AsRef<OsStr>> RetainedFile<D, N> {
    fn open(directory: D, name: N, private: bool, create_new: bool) -> io::Result<Self> {
        Self::open_with_links(directory, name, private, create_new, LinkPolicy::Single)
    }

    fn open_build_input(directory: D, name: N) -> io::Result<Self> {
        Self::open_with_links(directory, name, false, false, LinkPolicy::BuildInput)
    }

    fn open_with_links(
        directory: D,
        name: N,
        private: bool,
        create_new: bool,
        links: LinkPolicy,
    ) -> io::Result<Self> {
        let parent = directory.borrow();
        parent.revalidate()?;
        let file = open_file(
            &parent.path().join(name.as_ref()),
            GENERIC_READ
                | if create_new {
                    GENERIC_WRITE | WRITE_DAC | DELETE
                } else {
                    0
                },
            FILE_SHARE_READ,
            if create_new {
                CREATE_NEW
            } else {
                OPEN_EXISTING
            },
            false,
            create_new,
        )?;
        let before = snapshot_with_links(&file, private || create_new, false, links)?;
        let retained = Self {
            directory,
            name,
            file,
            before,
            links,
            private: private || create_new,
            writable: create_new,
            read_only: false,
            publishable: create_new,
        };
        retained.revalidate()?;
        if create_new {
            retained.file.sync_all()?;
            retained.directory.borrow().sync()?;
        }
        Ok(retained)
    }

    pub(super) fn snapshot(&self) -> io::Result<FileSnapshot> {
        self.revalidate()?;
        let value = FileSnapshot(snapshot_with_links(
            &self.file,
            self.private,
            false,
            self.links,
        )?);
        self.revalidate()?;
        Ok(value)
    }
    pub(super) fn seal(mut self) -> io::Result<Self> {
        self.file.sync_all()?;
        self.revalidate()?;
        self.before = snapshot_with_links(&self.file, self.private, false, self.links)?;
        self.writable = false;
        self.directory.borrow().sync()?;
        Ok(self)
    }
    pub(super) fn file(&self) -> &File {
        &self.file
    }
    pub(super) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    pub(super) fn identity(&self) -> io::Result<FileIdentity> {
        if identity(&self.file)? != self.before.id {
            return Err(changed());
        }
        Ok(self.before.id)
    }
    pub(super) fn revalidate(&self) -> io::Result<()> {
        self.directory.borrow().revalidate()?;
        let after = snapshot_with_links(&self.file, self.private, false, self.links)?;
        if self.read_only {
            private_files::validate_read_only(&self.file)?;
        }
        if after.id != self.before.id || (!self.writable && after != self.before) {
            return Err(changed());
        }
        let named = open_file(
            &self.directory.borrow().path().join(self.name.as_ref()),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            false,
            false,
        )?;
        let named_snapshot = snapshot_with_links(&named, self.private, false, self.links)?;
        if !named_file_matches(named_snapshot, after, self.before.id, self.links) {
            return Err(changed());
        }
        self.directory.borrow().revalidate()
    }
}

fn validate_current_owner(file: &File) -> io::Result<()> {
    let mut owner = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: the descriptor allocation and SID are owned until after comparison.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    let _allocation = LocalAllocation(descriptor);
    if !UserSid::current()?.equals(owner) {
        return Err(denied("removal entry has foreign ownership"));
    }
    Ok(())
}

fn create_directory(path: &Path) -> io::Result<()> {
    let path = wide(path.as_os_str())?;
    with_owner_security_attributes(|attributes| {
        // SAFETY: terminated path and descriptor remain alive through creation.
        unsafe { win_ok(CreateDirectoryW(path.as_ptr(), attributes.cast())) }
    })?
}

fn sync_directory_metadata(file: &File) -> io::Result<()> {
    let mut basic: FILE_BASIC_INFO = info(file, FileBasicInfo)?;
    // NTFS metadata is flushed by a metadata-changing request on a write-through handle.
    // Preserve creation/access times and attributes; advance the directory write time by one
    // native tick so the request cannot be optimized into a no-op. Directory times are local
    // custody observations, never consensus inputs.
    basic.LastWriteTime = basic
        .LastWriteTime
        .checked_add(1)
        .ok_or_else(|| invalid("native directory timestamp exhausted"))?;
    basic.ChangeTime = 0;
    // SAFETY: the private directory handle has FILE_WRITE_ATTRIBUTES and WRITE_THROUGH.
    unsafe {
        win_ok(SetFileInformationByHandle(
            file.as_raw_handle(),
            FileBasicInfo,
            from_ref(&basic).cast(),
            native_size::<FILE_BASIC_INFO>()?,
        ))
    }
}

fn rename_handle(file: &File, destination: &Path, mode: PublishMode) -> io::Result<()> {
    let name = wide(destination.as_os_str())?;
    let name_bytes = (name.len() - 1)
        .checked_mul(2)
        .ok_or_else(|| invalid("native rename length overflow"))?;
    let bytes = offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(name_bytes)
        .ok_or_else(|| invalid("native rename length overflow"))?;
    let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    // SAFETY: aligned allocation contains the header and complete UTF-16 tail; the source
    // handle retains DELETE access, so source identity never relies on reopening a pathname.
    unsafe {
        let value = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        (*value).Anonymous.ReplaceIfExists = mode == PublishMode::Replace;
        (*value).RootDirectory = null_mut();
        (*value).FileNameLength =
            u32::try_from(name_bytes).map_err(|_| invalid("native rename path too long"))?;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            (*value).FileName.as_mut_ptr(),
            name.len() - 1,
        );
        win_ok(SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            value.cast(),
            u32::try_from(bytes).map_err(|_| invalid("native rename path too long"))?,
        ))
    }
}

pub(super) fn read_external(
    parent: &Path,
    name: &OsStr,
    maximum: usize,
    private: bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    Directory::open_with_policy(parent, false, false)?.read(name, maximum, private)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{
        Authorization::SetSecurityInfo, GetSecurityDescriptorDacl,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };

    fn set_dacl(file: &File, sddl: &str) {
        let encoded = wide(OsStr::new(sddl)).unwrap();
        let mut descriptor = null_mut();
        // SAFETY: terminated fixture SDDL and initialized output slot.
        unsafe {
            win_ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                encoded.as_ptr(),
                1,
                &raw mut descriptor,
                null_mut(),
            ))
            .unwrap();
        }
        let _allocation = LocalAllocation(descriptor);
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = null_mut();
        // SAFETY: all descriptor data remains allocated through the synchronous update.
        unsafe {
            win_ok(GetSecurityDescriptorDacl(
                descriptor,
                &raw mut present,
                &raw mut dacl,
                &raw mut defaulted,
            ))
            .unwrap();
            assert_ne!(present, 0);
            assert_eq!(
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    dacl,
                    null_mut()
                ),
                0
            );
        }
    }

    #[test]
    fn private_acl_refuses_even_read_only_everyone_grants() {
        let temporary = tempfile::tempdir().unwrap();
        let store = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
        store
            .write_atomic("key", b"secret", PublishMode::CreateNew)
            .unwrap();
        let file = open_file(
            &store.path().join("key"),
            FILE_READ_ATTRIBUTES | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            false,
            false,
        )
        .unwrap();
        set_dacl(&file, "D:P(A;;GR;;;WD)");
        assert!(store.read("key", 6).is_err());
        assert!(crate::read_regular(store.path().join("key"), 6).is_ok());
        set_dacl(&file, "D:P(A;;GA;;;WD)");
        assert!(crate::read_regular(store.path().join("key"), 6).is_err());
    }

    #[test]
    fn borrowed_sealed_custody_rejects_an_external_dacl_change() {
        let temporary = tempfile::tempdir().unwrap();
        let store = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
        let name = OsStr::new("receipt");
        let mut writer = store.create_borrowed_private(name, 16).unwrap();
        writer.write_all(b"original").unwrap();
        let acl_writer = open_file(
            &store.path().join(name),
            FILE_READ_ATTRIBUTES | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            false,
            false,
        )
        .unwrap();
        let sealed = writer.seal_read_only().unwrap();
        let reopened = store.open_borrowed_read_only(name, 16).unwrap();
        assert_eq!(sealed.snapshot().unwrap(), reopened.snapshot().unwrap());
        set_dacl(&acl_writer, "D:P(A;;GR;;;WD)");
        assert!(sealed.snapshot().is_err());
        assert!(sealed.revalidate().is_err());
        assert!(reopened.snapshot().is_err());
        assert!(reopened.revalidate().is_err());
        assert!(store.open_borrowed_read_only(name, 16).is_err());
        // Restore deletion rights for fixture cleanup after all invalid capabilities close.
        set_dacl(&acl_writer, "D:P(A;;GA;;;WD)");
    }

    #[test]
    fn inherited_handle_fence_survives_the_original_owner_handle() {
        let temporary = tempfile::tempdir().unwrap();
        let store = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
        let owner = store.open_ownership_lock("runtime.lock").unwrap();
        let inherited = owner.try_clone().unwrap();
        drop(owner);
        assert!(store.open_ownership_lock("runtime.lock").is_err());
        store.clear_contents_preserving(&["runtime.lock"]).unwrap();
        drop(inherited);
        assert!(store.open_ownership_lock("runtime.lock").is_ok());
    }
}

#[cfg(test)]
mod build_input_snapshot_tests {
    use super::*;

    #[test]
    fn build_input_final_named_join_refuses_first_observed_link_or_metadata_changes() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("cargo-program");
        std::fs::write(&path, b"native snapshot fixture").unwrap();
        std::fs::hard_link(&path, temporary.path().join("cargo-dependency")).unwrap();
        let directory = Directory::open_reader(temporary.path()).unwrap();
        let original = directory
            .open_build_input(OsStr::new("cargo-program"))
            .unwrap();
        // Real native admission establishes the held full snapshot before a later named read.
        let after = original.before;
        assert_eq!(after.links, 2);
        assert!(named_file_matches(
            after,
            after,
            after.id,
            LinkPolicy::BuildInput
        ));
        let mut late_link = after;
        late_link.links += 1;
        assert!(!named_file_matches(
            late_link,
            after,
            after.id,
            LinkPolicy::BuildInput
        ));
        let mut late_content = after;
        late_content.length += 1;
        assert!(!named_file_matches(
            late_content,
            after,
            after.id,
            LinkPolicy::BuildInput
        ));
        let mut late_metadata = after;
        late_metadata.changed += 1;
        assert!(!named_file_matches(
            late_metadata,
            after,
            after.id,
            LinkPolicy::BuildInput
        ));
        let mut replaced = after;
        replaced.id.object[0] ^= 1;
        for policy in [LinkPolicy::Single, LinkPolicy::BuildInput] {
            assert!(!named_file_matches(replaced, after, after.id, policy));
        }
        // Strict owners keep their prior final ID join after their separate single-link
        // admission. Only build inputs need the additional full named-to-held equality.
        assert!(named_file_matches(
            late_content,
            after,
            after.id,
            LinkPolicy::Single
        ));
        original.revalidate().unwrap();
    }
}

#[cfg(test)]
mod private_child_parent_sharing_tests {
    use super::*;

    #[test]
    fn private_child_adds_one_handle_and_shares_the_complete_original_parent_chain() {
        let temporary = tempfile::tempdir().unwrap();
        let nested = temporary.path().join("one/two/three");
        std::fs::create_dir_all(&nested).unwrap();
        let parent = crate::OwnerDirectory::open(&nested).unwrap();
        let original = parent.create_private_child("journal").unwrap();
        let identity = original.identity().unwrap();
        drop(original);
        let depth = parent.inner.links.len();
        for optional in [false, true] {
            let child = if optional {
                parent
                    .open_private_child_optional("journal")
                    .unwrap()
                    .unwrap()
            } else {
                parent.open_private_child("journal").unwrap()
            };
            assert_eq!(child.identity().unwrap(), identity);
            assert_eq!(child.inner.links.len(), depth + 1);
            assert!(
                parent
                    .inner
                    .links
                    .iter()
                    .zip(&child.inner.links)
                    .all(|(parent, child)| Arc::ptr_eq(parent, child))
            );
            let shared = parent
                .inner
                .links
                .iter()
                .chain(&child.inner.links)
                .map(|link| Arc::as_ptr(link) as usize)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(shared.len(), depth + 1);
            // The old absolute selection holds a separate File for every prefix component.
            let reopened = crate::PrivateDirectory::open(child.path()).unwrap();
            assert_eq!(reopened.identity().unwrap(), identity);
            assert!(
                parent
                    .inner
                    .links
                    .iter()
                    .zip(&reopened.inner.links)
                    .all(|(parent, child)| !Arc::ptr_eq(parent, child))
            );
            let duplicated = parent
                .inner
                .links
                .iter()
                .chain(&reopened.inner.links)
                .map(|link| Arc::as_ptr(link) as usize)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(duplicated.len(), 2 * depth + 1);
        }
    }
}
