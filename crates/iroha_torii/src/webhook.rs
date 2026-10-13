//! Minimal webhook registry for the app-facing API with disk persistence and
//! a background delivery worker.
//!
//! Feature-gated behind `app_api`:
//! - Stores webhooks in-memory, persisted to `./storage/torii/webhooks.json` by default.
//!   Base directory is configured via `torii.data_dir`; tests may use `data_dir::OverrideGuard`.
//!   The versioned registry durably retains its ID high-water mark and an opaque
//!   generation for each registration so deleted IDs and queued deliveries are
//!   never inherited by a later registration.
//! - Exposes CRUD endpoints to create/list/delete webhooks.
//! - Background worker scans a disk-backed queue and delivers payloads with
//!   optional HMAC-SHA256 signature and exponential backoff retries. Queue
//!   admission, spool records, decoded bodies, and each scan batch have hard
//!   bounds so a large or adversarial queue cannot grow worker memory without
//!   limit.
//! - Durable webhook storage is supported on Apple and Linux hosts, where Torii
//!   can pin directories and enforce owner-private files. Enabling webhooks on
//!   other hosts fails startup instead of falling back to pathname-only storage.
//! - HTTPS delivery is supported when the `app_api_https` feature is enabled,
//!   using `reqwest` + `rustls` with native roots. WebSocket delivery requires
//!   `app_api_wss`; plain `http://` delivery is always available.
//!
//! Endpoints (wired in `lib.rs` when `app_api` is enabled):
//! - POST `/v1/webhooks` – Create a webhook.
//! - GET  `/v1/webhooks` – List webhooks.
//! - DELETE `/v1/webhooks/{id}` – Delete a webhook by id.
use crate::filter::filter_expr_to_value;
use axum::{
    extract::Path as AxumPath,
    http::{HeaderName, HeaderValue, StatusCode},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use core::{convert::TryFrom, str::FromStr};
use iroha_config::parameters::defaults;
use iroha_data_model::{events::data::prelude as df, prelude::DataEvent};
use iroha_futures::supervisor::ShutdownSignal;
use sha2::{Digest, Sha256};
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
use std::ffi::{OsStr, OsString};
#[cfg(all(test, any(target_vendor = "apple", target_os = "linux")))]
use std::sync::atomic::{AtomicU32, Ordering};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::{NonZeroU32, NonZeroUsize},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[cfg(any(test, target_vendor = "apple", target_os = "linux"))]
use std::{
    fs,
    io::{Read as _, Write as _},
};
use url::{Host, Url};
const WEBHOOK_REGISTRY_MAX_ENTRIES: usize = 1_024;
const WEBHOOK_REGISTRY_MAX_BYTES: usize = 8 * 1024 * 1024;
const WEBHOOK_ENTRY_MAX_BYTES: usize = 64 * 1024;
const WEBHOOK_REGISTRY_FORMAT_VERSION: u64 = 1;
const WEBHOOK_GENERATION_BYTES: usize = 16;
const WEBHOOK_HTTP_RESPONSE_HEADER_MAX_BYTES: u64 = 64 * 1024;
const WEBHOOK_DNS_MAX_ADDRESSES: usize = 64;
// The configured capacity may be lowered, but never raises this process-level
// safety ceiling. This intentionally matches the shipped default.
const WEBHOOK_QUEUE_HARD_CAPACITY: usize = 10_000;
const WEBHOOK_DELIVERY_MAX_BYTES: usize = 1024 * 1024;
const WEBHOOK_DELIVERY_METADATA_MAX_BYTES: usize = 64 * 1024;
const WEBHOOK_DELIVERY_MAX_BASE64_BYTES: usize = WEBHOOK_DELIVERY_MAX_BYTES.div_ceil(3) * 4;
// A 1 MiB body expands to about 1.34 MiB in base64; leave bounded room for the
// delivery metadata while rejecting unexpectedly large on-disk records.
const WEBHOOK_QUEUE_FILE_MAX_BYTES: usize = 2 * 1024 * 1024;
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
const WEBHOOK_QUEUE_SCAN_BATCH_SIZE: usize = 128;
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
const WEBHOOK_QUEUE_SCAN_WORK_ITEMS: usize = 1024;
const WEBHOOK_QUEUE_ADMISSION_SCAN_WORK_ITEMS: usize = WEBHOOK_QUEUE_HARD_CAPACITY * 2;
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
const WEBHOOK_TEMP_FILE_RETRIES: usize = 32;
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::webhook::WebhookCreate")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
)]
pub struct WebhookCreate {
    pub url: String,
    pub secret: Option<String>,
    pub active: bool,
    /// Optional filter to match events for this webhook.
    /// Uses the same JSON DSL as app-facing APIs (see `crate::filter::FilterExpr`).
    pub filter: Option<crate::filter::FilterExpr>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::webhook::WebhookEntry")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
)]
pub struct WebhookEntry {
    pub id: u64,
    pub url: String,
    pub active: bool,
    pub secret: Option<String>,
    pub filter: Option<crate::filter::FilterExpr>,
}
#[derive(Clone)]
struct RegisteredWebhook {
    entry: WebhookEntry,
    generation: [u8; WEBHOOK_GENERATION_BYTES],
}
#[derive(Clone, Default)]
struct RegistryInner {
    next_id: u64,
    items: HashMap<u64, RegisteredWebhook>,
}
fn registry() -> &'static Mutex<RegistryInner> {
    static REG: OnceLock<Mutex<RegistryInner>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(RegistryInner::default()))
}
fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn lock_registry() -> std::sync::MutexGuard<'static, RegistryInner> {
    lock_unpoisoned(registry())
}
fn webhook_delivery_attempt_lock(webhook_id: u64) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<u64, Weak<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let mut locks = lock_unpoisoned(LOCKS.get_or_init(|| Mutex::new(HashMap::new())));
    locks.retain(|_, lock| lock.strong_count() != 0);
    if let Some(lock) = locks.get(&webhook_id).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(webhook_id, Arc::downgrade(&lock));
    lock
}
fn data_dir() -> PathBuf {
    crate::data_dir::base_dir()
}
#[cfg(all(test, any(target_vendor = "apple", target_os = "linux")))]
fn registry_path() -> PathBuf {
    data_dir().join("webhooks.json")
}
fn queue_dir() -> PathBuf {
    data_dir().join("queue")
}

struct WebhookDirectory {
    path: PathBuf,
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    file: fs::File,
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WebhookFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WebhookFileIdentity;

struct BoundedWebhookFile {
    bytes: Vec<u8>,
    identity: WebhookFileIdentity,
}

#[derive(Clone, Copy)]
enum WebhookPublication {
    CreateNew,
    Replace,
    ReplaceIdentity(WebhookFileIdentity),
}

#[cfg(target_vendor = "apple")]
#[allow(unsafe_code)]
mod webhook_acl {
    use std::{
        ffi::{c_int, c_void},
        fs, io,
        os::fd::AsRawFd as _,
        path::Path,
        ptr,
    };

    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: c_int = 0;
    const ACL_NEXT_ENTRY: c_int = -1;
    const ACL_EXTENDED_DENY: c_int = 2;
    type Acl = *mut c_void;
    type AclEntry = *mut c_void;

    unsafe extern "C" {
        fn acl_free(object: *mut c_void) -> c_int;
        fn acl_get_entry(acl: Acl, entry_id: c_int, entry: *mut AclEntry) -> c_int;
        fn acl_get_tag_type(entry: AclEntry, tag_type: *mut c_int) -> c_int;
        fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> Acl;
        fn acl_init(count: c_int) -> Acl;
        fn acl_set_fd_np(fd: c_int, acl: Acl, acl_type: c_int) -> c_int;
        fn acl_valid(acl: Acl) -> c_int;
    }

    struct AclGuard(Acl);

    impl Drop for AclGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: This guard exclusively owns the ACL object.
                unsafe {
                    acl_free(self.0);
                }
            }
        }
    }

    fn file_acl(file: &fs::File, path: &Path) -> io::Result<Option<AclGuard>> {
        // SAFETY: The descriptor remains live for the ACL query.
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(io::Error::new(
                    error.kind(),
                    format!(
                        "failed to inspect the macOS ACL for {}: {error}",
                        path.display()
                    ),
                ))
            };
        }
        let acl = AclGuard(acl);
        // SAFETY: The guard owns a live ACL object.
        if unsafe { acl_valid(acl.0) } != 0 {
            return Err(io::Error::other(format!(
                "invalid macOS ACL on {}: {}",
                path.display(),
                io::Error::last_os_error()
            )));
        }
        Ok(Some(acl))
    }

    fn entry_exhausted(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::InvalidInput
    }

    pub(super) fn validate_ancestor(file: &fs::File, path: &Path) -> io::Result<()> {
        let Some(acl) = file_acl(file, path)? else {
            return Ok(());
        };
        let mut entry_id = ACL_FIRST_ENTRY;
        loop {
            let mut entry = ptr::null_mut();
            // SAFETY: The ACL is live and `entry` is a valid out pointer.
            if unsafe { acl_get_entry(acl.0, entry_id, &raw mut entry) } == 0 {
                let mut tag_type = 0;
                // SAFETY: A successful lookup returned a live entry.
                if unsafe { acl_get_tag_type(entry, &raw mut tag_type) } != 0 {
                    return Err(io::Error::other(format!(
                        "failed to inspect the macOS ACL on {}: {}",
                        path.display(),
                        io::Error::last_os_error()
                    )));
                }
                if tag_type != ACL_EXTENDED_DENY {
                    return Err(invalid_acl(path));
                }
                entry_id = ACL_NEXT_ENTRY;
                continue;
            }
            let error = io::Error::last_os_error();
            return if entry_exhausted(&error) {
                Ok(())
            } else {
                Err(error)
            };
        }
    }

    pub(super) fn validate_private(file: &fs::File, path: &Path) -> io::Result<()> {
        let Some(acl) = file_acl(file, path)? else {
            return Ok(());
        };
        let mut entry = ptr::null_mut();
        // SAFETY: The ACL is live and `entry` is a valid out pointer.
        if unsafe { acl_get_entry(acl.0, ACL_FIRST_ENTRY, &raw mut entry) } == 0 {
            return Err(invalid_acl(path));
        }
        let error = io::Error::last_os_error();
        if entry_exhausted(&error) {
            Ok(())
        } else {
            Err(error)
        }
    }

    pub(super) fn clear_private(file: &fs::File, path: &Path) -> io::Result<()> {
        // SAFETY: Zero requests a valid ACL with no entries.
        let acl = unsafe { acl_init(0) };
        if acl.is_null() {
            return Err(io::Error::last_os_error());
        }
        let acl = AclGuard(acl);
        // SAFETY: The descriptor and initialized ACL remain live for the call.
        if unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0, ACL_TYPE_EXTENDED) } != 0 {
            return Err(io::Error::last_os_error());
        }
        validate_private(file, path)
    }

    fn invalid_acl(path: &Path) -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "webhook persistence object must not have an extended allow ACL: {}",
                path.display()
            ),
        )
    }
}

#[cfg(all(not(target_vendor = "apple"), target_os = "linux"))]
mod webhook_acl {
    use std::{fs, io, path::Path};

    pub(super) fn validate_ancestor(_file: &fs::File, _path: &Path) -> io::Result<()> {
        Ok(())
    }
    pub(super) fn validate_private(_file: &fs::File, _path: &Path) -> io::Result<()> {
        Ok(())
    }
    pub(super) fn clear_private(_file: &fs::File, _path: &Path) -> io::Result<()> {
        Ok(())
    }
}

fn invalid_webhook_storage(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn unsupported_webhook_persistence() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "durable webhook persistence is unavailable on this platform because Torii cannot enforce descriptor-bound owner-private storage",
    )
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn open_webhook_directory_chain(
    path: &Path,
    create: bool,
    private_final: bool,
) -> io::Result<Option<WebhookDirectory>> {
    use std::{os::unix::fs::MetadataExt as _, path::Component};

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut components = Vec::new();
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(component) => components.push(component.to_os_string()),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(invalid_webhook_storage(format!(
                    "webhook storage path must not contain parent-directory components: {}",
                    absolute.display()
                )));
            }
        }
    }
    if components.is_empty() {
        return Err(invalid_webhook_storage(
            "the filesystem root cannot be used as webhook storage",
        ));
    }
    let mut directory = fs::File::from(
        rustix::fs::open(
            Path::new("/"),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    webhook_acl::validate_ancestor(&directory, Path::new("/"))?;
    let effective_uid = rustix::process::geteuid().as_raw();
    let root_metadata = directory.metadata()?;
    if !root_metadata.is_dir()
        || (root_metadata.uid() != 0 && root_metadata.uid() != effective_uid)
        || root_metadata.mode() & 0o022 != 0
    {
        return Err(invalid_webhook_storage(
            "webhook filesystem root is not a trusted directory",
        ));
    }
    let component_count = components.len();
    let mut cursor = PathBuf::from("/");
    for (index, component) in components.into_iter().enumerate() {
        cursor.push(&component);
        let created = match rustix::fs::statat(
            &directory,
            &component,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => false,
            Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
            Err(rustix::io::Errno::NOENT) => {
                match rustix::fs::mkdirat(&directory, &component, rustix::fs::Mode::RWXU) {
                    Ok(()) => true,
                    Err(rustix::io::Errno::EXIST) => false,
                    Err(error) => return Err(io::Error::from(error)),
                }
            }
            Err(error) => return Err(io::Error::from(error)),
        };
        let before = rustix::fs::statat(
            &directory,
            &component,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        let current = directory.metadata()?;
        let file_type = rustix::fs::FileType::from_raw_mode(before.st_mode);
        // macOS exposes /var and /tmp as root-owned symlinks. Permit only such immutable
        // system aliases; user-owned or writable-parent symlinks remain fatal.
        let trusted_system_symlink = file_type == rustix::fs::FileType::Symlink
            && before.st_uid == 0
            && current.uid() == 0
            && current.mode() & 0o022 == 0;
        if file_type != rustix::fs::FileType::Directory && !trusted_system_symlink {
            return Err(invalid_webhook_storage(format!(
                "webhook storage ancestor is a non-directory or untrusted symlink: {}",
                cursor.display()
            )));
        }
        let mut flags = rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC;
        if !trusted_system_symlink {
            flags |= rustix::fs::OFlags::NOFOLLOW;
        }
        let next = fs::File::from(
            rustix::fs::openat(&directory, &component, flags, rustix::fs::Mode::empty())
                .map_err(io::Error::from)?,
        );
        if created {
            rustix::fs::fchmod(&next, rustix::fs::Mode::RWXU).map_err(io::Error::from)?;
            webhook_acl::clear_private(&next, &cursor)?;
            next.sync_all()?;
            directory.sync_all()?;
        }
        let opened = next.metadata()?;
        let after = rustix::fs::statat(
            &directory,
            &component,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        let trusted_owner = opened.uid() == 0 || opened.uid() == effective_uid;
        let trusted_sticky_root = opened.uid() == 0 && opened.mode() & 0o1000 != 0;
        let stable_name = before.st_dev == after.st_dev
            && before.st_ino == after.st_ino
            && rustix::fs::FileType::from_raw_mode(after.st_mode) == file_type;
        let opened_matches_name = trusted_system_symlink
            || (u64::try_from(before.st_dev).ok() == Some(opened.dev())
                && before.st_ino == opened.ino());
        if !opened.is_dir()
            || !trusted_owner
            || (opened.mode() & 0o022 != 0 && !trusted_sticky_root)
            || !stable_name
            || !opened_matches_name
        {
            return Err(invalid_webhook_storage(format!(
                "webhook storage ancestor is unsafe or changed while opening: {}",
                cursor.display()
            )));
        }
        if index + 1 == component_count {
            if opened.uid() != effective_uid {
                return Err(invalid_webhook_storage(format!(
                    "webhook storage directory must be owned by the current user: {}",
                    cursor.display()
                )));
            }
            if private_final && opened.mode() & 0o7777 != 0o700 {
                rustix::fs::fchmod(&next, rustix::fs::Mode::RWXU).map_err(io::Error::from)?;
                webhook_acl::clear_private(&next, &cursor)?;
                next.sync_all()?;
                let tightened = next.metadata()?;
                if tightened.uid() != effective_uid || tightened.mode() & 0o7777 != 0o700 {
                    return Err(invalid_webhook_storage(format!(
                        "webhook queue directory could not be made private: {}",
                        cursor.display()
                    )));
                }
            }
            if private_final {
                webhook_acl::validate_private(&next, &cursor)?;
            } else {
                webhook_acl::validate_ancestor(&next, &cursor)?;
            }
        } else {
            webhook_acl::validate_ancestor(&next, &cursor)?;
        }
        directory = next;
    }
    Ok(Some(WebhookDirectory {
        path: absolute,
        file: directory,
    }))
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn open_webhook_directory_chain(
    _path: &Path,
    _create: bool,
    _private_final: bool,
) -> io::Result<Option<WebhookDirectory>> {
    Err(unsupported_webhook_persistence())
}

fn open_webhook_data_directory(create: bool) -> io::Result<Option<WebhookDirectory>> {
    open_webhook_directory_chain(&data_dir(), create, false)
}

fn open_webhook_queue_directory(create: bool) -> io::Result<Option<WebhookDirectory>> {
    open_webhook_directory_chain(&queue_dir(), create, true)
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn filename_in_webhook_directory<'a>(
    directory: &WebhookDirectory,
    path: &'a Path,
) -> io::Result<&'a OsStr> {
    if path.parent() != Some(directory.path.as_path()) {
        return Err(invalid_webhook_storage(format!(
            "webhook persistence path escaped its pinned directory: {}",
            path.display()
        )));
    }
    path.file_name().ok_or_else(|| {
        invalid_webhook_storage(format!(
            "webhook persistence path has no file name: {}",
            path.display()
        ))
    })
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn webhook_identity_from_stat(
    stat: &rustix::fs::Stat,
    path: &Path,
) -> io::Result<WebhookFileIdentity> {
    Ok(WebhookFileIdentity {
        device: u64::try_from(stat.st_dev).map_err(|_| {
            invalid_webhook_storage(format!("invalid device identity for {}", path.display()))
        })?,
        inode: stat.st_ino,
    })
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn webhook_identity_from_metadata(metadata: &fs::Metadata) -> WebhookFileIdentity {
    use std::os::unix::fs::MetadataExt as _;
    WebhookFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn inspect_private_webhook_file(
    directory: &WebhookDirectory,
    name: &OsStr,
    maximum_bytes: Option<usize>,
) -> io::Result<Option<(rustix::fs::Stat, WebhookFileIdentity)>> {
    let path = directory.path.join(name);
    let stat =
        match rustix::fs::statat(&directory.file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(io::Error::from(error)),
        };
    let size = usize::try_from(stat.st_size).ok();
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || maximum_bytes.is_some_and(|maximum| size.is_none_or(|size| size > maximum))
    {
        return Err(invalid_webhook_storage(format!(
            "webhook persistence entry must be a private, owned, single-link bounded regular file: {}",
            path.display()
        )));
    }
    let identity = webhook_identity_from_stat(&stat, &path)?;
    let file = fs::File::from(
        rustix::fs::openat(
            &directory.file,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    if webhook_identity_from_metadata(&file.metadata()?) != identity {
        return Err(invalid_webhook_storage(format!(
            "webhook persistence entry changed while validating permissions: {}",
            path.display()
        )));
    }
    webhook_acl::validate_private(&file, &path)?;
    Ok(Some((stat, identity)))
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn read_private_webhook_file_bounded(
    directory: &WebhookDirectory,
    path: &Path,
    maximum_bytes: usize,
) -> io::Result<Option<BoundedWebhookFile>> {
    use std::os::unix::fs::MetadataExt as _;

    let name = filename_in_webhook_directory(directory, path)?;
    let Some((before, identity)) =
        inspect_private_webhook_file(directory, name, Some(maximum_bytes))?
    else {
        return Ok(None);
    };
    let mut file = fs::File::from(
        rustix::fs::openat(
            &directory.file,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let opened_before = file.metadata()?;
    if !opened_before.is_file()
        || opened_before.uid() != rustix::process::geteuid().as_raw()
        || opened_before.mode() & 0o7777 != 0o600
        || opened_before.nlink() != 1
        || webhook_identity_from_metadata(&opened_before) != identity
        || usize::try_from(opened_before.len()).map_or(true, |size| size > maximum_bytes)
    {
        return Err(invalid_webhook_storage(format!(
            "webhook persistence entry changed while opening: {}",
            path.display()
        )));
    }
    let capacity = usize::try_from(opened_before.len())
        .unwrap_or(maximum_bytes)
        .min(maximum_bytes);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(io::Error::other)?;
    (&mut file)
        .take(
            u64::try_from(maximum_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err(invalid_webhook_storage(format!(
            "webhook persistence entry exceeds its byte bound: {}",
            path.display()
        )));
    }
    let opened_after = file.metadata()?;
    let Some((named_after, named_identity)) =
        inspect_private_webhook_file(directory, name, Some(maximum_bytes))?
    else {
        return Err(invalid_webhook_storage(format!(
            "webhook persistence entry disappeared while reading: {}",
            path.display()
        )));
    };
    if webhook_identity_from_metadata(&opened_after) != identity
        || named_identity != identity
        || opened_after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        || before.st_size != named_after.st_size
        || before.st_mtime != named_after.st_mtime
        || before.st_mtime_nsec != named_after.st_mtime_nsec
        || before.st_ctime != named_after.st_ctime
        || before.st_ctime_nsec != named_after.st_ctime_nsec
    {
        return Err(invalid_webhook_storage(format!(
            "webhook persistence entry changed while reading: {}",
            path.display()
        )));
    }
    Ok(Some(BoundedWebhookFile { bytes, identity }))
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn read_private_webhook_file_bounded(
    _directory: &WebhookDirectory,
    _path: &Path,
    _maximum_bytes: usize,
) -> io::Result<Option<BoundedWebhookFile>> {
    Err(unsupported_webhook_persistence())
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn create_private_webhook_temp_file(
    directory: &WebhookDirectory,
) -> io::Result<(fs::File, OsString)> {
    use rand::TryRngCore as _;

    let mut rng = rand::rngs::OsRng;
    for _ in 0..WEBHOOK_TEMP_FILE_RETRIES {
        let mut nonce = [0_u8; 16];
        rng.try_fill_bytes(&mut nonce).map_err(|error| {
            io::Error::other(format!(
                "failed to generate a webhook temporary-file name: {error}"
            ))
        })?;
        let name = OsString::from(format!(".webhook-{}.tmp", hex::encode(nonce)));
        match rustix::fs::openat(
            &directory.file,
            &name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        ) {
            Ok(file) => {
                let file = fs::File::from(file);
                rustix::fs::fchmod(&file, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)
                    .map_err(io::Error::from)?;
                webhook_acl::clear_private(&file, &directory.path.join(&name))?;
                return Ok((file, name));
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(io::Error::from(error)),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to allocate a collision-free webhook temporary file",
    ))
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn publication_matches(
    publication: WebhookPublication,
    actual: Option<WebhookFileIdentity>,
) -> bool {
    match publication {
        WebhookPublication::CreateNew => actual.is_none(),
        WebhookPublication::Replace => true,
        WebhookPublication::ReplaceIdentity(expected) => actual == Some(expected),
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn write_private_webhook_file_atomic(
    directory: &WebhookDirectory,
    path: &Path,
    bytes: &[u8],
    maximum_bytes: usize,
    publication: WebhookPublication,
) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if bytes.len() > maximum_bytes {
        return Err(invalid_webhook_storage(
            "webhook persistence payload exceeds its byte bound",
        ));
    }
    let name = filename_in_webhook_directory(directory, path)?;
    let initial =
        inspect_private_webhook_file(directory, name, None)?.map(|(_, identity)| identity);
    if !publication_matches(publication, initial) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "webhook persistence destination changed before publication",
        ));
    }
    let (mut temporary, temporary_name) = create_private_webhook_temp_file(directory)?;
    let temporary_path = directory.path.join(&temporary_name);
    let prepared = (|| {
        temporary.write_all(bytes)?;
        temporary.sync_all()?;
        let temporary_metadata = temporary.metadata()?;
        let Some((_, temporary_identity)) =
            inspect_private_webhook_file(directory, &temporary_name, Some(maximum_bytes))?
        else {
            return Err(invalid_webhook_storage(
                "webhook temporary file disappeared before publication",
            ));
        };
        if !temporary_metadata.is_file()
            || temporary_metadata.uid() != rustix::process::geteuid().as_raw()
            || temporary_metadata.mode() & 0o7777 != 0o600
            || temporary_metadata.nlink() != 1
            || temporary_metadata.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            || webhook_identity_from_metadata(&temporary_metadata) != temporary_identity
        {
            return Err(invalid_webhook_storage(
                "webhook temporary file failed its private-file invariant",
            ));
        }
        let current =
            inspect_private_webhook_file(directory, name, None)?.map(|(_, identity)| identity);
        let stable_destination = match publication {
            WebhookPublication::CreateNew => current.is_none(),
            WebhookPublication::Replace => current == initial,
            WebhookPublication::ReplaceIdentity(expected) => current == Some(expected),
        };
        if !stable_destination {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "webhook persistence destination changed during publication",
            ));
        }
        if current.is_none() {
            rustix::fs::renameat_with(
                &directory.file,
                &temporary_name,
                &directory.file,
                name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(io::Error::from)?;
        } else {
            rustix::fs::renameat(&directory.file, &temporary_name, &directory.file, name)
                .map_err(io::Error::from)?;
        }
        let Some((_, published_identity)) =
            inspect_private_webhook_file(directory, name, Some(maximum_bytes))?
        else {
            return Err(invalid_webhook_storage(
                "webhook publication disappeared after atomic replacement",
            ));
        };
        if published_identity != temporary_identity {
            return Err(invalid_webhook_storage(
                "webhook publication changed after atomic replacement",
            ));
        }
        directory.file.sync_all()
    })();
    if prepared.is_err() {
        if let Ok(Some((_, identity))) =
            inspect_private_webhook_file(directory, &temporary_name, None)
        {
            let _ = unlink_private_webhook_entry(directory, &temporary_path, Some(identity), false);
        }
    }
    prepared
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn write_private_webhook_file_atomic(
    _directory: &WebhookDirectory,
    _path: &Path,
    _bytes: &[u8],
    _maximum_bytes: usize,
    _publication: WebhookPublication,
) -> io::Result<()> {
    Err(unsupported_webhook_persistence())
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn unlink_private_webhook_entry(
    directory: &WebhookDirectory,
    path: &Path,
    expected: Option<WebhookFileIdentity>,
    sync: bool,
) -> io::Result<()> {
    let name = filename_in_webhook_directory(directory, path)?;
    if let Some(expected) = expected {
        let Some((_, current)) = inspect_private_webhook_file(directory, name, None)? else {
            return Ok(());
        };
        if current != expected {
            return Err(invalid_webhook_storage(
                "refusing to remove a replaced webhook persistence entry",
            ));
        }
    }
    rustix::fs::unlinkat(&directory.file, name, rustix::fs::AtFlags::empty())
        .map_err(io::Error::from)?;
    if sync {
        directory.file.sync_all()?;
    }
    Ok(())
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn unlink_private_webhook_entry(
    _directory: &WebhookDirectory,
    _path: &Path,
    _expected: Option<WebhookFileIdentity>,
    _sync: bool,
) -> io::Result<()> {
    Err(unsupported_webhook_persistence())
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn is_webhook_temporary_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(nonce) = name
        .strip_prefix(".webhook-")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    nonce.len() == 32
        && nonce
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn cleanup_webhook_temporary_files(
    directory: &WebhookDirectory,
    work_limit: usize,
) -> io::Result<usize> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut entries = rustix::fs::Dir::read_from(&directory.file).map_err(io::Error::from)?;
    let mut work = 0_usize;
    let mut removed = 0_usize;
    for entry in &mut entries {
        let entry = entry.map_err(io::Error::from)?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        if work >= work_limit {
            return Err(io::Error::other(
                "webhook temporary-file recovery work limit reached",
            ));
        }
        work = work.saturating_add(1);
        let name = OsStr::from_bytes(bytes);
        if !is_webhook_temporary_name(name) {
            continue;
        }
        let path = directory.path.join(name);
        let Some((_, identity)) = inspect_private_webhook_file(directory, name, None)? else {
            continue;
        };
        unlink_private_webhook_entry(directory, &path, Some(identity), false)?;
        removed = removed.saturating_add(1);
    }
    if removed != 0 {
        directory.file.sync_all()?;
    }
    Ok(removed)
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn cleanup_webhook_temporary_files(
    _directory: &WebhookDirectory,
    _work_limit: usize,
) -> io::Result<usize> {
    Err(unsupported_webhook_persistence())
}

fn recover_webhook_temporary_files() -> io::Result<()> {
    let data = open_webhook_data_directory(true)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "webhook data directory is unavailable",
        )
    })?;
    let queue = open_webhook_queue_directory(true)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "webhook queue directory is unavailable",
        )
    })?;
    cleanup_webhook_temporary_files(&data, WEBHOOK_QUEUE_ADMISSION_SCAN_WORK_ITEMS)?;
    cleanup_webhook_temporary_files(&queue, WEBHOOK_QUEUE_ADMISSION_SCAN_WORK_ITEMS)?;
    Ok(())
}

fn effective_queue_capacity(policy: WebhookPolicy) -> usize {
    policy.queue_capacity.get().min(WEBHOOK_QUEUE_HARD_CAPACITY)
}
#[cfg(test)]
fn queue_depth_bounded(maximum: usize) -> std::io::Result<usize> {
    let directory = open_webhook_queue_directory(true)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "webhook queue directory is unavailable",
        )
    })?;
    queue_depth_bounded_in(&directory, maximum, WEBHOOK_QUEUE_ADMISSION_SCAN_WORK_ITEMS)
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn queue_depth_bounded_in(
    directory: &WebhookDirectory,
    maximum: usize,
    work_limit: usize,
) -> io::Result<usize> {
    let mut count = 0_usize;
    let mut work = 0_usize;
    let mut entries = rustix::fs::Dir::read_from(&directory.file).map_err(io::Error::from)?;
    for entry in &mut entries {
        let entry = entry.map_err(io::Error::from)?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        if work >= work_limit {
            return Err(io::Error::other(
                "webhook queue admission scan work limit reached",
            ));
        }
        work = work.saturating_add(1);
        if !bytes.ends_with(b".json") {
            continue;
        }
        count = count.saturating_add(1);
        if count >= maximum {
            return Ok(maximum);
        }
    }
    Ok(count)
}
#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn queue_depth_bounded_in(
    _directory: &WebhookDirectory,
    _maximum: usize,
    _work_limit: usize,
) -> io::Result<usize> {
    Err(unsupported_webhook_persistence())
}
#[cfg(test)]
fn queue_depth_bounded_at(
    root: &Path,
    maximum: usize,
    work_limit: usize,
) -> std::io::Result<usize> {
    let mut count = 0_usize;
    for (index, entry) in fs::read_dir(root)?.enumerate() {
        if index >= work_limit {
            return Err(std::io::Error::other(
                "webhook queue admission scan work limit reached",
            ));
        }
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        count = count.saturating_add(1);
        if count >= maximum {
            return Ok(maximum);
        }
    }
    Ok(count)
}
#[cfg(all(test, any(target_vendor = "apple", target_os = "linux")))]
fn queue_depth() -> usize {
    match queue_depth_bounded(usize::MAX) {
        Ok(depth) => depth,
        Err(err) => {
            iroha_logger::warn!(%err, "failed to read webhook queue directory");
            0
        }
    }
}
fn queue_write_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}
struct QueueAdmission {
    _guard: std::sync::MutexGuard<'static, ()>,
    directory: WebhookDirectory,
    remaining: usize,
}
impl QueueAdmission {
    fn begin(policy: WebhookPolicy) -> std::io::Result<Self> {
        ensure_dirs()?;
        let guard = lock_unpoisoned(queue_write_lock());
        let directory = open_webhook_queue_directory(true)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "webhook queue directory is unavailable",
            )
        })?;
        let capacity = effective_queue_capacity(policy);
        let used = queue_depth_bounded_in(
            &directory,
            capacity,
            WEBHOOK_QUEUE_ADMISSION_SCAN_WORK_ITEMS,
        )?;
        Ok(Self {
            _guard: guard,
            directory,
            remaining: capacity.saturating_sub(used),
        })
    }
    fn is_full(&self) -> bool {
        self.remaining == 0
    }
    fn persist(&mut self, pd: &PendingDelivery) -> std::io::Result<()> {
        if self.is_full() {
            return Err(std::io::Error::other("webhook queue hard capacity reached"));
        }
        let encoded = encode_pending_delivery(pd)?;
        let path = self.directory.path.join(format!("{}.json", pd.id));
        write_private_webhook_file_atomic(
            &self.directory,
            &path,
            encoded.as_bytes(),
            WEBHOOK_QUEUE_FILE_MAX_BYTES,
            WebhookPublication::CreateNew,
        )?;
        self.remaining = self.remaining.saturating_sub(1);
        Ok(())
    }
}
fn encode_pending_delivery(pd: &PendingDelivery) -> std::io::Result<String> {
    if pd.body.len() > WEBHOOK_DELIVERY_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "webhook delivery exceeds hard byte limit",
        ));
    }
    if !delivery_metadata_is_bounded(&pd.id, &pd.url, &pd.content_type) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "webhook delivery metadata exceeds hard byte limit",
        ));
    }
    if !delivery_content_type_is_valid(&pd.content_type) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "webhook delivery content type is not a valid HTTP header value",
        ));
    }
    if pd
        .signature
        .as_deref()
        .is_some_and(|signature| !delivery_signature_is_valid(signature))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "webhook delivery signature is invalid",
        ));
    }
    let mut payload = norito::json::Map::new();
    payload.insert("id".into(), norito::json::Value::from(pd.id.clone()));
    payload.insert(
        "webhook_id".into(),
        norito::json::Value::from(pd.webhook_id),
    );
    payload.insert(
        "webhook_generation".into(),
        norito::json::Value::from(hex::encode(pd.webhook_generation)),
    );
    payload.insert("url".into(), norito::json::Value::from(pd.url.clone()));
    payload.insert(
        "content_type".into(),
        norito::json::Value::from(pd.content_type.clone()),
    );
    payload.insert(
        "signature".into(),
        pd.signature
            .clone()
            .map_or(norito::json::Value::Null, norito::json::Value::from),
    );
    payload.insert(
        "body".into(),
        norito::json::Value::from(STANDARD.encode(&pd.body)),
    );
    payload.insert(
        "attempts".into(),
        norito::json::Value::from(pd.attempts as u64),
    );
    payload.insert(
        "next_attempt_ms".into(),
        norito::json::Value::from(pd.next_attempt_ms),
    );
    let encoded = norito::json::to_json_pretty(&payload).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to encode webhook delivery: {err}"),
        )
    })?;
    if encoded.len() > WEBHOOK_QUEUE_FILE_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "webhook spool record exceeds hard byte limit",
        ));
    }
    Ok(encoded)
}
fn delivery_metadata_is_bounded(id: &str, url: &str, content_type: &str) -> bool {
    id.len()
        .checked_add(url.len())
        .and_then(|length| length.checked_add(content_type.len()))
        .is_some_and(|length| length <= WEBHOOK_DELIVERY_METADATA_MAX_BYTES)
}
fn delivery_content_type_is_valid(content_type: &str) -> bool {
    !content_type.is_empty() && HeaderValue::from_str(content_type).is_ok()
}
fn delivery_signature_is_valid(signature: &str) -> bool {
    HeaderValue::from_str(signature).is_ok()
        && signature.strip_prefix("sha256=").is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}
fn proof_id_from_json(value: &norito::json::Value) -> Option<iroha_data_model::proof::ProofId> {
    use iroha_data_model::proof::ProofId;
    let literal = value.as_str()?;
    let id = ProofId::from_str(literal).ok()?;
    (id.to_string() == literal).then_some(id)
}
fn parse_account_id_literal(input: &str) -> Option<iroha_data_model::account::AccountId> {
    let id = iroha_data_model::account::AccountId::parse_encoded(input).ok()?;
    (id.to_string() == input).then_some(id)
}
#[derive(Clone, Copy, Debug)]
pub struct HttpTimeoutConfig {
    pub connect: Duration,
    pub write: Duration,
    pub read: Duration,
}
impl Default for HttpTimeoutConfig {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            write: Duration::from_secs(10),
            read: Duration::from_secs(10),
        }
    }
}
fn http_timeout_state() -> &'static Mutex<HttpTimeoutConfig> {
    static STATE: OnceLock<Mutex<HttpTimeoutConfig>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HttpTimeoutConfig::default()))
}
pub fn http_timeout_config() -> HttpTimeoutConfig {
    *http_timeout_state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
pub fn set_http_timeout_config(config: HttpTimeoutConfig) {
    *http_timeout_state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = config;
}
#[derive(Clone, Copy, Debug)]
pub struct WebhookPolicy {
    /// Configured queue capacity, capped by the source-level hard ceiling.
    pub queue_capacity: NonZeroUsize,
    pub max_attempts: NonZeroU32,
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    pub connect_timeout: Duration,
    pub write_timeout: Duration,
    pub read_timeout: Duration,
}
impl Default for WebhookPolicy {
    fn default() -> Self {
        Self {
            queue_capacity: NonZeroUsize::new(defaults::torii::WEBHOOK_QUEUE_CAPACITY)
                .expect("default webhook queue capacity is non-zero"),
            max_attempts: NonZeroU32::new(defaults::torii::WEBHOOK_MAX_ATTEMPTS)
                .expect("default webhook max attempts is non-zero"),
            backoff_initial: Duration::from_millis(defaults::torii::WEBHOOK_BACKOFF_INITIAL_MS),
            backoff_max: Duration::from_millis(defaults::torii::WEBHOOK_BACKOFF_MAX_MS),
            connect_timeout: Duration::from_millis(defaults::torii::WEBHOOK_CONNECT_TIMEOUT_MS),
            write_timeout: Duration::from_millis(defaults::torii::WEBHOOK_WRITE_TIMEOUT_MS),
            read_timeout: Duration::from_millis(defaults::torii::WEBHOOK_READ_TIMEOUT_MS),
        }
    }
}
fn webhook_policy_state() -> &'static Mutex<WebhookPolicy> {
    static STATE: OnceLock<Mutex<WebhookPolicy>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(WebhookPolicy::default()))
}
#[cfg(test)]
fn webhook_policy_writer_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}
fn webhook_policy() -> WebhookPolicy {
    *webhook_policy_state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn apply_webhook_policy(policy: WebhookPolicy) {
    *webhook_policy_state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = policy;
    set_http_timeout_config(HttpTimeoutConfig {
        connect: policy.connect_timeout,
        write: policy.write_timeout,
        read: policy.read_timeout,
    });
}
pub fn set_webhook_policy(policy: WebhookPolicy) {
    #[cfg(test)]
    let _writer_guard = webhook_policy_writer_lock()
        .lock()
        .expect("webhook policy writer lock");
    apply_webhook_policy(policy);
}
/// Webhook destination security policy (SSRF guard rails).
#[derive(Clone, Debug)]
pub struct WebhookSecurityPolicy {
    /// Enable webhook destination guard rails.
    pub enabled: bool,
    /// CIDR allow-list for webhook destination IPs.
    pub allow_nets: Vec<crate::limits::IpNet>,
}
impl Default for WebhookSecurityPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_nets: Vec::new(),
        }
    }
}
fn webhook_security_policy_state() -> &'static Mutex<WebhookSecurityPolicy> {
    static STATE: OnceLock<Mutex<WebhookSecurityPolicy>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(WebhookSecurityPolicy::default()))
}
fn webhook_security_policy() -> WebhookSecurityPolicy {
    webhook_security_policy_state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}
pub fn set_webhook_security_policy(policy: WebhookSecurityPolicy) {
    *webhook_security_policy_state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = policy;
}
#[cfg(test)]
type HttpPostOverrideFn =
    dyn Fn(&str, &[(&str, String)], &[u8]) -> std::io::Result<u16> + Send + Sync;
#[cfg(test)]
fn http_post_override_slot() -> &'static Mutex<Option<Arc<HttpPostOverrideFn>>> {
    static SLOT: OnceLock<Mutex<Option<Arc<HttpPostOverrideFn>>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}
#[cfg(test)]
fn http_post_override_handler() -> Option<Arc<HttpPostOverrideFn>> {
    http_post_override_slot()
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().cloned())
}
#[cfg(test)]
#[must_use]
pub struct HttpPostOverrideGuard;
#[cfg(test)]
impl Drop for HttpPostOverrideGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = http_post_override_slot().lock() {
            *guard = None;
        }
    }
}
#[cfg(test)]
pub fn install_http_post_override<F>(handler: F) -> HttpPostOverrideGuard
where
    F: Fn(&str, &[(&str, String)], &[u8]) -> std::io::Result<u16> + Send + Sync + 'static,
{
    let mut guard = http_post_override_slot()
        .lock()
        .expect("http post override lock");
    assert!(guard.is_none(), "test http post override already installed");
    *guard = Some(Arc::new(handler));
    HttpPostOverrideGuard
}
fn ensure_dirs() -> io::Result<()> {
    open_webhook_data_directory(true)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "webhook data directory is unavailable",
        )
    })?;
    open_webhook_queue_directory(true)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "webhook queue directory is unavailable",
        )
    })?;
    Ok(())
}
fn webhook_generation_from_hex(value: &str) -> Option<[u8; WEBHOOK_GENERATION_BYTES]> {
    let bytes = hex::decode(value).ok()?;
    let generation: [u8; WEBHOOK_GENERATION_BYTES] = bytes.try_into().ok()?;
    (hex::encode(generation) == value).then_some(generation)
}
fn new_webhook_generation() -> io::Result<[u8; WEBHOOK_GENERATION_BYTES]> {
    use rand::TryRngCore as _;

    let mut generation = [0_u8; WEBHOOK_GENERATION_BYTES];
    let mut rng = rand::rngs::OsRng;
    rng.try_fill_bytes(&mut generation).map_err(|error| {
        io::Error::other(format!(
            "failed to generate webhook registration generation: {error}"
        ))
    })?;
    Ok(generation)
}
fn persist_registry(registry: &RegistryInner) -> io::Result<()> {
    ensure_dirs()?;
    let mut entries: Vec<_> = registry.items.values().collect();
    entries.sort_by_key(|registered| registered.entry.id);
    let arr = entries
        .into_iter()
        .map(registered_webhook_to_storage_json)
        .collect();
    let mut document = norito::json::Map::new();
    document.insert(
        "version".into(),
        norito::json::Value::from(WEBHOOK_REGISTRY_FORMAT_VERSION),
    );
    document.insert(
        "next_id".into(),
        norito::json::Value::from(registry.next_id),
    );
    document.insert("entries".into(), norito::json::Value::Array(arr));
    let body =
        norito::json::to_json_pretty(&norito::json::Value::Object(document)).map_err(|error| {
            invalid_webhook_storage(format!("failed to encode webhook registry: {error}"))
        })?;
    if body.len() > WEBHOOK_REGISTRY_MAX_BYTES {
        return Err(invalid_webhook_storage(format!(
            "webhook registry is {} bytes; maximum is {WEBHOOK_REGISTRY_MAX_BYTES}",
            body.len()
        )));
    }
    let directory = open_webhook_data_directory(false)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "webhook data directory disappeared before registry persistence",
        )
    })?;
    let path = directory.path.join("webhooks.json");
    write_private_webhook_file_atomic(
        &directory,
        &path,
        body.as_bytes(),
        WEBHOOK_REGISTRY_MAX_BYTES,
        WebhookPublication::Replace,
    )
}
fn load_registry() -> io::Result<()> {
    let Some(directory) = open_webhook_data_directory(false)? else {
        *lock_registry() = RegistryInner::default();
        return Ok(());
    };
    let path = directory.path.join("webhooks.json");
    let Some(file) =
        read_private_webhook_file_bounded(&directory, &path, WEBHOOK_REGISTRY_MAX_BYTES)?
    else {
        *lock_registry() = RegistryInner::default();
        return Ok(());
    };
    let value = norito::json::from_slice::<norito::json::Value>(&file.bytes).map_err(|error| {
        invalid_webhook_storage(format!(
            "failed to decode webhook registry {}: {error}",
            path.display()
        ))
    })?;
    let norito::json::Value::Object(mut document) = value else {
        return Err(invalid_webhook_storage(format!(
            "webhook registry is not a JSON object: {}",
            path.display()
        )));
    };
    let version = document
        .remove("version")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| {
            invalid_webhook_storage(format!(
                "webhook registry has no valid format version: {}",
                path.display()
            ))
        })?;
    if version != WEBHOOK_REGISTRY_FORMAT_VERSION {
        return Err(invalid_webhook_storage(format!(
            "unsupported webhook registry format version {version}: {}",
            path.display()
        )));
    }
    let next_id = document
        .remove("next_id")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| {
            invalid_webhook_storage(format!(
                "webhook registry has no valid next identifier: {}",
                path.display()
            ))
        })?;
    let Some(norito::json::Value::Array(arr)) = document.remove("entries") else {
        return Err(invalid_webhook_storage(format!(
            "webhook registry has no valid entries array: {}",
            path.display()
        )));
    };
    if arr.len() > WEBHOOK_REGISTRY_MAX_ENTRIES {
        return Err(invalid_webhook_storage(format!(
            "webhook registry contains {} entries; maximum is {WEBHOOK_REGISTRY_MAX_ENTRIES}",
            arr.len()
        )));
    }
    let policy = webhook_security_policy();
    let mut loaded = RegistryInner::default();
    for v in arr {
        if let norito::json::Value::Object(m) = v {
            let Some(idv) = m.get("id").and_then(norito::json::Value::as_u64) else {
                continue;
            };
            if idv > next_id {
                return Err(invalid_webhook_storage(format!(
                    "webhook identifier {idv} exceeds durable next identifier {next_id}"
                )));
            }
            let Some(generation) = m
                .get("generation")
                .and_then(norito::json::Value::as_str)
                .and_then(webhook_generation_from_hex)
            else {
                iroha_logger::warn!(
                    webhook_id = idv,
                    "skipping persisted webhook with an invalid generation"
                );
                continue;
            };
            if let (Some(urlv), Some(activev)) = (
                m.get("url")
                    .and_then(norito::json::Value::as_str)
                    .map(ToString::to_string),
                m.get("active").and_then(|v| match v {
                    norito::json::Value::Bool(b) => Some(*b),
                    _ => None,
                }),
            ) {
                let urlv = match validate_webhook_url_for_create(&urlv, &policy) {
                    Ok(url) => url.to_string(),
                    Err((_, error)) => {
                        iroha_logger::warn!(
                            webhook_id = idv,
                            %error,
                            "skipping persisted webhook with an invalid destination"
                        );
                        continue;
                    }
                };
                let secret = m
                    .get("secret")
                    .and_then(norito::json::Value::as_str)
                    .map(ToString::to_string);
                let filter = match m.get("filter") {
                    None | Some(norito::json::Value::Null) => None,
                    Some(value) => {
                        let Some(filter) = value_to_filter_expr(value) else {
                            iroha_logger::warn!(
                                webhook_id = idv,
                                "skipping persisted webhook with malformed filter"
                            );
                            continue;
                        };
                        if let Err(error) = validate_webhook_filter(&filter) {
                            iroha_logger::warn!(
                                webhook_id = idv,
                                %error,
                                "skipping persisted webhook with invalid filter"
                            );
                            continue;
                        }
                        Some(filter)
                    }
                };
                let entry = WebhookEntry {
                    id: idv,
                    url: urlv,
                    active: activev,
                    secret,
                    filter,
                };
                let registered = RegisteredWebhook { entry, generation };
                if loaded.items.insert(idv, registered).is_some() {
                    return Err(invalid_webhook_storage(format!(
                        "webhook registry contains duplicate identifier {idv}"
                    )));
                }
            }
        }
    }
    loaded.next_id = next_id;
    *lock_registry() = loaded;
    Ok(())
}
fn webhook_entry_to_storage_json(entry: &WebhookEntry) -> norito::json::Value {
    let mut map = norito::json::Map::new();
    map.insert("id".into(), norito::json::Value::from(entry.id));
    map.insert("url".into(), norito::json::Value::from(entry.url.clone()));
    map.insert("active".into(), norito::json::Value::from(entry.active));
    map.insert(
        "secret".into(),
        entry
            .secret
            .clone()
            .map_or(norito::json::Value::Null, norito::json::Value::from),
    );
    map.insert(
        "filter".into(),
        entry
            .filter
            .as_ref()
            .map_or(norito::json::Value::Null, filter_expr_to_value),
    );
    norito::json::Value::Object(map)
}
fn registered_webhook_to_storage_json(registered: &RegisteredWebhook) -> norito::json::Value {
    let norito::json::Value::Object(mut map) = webhook_entry_to_storage_json(&registered.entry)
    else {
        unreachable!("webhook storage encoder always returns an object");
    };
    map.insert(
        "generation".into(),
        norito::json::Value::from(hex::encode(registered.generation)),
    );
    norito::json::Value::Object(map)
}
fn registered_webhook_encoded_len(
    registered: &RegisteredWebhook,
) -> Result<usize, norito::json::Error> {
    norito::json::to_vec(&registered_webhook_to_storage_json(registered)).map(|bytes| bytes.len())
}
fn registry_can_retain(guard: &RegistryInner, candidate: &RegisteredWebhook) -> bool {
    if guard.items.len() >= WEBHOOK_REGISTRY_MAX_ENTRIES {
        return false;
    }
    let Ok(candidate_len) = registered_webhook_encoded_len(candidate) else {
        return false;
    };
    if candidate_len > WEBHOOK_ENTRY_MAX_BYTES {
        return false;
    }
    let retained = guard.items.values().try_fold(0_usize, |total, entry| {
        registered_webhook_encoded_len(entry)
            .ok()
            .and_then(|len| total.checked_add(len.saturating_add(1)))
    });
    retained.is_some_and(|retained| {
        retained
            .checked_add(candidate_len.saturating_add(2))
            .is_some_and(|total| total <= WEBHOOK_REGISTRY_MAX_BYTES)
    })
}
/// Initialize persistence: create data dir and load registry from disk.
pub fn init_persistence() -> io::Result<()> {
    ensure_dirs()?;
    recover_webhook_temporary_files()?;
    load_registry()
}
fn webhook_entry_to_public_json(entry: &WebhookEntry) -> norito::json::Value {
    let mut m = norito::json::Map::new();
    m.insert("id".into(), norito::json::Value::from(entry.id));
    m.insert("url".into(), norito::json::Value::from(entry.url.clone()));
    m.insert("active".into(), norito::json::Value::from(entry.active));
    m.insert(
        "has_secret".into(),
        norito::json::Value::from(entry.secret.is_some()),
    );
    if let Some(ref expr) = entry.filter {
        m.insert("filter".into(), filter_expr_to_value(expr));
    } else {
        m.insert("filter".into(), norito::json::Value::Null);
    }
    norito::json::Value::Object(m)
}
fn is_public_ipv4(v4: Ipv4Addr) -> bool {
    if v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
    {
        return false;
    }
    let [a, b, ..] = v4.octets();
    // 0.0.0.0/8 (\"this network\")
    if a == 0 {
        return false;
    }
    // 100.64.0.0/10 (carrier-grade NAT)
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }
    // 198.18.0.0/15 (benchmarking)
    if a == 198 && (b == 18 || b == 19) {
        return false;
    }
    // 240.0.0.0/4 (reserved)
    if a >= 240 {
        return false;
    }
    true
}
fn is_documentation_ipv6(v6: Ipv6Addr) -> bool {
    // 2001:db8::/32
    let seg = v6.segments();
    seg[0] == 0x2001 && seg[1] == 0x0db8
}
fn is_public_ipv6(v6: Ipv6Addr) -> bool {
    if v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || v6.is_unicast_link_local()
        || v6.is_unique_local()
        || is_documentation_ipv6(v6)
    {
        return false;
    }
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_public_ipv4(v4);
    }
    true
}
fn is_public_destination_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => is_public_ipv6(v6),
    }
}
fn is_destination_ip_allowed(ip: IpAddr, policy: &WebhookSecurityPolicy) -> bool {
    if crate::limits::cidr_contains(&policy.allow_nets, ip) {
        return true;
    }
    is_public_destination_ip(ip)
}
fn is_localhost_domain(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.');
    domain.eq_ignore_ascii_case("localhost")
}
fn validate_webhook_url_for_create(
    raw: &str,
    policy: &WebhookSecurityPolicy,
) -> Result<Url, (StatusCode, String)> {
    let url = Url::parse(raw)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid webhook url: {e}")))?;
    validate_parsed_webhook_url(&url, policy)?;
    Ok(url)
}
fn validate_parsed_webhook_url(
    url: &Url,
    policy: &WebhookSecurityPolicy,
) -> Result<(), (StatusCode, String)> {
    match url.scheme() {
        "http" => {}
        "https" if cfg!(feature = "app_api_https") => {}
        "ws" | "wss" if cfg!(feature = "app_api_wss") => {}
        unavailable @ ("https" | "ws" | "wss") => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("webhook scheme `{unavailable}` is unavailable in this build"),
            ));
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unsupported webhook scheme `{other}`"),
            ));
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "webhook url must not contain user information".to_string(),
        ));
    }
    if url.fragment().is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "webhook url must not contain a fragment".to_string(),
        ));
    }
    if url.port() == Some(0) {
        return Err((
            StatusCode::BAD_REQUEST,
            "webhook url port must not be zero".to_string(),
        ));
    }
    let Some(host) = url.host() else {
        return Err((
            StatusCode::BAD_REQUEST,
            "webhook url must include a host".to_string(),
        ));
    };
    if policy.enabled {
        if let Host::Domain(domain) = host {
            if is_localhost_domain(domain) {
                return Err((
                    StatusCode::FORBIDDEN,
                    "webhook url host `localhost` is not allowed".to_string(),
                ));
            }
        }
        match host {
            Host::Ipv4(v4) => {
                if !is_destination_ip_allowed(IpAddr::V4(v4), policy) {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "webhook url host is not allowed".to_string(),
                    ));
                }
            }
            Host::Ipv6(v6) => {
                if !is_destination_ip_allowed(IpAddr::V6(v6), policy) {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "webhook url host is not allowed".to_string(),
                    ));
                }
            }
            Host::Domain(_) => {}
        }
    }
    Ok(())
}
/// POST /v1/webhooks – create a webhook entry.
pub async fn handle_create_webhook(
    crate::utils::extractors::JsonOnly(req): crate::utils::extractors::JsonOnly<WebhookCreate>,
) -> axum::response::Response {
    if let Some(ref expr) = req.filter {
        if let Err(e) = validate_webhook_filter(expr) {
            return (StatusCode::BAD_REQUEST, format!("invalid filter: {e}")).into_response();
        }
    }
    let policy = webhook_security_policy();
    let url = match validate_webhook_url_for_create(&req.url, &policy) {
        Ok(url) => url.to_string(),
        Err((status, message)) => return (status, message).into_response(),
    };
    let mut guard = lock_registry();
    let Some(id) = guard.next_id.checked_add(1) else {
        return (
            StatusCode::INSUFFICIENT_STORAGE,
            "webhook registry identifier space exhausted",
        )
            .into_response();
    };
    let entry = WebhookEntry {
        id,
        url,
        active: req.active,
        secret: req.secret,
        filter: req.filter,
    };
    let generation = match new_webhook_generation() {
        Ok(generation) => generation,
        Err(error) => {
            iroha_logger::error!(%error, "failed to create webhook registration generation");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "webhook registry persistence is unavailable",
            )
                .into_response();
        }
    };
    let registered = RegisteredWebhook {
        entry: entry.clone(),
        generation,
    };
    if !registry_can_retain(&guard, &registered) {
        return (
            StatusCode::INSUFFICIENT_STORAGE,
            "webhook registry capacity exceeded",
        )
            .into_response();
    }
    let mut candidate = guard.clone();
    candidate.next_id = id;
    candidate.items.insert(id, registered);
    if let Err(error) = persist_registry(&candidate) {
        iroha_logger::error!(%error, "failed to commit webhook registry update");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "webhook registry persistence is unavailable",
        )
            .into_response();
    }
    *guard = candidate;
    drop(guard);
    // Build Norito JSON response
    let body = norito::json::to_json_pretty(&webhook_entry_to_public_json(&entry))
        .unwrap_or_else(|_| "{}".into());
    (StatusCode::CREATED, body).into_response()
}
/// GET /v1/webhooks – list current webhook entries.
pub async fn handle_list_webhooks() -> impl IntoResponse {
    let guard = lock_registry();
    let mut entries: Vec<_> = guard
        .items
        .values()
        .map(|registered| registered.entry.clone())
        .collect();
    entries.sort_by_key(|w| w.id);
    let mut arr = Vec::with_capacity(entries.len());
    for e in entries {
        arr.push(webhook_entry_to_public_json(&e));
    }
    let body = norito::json::to_json_pretty(&norito::json::Value::Array(arr))
        .unwrap_or_else(|_| "[]".into());
    axum::response::Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}
/// DELETE /v1/webhooks/{id} – delete a webhook.
pub async fn handle_delete_webhook(AxumPath(id): AxumPath<u64>) -> axum::response::Response {
    // Serialize deletion with the final registration check and network attempt.
    // Once DELETE returns, no delivery using the deleted generation can start.
    let delivery_lock = webhook_delivery_attempt_lock(id);
    let _delivery_guard = delivery_lock.lock().await;
    let mut guard = lock_registry();
    let mut candidate = guard.clone();
    if candidate.items.remove(&id).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Err(error) = persist_registry(&candidate) {
        iroha_logger::error!(%error, webhook_id = id, "failed to commit webhook deletion");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "webhook registry persistence is unavailable",
        )
            .into_response();
    }
    *guard = candidate;
    StatusCode::NO_CONTENT.into_response()
}
/// Compute HMAC-SHA256 of `body` with `secret` and return lowercase hex string.
fn hmac_sha256_hex(secret: &[u8], body: &[u8]) -> String {
    const BLOCK: usize = 64; // Sha256 block size
    let mut key = [0u8; BLOCK];
    if secret.len() > BLOCK {
        let digest = Sha256::digest(secret);
        key[..32].copy_from_slice(&digest);
    } else {
        key[..secret.len()].copy_from_slice(secret);
    }
    let mut o_key_pad = [0u8; BLOCK];
    let mut i_key_pad = [0u8; BLOCK];
    for i in 0..BLOCK {
        o_key_pad[i] = key[i] ^ 0x5c;
        i_key_pad[i] = key[i] ^ 0x36;
    }
    let mut inner = Sha256::new();
    inner.update(&i_key_pad);
    inner.update(body);
    let inner_sum = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&o_key_pad);
    outer.update(&inner_sum);
    let mac = outer.finalize();
    hex::encode(mac)
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::webhook::PendingDelivery")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
)]
struct PendingDelivery {
    id: String,
    webhook_id: u64,
    webhook_generation: [u8; WEBHOOK_GENERATION_BYTES],
    url: String,
    content_type: String,
    signature: Option<String>,
    body: Vec<u8>,
    attempts: u32,
    next_attempt_ms: u64,
}
fn new_delivery_id(webhook_id: u64, timestamp_ms: u64) -> io::Result<String> {
    use rand::TryRngCore as _;

    let mut nonce = [0_u8; 16];
    let mut rng = rand::rngs::OsRng;
    rng.try_fill_bytes(&mut nonce).map_err(|error| {
        io::Error::other(format!("failed to generate webhook delivery id: {error}"))
    })?;
    Ok(format!(
        "{webhook_id}-{timestamp_ms}-{}",
        hex::encode(nonce)
    ))
}
pub fn enqueue_event_for_matching_webhooks(
    event: &iroha_data_model::events::EventBox,
    content_type: &str,
) {
    if !delivery_content_type_is_valid(content_type) {
        iroha_logger::warn!("dropping webhook event with an invalid content type");
        return;
    }
    if let Err(error) = ensure_dirs() {
        iroha_logger::warn!(%error, "failed to prepare webhook queue storage");
        return;
    }
    if content_type.len() > WEBHOOK_DELIVERY_METADATA_MAX_BYTES {
        iroha_logger::warn!(
            actual = content_type.len(),
            maximum = WEBHOOK_DELIVERY_METADATA_MAX_BYTES,
            "dropping webhook event with oversized content type"
        );
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    // Snapshot registry to minimize lock duration
    let entries: Vec<(u64, RegisteredWebhook)> = lock_registry()
        .items
        .iter()
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    let json_val = crate::routing::event_to_json_value(event);
    let body = match norito::json::to_json(&json_val) {
        Ok(s) => s.into_bytes(),
        Err(e) => {
            iroha_logger::warn!(%e, "failed to serialize event for webhook");
            return;
        }
    };
    if body.len() > WEBHOOK_DELIVERY_MAX_BYTES {
        iroha_logger::warn!(
            actual = body.len(),
            maximum = WEBHOOK_DELIVERY_MAX_BYTES,
            "dropping oversized webhook event"
        );
        return;
    }
    let event_rows = webhook_event_rows(event);
    let policy = webhook_policy();
    let mut admission = match QueueAdmission::begin(policy) {
        Ok(admission) => admission,
        Err(err) => {
            iroha_logger::warn!(%err, "failed to inspect webhook queue capacity");
            return;
        }
    };
    for (id, registered) in entries {
        let w = registered.entry;
        if !w.active {
            continue;
        }
        if admission.is_full() {
            iroha_logger::warn!(
                capacity = effective_queue_capacity(policy),
                "webhook queue at capacity; dropping new deliveries"
            );
            break;
        }
        if let Some(ref expr) = w.filter {
            if !event_rows_match_filter(&event_rows, expr) {
                continue;
            }
        }
        let delivery_id = match new_delivery_id(id, now) {
            Ok(delivery_id) => delivery_id,
            Err(error) => {
                iroha_logger::warn!(%error, webhook_id = id, "failed to create webhook delivery id");
                continue;
            }
        };
        if !delivery_metadata_is_bounded(&delivery_id, &w.url, content_type) {
            iroha_logger::warn!(
                webhook_id = id,
                maximum = WEBHOOK_DELIVERY_METADATA_MAX_BYTES,
                "dropping webhook event with oversized metadata"
            );
            continue;
        }
        let pd = PendingDelivery {
            id: delivery_id,
            webhook_id: id,
            webhook_generation: registered.generation,
            url: w.url.clone(),
            content_type: content_type.to_string(),
            signature: w
                .secret
                .as_deref()
                .map(|secret| format!("sha256={}", hmac_sha256_hex(secret.as_bytes(), &body))),
            body: body.clone(),
            attempts: 0,
            next_attempt_ms: now,
        };
        if let Err(err) = admission.persist(&pd) {
            iroha_logger::warn!(%err, "failed to persist webhook payload");
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
enum WebhookFilterValidationError {
    #[error(transparent)]
    Structure(#[from] crate::filter::ValidateError),
    #[error("unsupported webhook filter field: {0}")]
    UnsupportedField(String),
    #[error("operator {operator} is not supported for webhook filter field {field}")]
    UnsupportedOperator {
        field: String,
        operator: &'static str,
    },
    #[error("invalid webhook filter value for {field}: expected {expected}")]
    InvalidValue {
        field: String,
        expected: &'static str,
    },
}

fn invalid_webhook_filter_value(
    field: &str,
    expected: &'static str,
) -> WebhookFilterValidationError {
    WebhookFilterValidationError::InvalidValue {
        field: field.to_owned(),
        expected,
    }
}

fn webhook_filter_field_is_supported(field: &str) -> bool {
    matches!(
        field,
        "tx_status"
            | "tx_hash"
            | "tx_block_height"
            | "block_status"
            | "block_height"
            | "event_kind"
            | "peer_id"
            | "domain_id"
            | "account_id"
            | "asset_id"
            | "asset_definition_id"
            | "nft_id"
            | "rwa_id"
            | "data_trigger_id"
            | "role_id"
            | "proof_id"
            | "peer_event"
            | "domain_event"
            | "account_event"
            | "asset_event"
            | "asset_definition_event"
            | "nft_event"
            | "rwa_event"
            | "role_event"
            | "configuration_event"
            | "executor_event"
            | "time_precommit"
            | "execute_trigger_id"
            | "execute_trigger_authority"
            | "trigger_completed_id"
            | "trigger_completed_outcome"
            | "proof_backend"
            | "proof_call_hash"
            | "proof_envelope_hash"
    )
}

fn validate_canonical_webhook_id<T>(
    field: &str,
    value: &norito::json::Value,
    expected: &'static str,
) -> Result<(), WebhookFilterValidationError>
where
    T: FromStr + ToString,
{
    let Some(literal) = value.as_str() else {
        return Err(invalid_webhook_filter_value(field, expected));
    };
    let Ok(parsed) = literal.parse::<T>() else {
        return Err(invalid_webhook_filter_value(field, expected));
    };
    if parsed.to_string() != literal {
        return Err(invalid_webhook_filter_value(field, expected));
    }
    Ok(())
}

fn validate_webhook_filter_value(
    field: &str,
    value: &norito::json::Value,
) -> Result<(), WebhookFilterValidationError> {
    let string_matches = |allowed: &[&str], expected| {
        value
            .as_str()
            .filter(|literal| allowed.contains(literal))
            .map(|_| ())
            .ok_or_else(|| invalid_webhook_filter_value(field, expected))
    };
    match field {
        "tx_status" => string_matches(
            &["Queued", "Expired", "Approved", "Rejected"],
            "a transaction status",
        ),
        "block_status" => string_matches(
            &["Created", "Approved", "Rejected", "Committed", "Applied"],
            "a block status",
        ),
        "event_kind" => string_matches(
            &[
                "Pipeline",
                "Data",
                "Time",
                "ExecuteTrigger",
                "TriggerCompleted",
            ],
            "an event kind",
        ),
        "peer_event" => string_matches(&["Added", "Removed"], "a peer event"),
        "domain_event" => string_matches(
            &[
                "Created",
                "Deleted",
                "AssetDefinition",
                "Asset",
                "Nft",
                "Rwa",
                "Account",
                "AccountLinked",
                "AccountUnlinked",
                "MetadataInserted",
                "MetadataRemoved",
                "OwnerChanged",
                "KaigiRosterSummary",
                "KaigiRelayRegistered",
                "KaigiRelayManifestUpdated",
                "KaigiUsageSummary",
                "KaigiRelayHealthUpdated",
                "StreamingTicketReady",
                "StreamingTicketRevoked",
                "KaigiRelayUnregistered",
                "KaigiStatusChanged",
            ],
            "a domain event",
        ),
        "account_event" => string_matches(
            &[
                "Created",
                "Deleted",
                "ControllerReplaced",
                "PermissionAdded",
                "PermissionRemoved",
                "RoleGranted",
                "RoleRevoked",
                "MetadataInserted",
                "MetadataRemoved",
                "Recovery",
                "Repo",
            ],
            "an account event",
        ),
        "asset_event" => string_matches(
            &[
                "Created",
                "Deleted",
                "Added",
                "Removed",
                "Transferred",
                "MetadataInserted",
                "MetadataRemoved",
                "BatchTransferOutcome",
            ],
            "an asset event",
        ),
        "asset_definition_event" => string_matches(
            &[
                "Created",
                "Deleted",
                "MetadataInserted",
                "MetadataRemoved",
                "MintabilityChanged",
                "MintabilityChangedDetailed",
                "TotalQuantityChanged",
                "OwnerChanged",
            ],
            "an asset-definition event",
        ),
        "nft_event" => string_matches(
            &[
                "Created",
                "Deleted",
                "MetadataInserted",
                "MetadataRemoved",
                "OwnerChanged",
            ],
            "an NFT event",
        ),
        "rwa_event" => string_matches(
            &[
                "Created",
                "MetadataInserted",
                "MetadataRemoved",
                "OwnerChanged",
                "Split",
                "Merged",
                "Redeemed",
                "Frozen",
                "Unfrozen",
                "Held",
                "Released",
                "ForceTransferred",
                "ControlsChanged",
            ],
            "an RWA event",
        ),
        "role_event" => string_matches(
            &["Created", "Deleted", "PermissionAdded", "PermissionRemoved"],
            "a role event",
        ),
        "configuration_event" => string_matches(&["Changed"], "a configuration event"),
        "executor_event" => string_matches(&["Upgraded"], "an executor event"),
        "trigger_completed_outcome" => string_matches(&["Success", "Failure"], "a trigger outcome"),
        "time_precommit" => value
            .as_bool()
            .map(|_| ())
            .ok_or_else(|| invalid_webhook_filter_value(field, "a boolean")),
        "tx_block_height" => {
            if value.is_null() || value.as_u64().is_some() {
                Ok(())
            } else {
                Err(invalid_webhook_filter_value(
                    field,
                    "an unsigned integer or null",
                ))
            }
        }
        "block_height" => value
            .as_u64()
            .map(|_| ())
            .ok_or_else(|| invalid_webhook_filter_value(field, "an unsigned integer")),
        "proof_call_hash" | "proof_envelope_hash" => {
            if value.is_null() {
                return Ok(());
            }
            let Some(literal) = value.as_str() else {
                return Err(invalid_webhook_filter_value(
                    field,
                    "64 lowercase hexadecimal digits or null",
                ));
            };
            let Some(bytes) = hex::decode(literal).ok().filter(|bytes| bytes.len() == 32) else {
                return Err(invalid_webhook_filter_value(
                    field,
                    "64 lowercase hexadecimal digits or null",
                ));
            };
            if hex::encode(bytes) != literal {
                return Err(invalid_webhook_filter_value(
                    field,
                    "64 lowercase hexadecimal digits or null",
                ));
            }
            Ok(())
        }
        "proof_backend" => {
            let Some(literal) = value.as_str() else {
                return Err(invalid_webhook_filter_value(
                    field,
                    "a non-empty backend identifier",
                ));
            };
            if literal.is_empty() || literal.trim() != literal {
                return Err(invalid_webhook_filter_value(
                    field,
                    "a non-empty backend identifier",
                ));
            }
            Ok(())
        }
        "tx_hash" => validate_canonical_webhook_id::<
            iroha_crypto::HashOf<iroha_data_model::transaction::signed::SignedTransaction>,
        >(field, value, "a canonical transaction hash"),
        "peer_id" => validate_canonical_webhook_id::<iroha_model_base::peer::PeerId>(
            field,
            value,
            "a canonical peer ID",
        ),
        "domain_id" => {
            let Some(literal) = value.as_str() else {
                return Err(invalid_webhook_filter_value(field, "a canonical domain ID"));
            };
            let Some(id) = iroha_model_base::domain::DomainId::parse_fully_qualified(literal).ok()
            else {
                return Err(invalid_webhook_filter_value(field, "a canonical domain ID"));
            };
            if id.to_string() != literal {
                return Err(invalid_webhook_filter_value(field, "a canonical domain ID"));
            }
            Ok(())
        }
        "account_id" | "execute_trigger_authority" => {
            let Some(literal) = value.as_str() else {
                return Err(invalid_webhook_filter_value(
                    field,
                    "a canonical account ID",
                ));
            };
            parse_account_id_literal(literal)
                .map(|_| ())
                .ok_or_else(|| invalid_webhook_filter_value(field, "a canonical account ID"))
        }
        "asset_id" => validate_canonical_webhook_id::<iroha_data_model::asset::AssetId>(
            field,
            value,
            "a canonical asset ID",
        ),
        "asset_definition_id" => validate_canonical_webhook_id::<
            iroha_data_model::asset::AssetDefinitionId,
        >(field, value, "a canonical asset-definition ID"),
        "nft_id" => validate_canonical_webhook_id::<iroha_data_model::nft::NftId>(
            field,
            value,
            "a canonical NFT ID",
        ),
        "rwa_id" => validate_canonical_webhook_id::<iroha_data_model::rwa::RwaId>(
            field,
            value,
            "a canonical RWA ID",
        ),
        "data_trigger_id" | "execute_trigger_id" | "trigger_completed_id" => {
            validate_canonical_webhook_id::<iroha_data_model::trigger::TriggerId>(
                field,
                value,
                "a canonical trigger ID",
            )
        }
        "role_id" => validate_canonical_webhook_id::<iroha_data_model::role::RoleId>(
            field,
            value,
            "a canonical role ID",
        ),
        "proof_id" => proof_id_from_json(value)
            .map(|_| ())
            .ok_or_else(|| invalid_webhook_filter_value(field, "a canonical proof ID")),
        _ => Err(WebhookFilterValidationError::UnsupportedField(
            field.to_owned(),
        )),
    }
}

fn validate_webhook_filter(
    expr: &crate::filter::FilterExpr,
) -> Result<(), WebhookFilterValidationError> {
    use crate::filter::FilterExpr as F;

    crate::filter::validate_filter(expr)?;

    fn validate_ordering(
        field: &str,
        value: &norito::json::Value,
        operator: &'static str,
    ) -> Result<(), WebhookFilterValidationError> {
        if !matches!(field, "tx_block_height" | "block_height") {
            return Err(WebhookFilterValidationError::UnsupportedOperator {
                field: field.to_owned(),
                operator,
            });
        }
        value
            .as_u64()
            .map(|_| ())
            .ok_or_else(|| invalid_webhook_filter_value(field, "an unsigned integer"))
    }

    fn visit(expr: &F) -> Result<(), WebhookFilterValidationError> {
        match expr {
            F::And(children) | F::Or(children) => {
                for child in children {
                    visit(child)?;
                }
                Ok(())
            }
            F::Not(inner) => visit(inner),
            F::Eq(field, value) | F::Ne(field, value) => {
                validate_webhook_filter_value(&field.0, value)
            }
            F::Lt(field, value) => validate_ordering(&field.0, value, "lt"),
            F::Lte(field, value) => validate_ordering(&field.0, value, "lte"),
            F::Gt(field, value) => validate_ordering(&field.0, value, "gt"),
            F::Gte(field, value) => validate_ordering(&field.0, value, "gte"),
            F::In(field, values) | F::Nin(field, values) => {
                for value in values {
                    validate_webhook_filter_value(&field.0, value)?;
                }
                Ok(())
            }
            F::Exists(field) | F::IsNull(field) => {
                if webhook_filter_field_is_supported(&field.0) {
                    Ok(())
                } else {
                    Err(WebhookFilterValidationError::UnsupportedField(
                        field.0.clone(),
                    ))
                }
            }
        }
    }

    visit(expr)
}

fn insert_webhook_event_field(
    fields: &mut norito::json::Map,
    name: &str,
    value: norito::json::Value,
) {
    fields.insert(name.to_owned(), value);
}

fn transaction_status_name(
    status: &iroha_data_model::events::pipeline::TransactionStatus,
) -> &'static str {
    use iroha_data_model::events::pipeline::TransactionStatus;
    match status {
        TransactionStatus::Queued => "Queued",
        TransactionStatus::Expired => "Expired",
        TransactionStatus::Approved => "Approved",
        TransactionStatus::Rejected(_) => "Rejected",
    }
}

fn block_status_name(status: iroha_data_model::events::pipeline::BlockStatus) -> &'static str {
    use iroha_data_model::events::pipeline::BlockStatus;
    match status {
        BlockStatus::Created => "Created",
        BlockStatus::Approved => "Approved",
        BlockStatus::Rejected(_) => "Rejected",
        BlockStatus::Committed => "Committed",
        BlockStatus::Applied => "Applied",
    }
}

fn pipeline_webhook_event_fields(
    event: &iroha_data_model::events::pipeline::PipelineEventBox,
) -> norito::json::Map {
    use iroha_data_model::events::pipeline::PipelineEventBox;

    let mut fields = norito::json::Map::new();
    insert_webhook_event_field(
        &mut fields,
        "event_kind",
        norito::json::Value::from("Pipeline"),
    );
    match event {
        PipelineEventBox::Transaction(event) => {
            insert_webhook_event_field(
                &mut fields,
                "tx_status",
                norito::json::Value::from(transaction_status_name(&event.status)),
            );
            insert_webhook_event_field(
                &mut fields,
                "tx_hash",
                norito::json::Value::from(event.hash.to_string()),
            );
            insert_webhook_event_field(
                &mut fields,
                "tx_block_height",
                event
                    .block_height
                    .map_or(norito::json::Value::Null, |height| {
                        norito::json::Value::from(height.get())
                    }),
            );
        }
        PipelineEventBox::Block(event) => {
            insert_webhook_event_field(
                &mut fields,
                "block_status",
                norito::json::Value::from(block_status_name(event.status)),
            );
            insert_webhook_event_field(
                &mut fields,
                "block_height",
                norito::json::Value::from(event.header.height().get()),
            );
        }
        PipelineEventBox::Warning(_) | PipelineEventBox::Witness(_) => {}
    }
    fields
}

fn insert_data_event_kind(fields: &mut norito::json::Map, field: &str, kind: &'static str) {
    insert_webhook_event_field(fields, field, norito::json::Value::from(kind));
}

fn data_webhook_event_fields(event: &DataEvent) -> norito::json::Map {
    use df::HasOrigin as _;
    use iroha_data_model::events::data::proof::ProofEvent;

    let mut fields = norito::json::Map::new();
    insert_webhook_event_field(&mut fields, "event_kind", norito::json::Value::from("Data"));
    match event {
        DataEvent::Peer(event) => {
            insert_webhook_event_field(
                &mut fields,
                "peer_id",
                norito::json::Value::from(event.origin().to_string()),
            );
            let kind = match event {
                df::PeerEvent::Added(_) => "Added",
                df::PeerEvent::Removed(_) => "Removed",
            };
            insert_data_event_kind(&mut fields, "peer_event", kind);
        }
        DataEvent::Domain(event) => {
            insert_webhook_event_field(
                &mut fields,
                "domain_id",
                norito::json::Value::from(event.origin().to_string()),
            );
            let kind = match event {
                df::DomainEvent::Created(_) => "Created",
                df::DomainEvent::Deleted(_) => "Deleted",
                df::DomainEvent::AssetDefinition(_) => "AssetDefinition",
                df::DomainEvent::Asset(_) => "Asset",
                df::DomainEvent::Nft(_) => "Nft",
                df::DomainEvent::Rwa(_) => "Rwa",
                df::DomainEvent::Account(_) => "Account",
                df::DomainEvent::AccountLinked(_) => "AccountLinked",
                df::DomainEvent::AccountUnlinked(_) => "AccountUnlinked",
                df::DomainEvent::MetadataInserted(_) => "MetadataInserted",
                df::DomainEvent::MetadataRemoved(_) => "MetadataRemoved",
                df::DomainEvent::OwnerChanged(_) => "OwnerChanged",
                df::DomainEvent::KaigiRosterSummary(_) => "KaigiRosterSummary",
                df::DomainEvent::KaigiRelayRegistered(_) => "KaigiRelayRegistered",
                df::DomainEvent::KaigiRelayManifestUpdated(_) => "KaigiRelayManifestUpdated",
                df::DomainEvent::KaigiUsageSummary(_) => "KaigiUsageSummary",
                df::DomainEvent::KaigiRelayHealthUpdated(_) => "KaigiRelayHealthUpdated",
                df::DomainEvent::StreamingTicketReady(_) => "StreamingTicketReady",
                df::DomainEvent::StreamingTicketRevoked(_) => "StreamingTicketRevoked",
                df::DomainEvent::KaigiRelayUnregistered(_) => "KaigiRelayUnregistered",
                df::DomainEvent::KaigiStatusChanged(_) => "KaigiStatusChanged",
            };
            insert_data_event_kind(&mut fields, "domain_event", kind);
            match event {
                df::DomainEvent::Nft(event) => {
                    insert_webhook_event_field(
                        &mut fields,
                        "nft_id",
                        norito::json::Value::from(event.origin().to_string()),
                    );
                    let kind = match event {
                        df::NftEvent::Created(_) => "Created",
                        df::NftEvent::Deleted(_) => "Deleted",
                        df::NftEvent::MetadataInserted(_) => "MetadataInserted",
                        df::NftEvent::MetadataRemoved(_) => "MetadataRemoved",
                        df::NftEvent::OwnerChanged(_) => "OwnerChanged",
                    };
                    insert_data_event_kind(&mut fields, "nft_event", kind);
                }
                df::DomainEvent::Rwa(event) => {
                    insert_webhook_event_field(
                        &mut fields,
                        "rwa_id",
                        norito::json::Value::from(event.origin().to_string()),
                    );
                    let kind = match event {
                        df::RwaEvent::Created(_) => "Created",
                        df::RwaEvent::MetadataInserted(_) => "MetadataInserted",
                        df::RwaEvent::MetadataRemoved(_) => "MetadataRemoved",
                        df::RwaEvent::OwnerChanged(_) => "OwnerChanged",
                        df::RwaEvent::Split(_) => "Split",
                        df::RwaEvent::Merged(_) => "Merged",
                        df::RwaEvent::Redeemed(_) => "Redeemed",
                        df::RwaEvent::Frozen(_) => "Frozen",
                        df::RwaEvent::Unfrozen(_) => "Unfrozen",
                        df::RwaEvent::Held(_) => "Held",
                        df::RwaEvent::Released(_) => "Released",
                        df::RwaEvent::ForceTransferred(_) => "ForceTransferred",
                        df::RwaEvent::ControlsChanged(_) => "ControlsChanged",
                    };
                    insert_data_event_kind(&mut fields, "rwa_event", kind);
                }
                _ => {}
            }
        }
        DataEvent::Account(event) => {
            insert_webhook_event_field(
                &mut fields,
                "account_id",
                norito::json::Value::from(event.origin().to_string()),
            );
            let kind = match event {
                df::AccountEvent::Created(_) => "Created",
                df::AccountEvent::Deleted(_) => "Deleted",
                df::AccountEvent::ControllerReplaced(_) => "ControllerReplaced",
                df::AccountEvent::PermissionAdded(_) => "PermissionAdded",
                df::AccountEvent::PermissionRemoved(_) => "PermissionRemoved",
                df::AccountEvent::RoleGranted(_) => "RoleGranted",
                df::AccountEvent::RoleRevoked(_) => "RoleRevoked",
                df::AccountEvent::MetadataInserted(_) => "MetadataInserted",
                df::AccountEvent::MetadataRemoved(_) => "MetadataRemoved",
                df::AccountEvent::Recovery(_) => "Recovery",
                df::AccountEvent::Repo(_) => "Repo",
            };
            insert_data_event_kind(&mut fields, "account_event", kind);
        }
        DataEvent::Asset(event) => {
            insert_webhook_event_field(
                &mut fields,
                "asset_id",
                norito::json::Value::from(event.origin().to_string()),
            );
            let kind = match event {
                df::AssetEvent::Created(_) => "Created",
                df::AssetEvent::Deleted(_) => "Deleted",
                df::AssetEvent::Added(_) => "Added",
                df::AssetEvent::Removed(_) => "Removed",
                df::AssetEvent::Transferred(_) => "Transferred",
                df::AssetEvent::MetadataInserted(_) => "MetadataInserted",
                df::AssetEvent::MetadataRemoved(_) => "MetadataRemoved",
                df::AssetEvent::BatchTransferOutcome(_) => "BatchTransferOutcome",
            };
            insert_data_event_kind(&mut fields, "asset_event", kind);
        }
        DataEvent::AssetDefinition(event) => {
            insert_webhook_event_field(
                &mut fields,
                "asset_definition_id",
                norito::json::Value::from(event.origin().to_string()),
            );
            let kind = match event {
                df::AssetDefinitionEvent::Created(_) => "Created",
                df::AssetDefinitionEvent::Deleted(_) => "Deleted",
                df::AssetDefinitionEvent::MetadataInserted(_) => "MetadataInserted",
                df::AssetDefinitionEvent::MetadataRemoved(_) => "MetadataRemoved",
                df::AssetDefinitionEvent::MintabilityChanged(_) => "MintabilityChanged",
                df::AssetDefinitionEvent::MintabilityChangedDetailed(_) => {
                    "MintabilityChangedDetailed"
                }
                df::AssetDefinitionEvent::TotalQuantityChanged(_) => "TotalQuantityChanged",
                df::AssetDefinitionEvent::OwnerChanged(_) => "OwnerChanged",
            };
            insert_data_event_kind(&mut fields, "asset_definition_event", kind);
        }
        DataEvent::Trigger(event) => {
            insert_webhook_event_field(
                &mut fields,
                "data_trigger_id",
                norito::json::Value::from(event.origin().to_string()),
            );
        }
        DataEvent::Role(event) => {
            insert_webhook_event_field(
                &mut fields,
                "role_id",
                norito::json::Value::from(event.origin().to_string()),
            );
            let kind = match event {
                df::RoleEvent::Created(_) => "Created",
                df::RoleEvent::Deleted(_) => "Deleted",
                df::RoleEvent::PermissionAdded(_) => "PermissionAdded",
                df::RoleEvent::PermissionRemoved(_) => "PermissionRemoved",
            };
            insert_data_event_kind(&mut fields, "role_event", kind);
        }
        DataEvent::Configuration(event) => {
            let kind = match event {
                df::ConfigurationEvent::Changed(_) => "Changed",
            };
            insert_data_event_kind(&mut fields, "configuration_event", kind);
        }
        DataEvent::Executor(event) => {
            let kind = match event {
                df::ExecutorEvent::Upgraded(_) => "Upgraded",
            };
            insert_data_event_kind(&mut fields, "executor_event", kind);
        }
        DataEvent::Proof(event) => match event {
            ProofEvent::Verified(event) => {
                insert_webhook_event_field(
                    &mut fields,
                    "proof_id",
                    norito::json::Value::from(event.id.to_string()),
                );
                insert_webhook_event_field(
                    &mut fields,
                    "proof_backend",
                    norito::json::Value::from(event.id.backend.clone()),
                );
                insert_webhook_event_field(
                    &mut fields,
                    "proof_call_hash",
                    event.call_hash.map_or(norito::json::Value::Null, |hash| {
                        norito::json::Value::from(hex::encode(hash))
                    }),
                );
                insert_webhook_event_field(
                    &mut fields,
                    "proof_envelope_hash",
                    event
                        .envelope_hash
                        .map_or(norito::json::Value::Null, |hash| {
                            norito::json::Value::from(hex::encode(hash))
                        }),
                );
            }
            ProofEvent::Rejected(event) => {
                insert_webhook_event_field(
                    &mut fields,
                    "proof_id",
                    norito::json::Value::from(event.id.to_string()),
                );
                insert_webhook_event_field(
                    &mut fields,
                    "proof_backend",
                    norito::json::Value::from(event.id.backend.clone()),
                );
                insert_webhook_event_field(
                    &mut fields,
                    "proof_call_hash",
                    event.call_hash.map_or(norito::json::Value::Null, |hash| {
                        norito::json::Value::from(hex::encode(hash))
                    }),
                );
                insert_webhook_event_field(
                    &mut fields,
                    "proof_envelope_hash",
                    event
                        .envelope_hash
                        .map_or(norito::json::Value::Null, |hash| {
                            norito::json::Value::from(hex::encode(hash))
                        }),
                );
            }
            ProofEvent::Pruned(event) => {
                insert_webhook_event_field(
                    &mut fields,
                    "proof_backend",
                    norito::json::Value::from(event.backend.clone()),
                );
            }
        },
        _ => {}
    }
    fields
}

fn webhook_event_rows(event: &iroha_data_model::events::EventBox) -> Vec<norito::json::Map> {
    use iroha_data_model::events::EventBox;

    match event {
        EventBox::Pipeline(event) => vec![pipeline_webhook_event_fields(event)],
        EventBox::PipelineBatch(events) => {
            events.iter().map(pipeline_webhook_event_fields).collect()
        }
        EventBox::Data(event) => vec![data_webhook_event_fields(event.as_ref())],
        EventBox::Time(_) => {
            let mut fields = norito::json::Map::new();
            insert_webhook_event_field(
                &mut fields,
                "event_kind",
                norito::json::Value::from("Time"),
            );
            insert_webhook_event_field(
                &mut fields,
                "time_precommit",
                norito::json::Value::from(true),
            );
            vec![fields]
        }
        EventBox::ExecuteTrigger(event) => {
            let mut fields = norito::json::Map::new();
            insert_webhook_event_field(
                &mut fields,
                "event_kind",
                norito::json::Value::from("ExecuteTrigger"),
            );
            insert_webhook_event_field(
                &mut fields,
                "execute_trigger_id",
                norito::json::Value::from(event.trigger_id().to_string()),
            );
            insert_webhook_event_field(
                &mut fields,
                "execute_trigger_authority",
                norito::json::Value::from(event.authority().to_string()),
            );
            vec![fields]
        }
        EventBox::TriggerCompleted(event) => {
            use iroha_data_model::events::trigger_completed::TriggerCompletedOutcome;

            let mut fields = norito::json::Map::new();
            insert_webhook_event_field(
                &mut fields,
                "event_kind",
                norito::json::Value::from("TriggerCompleted"),
            );
            insert_webhook_event_field(
                &mut fields,
                "trigger_completed_id",
                norito::json::Value::from(event.trigger_id().to_string()),
            );
            let outcome = match event.outcome() {
                TriggerCompletedOutcome::Success => "Success",
                TriggerCompletedOutcome::Failure(_) => "Failure",
            };
            insert_webhook_event_field(
                &mut fields,
                "trigger_completed_outcome",
                norito::json::Value::from(outcome),
            );
            vec![fields]
        }
    }
}

fn evaluate_webhook_filter(expr: &crate::filter::FilterExpr, fields: &norito::json::Map) -> bool {
    use crate::filter::FilterExpr as F;

    let numeric_order = |field: &crate::filter::FieldPath, expected: &norito::json::Value| {
        let actual = fields.get(&field.0)?.as_u64()?;
        let expected = expected.as_u64()?;
        Some(actual.cmp(&expected))
    };

    match expr {
        F::And(children) => children
            .iter()
            .all(|child| evaluate_webhook_filter(child, fields)),
        F::Or(children) => children
            .iter()
            .any(|child| evaluate_webhook_filter(child, fields)),
        F::Not(inner) => !evaluate_webhook_filter(inner, fields),
        F::Eq(field, expected) => fields
            .get(&field.0)
            .is_some_and(|actual| actual == expected),
        F::Ne(field, expected) => fields.get(&field.0).is_none_or(|actual| actual != expected),
        F::Lt(field, expected) => {
            numeric_order(field, expected).is_some_and(|order| order == core::cmp::Ordering::Less)
        }
        F::Lte(field, expected) => numeric_order(field, expected).is_some_and(|order| {
            matches!(
                order,
                core::cmp::Ordering::Less | core::cmp::Ordering::Equal
            )
        }),
        F::Gt(field, expected) => numeric_order(field, expected)
            .is_some_and(|order| order == core::cmp::Ordering::Greater),
        F::Gte(field, expected) => numeric_order(field, expected).is_some_and(|order| {
            matches!(
                order,
                core::cmp::Ordering::Greater | core::cmp::Ordering::Equal
            )
        }),
        F::In(field, expected) => fields
            .get(&field.0)
            .is_some_and(|actual| expected.iter().any(|candidate| candidate == actual)),
        F::Nin(field, expected) => fields
            .get(&field.0)
            .is_none_or(|actual| expected.iter().all(|candidate| candidate != actual)),
        F::Exists(field) => fields.contains_key(&field.0),
        F::IsNull(field) => fields
            .get(&field.0)
            .is_none_or(norito::json::Value::is_null),
    }
}

fn event_rows_match_filter(rows: &[norito::json::Map], expr: &crate::filter::FilterExpr) -> bool {
    rows.iter()
        .any(|fields| evaluate_webhook_filter(expr, fields))
}

#[cfg(test)]
fn event_matches_filter(
    event: &iroha_data_model::events::EventBox,
    expr: &crate::filter::FilterExpr,
) -> bool {
    event_rows_match_filter(&webhook_event_rows(event), expr)
}
fn value_to_filter_expr(v: &norito::json::Value) -> Option<crate::filter::FilterExpr> {
    let s = norito::json::to_json(v).ok()?;
    norito::json::from_str::<crate::filter::FilterExpr>(&s).ok()
}
fn io_timeout_error(operation: &str, duration: Duration) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{operation} timed out after {:?}", duration),
    )
}
fn io_invalid_input(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}
fn io_permission_denied(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message.into())
}
async fn resolve_destination_addrs(
    url: &Url,
    policy: &WebhookSecurityPolicy,
) -> std::io::Result<Vec<SocketAddr>> {
    let Some(host) = url.host() else {
        return Err(io_invalid_input("webhook url missing host"));
    };
    let Some(port) = url.port_or_known_default() else {
        return Err(io_invalid_input("webhook url missing port"));
    };
    if policy.enabled {
        if let Host::Domain(domain) = host {
            if is_localhost_domain(domain) {
                return Err(io_permission_denied(
                    "webhook destination host `localhost` is not allowed",
                ));
            }
        }
    }
    match host {
        Host::Ipv4(v4) => {
            let ip = IpAddr::V4(v4);
            if policy.enabled && !is_destination_ip_allowed(ip, policy) {
                return Err(io_permission_denied(
                    "webhook destination IP is not allowed",
                ));
            }
            Ok(vec![SocketAddr::new(ip, port)])
        }
        Host::Ipv6(v6) => {
            let ip = IpAddr::V6(v6);
            if policy.enabled && !is_destination_ip_allowed(ip, policy) {
                return Err(io_permission_denied(
                    "webhook destination IP is not allowed",
                ));
            }
            Ok(vec![SocketAddr::new(ip, port)])
        }
        Host::Domain(domain) => {
            let timeout = http_timeout_config().connect;
            let resolved = tokio::time::timeout(timeout, tokio::net::lookup_host((domain, port)))
                .await
                .map_err(|_| io_timeout_error("dns resolution", timeout))??;
            let addrs: Vec<SocketAddr> = resolved
                .take(WEBHOOK_DNS_MAX_ADDRESSES.saturating_add(1))
                .collect();
            if addrs.len() > WEBHOOK_DNS_MAX_ADDRESSES {
                return Err(io_invalid_input(format!(
                    "webhook destination resolved to more than {WEBHOOK_DNS_MAX_ADDRESSES} addresses"
                )));
            }
            if addrs.is_empty() {
                return Err(io_invalid_input(
                    "webhook destination resolved to no addresses",
                ));
            }
            if policy.enabled {
                for addr in &addrs {
                    if !is_destination_ip_allowed(addr.ip(), policy) {
                        return Err(io_permission_denied(
                            "webhook destination resolved to a disallowed IP",
                        ));
                    }
                }
            }
            Ok(addrs)
        }
    }
}
fn host_header_value(url: &Url) -> std::io::Result<String> {
    let Some(host) = url.host() else {
        return Err(io_invalid_input("webhook url missing host"));
    };
    let Some(port) = url.port_or_known_default() else {
        return Err(io_invalid_input("webhook url missing port"));
    };
    let known_default = match url.scheme() {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    };
    let host = match host {
        Host::Domain(domain) => domain.to_string(),
        Host::Ipv4(v4) => v4.to_string(),
        Host::Ipv6(v6) => format!("[{v6}]"),
    };
    let mut out = host;
    if known_default.is_some_and(|d| d != port) {
        out.push(':');
        out.push_str(&port.to_string());
    }
    Ok(out)
}
#[cfg(feature = "app_api_https")]
fn https_delivery_dns_override(
    url: &Url,
    connect_addrs: &[SocketAddr],
) -> Option<(String, Vec<SocketAddr>)> {
    match url.host() {
        // Preserve the original hostname for SNI / certificate verification while
        // pinning the actual connect target to the already-vetted address set.
        Some(Host::Domain(domain)) if !connect_addrs.is_empty() => {
            Some((domain.to_owned(), connect_addrs.to_vec()))
        }
        _ => None,
    }
}
#[cfg(feature = "app_api_wss")]
fn websocket_pinned_connect_addr(
    url: &Url,
    policy: &WebhookSecurityPolicy,
    connect_addrs: &[SocketAddr],
) -> Option<SocketAddr> {
    match url.scheme() {
        "ws" => connect_addrs.first().copied(),
        "wss" if policy.enabled => connect_addrs.first().copied(),
        _ => None,
    }
}
async fn http_post_plain(
    url: &Url,
    connect_addr: SocketAddr,
    host_header: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> std::io::Result<u16> {
    // Very small plain HTTP/1.1 client for http:// (no TLS).
    if url.scheme() != "http" {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid scheme for plain HTTP client",
        ))
    } else {
        let mut path = url.path().to_string();
        if path.is_empty() {
            path = "/".to_string();
        }
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        use tokio::{io::AsyncWriteExt, net::TcpStream};
        let timeouts = http_timeout_config();
        let mut stream =
            match tokio::time::timeout(timeouts.connect, TcpStream::connect(connect_addr)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(io_timeout_error("tcp connect", timeouts.connect)),
            };
        let mut req = Vec::new();
        req.extend_from_slice(format!("POST {} HTTP/1.1\r\n", path).as_bytes());
        req.extend_from_slice(format!("Host: {}\r\n", host_header).as_bytes());
        req.extend_from_slice(b"Connection: close\r\n");
        req.extend_from_slice(b"User-Agent: iroha-torii-webhook/1\r\n");
        for (k, v) in headers {
            req.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        req.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        req.extend_from_slice(b"\r\n");
        req.extend_from_slice(body);
        let write_result = tokio::time::timeout(timeouts.write, async {
            stream.write_all(&req).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| io_timeout_error("tcp write", timeouts.write))?;
        write_result?;

        tokio::time::timeout(timeouts.read, read_webhook_http_status(&mut stream))
            .await
            .map_err(|_| io_timeout_error("tcp read", timeouts.read))?
    }
}
async fn read_webhook_http_status<R>(reader: R) -> io::Result<u16>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncReadExt as _, BufReader};

    async fn read_line<R>(reader: &mut R, consumed: &mut usize) -> io::Result<Vec<u8>>
    where
        R: AsyncBufRead + Unpin,
    {
        let mut line = Vec::new();
        let read = reader.read_until(b'\n', &mut line).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "webhook response ended before its headers were complete",
            ));
        }
        *consumed = consumed.checked_add(read).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "webhook response size overflow")
        })?;
        ensure_webhook_http_response_is_bounded(*consumed)?;
        if !line.ends_with(b"\r\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "webhook response header line is not CRLF terminated",
            ));
        }
        Ok(line)
    }

    let mut reader =
        BufReader::new(reader.take(WEBHOOK_HTTP_RESPONSE_HEADER_MAX_BYTES.saturating_add(1)));
    let mut consumed = 0_usize;
    loop {
        let status_line = read_line(&mut reader, &mut consumed).await?;
        let status = parse_webhook_http_status_line(&status_line)?;
        loop {
            let line = read_line(&mut reader, &mut consumed).await?;
            if line == b"\r\n" {
                break;
            }
            validate_webhook_http_header_line(&line)?;
        }
        // RFC 9110 permits one or more informational responses before the
        // final response. A protocol switch is itself final for this client.
        if !(100..200).contains(&status) || status == 101 {
            return Ok(status);
        }
    }
}
fn parse_webhook_http_status_line(line: &[u8]) -> io::Result<u16> {
    let line = line.strip_suffix(b"\r\n").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "webhook response status line is not CRLF terminated",
        )
    })?;
    let line = core::str::from_utf8(line).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "webhook response status line is not valid ASCII",
        )
    })?;
    if !line.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "webhook response status line is not valid ASCII",
        ));
    }
    let mut fields = line.splitn(3, ' ');
    let version = fields.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "webhook response uses an unsupported HTTP version",
        ));
    }
    let code = fields.next().unwrap_or_default();
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "webhook response contains an invalid status code",
        ));
    }
    let code = code.parse::<u16>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "webhook response contains an invalid status code",
        )
    })?;
    if !(100..600).contains(&code) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "webhook response status code is outside the HTTP range",
        ));
    }
    Ok(code)
}
fn validate_webhook_http_header_line(line: &[u8]) -> io::Result<()> {
    let line = line.strip_suffix(b"\r\n").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "webhook response header line is not CRLF terminated",
        )
    })?;
    let separator = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "webhook response contains a malformed header",
        )
    })?;
    HeaderName::from_bytes(&line[..separator]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "webhook response contains an invalid header name",
        )
    })?;
    HeaderValue::from_bytes(&line[separator + 1..]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "webhook response contains an invalid header value",
        )
    })?;
    Ok(())
}
fn ensure_webhook_http_response_is_bounded(length: usize) -> std::io::Result<()> {
    if u64::try_from(length).unwrap_or(u64::MAX) > WEBHOOK_HTTP_RESPONSE_HEADER_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "webhook response headers exceeded the {WEBHOOK_HTTP_RESPONSE_HEADER_MAX_BYTES}-byte protocol limit"
            ),
        ));
    }
    Ok(())
}
#[cfg(feature = "app_api_https")]
fn webhook_https_client_builder() -> reqwest::ClientBuilder {
    let timeouts = http_timeout_config();
    reqwest::Client::builder()
        .timeout(timeouts.connect + timeouts.write + timeouts.read)
        .connect_timeout(timeouts.connect)
        .read_timeout(timeouts.read)
        .http1_only()
        // Proxy environment variables would let the proxy resolve and contact
        // a destination independently of the address set vetted below.
        .no_proxy()
        // The destination policy and DNS pin apply to exactly one URL. Following
        // a redirect would let the remote endpoint choose an unvetted host.
        .redirect(reqwest::redirect::Policy::none())
}
#[cfg(feature = "app_api_https")]
async fn http_post_https(
    url: &Url,
    connect_addrs: &[SocketAddr],
    headers: &[(&str, String)],
    body: &[u8],
) -> std::io::Result<u16> {
    use reqwest::header::{HeaderName, HeaderValue};
    let mut client_builder = webhook_https_client_builder();
    if let Some((domain, pinned_addrs)) = https_delivery_dns_override(url, connect_addrs) {
        client_builder = client_builder.resolve_to_addrs(&domain, &pinned_addrs);
    }
    let client = client_builder
        .build()
        .map_err(|e| std::io::Error::other(format!("https client build: {e}")))?;
    let mut req = client
        .post(url.as_str())
        .header("User-Agent", "iroha-torii-webhook/1")
        .header("Connection", "close");
    for (k, v) in headers {
        let name = HeaderName::from_str(k)
            .map_err(|error| io_invalid_input(format!("invalid webhook header name: {error}")))?;
        let value = HeaderValue::from_str(v)
            .map_err(|error| io_invalid_input(format!("invalid webhook header value: {error}")))?;
        req = req.header(name, value);
    }
    let resp = req
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| std::io::Error::other(format!("https req: {e}")))?;
    Ok(resp.status().as_u16())
}
async fn http_post(url: &str, headers: &[(&str, String)], body: &[u8]) -> std::io::Result<u16> {
    validate_webhook_outbound_headers(headers)?;
    let parsed = Url::parse(url).map_err(|e| io_invalid_input(format!("bad url: {e}")))?;
    let policy = webhook_security_policy();
    validate_parsed_webhook_url(&parsed, &policy).map_err(|(status, message)| {
        if status == StatusCode::FORBIDDEN {
            io_permission_denied(message)
        } else {
            io_invalid_input(message)
        }
    })?;
    #[cfg(test)]
    if let Some(handler) = http_post_override_handler() {
        return handler(url, headers, body);
    }
    let scheme = parsed.scheme();
    if scheme == "https" {
        #[cfg(feature = "app_api_https")]
        {
            let connect_addrs = if policy.enabled {
                resolve_destination_addrs(&parsed, &policy).await?
            } else {
                Vec::new()
            };
            return http_post_https(&parsed, &connect_addrs, headers, body).await;
        }
        #[cfg(not(feature = "app_api_https"))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "HTTPS not supported; enable feature app_api_https",
            ));
        }
    }
    #[cfg(feature = "app_api_wss")]
    if scheme == "wss" || scheme == "ws" {
        let connect_addrs = if scheme == "ws" || policy.enabled {
            resolve_destination_addrs(&parsed, &policy).await?
        } else {
            Vec::new()
        };
        let connect_addr = websocket_pinned_connect_addr(&parsed, &policy, &connect_addrs);
        return ws_send(&parsed, connect_addr, headers, body).await;
    }
    #[cfg(not(feature = "app_api_wss"))]
    if scheme == "wss" || scheme == "ws" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "WS/WSS not supported; enable feature app_api_wss",
        ));
    }
    if scheme != "http" {
        return Err(io_invalid_input(format!(
            "unsupported webhook scheme `{scheme}`"
        )));
    }
    let addrs = resolve_destination_addrs(&parsed, &policy).await?;
    let Some(connect_addr) = addrs.into_iter().next() else {
        return Err(io_invalid_input(
            "webhook destination resolved to no addresses",
        ));
    };
    let host_header = host_header_value(&parsed)?;
    http_post_plain(&parsed, connect_addr, &host_header, headers, body).await
}
fn validate_webhook_outbound_headers(headers: &[(&str, String)]) -> io::Result<()> {
    for (name, value) in headers {
        HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
            io_invalid_input(format!("invalid webhook header name `{name}`: {error}"))
        })?;
        HeaderValue::from_str(value).map_err(|error| {
            io_invalid_input(format!(
                "invalid webhook header value for `{name}`: {error}"
            ))
        })?;
    }
    Ok(())
}
#[cfg(feature = "app_api_wss")]
async fn ws_send(
    url: &Url,
    connect_addr: Option<SocketAddr>,
    headers: &[(&str, String)],
    body: &[u8],
) -> std::io::Result<u16> {
    use futures::SinkExt as _;
    use std::str::FromStr;
    use tokio_tungstenite::{client_async_tls_with_config, connect_async};
    use tungstenite::{
        Message,
        client::IntoClientRequest,
        http::{HeaderName, HeaderValue},
    };
    let mut req = url.as_str().into_client_request().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("bad url: {e}"))
    })?;
    for (k, v) in headers {
        let name = HeaderName::from_str(k)
            .map_err(|error| io_invalid_input(format!("invalid webhook header name: {error}")))?;
        let value = HeaderValue::from_str(v)
            .map_err(|error| io_invalid_input(format!("invalid webhook header value: {error}")))?;
        req.headers_mut().insert(name, value);
    }
    let timeouts = http_timeout_config();
    let (mut ws, _resp) = match connect_addr {
        Some(addr) => {
            use tokio::net::TcpStream;
            let stream = tokio::time::timeout(timeouts.connect, TcpStream::connect(addr))
                .await
                .map_err(|_| io_timeout_error("tcp connect", timeouts.connect))??;
            tokio::time::timeout(
                timeouts.connect,
                client_async_tls_with_config(req, stream, None, None),
            )
            .await
            .map_err(|_| io_timeout_error("websocket handshake", timeouts.connect))?
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("ws connect: {e}"))
            })?
        }
        None => tokio::time::timeout(timeouts.connect, connect_async(req))
            .await
            .map_err(|_| io_timeout_error("websocket connect", timeouts.connect))?
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("ws connect: {e}"))
            })?,
    };
    tokio::time::timeout(
        timeouts.write,
        ws.send(Message::Binary(body.to_vec().into())),
    )
    .await
    .map_err(|_| io_timeout_error("websocket write", timeouts.write))?
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("ws send: {e}")))?;
    let _ = tokio::time::timeout(timeouts.write, ws.close(None)).await;
    Ok(200)
}
fn backoff_delay(policy: &WebhookPolicy, attempts: u32) -> Duration {
    let base_ms = policy.backoff_initial.as_millis().max(1);
    let max_ms = policy.backoff_max.as_millis().max(base_ms);
    let pow = attempts.saturating_sub(1).min(31);
    let delay_ms = base_ms.saturating_mul(1u128 << pow).min(max_ms);
    Duration::from_millis(delay_ms as u64)
}
async fn try_deliver(pd: &PendingDelivery) -> bool {
    let mut headers = vec![("Content-Type", pd.content_type.clone())];
    if let Some(signature) = &pd.signature {
        headers.push(("X-Iroha-Webhook-Signature", signature.clone()));
    }
    match http_post(&pd.url, &headers, &pd.body).await {
        Ok(code) if (200..300).contains(&code) => true,
        Ok(code) => {
            iroha_logger::warn!(code, url=%pd.url, "webhook delivery returned non-2xx");
            false
        }
        Err(e) => {
            if matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput
            ) {
                iroha_logger::warn!(
                    %e,
                    url=%pd.url,
                    "dropping webhook payload due to disallowed destination"
                );
                return true;
            }
            if e.kind() == std::io::ErrorKind::TimedOut {
                iroha_logger::warn!(%e, url=%pd.url, "webhook delivery timed out");
            } else {
                iroha_logger::warn!(%e, url=%pd.url, "webhook delivery failed");
            }
            false
        }
    }
}
/// Spawn the background delivery worker after persistence initialization.
pub fn start_delivery_worker(
    shutdown: ShutdownSignal,
) -> tokio::task::JoinHandle<crate::ToriiCriticalWorkerExit> {
    tokio::spawn(async move {
        loop {
            let delay = tokio::select! {
                () = shutdown.receive() => {
                    return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                }
                delay = process_queue_once() => delay,
            };
            if !delay.is_zero() {
                tokio::select! {
                    () = shutdown.receive() => {
                        return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                    }
                    () = tokio::time::sleep(delay) => {}
                }
            }
        }
    })
}
#[cfg(test)]
struct QueueScanState {
    root: PathBuf,
    capacity: usize,
    entries: fs::ReadDir,
    retained: usize,
}
#[cfg(test)]
#[derive(Default)]
struct QueueScanCursor {
    state: Option<QueueScanState>,
}
struct QueueScanBatch {
    directory: Option<Arc<WebhookDirectory>>,
    paths: Vec<PathBuf>,
    overflow_paths: Vec<PathBuf>,
    sweep_complete: bool,
}
#[cfg(test)]
fn discover_queue_batch_at(
    cursor: &mut QueueScanCursor,
    root: &Path,
    capacity: usize,
    batch_limit: usize,
    work_limit: usize,
) -> std::io::Result<QueueScanBatch> {
    if cursor
        .state
        .as_ref()
        .is_none_or(|state| state.root != root || state.capacity != capacity)
    {
        cursor.state = Some(QueueScanState {
            root: root.to_path_buf(),
            capacity,
            entries: fs::read_dir(root)?,
            retained: 0,
        });
    }
    let mut paths = Vec::with_capacity(batch_limit);
    let mut overflow_paths = Vec::new();
    let mut work = 0_usize;
    let mut sweep_complete = false;
    while paths.len().saturating_add(overflow_paths.len()) < batch_limit && work < work_limit {
        let next = cursor
            .state
            .as_mut()
            .expect("queue scan state initialized")
            .entries
            .next();
        let Some(entry) = next else {
            cursor.state = None;
            sweep_complete = true;
            break;
        };
        work = work.saturating_add(1);
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                cursor.state = None;
                return Err(err);
            }
        };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let state = cursor
            .state
            .as_mut()
            .expect("queue scan state remains initialized");
        if state.retained < capacity {
            state.retained = state.retained.saturating_add(1);
            paths.push(path);
        } else {
            // Overflow records are removed without reading or decoding them.
            overflow_paths.push(path);
        }
    }
    paths.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    overflow_paths.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(QueueScanBatch {
        directory: None,
        paths,
        overflow_paths,
        sweep_complete,
    })
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
struct SecureQueueScanState {
    root: PathBuf,
    capacity: usize,
    directory: Arc<WebhookDirectory>,
    entries: rustix::fs::Dir,
    retained: usize,
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[derive(Default)]
struct SecureQueueScanCursor {
    state: Option<SecureQueueScanState>,
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn secure_queue_scan_cursor() -> &'static Mutex<SecureQueueScanCursor> {
    static CURSOR: OnceLock<Mutex<SecureQueueScanCursor>> = OnceLock::new();
    CURSOR.get_or_init(|| Mutex::new(SecureQueueScanCursor::default()))
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn discover_queue_batch(policy: WebhookPolicy) -> std::io::Result<QueueScanBatch> {
    use std::os::unix::ffi::OsStrExt as _;

    let root = queue_dir();
    let capacity = effective_queue_capacity(policy);
    let mut cursor = lock_unpoisoned(secure_queue_scan_cursor());
    if cursor
        .state
        .as_ref()
        .is_none_or(|state| state.root != root || state.capacity != capacity)
    {
        let directory = Arc::new(open_webhook_queue_directory(true)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "webhook queue directory is unavailable",
            )
        })?);
        let entries = rustix::fs::Dir::read_from(&directory.file).map_err(io::Error::from)?;
        cursor.state = Some(SecureQueueScanState {
            root: root.clone(),
            capacity,
            directory,
            entries,
            retained: 0,
        });
    }
    let directory = Arc::clone(
        &cursor
            .state
            .as_ref()
            .expect("secure queue scan state initialized")
            .directory,
    );
    let mut paths = Vec::with_capacity(WEBHOOK_QUEUE_SCAN_BATCH_SIZE);
    let mut overflow_paths = Vec::new();
    let mut work = 0_usize;
    let mut sweep_complete = false;
    while paths.len().saturating_add(overflow_paths.len()) < WEBHOOK_QUEUE_SCAN_BATCH_SIZE
        && work < WEBHOOK_QUEUE_SCAN_WORK_ITEMS
    {
        let next = cursor
            .state
            .as_mut()
            .expect("secure queue scan state initialized")
            .entries
            .next();
        let Some(entry) = next else {
            cursor.state = None;
            sweep_complete = true;
            break;
        };
        work = work.saturating_add(1);
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                cursor.state = None;
                return Err(io::Error::from(error));
            }
        };
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        let name = OsStr::from_bytes(bytes);
        if Path::new(name).extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let path = directory.path.join(name);
        let state = cursor
            .state
            .as_mut()
            .expect("secure queue scan state remains initialized");
        if state.retained < capacity {
            state.retained = state.retained.saturating_add(1);
            paths.push(path);
        } else {
            overflow_paths.push(path);
        }
    }
    paths.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    overflow_paths.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(QueueScanBatch {
        directory: Some(directory),
        paths,
        overflow_paths,
        sweep_complete,
    })
}
#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn discover_queue_batch(_policy: WebhookPolicy) -> std::io::Result<QueueScanBatch> {
    Err(unsupported_webhook_persistence())
}
#[cfg(all(test, any(target_vendor = "apple", target_os = "linux")))]
fn prune_verified_queue_overflow(
    paths: Vec<PathBuf>,
    policy: WebhookPolicy,
) -> std::io::Result<usize> {
    let directory = open_webhook_queue_directory(true)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "webhook queue directory is unavailable",
        )
    })?;
    prune_verified_queue_overflow_in(&directory, paths, policy)
}
fn prune_verified_queue_overflow_in(
    directory: &WebhookDirectory,
    paths: Vec<PathBuf>,
    policy: WebhookPolicy,
) -> std::io::Result<usize> {
    if paths.is_empty() {
        return Ok(0);
    }
    // Hold admission while re-counting and pruning. Files may have been
    // delivered since this streaming cursor classified the paths, so only the
    // currently verified excess is removed.
    let _guard = lock_unpoisoned(queue_write_lock());
    let capacity = effective_queue_capacity(policy);
    let observed = queue_depth_bounded_in(
        directory,
        capacity.saturating_add(paths.len()),
        WEBHOOK_QUEUE_ADMISSION_SCAN_WORK_ITEMS,
    )?;
    let mut remaining_excess = observed.saturating_sub(capacity).min(paths.len());
    let mut removed = 0_usize;
    for path in paths {
        if remaining_excess == 0 {
            break;
        }
        match unlink_private_webhook_entry(directory, &path, None, false) {
            Ok(()) => {
                remaining_excess = remaining_excess.saturating_sub(1);
                removed = removed.saturating_add(1);
                iroha_logger::warn!(
                    ?path,
                    capacity,
                    "removed webhook queue record beyond hard capacity"
                );
            }
            Err(err) => {
                iroha_logger::warn!(%err, ?path, "failed to remove excess webhook payload");
            }
        }
    }
    if removed != 0 {
        #[cfg(any(target_vendor = "apple", target_os = "linux"))]
        directory.file.sync_all()?;
    }
    Ok(removed)
}
async fn read_queue_file_bounded(
    directory: Arc<WebhookDirectory>,
    path: PathBuf,
) -> std::io::Result<BoundedWebhookFile> {
    run_queue_filesystem_operation(move || {
        read_private_webhook_file_bounded(&directory, &path, WEBHOOK_QUEUE_FILE_MAX_BYTES)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "webhook spool disappeared"))
    })
    .await
}
async fn remove_queue_file(
    directory: Arc<WebhookDirectory>,
    path: PathBuf,
    expected: Option<WebhookFileIdentity>,
) -> io::Result<()> {
    run_queue_filesystem_operation(move || {
        unlink_private_webhook_entry(&directory, &path, expected, true)
    })
    .await
}
async fn replace_queue_file(
    directory: Arc<WebhookDirectory>,
    path: PathBuf,
    expected: WebhookFileIdentity,
    bytes: Vec<u8>,
) -> io::Result<()> {
    run_queue_filesystem_operation(move || {
        write_private_webhook_file_atomic(
            &directory,
            &path,
            &bytes,
            WEBHOOK_QUEUE_FILE_MAX_BYTES,
            WebhookPublication::ReplaceIdentity(expected),
        )
    })
    .await
}
async fn run_queue_filesystem_operation<T>(
    operation: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T>
where
    T: Send + 'static,
{
    crate::panic_recovery::join_recoverable(crate::panic_recovery::spawn_blocking_recoverable(
        operation,
    ))
    .await
    .map_err(io::Error::other)?
}
fn decode_pending_delivery(bytes: &[u8]) -> Option<PendingDelivery> {
    if bytes.len() > WEBHOOK_QUEUE_FILE_MAX_BYTES {
        return None;
    }
    let norito::json::Value::Object(map) =
        norito::json::from_slice::<norito::json::Value>(bytes).ok()?
    else {
        return None;
    };
    let id = map.get("id")?.as_str()?;
    let webhook_id = map.get("webhook_id")?.as_u64()?;
    let webhook_generation = map
        .get("webhook_generation")?
        .as_str()
        .and_then(webhook_generation_from_hex)?;
    let url = map.get("url")?.as_str()?;
    let content_type = map.get("content_type")?.as_str()?;
    if !delivery_metadata_is_bounded(id, url, content_type)
        || !delivery_content_type_is_valid(content_type)
    {
        return None;
    }
    let signature = match map.get("signature")? {
        norito::json::Value::Null => None,
        norito::json::Value::String(signature) if delivery_signature_is_valid(signature) => {
            Some(signature.clone())
        }
        _ => return None,
    };
    let encoded_body = map.get("body")?.as_str()?;
    if encoded_body.len() > WEBHOOK_DELIVERY_MAX_BASE64_BYTES {
        return None;
    }
    let body = STANDARD.decode(encoded_body).ok()?;
    if body.len() > WEBHOOK_DELIVERY_MAX_BYTES {
        return None;
    }
    let attempts = match map.get("attempts") {
        None => 0,
        Some(value) => u32::try_from(value.as_u64()?).ok()?,
    };
    let next_attempt_ms = map
        .get("next_attempt_ms")
        .and_then(norito::json::Value::as_u64)
        .unwrap_or(0);
    Some(PendingDelivery {
        id: id.to_string(),
        webhook_id,
        webhook_generation,
        url: url.to_string(),
        content_type: content_type.to_string(),
        signature,
        body,
        attempts,
        next_attempt_ms,
    })
}
fn pending_delivery_registration_is_current(pd: &PendingDelivery) -> bool {
    lock_registry()
        .items
        .get(&pd.webhook_id)
        .is_some_and(|registered| {
            registered.entry.active && registered.generation == pd.webhook_generation
        })
}
async fn process_queue_once() -> Duration {
    let policy = webhook_policy();
    let batch = match discover_queue_batch(policy) {
        Ok(batch) => batch,
        Err(err) => {
            iroha_logger::warn!(%err, "failed to iterate webhook queue directory");
            return Duration::from_secs(5);
        }
    };
    let directory = match batch.directory {
        Some(directory) => directory,
        None => match open_webhook_queue_directory(true) {
            Ok(Some(directory)) => Arc::new(directory),
            Ok(None) => return Duration::from_secs(5),
            Err(error) => {
                iroha_logger::warn!(%error, "failed to pin webhook queue directory");
                return Duration::from_secs(5);
            }
        },
    };
    let batch_had_entries = !batch.paths.is_empty() || !batch.overflow_paths.is_empty();
    if let Err(err) = prune_verified_queue_overflow_in(&directory, batch.overflow_paths, policy) {
        iroha_logger::warn!(%err, "failed to verify webhook queue overflow");
    }
    let mut next_due = None;
    for path in batch.paths {
        let file = match read_queue_file_bounded(Arc::clone(&directory), path.clone()).await {
            Ok(file) => file,
            Err(e) => {
                iroha_logger::warn!(%e, ?path, "failed to read pending webhook delivery");
                if e.kind() == std::io::ErrorKind::InvalidData {
                    if let Err(remove_err) =
                        remove_queue_file(Arc::clone(&directory), path.clone(), None).await
                    {
                        iroha_logger::warn!(
                            %remove_err,
                            ?path,
                            "failed to remove invalid webhook payload"
                        );
                    }
                }
                continue;
            }
        };
        let mut pd = match decode_pending_delivery(&file.bytes) {
            Some(p) => p,
            None => {
                if let Err(e) =
                    remove_queue_file(Arc::clone(&directory), path.clone(), Some(file.identity))
                        .await
                {
                    iroha_logger::warn!(%e, ?path, "failed to remove invalid webhook payload");
                }
                continue;
            }
        };
        if !pending_delivery_registration_is_current(&pd) {
            iroha_logger::info!(
                webhook_id = pd.webhook_id,
                "dropping webhook payload for a deleted or replaced registration"
            );
            if let Err(error) =
                remove_queue_file(Arc::clone(&directory), path.clone(), Some(file.identity)).await
            {
                iroha_logger::warn!(
                    %error,
                    ?path,
                    "failed to remove invalidated webhook payload"
                );
            }
            continue;
        }
        // Wait until next_attempt
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if now_ms < pd.next_attempt_ms {
            let delay = Duration::from_millis(pd.next_attempt_ms.saturating_sub(now_ms));
            next_due = Some(next_due.map_or(delay, |current: Duration| current.min(delay)));
            continue;
        }
        if pd.attempts >= policy.max_attempts.get() {
            iroha_logger::warn!(
                attempts = pd.attempts,
                webhook_id = pd.webhook_id,
                "dropping webhook payload that exceeded max attempts"
            );
            if let Err(e) =
                remove_queue_file(Arc::clone(&directory), path.clone(), Some(file.identity)).await
            {
                iroha_logger::warn!(%e, ?path, "failed to remove over-attempted webhook payload");
            }
            continue;
        }
        let delivery_lock = webhook_delivery_attempt_lock(pd.webhook_id);
        let delivery_guard = delivery_lock.lock().await;
        if !pending_delivery_registration_is_current(&pd) {
            drop(delivery_guard);
            iroha_logger::info!(
                webhook_id = pd.webhook_id,
                "dropping webhook payload for a deleted or replaced registration"
            );
            if let Err(error) =
                remove_queue_file(Arc::clone(&directory), path.clone(), Some(file.identity)).await
            {
                iroha_logger::warn!(
                    %error,
                    ?path,
                    "failed to remove invalidated webhook payload"
                );
            }
            continue;
        }
        let delivered = try_deliver(&pd).await;
        if delivered {
            if let Err(e) =
                remove_queue_file(Arc::clone(&directory), path.clone(), Some(file.identity)).await
            {
                iroha_logger::warn!(%e, ?path, "failed to remove delivered webhook payload");
            }
        } else {
            pd.attempts = pd.attempts.saturating_add(1);
            if pd.attempts >= policy.max_attempts.get() {
                iroha_logger::warn!(
                    attempts = pd.attempts,
                    webhook_id = pd.webhook_id,
                    "dropping webhook payload after max attempts"
                );
                if let Err(e) =
                    remove_queue_file(Arc::clone(&directory), path.clone(), Some(file.identity))
                        .await
                {
                    iroha_logger::warn!(%e, ?path, "failed to remove failed webhook payload");
                }
                continue;
            }
            let delay = backoff_delay(&policy, pd.attempts);
            let next = SystemTime::now()
                .checked_add(delay)
                .unwrap_or_else(SystemTime::now)
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            pd.next_attempt_ms = next;
            match encode_pending_delivery(&pd) {
                Ok(encoded) => {
                    if let Err(e) = replace_queue_file(
                        Arc::clone(&directory),
                        path.clone(),
                        file.identity,
                        encoded.into_bytes(),
                    )
                    .await
                    {
                        iroha_logger::warn!(
                            %e,
                            ?path,
                            "failed to persist pending webhook delivery"
                        );
                    }
                }
                Err(err) => {
                    iroha_logger::warn!(
                        %err,
                        ?path,
                        "dropping webhook delivery that exceeded spool bounds"
                    );
                    if let Err(remove_err) =
                        remove_queue_file(Arc::clone(&directory), path.clone(), Some(file.identity))
                            .await
                    {
                        iroha_logger::warn!(
                            %remove_err,
                            ?path,
                            "failed to remove oversized webhook payload"
                        );
                    }
                }
            }
        }
        drop(delivery_guard);
    }
    if batch.sweep_complete {
        next_due
            .unwrap_or(Duration::from_secs(1))
            .min(Duration::from_secs(1))
    } else if batch_had_entries {
        Duration::ZERO
    } else {
        // A work-bounded scan containing only unrelated files must yield
        // before continuing the persistent directory cursor.
        Duration::from_millis(1)
    }
}
#[cfg(test)]
mod tests;
