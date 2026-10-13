//! Fixed shared control for the one-shot diagnostic's fatal resource outcome.
//!
//! This is a native, same-host control ABI, not a persisted or production codec.
//! The supervisor owns a fresh zeroed, unlinked, owner-only page file and must
//! neither write nor inspect it concurrently with the child. It reads only after
//! child death. Setup maps and initializes it before the verifier thread exists.
//! The mapping remains alive until process exit; fatal publication uses only
//! lock-free 64-bit atomics before `_exit`, never allocation, I/O or unwinding.

use std::{
    mem::{MaybeUninit, size_of},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr,
    sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering},
};

use super::budget::{MAX_INPUT_BYTES, VERIFICATION_UNITS};

const MAGIC: u64 = 0x5041_524c_4641_5431;
const SETUP: u64 = 1;
const ADMITTED: u64 = 2;
const EXHAUSTED: u64 = 3;

/// Four native-endian u64 words at offsets 0, 8, 16 and 24. The rest of the
/// mapped page stays zero. Both observed targets implement lock-free u64 atomics.
#[repr(C)]
struct Control {
    magic: AtomicU64,
    state: AtomicU64,
    charged_units: AtomicU64,
    charged_bytes: AtomicU64,
}

impl Control {
    const fn new() -> Self {
        Self {
            magic: AtomicU64::new(MAGIC),
            state: AtomicU64::new(SETUP),
            charged_units: AtomicU64::new(0),
            charged_bytes: AtomicU64::new(0),
        }
    }

    fn admit(&self, units: u64, bytes: u64) -> bool {
        if self.state.load(Ordering::Acquire) != SETUP
            || units != VERIFICATION_UNITS
            || bytes > MAX_INPUT_BYTES as u64
        {
            return false;
        }
        self.charged_units.store(units, Ordering::Relaxed);
        self.charged_bytes.store(bytes, Ordering::Relaxed);
        self.state.store(ADMITTED, Ordering::Release);
        true
    }

    fn mark_exhausted(&self) -> bool {
        if self.state.load(Ordering::Acquire) != ADMITTED {
            return false;
        }
        self.state.store(EXHAUSTED, Ordering::Release);
        true
    }
}

static CONTROL: AtomicPtr<Control> = AtomicPtr::new(ptr::null_mut());
static RESERVED_BYTES: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy)]
pub struct FatalError(pub &'static str, pub i32);

struct Page {
    control: *mut Control,
    bytes: usize,
}

impl Page {
    fn map(fd: OwnedFd) -> Result<Self, FatalError> {
        // SAFETY: scalar-only native queries and initialized output on success.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let bytes = usize::try_from(page).map_err(|_| FatalError("fatal_page_size", 0))?;
        if !bytes.is_power_of_two() || !(size_of::<Control>()..=65536).contains(&bytes) {
            return Err(FatalError("fatal_page_size", 0));
        }
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDWR {
            return Err(FatalError("fatal_fd_access", 0));
        }
        let mut metadata = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
            return Err(FatalError("fatal_fd_stat", 0));
        }
        let metadata = unsafe { metadata.assume_init() };
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
            || usize::try_from(metadata.st_size).ok() != Some(bytes)
            || metadata.st_nlink != 0
            || metadata.st_uid != unsafe { libc::geteuid() }
            || metadata.st_mode & 0o7777 != 0o600
        {
            return Err(FatalError("fatal_fd_shape", 0));
        }
        // SAFETY: exact-sized writable regular file, separate mapping; no fixed
        // address and no replacement of another mapping. Parent owns its bytes.
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(FatalError("fatal_mmap", 0));
        }
        let result = Self {
            control: base.cast(),
            bytes,
        };
        // SAFETY: the parent supplies an exclusive zeroed file and does not
        // mutate/truncate it while mapped. The whole mapping is readable.
        if unsafe { std::slice::from_raw_parts(base.cast::<u8>(), bytes) }
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(FatalError("fatal_fd_not_fresh", 0));
        }
        // SAFETY: mmap is page aligned, the region is large enough and no
        // observer reads concurrently. Initialization also touches the page.
        unsafe { result.control.write(Control::new()) };
        // OwnedFd closes here; the shared mapping keeps the unlinked file live.
        Ok(result)
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        // SAFETY: only unpublished setup failures or test-local pages drop.
        unsafe { libc::munmap(self.control.cast(), self.bytes) };
    }
}

/// Consume the inherited descriptor and install exactly one control page.
/// A successfully installed page intentionally lives until this process exits.
pub fn install(fd: i32) -> Result<usize, FatalError> {
    if fd < 3 {
        return Err(FatalError("fatal_fd_number", 0));
    }
    // Validate before constructing an OwnedFd, whose contract requires a live
    // descriptor. The single-threaded supervisor does not close it concurrently.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(FatalError("fatal_fd_access", 0));
    }
    // SAFETY: the qualification caller transfers this inherited descriptor;
    // no other child-side owner is created for it.
    let page = Page::map(unsafe { OwnedFd::from_raw_fd(fd) })?;
    if CONTROL
        .compare_exchange(
            ptr::null_mut(),
            page.control,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(FatalError("fatal_repeated_install", 0));
    }
    let bytes = page.bytes;
    RESERVED_BYTES.store(bytes, Ordering::Release);
    std::mem::forget(page);
    Ok(bytes)
}

/// The extra counted workspace reservation, required before worker setup.
pub fn reserved_bytes() -> Result<usize, FatalError> {
    let bytes = RESERVED_BYTES.load(Ordering::Acquire);
    if bytes == 0 {
        Err(FatalError("fatal_not_installed", 0))
    } else {
        Ok(bytes)
    }
}

/// Publish exactly one debit before enabling any verifier allocation.
pub fn admit(units: u64, bytes: u64) {
    let control = CONTROL.load(Ordering::Acquire);
    // SAFETY: install publishes initialized storage retained until exit. The
    // private entry admits once, with no concurrent writers or external edits.
    if control.is_null() || !unsafe { &*control }.admit(units, bytes) {
        unsafe { libc::_exit(74) };
    }
}

/// Publish resource failure and terminate the child, without native output,
/// formatting, allocation, mutexes, Rust unwinding or destructor promises.
pub fn exhausted() -> ! {
    let control = CONTROL.load(Ordering::Acquire);
    // SAFETY: as for admit; allocation failure runs only after admission.
    let code = if !control.is_null() && unsafe { &*control }.mark_exhausted() {
        73
    } else {
        74
    };
    unsafe { libc::_exit(code) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, os::fd::IntoRawFd};

    fn file(bytes: usize) -> File {
        let mut template = b"/tmp/parliament-fatal-unit-XXXXXX\0".to_vec();
        let fd = unsafe { libc::mkstemp(template.as_mut_ptr().cast()) };
        assert!(fd >= 0);
        assert_eq!(unsafe { libc::unlink(template.as_ptr().cast()) }, 0);
        let file = unsafe { File::from_raw_fd(fd) };
        file.set_len(bytes as u64).unwrap();
        file
    }

    fn page_size() -> usize {
        usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap()
    }

    #[test]
    fn native_control_layout_and_one_way_debit_are_exact() {
        assert_eq!(size_of::<Control>(), 32);
        assert_eq!(std::mem::align_of::<Control>(), 8);
        assert_eq!(std::mem::offset_of!(Control, magic), 0);
        assert_eq!(std::mem::offset_of!(Control, state), 8);
        assert_eq!(std::mem::offset_of!(Control, charged_units), 16);
        assert_eq!(std::mem::offset_of!(Control, charged_bytes), 24);
        for bytes in [0, MAX_INPUT_BYTES as u64] {
            let control = Control::new();
            assert!(!control.mark_exhausted());
            assert!(!control.admit(0, bytes));
            assert!(!control.admit(2, bytes));
            assert!(!control.admit(1, MAX_INPUT_BYTES as u64 + 1));
            assert!(control.admit(1, bytes));
            assert!(!control.admit(1, bytes));
            assert!(control.mark_exhausted());
            assert!(!control.mark_exhausted());
            assert_eq!(control.magic.load(Ordering::Acquire), MAGIC);
            assert_eq!(control.state.load(Ordering::Acquire), EXHAUSTED);
            assert_eq!(control.charged_units.load(Ordering::Acquire), 1);
            assert_eq!(control.charged_bytes.load(Ordering::Acquire), bytes);
        }
    }

    #[test]
    fn mapping_is_shared_and_rejects_invalid_or_nonfresh_files() {
        let file = file(page_size());
        let fd: OwnedFd = file.try_clone().unwrap().into();
        let page = Page::map(fd).unwrap();
        assert_eq!(page.bytes, page_size());
        let control = unsafe { &*page.control };
        assert!(control.admit(1, 123));
        assert!(control.mark_exhausted());
        use std::os::unix::fs::FileExt;
        let mut bytes = [0u8; 32];
        file.read_exact_at(&mut bytes, 0).unwrap();
        for (index, expected) in [MAGIC, EXHAUSTED, 1, 123].into_iter().enumerate() {
            assert_eq!(
                u64::from_ne_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap()),
                expected
            );
        }
        let fd: OwnedFd = file.try_clone().unwrap().into();
        assert!(matches!(
            Page::map(fd),
            Err(FatalError("fatal_fd_not_fresh", 0))
        ));
        drop(page);
        for length in [0, page_size() - 1, page_size() + 1] {
            let fd: OwnedFd = self::file(length).into();
            assert!(matches!(
                Page::map(fd),
                Err(FatalError("fatal_fd_shape", 0))
            ));
        }
        let readonly: OwnedFd = File::open("/dev/null").unwrap().into();
        assert!(matches!(
            Page::map(readonly),
            Err(FatalError("fatal_fd_access", 0))
        ));
        for permissions in [0o000, 0o400, 0o644, 0o700, 0o4600] {
            let fd = self::file(page_size()).into_raw_fd();
            assert_eq!(unsafe { libc::fchmod(fd, permissions) }, 0);
            assert!(matches!(
                Page::map(unsafe { OwnedFd::from_raw_fd(fd) }),
                Err(FatalError("fatal_fd_shape", 0))
            ));
        }
        let not_regular: OwnedFd = File::options()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap()
            .into();
        assert!(matches!(
            Page::map(not_regular),
            Err(FatalError("fatal_fd_shape", 0))
        ));
        assert!(matches!(install(0), Err(FatalError("fatal_fd_number", 0))));
        assert!(matches!(
            install(i32::MAX),
            Err(FatalError("fatal_fd_access", 0))
        ));
    }
}
