//! Native mapping and explicitly supplied pthread stack, restricted to
//! 64-bit Linux and macOS targets. Native runtime/TLS allocation is not hidden
//! inside the Rust allocator claim.

use std::{mem::MaybeUninit, ptr};

use super::arena::{Arena, HEAP_BYTES, TREE_BYTES};

// libc 0.2.186 omits this Darwin declaration. The exact signature is declared
// in the Apple SDK's pthread/pthread.h; every ABI type still comes from libc.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn pthread_attr_setstack(
        attr: *mut libc::pthread_attr_t,
        stack: *mut libc::c_void,
        size: libc::size_t,
    ) -> libc::c_int;
}
#[cfg(target_os = "linux")]
use libc::pthread_attr_setstack;

pub const STACK_BYTES: usize = 8 * 1024 * 1024;
pub const CONTROL_BYTES: usize = 64 * 1024;
pub const METADATA_BYTES: usize = 1024 * 1024;
pub const WORKSPACE_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct NativeError(pub &'static str, pub i32);

pub struct Mapping {
    base: *mut u8,
    length: usize,
    page: usize,
}

impl Mapping {
    pub fn new(heap_limit: usize) -> Result<Self, NativeError> {
        // SAFETY: this sysconf query has no pointer inputs.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page = usize::try_from(page).map_err(|_| NativeError("page_size", 0))?;
        if !page.is_power_of_two() || page > CONTROL_BYTES {
            return Err(NativeError("unsupported_page_size", 0));
        }
        let length = CONTROL_BYTES + HEAP_BYTES + METADATA_BYTES + STACK_BYTES + 2 * page;
        if length > WORKSPACE_LIMIT || TREE_BYTES > METADATA_BYTES {
            return Err(NativeError("workspace_partition", 0));
        }
        // SAFETY: anonymous writable mapping, no existing mappings replaced.
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(NativeError("mmap", errno()));
        }
        let result = Self {
            base: base.cast(),
            length,
            page,
        };
        for offset in [CONTROL_BYTES + HEAP_BYTES + METADATA_BYTES, length - page] {
            // SAFETY: these page-aligned ranges lie inside this mapping.
            if unsafe { libc::mprotect(result.base.add(offset).cast(), page, libc::PROT_NONE) } != 0
            {
                return Err(NativeError("mprotect", errno()));
            }
        }
        // SAFETY: control storage is aligned, heap/tree are disjoint and sized
        // above, and Drop cannot unmap until the worker has been joined.
        unsafe {
            result.arena().write(Arena::new(
                result.base.add(CONTROL_BYTES),
                result.base.add(CONTROL_BYTES + HEAP_BYTES),
                HEAP_BYTES,
                page,
                heap_limit,
            ));
        }
        Ok(result)
    }

    pub fn arena(&self) -> *mut Arena {
        self.base.cast()
    }

    pub fn control(&self) -> *mut u8 {
        // The first 4 KiB are reserved for the allocator's fixed control state.
        // SAFETY: offset lies in the writable 64 KiB control partition.
        unsafe { self.base.add(4096) }
    }

    pub fn stack(&self) -> *mut u8 {
        // SAFETY: the usable stack follows the protected lower guard.
        unsafe {
            self.base
                .add(CONTROL_BYTES + HEAP_BYTES + METADATA_BYTES + self.page)
        }
    }

    pub fn length(&self) -> usize {
        self.length
    }
    pub fn guard_bytes(&self) -> usize {
        2 * self.page
    }

    /// The supplied argument remains valid until this function returns. The
    /// callback must not unwind through C or escape pointers into this mapping.
    pub unsafe fn run(
        &self,
        callback: extern "C" fn(*mut libc::c_void) -> *mut libc::c_void,
        argument: *mut libc::c_void,
    ) -> Result<(), NativeError> {
        let mut attr = MaybeUninit::<libc::pthread_attr_t>::uninit();
        // SAFETY: pthread_attr_init initializes the opaque native ABI type.
        let code = unsafe { libc::pthread_attr_init(attr.as_mut_ptr()) };
        if code != 0 {
            return Err(NativeError("pthread_attr_init", code));
        }
        let attr = attr.as_mut_ptr();
        // SAFETY: attr is initialized and stack is the dedicated writable range.
        let code = unsafe { pthread_attr_setstack(attr, self.stack().cast(), STACK_BYTES) };
        if code != 0 {
            unsafe { libc::pthread_attr_destroy(attr) };
            return Err(NativeError("pthread_attr_setstack", code));
        }
        let mut thread = MaybeUninit::<libc::pthread_t>::uninit();
        // SAFETY: callback and argument obey this method's lifetime contract.
        let created =
            unsafe { libc::pthread_create(thread.as_mut_ptr(), attr, callback, argument) };
        unsafe { libc::pthread_attr_destroy(attr) };
        if created != 0 {
            return Err(NativeError("pthread_create", created));
        }
        let thread = unsafe { thread.assume_init() };
        // SAFETY: this handle was just created and has not been detached/joined.
        let joined = unsafe { libc::pthread_join(thread, ptr::null_mut()) };
        if joined != 0 {
            // The thread might still hold pointers into this mapping; returning
            // and dropping it would be unsound. End this diagnostic child only.
            unsafe { libc::_exit(74) };
        }
        Ok(())
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: Mapping is dropped only after the single worker has joined.
        unsafe { libc::munmap(self.base.cast(), self.length) };
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn current_stack() -> Result<(*mut u8, usize), NativeError> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: both queries inspect this live native thread.
        let thread = unsafe { libc::pthread_self() };
        let top = unsafe { libc::pthread_get_stackaddr_np(thread) }.cast::<u8>();
        let size = unsafe { libc::pthread_get_stacksize_np(thread) };
        if top.is_null() || size == 0 {
            return Err(NativeError("current_stack", 0));
        }
        // Darwin returns the high address; stack grows downward.
        Ok((top.wrapping_sub(size), size))
    }
    #[cfg(target_os = "linux")]
    {
        let mut attr = MaybeUninit::<libc::pthread_attr_t>::uninit();
        let code = unsafe { libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr()) };
        if code != 0 {
            return Err(NativeError("pthread_getattr_np", code));
        }
        let mut base = ptr::null_mut();
        let mut size = 0;
        let code = unsafe { libc::pthread_attr_getstack(attr.as_ptr(), &mut base, &mut size) };
        unsafe { libc::pthread_attr_destroy(attr.as_mut_ptr()) };
        if code != 0 {
            return Err(NativeError("pthread_attr_getstack", code));
        }
        Ok((base.cast(), size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Query {
        base: *mut u8,
        bytes: usize,
        matches: bool,
    }

    extern "C" fn inspect(argument: *mut libc::c_void) -> *mut libc::c_void {
        // SAFETY: the test passes a live exclusive Query until join completes.
        let query = unsafe { &mut *argument.cast::<Query>() };
        let marker = 0u8;
        query.matches = current_stack().is_ok_and(|(base, bytes)| {
            let marker = ptr::from_ref(&marker) as usize;
            base == query.base
                && bytes == query.bytes
                && marker >= base as usize
                && marker < base as usize + bytes
        });
        ptr::null_mut()
    }

    #[test]
    fn supplied_native_stack_and_partition_are_exact() {
        assert!(std::mem::size_of::<Arena>() <= 4096);
        let mapping = Mapping::new(HEAP_BYTES).unwrap();
        assert!(mapping.length() <= WORKSPACE_LIMIT);
        let mut query = Query {
            base: mapping.stack(),
            bytes: STACK_BYTES,
            matches: false,
        };
        unsafe { mapping.run(inspect, ptr::from_mut(&mut query).cast()) }.unwrap();
        assert!(query.matches);
        assert_eq!(unsafe { &*mapping.arena() }.stats().live_blocks, 0);
    }
}
