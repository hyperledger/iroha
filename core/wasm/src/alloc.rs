use core::alloc::Layout;
use core_alloc::alloc;

/// Exposes [`alloc::alloc`] to be called via FFI
///
/// # Safety
///
/// Check [`alloc::alloc`] documentation
#[no_mangle]
pub unsafe extern "C" fn _iroha_wasm_alloc(size: usize, align: usize) -> *mut u8 {
    if let Ok(layout) = Layout::from_size_align(size, align) {
        return alloc::alloc(layout);
    }

    core::ptr::null_mut()
}

/// Exposes [`alloc::dealloc`] to be called via FFI
///
/// # Safety
///
/// Check [`alloc::dealloc`] documentation
#[no_mangle]
pub unsafe extern "C" fn _iroha_wasm_dealloc(ptr: *mut u8, size: usize, align: usize) {
    if let Ok(layout) = Layout::from_size_align(size, align) {
        alloc::dealloc(ptr, layout);
    } else {
        /* NOTE: Leak memory */
    }
}
