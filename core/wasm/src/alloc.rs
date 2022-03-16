use core::alloc::Layout;
use core_alloc::alloc;

#[no_mangle]
unsafe extern "C" fn _iroha_wasm_alloc(size: usize, align: usize) -> *mut u8 {
    let layout = Layout::from_size_align(size, align).expect("Invalid memory layout");
    alloc::alloc(layout)
}

#[no_mangle]
unsafe extern "C" fn _iroha_wasm_dealloc(ptr: *mut u8, size: usize, align: usize) {
    let layout = Layout::from_size_align(size, align).expect("Invalid memory layout");
    alloc::dealloc(ptr, layout)
}
