use core::alloc::Layout;
use core_alloc::alloc;

#[no_mangle]
unsafe extern "C" fn _iroha_wasm_alloc(size: usize, align: usize) -> usize {
    let layout = Layout::from_size_align(size, align).expect("Invalid memory layout");
    alloc::alloc(layout) as usize
}

#[no_mangle]
unsafe extern "C" fn _iroha_wasm_dealloc(ptr: usize, size: usize, align: usize) {
    let layout = Layout::from_size_align(size, align).expect("Invalid memory layout");
    alloc::dealloc(ptr as *mut u8, layout)
}
