struct ProxyWasmAlloc;

mod host {
    #[link(wasm_import_module = "iroha")]
    extern "C" {
        pub(super) fn _iroha_wasm_alloc(size: usize, align: usize) -> *mut u8;
        pub(super) fn _iroha_wasm_dealloc(ptr: *mut u8, size: usize, align: usize);
    }
}

unsafe impl core::alloc::GlobalAlloc for ProxyWasmAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        host::_iroha_wasm_alloc(layout.size(), layout.align())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        host::_iroha_wasm_dealloc(ptr, layout.size(), layout.align())
    }
}

#[global_allocator]
static ALLOC: ProxyWasmAlloc = ProxyWasmAlloc;
