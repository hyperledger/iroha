use std::alloc::alloc;

use iroha_ffi::{ffi_export, IntoFfi, TryFromReprC};

/// FfiStruct
#[derive(Clone, IntoFfi, TryFromReprC)]
pub struct FfiStruct;

#[ffi_export]
impl FfiStruct {
    fn private(self) {}
}

fn main() {
    let s = FfiStruct;
    unsafe {
        FfiStruct__private(IntoFfi::into_ffi(s));
    }
}