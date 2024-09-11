use std::mem::MaybeUninit;

use iroha_ffi::{ffi_export, FfiType};

/// Ffi structure
#[derive(Clone, FfiType)]
pub struct FfiStruct;

/// Return nested structure
#[ffi_export]
pub fn return_nested() -> Vec<Vec<FfiStruct>> {
    vec![vec![FfiStruct, FfiStruct], vec![FfiStruct, FfiStruct]]
}

fn main() {
    let mut nested = MaybeUninit::uninit();
    unsafe { __return_nested(nested.as_mut_ptr()) };
}
