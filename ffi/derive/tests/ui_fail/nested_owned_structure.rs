use std::mem::MaybeUninit;

use iroha_ffi::{ffi_export, slice::OutBoxedSlice, FfiType};

type Nested = Vec<Vec<FfiStruct>>;

/// Ffi structure
#[derive(Clone, FfiType)]
pub struct FfiStruct;

/// Return nested structure
#[ffi_export]
pub fn return_nested() -> Nested {
    vec![vec![FfiStruct, FfiStruct], vec![FfiStruct, FfiStruct]]
}

fn main() {
    let mut params_len = MaybeUninit::uninit();
    let nested = OutBoxedSlice::from_uninit_slice(None, &mut params_len);
    unsafe { __return_nested(nested) };
}
