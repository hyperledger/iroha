use std::{alloc::alloc, mem::MaybeUninit};

use iroha_ffi::{ffi_export, slice::OutBoxedSlice, IntoFfi, TryFromReprC};

type Nested = Vec<Vec<FfiStruct>>;

/// Ffi structure
#[derive(Clone, IntoFfi, TryFromReprC)]
pub struct FfiStruct;

/// Return nested structure
#[ffi_export]
pub fn return_nested() -> Nested {
    vec![vec![FfiStruct, FfiStruct], vec![FfiStruct, FfiStruct]]
}

fn main() {
    let mut params_len = MaybeUninit::new(0);
    let nested = OutBoxedSlice::from_uninit_slice(None, &mut params_len);
    unsafe { __return_nested(nested) };
}
