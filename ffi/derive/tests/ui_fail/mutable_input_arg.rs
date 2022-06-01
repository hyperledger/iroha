//! Test which assures that methods taking mutable references as input arguments are not
//! allowed in the FFI. This limitation can be lifted in the future, and consequently
//! this test nullified, if the need for mutable input arguments feature arises

use iroha_ffi::{ffi_bindgen, FfiResult};
use std::mem::MaybeUninit;

struct FfiStruct {
    a: u32,
}

#[ffi_bindgen]
impl FfiStruct {
    /// From mutable input arg
    pub fn from_mutable_input_arg(a: &mut u32) -> Self {
        let output = Self { a: a.clone() };
        *a = 42;
        output
    }
}

fn main() -> Result<(), ()> {
    let s: MaybeUninit<*mut FfiStruct> = MaybeUninit::uninit();

    if FfiResult::Ok != FfiStruct__from_mutable_input_arg(s.as_mut_ptr()) {
        return Err(());
    }

    Ok(())
}
