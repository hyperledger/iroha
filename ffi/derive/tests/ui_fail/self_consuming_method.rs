//! Test which assures that methods consuming self are not allowed in FFI. If the need arises,
//! this limitation can be lifted in the future, and consequently this test nullified

use iroha_ffi::{ffi_bindgen, FfiResult};
use std::mem::MaybeUninit;

struct FfiStructBuilder;
struct FfiStruct;

#[ffi_bindgen]
impl FfiStructBuilder {
    /// New
    pub fn new() -> Self {
        Self
    }

    /// Build
    pub fn build(self) -> FfiStruct {
        FfiStruct
    }
}

fn main() -> Result<(), ()> {
    let s_builder: MaybeUninit<*mut FfiStructBuilder> = MaybeUninit::uninit();
    if FfiResult::Ok != FfiStructBuilder__new(s_builder.as_mut_ptr()) {
        return Err(());
    }

    let s_builder = unsafe { s_builder.assume_init() };
    let s: MaybeUninit<*mut FfiStruct> = MaybeUninit::uninit();
    if FfiResult::Ok != FfiStructBuilder__build(s_builder, s.as_mut_ptr()) {
        return Err(());
    }

    Ok(())
}
