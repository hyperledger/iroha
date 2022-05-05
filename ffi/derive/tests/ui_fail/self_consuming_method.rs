use iroha_ffi::{ffi_bindgen, FfiResult};
use std::mem::MaybeUninit;

struct FfiStructBuilder;
struct FfiStruct;

#[ffi_bindgen]
impl FfiStructBuilder {
    pub fn new() -> Self {
        FfiStruct
    }

    pub fn build(self) -> FfiStruct {
        FfiStruct
    }
}

fn main() -> Result<(), ()> {
    let s_builder: MaybeUninit<*mut FfiStructBuilder> = MaybeUninit::uninit();
    if FfiResult::Ok != ffi_struct_builder_new(s_builder.as_mut_ptr()) {
        return Err(());
    }

    let s_builder = unsafe { s_builder.assume_init() };
    let s: MaybeUninit<*mut FfiStruct> = MaybeUninit::uninit();
    if FfiResult::Ok != ffi_struct_builder_build(s_builder, s.as_mut_ptr()) {
        return Err(());
    }

    Ok(())
}
