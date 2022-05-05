use iroha_ffi::{ffi_bindgen, FfiResult};
use std::mem::MaybeUninit;

struct FfiStruct {
    a: u32,
}

#[ffi_bindgen]
impl FfiStruct {
    pub fn from_mutable_input_arg(a: &mut u32) -> Self {
        let output = Self { a: a.clone() };
        *a = 42;
        output
    }
}

fn main() -> Result<(), ()> {
    let s: MaybeUninit<*mut FfiStruct> = MaybeUninit::uninit();

    if FfiResult::Ok != ffi_struct_from_mutable_input_arg(s.as_mut_ptr()) {
        return Err(());
    }

    Ok(())
}
