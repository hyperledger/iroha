use getset::{Getters, Setters};
use iroha_ffi::ffi_bindgen;
use std::mem::MaybeUninit;

#[ffi_bindgen]
#[derive(Setters, Getters)]
#[getset(get = "pub")]
pub struct FfiStruct {
    #[getset(set = "pub")]
    a: u32,
    #[getset(skip)]
    b: u32,
}

fn main() {
    let s: *mut _ = &mut FfiStruct { a: 42, b: 32 };

    let a = MaybeUninit::<*const u32>::uninit();
    let b = MaybeUninit::<*const u32>::uninit();

    unsafe {
        FfiStruct__a(s, a.as_mut_ptr());
        let a = &*a.assume_init();
        FfiStruct__set_a(s, a);

        FfiStruct__b(s, b.as_mut_ptr());
        let b = &*b.assume_init();
        FfiStruct__set_b(s, b);
    }
}
