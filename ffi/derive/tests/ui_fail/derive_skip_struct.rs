use getset::{MutGetters, Setters};
use iroha_ffi::ffi_bindgen;
use std::mem::MaybeUninit;

#[ffi_bindgen]
#[derive(Setters, MutGetters)]
#[getset(skip)]
pub struct FfiStruct {
    #[getset(set = "pub", get_mut = "pub")]
    a: u32,
    b: i32,
}

fn main() {
    let s: *mut _ = &mut FfiStruct { a: 42, b: 32 };

    let a = MaybeUninit::<*mut u32>::uninit();
    let b = MaybeUninit::<*const i32>::uninit();

    unsafe {
        FfiStruct__a_mut(s, a.as_mut_ptr());
        let a = &mut *a.assume_init();
        FfiStruct__set_a(s, a);

        FfiStruct__b_mut(s, b.as_mut_ptr());
        let b = &*b.assume_init();
        FfiStruct__set_b(s, b);
    }
}
