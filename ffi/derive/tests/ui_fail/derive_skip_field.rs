use std::mem::MaybeUninit;

use getset::{Getters, Setters};
use iroha_ffi::{ffi_export, FfiConvert, FfiType};

/// FfiStruct
#[derive(Clone, Setters, Getters, FfiType)]
#[getset(get = "pub")]
#[ffi_export]
pub struct FfiStruct {
    /// a
    #[getset(set = "pub")]
    a: i32,
    /// b
    #[getset(skip)]
    b: u32,
}

fn main() {
    let s = FfiStruct { a: 42, b: 32 };

    let mut a = MaybeUninit::<*const i32>::uninit();
    let mut b = MaybeUninit::<*const u32>::uninit();

    unsafe {
        FfiStruct__a(FfiConvert::into_ffi(&s, &mut ()), a.as_mut_ptr());
        let a: &i32 = FfiConvert::try_from_ffi(a.assume_init(), &mut ()).unwrap();
        FfiStruct__set_a(
            FfiConvert::into_ffi(&mut s, &mut ()),
            FfiConvert::into_ffi(*a, &mut ()),
        );

        FfiStruct__b(FfiConvert::into_ffi(&s, &mut ()), b.as_mut_ptr());
        let b: &u32 = FfiConvert::try_from_ffi(b.assume_init(), &mut ()).unwrap();
        FfiStruct__set_b(
            FfiConvert::into_ffi(&mut s, &mut ()),
            FfiConvert::into_ffi(*b, &mut ()),
        );
    }
}
