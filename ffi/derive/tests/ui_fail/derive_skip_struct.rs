use std::mem::MaybeUninit;

use getset::{MutGetters, Setters};
use iroha_ffi::{ffi_export, FfiConvert, FfiType};

/// FfiStruct
#[derive(Clone, Setters, MutGetters, FfiType)]
#[getset(skip)]
#[ffi_export]
pub struct FfiStruct {
    /// a
    #[getset(set = "pub", get_mut = "pub")]
    a: u32,
    b: i32,
}

fn main() {
    let s = FfiStruct { a: 42, b: 32 };

    let mut a = MaybeUninit::<*mut u32>::uninit();
    let mut b = MaybeUninit::<*mut i32>::uninit();

    unsafe {
        FfiStruct__a_mut(FfiConvert::into_ffi(&mut s, &mut ()), a.as_mut_ptr());
        let a: &mut u32 = FfiConvert::try_from_ffi(a.assume_init(), &mut ()).unwrap();
        FfiStruct__set_a(
            FfiConvert::into_ffi(&mut s, &mut ()),
            FfiConvert::into_ffi(*a, &mut ()),
        );

        FfiStruct__b_mut(FfiConvert::into_ffi(&s, &mut ()), b.as_mut_ptr());
        let b: &mut i32 = FfiConvert::try_from_ffi(b.assume_init(), &mut ()).unwrap();
        FfiStruct__set_b(
            FfiConvert::into_ffi(&mut s, &mut ()),
            FfiConvert::into_ffi(*b, &mut ()),
        );
    }
}
