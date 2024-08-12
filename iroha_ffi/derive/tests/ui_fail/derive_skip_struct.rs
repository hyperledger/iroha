use std::mem::MaybeUninit;

use getset::{MutGetters, Setters};
use iroha_ffi::{ffi_export, FfiConvert, FfiType};

/// FfiStruct
#[ffi_export]
#[derive(Clone, Setters, MutGetters, FfiType)]
// TODO: I am not really sure what is the purpose of this test
// getset allows `#[getset(skip)]` to be placed on a struct, but it doesn't seem to have any effect at all
// Due to it being potentially error-prone, iroha_ffi_derive disallows such placement
// hence it's commented out here
// #[getset(skip)]
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
