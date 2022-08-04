use std::{alloc::alloc, mem::MaybeUninit};

use getset::{MutGetters, Setters};
use iroha_ffi::{ffi_export, IntoFfi, TryFromReprC};

/// FfiStruct
#[derive(Clone, Setters, MutGetters, IntoFfi, TryFromReprC)]
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
        FfiStruct__a_mut(IntoFfi::into_ffi(&mut s), a.as_mut_ptr());
        let a: &mut u32 = TryFromReprC::try_from_repr_c(a.assume_init(), &mut ()).unwrap();
        FfiStruct__set_a(IntoFfi::into_ffi(&mut s), IntoFfi::into_ffi(*a));

        FfiStruct__b_mut(IntoFfi::into_ffi(&s), b.as_mut_ptr());
        let b: &mut i32 = TryFromReprC::try_from_repr_c(b.assume_init(), &mut ()).unwrap();
        FfiStruct__set_b(IntoFfi::into_ffi(&mut s), IntoFfi::into_ffi(*b));
    }
}
