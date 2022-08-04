use std::{alloc::alloc, mem::MaybeUninit};

use getset::{Getters, Setters};
use iroha_ffi::{ffi, ffi_export, IntoFfi, TryFromReprC};

ffi! {
    /// FfiStruct
    #[derive(Clone, Setters, Getters, IntoFfi, TryFromReprC)]
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
}

fn main() {
    let s = FfiStruct { a: 42, b: 32 };

    let mut a = MaybeUninit::<*const i32>::uninit();
    let mut b = MaybeUninit::<*const u32>::uninit();

    unsafe {
        FfiStruct__a(IntoFfi::into_ffi(&s), a.as_mut_ptr());
        let a: &i32 = TryFromReprC::try_from_repr_c(a.assume_init(), &mut ()).unwrap();
        FfiStruct__set_a(IntoFfi::into_ffi(&mut s), IntoFfi::into_ffi(*a));

        FfiStruct__b(IntoFfi::into_ffi(&s), b.as_mut_ptr());
        let b: &u32 = TryFromReprC::try_from_repr_c(b.assume_init(), &mut ()).unwrap();
        FfiStruct__set_b(IntoFfi::into_ffi(&mut s), IntoFfi::into_ffi(*b));
    }
}
