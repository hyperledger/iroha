#![allow(unsafe_code, clippy::restriction)]

use std::{alloc::alloc, cmp::Ordering, mem::MaybeUninit};

use iroha_ffi::{def_ffi_fn, ffi, ffi_export, handles, FfiReturn, Handle, IntoFfi, TryFromReprC};

ffi! {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, IntoFfi, TryFromReprC)]
    pub struct FfiStruct1 {
        name: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, IntoFfi, TryFromReprC)]
    pub struct FfiStruct2 {
        name: String,
    }
}

handles! {0, FfiStruct1, FfiStruct2}
def_ffi_fn! {Drop: FfiStruct1, FfiStruct2}
def_ffi_fn! {Clone: FfiStruct1, FfiStruct2}
def_ffi_fn! {Eq: FfiStruct1, FfiStruct2}
def_ffi_fn! {Ord: FfiStruct1, FfiStruct2}

#[ffi_export]
impl FfiStruct1 {
    /// New
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

#[test]
fn gen_shared_fns() {
    let name = String::from("X");

    let ffi_struct1 = unsafe {
        let mut ffi_struct = MaybeUninit::new(core::ptr::null_mut());
        assert_eq! {FfiReturn::Ok, FfiStruct1__new(IntoFfi::into_ffi(name.as_str()), ffi_struct.as_mut_ptr())};
        let ffi_struct = ffi_struct.assume_init();
        assert!(!ffi_struct.is_null());
        assert_eq!(FfiStruct1 { name }, *ffi_struct);
        ffi_struct
    };

    unsafe {
        let cloned = {
            let mut cloned = MaybeUninit::<*mut FfiStruct1>::new(core::ptr::null_mut());

            __clone(
                FfiStruct1::ID,
                ffi_struct1.cast(),
                cloned.as_mut_ptr().cast(),
            );

            let cloned = TryFromReprC::try_from_repr_c(cloned.assume_init(), &mut ()).unwrap();
            assert_eq!(*ffi_struct1, cloned);

            cloned
        };

        let mut is_equal = MaybeUninit::new(1);
        let cloned_ptr = IntoFfi::into_ffi(&cloned);

        __eq(
            FfiStruct1::ID,
            ffi_struct1.cast(),
            cloned_ptr.cast(),
            is_equal.as_mut_ptr(),
        );
        let is_equal: bool =
            TryFromReprC::try_from_repr_c(is_equal.assume_init(), &mut ()).unwrap();
        assert!(is_equal);

        let mut ordering = MaybeUninit::new(1);
        __ord(
            FfiStruct1::ID,
            ffi_struct1.cast(),
            cloned_ptr.cast(),
            ordering.as_mut_ptr(),
        );
        let ordering: Ordering =
            TryFromReprC::try_from_repr_c(ordering.assume_init(), &mut ()).unwrap();
        assert_eq!(ordering, Ordering::Equal);

        assert_eq!(FfiReturn::Ok, __drop(FfiStruct1::ID, ffi_struct1.cast()));
        assert_eq!(
            FfiReturn::Ok,
            __drop(FfiStruct1::ID, cloned.into_ffi().cast())
        );
    }
}
