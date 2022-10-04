#![allow(unsafe_code, clippy::restriction)]

use std::{cmp::Ordering, mem::MaybeUninit};

use iroha_ffi::{def_ffi_fn, ffi_export, handles, FfiConvert, FfiReturn, FfiType, Handle};

/// Struct without a repr attribute is opaque by default
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, FfiType)]
pub struct FfiStruct1 {
    name: String,
}

/// Struct with a repr attribute can be forced to become opaque with `#[ffi_type(opaque)]`
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, FfiType)]
#[ffi_type(opaque)]
#[repr(C)]
pub struct FfiStruct2 {
    name: String,
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
        let mut store = Vec::new();
        assert_eq! {FfiReturn::Ok, FfiStruct1__new(FfiConvert::into_ffi(name.clone(), &mut store), ffi_struct.as_mut_ptr())};
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

            let cloned = FfiConvert::try_from_ffi(cloned.assume_init(), &mut ()).unwrap();
            assert_eq!(*ffi_struct1, cloned);

            cloned
        };

        let mut is_equal = MaybeUninit::new(1);
        let cloned_ptr = FfiConvert::into_ffi(&cloned, &mut ());

        __eq(
            FfiStruct1::ID,
            ffi_struct1.cast(),
            cloned_ptr.cast(),
            is_equal.as_mut_ptr(),
        );
        let is_equal: bool = FfiConvert::try_from_ffi(is_equal.assume_init(), &mut ()).unwrap();
        assert!(is_equal);

        let mut ordering = MaybeUninit::new(1);
        __ord(
            FfiStruct1::ID,
            ffi_struct1.cast(),
            cloned_ptr.cast(),
            ordering.as_mut_ptr(),
        );
        let ordering: Ordering = FfiConvert::try_from_ffi(ordering.assume_init(), &mut ()).unwrap();
        assert_eq!(ordering, Ordering::Equal);

        assert_eq!(FfiReturn::Ok, __drop(FfiStruct1::ID, ffi_struct1.cast()));
        assert_eq!(
            FfiReturn::Ok,
            __drop(FfiStruct1::ID, cloned.into_ffi(&mut ()).cast())
        );
    }
}
