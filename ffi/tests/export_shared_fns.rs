#![allow(unsafe_code)]

use std::{cmp::Ordering, mem::MaybeUninit};

use iroha_ffi::{def_ffi_fns, ffi_export, FfiConvert, FfiOutPtrRead, FfiReturn, FfiType, Handle};

iroha_ffi::handles! {FfiStruct1, FfiStruct2}

def_ffi_fns! {
    Drop: {FfiStruct1, FfiStruct2},
    Clone: {FfiStruct1, FfiStruct2},
    Eq: {FfiStruct1, FfiStruct2},
    Ord: {FfiStruct1, FfiStruct2}
}

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

#[ffi_export]
impl FfiStruct1 {
    /// New
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn export_shared_fns() {
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
                FfiStruct1::ID.into_ffi(&mut ()),
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
            FfiStruct1::ID.into_ffi(&mut ()),
            ffi_struct1.cast(),
            cloned_ptr.cast(),
            is_equal.as_mut_ptr(),
        );
        let is_equal: bool = FfiOutPtrRead::try_read_out(is_equal.assume_init()).unwrap();
        assert!(is_equal);

        let mut ordering = MaybeUninit::new(1);
        __ord(
            FfiStruct1::ID.into_ffi(&mut ()),
            ffi_struct1.cast(),
            cloned_ptr.cast(),
            ordering.as_mut_ptr(),
        );
        let ordering: Ordering = FfiOutPtrRead::try_read_out(ordering.assume_init()).unwrap();
        assert_eq!(ordering, Ordering::Equal);

        assert_eq!(
            FfiReturn::Ok,
            __drop(FfiStruct1::ID.into_ffi(&mut ()), ffi_struct1.cast())
        );
        assert_eq!(
            FfiReturn::Ok,
            __drop(
                FfiStruct1::ID.into_ffi(&mut ()),
                cloned.into_ffi(&mut ()).cast()
            )
        );
    }
}
