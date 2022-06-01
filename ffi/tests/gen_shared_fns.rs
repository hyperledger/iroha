#![allow(unsafe_code, clippy::restriction)]

use std::{cmp::Ordering, mem::MaybeUninit};

use iroha_ffi::{ffi_bindgen, gen_ffi_impl, handles, FfiResult};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FfiStruct1 {
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FfiStruct2 {
    name: String,
}

handles! {0, FfiStruct1, FfiStruct2}
gen_ffi_impl! {Drop: FfiStruct1, FfiStruct2}
gen_ffi_impl! {Clone: FfiStruct1, FfiStruct2}
gen_ffi_impl! {Eq: FfiStruct1, FfiStruct2}
gen_ffi_impl! {Ord: FfiStruct1, FfiStruct2}

#[ffi_bindgen]
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
        assert_eq! {FfiResult::Ok, FfiStruct1__new(&name, ffi_struct.as_mut_ptr())};
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

            let cloned = cloned.assume_init();
            assert_eq!(*ffi_struct1, *cloned);

            cloned
        };

        let mut is_equal = MaybeUninit::<bool>::new(false);
        __eq(
            FfiStruct1::ID,
            ffi_struct1.cast(),
            cloned.cast(),
            is_equal.as_mut_ptr(),
        );
        let is_equal = is_equal.assume_init();
        assert!(is_equal);

        let mut ordering = MaybeUninit::<Ordering>::new(Ordering::Less);
        __ord(
            FfiStruct1::ID,
            ffi_struct1.cast(),
            cloned.cast(),
            ordering.as_mut_ptr(),
        );
        let ordering = ordering.assume_init();
        assert_eq!(ordering, Ordering::Equal);

        assert_eq!(FfiResult::Ok, __drop(FfiStruct1::ID, ffi_struct1.cast()));
        assert_eq!(FfiResult::Ok, __drop(FfiStruct1::ID, cloned.cast()));
    }
}
