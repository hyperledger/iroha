use std::{cmp::Ordering, mem::MaybeUninit};

use iroha_ffi::{ffi_bindgen, gen_ffi_impl, handles};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FfiStruct1 {
    name: String,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
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

fn main() {
    let name = String::from("X");

    let ffi_struct1 = unsafe {
        let mut ffi_struct: MaybeUninit<*mut FfiStruct1> = MaybeUninit::uninit();
        FfiStruct1__new(&name, ffi_struct.as_mut_ptr());
        ffi_struct.assume_init()
    };

    unsafe {
        let cloned = {
            let mut cloned: MaybeUninit<*mut FfiStruct1> = MaybeUninit::uninit();

            __clone(
                FfiStruct1::ID,
                ffi_struct1.cast(),
                cloned.as_mut_ptr().cast(),
            );

            cloned.assume_init()
        };

        let mut is_equal: MaybeUninit<bool> = MaybeUninit::uninit();
        __eq(
            FfiStruct1::ID,
            ffi_struct1.cast(),
            cloned.cast(),
            is_equal.as_mut_ptr(),
        );

        let mut ordering: MaybeUninit<Ordering> = MaybeUninit::uninit();
        __ord(
            FfiStruct1::ID,
            ffi_struct1.cast(),
            cloned.cast(),
            ordering.as_mut_ptr(),
        );

        __drop(FfiStruct1::ID, ffi_struct1.cast());
        __drop(FfiStruct1::ID, cloned.cast());
    }
}
