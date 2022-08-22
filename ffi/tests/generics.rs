#![allow(unsafe_code, clippy::restriction, clippy::pedantic)]

use std::{alloc::alloc, mem::MaybeUninit};

use getset::Getters;
use iroha_ffi::{ffi_export, IntoFfi, TryFromReprC};

#[derive(Clone, Copy, IntoFfi, TryFromReprC, PartialEq, Eq, Debug)]
pub struct GenericFfiStruct<T>(T);

#[derive(IntoFfi, TryFromReprC, Clone, Copy, Getters)]
#[getset(get = "pub")]
#[ffi_export]
pub struct FfiStruct {
    inner: GenericFfiStruct<bool>,
}

#[ffi_export]
pub fn freestanding(input: GenericFfiStruct<String>) -> GenericFfiStruct<String> {
    input
}

#[test]
fn get_return_generic() {
    let ffi_struct = &FfiStruct {
        inner: GenericFfiStruct(true),
    };
    let mut output = MaybeUninit::<*const GenericFfiStruct<bool>>::new(core::ptr::null());

    unsafe {
        FfiStruct__inner(ffi_struct.into_ffi(), output.as_mut_ptr());
        assert_eq!(
            TryFromReprC::try_from_repr_c(output.assume_init(), &mut ()),
            Ok(&ffi_struct.inner)
        );
    }
}

#[test]
fn freestanding_accept_and_return_generic() {
    let inner = GenericFfiStruct(String::from("hello world"));
    let mut output = MaybeUninit::<*mut GenericFfiStruct<String>>::new(core::ptr::null_mut());

    unsafe {
        __freestanding(inner.clone().into_ffi(), output.as_mut_ptr());
        assert_eq!(
            TryFromReprC::try_from_repr_c(output.assume_init(), &mut ()),
            Ok(inner)
        );
    }
}
