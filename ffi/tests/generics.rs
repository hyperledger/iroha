#![allow(unsafe_code, clippy::restriction, clippy::pedantic)]

use std::mem::MaybeUninit;

use getset::Getters;
use iroha_ffi::{ffi_export, FfiConvert, FfiType};

#[derive(Clone, Copy, PartialEq, Eq, Debug, FfiType)]
pub struct GenericFfiStruct<T>(T);

#[derive(Clone, Copy, Getters, FfiType)]
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
        FfiStruct__inner(ffi_struct.into_ffi(&mut ()), output.as_mut_ptr());
        assert_eq!(
            FfiConvert::try_from_ffi(output.assume_init(), &mut ()),
            Ok(&ffi_struct.inner)
        );
    }
}

#[test]
fn freestanding_accept_and_return_generic() {
    let inner = GenericFfiStruct(String::from("hello world"));
    let mut output = MaybeUninit::<*mut GenericFfiStruct<String>>::new(core::ptr::null_mut());

    unsafe {
        __freestanding(inner.clone().into_ffi(&mut ()), output.as_mut_ptr());
        assert_eq!(
            FfiConvert::try_from_ffi(output.assume_init(), &mut ()),
            Ok(inner)
        );
    }
}
