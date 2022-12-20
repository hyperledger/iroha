#![allow(unsafe_code, clippy::restriction, clippy::pedantic)]

use std::{alloc, ops::Deref};

use iroha_ffi::{ffi_import, FfiType, LocalRef, LocalSlice};

iroha_ffi::def_ffi_fn! { dealloc }

#[derive(Debug, Clone, Copy, PartialEq, Eq, FfiType)]
#[ffi_type(unsafe {robust})]
#[repr(transparent)]
pub struct Transparent((u32, u32));

#[ffi_import]
pub fn freestanding_returns_non_local(input: &u32) -> &u32 {
    unreachable!("replaced by ffi_import")
}

#[ffi_import]
pub fn freestanding_returns_local_ref(input: &(u32, u32)) -> &(u32, u32) {
    unreachable!("replaced by ffi_import")
}

#[ffi_import]
pub fn freestanding_returns_local_slice(input: &[(u32, u32)]) -> &[(u32, u32)] {
    unreachable!("replaced by ffi_import")
}

#[ffi_import]
pub fn freestanding_take_and_return_array(input: [(u32, u32); 2]) -> [(u32, u32); 2] {
    unreachable!("replaced by ffi_import")
}

#[ffi_import]
pub fn freestanding_take_and_return_non_local_transparent_ref(input: &Transparent) -> &Transparent {
    unreachable!("replaced by ffi_import")
}

#[test]
#[webassembly_test::webassembly_test]
fn take_and_return_non_local() {
    let input = 420;
    let output: &u32 = freestanding_returns_non_local(&input);
    assert_eq!(&input, output);
}

#[test]
#[webassembly_test::webassembly_test]
fn tuple_ref_is_coppied_when_returned() {
    let in_tuple = (420, 420);
    let out_tuple: LocalRef<(u32, u32)> = freestanding_returns_local_ref(&in_tuple);
    assert_eq!(&in_tuple, out_tuple.deref());
}

#[test]
#[webassembly_test::webassembly_test]
fn vec_of_tuples_is_coppied_when_returned() {
    let in_tuple = vec![(420_u32, 420_u32)];
    let out_tuple: LocalSlice<(u32, u32)> = freestanding_returns_local_slice(&in_tuple);
    assert_eq!(&in_tuple, out_tuple.deref());
}

#[test]
#[webassembly_test::webassembly_test]
fn take_and_return_array() {
    let input = [(420, 420), (420, 420)];
    let output: [(u32, u32); 2] = freestanding_take_and_return_array(input);
    assert_eq!(input, output);
}

#[test]
#[webassembly_test::webassembly_test]
fn take_and_return_transparent_non_local_ref() {
    let input = Transparent((420, 420));
    let output: LocalRef<Transparent> =
        freestanding_take_and_return_non_local_transparent_ref(&input);
    assert_eq!(&input, output.deref());
}

mod ffi {
    use iroha_ffi::{
        slice::{OutBoxedSlice, SliceRef},
        FfiReturn, FfiTuple2,
    };

    #[no_mangle]
    unsafe extern "C" fn __freestanding_returns_non_local(
        input: *const u32,
        output: *mut *const u32,
    ) -> FfiReturn {
        output.write(input);
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn __freestanding_returns_local_ref(
        input: *const FfiTuple2<u32, u32>,
        output: *mut FfiTuple2<u32, u32>,
    ) -> FfiReturn {
        output.write(input.read());
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn __freestanding_returns_local_slice(
        input: SliceRef<FfiTuple2<u32, u32>>,
        output: *mut OutBoxedSlice<FfiTuple2<u32, u32>>,
    ) -> FfiReturn {
        output.write(OutBoxedSlice::from_vec(
            input.into_rust().map(|slice| slice.to_vec()),
        ));
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn __freestanding_take_and_return_array(
        input: *mut [FfiTuple2<u32, u32>; 2],
        output: *mut [FfiTuple2<u32, u32>; 2],
    ) -> FfiReturn {
        output.write(input.read());
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn __freestanding_take_and_return_non_local_transparent_ref(
        input: *const FfiTuple2<u32, u32>,
        output: *mut FfiTuple2<u32, u32>,
    ) -> FfiReturn {
        output.write(input.read());
        FfiReturn::Ok
    }
}
