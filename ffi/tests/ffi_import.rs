#![allow(unsafe_code)]

use iroha_ffi::{ffi, ffi_import, LocalRef, LocalSlice};

ffi! {
    // NOTE: Wrapped in ffi! to test that macro expansion works for non-opaque types as well.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[ffi_type(unsafe {robust})]
    #[repr(transparent)]
    pub struct Transparent((u32, u32));
}

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
pub fn freestanding_returns_iterator(
    input: impl IntoIterator<Item = u32>,
) -> impl ExactSizeIterator<Item = u32> {
    unreachable!("replaced by ffi_import")
}

#[ffi_import]
pub fn freestanding_take_and_return_array(input: [(u32, u32); 2]) -> impl Into<[(u32, u32); 2]> {
    unreachable!("replaced by ffi_import")
}

#[ffi_import]
pub fn freestanding_take_and_return_local_transparent_ref(input: &Transparent) -> &Transparent {
    unreachable!("replaced by ffi_import")
}

#[ffi_import]
pub fn freestanding_take_and_return_boxed_int(input: Box<u8>) -> Box<u8> {
    unreachable!("replaced by ffi_import")
}

#[ffi_import]
pub fn freestanding_return_empty_tuple_result(flag: bool) -> Result<(), u8> {
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
    assert_eq!(in_tuple, *out_tuple);
}

#[test]
#[webassembly_test::webassembly_test]
fn vec_of_tuples_is_coppied_when_returned() {
    let in_tuple = vec![(420_u32, 420_u32)];
    let out_tuple: LocalSlice<(u32, u32)> = freestanding_returns_local_slice(&in_tuple);
    assert_eq!(in_tuple, *out_tuple);
}

#[test]
#[webassembly_test::webassembly_test]
fn return_iterator() {
    let input = vec![420_u32, 420_u32];
    let output = freestanding_returns_iterator(input.clone());
    assert_eq!(input, output);
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
fn take_and_return_transparent_local_ref() {
    let input = Transparent((420, 420));
    let output: LocalRef<Transparent> = freestanding_take_and_return_local_transparent_ref(&input);
    assert_eq!(input, *output);
}

#[test]
#[webassembly_test::webassembly_test]
fn take_and_return_boxed_int() {
    let input: Box<u8> = Box::new(42u8);
    let output: Box<u8> = freestanding_take_and_return_boxed_int(input.clone());
    assert_eq!(input, output);
}

#[test]
#[webassembly_test::webassembly_test]
fn return_empty_tuple_result() {
    assert!(freestanding_return_empty_tuple_result(false).is_ok());
}

mod ffi {
    use std::alloc;

    use iroha_ffi::{
        slice::{OutBoxedSlice, SliceMut, SliceRef},
        FfiOutPtr, FfiReturn, FfiTuple2, FfiType,
    };

    iroha_ffi::def_ffi_fns! { dealloc }

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
        let input = input.into_rust().map(<[_]>::to_vec);
        output.write(OutBoxedSlice::from_vec(input));
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn __freestanding_returns_iterator(
        input: SliceMut<u32>,
        output: *mut OutBoxedSlice<u32>,
    ) -> FfiReturn {
        let input = input.into_rust().map(|slice| slice.to_vec());
        output.write(OutBoxedSlice::from_vec(input));
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
    unsafe extern "C" fn __freestanding_take_and_return_local_transparent_ref(
        input: <&(u32, u32) as FfiType>::ReprC,
        output: *mut <&(u32, u32) as FfiOutPtr>::OutPtr,
    ) -> FfiReturn {
        output.write(input.read());
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn __freestanding_take_and_return_boxed_int(
        input: <Box<u8> as FfiType>::ReprC,
        output: *mut <Box<u8> as FfiOutPtr>::OutPtr,
    ) -> FfiReturn {
        output.write(input.read());
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn __freestanding_return_empty_tuple_result(
        input: <bool as FfiType>::ReprC,
    ) -> FfiReturn {
        if input == 1 {
            return FfiReturn::ExecutionFail;
        }

        FfiReturn::Ok
    }
}
