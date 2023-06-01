use iroha_ffi::{ffi_export, ffi_import};

macro_rules! derive_freestanding_export_import {
    ($(fn $ident:ident($inp:ty) -> $out:ty);+ $(;)?) => {
        // FFI imports
        $(
            #[ffi_import]
            pub fn $ident(value: $inp) -> $out {
                unreachable!("replaced by ffi_import")
            }
        )*

        // FFI exports
        mod exports {
            use std::alloc;
            use super::*;

            iroha_ffi::def_ffi_fns! { dealloc }

            $(
                #[ffi_export]
                pub fn $ident(value: $inp) -> $out {
                    value
                }
            )*
        }
    };
}

derive_freestanding_export_import! {
    fn freestanding_u128(u128) -> u128;
    fn freestanding_i128(i128) -> i128;
    fn freestanding_u128_ref(&u128) -> &u128;
    fn freestanding_i128_ref(&i128) -> &i128;
    fn freestanding_u128_slice(&[u128]) -> &[u128];
    fn freestanding_i128_slice(&[i128]) -> &[i128];
    fn freestanding_u128_vec(Vec<u128>) -> Vec<u128>;
    fn freestanding_i128_vec(Vec<i128>) -> Vec<i128>;
    fn freestanding_u128_box(Box<u128>) -> Box<u128>;
    fn freestanding_i128_box(Box<i128>) -> Box<i128>;
    fn freestanding_u128_array([u128; 6]) -> [u128; 6];
    fn freestanding_i128_array([i128; 11]) -> [i128; 11];
}

fn u128_values() -> [u128; 6] {
    [
        u128::MAX,
        u128::from(u64::MAX),
        u128::from(u32::MAX),
        u128::from(u16::MAX),
        u128::from(u8::MAX),
        0,
    ]
}

fn i128_values() -> [i128; 11] {
    [
        i128::MAX,
        i128::from(i64::MAX),
        i128::from(i32::MAX),
        i128::from(i16::MAX),
        i128::from(i8::MAX),
        0,
        i128::from(i8::MIN),
        i128::from(i16::MIN),
        i128::from(i32::MIN),
        i128::from(i64::MIN),
        i128::MIN,
    ]
}

#[test]
#[webassembly_test::webassembly_test]
fn u128_conversion() {
    let values = u128_values();

    for value in values {
        assert_eq!(value, freestanding_u128(value));
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn i128_conversion() {
    let values = i128_values();

    for value in values {
        assert_eq!(value, freestanding_i128(value));
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn u128_ref_conversion() {
    let values = u128_values();

    for value in values {
        assert_eq!(value, *freestanding_u128_ref(&value));
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn i128_ref_conversion() {
    let values = i128_values();

    for value in values {
        assert_eq!(value, *freestanding_i128_ref(&value));
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn u128_slice_conversion() {
    let values = u128_values();

    assert_eq!(values, *freestanding_u128_slice(&values));
}

#[test]
#[webassembly_test::webassembly_test]
fn i128_slice_conversion() {
    let values = i128_values();

    assert_eq!(values, *freestanding_i128_slice(&values));
}

#[test]
#[webassembly_test::webassembly_test]
fn u128_vec_conversion() {
    let values = u128_values().to_vec();

    assert_eq!(values, freestanding_u128_vec(values.clone()))
}

#[test]
#[webassembly_test::webassembly_test]
fn i128_vec_conversion() {
    let values = i128_values().to_vec();

    assert_eq!(values, freestanding_i128_vec(values.clone()))
}

#[test]
#[webassembly_test::webassembly_test]
fn u128_box_conversion() {
    let values = u128_values();
    for value in values {
        let value = Box::new(value);
        assert_eq!(value, freestanding_u128_box(value.clone()))
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn i128_box_conversion() {
    let values = i128_values();

    for value in values {
        let value = Box::new(value);
        assert_eq!(value, freestanding_i128_box(value.clone()))
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn u128_array_conversion() {
    let values = u128_values();

    assert_eq!(values, freestanding_u128_array(values))
}

#[test]
#[webassembly_test::webassembly_test]
fn i128_array_conversion() {
    let values = i128_values();

    assert_eq!(values, freestanding_i128_array(values))
}
