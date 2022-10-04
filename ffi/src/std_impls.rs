// Triggered by `&mut str` expansion
#![allow(clippy::mut_mut)]

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use core::mem::ManuallyDrop;

use crate::{ffi_type, ir::InfallibleTransmute, ReprC};

// NOTE: This can be contested as it is nowhere documented that String is
// actually transmutable into Vec<u8>, but implicitly it should be
// SAFETY: String type should be transmutable into Vec<u8>
ffi_type! {unsafe impl Transparent for String[Vec<u8>] validated with {|target| core::str::from_utf8(target).is_ok()} }
// NOTE: `core::str::as_bytes` uses transmute internally which means that
// even though it's a string slice it can be transmuted into byte slice.
ffi_type! {unsafe impl<'itm> Transparent for &'itm str[&'itm [u8]] validated with {|target| core::str::from_utf8(target).is_ok()} }
// NOTE: `core::str::as_bytes` uses transmute internally which means that
// even though it's a string slice it can be transmuted into byte slice.
#[cfg(feature = "non_robust_ref_mut")]
ffi_type! {unsafe impl<'itm> Transparent for &'itm mut str[&'itm mut [u8]] validated with {|target| core::str::from_utf8(target).is_ok()} }
ffi_type! {unsafe impl<T> Transparent for core::mem::ManuallyDrop<T>[T] validated with {|_| true} }
ffi_type! {unsafe impl<T> Transparent for core::ptr::NonNull<T>[*mut T] validated with {|target: &*mut T| target.is_null()} }
ffi_type! {impl<K, V> Opaque for BTreeMap<K, V> }
ffi_type! {impl<K> Opaque for BTreeSet<K> }

// SAFETY: Type is `ReprC` if the inner type is
unsafe impl<T: ReprC> ReprC for ManuallyDrop<T> {}

// SAFETY: `ManuallyDrop` is robust with respect to `T`
unsafe impl<T> InfallibleTransmute for ManuallyDrop<T> {}
