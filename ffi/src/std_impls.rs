use alloc::collections::{BTreeMap, BTreeSet};
use core::{mem::ManuallyDrop, ptr::NonNull};

use crate::{
    ir::{Ir, Opaque, Transmute, Transparent},
    ReprC,
};

unsafe impl<T: ReprC> ReprC for ManuallyDrop<T> {}

unsafe impl<T> Transmute for ManuallyDrop<T> {
    type Target = T;

    unsafe fn is_valid(_: &Self::Target) -> bool {
        true
    }
}
unsafe impl<T> Transmute for NonNull<T> {
    type Target = *mut T;

    unsafe fn is_valid(inner: &Self::Target) -> bool {
        inner.as_mut().is_some()
    }
}

unsafe impl<K, V> Transmute for BTreeMap<K, V> {
    type Target = Self;

    unsafe fn is_valid(_: &Self) -> bool {
        true
    }
}

unsafe impl<K> Transmute for BTreeSet<K> {
    type Target = Self;

    unsafe fn is_valid(_: &Self) -> bool {
        true
    }
}

impl<T> Ir for ManuallyDrop<T> {
    type Type = Transparent<Self>;
}

impl<T> Ir for NonNull<T> {
    type Type = Transparent<Self>;
}

impl<K, V> Ir for BTreeMap<K, V> {
    type Type = Opaque<Self>;
}

impl<K> Ir for BTreeSet<K> {
    type Type = Opaque<Self>;
}
