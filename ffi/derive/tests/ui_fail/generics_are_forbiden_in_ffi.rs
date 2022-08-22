use std::alloc::alloc;
use iroha_ffi::{ffi_export, IntoFfi, TryFromReprC};
use getset::Getters;

#[ffi_export]
fn freestanding<T>(v: T) -> T { v }

#[derive(Getters, IntoFfi, TryFromReprC)]
#[getset(get = "pub")]
#[ffi_export]
pub struct FfiStruct<T> {
    inner: T,
}

fn main() {}
