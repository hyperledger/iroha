use getset::Getters;
use iroha_ffi::{ffi_export, FfiType};

#[ffi_export]
pub fn freestanding<T>(v: T) -> T {
    v
}

#[ffi_export]
#[derive(Getters, FfiType)]
#[getset(get = "pub")]
pub struct FfiStruct<T> {
    inner: T,
}

fn main() {}
