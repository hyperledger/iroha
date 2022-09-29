use getset::Getters;
use iroha_ffi::{ffi_export, FfiType};

#[ffi_export]
fn freestanding<T>(v: T) -> T {
    v
}

#[derive(Getters, FfiType)]
#[getset(get = "pub")]
#[ffi_export]
pub struct FfiStruct<T> {
    inner: T,
}

fn main() {}
