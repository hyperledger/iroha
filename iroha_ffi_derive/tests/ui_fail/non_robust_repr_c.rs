use iroha_ffi::FfiType;

/// ReprC struct
#[derive(Clone, Copy, PartialEq, Eq, FfiType)]
#[repr(C)]
pub struct NonRobustReprCStruct<T> {
    a: bool,
    b: T,
}

fn main() {}
