use iroha_ffi::FfiType;

/// Raw pointer type
#[derive(FfiType)]
#[repr(C)]
pub struct FfiStruct1(*mut u32);

/// Raw pointer type
#[derive(FfiType)]
pub enum FfiEnum1 {
    A,
    B(*mut u32),
}

fn main() {}
