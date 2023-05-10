use iroha_ffi::FfiType;

/// Uninhabited enum
#[derive(FfiType)]
#[ffi_type(opaque)]
pub enum FfiStruct1 {}

/// Uninhabited enum
#[derive(FfiType)]
pub enum FfiStruct2 {}

fn main() {}
