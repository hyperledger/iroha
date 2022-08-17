use iroha_ffi::{ffi_export, FfiConvert, FfiType};

/// FfiStruct
#[derive(Clone, FfiType)]
pub struct FfiStruct;

#[ffi_export]
impl FfiStruct {
    /// Private methods are skipped
    fn private(self) {}
}

fn main() {
    let s = FfiStruct;
    unsafe {
        // Function not found
        FfiStruct__private(FfiConvert::into_ffi(s, &mut ()));
    }
}
