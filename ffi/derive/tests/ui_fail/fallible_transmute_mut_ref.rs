use iroha_ffi::{ffi_export, ir::Transmute, FfiType};

/// Wrapper
#[derive(FfiType)]
#[repr(transparent)]
pub struct Wrapper(u32);

unsafe impl Transmute for Wrapper {
    type Target = u32;

    unsafe fn is_valid(inner: &Self::Target) -> bool {
        *inner != 0
    }
}

/// Take exclusive reference to a structure that is not-robust structure, for which it cannot
/// be guaranteed that the caller of the function will not set it to a trap representation.
#[ffi_export]
pub fn take_non_robust_ref_mut(_ffi_struct: &mut Wrapper) {}

fn main() {}
