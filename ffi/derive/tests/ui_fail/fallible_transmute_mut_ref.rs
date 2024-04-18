use iroha_ffi::{ffi_export, FfiType};

type WrapperInner = u32;

/// Wrapper
#[derive(FfiType)]
#[repr(transparent)]
pub struct Wrapper(WrapperInner);

iroha_ffi::ffi_type! {
    unsafe impl Transparent for Wrapper {
        type Target = WrapperInner;

        validation_fn=unsafe {|target: &WrapperInner| *target != 0},
        niche_value=0
    }
}

/// Take exclusive reference to a structure that is not-robust structure, for which it cannot
/// be guaranteed that the caller of the function will not set it to a trap representation.
#[ffi_export]
pub fn take_non_robust_ref_mut(_ffi_struct: &mut Wrapper) {}

fn main() {}
