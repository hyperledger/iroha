use iroha_ffi::ffi_export;

/// Array as argument
#[ffi_export]
pub fn array_arg(_arr: [u32; 2]) {}

fn main() {
    let arg = [12_u32, 42_u32];
    let mut store = Default::default();
    unsafe { __array_arg(arg) };
}
