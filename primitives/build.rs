//! Build script
//!
//! Warn if both `ffi-export` and `ffi-import` features are active at the same time

fn main() {
    let ffi_import = std::env::var_os("CARGO_FEATURE_FFI_IMPORT").is_some();
    let ffi_export = std::env::var_os("CARGO_FEATURE_FFI_EXPORT").is_some();

    #[allow(clippy::print_stderr)]
    if ffi_import && ffi_export {
        println!("cargo:warning=Features `ffi-export` and `ffi-import` are mutually exclusive");
        println!("cargo:warning=When both active, `ffi-import` feature takes precedence");
    }
}
