//! Build script

fn main() {
    println!("cargo:rustc-link-arg=--export-memory");
    println!("cargo:rustc-link-arg=--export-table");
}
