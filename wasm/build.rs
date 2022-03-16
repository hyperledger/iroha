//! Build script

fn main() {
    println!("cargo:rustc-link-arg=--import-memory");
    println!("cargo:rustc-link-arg=--import-table");
}
