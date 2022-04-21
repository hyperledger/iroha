//! Build script

fn main() {
    println!("cargo:rustc-link-arg=--export-table");
}
