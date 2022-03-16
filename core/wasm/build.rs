//! Build script

fn main() {
    println!("cargo:rustc-link-arg=-zstack-size=2097152"); // 2 MiB
}
