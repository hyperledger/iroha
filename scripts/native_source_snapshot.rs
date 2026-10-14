//! Print the maintained native source identity and its exact Cargo watch census.
//!
//! This small diagnostic is compiled by `audit_native_source_inputs.py` with the
//! successful build's host sha2 dependency. Its only argument is the source root.

#[allow(dead_code)]
#[path = "../crates/iroha_plonk/build_support/source_identity.rs"]
mod source_identity;

fn main() {
    let root = std::env::args_os()
        .nth(1)
        .expect("usage: source-snapshot <canonical-source-root>");
    let snapshot = source_identity::snapshot(std::path::Path::new(&root))
        .expect("complete actual native source closure");
    print!("digest=");
    for byte in snapshot.digest {
        print!("{byte:02x}");
    }
    println!();
    for path in snapshot.watched_paths {
        println!("watch={}", path.display());
    }
}
