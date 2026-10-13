//! Bind closed built-in source authority to the actual local mathematical inputs.

#[path = "build_support/source_identity.rs"]
mod source_identity;

fn main() {
    let out_dir =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo output directory"));
    // A missing rerun input makes Cargo rerun this script on every invocation.
    // Rescan new source/config membership even below ignored-output parents;
    // directory watches cannot express that boundary without scanning outputs.
    let rescan = out_dir.join("native-source-rescan-required");
    match std::fs::remove_file(&rescan) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => panic!("cannot keep source-rescan input absent: {error}"),
    }
    println!("cargo:rerun-if-changed={}", rescan.display());
    let manifest = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory"),
    );
    let root = manifest.parent().and_then(std::path::Path::parent);
    let snapshot = root
        .ok_or_else(|| "missing workspace root".to_owned())
        .and_then(source_identity::snapshot);
    let (digest, complete) = match snapshot {
        Ok(snapshot) => {
            for path in snapshot.watched_paths {
                println!("cargo:rerun-if-changed={}", path.display());
            }
            (snapshot.digest, true)
        }
        Err(error) => {
            // A published generic crate or incomplete checkout must still compile
            // so strict generation/import can run. It gains no built-in authority.
            println!("cargo:warning=closed source registry disabled: {error}");
            println!(
                "cargo:rerun-if-changed={}",
                manifest.join("build.rs").display()
            );
            if let Some(root) = root {
                println!(
                    "cargo:rerun-if-changed={}",
                    root.join(".git/index").display()
                );
                println!(
                    "cargo:rerun-if-changed={}",
                    root.join("Cargo.toml").display()
                );
            }
            ([0; 32], false)
        }
    };
    let read = |name| {
        println!("cargo:rerun-if-env-changed={name}");
        std::env::var(name).unwrap_or_default()
    };
    let arch = read("CARGO_CFG_TARGET_ARCH");
    let os = read("CARGO_CFG_TARGET_OS");
    let width = read("CARGO_CFG_TARGET_POINTER_WIDTH");
    let endian = read("CARGO_CFG_TARGET_ENDIAN");
    let target = read("TARGET");
    let supported = source_identity::supported_target(&arch, &os, &width, &endian);
    let source = format!(
        "// Generated from actual workspace inputs, not an environment digest.\n\
         pub(super) const CURRENT_NATIVE_SOURCE_DIGEST: [u8; 32] = {digest:?};\n\
         pub(super) const NATIVE_SOURCE_CLOSURE_COMPLETE: bool = {complete};\n\
         pub(super) const BUILTIN_TARGET_SUPPORTED: bool = {supported};\n\
         #[allow(dead_code)]\n\
         pub(super) const NATIVE_SOURCE_TARGET: &str = {target:?};\n"
    );
    let output = out_dir.join("native_source_identity.rs");
    if std::fs::read_to_string(&output).ok().as_deref() != Some(&source) {
        std::fs::write(output, source).expect("write native source identity");
    }
}
