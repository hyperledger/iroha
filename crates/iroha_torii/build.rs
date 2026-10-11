//! TORII-owned, test-only mutation selection for Sumeragi spec §13.4.
//!
//! This selector affects only the `iroha_torii` unit-test compilation, never another
//! dependency. The library guard rejects the feature in every non-test build. The environment
//! supplies one registered source switch; inherited compiler cfg injection is always refused.

use std::{env, fs, path::Path};

const CFG: &str = "sumeragi_torii_mutation";
const ENV: &str = "SUMERAGI_TORII_MUTATION";
const IDS: &[&str] = &["TOR1", "TOR2", "TOR3"];

fn main() {
    let values = IDS
        .iter()
        .map(|id| format!("{id:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("cargo:rustc-check-cfg=cfg({CFG}, values({values}))");
    println!("cargo:rerun-if-env-changed={ENV}");
    println!("cargo:rerun-if-changed=build.rs");
    let rustflags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    assert!(
        !rustflags.contains(CFG),
        "TORII mutation cfg cannot be injected through compiler flags; use the owning test selector"
    );
    let requested = env::var(ENV).ok().filter(|id| !id.is_empty());
    if env::var_os("CARGO_FEATURE_MUTATION_TESTING").is_none() {
        if let Some(id) = requested {
            println!("cargo:warning={ENV}={id} ignored: TORII mutation-testing is off");
        }
        return;
    }
    let Some(id) = requested else {
        return;
    };
    assert!(
        IDS.contains(&id.as_str()),
        "{ENV}={id:?}: unknown TORII mutation id"
    );
    println!("cargo:rerun-if-changed=src");
    let needle = format!("{CFG} = \"{id}\"");
    assert!(
        mentions(Path::new("src"), &needle),
        "{ENV}={id}: missing registered source switch"
    );
    println!("cargo:rustc-cfg={CFG}=\"{id}\"");
    println!("cargo:warning=iroha_torii is built with mutation {id} (spec §13.4)");
}

fn mentions(directory: &Path, needle: &str) -> bool {
    let Ok(entries) = fs::read_dir(directory) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        if path.is_dir() {
            mentions(&path, needle)
        } else {
            path.extension().is_some_and(|extension| extension == "rs")
                && fs::read_to_string(&path).is_ok_and(|source| source.contains(needle))
        }
    })
}
