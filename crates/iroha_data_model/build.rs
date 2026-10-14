//! Model-owned, test-only mutation selection for Sumeragi spec §13.4.
//!
//! This selector affects only the `DataModel` unit-test compilation, never Core or another
//! dependency. The library guard rejects the feature in every non-test build. The environment
//! supplies one registered source switch; inherited compiler cfg injection is always refused.

use std::{env, fs, path::Path};

const CFG: &str = "sumeragi_model_mutation";
const ENV: &str = "SUMERAGI_MODEL_MUTATION";
const IDS: &[&str] = &[
    "DM1", "DM2", "DM3", "DM4", "DM5", "DM6", "DM7", "DM8", "DM9", "DM10", "DM11", "DM12", "DM13",
    "DM14", "DM15", "DM16", "DM17", "DM18", "DM19", "DM20", "DM21", "DM22", "DM23", "DM24", "DM25",
    "DM26", "DM27", "DM28", "DM29", "DM30", "DM31", "DM32", "DM33", "DM34", "DM35", "DM36", "DM37",
    "DM38", "DM39", "DM40", "DM41", "DM42", "DM43",
];

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
        "Model mutation cfg cannot be injected through compiler flags; use the owning test selector"
    );
    let requested = env::var(ENV).ok().filter(|id| !id.is_empty());
    if env::var_os("CARGO_FEATURE_MUTATION_TESTING").is_none() {
        if let Some(id) = requested {
            println!("cargo:warning={ENV}={id} ignored: Model mutation-testing is off");
        }
        return;
    }
    let Some(id) = requested else {
        return;
    };
    assert!(
        IDS.contains(&id.as_str()),
        "{ENV}={id:?}: unknown Model mutation id"
    );
    println!("cargo:rerun-if-changed=src");
    let needle = format!("{CFG} = \"{id}\"");
    assert!(
        mentions(Path::new("src"), &needle),
        "{ENV}={id}: missing registered source switch"
    );
    println!("cargo:rustc-cfg={CFG}=\"{id}\"");
    println!("cargo:warning=iroha_data_model is built with mutation {id} (spec §13.4)");
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
