//! Norito build configuration, binding checks and test-only origin mutations.

use std::{env, path::PathBuf, process::Command};
fn main() {
    emit_mutation_cfg();
    emit_build_cfgs();
    if env::var_os("DOCS_RS").is_some() {
        return;
    }
    println!("cargo:rerun-if-env-changed=NORITO_CHECK_BINDINGS_SYNC");
    println!("cargo:rerun-if-env-changed=NORITO_SKIP_BINDINGS_SYNC");
    if env::var_os("NORITO_SKIP_BINDINGS_SYNC").is_some() {
        return;
    }
    if env::var_os("NORITO_CHECK_BINDINGS_SYNC").is_none() {
        return;
    }
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.clone());
    let git_dir = workspace_root.join(".git");
    if !git_dir.exists() {
        // Building from a packaged source; skip sync check.
        return;
    }
    let script_py = workspace_root
        .join("scripts")
        .join("check_norito_bindings_sync.py");
    let script_sh = workspace_root
        .join("scripts")
        .join("check_norito_bindings_sync.sh");
    if !script_py.exists() && !script_sh.exists() {
        // Script absent (possibly trimmed workspace); nothing to do.
        return;
    }
    if script_py.exists() {
        println!("cargo:rerun-if-changed={}", script_py.display());
    }
    if script_sh.exists() {
        println!("cargo:rerun-if-changed={}", script_sh.display());
    }
    if script_py.exists() {
        let interpreters = ["python3", "python"];
        for interpreter in interpreters {
            match Command::new(interpreter)
                .current_dir(&workspace_root)
                .arg(&script_py)
                .status()
            {
                Ok(status) => {
                    if status.success() {
                        return;
                    }
                    panic!(
                        "Norito bindings sync check failed. Please run scripts/check_norito_bindings_sync.py manually."
                    );
                }
                Err(_) => continue,
            }
        }
        // Fall through to shell wrapper if Python is unavailable.
    }
    if !script_sh.exists() {
        panic!(
            "Norito bindings sync check could not be executed because a Python interpreter was not found. \
             Install Python 3 and rerun scripts/check_norito_bindings_sync.py manually."
        );
    }
    let shells = ["sh", "bash"];
    for shell in shells {
        match Command::new(shell)
            .current_dir(&workspace_root)
            .arg(script_sh.as_os_str())
            .status()
        {
            Ok(status) => {
                if status.success() {
                    return;
                }
                panic!(
                    "Norito bindings sync check failed. Please run scripts/check_norito_bindings_sync.py manually."
                );
            }
            Err(_) => continue,
        }
    }
    panic!(
        "Norito bindings sync check could not be executed because no suitable shell or Python interpreter was found. \
         Install Python 3 and rerun scripts/check_norito_bindings_sync.py manually."
    );
}
fn emit_build_cfgs() {
    const CABAC_ENV: &str = "ENABLE_CABAC";
    const TRELLIS_ENV: &str = "ENABLE_TRELLIS";
    println!("cargo:rustc-check-cfg=cfg(norito_enable_cabac)");
    println!("cargo:rustc-check-cfg=cfg(norito_enable_trellis)");
    println!("cargo:rustc-check-cfg=cfg(norito_enable_rans_bundles)");
    println!("cargo:rerun-if-env-changed={CABAC_ENV}");
    println!("cargo:rerun-if-env-changed={TRELLIS_ENV}");
    if env_flag_enabled(CABAC_ENV) {
        println!("cargo:rustc-cfg=norito_enable_cabac");
    }
    if env_flag_enabled(TRELLIS_ENV) {
        println!("cargo:rustc-cfg=norito_enable_trellis");
    }
    println!("cargo:rustc-cfg=norito_enable_rans_bundles");
}
fn env_flag_enabled(name: &str) -> bool {
    match env::var(name) {
        Ok(value) => {
            let trimmed = value.trim();
            !trimmed.is_empty() && trimmed != "0" && !trimmed.eq_ignore_ascii_case("false")
        }
        Err(_) => false,
    }
}

// Each selector belongs only to this crate's libtest build. Never inject a
// dependency mutation through compiler flags or a shipping feature.
const CFG: &str = "sumeragi_norito_mutation";
const ENV: &str = "SUMERAGI_NORITO_MUTATION";
const IDS: &[&str] = &["NC1", "NC2", "NC3", "NC4", "NC5"];

fn emit_mutation_cfg() {
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
        "Norito mutation cfg cannot be injected through compiler flags; use the owning test selector"
    );
    let requested = env::var(ENV).ok().filter(|id| !id.is_empty());
    if env::var_os("CARGO_FEATURE_MUTATION_TESTING").is_none() {
        if let Some(id) = requested {
            println!("cargo:warning={ENV}={id} ignored: Norito mutation-testing is off");
        }
        return;
    }
    let Some(id) = requested else {
        return;
    };
    assert!(
        IDS.contains(&id.as_str()),
        "{ENV}={id:?}: unknown Norito mutation id"
    );
    println!("cargo:rerun-if-changed=src");
    let needle = format!("{CFG} = \"{id}\"");
    assert!(
        mentions_mutation(std::path::Path::new("src"), &needle),
        "{ENV}={id}: missing registered source switch"
    );
    println!("cargo:rustc-cfg={CFG}=\"{id}\"");
    println!("cargo:warning=norito is built with mutation {id} (spec §13.4)");
}

fn mentions_mutation(directory: &std::path::Path, needle: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        if path.is_dir() {
            mentions_mutation(&path, needle)
        } else {
            path.extension().is_some_and(|extension| extension == "rs")
                && std::fs::read_to_string(&path).is_ok_and(|source| source.contains(needle))
        }
    })
}
